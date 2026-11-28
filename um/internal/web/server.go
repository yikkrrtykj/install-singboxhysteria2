// Package web implements the UM-C browser plane: Cloudflare Access JWT
// verification, local password/TOTP/recovery authentication, server-side
// sessions/CSRF, account administration, and a session bridge into the existing
// B4 management service/RBAC. It is not the machine-ingest or local bearer
// admin plane.
package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/management"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/umcauth"
)

const (
	sessionCookie = "__Host-um_session"
	preauthCookie = "__Host-um_preauth"

	defaultIdleTimeout     = 30 * time.Minute
	defaultAbsoluteTimeout = 12 * time.Hour
	preauthTTL             = 5 * time.Minute
	maxWebBody             = 64 << 10
	csrfHeader             = "X-CSRF-Token"
	accessJWTHeader        = "Cf-Access-Jwt-Assertion"

	// KDFConcurrency bounds simultaneous Argon2id work so login/recovery bursts
	// cannot exhaust center memory.
	KDFConcurrency = 4
)

// Config configures the Web plane. Access must be a cryptographically configured
// verifier; the handler fails closed if absent. MasterKey is loaded from a
// protected file and is never stored in SQLite.
type Config struct {
	Store             *store.Store
	ManagementService *management.Service
	Access            *umcauth.Verifier
	MasterKey         []byte
	StaticDir         string
	AllowedOrigins    []string
	Now               func() time.Time
	IdleTimeout       time.Duration
	AbsoluteTimeout   time.Duration
	// TestHookAccessHeader permits tests to inject the Access JWT through a
	// request header only; it never changes production behavior. The browser
	// cannot set this header itself; Cloudflare Access supplies it at the origin.
	TestHookAccessHeader bool
}

// Handler is the isolated loopback Web plane.
type Handler struct {
	store     *store.Store
	mgmt      *management.Handler
	access    *umcauth.Verifier
	master    []byte
	static    string
	origins   map[string]bool
	now       func() time.Time
	idle      time.Duration
	absolute  time.Duration
	limiter   *limiter
	kdf       chan struct{}
	dummyHash string
}

// NewHandler constructs the Web plane and its bridge into B4 management. It
// never constructs a second management service or database.
func NewHandler(cfg Config) (*Handler, error) {
	if cfg.Store == nil || cfg.ManagementService == nil || cfg.Access == nil {
		return nil, errors.New("web: store, management service and Access verifier are required")
	}
	if len(cfg.MasterKey) != umcauth.MasterKeyBytes {
		return nil, errors.New("web: invalid master key")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = defaultIdleTimeout
	}
	if cfg.AbsoluteTimeout <= 0 {
		cfg.AbsoluteTimeout = defaultAbsoluteTimeout
	}
	if cfg.AbsoluteTimeout < cfg.IdleTimeout {
		return nil, errors.New("web: absolute timeout must be >= idle timeout")
	}
	origins := make(map[string]bool, len(cfg.AllowedOrigins))
	for _, origin := range cfg.AllowedOrigins {
		origin = strings.TrimRight(strings.TrimSpace(origin), "/")
		if origin == "" || !strings.HasPrefix(origin, "https://") {
			return nil, errors.New("web: allowed origins must be https URLs")
		}
		origins[origin] = true
	}
	dummyHash, err := umcauth.HashPassword("umc-dummy-password-not-a-credential", umcauth.DefaultPasswordParams())
	if err != nil {
		return nil, errors.New("web: password hashing unavailable")
	}
	h := &Handler{
		store: cfg.Store, access: cfg.Access, master: append([]byte(nil), cfg.MasterKey...),
		static: cfg.StaticDir, origins: origins, now: cfg.Now,
		idle: cfg.IdleTimeout, absolute: cfg.AbsoluteTimeout,
		limiter: newLimiter(cfg.Now), kdf: make(chan struct{}, KDFConcurrency), dummyHash: dummyHash,
	}
	auth, err := NewSessionAuthenticator(cfg.Store, cfg.Access, cfg.Now)
	if err != nil {
		return nil, err
	}
	h.mgmt, err = management.NewHandler(cfg.ManagementService, auth)
	if err != nil {
		return nil, err
	}
	return h, nil
}

// ServeHTTP is the Web listener entry point. Public health is intentionally
// minimal; every other route requires a valid Access JWT at the origin.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.setSecurityHeaders(w, r)
	if r.URL.Path == "/api/health" {
		if r.Method != http.MethodGet {
			h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		h.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": "um-center-web"})
		return
	}
	claims, err := h.verifyAccess(r)
	if err != nil {
		// Bound anonymous audit amplification from invalid/unauthenticated asset
		// floods; the authentication decision itself still fails closed.
		if h.limiter.allow("audit-access:"+remoteIP(r), 0.02, 2) {
			h.auditAnonymous(r, "access_jwt_rejected", "denied")
		}
		h.writeError(w, http.StatusUnauthorized, "access_unauthorized", "valid Cloudflare Access identity required")
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), accessContextKey{}, claims))
	switch {
	case strings.HasPrefix(r.URL.Path, "/api/v1/"):
		h.serveManagement(w, r)
	case strings.HasPrefix(r.URL.Path, "/auth/"):
		h.serveAuth(w, r)
	case strings.HasPrefix(r.URL.Path, "/web/api/"):
		h.serveWebAPI(w, r)
	case r.Method == http.MethodGet || r.Method == http.MethodHead:
		h.serveStatic(w, r)
	default:
		h.writeError(w, http.StatusNotFound, "endpoint_not_found", "unknown endpoint")
	}
}

func (h *Handler) verifyAccess(r *http.Request) (*umcauth.VerifiedToken, error) {
	raw := strings.TrimSpace(r.Header.Get(accessJWTHeader))
	if raw == "" {
		// Cloudflare Tunnel+Access places the assertion in the header. A
		// CF_Authorization cookie is not accepted as an origin-side substitute and
		// the email header is never identity.
		return nil, umcauth.ErrMalformedToken
	}
	if len(raw) > 32<<10 {
		return nil, umcauth.ErrTokenTooLarge
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	return h.access.Verify(ctx, raw)
}

func (h *Handler) setSecurityHeaders(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if strings.HasPrefix(r.URL.Path, "/auth/") || strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/web/") {
		w.Header().Set("Cache-Control", "no-store")
	}
	if r.TLS != nil {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
}

func (h *Handler) serveManagement(w http.ResponseWriter, r *http.Request) {
	ident, err := h.authenticate(r, store.AuthSessionActive)
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "unauthenticated", "local session required")
		return
	}
	if err := h.checkCSRF(r, ident); err != nil {
		h.auditIdentity(r, ident, "csrf_rejected", "web", "denied")
		h.writeError(w, http.StatusForbidden, "csrf_invalid", "CSRF validation failed")
		return
	}
	r = r.WithContext(withIdentity(r.Context(), ident))
	h.mgmt.ServeHTTP(w, r)
}

func (h *Handler) checkCSRF(r *http.Request, ident *identity) error {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		// B4 purge preview is a GET that creates a durable confirmation receipt;
		// treat it as a protected state-changing browser action.
		if !strings.HasSuffix(r.URL.Path, "/purge/preview") {
			return nil
		}
	}
	if !h.originAllowed(r) {
		return errors.New("origin not allowed")
	}
	provided := strings.TrimSpace(r.Header.Get(csrfHeader))
	if provided == "" || len(provided) > 256 {
		return errors.New("missing CSRF token")
	}
	sum := sha256.Sum256([]byte(provided))
	return compareConstant(hex.EncodeToString(sum[:]), ident.Session.CSRFHash)
}

func (h *Handler) originAllowed(r *http.Request) bool {
	origin := strings.TrimRight(strings.TrimSpace(r.Header.Get("Origin")), "/")
	if origin == "" {
		// Non-browser clients (local integration tests) may omit Origin; a
		// browser mutation is still protected by the per-session CSRF token.
		return true
	}
	return h.origins[origin]
}

func (h *Handler) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(value)
}

func (h *Handler) writeError(w http.ResponseWriter, status int, code, message string) {
	h.writeJSON(w, status, map[string]any{"error": map[string]any{
		"code": code, "message": message, "retryable": false,
	}})
}

func decodeJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return errors.New("missing body")
	}
	defer r.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxWebBody+1))
	if err != nil || len(raw) > maxWebBody {
		return errors.New("body too large")
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return errors.New("invalid JSON body")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("invalid JSON body")
	}
	return nil
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "unknown"
	}
	return host
}

func (h *Handler) auditAnonymous(r *http.Request, action, detail string) {
	// Bounded closed action names; detail is a static error category, never raw
	// JWT/header/user input. Anonymous failures are not attributed to a real user.
	_ = h.store.RecordAuthAudit(r.Context(), "anonymous", "unauthenticated", action, "web", "denied", h.now().Unix())
}

func (h *Handler) auditIdentity(r *http.Request, ident *identity, action, target, result string) {
	if ident == nil {
		return
	}
	_ = h.store.RecordAuthAudit(r.Context(), ident.User.UserID, ident.User.Role, action, target, result, h.now().Unix())
}

func compareConstant(a, b string) error {
	if len(a) != len(b) || umcauth.ConstantTimeEqual(a, b) == false {
		return errors.New("mismatch")
	}
	return nil
}

func (h *Handler) withKDF(fn func() error) error {
	select {
	case h.kdf <- struct{}{}:
		defer func() { <-h.kdf }()
		return fn()
	default:
		return errKDFBusy
	}
}

var errKDFBusy = errors.New("web: password processing busy")

func init() {
	// Avoid accidental MIME sniffing for extensionless static files.
	_ = mime.AddExtensionType(".js", "text/javascript")
	_ = mime.AddExtensionType(".css", "text/css")
}

// limiter is a bounded in-memory token bucket set for authentication endpoints.
type limiter struct {
	mu      sync.Mutex
	now     func() time.Time
	buckets map[string]*bucket
	max     int
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(now func() time.Time) *limiter {
	return &limiter{now: now, buckets: make(map[string]*bucket), max: 4096}
}

func (l *limiter) allow(key string, rate, burst float64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.buckets) > l.max {
		for k, b := range l.buckets {
			if now.Sub(b.last) > 10*time.Minute {
				delete(l.buckets, k)
			}
		}
		if len(l.buckets) > l.max {
			// Bounded fail-safe: clear the oldest map wholesale rather than grow.
			l.buckets = make(map[string]*bucket)
		}
	}
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: burst, last: now}
		l.buckets[key] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * rate
		if b.tokens > burst {
			b.tokens = burst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// static file serving -------------------------------------------------------

func (h *Handler) serveStatic(w http.ResponseWriter, r *http.Request) {
	if h.static == "" {
		h.writeError(w, http.StatusNotFound, "ui_unavailable", "web UI is not configured")
		return
	}
	clean := filepath.Clean("/" + r.URL.Path)
	if strings.Contains(clean, "..") {
		h.writeError(w, http.StatusNotFound, "endpoint_not_found", "unknown endpoint")
		return
	}
	rel := strings.TrimPrefix(clean, "/")
	if rel == "" {
		rel = "index.html"
	}
	full := filepath.Join(h.static, filepath.FromSlash(rel))
	info, err := os.Stat(full)
	if err == nil && !info.IsDir() {
		http.ServeFile(w, r, full)
		return
	}
	// SPA fallback for client-side routes. Never fall back for asset-looking
	// paths, and still require the Access JWT checked by ServeHTTP.
	if strings.Contains(rel, ".") {
		h.writeError(w, http.StatusNotFound, "endpoint_not_found", "unknown endpoint")
		return
	}
	index := filepath.Join(h.static, "index.html")
	if _, err := os.Stat(index); err != nil {
		h.writeError(w, http.StatusNotFound, "ui_unavailable", "web UI is not configured")
		return
	}
	http.ServeFile(w, r, index)
}

var errIdentityMissing = errors.New("web: identity missing")

func writeNoContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

func formatError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

var _ = fmt.Sprintf

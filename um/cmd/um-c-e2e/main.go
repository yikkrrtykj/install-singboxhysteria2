// Command um-c-e2e is an isolated browser/HTTP laboratory harness for UM-C. It
// runs the real center store, management service and Web handler with synthetic
// Cloudflare Access JWKS/JWT keys and a self-signed loopback TLS certificate. It
// is not a production command and never contacts Cloudflare or real DNS.
//
// Two lab-only surfaces exist on top of the real Web plane, and neither is part
// of any production command:
//
//   - `/__lab/state` and `/__lab/advance` on the browser listener drive a
//     deterministic lab clock (strictly forward-only) and expose synthetic,
//     throw-away fixtures (event ids, the seeded lab platform-admin credential
//     and the synthetic local B4 bearer below). The TOTP/session state machine
//     itself is the unchanged production handler; only its clock source is
//     injected, exactly like `web.Config.Now` supports in tests.
//   - `/__lab/b4/*` mounts the real B4 management handler with an in-memory
//     synthetic local bearer credential that behaves like the production
//     `FileAuthenticator` (Authorization: Bearer + constant-time digest
//     compare). It is a lab-only stand-in for the separate local admin listener
//     so the browser lab can prove that a credential valid on the local B4 plane
//     is still rejected by the browser Web plane `/api/v1/*`. It is mounted on
//     the existing self-signed TLS origin (never cross-origin) so the production
//     response CSP is not weakened for the lab.
//
// Every credential here is synthetic and lab-scoped; the harness never uses a
// real Cloudflare/DNS/certificate/paid resource, and the real edge deployment
// remains a production HOLD.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/management"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/umcauth"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/web"
)

// Synthetic fixtures. The browser lab reads these values from `/__lab/state`
// instead of hard-coding them, so a change here cannot silently desynchronize
// the harness and the test.
const (
	e2eAdminUsername = "e2e-admin"
	e2eAdminPassword = "E2E-UM-C-Password-2026!"
	// e2eOwnerUsername is a second platform_admin seeded through the real store
	// (the lab equivalent of the local Owner policy provisioning path; the Web
	// API deliberately cannot create platform_admins).
	e2eOwnerUsername = "e2e-owner"
	e2eOwnerPassword = "E2E-UM-C-Owner-Password-2026!"
	e2eEventAName    = "E2E Event A"
	e2eEventBName    = "E2E Event B"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "loopback browser listener")
	staticDir := flag.String("static", "web/dist", "built Vue frontend directory")
	flag.Parse()
	dir, err := os.MkdirTemp("", "um-c-e2e-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)
	st, err := store.Open(filepath.Join(dir, "center.db"))
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()
	keyPath := filepath.Join(dir, "master.key")
	if err := umcauth.GenerateMasterKeyFile(keyPath); err != nil {
		log.Fatal(err)
	}
	master, err := umcauth.LoadMasterKey(keyPath)
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	adminHash, err := umcauth.HashPassword(e2eAdminPassword, umcauth.DefaultPasswordParams())
	if err != nil {
		log.Fatal(err)
	}
	if _, err := st.BootstrapAuthUser(ctx, e2eAdminUsername, adminHash, time.Now().Unix()); err != nil {
		log.Fatal(err)
	}
	ownerHash, err := umcauth.HashPassword(e2eOwnerPassword, umcauth.DefaultPasswordParams())
	if err != nil {
		log.Fatal(err)
	}
	if _, err := st.CreateAuthUser(ctx, store.AuthUserInput{
		Username: e2eOwnerUsername, PasswordHash: ownerHash, Role: store.AuthRolePlatformAdmin,
		Now: time.Now().Unix(),
	}); err != nil {
		log.Fatal(err)
	}
	eventA := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	eventB := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	for _, event := range []struct{ id, name string }{
		{eventA, e2eEventAName},
		{eventB, e2eEventBName},
	} {
		if _, err := st.CreateEvent(ctx, event.id, event.name, time.Now().Unix()); err != nil {
			log.Fatal(err)
		}
	}
	msvc, err := management.NewService(st)
	if err != nil {
		log.Fatal(err)
	}

	// Deterministic, strictly forward-only lab clock. TOTP, session idle/absolute
	// expiry and the auth rate limiters all read this clock through the real Web
	// handler; the browser lab advances it instead of sleeping for 30-second TOTP
	// steps or 30-minute idle windows.
	clock := &labClock{}

	// Synthetic Cloudflare Access JWKS and a signed assertion. The browser test
	// injects only this synthetic header via Playwright routing.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	const kid = "um-c-e2e-key"
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(rsaKey.PublicKey.N.Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": n, "e": "AQAB",
		}}})
	}))
	defer jwks.Close()
	verifier, err := umcauth.NewVerifier(umcauth.Config{
		Issuer: "https://e2e.cloudflareaccess.test", Audience: "um-c-e2e-audience",
		JWKSURL: jwks.URL, AllowInsecureHTTPForTests: true,
	})
	if err != nil {
		log.Fatal(err)
	}

	cert, err := selfSignedCert()
	if err != nil {
		log.Fatal(err)
	}
	webLn, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	// The lab control/fixture surface is unauthenticated by design (it is only
	// ever a test harness), so refuse any non-loopback listener outright.
	if err := loopbackOnly(webLn); err != nil {
		log.Fatal(err)
	}
	webPort := webLn.Addr().(*net.TCPAddr).Port
	origin := fmt.Sprintf("https://localhost:%d", webPort)

	// Synthetic local B4 bearer credential: a valid local-admin credential for
	// the lab's B4 handler mount only. It is never a production credential and
	// the browser Web plane must still reject it.
	localBearer, err := umcauth.NewToken()
	if err != nil {
		log.Fatal(err)
	}
	bearerSum := sha256.Sum256([]byte(localBearer))
	fixtures := &labFixtures{
		clock: clock, localBearer: localBearer, localAdminURL: origin + "/__lab/b4",
		ownerUsername: e2eOwnerUsername, ownerPassword: e2eOwnerPassword,
		events: map[string]labEvent{
			"a": {ID: eventA, Name: e2eEventAName},
			"b": {ID: eventB, Name: e2eEventBName},
		},
	}

	h, err := web.NewHandler(web.Config{
		Store: st, ManagementService: msvc, Access: verifier, MasterKey: master,
		StaticDir: *staticDir, AllowedOrigins: []string{origin}, Now: clock.Now,
	})
	if err != nil {
		log.Fatal(err)
	}

	// The real B4 management handler, mounted as the local admin plane would be
	// in production, with the synthetic in-memory bearer authenticator. The lab
	// mount is same-origin and password-less only for that synthetic bearer; the
	// production handler itself is unchanged.
	adminHandler, err := management.NewHandler(msvc, &labLocalAuthenticator{
		tokenHash: hex.EncodeToString(bearerSum[:]),
	})
	if err != nil {
		log.Fatal(err)
	}
	webRoot := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/__lab/b4/"):
			trimmed := r.Clone(r.Context())
			trimmed.URL.Path = strings.TrimPrefix(r.URL.Path, "/__lab/b4")
			trimmed.URL.RawPath = ""
			adminHandler.ServeHTTP(w, trimmed)
			return
		case strings.HasPrefix(r.URL.Path, "/__lab/"):
			fixtures.ServeHTTP(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})

	webSrv := serveTLS(webLn, cert, webRoot)
	defer shutdownServers(webSrv)

	token := signAccessToken(rsaKey, kid, "e2e-browser-subject", time.Now())
	ready := map[string]string{
		"url": "https://localhost:" + fmt.Sprint(webPort), "token": token,
		"username": e2eAdminUsername, "password": e2eAdminPassword,
		"event_a": eventA, "event_b": eventB,
		"owner_username": e2eOwnerUsername, "static": *staticDir,
	}
	raw, _ := json.Marshal(ready)
	fmt.Println("E2E_READY " + string(raw))
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
}

// loopbackOnly rejects a listener that could expose the unauthenticated lab
// control/fixture surface beyond the local machine.
func loopbackOnly(ln net.Listener) error {
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok || addr.IP == nil || !addr.IP.IsLoopback() {
		return fmt.Errorf("um-c-e2e: browser lab listener must be loopback-only, got %q", ln.Addr().String())
	}
	return nil
}

func serveTLS(ln net.Listener, cert tls.Certificate, handler http.Handler) *http.Server {
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second}
	tlsLn := tls.NewListener(ln, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}})
	go func() { _ = srv.Serve(tlsLn) }()
	return srv
}

func shutdownServers(servers ...*http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(ctx)
	}
}

// labClock is a strictly forward-only clock offset injected into web.Config.Now.
type labClock struct {
	offset atomic.Int64
}

func (c *labClock) Now() time.Time {
	return time.Now().Add(time.Duration(c.offset.Load()) * time.Second)
}

func (c *labClock) Advance(seconds int64) {
	c.offset.Add(seconds)
}

type labEvent struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// labFixtures serves the lab-only control/read surface. It is mounted before the
// production Web handler (so no Cloudflare Access verification is required) and
// lives only in this command.
type labFixtures struct {
	clock         *labClock
	localBearer   string
	localAdminURL string
	ownerUsername string
	ownerPassword string
	events        map[string]labEvent
}

const maxLabClockAdvance = 24 * 60 * 60

func (l *labFixtures) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	switch r.URL.Path {
	case "/__lab/state":
		if r.Method != http.MethodGet {
			l.writeError(w, http.StatusMethodNotAllowed)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"now_unix":           l.clock.Now().Unix(),
			"b4_local_bearer":    l.localBearer,
			"b4_local_admin_url": l.localAdminURL,
			"platform_admin":     map[string]string{"username": l.ownerUsername, "password": l.ownerPassword},
			"events":             l.events,
		})
	case "/__lab/advance":
		if r.Method != http.MethodPost {
			l.writeError(w, http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Seconds int64 `json:"seconds"`
		}
		dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			l.writeError(w, http.StatusBadRequest)
			return
		}
		if req.Seconds < 0 || req.Seconds > maxLabClockAdvance {
			l.writeError(w, http.StatusBadRequest)
			return
		}
		l.clock.Advance(req.Seconds)
		_ = json.NewEncoder(w).Encode(map[string]any{"now_unix": l.clock.Now().Unix()})
	default:
		l.writeError(w, http.StatusNotFound)
	}
}

func (l *labFixtures) writeError(w http.ResponseWriter, status int) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": "lab_control_failed"})
}

// labLocalAuthenticator is the synthetic in-memory equivalent of the production
// local `FileAuthenticator`: it accepts exactly one lab bearer token in the
// Authorization header and resolves it to a trusted platform_admin principal. It
// is lab-only and never shipped in a production command.
type labLocalAuthenticator struct {
	tokenHash string
}

func (a *labLocalAuthenticator) Authenticate(r *http.Request) (management.Principal, error) {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if len(header) > 4096 || !strings.HasPrefix(header, prefix) {
		return management.Principal{}, management.ErrUnauthenticated
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	if token == "" {
		return management.Principal{}, management.ErrUnauthenticated
	}
	sum := sha256.Sum256([]byte(token))
	got := hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(got), []byte(a.tokenHash)) != 1 {
		return management.Principal{}, management.ErrUnauthenticated
	}
	return management.Principal{ID: "um-c-e2e-local-platform-admin", Role: management.RolePlatformAdmin}, nil
}

func signAccessToken(key *rsa.PrivateKey, kid, subject string, now time.Time) string {
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iss": "https://e2e.cloudflareaccess.test", "aud": "um-c-e2e-audience", "sub": subject,
		"exp": now.Add(time.Hour).Unix(), "nbf": now.Add(-10 * time.Second).Unix(),
		"iat": now.Add(-10 * time.Second).Unix(),
	})
	enc := base64.RawURLEncoding.EncodeToString
	signing := enc(header) + "." + enc(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, 5, sum[:])
	return signing + "." + enc(sig)
}

func selfSignedCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

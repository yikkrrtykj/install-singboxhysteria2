package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/umcauth"
)

type userView struct {
	UserID       string   `json:"user_id"`
	Username     string   `json:"username"`
	Role         string   `json:"role"`
	Enabled      bool     `json:"enabled"`
	EventIDs     []string `json:"event_ids"`
	TOTPEnrolled bool     `json:"totp_enrolled"`
	LastLoginAt  *int64   `json:"last_login_at,omitempty"`
}

func toUserView(u store.AuthUser) userView {
	return userView{UserID: u.UserID, Username: u.Username, Role: u.Role, Enabled: u.Enabled,
		EventIDs: u.EventIDs, TOTPEnrolled: len(u.TOTPSecret) > 0 && u.TOTPEnrolledAt != nil, LastLoginAt: u.LastLoginAt}
}

func (h *Handler) setSessionCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: value, Path: "/", Secure: true,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: maxAge})
}

func (h *Handler) setCSRFCookie(w http.ResponseWriter, value string, maxAge int) {
	// CSRF is a per-session double-submit token, not a credential. It remains
	// HttpOnly=false so the SPA can send it in X-CSRF-Token; it is never used
	// alone and cannot authenticate a request.
	http.SetCookie(w, &http.Cookie{Name: "__Host-um_csrf", Value: value, Path: "/", Secure: true,
		HttpOnly: false, SameSite: http.SameSiteStrictMode, MaxAge: maxAge})
}

func (h *Handler) setPreauthCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: preauthCookie, Value: value, Path: "/", Secure: true,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: maxAge})
}

func (h *Handler) clearCookies(w http.ResponseWriter) {
	for _, name := range []string{sessionCookie, preauthCookie, "__Host-um_csrf"} {
		http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", Secure: true, MaxAge: -1,
			Expires: time.Unix(1, 0), HttpOnly: name != "__Host-um_csrf", SameSite: http.SameSiteStrictMode})
	}
}

func (h *Handler) authUserView(r *http.Request, id *identity) map[string]any {
	csrf := ""
	if c, err := r.Cookie("__Host-um_csrf"); err == nil && compareConstant(umcauth.HashToken(c.Value), id.Session.CSRFHash) == nil {
		csrf = c.Value
	}
	out := map[string]any{
		"authenticated":       id.Session.State == store.AuthSessionActive,
		"session_state":       id.Session.State,
		"totp_required":       id.Session.State == store.AuthSessionTOTPPending,
		"totp_setup_required": id.Session.State == store.AuthSessionTOTPSetup,
		"user":                toUserView(id.User),
		"csrf_token":          csrf,
	}
	if id.Session.State == store.AuthSessionTOTPSetup && len(id.Session.PendingSecret) > 0 {
		if secret, err := h.openTOTP(id.User.UserID, id.Session.PendingSecret); err == nil {
			if uri, err := umcauth.OtpauthURI("UM Center", id.User.Username, secret); err == nil {
				// Setup material is re-displayed only inside the short-lived,
				// Access-bound pending session; it is never stored in the browser.
				out["secret"] = secret
				out["otpauth_uri"] = uri
			}
		}
	}
	return out
}

func (h *Handler) issueSession(ctx context.Context, w http.ResponseWriter, user store.AuthUser,
	claims *umcauth.VerifiedToken, state string, pending []byte) (string, error) {
	token, err := umcauth.NewToken()
	if err != nil {
		return "", err
	}
	publicID, err := umcauth.NewToken()
	if err != nil {
		return "", err
	}
	csrf, err := umcauth.NewCSRFToken()
	if err != nil {
		return "", err
	}
	now := h.now().Unix()
	idle := int64(h.idle / time.Second)
	absolute := int64(h.absolute / time.Second)
	sess := store.AuthSession{
		IDHash: umcauth.HashToken(token), PublicID: publicID, UserID: user.UserID, State: state,
		AccessSubject: claims.Claims.Subject, AccessIssuer: claims.Claims.Issuer,
		CSRFHash: umcauth.HashToken(csrf), PendingSecret: pending,
		CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now + idle, AbsoluteExpiresAt: now + absolute,
	}
	if len(pending) > 0 {
		v := now
		sess.PendingCreatedAt = &v
	}
	if err := h.store.CreateSession(ctx, sess); err != nil {
		return "", err
	}
	h.setSessionCookie(w, token, int(absolute))
	h.setCSRFCookie(w, csrf, int(absolute))
	return csrf, nil
}

func (h *Handler) rotateSession(ctx context.Context, w http.ResponseWriter, id *identity,
	state string, pending []byte) (string, error) {
	token, err := umcauth.NewToken()
	if err != nil {
		return "", err
	}
	publicID, err := umcauth.NewToken()
	if err != nil {
		return "", err
	}
	csrf, err := umcauth.NewCSRFToken()
	if err != nil {
		return "", err
	}
	now := h.now().Unix()
	sess := store.AuthSession{
		IDHash: umcauth.HashToken(token), PublicID: publicID, UserID: id.User.UserID, State: state,
		AccessSubject: id.Claims.Claims.Subject, AccessIssuer: id.Claims.Claims.Issuer,
		CSRFHash: umcauth.HashToken(csrf), PendingSecret: pending,
		CreatedAt: now, LastSeenAt: now,
		IdleExpiresAt: now + int64(h.idle/time.Second), AbsoluteExpiresAt: now + int64(h.absolute/time.Second),
	}
	if len(pending) > 0 {
		v := now
		sess.PendingCreatedAt = &v
	}
	if err := h.store.RotateSession(ctx, id.Session.IDHash, sess, now); err != nil {
		return "", err
	}
	h.setSessionCookie(w, token, int(h.absolute/time.Second))
	h.setCSRFCookie(w, csrf, int(h.absolute/time.Second))
	return csrf, nil
}

func (h *Handler) checkCSRFFor(r *http.Request, id *identity) error {
	provided := strings.TrimSpace(r.Header.Get(csrfHeader))
	if provided == "" || len(provided) > 256 {
		return errors.New("missing CSRF")
	}
	if compareConstant(umcauth.HashToken(provided), id.Session.CSRFHash) != nil {
		return errors.New("wrong CSRF")
	}
	if !h.originAllowed(r) {
		return errors.New("origin")
	}
	return nil
}

func (h *Handler) totpAAD(userID string) []byte {
	return []byte("umc-totp:" + userID + ":v1")
}

func (h *Handler) sealTOTP(userID, secret string) ([]byte, error) {
	return umcauth.Seal(h.master, []byte(secret), h.totpAAD(userID))
}

func (h *Handler) openTOTP(userID string, sealed []byte) (string, error) {
	raw, err := umcauth.Open(h.master, sealed, h.totpAAD(userID))
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func (h *Handler) authContext(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	claims, err := accessFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "access_unauthorized", "valid Cloudflare Access identity required")
		return
	}
	if id, err := h.authenticate(r, store.AuthSessionActive, store.AuthSessionTOTPPending, store.AuthSessionTOTPSetup); err == nil {
		h.writeJSON(w, http.StatusOK, h.authUserView(r, id))
		return
	}
	// No valid session: issue a short-lived preauth binding to the verified
	// Access subject, for login CSRF and subject continuity.
	token, err := umcauth.NewToken()
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal", "temporary authentication unavailable")
		return
	}
	csrf, err := umcauth.NewCSRFToken()
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal", "temporary authentication unavailable")
		return
	}
	now := h.now().Unix()
	p := store.AuthPreauth{TokenHash: umcauth.HashToken(token), AccessSubject: claims.Claims.Subject,
		AccessIssuer: claims.Claims.Issuer, CSRFHash: umcauth.HashToken(csrf),
		CreatedAt: now, ExpiresAt: now + int64(preauthTTL/time.Second)}
	if err := h.store.CreatePreauth(r.Context(), p); err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal", "temporary authentication unavailable")
		return
	}
	h.setPreauthCookie(w, token, int(preauthTTL/time.Second))
	h.writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": false, "totp_required": false, "totp_setup_required": false,
		"csrf_token": csrf,
	})
}

func (h *Handler) verifyPreauth(r *http.Request, claims *umcauth.VerifiedToken) (store.AuthPreauth, error) {
	cookie, err := r.Cookie(preauthCookie)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return store.AuthPreauth{}, errors.New("missing preauth")
	}
	p, err := h.store.GetPreauth(r.Context(), umcauth.HashToken(cookie.Value))
	if err != nil {
		return store.AuthPreauth{}, err
	}
	now := h.now().Unix()
	if now >= p.ExpiresAt || p.AccessSubject != claims.Claims.Subject || p.AccessIssuer != claims.Claims.Issuer {
		return store.AuthPreauth{}, errors.New("invalid preauth")
	}
	provided := strings.TrimSpace(r.Header.Get(csrfHeader))
	if provided == "" || compareConstant(umcauth.HashToken(provided), p.CSRFHash) != nil || !h.originAllowed(r) {
		return store.AuthPreauth{}, errors.New("invalid preauth csrf")
	}
	return p, nil
}

func (h *Handler) clearPreauth(r *http.Request, p store.AuthPreauth) {
	_ = h.store.DeletePreauth(r.Context(), p.TokenHash)
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	claims, err := accessFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "access_unauthorized", "valid Cloudflare Access identity required")
		return
	}
	if !h.limiter.allow("login-global:"+remoteIP(r), 5, 20) {
		h.writeError(w, http.StatusTooManyRequests, "rate_limited", "login rate limit exceeded")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "invalid login request")
		return
	}
	username := strings.TrimSpace(req.Username)
	if !h.limiter.allow("login-account:"+strings.ToLower(username)+":"+remoteIP(r), 0.2, 5) {
		h.writeError(w, http.StatusTooManyRequests, "rate_limited", "login rate limit exceeded")
		return
	}
	pre, err := h.verifyPreauth(r, claims)
	if err != nil {
		h.auditAnonymous(r, "umc_login_failed", "preauth")
		h.writeError(w, http.StatusForbidden, "login_csrf_failed", "login session is invalid or expired")
		return
	}
	user, getErr := h.store.GetAuthUserByUsername(r.Context(), username)
	if umcauth.ValidatePasswordPolicy(req.Password) != nil {
		h.auditAnonymous(r, "umc_login_failed", "password_policy")
		h.writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
		return
	}
	hash := h.dummyHash
	if getErr == nil {
		hash = user.PasswordHash
	}
	var ok bool
	err = h.withKDF(func() error {
		var verr error
		ok, verr = umcauth.VerifyPassword(hash, req.Password)
		return verr
	})
	if errors.Is(err, errKDFBusy) {
		h.writeError(w, http.StatusServiceUnavailable, "kdf_busy", "authentication busy; retry")
		return
	}
	if err != nil || !ok || getErr != nil || !user.Enabled {
		h.auditAnonymous(r, "umc_login_failed", "credentials")
		h.writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
		return
	}
	h.clearPreauth(r, pre)
	// Deliberately do not mark a full login yet: TOTP is mandatory.
	if len(user.TOTPSecret) > 0 && user.TOTPEnrolledAt != nil {
		csrf, err := h.issueSession(r.Context(), w, user, claims, store.AuthSessionTOTPPending, nil)
		if err != nil {
			h.writeError(w, http.StatusInternalServerError, "internal", "temporary authentication unavailable")
			return
		}
		h.auditIdentity(r, &identity{User: user}, "umc_password_ok", "user:"+user.UserID, "ok")
		h.writeJSON(w, http.StatusOK, map[string]any{"totp_required": true, "csrf_token": csrf,
			"user": toUserView(user)})
		return
	}
	secret, err := umcauth.NewTOTPSecret()
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal", "temporary authentication unavailable")
		return
	}
	sealed, err := h.sealTOTP(user.UserID, secret)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal", "temporary authentication unavailable")
		return
	}
	uri, err := umcauth.OtpauthURI("UM Center", user.Username, secret)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal", "temporary authentication unavailable")
		return
	}
	csrf, err := h.issueSession(r.Context(), w, user, claims, store.AuthSessionTOTPSetup, sealed)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal", "temporary authentication unavailable")
		return
	}
	h.auditIdentity(r, &identity{User: user}, "umc_totp_setup_started", "user:"+user.UserID, "ok")
	h.writeJSON(w, http.StatusOK, map[string]any{"totp_setup_required": true, "csrf_token": csrf,
		"secret": secret, "otpauth_uri": uri, "user": toUserView(user)})
}

func (h *Handler) verifyTOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	id, err := h.authenticate(r, store.AuthSessionTOTPPending, store.AuthSessionTOTPSetup)
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "unauthenticated", "pending TOTP session required")
		return
	}
	if err := h.checkCSRFFor(r, id); err != nil {
		h.auditIdentity(r, id, "csrf_rejected", "auth_totp", "denied")
		h.writeError(w, http.StatusForbidden, "csrf_invalid", "CSRF validation failed")
		return
	}
	if !h.limiter.allow("totp:"+id.User.UserID+":"+remoteIP(r), 0.5, 6) {
		h.writeError(w, http.StatusTooManyRequests, "rate_limited", "TOTP rate limit exceeded")
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "invalid TOTP request")
		return
	}
	now := h.now()
	var secret string
	if id.Session.State == store.AuthSessionTOTPSetup {
		secret, err = h.openTOTP(id.User.UserID, id.Session.PendingSecret)
	} else {
		secret, err = h.openTOTP(id.User.UserID, id.User.TOTPSecret)
	}
	if err != nil {
		h.auditIdentity(r, id, "umc_totp_failed", "auth_totp", "error")
		h.writeError(w, http.StatusInternalServerError, "totp_unavailable", "TOTP state unavailable")
		return
	}
	counter, ok, err := umcauth.VerifyTOTP(secret, strings.TrimSpace(req.Code), now, 1)
	if err != nil || !ok {
		h.auditIdentity(r, id, "umc_totp_failed", "auth_totp", "denied")
		h.writeError(w, http.StatusUnauthorized, "invalid_totp", "invalid TOTP code")
		return
	}
	oldHash := id.Session.IDHash
	if id.Session.State == store.AuthSessionTOTPSetup {
		sealed, err := h.sealTOTP(id.User.UserID, secret)
		if err != nil {
			h.writeError(w, http.StatusInternalServerError, "internal", "TOTP state unavailable")
			return
		}
		setupReq := h.mutationRequest(r, id.User, "umc_totp_enrolled", "user:"+id.User.UserID,
			"umc_totp_enrolled", id.User.UserID, "totp-setup")
		if err := h.store.SetAuthUserTOTP(setupReq.Context(), id.User.UserID, sealed, 1, now.Unix()); err != nil {
			h.writeError(w, http.StatusInternalServerError, "internal", "TOTP state unavailable")
			return
		}
		// SetAuthUserTOTP revoked all old sessions; create the active replacement.
		csrf, err := h.issueSession(r.Context(), w, id.User, id.Claims, store.AuthSessionActive, nil)
		if err != nil {
			h.writeError(w, http.StatusInternalServerError, "internal", "session unavailable")
			return
		}
		if err := h.store.ConsumeTOTPCounter(r.Context(), id.User.UserID, int64(counter), now.Unix()); err != nil {
			h.writeError(w, http.StatusInternalServerError, "internal", "TOTP state unavailable")
			return
		}
		codes, err := h.replaceRecoveryCodes(r.Context(), id.User.UserID)
		if err != nil {
			h.writeError(w, http.StatusInternalServerError, "internal", "recovery code setup failed")
			return
		}
		_ = h.store.MarkAuthLogin(r.Context(), id.User.UserID, now.Unix())
		h.writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "user": toUserView(id.User),
			"csrf_token": csrf, "recovery_codes": codes})
		return
	}
	nextToken, err := umcauth.NewToken()
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal", "session unavailable")
		return
	}
	nextPublic, err := umcauth.NewToken()
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal", "session unavailable")
		return
	}
	csrfRaw, err := umcauth.NewCSRFToken()
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal", "session unavailable")
		return
	}
	nowUnix := now.Unix()
	next := store.AuthSession{
		IDHash: umcauth.HashToken(nextToken), PublicID: nextPublic, UserID: id.User.UserID,
		State: store.AuthSessionActive, AccessSubject: id.Claims.Claims.Subject,
		AccessIssuer: id.Claims.Claims.Issuer, CSRFHash: umcauth.HashToken(csrfRaw),
		CreatedAt: nowUnix, LastSeenAt: nowUnix,
		IdleExpiresAt:     nowUnix + int64(h.idle/time.Second),
		AbsoluteExpiresAt: nowUnix + int64(h.absolute/time.Second),
	}
	if err := h.store.CompleteTOTPLogin(r.Context(), id.User.UserID, int64(counter), oldHash, next, nowUnix); err != nil {
		if errors.Is(err, store.ErrAuthTOTPReplayed) {
			h.auditIdentity(r, id, "umc_totp_replay", "auth_totp", "denied")
			h.writeError(w, http.StatusUnauthorized, "totp_replayed", "TOTP code already used")
			return
		}
		h.writeError(w, http.StatusInternalServerError, "internal", "session unavailable")
		return
	}
	h.setSessionCookie(w, nextToken, int(h.absolute/time.Second))
	h.setCSRFCookie(w, csrfRaw, int(h.absolute/time.Second))
	h.auditIdentity(r, id, "umc_login", "user:"+id.User.UserID, "ok")
	h.writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "user": toUserView(id.User),
		"csrf_token": csrfRaw})
}

func (h *Handler) replaceRecoveryCodes(ctx context.Context, userID string) ([]string, error) {
	codes, err := umcauth.GenerateRecoveryCodes(10)
	if err != nil {
		return nil, err
	}
	hashes := make([]string, len(codes))
	for i, code := range codes {
		hashes[i] = umcauth.HashRecoveryCode(code)
	}
	if err := h.store.ReplaceRecoveryCodes(ctx, userID, hashes, h.now().Unix()); err != nil {
		return nil, err
	}
	return codes, nil
}

func (h *Handler) recover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	claims, err := accessFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "access_unauthorized", "valid Cloudflare Access identity required")
		return
	}
	if !h.limiter.allow("recovery-global:"+remoteIP(r), 2, 10) {
		h.writeError(w, http.StatusTooManyRequests, "rate_limited", "recovery rate limit exceeded")
		return
	}
	var req struct {
		Username     string `json:"username"`
		Password     string `json:"password"`
		RecoveryCode string `json:"recovery_code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "invalid recovery request")
		return
	}
	pre, err := h.verifyPreauth(r, claims)
	if err != nil {
		h.auditAnonymous(r, "umc_recovery_failed", "preauth")
		h.writeError(w, http.StatusForbidden, "login_csrf_failed", "recovery session invalid or expired")
		return
	}
	user, err := h.store.GetAuthUserByUsername(r.Context(), req.Username)
	if err != nil || !user.Enabled {
		h.auditAnonymous(r, "umc_recovery_failed", "credentials")
		h.writeError(w, http.StatusUnauthorized, "invalid_recovery", "invalid recovery credentials")
		return
	}
	if !h.limiter.allow("recovery:"+user.UserID+":"+remoteIP(r), 0.1, 3) {
		h.writeError(w, http.StatusTooManyRequests, "rate_limited", "recovery rate limit exceeded")
		return
	}
	var ok bool
	if err := h.withKDF(func() error {
		var verr error
		ok, verr = umcauth.VerifyPassword(user.PasswordHash, req.Password)
		return verr
	}); err != nil || !ok {
		h.auditIdentity(r, &identity{User: user}, "umc_recovery_failed", "user:"+user.UserID, "denied")
		h.writeError(w, http.StatusUnauthorized, "invalid_recovery", "invalid recovery credentials")
		return
	}
	hash := umcauth.HashRecoveryCode(req.RecoveryCode)
	recoveryReq := h.mutationRequest(r, user, "umc_recovery_code_used", "user:"+user.UserID,
		"umc_recovery_used", user.UserID, "recovery-code")
	if err := h.store.ConsumeRecoveryCode(recoveryReq.Context(), user.UserID, hash, h.now().Unix()); err != nil {
		h.auditIdentity(r, &identity{User: user}, "umc_recovery_failed", "user:"+user.UserID, "denied")
		h.writeError(w, http.StatusUnauthorized, "invalid_recovery", "invalid recovery credentials")
		return
	}
	h.clearPreauth(r, pre)
	secret, err := umcauth.NewTOTPSecret()
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal", "temporary authentication unavailable")
		return
	}
	sealed, err := h.sealTOTP(user.UserID, secret)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal", "temporary authentication unavailable")
		return
	}
	uri, _ := umcauth.OtpauthURI("UM Center", user.Username, secret)
	csrf, err := h.issueSession(r.Context(), w, user, claims, store.AuthSessionTOTPSetup, sealed)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal", "session unavailable")
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"totp_setup_required": true, "csrf_token": csrf,
		"secret": secret, "otpauth_uri": uri, "user": toUserView(user)})
}

func (h *Handler) recordLedger(ctx context.Context, kind, subject, detail string) error {
	sum := sha256.Sum256([]byte(detail))
	return h.store.RecordAuthLedger(ctx, kind, subject, hex.EncodeToString(sum[:]), h.now().Unix())
}

// mutationRequest attaches atomic audit/ledger metadata to a critical auth-state
// mutation. The audit target is a non-secret ID/name and ledger detail is a hash;
// no password, TOTP secret, recovery code or session token is included.
func (h *Handler) mutationRequest(r *http.Request, actor store.AuthUser, action, target, ledgerKind, subject, detail string) *http.Request {
	detailHash := ""
	if detail != "" {
		sum := sha256.Sum256([]byte(detail))
		detailHash = hex.EncodeToString(sum[:])
	}
	ctx := store.WithAuthMutation(r.Context(), store.AuthMutationMeta{
		Audit: store.AuditMeta{Actor: "user:" + actor.Username, Role: actor.Role,
			Action: action, Target: target},
		LedgerKind: ledgerKind, LedgerSubject: subject, LedgerDetailHash: detailHash,
	})
	return r.WithContext(ctx)
}

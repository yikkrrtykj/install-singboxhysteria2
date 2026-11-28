package web

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/umcauth"
)

func (h *Handler) serveAuth(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/auth/"), "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		h.writeError(w, http.StatusNotFound, "endpoint_not_found", "unknown endpoint")
		return
	}
	switch parts[0] {
	case "context":
		h.authContext(w, r)
	case "login":
		h.login(w, r)
	case "totp":
		if len(parts) == 2 && parts[1] == "update" {
			h.updateTOTP(w, r)
			return
		}
		h.verifyTOTP(w, r)
	case "recovery":
		h.recover(w, r)
	case "logout", "abandon":
		h.logout(w, r)
	case "me":
		h.me(w, r)
	case "password":
		h.changePassword(w, r)
	case "recovery-codes":
		h.regenerateRecoveryCodes(w, r)
	case "sessions":
		if len(parts) == 1 {
			h.listSessions(w, r)
			return
		}
		if len(parts) == 3 && parts[2] == "revoke" {
			h.revokeOwnSession(w, r, parts[1])
			return
		}
		h.writeError(w, http.StatusNotFound, "endpoint_not_found", "unknown endpoint")
	default:
		h.writeError(w, http.StatusNotFound, "endpoint_not_found", "unknown endpoint")
	}
}

func (h *Handler) requireActive(w http.ResponseWriter, r *http.Request) (*identity, bool) {
	id, err := h.authenticate(r, store.AuthSessionActive)
	if err != nil {
		if errors.Is(err, ErrAuthUnavailable) {
			h.writeError(w, http.StatusServiceUnavailable, "auth_state_unavailable", "authentication state unavailable; retry")
			return nil, false
		}
		h.writeError(w, http.StatusUnauthorized, "unauthenticated", "authenticated session required")
		return nil, false
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
	default:
		if err := h.checkCSRFFor(r, id); err != nil {
			h.auditIdentity(r, id, "csrf_rejected", "session", "denied")
			h.writeError(w, http.StatusForbidden, "csrf_invalid", "CSRF validation failed")
			return nil, false
		}
	}
	return id, true
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	id, err := h.authenticate(r, store.AuthSessionActive, store.AuthSessionTOTPPending, store.AuthSessionTOTPSetup)
	if err != nil {
		if errors.Is(err, ErrAuthUnavailable) {
			h.writeError(w, http.StatusServiceUnavailable, "auth_state_unavailable", "authentication state unavailable; retry")
			return
		}
		h.writeError(w, http.StatusUnauthorized, "unauthenticated", "authenticated session required")
		return
	}
	// Logout is itself a security-state mutation: serialize it with management
	// mutations of the same account and revalidate after the gate.
	release := h.lockAuthGates(authLock{id: id.User.UserID, write: true})
	defer release()
	id, err = h.authenticate(r, store.AuthSessionActive, store.AuthSessionTOTPPending, store.AuthSessionTOTPSetup)
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "unauthenticated", "session changed; authenticate again")
		return
	}
	if r.Method == http.MethodPost {
		if err := h.checkCSRFFor(r, id); err != nil {
			h.writeError(w, http.StatusForbidden, "csrf_invalid", "CSRF validation failed")
			return
		}
	}
	// Revocation and its audit/ledger entry are one transaction. A database
	// failure must not be reported as a successful logout, and must not emit a
	// false success audit.
	logoutReq := h.mutationRequest(r, id.User, "umc_logout", "session:"+id.Session.PublicID,
		"umc_logout", id.User.UserID, "logout")
	revokeErr := h.store.RevokeSession(logoutReq.Context(), id.Session.IDHash, h.now().Unix())
	if revokeErr != nil && !errors.Is(revokeErr, store.ErrAuthSessionUnknown) {
		h.writeError(w, http.StatusServiceUnavailable, "logout_failed", "session revocation failed; retry logout")
		return
	}
	if errors.Is(revokeErr, store.ErrAuthSessionUnknown) {
		// A concurrent logout may already have revoked it. Only report idempotent
		// success after proving the session row is actually revoked.
		sess, err := h.store.GetSession(r.Context(), id.Session.IDHash)
		if err != nil || sess.RevokedAt == nil {
			h.writeError(w, http.StatusServiceUnavailable, "logout_state_uncertain", "session state could not be confirmed")
			return
		}
	}
	h.clearCookies(w)
	writeNoContent(w)
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	id, err := h.authenticate(r, store.AuthSessionActive, store.AuthSessionTOTPPending, store.AuthSessionTOTPSetup)
	if err != nil {
		if errors.Is(err, ErrAuthUnavailable) {
			h.writeError(w, http.StatusServiceUnavailable, "auth_state_unavailable", "authentication state unavailable; retry")
			return
		}
		h.writeError(w, http.StatusUnauthorized, "unauthenticated", "authenticated session required")
		return
	}
	h.writeJSON(w, http.StatusOK, h.authUserView(r, id))
}

func (h *Handler) changePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	id, release, ok := h.requireActiveWrite(w, r)
	if !ok {
		return
	}
	defer release()
	if !h.limiter.allow("password:"+id.User.UserID, 0.2, 3) {
		h.writeError(w, http.StatusTooManyRequests, "rate_limited", "password rate limit exceeded")
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "invalid password request")
		return
	}
	if err := umcauth.ValidatePasswordPolicy(req.NewPassword); err != nil {
		h.writeError(w, http.StatusBadRequest, "weak_password", "new password does not meet policy")
		return
	}
	if err := h.withKDF(func() error {
		ok, err := umcauth.VerifyPassword(id.User.PasswordHash, req.CurrentPassword)
		if err == nil && !ok {
			return errors.New("wrong password")
		}
		return err
	}); err != nil {
		h.auditIdentity(r, id, "umc_password_change_failed", "user:"+id.User.UserID, "denied")
		h.writeError(w, http.StatusUnauthorized, "invalid_credentials", "current password is invalid")
		return
	}
	var hash string
	if err := h.withKDF(func() error {
		var err error
		hash, err = umcauth.HashPassword(req.NewPassword, umcauth.DefaultPasswordParams())
		return err
	}); err != nil {
		h.writeError(w, http.StatusServiceUnavailable, "kdf_busy", "authentication busy; retry")
		return
	}
	changeReq := h.mutationRequest(r, id.User, "umc_password_changed", "user:"+id.User.UserID,
		"umc_password_changed", id.User.UserID, "password")
	if err := h.store.SetAuthUserPassword(changeReq.Context(), id.User.UserID, hash, h.now().Unix()); err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal", "password update failed")
		return
	}
	h.clearCookies(w)
	h.writeJSON(w, http.StatusOK, map[string]any{"relogin_required": true})
}

func (h *Handler) regenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	id, release, ok := h.requireActiveWrite(w, r)
	if !ok {
		return
	}
	defer release()
	rotateReq := h.mutationRequest(r, id.User, "umc_recovery_codes_regenerated", "user:"+id.User.UserID,
		"umc_recovery_codes_rotated", id.User.UserID, "recovery-codes")
	codes, err := h.replaceRecoveryCodes(rotateReq.Context(), id.User.UserID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal", "recovery code generation failed")
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

func (h *Handler) listSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	id, err := h.authenticate(r, store.AuthSessionActive)
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "unauthenticated", "authenticated session required")
		return
	}
	items, err := h.store.ListUserSessions(r.Context(), id.User.UserID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal", "session list unavailable")
		return
	}
	out := make([]map[string]any, 0, len(items))
	for _, s := range items {
		out = append(out, sessionView(s, s.IDHash == id.Session.IDHash))
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

func sessionView(s store.AuthSession, current bool) map[string]any {
	return map[string]any{
		"session_id": s.PublicID, "state": s.State, "created_at": s.CreatedAt,
		"last_seen_at": s.LastSeenAt, "idle_expires_at": s.IdleExpiresAt,
		"absolute_expires_at": s.AbsoluteExpiresAt, "revoked_at": s.RevokedAt,
		"current": current,
	}
}

func (h *Handler) revokeOwnSession(w http.ResponseWriter, r *http.Request, publicID string) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	id, release, ok := h.requireActiveWrite(w, r)
	if !ok {
		return
	}
	defer release()
	if strings.TrimSpace(publicID) == "" || len(publicID) > 256 {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "invalid session id")
		return
	}
	sess, err := h.store.GetSessionByPublicID(r.Context(), publicID)
	if err != nil || sess.UserID != id.User.UserID {
		h.writeError(w, http.StatusNotFound, "not_found", "session not found")
		return
	}
	revokeReq := h.mutationRequest(r, id.User, "umc_session_revoked", "session:"+publicID,
		"umc_session_revoked", id.User.UserID, "revoke-session")
	if err := h.store.RevokeSessionByPublicID(revokeReq.Context(), publicID, h.now().Unix()); err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal", "session revoke failed")
		return
	}
	if sess.IDHash == id.Session.IDHash {
		h.clearCookies(w)
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"revoked": true})
}

// TOTP update is intentionally exposed through /auth/totp/update in addition to
// the router's verification action.
func (h *Handler) updateTOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	id, release, ok := h.requireActiveWrite(w, r)
	if !ok {
		return
	}
	defer release()
	var req struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "invalid TOTP update request")
		return
	}
	if err := h.withKDF(func() error {
		ok, err := umcauth.VerifyPassword(id.User.PasswordHash, req.Password)
		if err == nil && !ok {
			return errors.New("wrong password")
		}
		return err
	}); err != nil {
		h.auditIdentity(r, id, "umc_totp_update_failed", "user:"+id.User.UserID, "denied")
		h.writeError(w, http.StatusUnauthorized, "invalid_credentials", "current password is invalid")
		return
	}
	secret, err := umcauth.NewTOTPSecret()
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal", "TOTP setup unavailable")
		return
	}
	sealed, err := h.sealTOTP(id.User.UserID, secret)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal", "TOTP setup unavailable")
		return
	}
	uri, _ := umcauth.OtpauthURI("UM Center", id.User.Username, secret)
	csrf, err := h.rotateSession(r.Context(), w, id, store.AuthSessionTOTPSetup, sealed)
	if err != nil {
		if errors.Is(err, store.ErrAuthStale) || errors.Is(err, store.ErrAuthSessionUnknown) {
			h.writeError(w, http.StatusUnauthorized, "credentials_changed", "account security state changed; authenticate again")
			return
		}
		h.writeError(w, http.StatusInternalServerError, "internal", "session unavailable")
		return
	}
	h.auditIdentity(r, id, "umc_totp_update_started", "user:"+id.User.UserID, "ok")
	h.writeJSON(w, http.StatusOK, map[string]any{"totp_setup_required": true, "csrf_token": csrf,
		"secret": secret, "otpauth_uri": uri})
}

func (h *Handler) routeTOTPUpdate(w http.ResponseWriter, r *http.Request) {
	h.updateTOTP(w, r)
}

var _ = context.Background
var _ = time.Now

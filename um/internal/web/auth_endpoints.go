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
		h.writeError(w, http.StatusUnauthorized, "unauthenticated", "authenticated session required")
		return
	}
	if r.Method == http.MethodPost {
		if err := h.checkCSRFFor(r, id); err != nil {
			h.writeError(w, http.StatusForbidden, "csrf_invalid", "CSRF validation failed")
			return
		}
	}
	_ = h.store.RevokeSession(r.Context(), id.Session.IDHash, h.now().Unix())
	h.auditIdentity(r, id, "umc_logout", "session", "ok")
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
	id, ok := h.requireActive(w, r)
	if !ok {
		return
	}
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
	id, ok := h.requireActive(w, r)
	if !ok {
		return
	}
	codes, err := h.replaceRecoveryCodes(r.Context(), id.User.UserID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal", "recovery code generation failed")
		return
	}
	h.auditIdentity(r, id, "umc_recovery_codes_regenerated", "user:"+id.User.UserID, "ok")
	_ = h.recordLedger(r.Context(), "umc_recovery_codes_rotated", id.User.UserID, "recovery-codes")
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
	id, ok := h.requireActive(w, r)
	if !ok {
		return
	}
	if strings.TrimSpace(publicID) == "" || len(publicID) > 256 {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "invalid session id")
		return
	}
	sess, err := h.store.GetSessionByPublicID(r.Context(), publicID)
	if err != nil || sess.UserID != id.User.UserID {
		h.writeError(w, http.StatusNotFound, "not_found", "session not found")
		return
	}
	if err := h.store.RevokeSessionByPublicID(r.Context(), publicID, h.now().Unix()); err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal", "session revoke failed")
		return
	}
	h.auditIdentity(r, id, "umc_session_revoked", "session", "ok")
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
	id, ok := h.requireActive(w, r)
	if !ok {
		return
	}
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

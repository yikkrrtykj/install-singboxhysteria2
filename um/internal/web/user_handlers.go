package web

import (
	"errors"
	"net/http"
	"strings"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/management"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/umcauth"
)

func (h *Handler) serveWebAPI(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/web/api/"), "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		h.writeError(w, http.StatusNotFound, "endpoint_not_found", "unknown endpoint")
		return
	}
	switch parts[0] {
	case "users":
		h.routeUsers(w, r, parts[1:])
	case "status":
		if r.Method != http.MethodGet {
			h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		id, ok := h.requireActive(w, r)
		if !ok {
			return
		}
		h.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user": toUserView(id.User)})
	default:
		h.writeError(w, http.StatusNotFound, "endpoint_not_found", "unknown endpoint")
	}
}

func (h *Handler) requirePlatformAdmin(w http.ResponseWriter, r *http.Request) (*identity, bool) {
	id, ok := h.requireActive(w, r)
	if !ok {
		return nil, false
	}
	if id.Principal.Role != management.RolePlatformAdmin {
		h.auditIdentity(r, id, "umc_user_admin_denied", "user_admin", "denied")
		h.writeError(w, http.StatusForbidden, "forbidden", "platform_admin required")
		return nil, false
	}
	return id, true
}

func (h *Handler) routeUsers(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) == 0 {
		switch r.Method {
		case http.MethodGet:
			h.listUsers(w, r)
		case http.MethodPost:
			h.createUser(w, r)
		default:
			h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		}
		return
	}
	userID := parts[0]
	if strings.TrimSpace(userID) == "" || len(userID) > 128 {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "invalid user id")
		return
	}
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		h.showUser(w, r, userID)
		return
	}
	action := parts[1]
	if len(parts) == 2 {
		switch action {
		case "disable", "enable", "reset-password", "role":
			if r.Method != http.MethodPost {
				h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
				return
			}
			switch action {
			case "disable":
				h.setUserEnabled(w, r, userID, false)
			case "enable":
				h.setUserEnabled(w, r, userID, true)
			case "reset-password":
				h.resetUserPassword(w, r, userID)
			case "role":
				h.setUserRole(w, r, userID)
			}
			return
		}
	}
	if action == "sessions" && len(parts) == 2 && r.Method == http.MethodGet {
		h.listUserSessions(w, r, userID)
		return
	}
	if action == "sessions" && len(parts) == 4 && parts[3] == "revoke" && r.Method == http.MethodPost {
		h.revokeUserSession(w, r, userID, parts[2])
		return
	}
	h.writeError(w, http.StatusNotFound, "endpoint_not_found", "unknown endpoint")
}

func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.requirePlatformAdmin(w, r)
	if !ok {
		return
	}
	users, err := h.store.ListAuthUsers(r.Context())
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal", "user list unavailable")
		return
	}
	out := make([]userView, 0, len(users))
	for _, u := range users {
		out = append(out, toUserView(u))
	}
	h.auditIdentity(r, actor, "umc_users_listed", "user_admin", "ok")
	h.writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

func (h *Handler) showUser(w http.ResponseWriter, r *http.Request, userID string) {
	actor, ok := h.requirePlatformAdmin(w, r)
	if !ok {
		return
	}
	u, err := h.store.GetAuthUserByID(r.Context(), userID)
	if err != nil {
		h.writeError(w, http.StatusNotFound, "not_found", "user not found")
		return
	}
	_, unused, _ := h.store.CountRecoveryCodes(r.Context(), userID)
	h.auditIdentity(r, actor, "umc_user_viewed", "user:"+userID, "ok")
	view := toUserView(u)
	h.writeJSON(w, http.StatusOK, map[string]any{"user": view, "recovery_codes_unused": unused})
}

func (h *Handler) createUser(w http.ResponseWriter, r *http.Request) {
	actor, release, ok := h.requireAdminActor(w, r)
	if !ok {
		return
	}
	defer release()
	var req struct {
		Username string   `json:"username"`
		Role     string   `json:"role"`
		EventIDs []string `json:"event_ids"`
	}
	if err := decodeJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "invalid user request")
		return
	}
	if req.Role != store.AuthRoleEventAdmin && req.Role != store.AuthRoleViewer {
		// Additional platform_admin creation requires a separate Owner policy;
		// Web self-service expansion is deliberately refused.
		h.writeError(w, http.StatusBadRequest, "invalid_role", "Web can create only event_admin or viewer")
		return
	}
	password, err := umcauth.NewToken()
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal", "user creation unavailable")
		return
	}
	var hash string
	if err := h.withKDF(func() error {
		var err error
		hash, err = umcauth.HashPassword(password, umcauth.DefaultPasswordParams())
		return err
	}); err != nil {
		h.writeError(w, http.StatusServiceUnavailable, "kdf_busy", "authentication busy; retry")
		return
	}
	createReq := h.mutationRequest(r, actor.User, "umc_user_created", "user:"+req.Username,
		"umc_user_created", "user:"+req.Username, "create:"+req.Role)
	user, err := h.store.CreateAuthUser(createReq.Context(), store.AuthUserInput{
		Username: req.Username, PasswordHash: hash, Role: req.Role, EventIDs: req.EventIDs, Now: h.now().Unix(),
	})
	if err != nil {
		h.writeAuthStoreError(w, err)
		return
	}
	h.writeJSON(w, http.StatusCreated, map[string]any{"user": toUserView(user), "initial_password": password})
}

func (h *Handler) setUserEnabled(w http.ResponseWriter, r *http.Request, userID string, enabled bool) {
	actor, release, ok := h.requireAdminMutation(w, r, userID)
	if !ok {
		return
	}
	defer release()
	action := "umc_user_disabled"
	if enabled {
		action = "umc_user_enabled"
	}
	stateReq := h.mutationRequest(r, actor.User, action, "user:"+userID, action, userID, "enabled")
	if err := h.store.SetAuthUserEnabled(stateReq.Context(), userID, enabled, h.now().Unix()); err != nil {
		h.writeAuthStoreError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"user_id": userID, "enabled": enabled})
}

func (h *Handler) setUserRole(w http.ResponseWriter, r *http.Request, userID string) {
	actor, release, ok := h.requireAdminMutation(w, r, userID)
	if !ok {
		return
	}
	defer release()
	var req struct {
		Role     string   `json:"role"`
		EventIDs []string `json:"event_ids"`
	}
	if err := decodeJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "invalid role request")
		return
	}
	if req.Role == store.AuthRolePlatformAdmin {
		h.writeError(w, http.StatusBadRequest, "invalid_role", "platform_admin expansion requires Owner policy")
		return
	}
	roleReq := h.mutationRequest(r, actor.User, "umc_user_scope_changed", "user:"+userID,
		"umc_user_scope_changed", userID, req.Role)
	if err := h.store.SetAuthUserRoleAndScopes(roleReq.Context(), userID, req.Role, req.EventIDs, h.now().Unix()); err != nil {
		h.writeAuthStoreError(w, err)
		return
	}
	u, _ := h.store.GetAuthUserByID(r.Context(), userID)
	h.writeJSON(w, http.StatusOK, map[string]any{"user": toUserView(u)})
}

func (h *Handler) resetUserPassword(w http.ResponseWriter, r *http.Request, userID string) {
	actor, release, ok := h.requireAdminMutation(w, r, userID)
	if !ok {
		return
	}
	defer release()
	if _, err := h.store.GetAuthUserByID(r.Context(), userID); err != nil {
		h.writeError(w, http.StatusNotFound, "not_found", "user not found")
		return
	}
	password, err := umcauth.NewToken()
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal", "password reset unavailable")
		return
	}
	var hash string
	if err := h.withKDF(func() error {
		var err error
		hash, err = umcauth.HashPassword(password, umcauth.DefaultPasswordParams())
		return err
	}); err != nil {
		h.writeError(w, http.StatusServiceUnavailable, "kdf_busy", "authentication busy; retry")
		return
	}
	resetReq := h.mutationRequest(r, actor.User, "umc_user_password_reset", "user:"+userID,
		"umc_user_password_reset", userID, "admin-reset")
	if err := h.store.SetAuthUserPassword(resetReq.Context(), userID, hash, h.now().Unix()); err != nil {
		h.writeAuthStoreError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"user_id": userID, "temporary_password": password,
		"relogin_required": true})
}

func (h *Handler) listUserSessions(w http.ResponseWriter, r *http.Request, userID string) {
	actor, ok := h.requirePlatformAdmin(w, r)
	if !ok {
		return
	}
	items, err := h.store.ListUserSessions(r.Context(), userID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal", "session list unavailable")
		return
	}
	out := make([]map[string]any, 0, len(items))
	for _, s := range items {
		out = append(out, sessionView(s, false))
	}
	h.auditIdentity(r, actor, "umc_user_sessions_listed", "user:"+userID, "ok")
	h.writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

func (h *Handler) revokeUserSession(w http.ResponseWriter, r *http.Request, userID, publicID string) {
	actor, release, ok := h.requireAdminMutation(w, r, userID)
	if !ok {
		return
	}
	defer release()
	sess, err := h.store.GetSessionByPublicID(r.Context(), publicID)
	if err != nil || sess.UserID != userID {
		h.writeError(w, http.StatusNotFound, "not_found", "session not found")
		return
	}
	revokeReq := h.mutationRequest(r, actor.User, "umc_user_session_revoked", "user:"+userID,
		"umc_user_session_revoked", userID, "revoke-session")
	if err := h.store.RevokeSessionByPublicID(revokeReq.Context(), publicID, h.now().Unix()); err != nil {
		if !errors.Is(err, store.ErrAuthSessionUnknown) {
			h.writeError(w, http.StatusServiceUnavailable, "revoke_failed", "session revoke failed; retry")
			return
		}
		already, getErr := h.store.GetSessionByPublicID(r.Context(), publicID)
		if getErr != nil || already.RevokedAt == nil || already.UserID != userID {
			h.writeError(w, http.StatusServiceUnavailable, "revoke_state_uncertain", "session state could not be confirmed")
			return
		}
		h.writeJSON(w, http.StatusOK, map[string]any{"revoked": true, "already_revoked": true})
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"revoked": true})
}

func (h *Handler) writeAuthStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrAuthUserExists):
		h.writeError(w, http.StatusConflict, "user_exists", "username already exists")
	case errors.Is(err, store.ErrAuthUserUnknown), errors.Is(err, store.ErrAuthSessionUnknown):
		h.writeError(w, http.StatusNotFound, "not_found", "resource not found")
	case errors.Is(err, store.ErrAuthLastPlatformAdmin):
		h.writeError(w, http.StatusConflict, "last_platform_admin", "cannot remove the last enabled platform admin")
	case errors.Is(err, store.ErrAuthAlreadyBootstrapped):
		h.writeError(w, http.StatusConflict, "already_initialized", "authentication is already initialized")
	default:
		h.writeError(w, http.StatusBadRequest, "invalid_request", "request could not be applied")
	}
}

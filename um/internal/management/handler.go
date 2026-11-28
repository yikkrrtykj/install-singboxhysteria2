package management

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
)

// Authenticator resolves a trusted local principal from the request credential.
// Production uses FileAuthenticator; tests may inject a trusted resolver.
// Handlers never read a role/header/query-supplied principal directly.
type Authenticator interface {
	Authenticate(*http.Request) (Principal, error)
}

// Handler serves the versioned admin API. It is mounted on the isolated admin
// listener and never on the ingest listener.
type Handler struct {
	svc  *Service
	auth Authenticator
}

func NewHandler(svc *Service, auth Authenticator) (*Handler, error) {
	if svc == nil {
		return nil, errors.New("management: service is required")
	}
	return &Handler{svc: svc, auth: auth}, nil
}

const maxAdminBody = 1 << 20

type successBody struct {
	V    int `json:"v"`
	Data any `json:"data"`
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	w.Header().Set("X-Request-ID", requestID)
	w.Header().Set("Cache-Control", "no-store")
	if h.auth == nil {
		h.writeError(w, http.StatusServiceUnavailable, "admin_auth_unavailable", "management authentication is not configured", false, requestID)
		return
	}
	principal, err := h.auth.Authenticate(r)
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "unauthenticated", "valid local admin credential required", false, requestID)
		return
	}
	ctx := withRequestID(r.Context(), requestID)
	path := r.URL.Path
	if !strings.HasPrefix(path, "/api/v1/") {
		h.writeError(w, http.StatusNotFound, "endpoint_not_found", "unknown endpoint", false, requestID)
		return
	}
	parts := strings.Split(strings.TrimPrefix(path, "/api/v1/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		h.writeError(w, http.StatusNotFound, "endpoint_not_found", "unknown endpoint", false, requestID)
		return
	}
	switch parts[0] {
	case "health":
		if len(parts) != 1 {
			h.writeError(w, http.StatusNotFound, "endpoint_not_found", "unknown endpoint", false, requestID)
			return
		}
		h.requireMethod(w, r, requestID, http.MethodGet)
		if r.Method == http.MethodGet {
			h.writeJSON(w, http.StatusOK, h.svc.Health(ctx, principal))
		}
	case "events":
		h.routeEvents(ctx, w, r, principal, parts, requestID)
	case "retention":
		h.routeRetention(ctx, w, r, principal, parts, requestID)
	case "capacity":
		h.requireMethod(w, r, requestID, http.MethodGet)
		if r.Method == http.MethodGet {
			v, err := h.svc.Capacity(ctx, principal)
			h.respond(w, err, v, requestID)
		}
	case "audit":
		h.routeAudit(ctx, w, r, principal, parts, requestID)
	default:
		h.writeError(w, http.StatusNotFound, "endpoint_not_found", "unknown endpoint", false, requestID)
	}
}

func (h *Handler) routeEvents(ctx context.Context, w http.ResponseWriter, r *http.Request, p Principal, parts []string, requestID string) {
	switch len(parts) {
	case 1:
		switch r.Method {
		case http.MethodGet:
			state := r.URL.Query().Get("state")
			limit, offset, err := page(r)
			if err != nil {
				h.writeError(w, http.StatusBadRequest, "invalid_request", err.Error(), false, requestID)
				return
			}
			v, err := h.svc.ListEvents(ctx, p, state, limit, offset)
			h.respond(w, err, v, requestID)
		case http.MethodPost:
			var req struct {
				EventID     string `json:"event_id"`
				DisplayName string `json:"display_name"`
			}
			if err := h.decode(w, r, &req); err != nil {
				if errors.Is(err, errAdminBodyTooLarge) {
					h.writeError(w, http.StatusRequestEntityTooLarge, "invalid_request", "request body too large", false, requestID)
					return
				}
				h.writeError(w, http.StatusBadRequest, "invalid_request", err.Error(), false, requestID)
				return
			}
			v, err := h.svc.CreateEvent(ctx, p, req.EventID, req.DisplayName)
			h.respondStatus(w, err, v, http.StatusCreated, requestID)
		default:
			h.methodNotAllowed(w, requestID)
		}
		return
	case 2:
		eventID := parts[1]
		switch r.Method {
		case http.MethodGet:
			v, err := h.svc.GetEvent(ctx, p, eventID)
			h.respond(w, err, v, requestID)
		case http.MethodPatch:
			var req struct {
				DisplayName string `json:"display_name"`
			}
			if err := h.decode(w, r, &req); err != nil {
				if errors.Is(err, errAdminBodyTooLarge) {
					h.writeError(w, http.StatusRequestEntityTooLarge, "invalid_request", "request body too large", false, requestID)
					return
				}
				h.writeError(w, http.StatusBadRequest, "invalid_request", err.Error(), false, requestID)
				return
			}
			v, err := h.svc.RenameEvent(ctx, p, eventID, req.DisplayName)
			h.respond(w, err, v, requestID)
		default:
			h.methodNotAllowed(w, requestID)
		}
		return
	}
	resource := parts[2]
	switch resource {
	case "archive":
		if len(parts) != 3 || r.Method != http.MethodPost {
			h.methodNotAllowed(w, requestID)
			return
		}
		err := h.svc.ArchiveEvent(ctx, p, parts[1])
		h.respond(w, err, map[string]any{"event_id": parts[1], "state": "archived"}, requestID)
	case "purge":
		if len(parts) != 4 {
			h.writeError(w, http.StatusNotFound, "endpoint_not_found", "unknown endpoint", false, requestID)
			return
		}
		switch parts[3] {
		case "preview":
			if r.Method != http.MethodGet {
				h.methodNotAllowed(w, requestID)
				return
			}
			v, err := h.svc.PurgePreview(ctx, p, parts[1])
			h.respond(w, err, v, requestID)
		case "confirm":
			if r.Method != http.MethodPost {
				h.methodNotAllowed(w, requestID)
				return
			}
			var req struct {
				Confirmation string `json:"confirmation"`
			}
			if err := h.decode(w, r, &req); err != nil {
				if errors.Is(err, errAdminBodyTooLarge) {
					h.writeError(w, http.StatusRequestEntityTooLarge, "invalid_request", "request body too large", false, requestID)
					return
				}
				h.writeError(w, http.StatusBadRequest, "invalid_request", err.Error(), false, requestID)
				return
			}
			v, err := h.svc.PurgeConfirm(ctx, p, parts[1], req.Confirmation)
			h.respond(w, err, v, requestID)
		case "status":
			if r.Method != http.MethodGet {
				h.methodNotAllowed(w, requestID)
				return
			}
			v, err := h.svc.PurgeStatus(ctx, p, parts[1])
			h.respond(w, err, v, requestID)
		default:
			h.writeError(w, http.StatusNotFound, "endpoint_not_found", "unknown endpoint", false, requestID)
		}
	case "nodes":
		h.routeNodes(ctx, w, r, p, parts, requestID)
	case "tokens":
		h.routeTokens(ctx, w, r, p, parts, requestID)
	case "aliases":
		h.routeAliases(ctx, w, r, p, parts, requestID)
	case "mapping":
		h.routeMapping(ctx, w, r, p, parts, requestID)
	default:
		h.writeError(w, http.StatusNotFound, "endpoint_not_found", "unknown endpoint", false, requestID)
	}
}

func (h *Handler) routeNodes(ctx context.Context, w http.ResponseWriter, r *http.Request, p Principal, parts []string, requestID string) {
	// /events/{id}/nodes, /nodes/{node}, /nodes/{node}/revoke, /nodes/{node}/config[/history]
	if len(parts) == 3 {
		if r.Method != http.MethodGet {
			h.methodNotAllowed(w, requestID)
			return
		}
		limit, offset, err := page(r)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, "invalid_request", err.Error(), false, requestID)
			return
		}
		v, err := h.svc.ListNodes(ctx, p, parts[1], r.URL.Query().Get("class"), r.URL.Query().Get("state"), limit, offset)
		h.respond(w, err, v, requestID)
		return
	}
	nodeID := parts[3]
	if len(parts) == 4 {
		if r.Method != http.MethodGet {
			h.methodNotAllowed(w, requestID)
			return
		}
		v, err := h.svc.GetNode(ctx, p, parts[1], nodeID)
		h.respond(w, err, v, requestID)
		return
	}
	if len(parts) == 5 && parts[4] == "revoke" {
		if r.Method != http.MethodPost {
			h.methodNotAllowed(w, requestID)
			return
		}
		err := h.svc.RevokeNode(ctx, p, parts[1], nodeID)
		h.respond(w, err, map[string]any{"node_id": nodeID, "state": "revoked"}, requestID)
		return
	}
	if len(parts) == 5 && parts[4] == "config" {
		switch r.Method {
		case http.MethodGet:
			v, err := h.svc.GetConfig(ctx, p, parts[1], nodeID)
			h.respond(w, err, v, requestID)
		case http.MethodPut:
			var req struct {
				CadenceSeconds      int              `json:"cadence_seconds"`
				Sources             map[string]bool  `json:"sources"`
				ExpectedInboundTags []InboundTagView `json:"expected_inbound_tags"`
			}
			if err := h.decode(w, r, &req); err != nil {
				if errors.Is(err, errAdminBodyTooLarge) {
					h.writeError(w, http.StatusRequestEntityTooLarge, "invalid_request", "request body too large", false, requestID)
					return
				}
				h.writeError(w, http.StatusBadRequest, "invalid_request", err.Error(), false, requestID)
				return
			}
			tags := make([]store.InboundTag, 0, len(req.ExpectedInboundTags))
			for _, t := range req.ExpectedInboundTags {
				tags = append(tags, store.InboundTag{InboundTag: t.InboundTag, Kind: t.Kind})
			}
			v, err := h.svc.UpdateConfig(ctx, p, parts[1], nodeID, req.CadenceSeconds, req.Sources, tags)
			h.respond(w, err, v, requestID)
		default:
			h.methodNotAllowed(w, requestID)
		}
		return
	}
	if len(parts) == 6 && parts[4] == "config" && parts[5] == "history" {
		if r.Method != http.MethodGet {
			h.methodNotAllowed(w, requestID)
			return
		}
		v, err := h.svc.ConfigHistory(ctx, p, parts[1], nodeID)
		h.respond(w, err, v, requestID)
		return
	}
	h.writeError(w, http.StatusNotFound, "endpoint_not_found", "unknown endpoint", false, requestID)
}

func (h *Handler) routeTokens(ctx context.Context, w http.ResponseWriter, r *http.Request, p Principal, parts []string, requestID string) {
	if len(parts) == 3 {
		switch r.Method {
		case http.MethodGet:
			limit, offset, err := page(r)
			if err != nil {
				h.writeError(w, http.StatusBadRequest, "invalid_request", err.Error(), false, requestID)
				return
			}
			items, total, err := h.svc.ListTokens(ctx, p, parts[1], limit, offset)
			if err != nil {
				h.respond(w, err, nil, requestID)
				return
			}
			h.writeJSON(w, http.StatusOK, map[string]any{"tokens": items, "total": total, "limit": limit, "offset": offset})
		case http.MethodPost:
			var req struct {
				NodeClass  string `json:"node_class"`
				TTLSeconds int    `json:"ttl_seconds"`
			}
			if err := h.decode(w, r, &req); err != nil {
				if errors.Is(err, errAdminBodyTooLarge) {
					h.writeError(w, http.StatusRequestEntityTooLarge, "invalid_request", "request body too large", false, requestID)
					return
				}
				h.writeError(w, http.StatusBadRequest, "invalid_request", err.Error(), false, requestID)
				return
			}
			v, err := h.svc.CreateToken(ctx, p, parts[1], req.NodeClass, req.TTLSeconds)
			h.respondStatus(w, err, v, http.StatusCreated, requestID)
		default:
			h.methodNotAllowed(w, requestID)
		}
		return
	}
	if len(parts) == 4 {
		if r.Method != http.MethodGet {
			h.methodNotAllowed(w, requestID)
			return
		}
		v, err := h.svc.GetToken(ctx, p, parts[1], parts[3])
		h.respond(w, err, v, requestID)
		return
	}
	if len(parts) == 5 && parts[4] == "revoke" {
		if r.Method != http.MethodPost {
			h.methodNotAllowed(w, requestID)
			return
		}
		err := h.svc.RevokeToken(ctx, p, parts[1], parts[3])
		h.respond(w, err, map[string]any{"token_id": parts[3], "status": "revoked"}, requestID)
		return
	}
	h.writeError(w, http.StatusNotFound, "endpoint_not_found", "unknown endpoint", false, requestID)
}

func (h *Handler) routeAliases(ctx context.Context, w http.ResponseWriter, r *http.Request, p Principal, parts []string, requestID string) {
	if len(parts) == 3 && r.Method == http.MethodGet {
		v, err := h.svc.ListAliases(ctx, p, parts[1], r.URL.Query().Get("target_type"))
		h.respond(w, err, v, requestID)
		return
	}
	if len(parts) == 5 {
		targetType, targetKey := parts[3], parts[4]
		switch r.Method {
		case http.MethodPut:
			var req struct {
				DisplayName     string `json:"display_name"`
				ExpectedVersion *int64 `json:"expected_version"`
			}
			if err := h.decode(w, r, &req); err != nil {
				if errors.Is(err, errAdminBodyTooLarge) {
					h.writeError(w, http.StatusRequestEntityTooLarge, "invalid_request", "request body too large", false, requestID)
					return
				}
				h.writeError(w, http.StatusBadRequest, "invalid_request", err.Error(), false, requestID)
				return
			}
			v, err := h.svc.SetAlias(ctx, p, parts[1], targetType, targetKey, req.DisplayName, req.ExpectedVersion)
			h.respond(w, err, v, requestID)
		case http.MethodDelete:
			err := h.svc.DeleteAlias(ctx, p, parts[1], targetType, targetKey)
			h.respond(w, err, map[string]any{"deleted": true}, requestID)
		default:
			h.methodNotAllowed(w, requestID)
		}
		return
	}
	h.writeError(w, http.StatusNotFound, "endpoint_not_found", "unknown endpoint", false, requestID)
}

func (h *Handler) routeMapping(ctx context.Context, w http.ResponseWriter, r *http.Request, p Principal, parts []string, requestID string) {
	if len(parts) == 4 {
		switch r.Method {
		case http.MethodGet:
			v, err := h.svc.ListMapping(ctx, p, parts[1], parts[3])
			h.respond(w, err, v, requestID)
		case http.MethodPost:
			var req struct {
				Version       int                `json:"version"`
				EffectiveFrom int64              `json:"effective_from"`
				Entries       []MappingEntryView `json:"entries"`
			}
			if err := h.decode(w, r, &req); err != nil {
				if errors.Is(err, errAdminBodyTooLarge) {
					h.writeError(w, http.StatusRequestEntityTooLarge, "invalid_request", "request body too large", false, requestID)
					return
				}
				h.writeError(w, http.StatusBadRequest, "invalid_request", err.Error(), false, requestID)
				return
			}
			entries := make(map[string]string, len(req.Entries))
			for _, e := range req.Entries {
				if _, exists := entries[e.RouteToken]; exists {
					h.writeError(w, http.StatusBadRequest, "invalid_request", "duplicate route token", false, requestID)
					return
				}
				entries[e.RouteToken] = e.TargetNodeID
			}
			err := h.svc.CreateMapping(ctx, p, parts[1], parts[3], req.Version, req.EffectiveFrom, entries)
			h.respondStatus(w, err, map[string]any{"created": err == nil}, http.StatusCreated, requestID)
		default:
			h.methodNotAllowed(w, requestID)
		}
		return
	}
	if len(parts) == 5 && parts[4] == "resolve" {
		if r.Method != http.MethodGet {
			h.methodNotAllowed(w, requestID)
			return
		}
		at := int64(0)
		if raw := r.URL.Query().Get("at"); raw != "" {
			v, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || v <= 0 {
				h.writeError(w, http.StatusBadRequest, "invalid_request", "at must be a positive epoch second", false, requestID)
				return
			}
			at = v
		}
		v, err := h.svc.ResolveMapping(ctx, p, parts[1], parts[3], at)
		h.respond(w, err, v, requestID)
		return
	}
	h.writeError(w, http.StatusNotFound, "endpoint_not_found", "unknown endpoint", false, requestID)
}

func (h *Handler) routeRetention(ctx context.Context, w http.ResponseWriter, r *http.Request, p Principal, parts []string, requestID string) {
	if len(parts) != 2 {
		h.writeError(w, http.StatusNotFound, "endpoint_not_found", "unknown endpoint", false, requestID)
		return
	}
	switch parts[1] {
	case "state":
		if r.Method != http.MethodGet {
			h.methodNotAllowed(w, requestID)
			return
		}
		v, err := h.svc.RetentionState(ctx, p)
		h.respond(w, err, v, requestID)
	case "timeline":
		if r.Method != http.MethodGet {
			h.methodNotAllowed(w, requestID)
			return
		}
		v, err := h.svc.RetentionTimeline(ctx, p)
		h.respond(w, err, v, requestID)
	case "run":
		if r.Method != http.MethodPost {
			h.methodNotAllowed(w, requestID)
			return
		}
		counts, err := h.svc.RunRetention(ctx, p)
		h.respond(w, err, counts, requestID)
	case "runs":
		if r.Method != http.MethodGet {
			h.methodNotAllowed(w, requestID)
			return
		}
		limit, _, err := page(r)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, "invalid_request", err.Error(), false, requestID)
			return
		}
		v, err := h.svc.RetentionRuns(ctx, p, limit)
		h.respond(w, err, v, requestID)
	default:
		h.writeError(w, http.StatusNotFound, "endpoint_not_found", "unknown endpoint", false, requestID)
	}
}

func (h *Handler) routeAudit(ctx context.Context, w http.ResponseWriter, r *http.Request, p Principal, parts []string, requestID string) {
	if r.Method != http.MethodGet {
		h.methodNotAllowed(w, requestID)
		return
	}
	if len(parts) == 2 && parts[1] == "verify" {
		err := h.svc.VerifyLedger(ctx, p)
		h.respond(w, err, map[string]any{"verified": err == nil}, requestID)
		return
	}
	if len(parts) != 1 {
		h.writeError(w, http.StatusNotFound, "endpoint_not_found", "unknown endpoint", false, requestID)
		return
	}
	limit, offset, err := page(r)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", err.Error(), false, requestID)
		return
	}
	since, err := auditTime(r, "since")
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", err.Error(), false, requestID)
		return
	}
	until, err := auditTime(r, "until")
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", err.Error(), false, requestID)
		return
	}
	v, err := h.svc.ListAudit(ctx, p, r.URL.Query().Get("event_id"), r.URL.Query().Get("action"),
		r.URL.Query().Get("result"), r.URL.Query().Get("actor"), since, until, limit, offset)
	h.respond(w, err, v, requestID)
}

func auditTime(r *http.Request, name string) (int64, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return 0, nil
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("%s must be a non-negative Unix second", name)
	}
	return v, nil
}

func (h *Handler) requireMethod(w http.ResponseWriter, r *http.Request, requestID, method string) {
	if r.Method != method {
		h.methodNotAllowed(w, requestID)
	}
}

func (h *Handler) methodNotAllowed(w http.ResponseWriter, requestID string) {
	h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", false, requestID)
}

func page(r *http.Request) (int, int, error) {
	limit, offset := 0, 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 1 || v > maxPageLimit {
			return 0, 0, errors.New("limit must be in [1,100]")
		}
		limit = v
	}
	if raw := r.URL.Query().Get("offset"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 0 || v > 100000 {
			return 0, 0, errors.New("offset must be in [0,100000]")
		}
		offset = v
	}
	return limit, offset, nil
}

var errAdminBodyTooLarge = errors.New("admin request body exceeds 1 MiB")

func (h *Handler) decode(w http.ResponseWriter, r *http.Request, dst any) error {
	ct := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	if ct != "application/json" {
		return errors.New("Content-Type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return errAdminBodyTooLarge
		}
		return errors.New("invalid JSON body")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return errAdminBodyTooLarge
		}
		return errors.New("invalid JSON body")
	}
	return nil
}

// respond writes a service result with the standard admin error mapping.
func (h *Handler) respond(w http.ResponseWriter, err error, data any, requestID string) {
	h.respondStatus(w, err, data, http.StatusOK, requestID)
}

func (h *Handler) respondStatus(w http.ResponseWriter, err error, data any, okStatus int, requestID string) {
	if err != nil {
		h.writeServiceError(w, err, requestID)
		return
	}
	h.writeJSON(w, okStatus, data)
}

func (h *Handler) writeServiceError(w http.ResponseWriter, err error, requestID string) {
	var inv *InvalidError
	switch {
	case errors.As(err, &inv):
		h.writeError(w, http.StatusBadRequest, "invalid_request", "invalid "+inv.Field, false, requestID)
	case errors.Is(err, ErrUnauthenticated):
		h.writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication required", false, requestID)
	case errors.Is(err, ErrForbidden):
		h.writeError(w, http.StatusForbidden, "forbidden", "action not permitted", false, requestID)
	case errors.Is(err, ErrNotFound):
		h.writeError(w, http.StatusNotFound, "not_found", "resource not found", false, requestID)
	case errors.Is(err, ErrConflict):
		h.writeError(w, http.StatusConflict, "conflict", "resource conflict", false, requestID)
	case errors.Is(err, ErrArchived):
		h.writeError(w, http.StatusConflict, "event_archived", "event is archived", false, requestID)
	case errors.Is(err, ErrPurged):
		h.writeError(w, http.StatusGone, "event_purged", "event is permanently purged", false, requestID)
	case errors.Is(err, ErrPurging):
		h.writeError(w, http.StatusConflict, "event_purging", "event purge in progress", false, requestID)
	case errors.Is(err, ErrQuota):
		h.writeError(w, http.StatusServiceUnavailable, "quota_exceeded", "capacity quota exceeded", false, requestID)
	case errors.Is(err, ErrAuditUnavailable):
		h.writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "audit storage unavailable", true, requestID)
	default:
		h.writeError(w, http.StatusInternalServerError, "internal_error", "request failed", false, requestID)
	}
}

func (h *Handler) writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(successBody{V: 1, Data: data})
}

func (h *Handler) writeError(w http.ResponseWriter, status int, code, message string, retryable bool, requestID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorBody{V: 1, Error: ErrorCode{Code: code, Message: message, Retryable: retryable}, RequestID: requestID})
}

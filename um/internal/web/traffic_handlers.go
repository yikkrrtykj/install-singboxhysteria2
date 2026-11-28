package web

// Bounded UM-C read-only traffic query API.
//
// Both routes are GET-only, live on the Web (browser) plane behind Cloudflare
// Access, and additionally require an active local session (requireActive) with
// the same role/event scoping as the B4 read API:
//
//   - viewer:     read-only, only its assigned events;
//   - event_admin: only its assigned events;
//   - platform_admin: all events.
//
// The event scope is resolved into SQL predicates by the store query methods; no
// query text, table name or order clause is caller-controlled. Times are
// observed_at (the traffic clock), never received_at, so a late/offline replay is
// ordered by when it was observed. Ranges are capped at 30 days and rows at 2000.

import (
	"net/http"
	"regexp"
	"strconv"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/management"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
)

const (
	trafficLatestPath  = "latest"
	trafficHistoryPath = "history"
)

var trafficInboundTagPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// trafficPointView is the normalized query row exposed by the API. Bytes are
// integers (never floats) and null means not observed.
type trafficPointView struct {
	EventID                         string   `json:"event_id"`
	NodeID                          string   `json:"node_id"`
	InboundTag                      string   `json:"inbound_tag"`
	Kind                            string   `json:"kind"`
	ObservedAt                      int64    `json:"observed_at"`
	CollectedAt                     int64    `json:"collected_at"`
	Availability                    string   `json:"availability"`
	Freshness                       string   `json:"freshness"`
	Quality                         string   `json:"quality"`
	SourceEpoch                     string   `json:"source_epoch"`
	Sequence                        int64    `json:"sequence"`
	CounterScope                    string   `json:"counter_scope"`
	Exactness                       string   `json:"exactness"`
	ActiveConnections               int64    `json:"active_connections"`
	UplinkObservedLowerBoundBytes   *int64   `json:"uplink_observed_lower_bound_bytes"`
	DownlinkObservedLowerBoundBytes *int64   `json:"downlink_observed_lower_bound_bytes"`
	UplinkObservedRateBps           *float64 `json:"uplink_observed_rate_bps"`
	DownlinkObservedRateBps         *float64 `json:"downlink_observed_rate_bps"`
	GapBeforeSeconds                *int64   `json:"gap_before_seconds"`
}

// trafficObservationStateView is the report-level latest observation header,
// including honest unavailable sentinels that carry no per-inbound rows.
type trafficObservationStateView struct {
	EventID           string   `json:"event_id"`
	NodeID            string   `json:"node_id"`
	SourceEpoch       string   `json:"source_epoch"`
	Sequence          int64    `json:"sequence"`
	ObservedAt        int64    `json:"observed_at"`
	CollectedAt       int64    `json:"collected_at"`
	Availability      string   `json:"availability"`
	Freshness         string   `json:"freshness"`
	ActiveConnections *int64   `json:"active_connections"`
	RateWindowSeconds *float64 `json:"rate_window_seconds"`
	CounterScope      string   `json:"counter_scope"`
	Exactness         string   `json:"exactness"`
}

type trafficResponse struct {
	Points       []trafficPointView            `json:"points"`
	Observations []trafficObservationStateView `json:"observations,omitempty"`
	Truncated    bool                          `json:"truncated"`
	Limit        int                           `json:"limit"`
	From         *int64                        `json:"from"`
	To           *int64                        `json:"to"`
}

func (h *Handler) routeTraffic(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) != 1 || (parts[0] != trafficLatestPath && parts[0] != trafficHistoryPath) {
		h.writeError(w, http.StatusNotFound, "endpoint_not_found", "unknown endpoint")
		return
	}
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	id, ok := h.requireActive(w, r)
	if !ok {
		return
	}
	history := parts[0] == trafficHistoryPath
	query, scope, eventFilter, ok := h.parseTrafficQuery(w, r, id, history)
	if !ok {
		return
	}
	query.EventID = eventFilter
	if history {
		points, truncated, err := h.store.QueryTrafficHistory(r.Context(), scope, query)
		if err != nil {
			if store.IsInvalidArgument(err) {
				h.writeError(w, http.StatusBadRequest, "invalid_request", "invalid traffic query")
				return
			}
			h.writeError(w, http.StatusInternalServerError, "internal", "traffic query unavailable")
			return
		}
		from, to := query.From, query.To
		h.writeJSON(w, http.StatusOK, trafficResponse{Points: trafficPointViews(points), Truncated: truncated,
			Limit: query.Limit, From: &from, To: &to})
		return
	}
	points, err := h.store.QueryLatestTraffic(r.Context(), scope, query)
	if err != nil {
		if store.IsInvalidArgument(err) {
			h.writeError(w, http.StatusBadRequest, "invalid_request", "invalid traffic query")
			return
		}
		h.writeError(w, http.StatusInternalServerError, "internal", "traffic query unavailable")
		return
	}
	states, err := h.store.QueryLatestTrafficStates(r.Context(), scope, query)
	if err != nil {
		if store.IsInvalidArgument(err) {
			h.writeError(w, http.StatusBadRequest, "invalid_request", "invalid traffic query")
			return
		}
		h.writeError(w, http.StatusInternalServerError, "internal", "traffic query unavailable")
		return
	}
	response := trafficResponse{Points: trafficPointViews(points),
		Observations: trafficObservationStateViews(states), Limit: query.Limit}
	if query.From > 0 {
		from := query.From
		response.From = &from
	}
	if query.To > 0 {
		to := query.To
		response.To = &to
	}
	h.writeJSON(w, http.StatusOK, response)
}

// parseTrafficQuery validates the bounded query parameters and resolves the
// caller's event authorization into a store SQL scope. It never echoes client
// input into SQL.
func (h *Handler) parseTrafficQuery(w http.ResponseWriter, r *http.Request, id *identity, history bool) (store.TrafficQuery, store.TrafficEventScope, string, bool) {
	var query store.TrafficQuery
	values := r.URL.Query()
	allowed := map[string]bool{
		"event_id": true, "node_id": true, "inbound_tag": true, "kind": true,
		"from": true, "to": true, "limit": true,
	}
	if history {
		allowed["step_seconds"] = true
	}
	for key, entries := range values {
		if !allowed[key] || len(entries) != 1 {
			h.writeError(w, http.StatusBadRequest, "invalid_request", "invalid traffic query parameter")
			return query, store.TrafficEventScope{}, "", false
		}
	}
	eventID := values.Get("event_id")
	if eventID != "" && !store.IsUUIDv4(eventID) {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "invalid event id")
		return query, store.TrafficEventScope{}, "", false
	}
	nodeID := values.Get("node_id")
	if nodeID != "" && !store.IsUUIDv4(nodeID) {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "invalid node id")
		return query, store.TrafficEventScope{}, "", false
	}
	query.NodeID = nodeID
	inboundTag := values.Get("inbound_tag")
	if inboundTag != "" && !trafficInboundTagPattern.MatchString(inboundTag) {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "invalid inbound tag")
		return query, store.TrafficEventScope{}, "", false
	}
	query.InboundTag = inboundTag
	kind := values.Get("kind")
	switch kind {
	case "", "reality", "hysteria2", "other":
		query.Kind = kind
	default:
		h.writeError(w, http.StatusBadRequest, "invalid_request", "invalid inbound kind")
		return query, store.TrafficEventScope{}, "", false
	}
	if raw := values.Get("from"); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value < 0 {
			h.writeError(w, http.StatusBadRequest, "invalid_request", "invalid from timestamp")
			return query, store.TrafficEventScope{}, "", false
		}
		query.From = value
	}
	if raw := values.Get("to"); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value < 0 {
			h.writeError(w, http.StatusBadRequest, "invalid_request", "invalid to timestamp")
			return query, store.TrafficEventScope{}, "", false
		}
		query.To = value
	}
	query.Limit = store.TrafficQueryDefaultLimit
	if raw := values.Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > store.TrafficQueryMaxLimit {
			h.writeError(w, http.StatusBadRequest, "invalid_request", "invalid limit")
			return query, store.TrafficEventScope{}, "", false
		}
		query.Limit = value
	}
	if history {
		if raw := values.Get("step_seconds"); raw != "" {
			value, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || value < 1 || value > store.TrafficQueryMaxStepSeconds {
				h.writeError(w, http.StatusBadRequest, "invalid_request", "invalid step_seconds")
				return query, store.TrafficEventScope{}, "", false
			}
			query.StepSeconds = value
		}
		if query.From == 0 || query.To == 0 {
			h.writeError(w, http.StatusBadRequest, "invalid_request", "history requires from and to")
			return query, store.TrafficEventScope{}, "", false
		}
	}

	// Event authorization. platform_admin is global; every other authenticated
	// role is restricted to its resolved event set. An explicit out-of-scope
	// event_id is a consistent 403 (never an existence oracle or empty 200).
	scope := store.TrafficEventScope{}
	if id.Principal.Role == management.RolePlatformAdmin {
		scope.AllEvents = true
	} else {
		if eventID != "" && !id.Principal.HasEvent(eventID) {
			h.auditIdentity(r, id, "umc_traffic_denied", "traffic", "denied")
			h.writeError(w, http.StatusForbidden, "forbidden", "event scope does not permit this traffic query")
			return query, store.TrafficEventScope{}, "", false
		}
		scope.EventIDs = id.Principal.AllowedEvents()
	}
	return query, scope, eventID, true
}

func trafficObservationStateViews(states []store.TrafficObservationState) []trafficObservationStateView {
	views := make([]trafficObservationStateView, 0, len(states))
	for _, state := range states {
		views = append(views, trafficObservationStateView{
			EventID: state.EventID, NodeID: state.NodeID, SourceEpoch: state.SourceEpoch,
			Sequence: state.Sequence, ObservedAt: state.ObservedAt, CollectedAt: state.CollectedAt,
			Availability: state.Availability, Freshness: state.Freshness,
			ActiveConnections: state.ActiveConnections, RateWindowSeconds: state.RateWindowSeconds,
			CounterScope: state.CounterScope, Exactness: state.Exactness,
		})
	}
	return views
}

func trafficPointViews(points []store.TrafficPoint) []trafficPointView {
	views := make([]trafficPointView, 0, len(points))
	for _, point := range points {
		views = append(views, trafficPointView{
			EventID: point.EventID, NodeID: point.NodeID, InboundTag: point.InboundTag, Kind: point.Kind,
			ObservedAt: point.ObservedAt, CollectedAt: point.CollectedAt,
			Availability: point.Availability, Freshness: point.Freshness, Quality: point.Quality,
			SourceEpoch: point.SourceEpoch, Sequence: point.Sequence,
			CounterScope: point.CounterScope, Exactness: point.Exactness,
			ActiveConnections:               point.ActiveConnections,
			UplinkObservedLowerBoundBytes:   point.UplinkObservedLowerBoundBytes,
			DownlinkObservedLowerBoundBytes: point.DownlinkObservedLowerBoundBytes,
			UplinkObservedRateBps:           point.UplinkObservedRateBps,
			DownlinkObservedRateBps:         point.DownlinkObservedRateBps,
			GapBeforeSeconds:                point.GapBeforeSeconds,
		})
	}
	return views
}

package management

// RouteInfo is one documented admin API operation. The OpenAPI specification
// and the handler route table are checked against this inventory by tests so a
// new endpoint cannot be documented or implemented silently out of sync.
type RouteInfo struct {
	Method string
	Path   string
}

// AdminRouteInventory returns the closed set of B4 management API operations.
func AdminRouteInventory() []RouteInfo {
	return []RouteInfo{
		{Method: "DELETE", Path: "/api/v1/events/{event_id}/aliases/{target_type}/{target_key}"},
		{Method: "GET", Path: "/api/v1/audit"},
		{Method: "GET", Path: "/api/v1/audit/verify"},
		{Method: "GET", Path: "/api/v1/capacity"},
		{Method: "GET", Path: "/api/v1/events"},
		{Method: "GET", Path: "/api/v1/events/{event_id}"},
		{Method: "GET", Path: "/api/v1/events/{event_id}/aliases"},
		{Method: "GET", Path: "/api/v1/events/{event_id}/mapping/{windows_node_id}"},
		{Method: "GET", Path: "/api/v1/events/{event_id}/mapping/{windows_node_id}/resolve"},
		{Method: "GET", Path: "/api/v1/events/{event_id}/nodes"},
		{Method: "GET", Path: "/api/v1/events/{event_id}/nodes/{node_id}"},
		{Method: "GET", Path: "/api/v1/events/{event_id}/nodes/{node_id}/config"},
		{Method: "GET", Path: "/api/v1/events/{event_id}/nodes/{node_id}/config/history"},
		{Method: "GET", Path: "/api/v1/events/{event_id}/purge/preview"},
		{Method: "GET", Path: "/api/v1/events/{event_id}/purge/status"},
		{Method: "GET", Path: "/api/v1/events/{event_id}/tokens"},
		{Method: "GET", Path: "/api/v1/events/{event_id}/tokens/{token_id}"},
		{Method: "GET", Path: "/api/v1/health"},
		{Method: "GET", Path: "/api/v1/retention/runs"},
		{Method: "GET", Path: "/api/v1/retention/state"},
		{Method: "GET", Path: "/api/v1/retention/timeline"},
		{Method: "PATCH", Path: "/api/v1/events/{event_id}"},
		{Method: "POST", Path: "/api/v1/events"},
		{Method: "POST", Path: "/api/v1/events/{event_id}/archive"},
		{Method: "POST", Path: "/api/v1/events/{event_id}/mapping/{windows_node_id}"},
		{Method: "POST", Path: "/api/v1/events/{event_id}/nodes/{node_id}/revoke"},
		{Method: "POST", Path: "/api/v1/events/{event_id}/purge/confirm"},
		{Method: "POST", Path: "/api/v1/events/{event_id}/tokens"},
		{Method: "POST", Path: "/api/v1/events/{event_id}/tokens/{token_id}/revoke"},
		{Method: "POST", Path: "/api/v1/retention/run"},
		{Method: "PUT", Path: "/api/v1/events/{event_id}/aliases/{target_type}/{target_key}"},
		{Method: "PUT", Path: "/api/v1/events/{event_id}/nodes/{node_id}/config"},
	}
}

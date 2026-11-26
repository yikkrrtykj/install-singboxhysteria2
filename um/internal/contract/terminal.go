package contract

import (
	"encoding/json"
)

// Windows terminal route tokens are exactly the six tokens frozen in
// report-snapshot.schema.json, aligned with the existing windowsobs Role enum.
// They are the only route vocabulary the center accepts; local proxy names are
// operator-local and never uploaded.
var routeTokens = [...]string{"a_reality", "a_hy2", "b_reality", "b_hy2", "direct", "unknown"}

// Independent terminal sampling bounds (seconds) relative to collected_at.
const (
	terminalSamplingPastSeconds   = 300
	terminalSamplingFutureSeconds = 60
)

// terminalTelemetry mirrors the frozen snapshot terminal object. It is decoded
// only after report-snapshot.schema.json has accepted the body.
type terminalTelemetry struct {
	Selection struct {
		Availability string  `json:"availability"`
		SampledAt    int64   `json:"sampled_at"`
		Route        *string `json:"route"`
		ReasonCode   *string `json:"reason_code"`
	} `json:"selection"`
	ActiveConnections struct {
		Availability string            `json:"availability"`
		SampledAt    int64             `json:"sampled_at"`
		Total        *int64            `json:"total"`
		ByRoute      map[string]*int64 `json:"by_route"`
	} `json:"active_connections"`
}

// validateTerminalTelemetry enforces the Windows terminal runtime semantics:
// privacy sentinel rejection, independent sampling bounds, selection
// availability coherence and active-connection count coherence
// (ok => all non-null and total == sum of the six tokens; partial => at least
// one null; unavailable => all null).
func validateTerminalTelemetry(collectedAt int64, raw json.RawMessage) error {
	var telemetry terminalTelemetry
	if err := json.Unmarshal(raw, &telemetry); err != nil {
		return invalid("terminal", "malformed terminal telemetry")
	}

	// Privacy boundary: scan every string reachable from the terminal object
	// before any semantic rule inspects it. The offending value is never
	// echoed.
	doc, err := decodeAny(raw)
	if err != nil {
		return invalid("terminal", "malformed terminal telemetry")
	}
	if err := scanPrivacy(doc, "terminal"); err != nil {
		return err
	}

	// Independent selection/connection sampling is allowed, but unbounded skew
	// is not: both samples must lie in [collected_at-300s, collected_at+60s].
	earliest := collectedAt - terminalSamplingPastSeconds
	latest := collectedAt + terminalSamplingFutureSeconds
	if sampledAt := telemetry.Selection.SampledAt; sampledAt < earliest || sampledAt > latest {
		return invalid("terminal.selection.sampled_at", "sampled_at outside [collected_at-300, collected_at+60]")
	}
	if sampledAt := telemetry.ActiveConnections.SampledAt; sampledAt < earliest || sampledAt > latest {
		return invalid("terminal.active_connections.sampled_at", "sampled_at outside [collected_at-300, collected_at+60]")
	}

	if err := validateSelectionCoherence(&telemetry); err != nil {
		return err
	}
	return validateActiveConnectionsCoherence(&telemetry)
}

// validateSelectionCoherence enforces availability coherence for the route
// selection sample: ok requires a non-null route, partial requires at least one
// of route/reason_code to be null, unavailable requires a null route explained
// by a non-null reason_code.
func validateSelectionCoherence(telemetry *terminalTelemetry) error {
	selection := telemetry.Selection
	switch selection.Availability {
	case "ok":
		if selection.Route == nil {
			return invalid("terminal.selection.route", "selection availability ok requires a non-null route")
		}
	case "partial":
		if selection.Route != nil && selection.ReasonCode != nil {
			return invalid("terminal.selection", "selection availability partial requires route or reason_code to be null")
		}
	case "unavailable":
		if selection.Route != nil {
			return invalid("terminal.selection.route", "selection availability unavailable requires a null route")
		}
		if selection.ReasonCode == nil {
			return invalid("terminal.selection.reason_code", "selection availability unavailable requires a non-null reason_code")
		}
	default:
		return invalid("terminal.selection.availability", "unknown selection availability")
	}
	return nil
}

// validateActiveConnectionsCoherence enforces availability coherence for the
// connection aggregate: ok requires total and all six route counts non-null
// with total == sum; partial requires at least one null count; unavailable
// requires every count null.
func validateActiveConnectionsCoherence(telemetry *terminalTelemetry) error {
	connections := telemetry.ActiveConnections
	switch connections.Availability {
	case "ok":
		if connections.Total == nil {
			return invalid("terminal.active_connections.total", "availability ok requires a non-null total")
		}
		var sum int64
		for _, token := range routeTokens {
			count, ok := connections.ByRoute[token]
			if !ok || count == nil {
				return invalid("terminal.active_connections.by_route."+token, "availability ok requires all six non-null route counts")
			}
			sum += *count
		}
		if sum != *connections.Total {
			return invalid("terminal.active_connections.total", "total does not equal the sum of by_route")
		}
	case "partial":
		allPresent := connections.Total != nil
		for _, token := range routeTokens {
			count, ok := connections.ByRoute[token]
			if !ok || count == nil {
				allPresent = false
			}
		}
		if allPresent {
			return invalid("terminal.active_connections", "availability partial requires at least one null count")
		}
	case "unavailable":
		if connections.Total != nil {
			return invalid("terminal.active_connections.total", "availability unavailable requires a null total")
		}
		for _, token := range routeTokens {
			count, ok := connections.ByRoute[token]
			if ok && count != nil {
				return invalid("terminal.active_connections.by_route."+token, "availability unavailable requires null route counts")
			}
		}
	default:
		return invalid("terminal.active_connections.availability", "unknown active_connections availability")
	}
	return nil
}

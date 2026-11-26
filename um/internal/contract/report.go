package contract

import (
	"encoding/json"
	"fmt"
)

// Frozen temporal bounds for report sub-samples, in seconds relative to
// collected_at (docs/um/um-a/04-node-protocol-v1.md §9.3):
//   - metrics.samples[].at ∈ [collected_at-600, collected_at+60]
//   - events[].at          ∈ [collected_at-3600, collected_at+60]
//
// The schema already bounds collected_at itself (non-negative integer). Whether
// collected_at is in the future relative to *server* time, and whether a payload
// is fresh relative to sent_at, is NOT decidable by pure runtime validation: it
// needs the authenticated transport timestamp and server clock, so it stays a
// UM-B2 ingest responsibility.
const (
	metricsSamplePastSeconds   = 600
	metricsSampleFutureSeconds = 60
	eventPastSeconds           = 3600
	eventFutureSeconds         = 60
	secondsPerMinute           = 60
)

// Event kinds by platform. Revision 5 freezes: linux_vps may send service /
// protocol / generic agent kinds; windows_terminal may send the two terminal
// kinds plus generic agent kinds. Cross-class kinds are a platform mismatch.
var (
	linuxOnlyEventKinds = map[string]struct{}{
		"service_restart":   {},
		"service_failure":   {},
		"protocol_outage":   {},
		"protocol_recovery": {},
	}
	windowsOnlyEventKinds = map[string]struct{}{
		"terminal_route_changed":      {},
		"terminal_source_unavailable": {},
	}
	genericEventKinds = map[string]struct{}{
		"agent_started":  {},
		"agent_error":    {},
		"config_update":  {},
		"clock_skew":     {},
		"spool_overflow": {},
	}
)

// eventsEnvelope is the shape needed for per-class event-kind enforcement,
// temporal bounds and event-id uniqueness; report-events.schema.json has already
// validated structure and closed detail.
type eventsEnvelope struct {
	CollectedAt int64           `json:"collected_at"`
	Events      []eventEnvelope `json:"events"`
}

type eventEnvelope struct {
	EventID string `json:"event_id"`
	At      int64  `json:"at"`
	Kind    string `json:"kind"`
}

// metricsEnvelope is the shape needed for sample temporal checks;
// report-metrics.schema.json has already validated structure and ranges.
type metricsEnvelope struct {
	CollectedAt int64 `json:"collected_at"`
	Samples     []struct {
		At int64 `json:"at"`
	} `json:"samples"`
}

// ValidateReportBody enforces the per-class allowlist for a report body and
// delegates to snapshot/metrics/events validation. It uses the default
// ValidateOptions{TerminalConfigured: true}; callers that know the center
// terminal-source configuration must use ValidateReportBodyWithOptions.
//
//   - every report type: strict-JSON grammar (no duplicate object member names,
//     no trailing data) -> invalid_request, before schema validation;
//   - snapshot: ValidateSnapshotWithOptions (JSON Schema + platform isolation +
//     Linux availability coherence + terminal runtime semantics + privacy scan);
//   - metrics: schema validation and temporal sample checks for linux_vps;
//     windows_terminal metrics are deferred in v1 -> platform_mismatch;
//   - events: schema validation, path-aware privacy scan, temporal bounds,
//     duplicate event_id rejection and per-class event-kind allowlists
//     (terminal_route_changed / terminal_source_unavailable only for
//     windows_terminal, server kinds only for linux_vps).
//
// nodeClass is the immutable class bound at enrollment; reportType is the
// expected body type ("snapshot", "metrics" or "events"). The body's own "type"
// discriminator is enforced by the schema.
//
// Decisions that remain UM-B2-owned because they need center state are not
// decidable here: `expected_inbound_tags`/kind matching for protocol and traffic
// entries, center node state, and payload freshness against sent_at/server time.
func ValidateReportBody(nodeClass, reportType string, raw []byte) error {
	return ValidateReportBodyWithOptions(nodeClass, reportType, raw, ValidateOptions{TerminalConfigured: true})
}

// ValidateReportBodyWithOptions is ValidateReportBody with explicit center-state
// options. See ValidateOptions.
func ValidateReportBodyWithOptions(nodeClass, reportType string, raw []byte, opts ValidateOptions) error {
	// Grammar before schema: duplicate members and trailing data are rejected for
	// every report type so no two consumers can disagree about the same bytes.
	if err := validateStrictJSON(raw); err != nil {
		return err
	}

	switch reportType {
	case ReportTypeSnapshot:
		return ValidateSnapshotWithOptions(nodeClass, raw, opts)
	case ReportTypeMetrics:
		if err := validateNodeClass(nodeClass); err != nil {
			return err
		}
		if nodeClass == NodeClassWindowsTerminal {
			return mismatch("report_type", "windows_terminal report-metrics is deferred in v1")
		}
		if err := validateSchema(metricsSchemaFile, raw); err != nil {
			return err
		}
		if err := scanReportPrivacy(ReportTypeMetrics, raw); err != nil {
			return err
		}
		return validateMetricsSemantics(raw)
	case ReportTypeEvents:
		if err := validateNodeClass(nodeClass); err != nil {
			return err
		}
		if err := validateSchema(eventsSchemaFile, raw); err != nil {
			return err
		}
		if err := scanReportPrivacy(ReportTypeEvents, raw); err != nil {
			return err
		}
		return validateEventsSemantics(nodeClass, raw)
	default:
		return invalid("report_type", "unknown report type")
	}
}

// validateNodeClass rejects classes outside the frozen platform enum.
func validateNodeClass(nodeClass string) error {
	switch nodeClass {
	case NodeClassLinuxVPS, NodeClassWindowsTerminal:
		return nil
	default:
		return invalid("node_class", "unknown node class")
	}
}

// validateMetricsSemantics enforces the frozen metric-sample temporal contract:
// every sample at must be minute-aligned, strictly increasing (therefore
// unique), and inside [collected_at-600, collected_at+60].
func validateMetricsSemantics(raw []byte) error {
	var body metricsEnvelope
	if err := json.Unmarshal(raw, &body); err != nil {
		return invalid("body", "malformed metrics body")
	}
	earliest := body.CollectedAt - metricsSamplePastSeconds
	latest := body.CollectedAt + metricsSampleFutureSeconds
	var previous int64
	for index, sample := range body.Samples {
		field := fmt.Sprintf("samples[%d].at", index)
		if sample.At%secondsPerMinute != 0 {
			return invalid(field, "sample at must be minute-aligned (a multiple of 60 seconds)")
		}
		if sample.At < earliest || sample.At > latest {
			return invalid(field, "sample at outside [collected_at-600, collected_at+60]")
		}
		if index > 0 && sample.At <= previous {
			return invalid(field, "sample times must be strictly increasing and unique")
		}
		previous = sample.At
	}
	return nil
}

// validateEventsSemantics enforces the frozen event temporal contract
// (at ∈ [collected_at-3600, collected_at+60]), rejects duplicate event_id values
// within one report body, and applies the per-class event-kind allowlist. Event
// ids are contract identifiers: a duplicate error names only the array indices.
func validateEventsSemantics(nodeClass string, raw []byte) error {
	var body eventsEnvelope
	if err := json.Unmarshal(raw, &body); err != nil {
		return invalid("body", "malformed events body")
	}
	earliest := body.CollectedAt - eventPastSeconds
	latest := body.CollectedAt + eventFutureSeconds
	seen := make(map[string]int, len(body.Events))
	for index, event := range body.Events {
		if event.At < earliest || event.At > latest {
			return invalid(fmt.Sprintf("events[%d].at", index), "event at outside [collected_at-3600, collected_at+60]")
		}
		if first, duplicate := seen[event.EventID]; duplicate {
			return invalid(fmt.Sprintf("events[%d].event_id", index),
				fmt.Sprintf("duplicate event_id within report body (first seen at events[%d])", first))
		}
		seen[event.EventID] = index
	}
	return validateEventKinds(nodeClass, body.Events)
}

// validateEventKinds enforces the per-class event-kind allowlist after the
// report-events schema has accepted the closed detail object.
func validateEventKinds(nodeClass string, events []eventEnvelope) error {
	for index, event := range events {
		field := fmt.Sprintf("events[%d].kind", index)
		switch nodeClass {
		case NodeClassLinuxVPS:
			if _, windowsOnly := windowsOnlyEventKinds[event.Kind]; windowsOnly {
				return mismatch(field, "terminal event kinds are only allowed for windows_terminal")
			}
		case NodeClassWindowsTerminal:
			if _, linuxOnly := linuxOnlyEventKinds[event.Kind]; linuxOnly {
				return mismatch(field, "server telemetry event kinds are not allowed for windows_terminal")
			}
		}
		_, generic := genericEventKinds[event.Kind]
		_, linuxOnly := linuxOnlyEventKinds[event.Kind]
		_, windowsOnly := windowsOnlyEventKinds[event.Kind]
		if !generic && !linuxOnly && !windowsOnly {
			return invalid(field, "unknown event kind")
		}
	}
	return nil
}

package contract

import (
	"encoding/json"
	"fmt"
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

// eventsEnvelope is the minimal shape needed for per-class event-kind
// enforcement; report-events.schema.json has already validated structure and
// closed detail.
type eventsEnvelope struct {
	Events []struct {
		Kind string `json:"kind"`
	} `json:"events"`
}

// ValidateReportBody enforces the per-class allowlist for a report body and
// delegates to snapshot/metrics/events validation:
//
//   - snapshot: ValidateSnapshot (JSON Schema + platform isolation + terminal
//     runtime semantics);
//   - metrics: schema validation for linux_vps; windows_terminal metrics are
//     deferred in v1 -> platform_mismatch;
//   - events: schema validation plus per-class event-kind allowlists
//     (terminal_route_changed / terminal_source_unavailable only for
//     windows_terminal, server kinds only for linux_vps).
//
// nodeClass is the immutable class bound at enrollment; reportType is the
// expected body type ("snapshot", "metrics" or "events"). The body's own "type"
// discriminator is enforced by the schema.
func ValidateReportBody(nodeClass, reportType string, raw []byte) error {
	switch reportType {
	case ReportTypeSnapshot:
		return ValidateSnapshot(nodeClass, raw)
	case ReportTypeMetrics:
		if err := validateNodeClass(nodeClass); err != nil {
			return err
		}
		if nodeClass == NodeClassWindowsTerminal {
			return mismatch("report_type", "windows_terminal report-metrics is deferred in v1")
		}
		return validateSchema(metricsSchemaFile, raw)
	case ReportTypeEvents:
		if err := validateNodeClass(nodeClass); err != nil {
			return err
		}
		if err := validateSchema(eventsSchemaFile, raw); err != nil {
			return err
		}
		return validateEventKinds(nodeClass, raw)
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

// validateEventKinds enforces the per-class event-kind allowlist after the
// report-events schema has accepted the closed detail object.
func validateEventKinds(nodeClass string, raw []byte) error {
	var body eventsEnvelope
	if err := json.Unmarshal(raw, &body); err != nil {
		return invalid("body", "malformed events body")
	}
	for index, event := range body.Events {
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

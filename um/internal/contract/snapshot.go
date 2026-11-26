package contract

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Frozen temporal bounds for snapshot sub-samples, in seconds relative to
// collected_at. protocol observed_at uses the protocol-level bound from
// docs/um/um-a/04-node-protocol-v1.md §9.3; the terminal sampling bounds live in
// terminal.go.
const (
	protocolObservedAtPastSeconds  = 900
	snapshotFutureToleranceSeconds = 60
)

// ValidateOptions carries the source switches that live in center/agent-config
// state and are therefore invisible to pure runtime validation.
//
// The frozen contract makes a Windows `terminal` object mandatory exactly when
// the center has the terminal source configured for that node, and forbidden
// when it is not configured. Since a pure validator cannot read agent-config,
// the UM-B2 ingest layer must pass that decision explicitly.
//
// The option-less wrappers (ValidateSnapshot / ValidateReportBody) keep the
// historical default TerminalConfigured=true, which preserves the committed
// positive terminal example and the "a configured source must report" rule.
type ValidateOptions struct {
	// TerminalConfigured reports whether the center/agent-config has the
	// windows_terminal terminal source configured for this node (the `terminal`
	// collect switch). When true, a windows_terminal snapshot MUST carry the
	// `terminal` object; when false it MUST NOT. Ignored for linux_vps, which
	// never carries terminal telemetry.
	TerminalConfigured bool
}

// snapshotEnvelope is the shape needed by the runtime rules. Fields not relevant
// to platform isolation / availability coherence / terminal semantics are not
// decoded. The body has already passed report-snapshot.schema.json and the
// strict-JSON scan when this struct is populated, so required fields are present
// and well-typed.
type snapshotEnvelope struct {
	CollectedAt  int64                      `json:"collected_at"`
	Host         snapshotHost               `json:"host"`
	Availability map[string]string          `json:"availability"`
	System       map[string]json.RawMessage `json:"system"`
	Services     []serviceEntry             `json:"services"`
	Protocols    []protocolEntry            `json:"protocols"`
	Traffic      []trafficEntry             `json:"traffic"`
	Clients      clientsEnvelope            `json:"clients"`
	Terminal     json.RawMessage            `json:"terminal"`
}

type snapshotHost struct {
	OS string `json:"os"`
}

type serviceEntry struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

type protocolEntry struct {
	Kind       string `json:"kind"`
	InboundTag string `json:"inbound_tag"`
	State      string `json:"state"`
	Reason     string `json:"reason"`
	ObservedAt int64  `json:"observed_at"`
}

type trafficEntry struct {
	Scope         string `json:"scope"`
	InboundTag    string `json:"inbound_tag"`
	UplinkBytes   *int64 `json:"uplink_total_bytes"`
	DownlinkBytes *int64 `json:"downlink_total_bytes"`
}

type clientsEnvelope struct {
	Active    *int64            `json:"active"`
	Tracked   *int64            `json:"tracked"`
	Summaries []json.RawMessage `json:"summaries"`
}

var systemFieldNames = []string{
	"cpu_pct", "load1", "mem_total_bytes", "mem_used_bytes",
	"disk_total_bytes", "disk_used_bytes", "net_rx_bytes", "net_tx_bytes",
}

// ValidateSnapshot enforces the rev-5 runtime rules for a report body of type
// snapshot that JSON Schema cannot express. It is meant to be called after
// signature/authentication on the ingest path and uses the default
// ValidateOptions{TerminalConfigured: true}; callers that know the center
// source configuration must use ValidateSnapshotWithOptions.
//
//  1. Strict-JSON grammar (no duplicate object member names, no trailing data).
//  2. Report snapshot contract validation (JSON Schema 2020-12) -> invalid_request.
//  3. Full-body path-aware privacy sentinel scan -> invalid_request.
//  4. Platform isolation: linux_vps must not carry terminal and must be
//     host.os=linux; windows_terminal must be host.os=windows and carry the
//     terminal object iff the terminal source is configured -> platform_mismatch.
//  5. Linux availability ↔ null/empty coherence, protocol state/reason coherence
//     and protocol observed_at bounds -> invalid_request.
//  6. Windows base data honesty: services/protocols/traffic/clients unavailable/
//     null/empty; the optional rev-5 system source is coherence-checked.
//  7. Terminal selection/connection coherence and independent sampling bounds ->
//     invalid_request.
func ValidateSnapshot(nodeClass string, raw []byte) error {
	return ValidateSnapshotWithOptions(nodeClass, raw, ValidateOptions{TerminalConfigured: true})
}

// ValidateSnapshotWithOptions is ValidateSnapshot with explicit center-state
// options. See ValidateOptions.
func ValidateSnapshotWithOptions(nodeClass string, raw []byte, opts ValidateOptions) error {
	// 1–2. Real JSON Schema validation of the frozen contract (which itself
	// enforces strict JSON before schema work).
	if err := validateSchema(snapshotSchemaFile, raw); err != nil {
		return err
	}

	// 3. Privacy boundary: scan every string reachable from the body, by path.
	// This covers identifiers the schema defines (report_id) without flagging
	// them, and all non-terminal fields (metrics/events are scanned in report.go).
	if err := scanReportPrivacy(ReportTypeSnapshot, raw); err != nil {
		return err
	}

	// 4. Minimal parse; fields are schema-guaranteed.
	var snap snapshotEnvelope
	if err := json.Unmarshal(raw, &snap); err != nil {
		return invalid("body", "malformed snapshot body")
	}
	hasTerminal := len(snap.Terminal) > 0 && !isJSONNull(snap.Terminal)

	switch nodeClass {
	case NodeClassLinuxVPS:
		if hasTerminal {
			return mismatch("terminal", "linux_vps snapshot must not carry terminal telemetry")
		}
		if snap.Host.OS != "linux" {
			return mismatch("host.os", "linux_vps snapshot requires host.os=linux")
		}
		return validateLinuxSnapshotSemantics(&snap)
	case NodeClassWindowsTerminal:
		if snap.Host.OS != "windows" {
			return mismatch("host.os", "windows_terminal snapshot requires host.os=windows")
		}
		// Terminal presence is decided by the center source configuration, which
		// only UM-B2 can supply; presence must match that switch exactly.
		if opts.TerminalConfigured {
			if !hasTerminal {
				return mismatch("terminal", "windows_terminal snapshot must carry terminal telemetry when the terminal source is configured")
			}
		} else if hasTerminal {
			return mismatch("terminal", "windows_terminal snapshot must not carry terminal telemetry when the terminal source is not configured")
		}
		if err := validateWindowsBaseHonesty(&snap); err != nil {
			return err
		}
		if !hasTerminal {
			return nil
		}
		return validateTerminalTelemetry(snap.CollectedAt, snap.Terminal)
	default:
		return invalid("node_class", "unknown node class")
	}
}

// validateLinuxSnapshotSemantics enforces the frozen "availability ⇒
// null/empty/unknown" coherence rules for a Linux VPS snapshot. For object
// fields the projection is null vs non-null; for array fields it is
// empty/non-empty and the array's own unknown token (state=unknown for
// services/protocols, a null counter for traffic, a null count for clients).
func validateLinuxSnapshotSemantics(snap *snapshotEnvelope) error {
	if err := validateSystemCoherence(snap); err != nil {
		return err
	}
	if err := validateServicesCoherence(snap); err != nil {
		return err
	}
	if err := validateProtocolsCoherence(snap); err != nil {
		return err
	}
	if err := validateTrafficCoherence(snap); err != nil {
		return err
	}
	return validateClientsCoherence(snap)
}

// validateSystemCoherence enforces system availability ↔ system-field
// nullability: ok ⇒ every field non-null; unavailable ⇒ every field null;
// partial ⇒ at least one null.
func validateSystemCoherence(snap *snapshotEnvelope) error {
	switch availability := snap.Availability["system"]; availability {
	case "ok":
		for _, field := range systemFieldNames {
			if raw, ok := snap.System[field]; !ok || isJSONNull(raw) {
				return invalid("system."+field, "system availability ok requires every system field to be non-null")
			}
		}
	case "unavailable":
		for _, field := range systemFieldNames {
			if raw, ok := snap.System[field]; ok && !isJSONNull(raw) {
				return invalid("system."+field, "system availability unavailable requires every system field to be null")
			}
		}
	case "partial":
		if !hasNullSystemField(snap) {
			return invalid("system", "system availability partial requires at least one null system field")
		}
	default:
		return invalid("availability.system", "unknown system availability")
	}
	return nil
}

func hasNullSystemField(snap *snapshotEnvelope) bool {
	for _, field := range systemFieldNames {
		if raw, ok := snap.System[field]; !ok || isJSONNull(raw) {
			return true
		}
	}
	return false
}

// validateServicesCoherence enforces services availability ↔ array contents:
// ok ⇒ non-empty array; unavailable ⇒ empty array; partial ⇒ at least one
// observed service with state=unknown (the array projection of "at least one
// null/unknown value").
func validateServicesCoherence(snap *snapshotEnvelope) error {
	switch availability := snap.Availability["services"]; availability {
	case "ok":
		if len(snap.Services) == 0 {
			return invalid("services", "services availability ok requires a non-empty services array")
		}
	case "unavailable":
		if len(snap.Services) != 0 {
			return invalid("services", "services availability unavailable requires an empty services array")
		}
	case "partial":
		for _, service := range snap.Services {
			if service.State == "unknown" {
				return nil
			}
		}
		return invalid("services", "services availability partial requires at least one observed service with state=unknown")
	default:
		return invalid("availability.services", "unknown services availability")
	}
	return nil
}

// validateProtocolsCoherence enforces protocols availability ↔ array contents
// plus, for every observed protocol, state/reason coherence and observed_at
// temporal bounds.
func validateProtocolsCoherence(snap *snapshotEnvelope) error {
	switch availability := snap.Availability["protocols"]; availability {
	case "ok":
		if len(snap.Protocols) == 0 {
			return invalid("protocols", "protocols availability ok requires a non-empty protocols array")
		}
	case "unavailable":
		if len(snap.Protocols) != 0 {
			return invalid("protocols", "protocols availability unavailable requires an empty protocols array")
		}
	case "partial":
		unknown := false
		for _, protocol := range snap.Protocols {
			if protocol.State == "unknown" {
				unknown = true
				break
			}
		}
		if !unknown {
			return invalid("protocols", "protocols availability partial requires at least one protocol with state=unknown")
		}
	default:
		return invalid("availability.protocols", "unknown protocols availability")
	}
	return validateProtocolEntries(snap.CollectedAt, snap.Protocols)
}

// validateProtocolEntries enforces per-protocol evidence rules: state=up only
// with reason=ok; state=unknown only with source_unavailable/unknown; state=down
// only with a non-ok reason; observed_at within [collected_at-900,
// collected_at+60]. Up without evidence is never rendered.
func validateProtocolEntries(collectedAt int64, protocols []protocolEntry) error {
	earliest := collectedAt - protocolObservedAtPastSeconds
	latest := collectedAt + snapshotFutureToleranceSeconds
	for index, protocol := range protocols {
		field := fmt.Sprintf("protocols[%d]", index)
		if protocol.ObservedAt < earliest || protocol.ObservedAt > latest {
			return invalid(field+".observed_at", "observed_at outside [collected_at-900, collected_at+60]")
		}
		switch protocol.State {
		case "up":
			if protocol.Reason != "ok" {
				return invalid(field+".reason", "protocol state up requires reason ok")
			}
		case "unknown":
			if protocol.Reason != "source_unavailable" && protocol.Reason != "unknown" {
				return invalid(field+".reason", "protocol state unknown requires reason source_unavailable or unknown")
			}
		case "down":
			if protocol.Reason == "ok" {
				return invalid(field+".reason", "protocol state down requires a non-ok reason")
			}
		default:
			return invalid(field+".state", "unknown protocol state")
		}
	}
	return nil
}

// validateTrafficCoherence enforces traffic availability ↔ array contents:
// ok ⇒ non-empty with non-null counters; unavailable ⇒ empty; partial ⇒ at
// least one null counter.
func validateTrafficCoherence(snap *snapshotEnvelope) error {
	switch availability := snap.Availability["traffic"]; availability {
	case "ok":
		if len(snap.Traffic) == 0 {
			return invalid("traffic", "traffic availability ok requires a non-empty traffic array")
		}
		for index, entry := range snap.Traffic {
			field := fmt.Sprintf("traffic[%d]", index)
			if entry.UplinkBytes == nil {
				return invalid(field+".uplink_total_bytes", "traffic availability ok requires non-null uplink_total_bytes")
			}
			if entry.DownlinkBytes == nil {
				return invalid(field+".downlink_total_bytes", "traffic availability ok requires non-null downlink_total_bytes")
			}
		}
	case "unavailable":
		if len(snap.Traffic) != 0 {
			return invalid("traffic", "traffic availability unavailable requires an empty traffic array")
		}
	case "partial":
		for _, entry := range snap.Traffic {
			if entry.UplinkBytes == nil || entry.DownlinkBytes == nil {
				return nil
			}
		}
		return invalid("traffic", "traffic availability partial requires at least one null traffic counter")
	default:
		return invalid("availability.traffic", "unknown traffic availability")
	}
	return nil
}

// validateClientsCoherence enforces clients availability ↔ counters/summaries:
// ok ⇒ active and tracked non-null; unavailable ⇒ both null and summaries empty;
// partial ⇒ at least one of active/tracked null.
func validateClientsCoherence(snap *snapshotEnvelope) error {
	clients := snap.Clients
	switch availability := snap.Availability["clients"]; availability {
	case "ok":
		if clients.Active == nil {
			return invalid("clients.active", "clients availability ok requires a non-null active count")
		}
		if clients.Tracked == nil {
			return invalid("clients.tracked", "clients availability ok requires a non-null tracked count")
		}
	case "unavailable":
		if clients.Active != nil {
			return invalid("clients.active", "clients availability unavailable requires a null active count")
		}
		if clients.Tracked != nil {
			return invalid("clients.tracked", "clients availability unavailable requires a null tracked count")
		}
		if len(clients.Summaries) != 0 {
			return invalid("clients.summaries", "clients availability unavailable requires an empty summaries array")
		}
	case "partial":
		if clients.Active != nil && clients.Tracked != nil {
			return invalid("clients", "clients availability partial requires active or tracked to be null")
		}
	default:
		return invalid("availability.clients", "unknown clients availability")
	}
	return nil
}

// validateWindowsBaseHonesty enforces the frozen requirement that a Windows
// terminal snapshot keeps the server-side base data in its honest
// unavailable/null/empty state instead of fabricating values. Revision 5 makes
// `system` an optional terminal-side source, so system availability may be
// ok|partial|unavailable but must obey the generic nullability coherence rule;
// services/protocols/traffic/clients are platform-forbidden on windows_terminal
// and must stay unavailable/null/empty.
func validateWindowsBaseHonesty(snap *snapshotEnvelope) error {
	for _, field := range []string{"services", "protocols", "traffic", "clients"} {
		if snap.Availability[field] != "unavailable" {
			return mismatch("availability."+field, "windows_terminal base availability must be unavailable")
		}
	}
	if err := validateSystemCoherence(snap); err != nil {
		return err
	}
	if len(snap.Services) != 0 {
		return mismatch("services", "windows_terminal base services must be empty")
	}
	if len(snap.Protocols) != 0 {
		return mismatch("protocols", "windows_terminal base protocols must be empty")
	}
	if len(snap.Traffic) != 0 {
		return mismatch("traffic", "windows_terminal base traffic must be empty")
	}
	if snap.Clients.Active != nil {
		return mismatch("clients.active", "windows_terminal base clients.active must be null")
	}
	if snap.Clients.Tracked != nil {
		return mismatch("clients.tracked", "windows_terminal base clients.tracked must be null")
	}
	if len(snap.Clients.Summaries) != 0 {
		return mismatch("clients.summaries", "windows_terminal base clients.summaries must be empty")
	}
	return nil
}

// isJSONNull reports whether raw is the JSON literal null.
func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

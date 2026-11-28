package contract

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/schema"
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
	// MonitorExportConfigured reports whether the center/agent-config has the
	// linux_vps monitor_export source enabled at the snapshot's collected_at.
	// Revision-7 snapshots (contract_revision=7 + traffic_observation) are
	// accepted only when it is true. A rev-5 body remains valid even when it is
	// true: old/unknown agents must be able to report a snapshot so the center can
	// learn their capability version before ever emitting the optional rev-7
	// switch (OD-LT-14); such an agent simply has no traffic observation. Ignored
	// for windows_terminal, which never carries a read-only traffic export
	// observation.
	MonitorExportConfigured bool
	// CadenceSeconds is the signed center config cadence effective for this
	// report. It is used only for the rev-7 freshness bound
	// fresh iff age <= max(2*cadence,120); zero keeps the legacy 15 s default
	// for option-less callers that predate the rev-7 cadence plumbing.
	CadenceSeconds int
}

// snapshotEnvelope is the shape needed by the runtime rules. Fields not relevant
// to platform isolation / availability coherence / terminal semantics are not
// decoded. The body has already passed report-snapshot.schema.json and the
// strict-JSON scan when this struct is populated, so required fields are present
// and well-typed.
type snapshotEnvelope struct {
	CollectedAt        int64                      `json:"collected_at"`
	ContractRevision   json.RawMessage            `json:"contract_revision"`
	Host               snapshotHost               `json:"host"`
	Availability       map[string]string          `json:"availability"`
	System             map[string]json.RawMessage `json:"system"`
	Services           []serviceEntry             `json:"services"`
	Protocols          []protocolEntry            `json:"protocols"`
	Traffic            []trafficEntry             `json:"traffic"`
	TrafficObservation json.RawMessage            `json:"traffic_observation"`
	Clients            clientsEnvelope            `json:"clients"`
	Terminal           json.RawMessage            `json:"terminal"`
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
//  2. Contract revision selection: an absent contract_revision keeps the rev-5
//     schema/behavior; contract_revision=7 selects report-snapshot.rev7
//     .schema.json and is only legal for linux_vps with the monitor_export
//     source configured -> invalid_request/platform_mismatch.
//  3. Report snapshot contract validation (JSON Schema 2020-12) -> invalid_request.
//  4. Full-body path-aware privacy sentinel scan -> invalid_request.
//  5. Platform isolation: linux_vps must not carry terminal and must be
//     host.os=linux; windows_terminal must be host.os=windows and carry the
//     terminal object iff the terminal source is configured -> platform_mismatch.
//  6. Linux availability ↔ null/empty coherence, protocol state/reason coherence
//     and protocol observed_at bounds -> invalid_request.
//  7. Revision 7: traffic_observation lower-bound/freshness/epoch coherence and
//     the honest empty traffic projection -> invalid_request.
//  8. Windows base data honesty: services/protocols/traffic/clients unavailable/
//     null/empty; the optional rev-5 system source is coherence-checked.
//  9. Terminal selection/connection coherence and independent sampling bounds ->
//     invalid_request.
func ValidateSnapshot(nodeClass string, raw []byte) error {
	return ValidateSnapshotWithOptions(nodeClass, raw, ValidateOptions{TerminalConfigured: true})
}

// ValidateSnapshotWithOptions is ValidateSnapshot with explicit center-state
// options. See ValidateOptions.
func ValidateSnapshotWithOptions(nodeClass string, raw []byte, opts ValidateOptions) error {
	return validateSnapshotWithSchemaSet(nil, nodeClass, raw, opts)
}

// ValidateSnapshotWithSchemaSet is ValidateSnapshotWithOptions using an explicit
// startup-loaded contract schema set. The center must use this variant: a
// deployed binary cannot rely on the source checkout path being present.
func ValidateSnapshotWithSchemaSet(set *schema.Set, nodeClass string, raw []byte, opts ValidateOptions) error {
	return validateSnapshotWithSchemaSet(set, nodeClass, raw, opts)
}

func validateSnapshotWithSchemaSet(set *schema.Set, nodeClass string, raw []byte, opts ValidateOptions) error {
	// 1. Strict JSON grammar before any schema/revision selection so two
	// consumers can never disagree about the same bytes.
	if err := validateStrictJSON(raw); err != nil {
		return err
	}

	// 2. Contract revision selection. A body without contract_revision is a
	// rev-5 body and keeps the rev-5 schema/behavior byte-for-byte. A body that
	// declares contract_revision=7 must use the rev-7 schema and is only legal
	// for a linux_vps node whose monitor_export source is configured at
	// collected_at. The rev-7 schema is optional in a deployment that predates
	// the contract change; selecting it when absent fails closed.
	revision, err := snapshotContractRevision(raw)
	if err != nil {
		return err
	}
	selectedSchema := snapshotSchemaFile
	switch revision {
	case 0:
		// A rev-5 body stays valid even when the center source is enabled: an old
		// agent (or a new agent before it has received the optional config switch)
		// must never have its authenticated snapshot rejected, preserving the
		// old-agent bootstrap ordering (report first, then the center may emit the
		// rev-7 switch). Rev-7 bodies are the ones that require an enabled source.
	case ContractRevision7:
		if nodeClass != NodeClassLinuxVPS {
			return mismatch("contract_revision", "contract_revision 7 is only allowed for linux_vps snapshots")
		}
		if !opts.MonitorExportConfigured {
			return invalid("contract_revision", "contract_revision 7 requires the monitor_export source to be configured")
		}
		selectedSchema = SnapshotRev7SchemaFile
	default:
		return invalid("contract_revision", "unsupported snapshot contract revision")
	}

	// 3. Real JSON Schema validation of the selected frozen contract.
	var schemaErr error
	if set != nil {
		if !set.Has(selectedSchema) {
			return invalid("contract_revision", "the selected snapshot contract schema is not loaded")
		}
		schemaErr = set.Validate(selectedSchema, raw)
	} else {
		schemaErr = validateSchema(selectedSchema, raw)
	}
	if schemaErr != nil {
		return schemaErr
	}

	// 4. Privacy boundary: scan every string reachable from the body, by path.
	// This covers identifiers the schema defines (report_id) without flagging
	// them, and all non-terminal fields (metrics/events are scanned in report.go).
	if err := scanReportPrivacy(ReportTypeSnapshot, raw); err != nil {
		return err
	}

	// 5. Minimal parse; fields are schema-guaranteed.
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
		if err := validateLinuxSnapshotSemantics(&snap); err != nil {
			return err
		}
		if revision == ContractRevision7 {
			return validateRevision7SnapshotSemantics(&snap, opts.CadenceSeconds)
		}
		return nil
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

// snapshotContractRevision returns the declared contract_revision, or 0 for a
// rev-5 body. contract_revision is a schema-bounded integer; a wrong JSON type
// is a contract violation rather than an ignored field.
func snapshotContractRevision(raw []byte) (int, error) {
	var probe struct {
		ContractRevision *int `json:"contract_revision"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return 0, invalid("body", "malformed snapshot body")
	}
	if probe.ContractRevision == nil {
		return 0, nil
	}
	return *probe.ContractRevision, nil
}

// validateRevision7SnapshotSemantics enforces the rev-7-only additions on top of
// the rev-5 Linux coherence rules: the traffic_observation object must be a
// coherent lower-bound observation, and the frozen rev-5 traffic array/state
// stays an honest unavailable/empty projection because lower bounds are not
// contract totals.
func validateRevision7SnapshotSemantics(snap *snapshotEnvelope, cadenceSeconds int) error {
	if len(snap.TrafficObservation) == 0 || isJSONNull(snap.TrafficObservation) {
		return invalid("traffic_observation", "contract_revision 7 requires a traffic_observation object")
	}
	if _, err := ValidateTrafficObservationWithCadence(snap.CollectedAt, snap.TrafficObservation, cadenceSeconds); err != nil {
		return err
	}
	if len(snap.Traffic) != 0 {
		return invalid("traffic", "the monitor_export source reports lower bounds, not contract totals; traffic must stay empty")
	}
	if snap.Availability["traffic"] != "unavailable" && snap.Availability["traffic"] != "partial" {
		return invalid("availability.traffic", "the monitor_export source allows availability.traffic partial or unavailable, never ok")
	}
	return nil
}

func isSnapshotRevision7(snap *snapshotEnvelope) bool {
	if len(snap.ContractRevision) == 0 {
		return false
	}
	var revision int
	if err := json.Unmarshal(snap.ContractRevision, &revision); err != nil {
		return false
	}
	return revision == ContractRevision7
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
		// Rev-7 Linux has a separate traffic_observation block that carries the
		// lower-bound data; its frozen rev-5 traffic projection MUST stay empty.
		// The contract permits availability.traffic to be "partial" in that one
		// narrow case (but never "ok"). Snowflake/empty partial is still invalid
		// for every rev-5 body.
		if len(snap.Traffic) == 0 && isSnapshotRevision7(snap) {
			return nil
		}
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

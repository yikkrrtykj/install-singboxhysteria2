package contract

import (
	"bytes"
	"encoding/json"
)

// snapshotEnvelope is the minimal shape needed by the runtime rules. Fields not
// relevant to platform isolation / terminal semantics are not decoded; raw
// JSON is kept for the terminal object and the base collections so honest
// null/empty checks do not lose information.
//
// The body has already passed report-snapshot.schema.json when this struct is
// populated, so every required field and enum is guaranteed to be present and
// well-typed.
type snapshotEnvelope struct {
	CollectedAt  int64                      `json:"collected_at"`
	Host         snapshotHost               `json:"host"`
	Availability map[string]string          `json:"availability"`
	System       map[string]json.RawMessage `json:"system"`
	Services     json.RawMessage            `json:"services"`
	Protocols    json.RawMessage            `json:"protocols"`
	Traffic      json.RawMessage            `json:"traffic"`
	Clients      map[string]json.RawMessage `json:"clients"`
	Terminal     json.RawMessage            `json:"terminal"`
}

type snapshotHost struct {
	OS string `json:"os"`
}

var (
	availabilityFields = []string{"system", "services", "protocols", "traffic", "clients"}
	systemFieldNames   = []string{
		"cpu_pct", "load1", "mem_total_bytes", "mem_used_bytes",
		"disk_total_bytes", "disk_used_bytes", "net_rx_bytes", "net_tx_bytes",
	}
	collectionFieldNames = []string{"services", "protocols", "traffic"}
	clientFieldNames     = []string{"active", "tracked", "summaries"}
)

// ValidateSnapshot enforces the rev-5 runtime rules for a report body of type
// snapshot that JSON Schema cannot express. It is meant to be called after
// signature/authentication on the ingest path.
//
//  1. Report snapshot contract validation (JSON Schema 2020-12) -> invalid_request.
//  2. Platform isolation: linux_vps must not carry terminal and must be
//     host.os=linux; windows_terminal must carry terminal and must be
//     host.os=windows -> platform_mismatch.
//  3. Windows base data must be honest: availability all unavailable, system
//     fields all null, services/protocols/traffic empty, clients counters null
//     and summaries empty -> platform_mismatch.
//  4. Terminal selection/connection coherence, independent sampling bounds and
//     the privacy sentinel scan -> invalid_request.
func ValidateSnapshot(nodeClass string, raw []byte) error {
	// 1. Real JSON Schema validation of the frozen contract.
	if err := validateSchema(snapshotSchemaFile, raw); err != nil {
		return err
	}

	// 2. Minimal parse; fields are schema-guaranteed.
	var snap snapshotEnvelope
	if err := json.Unmarshal(raw, &snap); err != nil {
		return invalid("body", "malformed snapshot body")
	}
	hasTerminal := len(snap.Terminal) > 0 && !isJSONNull(snap.Terminal)

	// 3. Platform isolation.
	switch nodeClass {
	case NodeClassLinuxVPS:
		if hasTerminal {
			return mismatch("terminal", "linux_vps snapshot must not carry terminal telemetry")
		}
		if snap.Host.OS != "linux" {
			return mismatch("host.os", "linux_vps snapshot requires host.os=linux")
		}
		return nil
	case NodeClassWindowsTerminal:
		if snap.Host.OS != "windows" {
			return mismatch("host.os", "windows_terminal snapshot requires host.os=windows")
		}
		if !hasTerminal {
			return mismatch("terminal", "windows_terminal snapshot must carry terminal telemetry")
		}
		if err := validateWindowsBaseHonesty(&snap); err != nil {
			return err
		}
		return validateTerminalTelemetry(snap.CollectedAt, snap.Terminal)
	default:
		return invalid("node_class", "unknown node class")
	}
}

// validateWindowsBaseHonesty enforces the frozen requirement that a Windows
// terminal snapshot keeps the server-side base data in its honest
// unavailable/null/empty state instead of fabricating values.
func validateWindowsBaseHonesty(snap *snapshotEnvelope) error {
	for _, field := range availabilityFields {
		if snap.Availability[field] != "unavailable" {
			return mismatch("availability."+field, "windows_terminal base availability must be unavailable")
		}
	}
	for _, field := range systemFieldNames {
		value, ok := snap.System[field]
		if !ok || !isJSONNull(value) {
			return mismatch("system."+field, "windows_terminal base system fields must be null")
		}
	}
	for _, field := range collectionFieldNames {
		value, ok := snapshotCollection(snap, field)
		if !ok || !isEmptyJSONArray(value) {
			return mismatch(field, "windows_terminal base "+field+" must be empty")
		}
	}
	for _, field := range clientFieldNames {
		value, ok := snap.Clients[field]
		if !ok {
			return mismatch("clients."+field, "windows_terminal clients."+field+" is missing")
		}
		if field == "summaries" {
			if !isEmptyJSONArray(value) {
				return mismatch("clients.summaries", "windows_terminal base clients.summaries must be empty")
			}
			continue
		}
		if !isJSONNull(value) {
			return mismatch("clients."+field, "windows_terminal base clients."+field+" must be null")
		}
	}
	return nil
}

// snapshotCollection returns the raw base collection field by name.
func snapshotCollection(snap *snapshotEnvelope, field string) (json.RawMessage, bool) {
	switch field {
	case "services":
		return snap.Services, true
	case "protocols":
		return snap.Protocols, true
	case "traffic":
		return snap.Traffic, true
	default:
		return nil, false
	}
}

// isJSONNull reports whether raw is the JSON literal null.
func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// isEmptyJSONArray reports whether raw is a syntactically valid empty JSON array.
func isEmptyJSONArray(raw json.RawMessage) bool {
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return false
	}
	return len(items) == 0
}

package contract

import (
	"encoding/json"
	"strings"
	"testing"
)

func baseTrafficObservation(collectedAt int64) map[string]any {
	observed := collectedAt - 2
	uplink := int64(1000)
	downlink := int64(2000)
	rate := 12.5
	return map[string]any{
		"source":              "monitor_readonly_export",
		"source_epoch":        strings.Repeat("ab", 16),
		"sequence":            int64(7),
		"observed_at":         observed,
		"age_seconds":         int64(2),
		"freshness":           "fresh",
		"availability":        "ok",
		"counter_scope":       "observation_epoch",
		"exactness":           "lower_bound",
		"active_connections":  int64(2),
		"rate_window_seconds": 60.0,
		"inbounds": []any{map[string]any{
			"inbound_tag": "vless-in", "kind": "reality", "observed_at": observed,
			"availability": "ok", "quality": "lower_bound",
			"uplink_observed_lower_bound_bytes": uplink, "downlink_observed_lower_bound_bytes": downlink,
			"uplink_observed_rate_bps": rate, "downlink_observed_rate_bps": nil,
			"active_connections": int64(2),
		}},
	}
}

func TestValidateSnapshotRev5AllowedWhenMonitorExportConfigured(t *testing.T) {
	// OD-LT-14 bootstrap ordering: an old/unknown agent's rev-5 snapshot must stay
	// valid while the center source is enabled, so the center can learn the agent
	// capability version before ever emitting the optional rev-7 switch.
	raw := readExample(t, linuxSnapshotExample)
	opts := ValidateOptions{TerminalConfigured: true, MonitorExportConfigured: true}
	if err := ValidateSnapshotWithOptions(NodeClassLinuxVPS, raw, opts); err != nil {
		t.Fatalf("rev-5 snapshot rejected while monitor_export is configured: %v", err)
	}
}

func TestValidateTrafficObservationAcceptsCoherentObservation(t *testing.T) {
	collectedAt := int64(1_700_000_000)
	raw, err := json.Marshal(baseTrafficObservation(collectedAt))
	if err != nil {
		t.Fatal(err)
	}
	observation, err := ValidateTrafficObservation(collectedAt, raw)
	if err != nil {
		t.Fatalf("coherent observation rejected: %v", err)
	}
	if observation.SourceEpoch != strings.Repeat("ab", 16) || len(observation.Inbounds) != 1 {
		t.Fatalf("unexpected decoded observation: %+v", observation)
	}
}

func TestValidateTrafficObservationAcceptsPartialNullCounters(t *testing.T) {
	// A partial quality row with null counters is honest (stale monitor or an
	// over-range counter published as null) and must not be rejected.
	collectedAt := int64(1_700_000_000)
	observation := baseTrafficObservation(collectedAt)
	observation["freshness"] = "stale"
	observation["availability"] = "partial"
	observation["observed_at"] = collectedAt - 40
	observation["age_seconds"] = int64(40)
	observation["active_connections"] = nil
	inbound := observation["inbounds"].([]any)[0].(map[string]any)
	inbound["availability"] = "partial"
	inbound["quality"] = "partial"
	inbound["uplink_observed_lower_bound_bytes"] = nil
	inbound["downlink_observed_lower_bound_bytes"] = nil
	inbound["uplink_observed_rate_bps"] = nil
	raw, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateTrafficObservation(collectedAt, raw); err != nil {
		t.Fatalf("partial null-counter observation rejected: %v", err)
	}
}

func TestValidateTrafficObservationRejectsIncoherence(t *testing.T) {
	collectedAt := int64(1_700_000_000)
	cases := []struct {
		name   string
		mutate func(observation map[string]any)
	}{
		{"wrong source", func(o map[string]any) { o["source"] = "service_api" }},
		{"bad epoch", func(o map[string]any) { o["source_epoch"] = "abc" }},
		{"age mismatch", func(o map[string]any) { o["age_seconds"] = int64(9) }},
		{"future observed", func(o map[string]any) {
			o["observed_at"] = collectedAt + 10
			o["age_seconds"] = int64(0)
			o["inbounds"].([]any)[0].(map[string]any)["observed_at"] = collectedAt + 10
		}},
		{"fresh but stale age", func(o map[string]any) {
			o["observed_at"] = collectedAt - 40
			o["age_seconds"] = int64(40)
		}},
		{"stale but ok", func(o map[string]any) {
			o["freshness"] = "stale"
			o["observed_at"] = collectedAt - 40
			o["age_seconds"] = int64(40)
		}},
		{"unavailable with ok availability", func(o map[string]any) {
			o["freshness"] = "unavailable"
		}},
		{"unavailable with counters", func(o map[string]any) {
			o["freshness"] = "unavailable"
			o["availability"] = "unavailable"
		}},
		{"counter overflow", func(o map[string]any) {
			o["inbounds"].([]any)[0].(map[string]any)["uplink_observed_lower_bound_bytes"] = int64(9007199254740992)
		}},
		{"lower_bound null counter", func(o map[string]any) {
			o["inbounds"].([]any)[0].(map[string]any)["uplink_observed_lower_bound_bytes"] = nil
		}},
		{"rate without window", func(o map[string]any) { o["rate_window_seconds"] = nil }},
		{"double counted active", func(o map[string]any) { o["active_connections"] = int64(1) }},
		{"unknown kind", func(o map[string]any) {
			o["inbounds"].([]any)[0].(map[string]any)["kind"] = "vless"
		}},
		{"duplicate inbound tag", func(o map[string]any) {
			inbounds := o["inbounds"].([]any)
			duplicate := map[string]any{}
			for key, value := range inbounds[0].(map[string]any) {
				duplicate[key] = value
			}
			o["inbounds"] = append(inbounds, duplicate)
			o["active_connections"] = int64(4)
		}},
		{"partial without inbound rows", func(o map[string]any) {
			o["availability"] = "partial"
			o["inbounds"] = []any{}
			o["active_connections"] = nil
		}},
	}
	for _, tcCase := range cases {
		t.Run(tcCase.name, func(t *testing.T) {
			observation := baseTrafficObservation(collectedAt)
			tcCase.mutate(observation)
			raw, err := json.Marshal(observation)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ValidateTrafficObservation(collectedAt, raw); err == nil {
				t.Fatalf("incoherent observation accepted: %v", observation)
			}
		})
	}
}

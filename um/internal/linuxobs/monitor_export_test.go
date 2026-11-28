package linuxobs

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/contract"
)

func TestMonitorExportDisabledSnapshotIsByteIdentical(t *testing.T) {
	col, _, _, _ := newFakeCollector(t)
	rc := reportContext(nil, testExpectedTags())
	before, err := col.Snapshot(context.Background(), rc)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	// A configured local export path must not change the disabled rev-5 body:
	// byte-identical means no contract_revision/traffic_observation members.
	col.MonitorExportFile = writeMonitorExport(t, validMonitorExport(testCollectedAt, 7, "aa"))
	after, err := col.Snapshot(context.Background(), rc)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if string(before) != string(after) {
		t.Fatalf("source-disabled snapshot changed when an export path was configured")
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(after, &members); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	for _, field := range []string{"contract_revision", "traffic_observation"} {
		if _, present := members[field]; present {
			t.Fatalf("source-disabled rev-5 body carries %q", field)
		}
	}
	// The byte-identical body remains valid under the frozen rev-5 contract.
	validateSnapshotBody(t, after)
}

func TestMonitorExportValidFreshObservation(t *testing.T) {
	col, _, _, _ := newFakeCollector(t)
	col.MonitorExportFile = writeMonitorExport(t, validMonitorExport(testCollectedAt-2, 7, "aa"))
	raw, err := col.Snapshot(context.Background(), reportContext([]string{sourceMonitorExport}, testExpectedTags()))
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	var body snapshotBody
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.ContractRevision != contractRevision7 {
		t.Fatalf("contract_revision = %d, want 7", body.ContractRevision)
	}
	obs := body.TrafficObservation
	if obs == nil {
		t.Fatal("missing traffic_observation")
	}
	if obs.Source != "monitor_readonly_export" || obs.CounterScope != "observation_epoch" ||
		obs.Exactness != "lower_bound" || obs.Freshness != "fresh" || obs.Availability != "ok" {
		t.Fatalf("unexpected observation header: %+v", obs)
	}
	if obs.SourceEpoch != strings.Repeat("aa", 16) || obs.Sequence != 7 {
		t.Fatalf("unexpected source epoch/sequence: %q/%d", obs.SourceEpoch, obs.Sequence)
	}
	if obs.AgeSeconds != 2 || obs.ObservedAt != testCollectedAt-2 {
		t.Fatalf("unexpected age/observed_at: %d/%d", obs.AgeSeconds, obs.ObservedAt)
	}
	if obs.ActiveConnections == nil || *obs.ActiveConnections != 3 {
		t.Fatalf("unexpected active connections: %v", obs.ActiveConnections)
	}
	if len(obs.Inbounds) != 2 {
		t.Fatalf("inbounds = %d, want 2", len(obs.Inbounds))
	}
	for _, inbound := range obs.Inbounds {
		if inbound.Availability != "ok" || inbound.Quality != "lower_bound" ||
			inbound.UplinkObservedLowerBoundBytes == nil || inbound.DownlinkObservedLowerBoundBytes == nil {
			t.Fatalf("unexpected inbound observation: %+v", inbound)
		}
	}
	// No contract totals are produced from lower bounds.
	if len(body.Traffic) != 0 || body.Availability.Traffic != "unavailable" {
		t.Fatalf("traffic projection is not honestly empty: %+v", body.Availability)
	}
	// The rev-7 runtime coherence rules accept the emitted observation.
	var envelope struct {
		CollectedAt        int64           `json:"collected_at"`
		TrafficObservation json.RawMessage `json:"traffic_observation"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if _, err := contract.ValidateTrafficObservation(envelope.CollectedAt, envelope.TrafficObservation); err != nil {
		t.Fatalf("rev-7 traffic observation rejected: %v", err)
	}
}

func TestMonitorExportStaleAndMonitorStale(t *testing.T) {
	t.Run("old observed_at is stale", func(t *testing.T) {
		col, _, _, _ := newFakeCollector(t)
		export := validMonitorExport(testCollectedAt-200, 3, "bb")
		col.MonitorExportFile = writeMonitorExport(t, export)
		raw, err := col.Snapshot(context.Background(), reportContext([]string{sourceMonitorExport}, testExpectedTags()))
		if err != nil {
			t.Fatalf("snapshot: %v", err)
		}
		obs := decodeTrafficObservation(t, raw)
		if obs.Freshness != "stale" || obs.Availability != "partial" {
			t.Fatalf("stale export rendered as %s/%s", obs.Freshness, obs.Availability)
		}
		if obs.AgeSeconds != 200 {
			t.Fatalf("age_seconds = %d, want 200", obs.AgeSeconds)
		}
		// Lower-bound counters remain honest observed data, just not fresh.
		if obs.Inbounds[0].Quality != "lower_bound" || obs.Inbounds[0].UplinkObservedLowerBoundBytes == nil {
			t.Fatalf("stale lower bounds were discarded: %+v", obs.Inbounds[0])
		}
	})
	t.Run("monitor_stale is never fresh", func(t *testing.T) {
		col, _, _, _ := newFakeCollector(t)
		export := validMonitorExport(testCollectedAt, 4, "cc")
		export["monitor_stale"] = true
		lastSuccess := testCollectedAt - 600
		export["monitor_last_success_at"] = lastSuccess
		col.MonitorExportFile = writeMonitorExport(t, export)
		raw, err := col.Snapshot(context.Background(), reportContext([]string{sourceMonitorExport}, testExpectedTags()))
		if err != nil {
			t.Fatalf("snapshot: %v", err)
		}
		obs := decodeTrafficObservation(t, raw)
		if obs.Freshness != "stale" || obs.Availability == "ok" {
			t.Fatalf("monitor_stale export rendered as %s/%s", obs.Freshness, obs.Availability)
		}
	})
}

func TestMonitorExportInvalidInputsDegradeToUnavailable(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, export map[string]any)
		raw    string
	}{
		{name: "malformed", raw: "{not json"},
		{name: "unsupported schema version", mutate: func(_ *testing.T, export map[string]any) {
			export["schema_version"] = 2
		}},
		{name: "unknown member privacy field", mutate: func(_ *testing.T, export map[string]any) {
			export["user_id"] = "alice"
		}},
		{name: "duplicate tag", mutate: func(_ *testing.T, export map[string]any) {
			inbounds := export["inbounds"].([]map[string]any)
			duplicate := make(map[string]any, len(inbounds[0]))
			for key, value := range inbounds[0] {
				duplicate[key] = value
			}
			export["inbounds"] = append(inbounds, duplicate)
		}},
		{name: "counter overflow", mutate: func(_ *testing.T, export map[string]any) {
			inbounds := export["inbounds"].([]map[string]any)
			inbounds[0]["observed_uplink_bytes"] = int64(9007199254740992)
		}},
		{name: "future observed_at", mutate: func(_ *testing.T, export map[string]any) {
			observed := testCollectedAt + 10
			export["observed_at"] = observed
			export["generated_at"] = observed + 1
			export["monitor_last_success_at"] = observed
			for _, inbound := range export["inbounds"].([]map[string]any) {
				inbound["observed_at"] = observed
			}
		}},
		{name: "generated before observed", mutate: func(_ *testing.T, export map[string]any) {
			export["generated_at"] = testCollectedAt - 100
		}},
		{name: "negative byte counter", mutate: func(_ *testing.T, export map[string]any) {
			inbounds := export["inbounds"].([]map[string]any)
			inbounds[0]["observed_downlink_bytes"] = int64(-1)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			col, _, _, _ := newFakeCollector(t)
			if tc.raw != "" {
				path := filepath.Join(t.TempDir(), "export.json")
				if err := os.WriteFile(path, []byte(tc.raw), 0o600); err != nil {
					t.Fatalf("write export: %v", err)
				}
				col.MonitorExportFile = path
			} else {
				export := validMonitorExport(testCollectedAt, 5, "dd")
				tc.mutate(t, export)
				col.MonitorExportFile = writeMonitorExport(t, export)
			}
			raw, err := col.Snapshot(context.Background(), reportContext([]string{sourceMonitorExport}, testExpectedTags()))
			if err != nil {
				t.Fatalf("snapshot must not fail for an invalid export: %v", err)
			}
			var body snapshotBody
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if body.ContractRevision != contractRevision7 || body.TrafficObservation == nil {
				t.Fatalf("enabled source must still emit a rev-7 object")
			}
			obs := body.TrafficObservation
			if obs.Freshness != "unavailable" || obs.Availability != "unavailable" {
				t.Fatalf("invalid export rendered as %s/%s", obs.Freshness, obs.Availability)
			}
			if obs.ActiveConnections != nil || len(obs.Inbounds) != 0 {
				t.Fatalf("invalid export leaked observations: %+v", obs)
			}
			// The rest of the snapshot still succeeds honestly; the base rev-5
			// projection is untouched by a degraded observation.
			if body.Availability.Traffic != "unavailable" || len(body.Traffic) != 0 {
				t.Fatalf("degraded observation changed the base traffic projection: %+v", body.Availability)
			}
		})
	}
}

func TestMonitorExportFileGuards(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		col, _, _, _ := newFakeCollector(t)
		col.MonitorExportFile = filepath.Join(t.TempDir(), "absent.json")
		assertUnavailableObservation(t, col)
	})
	t.Run("relative path", func(t *testing.T) {
		col, _, _, _ := newFakeCollector(t)
		col.MonitorExportFile = "export.json"
		assertUnavailableObservation(t, col)
	})
	t.Run("path traversal", func(t *testing.T) {
		if err := ValidateMonitorExportPath("exports/../secret.json"); err == nil {
			t.Fatal("relative traversal path accepted")
		}
		col, _, _, _ := newFakeCollector(t)
		col.MonitorExportFile = filepath.Join(t.TempDir(), "exports", "..", "other.json")
		assertUnavailableObservation(t, col)
	})
	t.Run("directory", func(t *testing.T) {
		col, _, _, _ := newFakeCollector(t)
		col.MonitorExportFile = t.TempDir()
		assertUnavailableObservation(t, col)
	})
	t.Run("oversized", func(t *testing.T) {
		col, _, _, _ := newFakeCollector(t)
		path := filepath.Join(t.TempDir(), "export.json")
		content := strings.Repeat(" ", int(maxMonitorExportBytes)) + "{}"
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write oversized export: %v", err)
		}
		col.MonitorExportFile = path
		assertUnavailableObservation(t, col)
	})
	t.Run("symlink", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation requires privileges on this host")
		}
		col, _, _, _ := newFakeCollector(t)
		dir := t.TempDir()
		target := writeMonitorExportAt(t, dir, "target.json", validMonitorExport(testCollectedAt, 6, "ee"))
		link := filepath.Join(dir, "export.json")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlink unsupported: %v", err)
		}
		col.MonitorExportFile = link
		assertUnavailableObservation(t, col)
	})
	t.Run("permission denied", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("POSIX file modes are not enforced on this host")
		}
		if os.Geteuid() == 0 {
			t.Skip("root bypasses file modes")
		}
		col, _, _, _ := newFakeCollector(t)
		path := writeMonitorExport(t, validMonitorExport(testCollectedAt, 8, "ff"))
		if err := os.Chmod(path, 0o000); err != nil {
			t.Skipf("chmod unsupported: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
		col.MonitorExportFile = path
		assertUnavailableObservation(t, col)
	})
}

func TestMonitorExportSequenceAndEpochGuard(t *testing.T) {
	t.Run("replay of the same sequence is not fresh", func(t *testing.T) {
		col, _, _, _ := newFakeCollector(t)
		col.MonitorExportFile = writeMonitorExport(t, validMonitorExport(testCollectedAt, 9, "ab"))
		first := snapshotTraffic(t, col)
		if first.Freshness != "fresh" {
			t.Fatalf("first export freshness = %s", first.Freshness)
		}
		second := snapshotTraffic(t, col)
		if second.Freshness != "unavailable" || second.Availability != "unavailable" {
			t.Fatalf("replayed export rendered as %s/%s", second.Freshness, second.Availability)
		}
		if second.ObservedAt != 0 || second.AgeSeconds != 86400 || second.SourceEpoch != "00000000000000000000000000000000" {
			t.Fatalf("unavailable observation is not the exact no-observation sentinel: %+v", second)
		}
	})
	t.Run("sequence regression is unavailable", func(t *testing.T) {
		col, _, _, _ := newFakeCollector(t)
		col.MonitorExportFile = writeMonitorExport(t, validMonitorExport(testCollectedAt, 9, "ac"))
		if obs := snapshotTraffic(t, col); obs.Freshness != "fresh" {
			t.Fatalf("first export freshness = %s", obs.Freshness)
		}
		col.MonitorExportFile = writeMonitorExport(t, validMonitorExport(testCollectedAt, 8, "ac"))
		if obs := snapshotTraffic(t, col); obs.Freshness != "unavailable" {
			t.Fatalf("regressed export rendered as %s", obs.Freshness)
		}
	})
	t.Run("source epoch change is accepted", func(t *testing.T) {
		col, _, _, _ := newFakeCollector(t)
		col.MonitorExportFile = writeMonitorExport(t, validMonitorExport(testCollectedAt-200, 9, "ad"))
		if obs := snapshotTraffic(t, col); obs.Freshness != "stale" {
			t.Fatalf("first export freshness = %s", obs.Freshness)
		}
		col.MonitorExportFile = writeMonitorExport(t, validMonitorExport(testCollectedAt, 1, "ae"))
		obs := snapshotTraffic(t, col)
		if obs.Freshness != "fresh" || obs.Availability != "ok" {
			t.Fatalf("new epoch rendered as %s/%s", obs.Freshness, obs.Availability)
		}
		if obs.SourceEpoch != strings.Repeat("ae", 16) || obs.Sequence != 1 {
			t.Fatalf("unexpected new epoch identity: %q/%d", obs.SourceEpoch, obs.Sequence)
		}
	})
	t.Run("invalid export does not poison the sequence guard", func(t *testing.T) {
		col, _, _, _ := newFakeCollector(t)
		bad := validMonitorExport(testCollectedAt, 5, "b1")
		bad["inbounds"].([]map[string]any)[0]["quality"] = "bogus"
		col.MonitorExportFile = writeMonitorExport(t, bad)
		if obs := snapshotTraffic(t, col); obs.Freshness != "unavailable" {
			t.Fatalf("malformed export rendered as %s", obs.Freshness)
		}
		// The corrected file keeps the same sequence: the rejected publication
		// must not have advanced the in-memory guard.
		col.MonitorExportFile = writeMonitorExport(t, validMonitorExport(testCollectedAt, 5, "b1"))
		obs := snapshotTraffic(t, col)
		if obs.Freshness != "fresh" || obs.Availability != "ok" {
			t.Fatalf("corrected export rendered as %s/%s", obs.Freshness, obs.Availability)
		}
	})
	t.Run("epoch change with backwards observed_at is rejected", func(t *testing.T) {
		col, _, _, _ := newFakeCollector(t)
		col.MonitorExportFile = writeMonitorExport(t, validMonitorExport(testCollectedAt, 9, "af"))
		if obs := snapshotTraffic(t, col); obs.Freshness != "fresh" {
			t.Fatalf("first export freshness = %s", obs.Freshness)
		}
		col.MonitorExportFile = writeMonitorExport(t, validMonitorExport(testCollectedAt-30, 1, "b0"))
		if obs := snapshotTraffic(t, col); obs.Freshness != "unavailable" {
			t.Fatalf("backwards epoch change rendered as %s", obs.Freshness)
		}
	})
}

func TestMonitorExportMissingExpectedTagIsPartial(t *testing.T) {
	col, _, _, _ := newFakeCollector(t)
	export := validMonitorExport(testCollectedAt, 11, "ba")
	export["inbounds"] = export["inbounds"].([]map[string]any)[:1] // only vless-in
	export["active_connections"] = int64(2)
	col.MonitorExportFile = writeMonitorExport(t, export)
	raw, err := col.Snapshot(context.Background(), reportContext([]string{sourceMonitorExport}, testExpectedTags()))
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	obs := decodeTrafficObservation(t, raw)
	if obs.Freshness != "fresh" || obs.Availability != "partial" {
		t.Fatalf("missing tag rendered as %s/%s", obs.Freshness, obs.Availability)
	}
	if len(obs.Inbounds) != 2 {
		t.Fatalf("inbounds = %d, want one row per expected tag", len(obs.Inbounds))
	}
	for _, inbound := range obs.Inbounds {
		if inbound.InboundTag == "hy2-in" {
			if inbound.Availability != "unavailable" || inbound.Quality != "unavailable" ||
				inbound.UplinkObservedLowerBoundBytes != nil {
				t.Fatalf("missing tag was not rendered honestly unavailable: %+v", inbound)
			}
		}
	}
}

func TestMonitorExportPartialQualityWithNullCounters(t *testing.T) {
	// The monitor publishes an over-range/stale counter as null with quality
	// "partial"; the agent must treat that as an honest partial observation, not
	// a malformed file.
	col, _, _, _ := newFakeCollector(t)
	export := validMonitorExport(testCollectedAt, 13, "bc")
	export["monitor_stale"] = true
	inbounds := export["inbounds"].([]map[string]any)
	inbounds[0]["observed_uplink_bytes"] = nil
	inbounds[0]["observed_downlink_bytes"] = nil
	inbounds[0]["quality"] = "partial"
	inbounds[1]["quality"] = "partial"
	inbounds[1]["observed_uplink_bytes"] = nil
	inbounds[1]["observed_downlink_bytes"] = nil
	export["inbounds"] = inbounds
	col.MonitorExportFile = writeMonitorExport(t, export)
	raw, err := col.Snapshot(context.Background(), reportContext([]string{sourceMonitorExport}, testExpectedTags()))
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	obs := decodeTrafficObservation(t, raw)
	if obs.Freshness != "stale" || obs.Availability != "partial" {
		t.Fatalf("partial-stale export rendered as %s/%s", obs.Freshness, obs.Availability)
	}
	for _, inbound := range obs.Inbounds {
		if inbound.Quality != "partial" || inbound.Availability != "partial" {
			t.Fatalf("partial quality mapping = %+v", inbound)
		}
		if inbound.UplinkObservedLowerBoundBytes != nil || inbound.DownlinkObservedLowerBoundBytes != nil {
			t.Fatalf("partial null counters were fabricated: %+v", inbound)
		}
	}
}

func TestMonitorExportNotReadForMetricsOrEvents(t *testing.T) {
	col, _, _, _ := newFakeCollector(t)
	col.MonitorExportFile = writeMonitorExport(t, validMonitorExport(testCollectedAt, 12, "bb"))
	rc := reportContext([]string{sourceMonitorExport}, testExpectedTags())
	for name, bodyFn := range map[string]func() ([]byte, error){
		"metrics": func() ([]byte, error) { return col.Metrics(context.Background(), rc) },
		"events":  func() ([]byte, error) { return col.Events(context.Background(), rc) },
	} {
		raw, err := bodyFn()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var members map[string]json.RawMessage
		if err := json.Unmarshal(raw, &members); err != nil {
			t.Fatalf("%s decode: %v", name, err)
		}
		for _, field := range []string{"contract_revision", "traffic_observation"} {
			if _, present := members[field]; present {
				t.Fatalf("%s unexpectedly carries %q", name, field)
			}
		}
	}
}

// validMonitorExport returns a schema-shaped synthetic export. observedAt is the
// export's observed timestamp; epochSeed is repeated 16 times to form a 32-hex
// source epoch.
func validMonitorExport(observedAt, sequence int64, epochSeed string) map[string]any {
	return map[string]any{
		"schema":                  monitorExportSchema,
		"schema_version":          monitorExportSchemaVersion,
		"source":                  monitorExportSource,
		"source_epoch":            strings.Repeat(epochSeed, 16),
		"sequence":                sequence,
		"generated_at":            observedAt + 1,
		"observed_at":             observedAt,
		"monitor_stale":           false,
		"monitor_last_success_at": observedAt,
		"counter_scope":           "observation_epoch",
		"exactness":               "lower_bound",
		"active_connections":      int64(3),
		"rate_window_seconds":     60.0,
		"inbounds": []map[string]any{
			{
				"inbound_tag": "vless-in", "kind": "reality",
				"observed_uplink_bytes": int64(1000), "observed_downlink_bytes": int64(2000),
				"uplink_observed_rate_bps": 10.5, "downlink_observed_rate_bps": 20.5,
				"active_connections": int64(2), "observed_at": observedAt, "quality": "lower_bound",
			},
			{
				"inbound_tag": "hy2-in", "kind": "hysteria2",
				"observed_uplink_bytes": int64(3000), "observed_downlink_bytes": int64(4000),
				"uplink_observed_rate_bps": nil, "downlink_observed_rate_bps": nil,
				"active_connections": int64(1), "observed_at": observedAt, "quality": "lower_bound",
			},
		},
	}
}

func writeMonitorExport(t *testing.T, export map[string]any) string {
	t.Helper()
	return writeMonitorExportAt(t, t.TempDir(), "export.json", export)
}

func writeMonitorExportAt(t *testing.T, dir, name string, export map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(export)
	if err != nil {
		t.Fatalf("marshal export: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write export: %v", err)
	}
	return path
}

func snapshotTraffic(t *testing.T, col *Collector) *trafficObservationBody {
	t.Helper()
	raw, err := col.Snapshot(context.Background(), reportContext([]string{sourceMonitorExport}, testExpectedTags()))
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	return decodeTrafficObservation(t, raw)
}

func decodeTrafficObservation(t *testing.T, raw []byte) *trafficObservationBody {
	t.Helper()
	var body snapshotBody
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode snapshot body: %v", err)
	}
	if body.ContractRevision != contractRevision7 || body.TrafficObservation == nil {
		t.Fatalf("snapshot did not carry a rev-7 traffic observation")
	}
	return body.TrafficObservation
}

func assertUnavailableObservation(t *testing.T, col *Collector) {
	t.Helper()
	obs := snapshotTraffic(t, col)
	if obs.Freshness != "unavailable" || obs.Availability != "unavailable" {
		t.Fatalf("observation rendered as %s/%s, want unavailable/unavailable", obs.Freshness, obs.Availability)
	}
	if obs.ActiveConnections != nil || len(obs.Inbounds) != 0 {
		t.Fatalf("unavailable observation leaked counters: %+v", obs)
	}
	if obs.SourceEpoch != zeroCounterEpoch || obs.Sequence != 0 {
		t.Fatalf("unavailable observation identity is not the documented unknown token: %q/%d", obs.SourceEpoch, obs.Sequence)
	}
}

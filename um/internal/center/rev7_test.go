package center_test

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/center"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/schema"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/wire"
)

// rev7ContractDir materializes a candidate revision-7 contract directory for
// local tests only. The normative rev-7 schema files are authored in the frozen
// contract change under docs/um/contracts/v1; until that lands this helper
// derives the rev-7 snapshot/agent-config schemas from the frozen rev-5 files so
// the center schema-selection path can be exercised without editing production
// contract files. These files are written to a temp dir and are not committed.
func rev7ContractDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	entries, err := os.ReadDir(contractsDir)
	if err != nil {
		t.Fatalf("read frozen contracts: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".schema.json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(contractsDir, entry.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(dir, entry.Name()), raw, 0o600); err != nil {
			t.Fatalf("copy %s: %v", entry.Name(), err)
		}
	}
	// Derive report-snapshot.rev7.schema.json from the frozen rev-5 schema.
	snapshot := readSchemaDoc(t, filepath.Join(contractsDir, "report-snapshot.schema.json"))
	snapshot["$id"] = "https://um.invalid/contracts/v1/report-snapshot.rev7.schema.json"
	props := snapshot["properties"].(map[string]any)
	props["contract_revision"] = map[string]any{"const": 7}
	props["traffic_observation"] = rev7TrafficObservationSchema()
	snapshot["required"] = append(snapshot["required"].([]any), "contract_revision", "traffic_observation")
	writeSchemaDoc(t, filepath.Join(dir, "report-snapshot.rev7.schema.json"), snapshot)
	// Derive agent-config.rev7.schema.json with the OPTIONAL monitor_export switch.
	agentConfig := readSchemaDoc(t, filepath.Join(contractsDir, "agent-config.schema.json"))
	agentConfig["$id"] = "https://um.invalid/contracts/v1/agent-config.rev7.schema.json"
	collect := agentConfig["properties"].(map[string]any)["collect"].(map[string]any)
	collect["properties"].(map[string]any)["monitor_export"] = map[string]any{"type": "boolean"}
	writeSchemaDoc(t, filepath.Join(dir, "agent-config.rev7.schema.json"), agentConfig)
	return dir
}

func readSchemaDoc(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return doc
}

func writeSchemaDoc(t *testing.T, path string, doc map[string]any) {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func rev7TrafficObservationSchema() map[string]any {
	return map[string]any{
		"type": "object", "additionalProperties": false,
		"required": []any{"source", "source_epoch", "sequence", "observed_at", "age_seconds",
			"freshness", "availability", "counter_scope", "exactness", "active_connections",
			"rate_window_seconds", "inbounds"},
		"properties": map[string]any{
			"source":        map[string]any{"const": "monitor_readonly_export"},
			"source_epoch":  map[string]any{"type": "string", "pattern": "^[0-9a-f]{32}$"},
			"sequence":      map[string]any{"type": "integer", "minimum": 0, "maximum": 9007199254740991},
			"observed_at":   map[string]any{"type": "integer", "minimum": 0, "maximum": 1000000000000},
			"age_seconds":   map[string]any{"type": "integer", "minimum": 0, "maximum": 86400},
			"freshness":     map[string]any{"enum": []any{"fresh", "stale", "unavailable"}},
			"availability":  map[string]any{"enum": []any{"ok", "partial", "unavailable"}},
			"counter_scope": map[string]any{"const": "observation_epoch"},
			"exactness":     map[string]any{"const": "lower_bound"},
			"active_connections": map[string]any{"oneOf": []any{
				map[string]any{"type": "integer", "minimum": 0, "maximum": 1000000},
				map[string]any{"type": "null"},
			}},
			"rate_window_seconds": map[string]any{"oneOf": []any{
				map[string]any{"type": "number", "exclusiveMinimum": 0, "maximum": 3600},
				map[string]any{"type": "null"},
			}},
			"inbounds": map[string]any{
				"type": "array", "minItems": 0, "maxItems": 16,
				"items": map[string]any{
					"type": "object", "additionalProperties": false,
					"required": []any{"inbound_tag", "kind", "observed_at", "availability", "quality",
						"uplink_observed_lower_bound_bytes", "downlink_observed_lower_bound_bytes",
						"uplink_observed_rate_bps", "downlink_observed_rate_bps", "active_connections"},
					"properties": map[string]any{
						"inbound_tag": map[string]any{"type": "string", "maxLength": 64,
							"pattern": "^[A-Za-z0-9][A-Za-z0-9._-]*$"},
						"kind":         map[string]any{"enum": []any{"reality", "hysteria2", "other"}},
						"observed_at":  map[string]any{"type": "integer", "minimum": 0, "maximum": 1000000000000},
						"availability": map[string]any{"enum": []any{"ok", "partial", "unavailable"}},
						"quality":      map[string]any{"enum": []any{"lower_bound", "partial", "unavailable"}},
						"uplink_observed_lower_bound_bytes": map[string]any{"oneOf": []any{
							map[string]any{"type": "integer", "minimum": 0, "maximum": 9007199254740991},
							map[string]any{"type": "null"},
						}},
						"downlink_observed_lower_bound_bytes": map[string]any{"oneOf": []any{
							map[string]any{"type": "integer", "minimum": 0, "maximum": 9007199254740991},
							map[string]any{"type": "null"},
						}},
						"uplink_observed_rate_bps": map[string]any{"oneOf": []any{
							map[string]any{"type": "number", "minimum": 0, "maximum": 1000000000000},
							map[string]any{"type": "null"},
						}},
						"downlink_observed_rate_bps": map[string]any{"oneOf": []any{
							map[string]any{"type": "number", "minimum": 0, "maximum": 1000000000000},
							map[string]any{"type": "null"},
						}},
						"active_connections": map[string]any{"type": "integer", "minimum": 0, "maximum": 1000000},
					},
				},
			},
		},
	}
}

func startRev7TestCenter(t *testing.T) (*testCenter, string) {
	t.Helper()
	dir := rev7ContractDir(t)
	dbPath := filepath.Join(t.TempDir(), "private", "center.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	schemas, err := schema.Load(dir)
	if err != nil {
		t.Fatalf("load rev7 schemas: %v", err)
	}
	svc, err := center.NewService(center.ServiceConfig{Store: st, Schemas: schemas})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	cfg := center.Config{IngestAddr: "127.0.0.1:0", AdminAddr: "127.0.0.1:0",
		DBPath: dbPath, ContractDir: dir, RateLimitPerSecond: -1}
	srv, err := center.NewServer(cfg, svc)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	tc := &testCenter{store: st, server: srv, url: "http://" + srv.IngestAddr(), dbPath: dbPath}
	t.Cleanup(func() { _ = srv.Close(); _ = st.Close() })
	return tc, dir
}

func rev7Sources(monitorExport bool) map[string]bool {
	return map[string]bool{
		"system": false, "services": false, "singbox_api": false,
		"mihomo_api": false, "terminal": false, "events": false,
		"monitor_export": monitorExport,
	}
}

// enableRev7Config enables monitor_export at/after the enrollment-time config.
func enableRev7Config(t *testing.T, tc *testCenter, a *syntheticAgent, enabled bool) {
	t.Helper()
	tags := []store.InboundTag{{InboundTag: "vless-in", Kind: "reality"}, {InboundTag: "hy2-in", Kind: "hysteria2"}}
	if _, err := tc.store.UpdateNodeConfig(contextBackground(), a.nodeID, rev7Sources(enabled), tags, 60, time.Now().Unix()); err != nil {
		t.Fatalf("update node config: %v", err)
	}
}

// rev7SnapshotDoc builds a snapshot whose base telemetry is the honest
// unavailable projection (all other sources disabled) plus the rev-7 observation.
func rev7SnapshotDoc(t *testing.T, collectedAt int64, observation map[string]any) map[string]any {
	t.Helper()
	doc := b2SnapshotDoc(t, collectedAt)
	doc["availability"] = map[string]any{
		"system": "unavailable", "services": "unavailable", "protocols": "unavailable",
		"traffic": "unavailable", "clients": "unavailable",
	}
	doc["system"] = map[string]any{
		"cpu_pct": nil, "load1": nil, "mem_total_bytes": nil, "mem_used_bytes": nil,
		"disk_total_bytes": nil, "disk_used_bytes": nil, "net_rx_bytes": nil, "net_tx_bytes": nil,
	}
	doc["services"] = []any{}
	doc["protocols"] = []any{}
	doc["traffic"] = []any{}
	doc["clients"] = map[string]any{"active": nil, "tracked": nil, "summaries": []any{}}
	doc["contract_revision"] = 7
	doc["traffic_observation"] = observation
	// Revision-7 bodies are only produced by the rev-7-capable agent release.
	doc["agent"].(map[string]any)["version"] = "1.1.0"
	return doc
}

func freshTrafficObservationDoc(collectedAt int64) map[string]any {
	observed := collectedAt - 2
	between := func(uplink, downlink int64) map[string]any {
		return map[string]any{
			"uplink_observed_lower_bound_bytes": uplink, "downlink_observed_lower_bound_bytes": downlink,
			"uplink_observed_rate_bps": nil, "downlink_observed_rate_bps": nil,
		}
	}
	inbound := func(tag, kind string, uplink, downlink int64, active int64) map[string]any {
		entry := between(uplink, downlink)
		entry["inbound_tag"] = tag
		entry["kind"] = kind
		entry["observed_at"] = observed
		entry["availability"] = "ok"
		entry["quality"] = "lower_bound"
		entry["active_connections"] = active
		return entry
	}
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
		"active_connections":  int64(3),
		"rate_window_seconds": 60.0,
		"inbounds": []any{
			inbound("vless-in", "reality", 1000, 2000, 2),
			inbound("hy2-in", "hysteria2", 3000, 4000, 1),
		},
	}
}

func pullConfig(t *testing.T, tc *testCenter, a *syntheticAgent) (int, map[string]any) {
	t.Helper()
	body := []byte("{}")
	a.seq++
	h, err := a.headers(wire.Config, time.Now().Unix(), b2Nonce(t), body)
	if err != nil {
		t.Fatalf("config headers: %v", err)
	}
	return doPost(t, tc, "/v1/agent/config", h, body)
}

func configCollect(t *testing.T, resp map[string]any) map[string]any {
	t.Helper()
	collect, ok := resp["collect"].(map[string]any)
	if !ok {
		t.Fatalf("config response has no collect object: %v", resp)
	}
	return collect
}

func requireSixKeyCollect(t *testing.T, resp map[string]any) {
	t.Helper()
	collect := configCollect(t, resp)
	if len(collect) != 6 {
		t.Fatalf("old/unknown agent must receive exactly six collect keys, got %v", collect)
	}
	if _, present := collect["monitor_export"]; present {
		t.Fatalf("monitor_export emitted to an old/unknown agent: %v", collect)
	}
}

// rev5HonestSnapshotDoc is a valid rev-5 Linux snapshot with the honest
// unavailable projection and an explicit agent.version. It is the bootstrap
// report that lets the center learn a node's capability version (OD-LT-14).
func rev5HonestSnapshotDoc(t *testing.T, collectedAt int64, version string) map[string]any {
	t.Helper()
	doc := b2SnapshotDoc(t, collectedAt)
	doc["agent"].(map[string]any)["version"] = version
	doc["availability"] = map[string]any{
		"system": "unavailable", "services": "unavailable", "protocols": "unavailable",
		"traffic": "unavailable", "clients": "unavailable",
	}
	doc["system"] = map[string]any{
		"cpu_pct": nil, "load1": nil, "mem_total_bytes": nil, "mem_used_bytes": nil,
		"disk_total_bytes": nil, "disk_used_bytes": nil, "net_rx_bytes": nil, "net_tx_bytes": nil,
	}
	doc["services"] = []any{}
	doc["protocols"] = []any{}
	doc["traffic"] = []any{}
	doc["clients"] = map[string]any{"active": nil, "tracked": nil, "summaries": []any{}}
	return doc
}

// bootstrapAgentVersion sends one authenticated rev-5 snapshot so the center
// records the node's latest agent.version (the OD-LT-14 capability evidence).
func bootstrapAgentVersion(t *testing.T, tc *testCenter, a *syntheticAgent, collectedAt int64, version string) {
	t.Helper()
	status, resp, _ := reportAttempt(t, tc, a, rev5HonestSnapshotDoc(t, collectedAt, version))
	if status != http.StatusOK || (resp["result"] != "accepted" && resp["result"] != "stale_ignored") {
		t.Fatalf("bootstrap snapshot (version %s) status=%d resp=%v", version, status, resp)
	}
}

func TestRev7AgentConfigIncludesOptionalMonitorExport(t *testing.T) {
	tc, _ := startRev7TestCenter(t)
	linux := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	enableRev7Config(t, tc, linux, true)
	base := b2BaseCollected(t)

	// Enabling before any authenticated snapshot: the version is unknown, so the
	// strict six-key response is served (an old agent must never see the key).
	status, resp := pullConfig(t, tc, linux)
	if status != http.StatusOK {
		t.Fatalf("unknown-version config pull status=%d resp=%v", status, resp)
	}
	requireSixKeyCollect(t, resp)

	// Old agent version: still six keys even though the source is enabled.
	bootstrapAgentVersion(t, tc, linux, base, "1.0.0")
	status, resp = pullConfig(t, tc, linux)
	if status != http.StatusOK {
		t.Fatalf("old-version config pull status=%d resp=%v", status, resp)
	}
	requireSixKeyCollect(t, resp)

	// A rev-7-capable agent reports 1.1.0; the next config pull may carry the
	// optional switch, and only then.
	bootstrapAgentVersion(t, tc, linux, base+10, "1.1.0")
	status, resp = pullConfig(t, tc, linux)
	if status != http.StatusOK {
		t.Fatalf("rev7 config pull status=%d resp=%v", status, resp)
	}
	collect := configCollect(t, resp)
	if len(collect) != 7 || collect["monitor_export"] != true {
		t.Fatalf("rev7 collect = %v", resp["collect"])
	}

	// Disabling the stored source omits the key entirely (six keys, absence=false).
	enableRev7Config(t, tc, linux, false)
	status, resp = pullConfig(t, tc, linux)
	if status != http.StatusOK {
		t.Fatalf("disabled config pull status=%d resp=%v", status, resp)
	}
	requireSixKeyCollect(t, resp)
}

func TestRev7AgentVersionGateBootstrapOrdering(t *testing.T) {
	tc, _ := startRev7TestCenter(t)
	linux := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	enableRev7Config(t, tc, linux, true)
	base := b2BaseCollected(t)
	bootstrapAgentVersion(t, tc, linux, base, "1.0.0")
	// A newer authenticated snapshot upgrades the capability evidence.
	bootstrapAgentVersion(t, tc, linux, base+10, "1.1.0")
	status, resp := pullConfig(t, tc, linux)
	if status != http.StatusOK {
		t.Fatalf("config pull status=%d resp=%v", status, resp)
	}
	collect := configCollect(t, resp)
	if len(collect) != 7 || collect["monitor_export"] != true {
		t.Fatalf("post-upgrade collect = %v", collect)
	}
	// A prerelease of the minimum is semver-older and is not sufficient.
	bootstrapAgentVersion(t, tc, linux, base+20, "1.1.0-rc.1")
	status, resp = pullConfig(t, tc, linux)
	if status != http.StatusOK {
		t.Fatalf("prerelease config pull status=%d resp=%v", status, resp)
	}
	requireSixKeyCollect(t, resp)
	// Windows never receives the linux-only switch, even before any report (the
	// gate is class AND source AND rev-7 contract AND version).
	windows := enrollAgent(t, tc, store.NodeClassWindowsTerminal, "windows")
	status, resp = pullConfig(t, tc, windows)
	if status != http.StatusOK {
		t.Fatalf("windows config pull status=%d resp=%v", status, resp)
	}
	requireSixKeyCollect(t, resp)
}

func TestRev7ConfigOmitsSwitchWithoutRev7Schema(t *testing.T) {
	tc := startTestCenter(t) // frozen rev-5 contract dir only
	linux := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	enableRev7Config(t, tc, linux, true)
	base := b2BaseCollected(t)
	bootstrapAgentVersion(t, tc, linux, base, "1.1.0")
	// The stored source switch stays true, but without the rev-7 contract schema a
	// center must keep serving the frozen six-key rev-5 config (old agents are
	// unaffected); it takes effect after the contract deployment.
	status, resp := pullConfig(t, tc, linux)
	if status != http.StatusOK {
		t.Fatalf("config pull without rev7 schema status=%d resp=%v, want 200 six keys", status, resp)
	}
	requireSixKeyCollect(t, resp)
}

func TestRev7SnapshotAcceptedStoredAndDeduped(t *testing.T) {
	tc, _ := startRev7TestCenter(t)
	linux := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	enableRev7Config(t, tc, linux, true)
	base := b2BaseCollected(t)
	// Bootstrap capability evidence first; the rev-7 report is newer than the
	// bootstrap snapshot so it is the accepted latest snapshot.
	bootstrapAgentVersion(t, tc, linux, base, "1.1.0")
	if status, resp := pullConfig(t, tc, linux); status != http.StatusOK {
		t.Fatalf("config pull status=%d resp=%v", status, resp)
	}
	rev7At := base + 10
	doc := rev7SnapshotDoc(t, rev7At, freshTrafficObservationDoc(rev7At))
	status, resp, _ := reportAttempt(t, tc, linux, doc)
	if status != http.StatusOK || resp["result"] != "accepted" {
		t.Fatalf("rev7 snapshot status=%d resp=%v", status, resp)
	}
	// Normalized rows: one report + one row per inbound, queryable by observed_at.
	latest, err := tc.store.QueryLatestTraffic(contextBackground(),
		store.TrafficEventScope{AllEvents: true}, store.TrafficQuery{})
	if err != nil {
		t.Fatalf("query latest: %v", err)
	}
	if len(latest) != 2 {
		t.Fatalf("latest series = %d, want 2 inbounds", len(latest))
	}
	for _, point := range latest {
		if point.ObservedAt != rev7At-2 || point.Availability != "ok" || point.Freshness != "fresh" ||
			point.Quality != "lower_bound" || point.SourceEpoch != strings.Repeat("ab", 16) ||
			point.Sequence != 7 || point.UplinkObservedLowerBoundBytes == nil {
			t.Fatalf("stored traffic point = %+v", point)
		}
	}
	// Exact replay (same report_id/body, new nonce/seq) is an idempotent duplicate.
	replay := doc
	status, resp, _ = reportAttempt(t, tc, linux, replay)
	if status != http.StatusOK || resp["result"] != "duplicate" {
		t.Fatalf("replay status=%d resp=%v, want duplicate", status, resp)
	}
	history, truncated, err := tc.store.QueryTrafficHistory(contextBackground(),
		store.TrafficEventScope{AllEvents: true},
		store.TrafficQuery{From: rev7At - 120, To: rev7At + 60, Limit: 100})
	if err != nil || truncated {
		t.Fatalf("history err=%v truncated=%v", err, truncated)
	}
	if len(history) != 2 {
		t.Fatalf("history rows after replay = %d, want 2 (no duplicate rows)", len(history))
	}
	// The center recorded the rev-7 agent capability version from the signed
	// snapshot (OD-LT-14 metadata), not from any header or client-supplied field.
	version, err := tc.store.GetLastAgentVersion(contextBackground(), linux.nodeID)
	if err != nil || version != "1.1.0" {
		t.Fatalf("recorded agent version = %q err=%v", version, err)
	}
}

func TestRev7SnapshotRejectedWhenSourceDisabled(t *testing.T) {
	tc, _ := startRev7TestCenter(t)
	linux := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	enableRev7Config(t, tc, linux, false)
	base := b2BaseCollected(t)
	doc := rev7SnapshotDoc(t, base, freshTrafficObservationDoc(base))
	status, resp, _ := reportAttempt(t, tc, linux, doc)
	if status != http.StatusBadRequest || resp["error"] != "invalid_request" {
		t.Fatalf("rev7 with disabled source status=%d resp=%v", status, resp)
	}
}

func TestRev7SnapshotRejectsUnknownTagKindMismatch(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(observation map[string]any)
	}{
		{"unknown tag", func(observation map[string]any) {
			inbounds := observation["inbounds"].([]any)
			entry := map[string]any{}
			for k, v := range inbounds[0].(map[string]any) {
				entry[k] = v
			}
			entry["inbound_tag"] = "unknown-in"
			observation["inbounds"] = append(inbounds, entry)
		}},
		{"kind mismatch", func(observation map[string]any) {
			inbounds := observation["inbounds"].([]any)
			inbounds[1].(map[string]any)["kind"] = "other"
		}},
		{"ok omits expected tag", func(observation map[string]any) {
			observation["inbounds"] = observation["inbounds"].([]any)[:1]
			observation["active_connections"] = int64(2)
		}},
	}
	for _, tcCase := range cases {
		t.Run(tcCase.name, func(t *testing.T) {
			tc, _ := startRev7TestCenter(t)
			linux := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
			enableRev7Config(t, tc, linux, true)
			base := b2BaseCollected(t)
			bootstrapAgentVersion(t, tc, linux, base, "1.1.0")
			rev7At := base + 10
			observation := freshTrafficObservationDoc(rev7At)
			tcCase.mutate(observation)
			doc := rev7SnapshotDoc(t, rev7At, observation)
			status, resp, _ := reportAttempt(t, tc, linux, doc)
			if status != http.StatusBadRequest || resp["error"] != "invalid_request" {
				t.Fatalf("invalid rev7 observation status=%d resp=%v", status, resp)
			}
		})
	}
}

func TestRev7SnapshotHonestUnavailableObservationAccepted(t *testing.T) {
	tc, _ := startRev7TestCenter(t)
	linux := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	enableRev7Config(t, tc, linux, true)
	base := b2BaseCollected(t)
	bootstrapAgentVersion(t, tc, linux, base, "1.1.0")
	if status, resp := pullConfig(t, tc, linux); status != http.StatusOK {
		t.Fatalf("config pull status=%d resp=%v", status, resp)
	}
	rev7At := base + 10
	observation := map[string]any{
		"source": "monitor_readonly_export", "source_epoch": zeroEpoch(),
		"sequence": int64(0), "observed_at": int64(0), "age_seconds": int64(86400),
		"freshness": "unavailable", "availability": "unavailable",
		"counter_scope": "observation_epoch", "exactness": "lower_bound",
		"active_connections": nil, "rate_window_seconds": nil, "inbounds": []any{},
	}
	doc := rev7SnapshotDoc(t, rev7At, observation)
	status, resp, _ := reportAttempt(t, tc, linux, doc)
	if status != http.StatusOK || resp["result"] != "accepted" {
		t.Fatalf("honest unavailable observation status=%d resp=%v", status, resp)
	}
	history, _, err := tc.store.QueryTrafficHistory(contextBackground(),
		store.TrafficEventScope{AllEvents: true},
		store.TrafficQuery{From: rev7At - 60, To: rev7At + 60, Limit: 10})
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(history) != 0 {
		t.Fatalf("unavailable observation stored %d inbound rows", len(history))
	}
}

func TestRev7SnapshotRejectedForWindows(t *testing.T) {
	tc, _ := startRev7TestCenter(t)
	windows := enrollAgent(t, tc, store.NodeClassWindowsTerminal, "windows")
	base := b2BaseCollected(t)
	doc := b2SnapshotDoc(t, base)
	doc["host"].(map[string]any)["os"] = "windows"
	doc["contract_revision"] = 7
	doc["traffic_observation"] = freshTrafficObservationDoc(base)
	status, resp, _ := reportAttempt(t, tc, windows, doc)
	if status != http.StatusBadRequest || resp["error"] != "platform_mismatch" {
		t.Fatalf("windows rev7 status=%d resp=%v, want 400 platform_mismatch", status, resp)
	}
}

func zeroEpoch() string { return strings.Repeat("0", 32) }

func TestRev5SnapshotStillAcceptedWithRev7SchemasLoaded(t *testing.T) {
	tc, _ := startRev7TestCenter(t)
	linux := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	base := b2BaseCollected(t)
	doc := b2SnapshotDoc(t, base)
	status, resp, _ := reportAttempt(t, tc, linux, doc)
	if status != http.StatusOK || resp["result"] != "accepted" {
		t.Fatalf("rev5 snapshot under rev7 schema set status=%d resp=%v", status, resp)
	}
}

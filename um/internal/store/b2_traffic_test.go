package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func testTrafficObservation(collectedAt int64, sequence int64, epoch string) *TrafficObservationRecord {
	uplink := int64(1000)
	downlink := int64(2000)
	rate := 12.5
	active := int64(2)
	window := 60.0
	return &TrafficObservationRecord{
		Source: "monitor_readonly_export", SourceEpoch: strings.Repeat(epoch, 16), Sequence: sequence,
		ObservedAt: collectedAt, CollectedAt: collectedAt, ReceivedAt: collectedAt,
		Availability: "ok", Freshness: "fresh", ActiveConnections: &active, RateWindowSeconds: &window,
		CounterScope: "observation_epoch", Exactness: "lower_bound", BytesEstimate: 512,
		Inbounds: []TrafficInboundRecord{{
			InboundTag: "vless-in", Kind: "reality", ObservedAt: collectedAt,
			Availability: "ok", Quality: "lower_bound",
			UplinkObservedLowerBoundBytes: &uplink, DownlinkObservedLowerBoundBytes: &downlink,
			UplinkObservedRateBps: &rate, ActiveConnections: 2,
		}},
	}
}

func storeTrafficSnapshot(t *testing.T, s *Store, id EnrolledIdentity, reportID string, collectedAt int64, obs *TrafficObservationRecord) ReportDisposition {
	t.Helper()
	var disposition ReportDisposition
	if err := s.WithTx(testContext(), func(tx *Tx) error {
		var err error
		disposition, err = tx.StoreSnapshotTx(testContext(), SnapshotRecord{
			NodeID: id.NodeID, EventID: id.EventID, NodeClass: id.NodeClass,
			ReportID: reportID, CollectedAt: collectedAt, ReceivedAt: collectedAt + 1,
			BodySHA256: "sha-" + reportID, Payload: []byte(`{"v":1,"type":"snapshot"}`),
			TrafficObservation: obs,
		})
		return err
	}); err != nil {
		t.Fatalf("store snapshot %q: %v", reportID, err)
	}
	return disposition
}

func TestTrafficObservationStoredInSnapshotTransactionAndDeduped(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	now := int64(1_700_000_000)
	id := testEnroll(t, s, NodeClassLinuxVPS, now)

	disp := storeTrafficSnapshot(t, s, id, "traffic-1", now-10, testTrafficObservation(now-10, 1, "ab"))
	if disp != DispositionAccepted {
		t.Fatalf("first snapshot disposition = %q", disp)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM traffic_observation_reports`); got != 1 {
		t.Fatalf("traffic report rows = %d, want 1", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM traffic_observations`); got != 1 {
		t.Fatalf("traffic observation rows = %d, want 1", got)
	}
	var (
		nodeID, eventID, reportID, source, sourceEpoch, scope, exactness string
		sequence, observedAt, collectedAt                                int64
	)
	if err := s.db.QueryRow(`SELECT node_id,event_id,report_id,source,source_epoch,sequence,observed_at,collected_at,counter_scope,exactness
		FROM traffic_observation_reports`).Scan(&nodeID, &eventID, &reportID, &source, &sourceEpoch,
		&sequence, &observedAt, &collectedAt, &scope, &exactness); err != nil {
		t.Fatalf("read normalized report row: %v", err)
	}
	if nodeID != id.NodeID || eventID != id.EventID || reportID != "traffic-1" ||
		source != "monitor_readonly_export" || sourceEpoch != strings.Repeat("ab", 16) ||
		sequence != 1 || observedAt != now-10 || collectedAt != now-10 ||
		scope != "observation_epoch" || exactness != "lower_bound" {
		t.Fatalf("unexpected normalized report row: %s/%s/%s/%s/%s/%d/%d/%d/%s/%s",
			nodeID, eventID, reportID, source, sourceEpoch, sequence, observedAt, collectedAt, scope, exactness)
	}
	// The raw export/report body is not copied into the normalized tables.
	var columns int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('traffic_observations') WHERE name LIKE '%payload%'`).Scan(&columns); err != nil {
		t.Fatalf("inspect traffic_observations columns: %v", err)
	}
	if columns != 0 {
		t.Fatal("normalized traffic table unexpectedly carries a raw payload column")
	}

	// Replaying the same snapshot report hits the snapshot hash dedupe first and
	// never duplicates traffic rows.
	disp = storeTrafficSnapshot(t, s, id, "traffic-1", now-10, testTrafficObservation(now-10, 1, "ab"))
	if disp != DispositionDuplicate {
		t.Fatalf("replayed snapshot disposition = %q, want duplicate", disp)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM traffic_observation_reports`); got != 1 {
		t.Fatalf("traffic report rows after replay = %d", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM traffic_observations`); got != 1 {
		t.Fatalf("traffic observation rows after replay = %d", got)
	}

	// Late/offline replay ordering: an older collected_at is stale_ignored for
	// node_latest but its observation is still stored because the traffic time is
	// observed_at.
	disp = storeTrafficSnapshot(t, s, id, "traffic-2", now-20, testTrafficObservation(now-20, 2, "ab"))
	if disp != DispositionStaleIgnored {
		t.Fatalf("late snapshot disposition = %q, want stale_ignored", disp)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM traffic_observation_reports`); got != 2 {
		t.Fatalf("late observation was not stored: %d reports", got)
	}
}

func TestSnapshotRecordsLatestAuthenticatedAgentVersion(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	id := testEnroll(t, s, NodeClassLinuxVPS, now)
	storeVersion := func(reportID string, collectedAt int64, version string) {
		t.Helper()
		if err := s.WithTx(ctx, func(tx *Tx) error {
			_, err := tx.StoreSnapshotTx(ctx, SnapshotRecord{
				NodeID: id.NodeID, EventID: id.EventID, NodeClass: id.NodeClass,
				ReportID: reportID, CollectedAt: collectedAt, ReceivedAt: collectedAt + 1,
				BodySHA256: "sha-" + reportID, Payload: []byte(`{"v":1,"type":"snapshot"}`),
				AgentVersion: version,
			})
			return err
		}); err != nil {
			t.Fatalf("store snapshot %q: %v", reportID, err)
		}
	}
	getVersion := func() string {
		t.Helper()
		version, err := s.GetLastAgentVersion(ctx, id.NodeID)
		if err != nil {
			t.Fatalf("GetLastAgentVersion: %v", err)
		}
		return version
	}
	if got := getVersion(); got != "" {
		t.Fatalf("unknown initial version = %q", got)
	}
	storeVersion("agent-v1", now-20, "1.0.0")
	if got := getVersion(); got != "1.0.0" {
		t.Fatalf("recorded version = %q", got)
	}
	storeVersion("agent-v2", now-5, "1.1.0")
	if got := getVersion(); got != "1.1.0" {
		t.Fatalf("recorded version = %q", got)
	}
	// An authenticated stale_ignored snapshot still proves the agent's capability:
	// "latest" means the last authenticated report, not the newest collected_at.
	storeVersion("agent-v3", now-10, "1.2.0")
	if got := getVersion(); got != "1.2.0" {
		t.Fatalf("stale-ignored snapshot did not update version: %q", got)
	}
	// A value outside the frozen agent.version grammar is never persisted raw.
	storeVersion("agent-v4", now-1, "not-a-version")
	if got := getVersion(); got != "1.2.0" {
		t.Fatalf("invalid version overwrote capability evidence: %q", got)
	}
}

func TestTrafficQueryLatestUsesObservedAt(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	eventA := testEnrollEvent(t, s, "00000000-0000-4000-8000-00000000000a", NodeClassLinuxVPS, now)
	eventB := testEnrollEvent(t, s, "00000000-0000-4000-8000-00000000000b", NodeClassLinuxVPS, now)
	// Event A: the newest observed_at row arrived first (received_at huge), the
	// older observed_at row arrived later. Latest must pick observed_at.
	observedNew := testTrafficObservation(now-50, 3, "ab")
	observedNew.ReceivedAt = now + 500
	storeTrafficSnapshot(t, s, eventA, "b-late-arrival", now-50, observedNew)
	observedOld := testTrafficObservation(now-100, 2, "ab")
	observedOld.ReceivedAt = now + 900
	storeTrafficSnapshot(t, s, eventA, "a-late-arrival", now-100, observedOld)
	storeTrafficSnapshot(t, s, eventB, "c-event-b", now-70, testTrafficObservation(now-70, 1, "cd"))

	all, err := s.QueryLatestTraffic(ctx, TrafficEventScope{AllEvents: true}, TrafficQuery{})
	if err != nil {
		t.Fatalf("latest all events: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("latest rows = %d, want one per (event,node,inbound) series", len(all))
	}
	byEvent := map[string]TrafficPoint{}
	for _, point := range all {
		byEvent[point.EventID] = point
	}
	if got := byEvent[eventA.EventID]; got.ObservedAt != now-50 || got.Sequence != 3 {
		t.Fatalf("latest event A row = %+v, want observed_at=%d sequence=3", got, now-50)
	}
	if got := byEvent[eventB.EventID]; got.ObservedAt != now-70 {
		t.Fatalf("latest event B row = %+v", got)
	}

	// Scoped query: only the assigned event is visible; an empty non-global
	// scope is fail-closed (matches nothing).
	scoped, err := s.QueryLatestTraffic(ctx, TrafficEventScope{EventIDs: []string{eventB.EventID}}, TrafficQuery{})
	if err != nil || len(scoped) != 1 || scoped[0].EventID != eventB.EventID {
		t.Fatalf("scoped latest = %+v err=%v", scoped, err)
	}
	empty, err := s.QueryLatestTraffic(ctx, TrafficEventScope{EventIDs: []string{}}, TrafficQuery{})
	if err != nil {
		t.Fatalf("empty scope latest: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("empty non-global scope returned %d rows", len(empty))
	}
	// Filter by node/tag/kind and observed_at window.
	filtered, err := s.QueryLatestTraffic(ctx, TrafficEventScope{AllEvents: true}, TrafficQuery{
		NodeID: eventA.NodeID, InboundTag: "vless-in", Kind: "reality",
		From: now - 60, To: now,
	})
	if err != nil || len(filtered) != 1 || filtered[0].ObservedAt != now-50 {
		t.Fatalf("filtered latest = %+v err=%v", filtered, err)
	}
}

func TestTrafficQueryHistoryGapEpochAndTruncation(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	id := testEnrollEvent(t, s, "00000000-0000-4000-8000-00000000000a", NodeClassLinuxVPS, now)
	storeTrafficSnapshot(t, s, id, "h1", now-300, testTrafficObservation(now-300, 1, "ab"))
	storeTrafficSnapshot(t, s, id, "h2", now-240, testTrafficObservation(now-240, 2, "ab"))
	storeTrafficSnapshot(t, s, id, "h3", now-180, testTrafficObservation(now-180, 3, "ab"))
	// The monitor restarted: independent source epoch resets the sequence.
	storeTrafficSnapshot(t, s, id, "h4", now-60, testTrafficObservation(now-60, 1, "cd"))

	points, truncated, err := s.QueryTrafficHistory(ctx, TrafficEventScope{AllEvents: true},
		TrafficQuery{From: now - 400, To: now - 100, Limit: 10, StepSeconds: 0})
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if truncated || len(points) != 3 {
		t.Fatalf("history rows=%d truncated=%v", len(points), truncated)
	}
	for index, point := range points {
		if point.ObservedAt != now-int64(300-60*index) {
			t.Fatalf("history order row %d = %d", index, point.ObservedAt)
		}
	}
	if points[0].GapBeforeSeconds != nil {
		t.Fatalf("first row gap = %v, want nil", *points[0].GapBeforeSeconds)
	}
	if points[1].GapBeforeSeconds == nil || *points[1].GapBeforeSeconds != 60 {
		t.Fatalf("second row gap = %v, want 60", points[1].GapBeforeSeconds)
	}
	// Epoch boundary over the full range: no fabricated gap across resets.
	all, _, err := s.QueryTrafficHistory(ctx, TrafficEventScope{AllEvents: true},
		TrafficQuery{From: now - 400, To: now, Limit: 10})
	if err != nil {
		t.Fatalf("history all: %v", err)
	}
	if len(all) != 4 {
		t.Fatalf("history all rows = %d", len(all))
	}
	if all[3].SourceEpoch != strings.Repeat("cd", 16) || all[3].GapBeforeSeconds != nil {
		t.Fatalf("epoch reset row = %+v", all[3])
	}
	// Truncation metadata.
	limited, truncated, err := s.QueryTrafficHistory(ctx, TrafficEventScope{AllEvents: true},
		TrafficQuery{From: now - 400, To: now, Limit: 2})
	if err != nil || !truncated || len(limited) != 2 {
		t.Fatalf("truncated history rows=%d truncated=%v err=%v", len(limited), truncated, err)
	}
	// Downsample step keeps the newest observed_at per bucket.
	sampled, _, err := s.QueryTrafficHistory(ctx, TrafficEventScope{AllEvents: true},
		TrafficQuery{From: now - 400, To: now, Limit: 10, StepSeconds: 360})
	if err != nil {
		t.Fatalf("downsample: %v", err)
	}
	if len(sampled) != 2 {
		t.Fatalf("downsampled rows = %d, want 2 buckets", len(sampled))
	}
	// now-300/-240/-180 share one bucket (newest kept); now-60 is its own bucket.
	if sampled[0].ObservedAt != now-180 || sampled[1].ObservedAt != now-60 {
		t.Fatalf("downsample picked wrong rows: %d/%d", sampled[0].ObservedAt, sampled[1].ObservedAt)
	}
}

func TestTrafficQueryBounds(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	if _, err := s.QueryLatestTraffic(ctx, TrafficEventScope{AllEvents: true}, TrafficQuery{Limit: TrafficQueryMaxLimit + 1}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("oversized limit error = %v", err)
	}
	if _, _, err := s.QueryTrafficHistory(ctx, TrafficEventScope{AllEvents: true}, TrafficQuery{Limit: 10}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("unbounded history error = %v", err)
	}
	if _, _, err := s.QueryTrafficHistory(ctx, TrafficEventScope{AllEvents: true},
		TrafficQuery{From: 100, To: 100 + TrafficQueryMaxRangeSeconds + 1, Limit: 10}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("range bound error = %v", err)
	}
	if _, _, err := s.QueryTrafficHistory(ctx, TrafficEventScope{AllEvents: true},
		TrafficQuery{From: 200, To: 100, Limit: 10}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("reversed range error = %v", err)
	}
	if _, err := s.QueryLatestTraffic(ctx, TrafficEventScope{AllEvents: true}, TrafficQuery{Kind: "vless"}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("unknown kind error = %v", err)
	}
}

func TestTrafficMigrationFromV13AndConfigNormalization(t *testing.T) {
	path := tempStorePath(t)
	prepareSchemaVersion13(t, path)
	s := openTestStore(t, path)
	ctx := testContext()
	version, err := s.SchemaVersion(ctx)
	if err != nil || version != 14 {
		t.Fatalf("schema version = %d err=%v, want 14", version, err)
	}
	for _, table := range []string{"traffic_observation_reports", "traffic_observations"} {
		if got := queryInt(t, s, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table); got != 1 {
			t.Fatalf("v14 table %q missing", table)
		}
	}
	// The OD-LT-14 capability metadata columns are additive and nullable on an
	// existing v13 nodes row.
	for _, column := range []string{"last_agent_version", "last_agent_version_at"} {
		if got := queryInt(t, s, `SELECT COUNT(*) FROM pragma_table_info('nodes') WHERE name=?`, column); got != 1 {
			t.Fatalf("v14 nodes column %q missing", column)
		}
	}
	if version, err := s.GetLastAgentVersion(ctx, "11111111-1111-4111-8111-111111111111"); err != nil || version != "" {
		t.Fatalf("migrated node agent version = %q err=%v, want unknown", version, err)
	}
	// An old six-key config row is normalized to seven keys with the new switch
	// disabled, without changing its config_version.
	cfg, err := s.GetNodeConfig(ctx, "11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatalf("GetNodeConfig: %v", err)
	}
	if len(cfg.Sources) != 7 || cfg.Sources["monitor_export"] {
		t.Fatalf("normalized sources = %v", cfg.Sources)
	}
	if cfg.ConfigVersion != 1 {
		t.Fatalf("config_version changed to %d", cfg.ConfigVersion)
	}
	// A six-key admin update is accepted and stored normalized; a seven-key update
	// can enable the linux source; windows may not enable it.
	cfg, err = s.UpdateNodeConfig(ctx, cfg.NodeID, sixSourceMap(), []InboundTag{{InboundTag: "vless-in", Kind: "reality"}}, 60, 2_000)
	if err != nil || len(cfg.Sources) != 7 || cfg.Sources["monitor_export"] {
		t.Fatalf("six-key update = %+v err=%v", cfg, err)
	}
	seven := sixSourceMap()
	seven["monitor_export"] = true
	cfg, err = s.UpdateNodeConfig(ctx, cfg.NodeID, seven, []InboundTag{{InboundTag: "vless-in", Kind: "reality"}}, 60, 3_000)
	if err != nil || !cfg.Sources["monitor_export"] {
		t.Fatalf("seven-key update = %+v err=%v", cfg, err)
	}
	windowsSeven := sixSourceMap()
	windowsSeven["monitor_export"] = true
	if err := validateConfigForClass(NodeClassWindowsTerminal, windowsSeven, nil, 60, 1); err == nil {
		t.Fatal("windows monitor_export=true config accepted")
	}
	if err := validateConfigForClass(NodeClassWindowsTerminal, sixSourceMap(), nil, 60, 1); err != nil {
		t.Fatalf("windows six-key config rejected: %v", err)
	}
	if err := validateConfigForClass(NodeClassLinuxVPS, sixSourceMap(), []InboundTag{{InboundTag: "vless-in", Kind: "reality"}}, 60, 1); err != nil {
		t.Fatalf("linux six-key config rejected: %v", err)
	}
}

func sixSourceMap() map[string]bool {
	return map[string]bool{"system": false, "services": false, "singbox_api": false,
		"mihomo_api": false, "terminal": false, "events": false}
}

// prepareSchemaVersion13 creates a raw database migrated exactly through v13 and
// seeds an older six-key node config, so store.Open must apply only the additive
// v14 traffic migration.
func prepareSchemaVersion13(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}
	for _, migration := range migrations {
		if migration.version > 13 {
			break
		}
		for _, statement := range migration.statements {
			if _, err := db.Exec(statement); err != nil {
				t.Fatalf("apply v%d statement: %v", migration.version, err)
			}
		}
		if _, err := db.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)`, migration.version, 1); err != nil {
			t.Fatalf("record v%d: %v", migration.version, err)
		}
	}
	sources, _ := json.Marshal(sixSourceMap())
	tags, _ := json.Marshal([]InboundTag{{InboundTag: "vless-in", Kind: "reality"}})
	if _, err := db.Exec(`INSERT INTO nodes(node_id,event_id,node_class,state,created_at)
		VALUES(?,?,?,?,?)`, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222",
		NodeClassLinuxVPS, "active", 1_000); err != nil {
		t.Fatalf("seed node: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO node_configs(node_id,event_id,config_version,cadence_seconds,sources_json,expected_inbound_tags_json,device_salt,updated_at)
		VALUES(?,?,?,?,?,?,?,?)`, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222",
		1, 60, string(sources), string(tags), strings.Repeat("A", 43), 1_000); err != nil {
		t.Fatalf("seed node config: %v", err)
	}
}

func TestTrafficRetentionPurgesTrafficRows(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	eventA := testEnrollEvent(t, s, "00000000-0000-4000-8000-00000000000a", NodeClassLinuxVPS, now)
	old := testTrafficObservation(now-31*24*60*60, 1, "ab")
	storeTrafficSnapshot(t, s, eventA, "traffic-old", now-31*24*60*60, old)
	recent := testTrafficObservation(now-10*24*60*60, 2, "ab")
	storeTrafficSnapshot(t, s, eventA, "traffic-recent", now-10*24*60*60, recent)
	if got := queryInt(t, s, `SELECT COUNT(*) FROM traffic_observations`); got != 2 {
		t.Fatalf("seeded traffic rows = %d", got)
	}
	stats, err := s.CapacityStatsExtended(ctx)
	if err != nil {
		t.Fatalf("capacity stats: %v", err)
	}
	if stats.TrafficBytes <= 0 {
		t.Fatalf("capacity traffic bytes = %d, want > 0", stats.TrafficBytes)
	}
	preview, err := s.PurgePreview(ctx, eventA.EventID)
	if err != nil {
		t.Fatalf("purge preview: %v", err)
	}
	if preview.TableCounts["traffic_observation_reports"] != 2 || preview.TableCounts["traffic_observations"] != 2 {
		t.Fatalf("purge preview traffic counts = %+v", preview.TableCounts)
	}

	// Active rolling 30d retention: the old report and its child rows disappear.
	if _, err := s.RunRetentionB2(ctx, now); err != nil {
		t.Fatalf("retention: %v", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM traffic_observation_reports`); got != 1 {
		t.Fatalf("traffic reports after active retention = %d, want 1", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM traffic_observations`); got != 1 {
		t.Fatalf("traffic observations after active retention = %d, want 1", got)
	}

	// Archive tail expiry deletes the remaining report; the FK cascade removes the
	// child row, and event purge leaves no traffic rows behind either.
	if err := s.ArchiveEvent(ctx, eventA.EventID, now+1); err != nil {
		t.Fatalf("archive: %v", err)
	}
	if _, err := s.RunRetentionB2(ctx, now+1+PolicyBArchiveTailSeconds+1); err != nil {
		t.Fatalf("archive tail retention: %v", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM traffic_observation_reports`); got != 0 {
		t.Fatalf("traffic reports after archive tail = %d", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM traffic_observations`); got != 0 {
		t.Fatalf("traffic observations after archive tail = %d (cascade failed)", got)
	}
	stats, err = s.CapacityStatsExtended(ctx)
	if err != nil || stats.TrafficBytes != 0 {
		t.Fatalf("capacity traffic bytes after purge = %d err=%v", stats.TrafficBytes, err)
	}
}

func TestTrafficObservationStateExposesUnavailableSentinel(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_901_500_000)
	rec := SnapshotRecord{
		NodeID: "44444444-4444-4444-8444-444444444444", EventID: "55555555-5555-4555-8555-555555555555",
		NodeClass: "linux_vps", ReportID: "66666666-6666-4666-8666-666666666666",
		CollectedAt: now, ReceivedAt: now, BodySHA256: "hash",
		TrafficObservation: &TrafficObservationRecord{
			Source: "monitor_readonly_export", SourceEpoch: "00000000000000000000000000000000",
			Sequence: 0, ObservedAt: 0, CollectedAt: now, ReceivedAt: now,
			Availability: "unavailable", Freshness: "unavailable",
			CounterScope: "observation_epoch", Exactness: "lower_bound", BytesEstimate: 100,
		},
	}
	if err := s.SeedTrafficObservationForTest(ctx, rec); err != nil {
		t.Fatal(err)
	}
	states, err := s.QueryLatestTrafficStates(ctx, TrafficEventScope{AllEvents: true}, TrafficQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].Availability != "unavailable" || states[0].ObservedAt != 0 ||
		states[0].NodeID != rec.NodeID {
		t.Fatalf("sentinel states = %+v", states)
	}
	points, err := s.QueryLatestTraffic(ctx, TrafficEventScope{AllEvents: true}, TrafficQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(points) != 0 {
		t.Fatalf("sentinel must not fabricate traffic points: %+v", points)
	}
}

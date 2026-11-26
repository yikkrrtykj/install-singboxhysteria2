package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/protocol"
)

func testPublicKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func testEnroll(t *testing.T, s *Store, class string, now int64) EnrolledIdentity {
	t.Helper()
	ctx := testContext()
	_, hash, err := NewEnrollToken()
	if err != nil {
		t.Fatalf("NewEnrollToken: %v", err)
	}
	if err := s.CreateEnrollToken(ctx, hash, "event-b2", class, now+3600, now); err != nil {
		t.Fatalf("CreateEnrollToken: %v", err)
	}
	host := "linux"
	if class == NodeClassWindowsTerminal {
		host = "windows"
	}
	id, err := s.Enroll(ctx, hash, class, host, testPublicKey(t), now)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	return id
}

func TestB2EnrollmentSingleUseAndScope(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)

	// Scope mismatch is rejected without consuming the token.
	_, hash, _ := NewEnrollToken()
	if err := s.CreateEnrollToken(ctx, hash, "event-b2", NodeClassLinuxVPS, now+3600, now); err != nil {
		t.Fatalf("create token: %v", err)
	}
	if _, err := s.Enroll(ctx, hash, NodeClassWindowsTerminal, "windows", testPublicKey(t), now); !errors.Is(err, ErrTokenScopeMismatch) {
		t.Fatalf("scope mismatch error = %v", err)
	}
	info, err := s.TokenInfo(ctx, hash)
	if err != nil || info.UsedAt != nil {
		t.Fatalf("scope mismatch consumed token: %+v err=%v", info, err)
	}
	// Correct scope succeeds and consumes the token atomically.
	id, err := s.Enroll(ctx, hash, NodeClassLinuxVPS, "linux", testPublicKey(t), now)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if id.EventID != "event-b2" || id.NodeClass != NodeClassLinuxVPS || id.KeyID == "" || id.DeviceSalt == "" {
		t.Fatalf("identity = %+v", id)
	}
	cfg, err := s.GetNodeConfig(ctx, id.NodeID)
	if err != nil || cfg.ConfigVersion != DefaultConfigVersion || len(cfg.ExpectedInboundTags) == 0 {
		t.Fatalf("config = %+v err=%v", cfg, err)
	}
	// Running account: active on commit.
	var nodeState, keyState string
	if err := s.db.QueryRowContext(ctx, `SELECT state FROM nodes WHERE node_id=?`, id.NodeID).Scan(&nodeState); err != nil || nodeState != NodeActive {
		t.Fatalf("node state = %q err=%v", nodeState, err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT state FROM node_keys WHERE key_id=?`, id.KeyID).Scan(&keyState); err != nil || keyState != KeyActive {
		t.Fatalf("key state = %q err=%v", keyState, err)
	}
	// Response-loss retry: token_used, node remains active and is not pending.
	if _, err := s.Enroll(ctx, hash, NodeClassLinuxVPS, "linux", testPublicKey(t), now); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("token retry error = %v, want token_used", err)
	}
	if nodeState != NodeActive {
		t.Fatal("orphan handling changed node state")
	}
	// Expired token.
	_, hash2, _ := NewEnrollToken()
	if err := s.CreateEnrollToken(ctx, hash2, "event-b2", NodeClassLinuxVPS, now+10, now); err != nil {
		t.Fatalf("create expiring token: %v", err)
	}
	if _, err := s.Enroll(ctx, hash2, NodeClassLinuxVPS, "linux", testPublicKey(t), now+11); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired token error = %v", err)
	}
}

func TestB2RotationLifecycle(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	id := testEnroll(t, s, NodeClassLinuxVPS, now)
	newPub := testPublicKey(t)
	var newKeyID string
	if err := s.WithTx(ctx, func(tx *Tx) error {
		r := RotationRecord{NodeID: id.NodeID, OldKeyID: id.KeyID, Nonce: "rotate-nonce-1", BodySHA256: "body-hash", ExpiresAt: now + 300, CreatedAt: now}
		if err := tx.CreateRotationTx(ctx, r, newPub); err != nil {
			return err
		}
		rec, ok, err := tx.RotationTx(ctx, id.NodeID, "rotate-nonce-1")
		if err != nil || !ok || rec.State != RotationAwaitingProof {
			return fmt.Errorf("rotation = %+v ok=%v err=%v", rec, ok, err)
		}
		newKeyID = rec.NewKeyID
		key, err := tx.KeyTx(ctx, id.NodeID, newKeyID)
		if err != nil || key.State != KeyProvisional {
			return fmt.Errorf("provisional key = %+v err=%v", key, err)
		}
		return nil
	}); err != nil {
		t.Fatalf("create rotation: %v", err)
	}
	// Confirm: new active, old revoked, rotation confirmed.
	if err := s.WithTx(ctx, func(tx *Tx) error {
		rec, err := tx.ConfirmRotationTx(ctx, id.NodeID, "rotate-nonce-1", now+10)
		if err != nil {
			return err
		}
		if rec.State != RotationConfirmed || rec.NewKeyID != newKeyID {
			return fmt.Errorf("confirmed = %+v", rec)
		}
		oldKey, err := tx.KeyTx(ctx, id.NodeID, id.KeyID)
		if err != nil || oldKey.State != KeyRevoked {
			return fmt.Errorf("old key = %+v err=%v", oldKey, err)
		}
		newKey, err := tx.KeyTx(ctx, id.NodeID, newKeyID)
		if err != nil || newKey.State != KeyActive {
			return fmt.Errorf("new key = %+v err=%v", newKey, err)
		}
		return nil
	}); err != nil {
		t.Fatalf("confirm rotation: %v", err)
	}

	// Expired rotation aborts only the provisional key; old key stays active.
	s2 := openTestStore(t, tempStorePath(t))
	id2 := testEnroll(t, s2, NodeClassWindowsTerminal, now)
	var provisionalID string
	if err := s2.WithTx(ctx, func(tx *Tx) error {
		r := RotationRecord{NodeID: id2.NodeID, OldKeyID: id2.KeyID, Nonce: "rotate-expire", BodySHA256: "h", ExpiresAt: now + 5, CreatedAt: now}
		if err := tx.CreateRotationTx(ctx, r, testPublicKey(t)); err != nil {
			return err
		}
		rec, _, err := tx.RotationTx(ctx, id2.NodeID, "rotate-expire")
		provisionalID = rec.NewKeyID
		return err
	}); err != nil {
		t.Fatalf("create expiring rotation: %v", err)
	}
	n, err := s2.AbortExpiredRotations(ctx, now+6)
	if err != nil || n != 1 {
		t.Fatalf("AbortExpiredRotations = %d, %v", n, err)
	}
	if err := s2.WithTx(ctx, func(tx *Tx) error {
		rec, ok, err := tx.RotationTx(ctx, id2.NodeID, "rotate-expire")
		if err != nil || !ok || rec.State != RotationAborted {
			return fmt.Errorf("aborted rotation = %+v ok=%v err=%v", rec, ok, err)
		}
		oldKey, err := tx.KeyTx(ctx, id2.NodeID, id2.KeyID)
		if err != nil || oldKey.State != KeyActive {
			return fmt.Errorf("old key must stay active: %+v %v", oldKey, err)
		}
		newKey, err := tx.KeyTx(ctx, id2.NodeID, provisionalID)
		if err != nil || newKey.State != KeyRevoked {
			return fmt.Errorf("provisional key must be revoked: %+v %v", newKey, err)
		}
		return nil
	}); err != nil {
		t.Fatalf("aborted state: %v", err)
	}

	// Admin revocation wins over pending rotation.
	if err := s2.RevokeNode(ctx, id2.NodeID, now+20); err != nil {
		t.Fatalf("RevokeNode: %v", err)
	}
	if err := s2.WithTx(ctx, func(tx *Tx) error {
		node, err := tx.NodeTx(ctx, id2.NodeID)
		if err != nil || node.State != NodeRevoked {
			return fmt.Errorf("node state = %+v %v", node, err)
		}
		key, err := tx.KeyTx(ctx, id2.NodeID, id2.KeyID)
		if err != nil || key.State != KeyRevoked {
			return fmt.Errorf("revoked key = %+v %v", key, err)
		}
		return nil
	}); err != nil {
		t.Fatalf("admin revoke state: %v", err)
	}
}

func TestB2ApplyIngestTransactionAndSnapshotOrdering(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	id := testEnroll(t, s, NodeClassLinuxVPS, now)
	attempt := protocol.Attempt{Gen: 1, BootID: strings.Repeat("a", 32), Seq: 1, Fingerprint: "fp-1"}
	nonceFP := func(n string) string { return "nonce-fp-" + n }
	applySnapshot := func(tx *Tx, reportID string, collectedAt int64, payload string) (ReportDisposition, error) {
		status, err := tx.CheckOrInsertNonce(ctx, id.NodeID, "nonce-"+reportID, nonceFP(reportID), now)
		if err != nil || status == NonceReuse {
			return "", fmt.Errorf("nonce status=%q err=%v", status, err)
		}
		reportStatus, err := tx.CheckOrInsertReport(ctx, id.NodeID, reportID, "sha-"+reportID, now)
		if err != nil || reportStatus == ReportConflict {
			return "", fmt.Errorf("report status=%q err=%v", reportStatus, err)
		}
		if reportStatus == ReportDuplicate {
			return DispositionDuplicate, nil
		}
		disp, err := tx.StoreSnapshotTx(ctx, SnapshotRecord{NodeID: id.NodeID, EventID: id.EventID, NodeClass: id.NodeClass,
			ReportID: reportID, CollectedAt: collectedAt, ReceivedAt: now, BodySHA256: "sha-" + reportID, Payload: []byte(payload)})
		return disp, err
	}
	var disp ReportDisposition
	res, d, err := s.ApplyIngest(ctx, id.NodeID, attempt, "fp-1", func(tx *Tx) error {
		key, kerr := tx.KeyTx(ctx, id.NodeID, id.KeyID)
		if kerr != nil || key.State != KeyActive {
			return fmt.Errorf("key state=%+v err=%v", key, kerr)
		}
		return nil
	}, func(tx *Tx) (ReportDisposition, error) {
		var aerr error
		disp, aerr = applySnapshot(tx, "report-1", now-10, `{"v":1,"type":"snapshot","report_id":"report-1","collected_at":1}`)
		return disp, aerr
	})
	if err != nil || res.Outcome != protocol.Accepted || d != DispositionAccepted || disp != DispositionAccepted {
		t.Fatalf("first ingest res=%+v d=%q disp=%q err=%v", res, d, disp, err)
	}
	latest, err := s.GetLatestSnapshot(ctx, id.NodeID)
	if err != nil || latest.ReportID != "report-1" || latest.CollectedAt != now-10 {
		t.Fatalf("latest = %+v err=%v", latest, err)
	}
	// Newer snapshot accepted; older snapshot answered stale_ignored and does not
	// overwrite latest.
	attempt2 := protocol.Attempt{Gen: 1, BootID: strings.Repeat("a", 32), Seq: 2, Fingerprint: "fp-2"}
	res, d, err = s.ApplyIngest(ctx, id.NodeID, attempt2, "fp-2", func(tx *Tx) error { return nil },
		func(tx *Tx) (ReportDisposition, error) {
			return applySnapshot(tx, "report-2", now-5, `{"v":1,"type":"snapshot","report_id":"report-2","collected_at":2}`)
		})
	if err != nil || res.Outcome != protocol.Accepted || d != DispositionAccepted {
		t.Fatalf("newer ingest = %+v %q %v", res, d, err)
	}
	attempt3 := protocol.Attempt{Gen: 1, BootID: strings.Repeat("a", 32), Seq: 3, Fingerprint: "fp-3"}
	res, d, err = s.ApplyIngest(ctx, id.NodeID, attempt3, "fp-3", func(tx *Tx) error { return nil },
		func(tx *Tx) (ReportDisposition, error) {
			return applySnapshot(tx, "report-3", now-20, `{"v":1,"type":"snapshot","report_id":"report-3","collected_at":3}`)
		})
	if err != nil || res.Outcome != protocol.Accepted || d != DispositionStaleIgnored {
		t.Fatalf("stale ingest = %+v %q %v, want stale_ignored", res, d, err)
	}
	latest, _ = s.GetLatestSnapshot(ctx, id.NodeID)
	if latest.ReportID != "report-2" {
		t.Fatalf("stale snapshot overwrote latest: %+v", latest)
	}
	// Exact retry of the committed attempt is a transport duplicate; callback
	// still resolves report dedupe without advancing high-water.
	res, d, err = s.ApplyIngest(ctx, id.NodeID, attempt2, "fp-2", func(tx *Tx) error { return nil },
		func(tx *Tx) (ReportDisposition, error) {
			return applySnapshot(tx, "report-2", now-5, `{"v":1,"type":"snapshot","report_id":"report-2","collected_at":2}`)
		})
	if err != nil || res.Outcome != protocol.Duplicate || d != DispositionDuplicate {
		t.Fatalf("retry = %+v %q %v, want duplicate/duplicate", res, d, err)
	}
	// Failed payload callback rolls back the high-water and dedupe.
	before, _ := s.GetBoot(ctx, id.NodeID)
	attempt4 := protocol.Attempt{Gen: 1, BootID: strings.Repeat("a", 32), Seq: 4, Fingerprint: "fp-4"}
	_, _, err = s.ApplyIngest(ctx, id.NodeID, attempt4, "fp-4", func(tx *Tx) error { return nil },
		func(tx *Tx) (ReportDisposition, error) {
			if _, err := tx.CheckOrInsertNonce(ctx, id.NodeID, "nonce-fail", "fp-fail", now); err != nil {
				return "", err
			}
			return "", errors.New("payload storage failure")
		})
	if err == nil {
		t.Fatal("failed payload ingest returned nil error")
	}
	after, _ := s.GetBoot(ctx, id.NodeID)
	if after != before {
		t.Fatalf("failed ingest advanced high-water: before=%+v after=%+v", before, after)
	}
	if seen, _ := s.NonceSeen(ctx, id.NodeID, "nonce-fail"); seen {
		t.Fatal("failed ingest left nonce")
	}
}

func testEnrollEvent(t *testing.T, s *Store, event, class string, now int64) EnrolledIdentity {
	t.Helper()
	ctx := testContext()
	_, hash, _ := NewEnrollToken()
	if err := s.CreateEnrollToken(ctx, hash, event, class, now+3600, now); err != nil {
		t.Fatalf("CreateEnrollToken: %v", err)
	}
	host := "linux"
	if class == NodeClassWindowsTerminal {
		host = "windows"
	}
	id, err := s.Enroll(ctx, hash, class, host, testPublicKey(t), now)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	return id
}

func seedTelemetry(t *testing.T, s *Store, id EnrolledIdentity, reportID string, collectedAt, now int64) {
	t.Helper()
	ctx := testContext()
	if err := s.WithTx(ctx, func(tx *Tx) error {
		_, err := tx.StoreSnapshotTx(ctx, SnapshotRecord{NodeID: id.NodeID, EventID: id.EventID, NodeClass: id.NodeClass,
			ReportID: reportID, CollectedAt: collectedAt, ReceivedAt: now, BodySHA256: "sha-" + reportID, Payload: []byte(`{"v":1}`)})
		return err
	}); err != nil {
		t.Fatalf("seed snapshot %s: %v", reportID, err)
	}
	if err := s.WithTx(ctx, func(tx *Tx) error {
		_, err := tx.StoreMetricsTx(ctx, ReportRecord{NodeID: id.NodeID, EventID: id.EventID, ReportID: "m-" + reportID,
			CollectedAt: collectedAt, ReceivedAt: now, BodySHA256: "m-" + reportID, Payload: []byte(`{"v":1}`)})
		return err
	}); err != nil {
		t.Fatalf("seed metrics %s: %v", reportID, err)
	}
	if err := s.WithTx(ctx, func(tx *Tx) error {
		_, err := tx.StoreEventsTx(ctx, ReportRecord{NodeID: id.NodeID, EventID: id.EventID, ReportID: "e-" + reportID,
			CollectedAt: collectedAt, ReceivedAt: now, BodySHA256: "e-" + reportID, Payload: []byte(`{"v":1}`)},
			[]EventRecord{{EventID: "ev-" + reportID, At: collectedAt, Kind: "agent_started", DetailsJSON: `{}`}})
		return err
	}); err != nil {
		t.Fatalf("seed events %s: %v", reportID, err)
	}
}

func TestB2RetentionPhysicalPruning(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	id := testEnroll(t, s, NodeClassLinuxVPS, now)
	for seq := uint64(1); seq <= 300; seq++ {
		if err := recordSeq(ctx, s.db, id.NodeID, 1, "boot-b2", seq, fmt.Sprintf("fp-%d", seq), now); err != nil {
			t.Fatalf("RecordSeq(%d): %v", seq, err)
		}
	}
	mustPutBoot(t, s, id.NodeID, 1, "boot-b2", 300, "fp-300")
	// Old-generation exact-retry fingerprints must be removed as well.
	for seq := uint64(1); seq <= 10; seq++ {
		if err := recordSeq(ctx, s.db, id.NodeID, 2, "old-boot", seq, fmt.Sprintf("old-%d", seq), now); err != nil {
			t.Fatalf("old RecordSeq(%d): %v", seq, err)
		}
	}
	for gen := uint64(1); gen <= 10; gen++ {
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO boot_registry(node_id,boot_gen,boot_id,first_seen_at,last_seen_at,last_seq,state)
			 VALUES(?,?,?,?,?,1,'retired')`, id.NodeID, gen, fmt.Sprintf("boot-%d", gen), now, now); err != nil {
			t.Fatalf("seed boot_registry gen %d: %v", gen, err)
		}
	}
	if _, err := s.RunRetentionB2(ctx, now); err != nil {
		t.Fatalf("RunRetentionB2: %v", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM seq_dedupe WHERE node_id=? AND boot_gen=1`, id.NodeID); got != 256 {
		t.Fatalf("current seq rows = %d, want 256", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM seq_dedupe WHERE node_id=? AND boot_gen=2`, id.NodeID); got != 0 {
		t.Fatalf("old-generation seq rows = %d, want 0", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM boot_registry WHERE node_id=?`, id.NodeID); got != 8 {
		t.Fatalf("boot_registry rows = %d, want 8", got)
	}
	if _, err := s.GetBoot(ctx, id.NodeID); err != nil {
		t.Fatalf("node_boot must survive retention: %v", err)
	}
	// Old generation remains rejected by the persistent high-water.
	if _, err := protocol.Evaluate(protocol.Boot{HighestGen: 1, BootID: "boot-b2", LastSeq: 1}, protocol.Attempt{Gen: 0, BootID: "old-boot", Seq: 2, Fingerprint: "x"}, protocol.Options{}); err == nil {
		t.Fatal("retired generation did not produce a protocol rejection")
	}
}

func TestB2PolicyBEventLifecycle(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	eventA := testEnrollEvent(t, s, "event-a", NodeClassLinuxVPS, now)
	eventB := testEnrollEvent(t, s, "event-b", NodeClassLinuxVPS, now+1)
	seedTelemetry(t, s, eventA, "a-old", now-31*24*60*60, now)
	seedTelemetry(t, s, eventA, "a-new", now-10*24*60*60, now)
	seedTelemetry(t, s, eventB, "b-new", now-10*24*60*60, now+1)

	// Active event rolling 30d.
	if _, err := s.RunRetentionB2(ctx, now); err != nil {
		t.Fatalf("retention active: %v", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM snapshots WHERE event_id='event-a'`); got != 1 {
		t.Fatalf("active event A rows=%d, want 1", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM snapshots WHERE report_id='a-old'`); got != 0 {
		t.Fatalf("old active row survived")
	}
	// Archive A at T: ingest closed, tail kept until T+30d; B unaffected.
	if err := s.ArchiveEvent(ctx, "event-a", now); err != nil {
		t.Fatalf("ArchiveEvent A: %v", err)
	}
	ea, err := s.EventState(ctx, "event-a")
	if err != nil || ea.State != EventArchived || ea.ArchivedAt == nil || ea.PurgeAfter == nil {
		t.Fatalf("event A state = %+v err=%v", ea, err)
	}
	if err := s.ArchiveEvent(ctx, "event-a", now+1); !errors.Is(err, ErrEventArchived) {
		t.Fatalf("double archive = %v, want ErrEventArchived", err)
	}
	if _, err := s.RunRetentionB2(ctx, now+29*24*60*60); err != nil {
		t.Fatalf("archive tail retention: %v", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM snapshots WHERE event_id='event-a'`); got != 1 {
		t.Fatalf("archive tail A rows=%d, want 1", got)
	}
	// At T+30d the event data disappears; catalog survives; B aged out too.
	if _, err := s.RunRetentionB2(ctx, now+31*24*60*60); err != nil {
		t.Fatalf("archive expiry retention: %v", err)
	}
	for _, table := range []string{"snapshots", "report_metrics", "report_events"} {
		if got := queryInt(t, s, `SELECT COUNT(*) FROM `+table+` WHERE event_id='event-a'`); got != 0 {
			t.Fatalf("%s event A rows=%d after T+30d, want 0", table, got)
		}
		if got := queryInt(t, s, `SELECT COUNT(*) FROM `+table+` WHERE event_id='event-b'`); got != 0 {
			// B is still active but its only row is >30d old at this simulated time.
			t.Fatalf("%s event B active rolling rows=%d, want 0", table, got)
		}
	}
	ea, _ = s.EventState(ctx, "event-a")
	if ea.DataPurgedAt == nil {
		t.Fatal("archive tail expiry did not record data_purged_at")
	}
	// Purge deletes the catalog and writes a content-free tombstone.
	if err := s.PurgeEvent(ctx, "event-a", "admin", false, now+32*24*60*60); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("purge without confirmation = %v, want ErrInvalidArgument", err)
	}
	if err := s.PurgeEvent(ctx, "event-a", "admin", true, now+32*24*60*60); err != nil {
		t.Fatalf("PurgeEvent: %v", err)
	}
	if _, err := s.EventState(ctx, "event-a"); !errors.Is(err, ErrEventUnknown) {
		t.Fatalf("event catalog survived purge: %v", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM purge_tombstones WHERE event_id='event-a'`); got != 1 {
		t.Fatalf("purge tombstones=%d, want 1", got)
	}
}

func TestB2ArchiveMultipleReportsNoLoss(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	a := testEnrollEvent(t, s, "event-a", NodeClassLinuxVPS, now)
	b := testEnrollEvent(t, s, "event-b", NodeClassLinuxVPS, now)
	for i, id := range []EnrolledIdentity{a, a, b, b} {
		seedTelemetry(t, s, id, fmt.Sprintf("r%d", i), now-60, now+int64(i))
	}
	if err := s.ArchiveEvent(ctx, "event-a", now+10); err != nil {
		t.Fatalf("archive: %v", err)
	}
	if _, err := s.RunRetentionB2(ctx, now+10+PolicyBArchiveTailSeconds+1); err != nil {
		t.Fatalf("retention after tail: %v", err)
	}
	for _, table := range []string{"snapshots", "report_metrics", "report_events"} {
		if got := queryInt(t, s, `SELECT COUNT(*) FROM `+table+` WHERE event_id='event-a'`); got != 0 {
			t.Fatalf("%s lost/retained archive rows=%d, want 0 at tail expiry", table, got)
		}
	}
	// B's rows were also past active rolling 30d at that simulated time.
	if got := queryInt(t, s, `SELECT COUNT(*) FROM snapshots WHERE event_id='event-b'`); got != 0 {
		t.Fatalf("event B rows=%d, want 0 after rolling window", got)
	}
	// No legacy archive copy table exists/needs to exist.
	if got := queryInt(t, s, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='archive_records'`); got != 0 {
		t.Fatal("legacy archive_records table still exists")
	}
}

func TestB2RetentionFailureDegradedAndIdempotent(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	id := testEnroll(t, s, NodeClassLinuxVPS, now)
	if err := s.WithTx(ctx, func(tx *Tx) error {
		_, err := tx.StoreSnapshotTx(ctx, SnapshotRecord{NodeID: id.NodeID, EventID: id.EventID, NodeClass: id.NodeClass,
			ReportID: "old", CollectedAt: now - 40*24*60*60, ReceivedAt: now - 40*24*60*60,
			BodySHA256: "old", Payload: []byte(`{"v":1}`)})
		return err
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	s.SetRetentionHookForTest(func(stage string) error {
		if strings.HasPrefix(stage, "delete:snapshots") {
			return errors.New("injected disk failure")
		}
		return nil
	})
	if _, err := s.RunRetentionB2(ctx, now); !errors.Is(err, ErrRetentionDegraded) {
		t.Fatalf("faulted retention = %v, want ErrRetentionDegraded", err)
	}
	st, err := s.GetRetentionState(ctx)
	if err != nil || !st.Degraded || st.FailureCount == 0 {
		t.Fatalf("retention state = %+v err=%v", st, err)
	}
	// Hook fires before the first batch delete, so the source data is intact.
	if got := queryInt(t, s, `SELECT COUNT(*) FROM snapshots WHERE report_id='old'`); got != 1 {
		t.Fatalf("faulted retention deleted source data: %d", got)
	}
	s.SetRetentionHookForTest(nil)
	if _, err := s.RunRetentionB2(ctx, now); err != nil {
		t.Fatalf("recovered retention: %v", err)
	}
	st, _ = s.GetRetentionState(ctx)
	if st.Degraded {
		t.Fatal("retention state still degraded after successful run")
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM snapshots WHERE report_id='old'`); got != 0 {
		t.Fatal("recovered retention did not delete expired row")
	}
}

func TestB2QuotaRefusesNewEnrollment(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	// Event catalog exists, then fill the global hard quota directly.
	_, hash, _ := NewEnrollToken()
	if err := s.CreateEnrollToken(ctx, hash, "event-quota", NodeClassLinuxVPS, now+3600, now); err != nil {
		t.Fatalf("token: %v", err)
	}
	for i := 0; i < MaxActiveNodesAllEvents; i++ {
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO nodes(node_id,event_id,node_class,state,created_at) VALUES(?,?,?,?,?)`,
			fmt.Sprintf("quota-node-%03d", i), "event-quota", NodeClassLinuxVPS, NodeActive, now); err != nil {
			t.Fatalf("seed node %d: %v", i, err)
		}
	}
	_, hash2, _ := NewEnrollToken()
	err := s.CreateEnrollToken(ctx, hash2, "event-quota", NodeClassLinuxVPS, now+7200, now)
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("quota token creation = %v, want ErrQuotaExceeded", err)
	}
}

func TestB2ArchivedEventQuota(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	for i := 0; i < MaxArchivedEventsWithData; i++ {
		ev := fmt.Sprintf("archived-event-%02d", i)
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO event_catalog(event_id,state,created_at,archived_at,purge_after,data_purged_at,updated_at)
			 VALUES(?,?,?,?,?,NULL,?)`, ev, EventArchived, now, now, now+PolicyBArchiveTailSeconds, now); err != nil {
			t.Fatalf("seed archived event %d: %v", i, err)
		}
	}
	_, hash, _ := NewEnrollToken()
	if err := s.CreateEnrollToken(ctx, hash, "event-new", NodeClassLinuxVPS, now+3600, now); err != nil {
		t.Fatalf("token: %v", err)
	}
	err := s.ArchiveEvent(ctx, "event-new", now)
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("archived event quota = %v, want ErrQuotaExceeded", err)
	}
}

func TestB2EnrollmentTokenConcurrentSingleUse(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	_, hash, _ := NewEnrollToken()
	if err := s.CreateEnrollToken(ctx, hash, "event-b2", NodeClassLinuxVPS, now+3600, now); err != nil {
		t.Fatalf("token: %v", err)
	}
	type result struct {
		id  EnrolledIdentity
		err error
	}
	ch := make(chan result, 2)
	for i := 0; i < 2; i++ {
		go func() {
			id, err := s.Enroll(ctx, hash, NodeClassLinuxVPS, "linux", testPublicKey(t), now)
			ch <- result{id: id, err: err}
		}()
	}
	var successes, used int
	for i := 0; i < 2; i++ {
		r := <-ch
		switch {
		case r.err == nil:
			successes++
		case errors.Is(r.err, ErrTokenUsed):
			used++
		default:
			t.Fatalf("unexpected enroll error: %v", r.err)
		}
	}
	if successes != 1 || used != 1 {
		t.Fatalf("concurrent enrollment successes=%d token_used=%d, want 1/1", successes, used)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM nodes`); got != 1 {
		t.Fatalf("concurrent enrollment created %d nodes, want 1", got)
	}
}

func TestB2RotationStateIntegrityAndRevocation(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	id := testEnroll(t, s, NodeClassLinuxVPS, now)
	// Create and confirm one rotation.
	var newKeyID string
	if err := s.WithTx(ctx, func(tx *Tx) error {
		if err := tx.CreateRotationTx(ctx, RotationRecord{NodeID: id.NodeID, OldKeyID: id.KeyID, Nonce: "n1", BodySHA256: "h1", ExpiresAt: now + 300, CreatedAt: now}, testPublicKey(t)); err != nil {
			return err
		}
		rec, _, err := tx.RotationTx(ctx, id.NodeID, "n1")
		newKeyID = rec.NewKeyID
		if err != nil {
			return err
		}
		_, err = tx.ConfirmRotationTx(ctx, id.NodeID, "n1", now)
		return err
	}); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	// A second confirmation must not look successful.
	if err := s.WithTx(ctx, func(tx *Tx) error {
		_, err := tx.ConfirmRotationTx(ctx, id.NodeID, "n1", now+1)
		return err
	}); !errors.Is(err, ErrRotationState) {
		t.Fatalf("second confirm error = %v, want ErrRotationState", err)
	}
	// Start a second rotation from the active new key, then revoke the old key's
	// related provisional key; it must not survive confirmation.
	var provisionalID string
	if err := s.WithTx(ctx, func(tx *Tx) error {
		if err := tx.CreateRotationTx(ctx, RotationRecord{NodeID: id.NodeID, OldKeyID: newKeyID, Nonce: "n2", BodySHA256: "h2", ExpiresAt: now + 300, CreatedAt: now}, testPublicKey(t)); err != nil {
			return err
		}
		rec, _, err := tx.RotationTx(ctx, id.NodeID, "n2")
		provisionalID = rec.NewKeyID
		return err
	}); err != nil {
		t.Fatalf("create n2: %v", err)
	}
	if err := s.RevokeKey(ctx, id.NodeID, newKeyID, now+2); err != nil {
		t.Fatalf("revoke active key: %v", err)
	}
	if err := s.WithTx(ctx, func(tx *Tx) error {
		prov, err := tx.KeyTx(ctx, id.NodeID, provisionalID)
		if err != nil || prov.State != KeyRevoked {
			return fmt.Errorf("provisional key state=%+v err=%v", prov, err)
		}
		rec, ok, err := tx.RotationTx(ctx, id.NodeID, "n2")
		if err != nil || !ok || rec.State != RotationAborted {
			return fmt.Errorf("rotation n2 = %+v ok=%v err=%v", rec, ok, err)
		}
		if _, err := tx.ConfirmRotationTx(ctx, id.NodeID, "n2", now+3); !errors.Is(err, ErrRotationState) {
			return fmt.Errorf("confirm aborted rotation error = %v, want ErrRotationState", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("revoke state: %v", err)
	}
	// Node revoke differs from single-key revoke: node retired, history untouched.
	if err := s.RevokeNode(ctx, id.NodeID, now+4); err != nil {
		t.Fatalf("revoke node: %v", err)
	}
	node, err := s.GetNode(ctx, id.NodeID)
	if err != nil || node.State != NodeRevoked {
		t.Fatalf("node state=%+v err=%v", node, err)
	}
	if err := s.WithTx(ctx, func(tx *Tx) error {
		n, err := tx.NodeTx(ctx, id.NodeID)
		if err != nil {
			return err
		}
		var retired sql.NullInt64
		if err := tx.tx.QueryRowContext(ctx, `SELECT retired_at FROM nodes WHERE node_id=?`, id.NodeID).Scan(&retired); err != nil {
			return err
		}
		if !retired.Valid {
			t.Fatal("node retire did not set retired_at")
		}
		_ = n
		return nil
	}); err != nil {
		t.Fatalf("retired_at: %v", err)
	}
	if _, err := s.GetLatestSnapshot(ctx, id.NodeID); !errors.Is(err, ErrNotFound) {
		// No snapshot was seeded; this is only a sanity read.
	}
}

func TestB2ArchiveAndRetentionFaultLeavesDataIntact(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	id := testEnrollEvent(t, s, "event-fault", NodeClassLinuxVPS, now)
	seedTelemetry(t, s, id, "fault-row", now-10, now)
	for _, stage := range []string{"archive:begin", "archive:write"} {
		s.SetRetentionHookForTest(func(got string) error {
			if got == stage {
				return errors.New("injected archive failure " + stage)
			}
			return nil
		})
		if err := s.ArchiveEvent(ctx, "event-fault", now); err == nil {
			t.Fatalf("archive fault %s was not reported", stage)
		}
		ev, err := s.EventState(ctx, "event-fault")
		if err != nil || ev.State != EventActive {
			t.Fatalf("archive fault %s changed state: %+v err=%v", stage, ev, err)
		}
		if got := queryInt(t, s, `SELECT COUNT(*) FROM snapshots WHERE report_id='fault-row'`); got != 1 {
			t.Fatalf("archive fault %s lost data: %d", stage, got)
		}
	}
	// Archive scan failure must not delete telemetry.
	s.SetRetentionHookForTest(func(got string) error {
		if got == "retention:scan_events" {
			return errors.New("injected scan failure")
		}
		return nil
	})
	if _, err := s.RunRetentionB2(ctx, now); !errors.Is(err, ErrRetentionDegraded) {
		t.Fatalf("scan fault = %v, want degraded", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM snapshots WHERE report_id='fault-row'`); got != 1 {
		t.Fatalf("scan fault lost data: %d", got)
	}
	s.SetRetentionHookForTest(nil)
	if err := s.ArchiveEvent(ctx, "event-fault", now); err != nil {
		t.Fatalf("clean archive: %v", err)
	}
}

func TestB2EventStorageNormalizationAndCrossTypeConflict(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	id := testEnrollEvent(t, s, "event-events", NodeClassLinuxVPS, now)
	payload := []byte(`{"v":1,"type":"events","events":[]}`)
	if err := s.WithTx(ctx, func(tx *Tx) error {
		if status, err := tx.CheckOrInsertReport(ctx, id.NodeID, "events-1", "h-events", now); err != nil || status != ReportNew {
			return fmt.Errorf("report dedupe status=%q err=%v", status, err)
		}
		_, err := tx.StoreEventsTx(ctx, ReportRecord{NodeID: id.NodeID, EventID: id.EventID, ReportID: "events-1",
			CollectedAt: now, ReceivedAt: now, BodySHA256: "h-events", Payload: payload}, []EventRecord{
			{EventID: "ev-1", At: now, Kind: "agent_started", Severity: "warning", DetailsJSON: `{"a":1}`},
			{EventID: "ev-2", At: now + 1, Kind: "agent_error", Severity: "critical", DetailsJSON: `{"b":2}`},
		})
		return err
	}); err != nil {
		t.Fatalf("StoreEventsTx: %v", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM report_event_reports WHERE report_id='events-1'`); got != 1 {
		t.Fatalf("event report rows=%d, want one shared payload row", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM report_events WHERE report_id='events-1'`); got != 2 {
		t.Fatalf("event rows=%d, want 2", got)
	}
	if got := queryString(t, s, `SELECT severity FROM report_events WHERE event_id_json='ev-1'`); got != "warning" {
		t.Fatalf("severity=%q, want warning", got)
	}
	// The same report_id cannot be reused for a different report type/body.
	if err := s.WithTx(ctx, func(tx *Tx) error {
		status, err := tx.CheckOrInsertReport(ctx, id.NodeID, "events-1", "different-body", now)
		if err != nil {
			return err
		}
		if status != ReportConflict {
			t.Fatalf("cross-type report_id status=%q, want conflict", status)
		}
		return nil
	}); err != nil {
		t.Fatalf("cross-type conflict: %v", err)
	}
	stats, err := s.CapacityStatsExtended(ctx)
	if err != nil || stats.EventsBytes <= 0 || stats.DBSizeBytes <= 0 {
		t.Fatalf("capacity extended = %+v err=%v", stats, err)
	}
}

func TestB2PolicyBMultipleArchiveTimesAndExactBoundary(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	a := testEnrollEvent(t, s, "event-aa", NodeClassLinuxVPS, now)
	b := testEnrollEvent(t, s, "event-bb", NodeClassLinuxVPS, now+1)
	seedTelemetry(t, s, a, "aa-row", now-10, now)
	seedTelemetry(t, s, b, "bb-row", now-10, now+1)
	if err := s.ArchiveEvent(ctx, "event-aa", now); err != nil {
		t.Fatalf("archive A: %v", err)
	}
	if err := s.ArchiveEvent(ctx, "event-bb", now+5*24*60*60); err != nil {
		t.Fatalf("archive B: %v", err)
	}
	// At exactly T_A+30d, A's data is deleted; B's tail is still alive.
	if _, err := s.RunRetentionB2(ctx, now+PolicyBArchiveTailSeconds); err != nil {
		t.Fatalf("retention at A boundary: %v", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM snapshots WHERE event_id='event-aa'`); got != 0 {
		t.Fatalf("event A data at exact T+30d = %d, want 0", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM snapshots WHERE event_id='event-bb'`); got != 1 {
		t.Fatalf("event B data before its boundary = %d, want 1", got)
	}
	// At exactly T_B+30d, B's data is deleted as well; catalogs remain.
	if _, err := s.RunRetentionB2(ctx, now+5*24*60*60+PolicyBArchiveTailSeconds); err != nil {
		t.Fatalf("retention at B boundary: %v", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM snapshots WHERE event_id='event-bb'`); got != 0 {
		t.Fatalf("event B data at exact T+30d = %d, want 0", got)
	}
	for _, ev := range []string{"event-aa", "event-bb"} {
		info, err := s.EventState(ctx, ev)
		if err != nil || info.DataPurgedAt == nil {
			t.Fatalf("catalog %s after tail: %+v err=%v", ev, info, err)
		}
	}
	// Idempotent restart-equivalent runs.
	if _, err := s.RunRetentionB2(ctx, now+40*24*60*60); err != nil {
		t.Fatalf("repeat retention: %v", err)
	}
}

func TestB2QuotaPerEventAndCatalog(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	// Per-event node quota.
	_, hash, _ := NewEnrollToken()
	if err := s.CreateEnrollToken(ctx, hash, "event-per", NodeClassLinuxVPS, now+3600, now); err != nil {
		t.Fatalf("token: %v", err)
	}
	for i := 0; i < MaxActiveNodesPerEvent; i++ {
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO nodes(node_id,event_id,node_class,state,created_at) VALUES(?,?,?,?,?)`,
			fmt.Sprintf("per-node-%03d", i), "event-per", NodeClassLinuxVPS, NodeActive, now); err != nil {
			t.Fatalf("seed per-event node: %v", err)
		}
	}
	_, hash2, _ := NewEnrollToken()
	if err := s.CreateEnrollToken(ctx, hash2, "event-per", NodeClassLinuxVPS, now+3600, now); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("per-event quota = %v, want ErrQuotaExceeded", err)
	}
	// Event catalog quota.
	s2 := openTestStore(t, tempStorePath(t))
	for i := 0; i < MaxEventsCatalog; i++ {
		if _, err := s2.db.ExecContext(ctx,
			`INSERT INTO event_catalog(event_id,state,created_at,archived_at,purge_after,data_purged_at,updated_at)
			 VALUES(?,?,?,NULL,NULL,NULL,?)`, fmt.Sprintf("catalog-%02d", i), EventActive, now, now); err != nil {
			t.Fatalf("seed catalog: %v", err)
		}
	}
	_, hash3, _ := NewEnrollToken()
	if err := s2.CreateEnrollToken(ctx, hash3, "catalog-new", NodeClassLinuxVPS, now+3600, now); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("event catalog quota = %v, want ErrQuotaExceeded", err)
	}
}

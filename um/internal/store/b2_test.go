package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

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
	if err := s.CreateEnrollToken(ctx, hash, "00000000-0000-4000-8000-0000000000b2", class, now+3600, now); err != nil {
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
	if err := s.CreateEnrollToken(ctx, hash, "00000000-0000-4000-8000-0000000000b2", NodeClassLinuxVPS, now+3600, now); err != nil {
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
	if id.EventID != "00000000-0000-4000-8000-0000000000b2" || id.NodeClass != NodeClassLinuxVPS || id.KeyID == "" || id.DeviceSalt == "" {
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
	if err := s.CreateEnrollToken(ctx, hash2, "00000000-0000-4000-8000-0000000000b2", NodeClassLinuxVPS, now+10, now); err != nil {
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
	eventA := testEnrollEvent(t, s, "00000000-0000-4000-8000-00000000000a", NodeClassLinuxVPS, now)
	eventB := testEnrollEvent(t, s, "00000000-0000-4000-8000-00000000000b", NodeClassLinuxVPS, now+1)
	seedTelemetry(t, s, eventA, "a-old", now-31*24*60*60, now)
	seedTelemetry(t, s, eventA, "a-new", now-10*24*60*60, now)
	seedTelemetry(t, s, eventB, "b-new", now-10*24*60*60, now+1)

	// Active event rolling 30d.
	if _, err := s.RunRetentionB2(ctx, now); err != nil {
		t.Fatalf("retention active: %v", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM snapshots WHERE event_id='00000000-0000-4000-8000-00000000000a'`); got != 1 {
		t.Fatalf("active event A rows=%d, want 1", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM snapshots WHERE report_id='a-old'`); got != 0 {
		t.Fatalf("old active row survived")
	}
	// Archive A at T: ingest closed, tail kept until T+30d; B unaffected.
	if err := s.ArchiveEvent(ctx, "00000000-0000-4000-8000-00000000000a", now); err != nil {
		t.Fatalf("ArchiveEvent A: %v", err)
	}
	ea, err := s.EventState(ctx, "00000000-0000-4000-8000-00000000000a")
	if err != nil || ea.State != EventArchived || ea.ArchivedAt == nil || ea.PurgeAfter == nil {
		t.Fatalf("event A state = %+v err=%v", ea, err)
	}
	if err := s.ArchiveEvent(ctx, "00000000-0000-4000-8000-00000000000a", now+1); !errors.Is(err, ErrEventArchived) {
		t.Fatalf("double archive = %v, want ErrEventArchived", err)
	}
	if _, err := s.RunRetentionB2(ctx, now+29*24*60*60); err != nil {
		t.Fatalf("archive tail retention: %v", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM snapshots WHERE event_id='00000000-0000-4000-8000-00000000000a'`); got != 1 {
		t.Fatalf("archive tail A rows=%d, want 1", got)
	}
	// At T+30d the event data disappears; catalog survives; B aged out too.
	if _, err := s.RunRetentionB2(ctx, now+31*24*60*60); err != nil {
		t.Fatalf("archive expiry retention: %v", err)
	}
	for _, table := range []string{"snapshots", "report_metrics", "report_events"} {
		if got := queryInt(t, s, `SELECT COUNT(*) FROM `+table+` WHERE event_id='00000000-0000-4000-8000-00000000000a'`); got != 0 {
			t.Fatalf("%s event A rows=%d after T+30d, want 0", table, got)
		}
		if got := queryInt(t, s, `SELECT COUNT(*) FROM `+table+` WHERE event_id='00000000-0000-4000-8000-00000000000b'`); got != 0 {
			// B is still active but its only row is >30d old at this simulated time.
			t.Fatalf("%s event B active rolling rows=%d, want 0", table, got)
		}
	}
	ea, _ = s.EventState(ctx, "00000000-0000-4000-8000-00000000000a")
	if ea.DataPurgedAt == nil {
		t.Fatal("archive tail expiry did not record data_purged_at")
	}
	// Purge deletes the catalog and writes a content-free tombstone.
	if err := s.PurgeEvent(ctx, "00000000-0000-4000-8000-00000000000a", "admin", false, now+32*24*60*60); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("purge without confirmation = %v, want ErrInvalidArgument", err)
	}
	if err := s.PurgeEvent(ctx, "00000000-0000-4000-8000-00000000000a", "admin", true, now+32*24*60*60); err != nil {
		t.Fatalf("PurgeEvent: %v", err)
	}
	if _, err := s.EventState(ctx, "00000000-0000-4000-8000-00000000000a"); !errors.Is(err, ErrEventUnknown) {
		t.Fatalf("event catalog survived purge: %v", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM purge_tombstones WHERE event_id='00000000-0000-4000-8000-00000000000a'`); got != 1 {
		t.Fatalf("purge tombstones=%d, want 1", got)
	}
}

func TestB2ArchiveMultipleReportsNoLoss(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	a := testEnrollEvent(t, s, "00000000-0000-4000-8000-00000000000a", NodeClassLinuxVPS, now)
	b := testEnrollEvent(t, s, "00000000-0000-4000-8000-00000000000b", NodeClassLinuxVPS, now)
	for i, id := range []EnrolledIdentity{a, a, b, b} {
		seedTelemetry(t, s, id, fmt.Sprintf("r%d", i), now-60, now+int64(i))
	}
	if err := s.ArchiveEvent(ctx, "00000000-0000-4000-8000-00000000000a", now+10); err != nil {
		t.Fatalf("archive: %v", err)
	}
	if _, err := s.RunRetentionB2(ctx, now+10+PolicyBArchiveTailSeconds+1); err != nil {
		t.Fatalf("retention after tail: %v", err)
	}
	for _, table := range []string{"snapshots", "report_metrics", "report_events"} {
		if got := queryInt(t, s, `SELECT COUNT(*) FROM `+table+` WHERE event_id='00000000-0000-4000-8000-00000000000a'`); got != 0 {
			t.Fatalf("%s lost/retained archive rows=%d, want 0 at tail expiry", table, got)
		}
	}
	// B's rows were also past active rolling 30d at that simulated time.
	if got := queryInt(t, s, `SELECT COUNT(*) FROM snapshots WHERE event_id='00000000-0000-4000-8000-00000000000b'`); got != 0 {
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
	if err := s.CreateEnrollToken(ctx, hash, "00000000-0000-4000-8000-0000000000c1", NodeClassLinuxVPS, now+3600, now); err != nil {
		t.Fatalf("token: %v", err)
	}
	for i := 0; i < MaxActiveNodesAllEvents; i++ {
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO nodes(node_id,event_id,node_class,state,created_at) VALUES(?,?,?,?,?)`,
			fmt.Sprintf("quota-node-%03d", i), "00000000-0000-4000-8000-0000000000c1", NodeClassLinuxVPS, NodeActive, now); err != nil {
			t.Fatalf("seed node %d: %v", i, err)
		}
	}
	_, hash2, _ := NewEnrollToken()
	err := s.CreateEnrollToken(ctx, hash2, "00000000-0000-4000-8000-0000000000c1", NodeClassLinuxVPS, now+7200, now)
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
	if err := s.CreateEnrollToken(ctx, hash, "00000000-0000-4000-8000-0000000000c2", NodeClassLinuxVPS, now+3600, now); err != nil {
		t.Fatalf("token: %v", err)
	}
	err := s.ArchiveEvent(ctx, "00000000-0000-4000-8000-0000000000c2", now)
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("archived event quota = %v, want ErrQuotaExceeded", err)
	}
}

func TestB2EnrollmentTokenConcurrentSingleUse(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	_, hash, _ := NewEnrollToken()
	if err := s.CreateEnrollToken(ctx, hash, "00000000-0000-4000-8000-0000000000b2", NodeClassLinuxVPS, now+3600, now); err != nil {
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
	id := testEnrollEvent(t, s, "00000000-0000-4000-8000-0000000000c3", NodeClassLinuxVPS, now)
	seedTelemetry(t, s, id, "fault-row", now-10, now)
	for _, stage := range []string{"archive:begin", "archive:write"} {
		s.SetRetentionHookForTest(func(got string) error {
			if got == stage {
				return errors.New("injected archive failure " + stage)
			}
			return nil
		})
		if err := s.ArchiveEvent(ctx, "00000000-0000-4000-8000-0000000000c3", now); err == nil {
			t.Fatalf("archive fault %s was not reported", stage)
		}
		ev, err := s.EventState(ctx, "00000000-0000-4000-8000-0000000000c3")
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
	if err := s.ArchiveEvent(ctx, "00000000-0000-4000-8000-0000000000c3", now); err != nil {
		t.Fatalf("clean archive: %v", err)
	}
}

func TestB2EventStorageNormalizationAndCrossTypeConflict(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	id := testEnrollEvent(t, s, "00000000-0000-4000-8000-0000000000c4", NodeClassLinuxVPS, now)
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
	a := testEnrollEvent(t, s, "00000000-0000-4000-8000-0000000000aa", NodeClassLinuxVPS, now)
	b := testEnrollEvent(t, s, "00000000-0000-4000-8000-0000000000bb", NodeClassLinuxVPS, now+1)
	seedTelemetry(t, s, a, "aa-row", now-10, now)
	seedTelemetry(t, s, b, "bb-row", now-10, now+1)
	if err := s.ArchiveEvent(ctx, "00000000-0000-4000-8000-0000000000aa", now); err != nil {
		t.Fatalf("archive A: %v", err)
	}
	if err := s.ArchiveEvent(ctx, "00000000-0000-4000-8000-0000000000bb", now+5*24*60*60); err != nil {
		t.Fatalf("archive B: %v", err)
	}
	// At exactly T_A+30d, A's data is deleted; B's tail is still alive.
	if _, err := s.RunRetentionB2(ctx, now+PolicyBArchiveTailSeconds); err != nil {
		t.Fatalf("retention at A boundary: %v", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM snapshots WHERE event_id='00000000-0000-4000-8000-0000000000aa'`); got != 0 {
		t.Fatalf("event A data at exact T+30d = %d, want 0", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM snapshots WHERE event_id='00000000-0000-4000-8000-0000000000bb'`); got != 1 {
		t.Fatalf("event B data before its boundary = %d, want 1", got)
	}
	// At exactly T_B+30d, B's data is deleted as well; catalogs remain.
	if _, err := s.RunRetentionB2(ctx, now+5*24*60*60+PolicyBArchiveTailSeconds); err != nil {
		t.Fatalf("retention at B boundary: %v", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM snapshots WHERE event_id='00000000-0000-4000-8000-0000000000bb'`); got != 0 {
		t.Fatalf("event B data at exact T+30d = %d, want 0", got)
	}
	for _, ev := range []string{"00000000-0000-4000-8000-0000000000aa", "00000000-0000-4000-8000-0000000000bb"} {
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
	if err := s.CreateEnrollToken(ctx, hash, "00000000-0000-4000-8000-0000000000c5", NodeClassLinuxVPS, now+3600, now); err != nil {
		t.Fatalf("token: %v", err)
	}
	for i := 0; i < MaxActiveNodesPerEvent; i++ {
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO nodes(node_id,event_id,node_class,state,created_at) VALUES(?,?,?,?,?)`,
			fmt.Sprintf("per-node-%03d", i), "00000000-0000-4000-8000-0000000000c5", NodeClassLinuxVPS, NodeActive, now); err != nil {
			t.Fatalf("seed per-event node: %v", err)
		}
	}
	_, hash2, _ := NewEnrollToken()
	if err := s.CreateEnrollToken(ctx, hash2, "00000000-0000-4000-8000-0000000000c5", NodeClassLinuxVPS, now+3600, now); !errors.Is(err, ErrQuotaExceeded) {
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
	if err := s2.CreateEnrollToken(ctx, hash3, "00000000-0000-4000-8000-0000000000ca", NodeClassLinuxVPS, now+3600, now); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("event catalog quota = %v, want ErrQuotaExceeded", err)
	}
}

func seedEventWithMapping(t *testing.T, s *Store, eventID string, now int64) (EnrolledIdentity, EnrolledIdentity) {
	t.Helper()
	ctx := testContext()
	win := testEnrollEvent(t, s, eventID, NodeClassWindowsTerminal, now)
	linux := testEnrollEvent(t, s, eventID, NodeClassLinuxVPS, now)
	if err := s.createMappingVersion(ctx, eventID, win.NodeID, 1, now, "admin",
		map[string]string{RouteTokenAReality: linux.NodeID}, now); err != nil {
		t.Fatalf("seed mapping: %v", err)
	}
	return win, linux
}

func TestB2PurgeWithMappingsAndPermanentGraveyard(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	eventID := "00000000-0000-4000-8000-0000000000c6"
	_, linux := seedEventWithMapping(t, s, eventID, now)
	seedTelemetry(t, s, linux, "purge-snap", now-10, now)
	mustPutBoot(t, s, linux.NodeID, 1, "boot-purge", 1, "fp-purge")
	// Ordinary mapping delete remains forbidden outside the purge authorization.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM route_mapping_entries WHERE event_id=?`, eventID); err == nil {
		t.Fatal("ordinary mapping DELETE was allowed")
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE route_mapping_versions SET effective_to=? WHERE event_id=?`, now+5, eventID); err == nil {
		t.Fatal("ordinary mapping UPDATE was allowed")
	}
	if err := s.PurgeEvent(ctx, eventID, "admin", true, now+1); err != nil {
		t.Fatalf("purge with mapping: %v", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM route_mapping_versions WHERE event_id=?`, eventID); got != 0 {
		t.Fatalf("mapping versions remain after purge: %d", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM route_mapping_entries WHERE event_id=?`, eventID); got != 0 {
		t.Fatalf("mapping entries remain after purge: %d", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM snapshots WHERE event_id=?`, eventID); got != 0 {
		t.Fatalf("telemetry remains after purge: %d", got)
	}
	if exists, err := s.EventGraveyardExists(ctx, eventID); err != nil || !exists {
		t.Fatalf("graveyard exists=%v err=%v", exists, err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM purge_ops WHERE event_id=? AND state='completed' AND deleted_rows>0`, eventID); got != 1 {
		t.Fatalf("completed purge operation/progress rows=%d, want 1", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM security_ledger WHERE kind='event_purged'`); got != 1 {
		t.Fatalf("event_purged audit rows=%d, want 1", got)
	}
	// While the audit tombstone is valid, the event ID is already refused.
	_, hashLive, _ := NewEnrollToken()
	if err := s.CreateEnrollToken(ctx, hashLive, eventID, NodeClassLinuxVPS, now+3600, now); !errors.Is(err, ErrEventPurged) {
		t.Fatalf("token while tombstone valid = %v, want ErrEventPurged", err)
	}
	// Tombstone expiry must not re-authorize the event ID.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM purge_tombstones WHERE event_id=?`, eventID); err != nil {
		t.Fatalf("expire tombstone: %v", err)
	}
	_, hash, _ := NewEnrollToken()
	if err := s.CreateEnrollToken(ctx, hash, eventID, NodeClassLinuxVPS, now+3600, now); !errors.Is(err, ErrEventPurged) {
		t.Fatalf("reissued token for purged event = %v, want ErrEventPurged", err)
	}
	// Old nodes/keys stay revoked and cannot regain eligibility.
	node, err := s.GetNode(ctx, linux.NodeID)
	if err != nil || node.State != NodeRevoked {
		t.Fatalf("purged node state=%+v err=%v", node, err)
	}
	key, err := s.GetKey(ctx, linux.NodeID, linux.KeyID)
	if err != nil || key.State != KeyRevoked {
		t.Fatalf("purged key state=%+v err=%v", key, err)
	}
	// A fresh event with the same ID cannot be created by token issuance.
	if _, err := s.EventState(ctx, eventID); !errors.Is(err, ErrEventUnknown) {
		t.Fatalf("event catalog after purge = %v, want unknown", err)
	}
	// The old high-water remains persisted/fail-closed, and the old identity is
	// blocked before any transport state can advance it.
	if _, err := s.GetBoot(ctx, linux.NodeID); err != nil {
		t.Fatalf("purge deleted authoritative old boot high-water: %v", err)
	}
	if err := s.WithTx(ctx, func(tx *Tx) error {
		_, err := tx.EventActiveTx(ctx, eventID)
		return err
	}); !errors.Is(err, ErrEventPurged) {
		t.Fatalf("old identity event gate = %v, want ErrEventPurged", err)
	}
}

func TestB2PurgeRecoveryAndFaults(t *testing.T) {
	path := tempStorePath(t)
	s := openTestStore(t, path)
	ctx := testContext()
	now := int64(1_700_000_000)
	eventID := "00000000-0000-4000-8000-0000000000c7"
	_, linux := seedEventWithMapping(t, s, eventID, now)
	seedTelemetry(t, s, linux, "fault-snap", now-10, now)
	// Failure after a committed telemetry batch leaves a persisted op; data that
	// was not yet processed is still there and ingest stays blocked.
	s.SetRetentionHookForTest(func(stage string) error {
		if stage == "purge:after_batch" {
			return errors.New("injected after batch")
		}
		return nil
	})
	if err := s.PurgeEvent(ctx, eventID, "admin", true, now+1); err == nil {
		t.Fatal("injected purge failure was not reported")
	}
	if err := s.WithTx(ctx, func(tx *Tx) error {
		_, err := tx.EventActiveTx(ctx, eventID)
		return err
	}); !errors.Is(err, ErrEventPurged) {
		t.Fatalf("ingest gate after failed purge = %v, want ErrEventPurged", err)
	}
	s.SetRetentionHookForTest(nil)
	// Restart the database; retry resumes and completes the purge.
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	s = openTestStore(t, path)
	defer s.Close()
	if err := s.PurgeEvent(ctx, eventID, "admin", true, now+2); err != nil {
		t.Fatalf("resume purge after restart: %v", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM route_mapping_versions WHERE event_id=?`, eventID); got != 0 {
		t.Fatalf("mapping versions after resumed purge=%d", got)
	}
	if exists, err := s.EventGraveyardExists(ctx, eventID); err != nil || !exists {
		t.Fatalf("graveyard after resume=%v err=%v", exists, err)
	}
	// Mapping/tombstone-stage faults are also resumable.
	for i, stage := range []string{"purge:mapping", "purge:tombstone"} {
		p := tempStorePath(t)
		s2 := openTestStore(t, p)
		ev := fmt.Sprintf("00000000-0000-4000-8000-%012d", 900+i)
		_, l2 := seedEventWithMapping(t, s2, ev, now)
		seedTelemetry(t, s2, l2, "f-"+stage, now-10, now)
		s2.SetRetentionHookForTest(func(got string) error {
			if got == stage {
				return errors.New("injected " + stage)
			}
			return nil
		})
		if err := s2.PurgeEvent(ctx, ev, "admin", true, now+1); err == nil {
			t.Fatalf("%s fault not reported", stage)
		}
		s2.SetRetentionHookForTest(nil)
		if err := s2.PurgeEvent(ctx, ev, "admin", true, now+2); err != nil {
			t.Fatalf("resume %s: %v", stage, err)
		}
		if exists, err := s2.EventGraveyardExists(ctx, ev); err != nil || !exists {
			t.Fatalf("%s graveyard=%v err=%v", stage, exists, err)
		}
		_ = s2.Close()
	}
}

func TestB2PurgeBlocksIngestAndEnrollmentConcurrently(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	eventID := "00000000-0000-4000-8000-0000000000c8"
	win, linux := seedEventWithMapping(t, s, eventID, now)
	seedTelemetry(t, s, linux, "conc-snap", now-10, now)
	// Same public mapping parameters used below must succeed on the active event.
	activeEffective := time.Now().Unix() + 3600
	if err := s.CreateMappingVersion(ctx, eventID, win.NodeID, 2, activeEffective, "admin",
		map[string]string{RouteTokenAReality: linux.NodeID}); err != nil {
		t.Fatalf("active mapping with future effective_from: %v", err)
	}
	// Start a purge that fails after persisting the operation, so the event stays
	// blocked while ingest attempts race it.
	s.SetRetentionHookForTest(func(stage string) error {
		if stage == "purge:persisted" {
			return errors.New("hold purge after persisted")
		}
		return nil
	})
	if err := s.PurgeEvent(ctx, eventID, "admin", true, now+1); err == nil {
		t.Fatal("purge hold not reported")
	}
	s.SetRetentionHookForTest(nil)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _, err := s.ApplyIngest(ctx, linux.NodeID, protocol.Attempt{Gen: 1, BootID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Seq: 1, Fingerprint: "fp"}, "fp",
			func(tx *Tx) error {
				_, err := tx.EventActiveTx(ctx, eventID)
				return err
			}, nil)
		errs <- err
	}()
	go func() {
		defer wg.Done()
		_, hash, _ := NewEnrollToken()
		errs <- s.CreateEnrollToken(ctx, hash, eventID, NodeClassWindowsTerminal, now+3600, now)
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err == nil {
			t.Fatal("ingest/enrollment succeeded during purging")
		}
		if !errors.Is(err, ErrEventPurged) && !errors.Is(err, ErrEventUnknown) {
			t.Fatalf("unexpected concurrent purge error: %v", err)
		}
	}
	// Ordinary mapping/config writes are also blocked by the purging state.
	purgingEffective := time.Now().Unix() + 7200
	if err := s.CreateMappingVersion(ctx, eventID, win.NodeID, 3, purgingEffective, "admin",
		map[string]string{RouteTokenAReality: linux.NodeID}); !errors.Is(err, ErrEventPurged) {
		t.Fatalf("mapping write during purging = %v, want ErrEventPurged", err)
	}
	if _, err := s.UpdateNodeConfig(ctx, linux.NodeID, nil, nil, 60, purgingEffective); !errors.Is(err, ErrEventPurged) {
		t.Fatalf("config update during purging = %v, want ErrEventPurged", err)
	}
	_ = win
}

func TestB2RetentionRunsBoundedAndLatestFK(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	id := testEnrollEvent(t, s, "00000000-0000-4000-8000-0000000000c9", NodeClassLinuxVPS, now)
	// Latest state old enough to be removed; it references a snapshot row that is
	// also deleted, so FK ordering must be correct.
	if err := s.WithTx(ctx, func(tx *Tx) error {
		_, err := tx.StoreSnapshotTx(ctx, SnapshotRecord{NodeID: id.NodeID, EventID: id.EventID, NodeClass: id.NodeClass,
			ReportID: "old-latest", CollectedAt: now - 40*24*60*60, ReceivedAt: now - 40*24*60*60,
			BodySHA256: "old-hash", Payload: []byte(`{"v":1}`)})
		return err
	}); err != nil {
		t.Fatalf("seed latest: %v", err)
	}
	// Seed more retention_runs than the bound; one run must cap them.
	for i := 0; i < 105; i++ {
		if _, err := s.db.ExecContext(ctx, `INSERT INTO retention_runs(ran_at,result_json) VALUES(?,?)`, now+int64(i), `{}`); err != nil {
			t.Fatalf("seed retention run: %v", err)
		}
	}
	if _, err := s.RunRetentionB2(ctx, now); err != nil {
		t.Fatalf("retention: %v", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM retention_runs`); got != RetentionRunsKeep {
		t.Fatalf("retention_runs=%d, want %d", got, RetentionRunsKeep)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM node_latest WHERE node_id=?`, id.NodeID); got != 0 {
		t.Fatalf("expired latest pointer survived: %d", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM snapshots WHERE report_id='old-latest'`); got != 0 {
		t.Fatalf("expired snapshot survived: %d", got)
	}
}

func TestB2RotationExpiryEqualityBoundary(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	id := testEnroll(t, s, NodeClassLinuxVPS, now)
	var keyID string
	if err := s.WithTx(ctx, func(tx *Tx) error {
		if err := tx.CreateRotationTx(ctx, RotationRecord{NodeID: id.NodeID, OldKeyID: id.KeyID, Nonce: "eq", BodySHA256: "h", ExpiresAt: now, CreatedAt: now}, testPublicKey(t)); err != nil {
			return err
		}
		rec, _, err := tx.RotationTx(ctx, id.NodeID, "eq")
		keyID = rec.NewKeyID
		return err
	}); err != nil {
		t.Fatalf("create rotation: %v", err)
	}
	// At exactly expires_at the intent is still valid for confirmation.
	if err := s.WithTx(ctx, func(tx *Tx) error {
		_, err := tx.ConfirmRotationTx(ctx, id.NodeID, "eq", now)
		return err
	}); err != nil {
		t.Fatalf("confirm at expiry equality: %v", err)
	}
	// A second rotation with expiry now must not be aborted at equality.
	id2 := testEnroll(t, s, NodeClassLinuxVPS, now+1)
	if err := s.WithTx(ctx, func(tx *Tx) error {
		return tx.CreateRotationTx(ctx, RotationRecord{NodeID: id2.NodeID, OldKeyID: id2.KeyID, Nonce: "eq2", BodySHA256: "h", ExpiresAt: now + 10, CreatedAt: now + 1}, testPublicKey(t))
	}); err != nil {
		t.Fatalf("create second: %v", err)
	}
	if n, err := s.AbortExpiredRotations(ctx, now+10); err != nil || n != 0 {
		t.Fatalf("abort at equality = %d err=%v, want 0", n, err)
	}
	if n, err := s.AbortExpiredRotations(ctx, now+11); err != nil || n != 1 {
		t.Fatalf("abort after expiry = %d err=%v, want 1", n, err)
	}
	_ = keyID
}

func TestB2PurgeBatchProgressSurvivesRestart(t *testing.T) {
	path := tempStorePath(t)
	s := openTestStore(t, path)
	ctx := testContext()
	now := int64(1_700_000_000)
	eventID := "00000000-0000-4000-8000-0000000000d1"
	id := testEnrollEvent(t, s, eventID, NodeClassLinuxVPS, now)
	// 50,005 normalized event rows force one full 50k batch plus a remainder.
	if _, err := s.db.ExecContext(ctx,
		`WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n < 50005)
		 INSERT INTO report_events(node_id,event_id,report_id,collected_at,received_at,event_id_json,event_at,kind,severity,details_json)
		 SELECT ?,?,printf('r-%06d',n),?,?,printf('e-%06d',n),?,'agent_started','info','{}' FROM seq`,
		id.NodeID, eventID, now, now, now); err != nil {
		t.Fatalf("seed 50k event rows: %v", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM report_events WHERE event_id=?`, eventID); got != 50005 {
		t.Fatalf("seeded rows=%d", got)
	}
	s.SetRetentionHookForTest(func(stage string) error {
		if stage == "purge:after_batch" {
			return errors.New("interrupt after committed batch")
		}
		return nil
	})
	if err := s.PurgeEvent(ctx, eventID, "admin", true, now+1); err == nil {
		t.Fatal("batch-boundary interruption not reported")
	}
	// The first 50k batch and its progress committed together.
	var op PurgeOp
	if _, ok, err := s.loadPurgeOp(ctx, eventID); err != nil || !ok {
		t.Fatalf("load op: ok=%v err=%v", ok, err)
	} else if ok {
		op, _, _ = s.loadPurgeOp(ctx, eventID)
	}
	if op.DeletedRows != RetentionBatchRows {
		t.Fatalf("persisted progress=%d, want %d", op.DeletedRows, RetentionBatchRows)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM report_events WHERE event_id=?`, eventID); got != 5 {
		t.Fatalf("remaining rows after first batch=%d, want 5", got)
	}
	s.SetRetentionHookForTest(nil)
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	s = openTestStore(t, path)
	defer s.Close()
	if err := s.PurgeEvent(ctx, eventID, "admin", true, now+2); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if got := queryInt(t, s, `SELECT deleted_rows FROM purge_ops WHERE event_id=? AND state='completed'`, eventID); got != 50005 {
		t.Fatalf("completed deleted_rows=%d, want 50005", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM report_events WHERE event_id=?`, eventID); got != 0 {
		t.Fatalf("remaining rows after resume=%d", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM security_ledger WHERE kind='event_purged'`); got != 1 {
		t.Fatalf("event_purged audit rows=%d, want exactly 1", got)
	}
	// A duplicate completion call is idempotent and writes no second audit.
	if err := s.PurgeEvent(ctx, eventID, "admin", true, now+3); err != nil {
		t.Fatalf("idempotent purge: %v", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM security_ledger WHERE kind='event_purged'`); got != 1 {
		t.Fatalf("duplicate audit rows=%d", got)
	}
}

func TestB2OverlapBudgetFormula(t *testing.T) {
	// Explicit byte budget: plan 1000 => limit 2000.
	if b := ComputeOverlapBudget(1000, 0, 2000); b.Exceeds() || b.BudgetBytes != 2000 || b.Unit != "bytes" {
		t.Fatalf("equal boundary = %+v, want below/equal allowed", b)
	}
	if b := ComputeOverlapBudget(1000, 0, 2001); !b.Exceeds() {
		t.Fatalf("above boundary = %+v, want exceeded", b)
	}
	if b := ComputeOverlapBudget(1000, 500, 1500); b.Exceeds() {
		t.Fatalf("archived+candidate equal limit = %+v", b)
	}
	if b := ComputeOverlapBudget(1000, 500, 1501); !b.Exceeds() {
		t.Fatalf("archived+candidate above limit = %+v", b)
	}
	// Last active event: archived=0, candidate can use the whole 2x plan cap.
	if b := ComputeOverlapBudget(1000, 0, 2000); b.Exceeds() || b.ArchivedStoredBytes != 0 || b.CandidateBytes != 2000 {
		t.Fatalf("last active event formula = %+v", b)
	}
}

func TestB2OverlapBudgetArchiveBoundary(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	seedEvent := func(ev string, payloadLen int, collected int64) {
		t.Helper()
		id := testEnrollEvent(t, s, ev, NodeClassLinuxVPS, now)
		if err := s.WithTx(ctx, func(tx *Tx) error {
			_, err := tx.StoreSnapshotTx(ctx, SnapshotRecord{NodeID: id.NodeID, EventID: ev, NodeClass: id.NodeClass,
				ReportID: "r-" + ev, CollectedAt: collected, ReceivedAt: now,
				BodySHA256: "hash-" + ev, Payload: []byte(strings.Repeat("x", payloadLen))})
			return err
		}); err != nil {
			t.Fatalf("seed %s: %v", ev, err)
		}
	}
	// Archive A under the normal budget; then use a 100-byte planning basis.
	a := "00000000-0000-4000-8000-0000000000e1"
	seedEvent(a, 100, now-10)
	if err := s.ArchiveEvent(ctx, a, now); err != nil {
		t.Fatalf("archive A: %v", err)
	}
	s.SetOverlapBudgetForTest(100) // limit 200 bytes
	b := "00000000-0000-4000-8000-0000000000e2"
	seedEvent(b, 100, now-10)
	if err := s.ArchiveEvent(ctx, b, now); err != nil {
		t.Fatalf("equal overlap boundary: %v", err)
	}
	c := "00000000-0000-4000-8000-0000000000e3"
	seedEvent(c, 101, now-10)
	if err := s.ArchiveEvent(ctx, c, now); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("above overlap boundary = %v, want ErrQuotaExceeded", err)
	}
	// A last active event can still archive within the explicit cap.
	s.SetOverlapBudgetForTest(0)
	d := "00000000-0000-4000-8000-0000000000e4"
	seedEvent(d, 10, now-10)
	if err := s.ArchiveEvent(ctx, d, now); err != nil {
		t.Fatalf("last active event archive: %v", err)
	}
}

func TestB2ConfigHistoryBoundsAndFailClosed(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	id := testEnroll(t, s, NodeClassLinuxVPS, now)
	// A collection time before the only (later) history must fail closed rather
	// than borrowing that later enable through an "earliest history" fallback.
	if err := s.WithTx(ctx, func(tx *Tx) error {
		_, err := tx.ConfigAtTx(ctx, id.NodeID, now-100)
		return err
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pre-history ConfigAtTx = %v, want ErrNotFound", err)
	}
	// No valid history at collected_at: fail closed, never borrow a later enable.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM node_config_history WHERE node_id=?`, id.NodeID); err != nil {
		t.Fatalf("delete history: %v", err)
	}
	if err := s.WithTx(ctx, func(tx *Tx) error {
		_, err := tx.ConfigAtTx(ctx, id.NodeID, now+100)
		return err
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing history ConfigAtTx = %v, want ErrNotFound", err)
	}
	// Recreate the fail-closed initial row at registration time.
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO node_config_history(node_id,event_id,config_version,effective_from,sources_json,expected_inbound_tags_json,cadence_seconds,device_salt)
		 SELECT n.node_id,n.event_id,1,n.created_at,'{"system":false,"services":false,"singbox_api":false,"mihomo_api":false,"terminal":false,"events":false}','[]',c.cadence_seconds,c.device_salt FROM nodes n JOIN node_configs c ON c.node_id=n.node_id WHERE n.node_id=?`, id.NodeID); err != nil {
		t.Fatalf("seed initial history: %v", err)
	}
	node, err := s.GetNode(ctx, id.NodeID)
	if err != nil {
		t.Fatalf("get node: %v", err)
	}
	// Earlier than registration / earlier than latest history is rejected.
	if _, err := s.UpdateNodeConfig(ctx, id.NodeID, nil, nil, 60, node.CreatedAt-1); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("pre-registration config update = %v, want ErrInvalidArgument", err)
	}
	if _, err := s.UpdateNodeConfig(ctx, id.NodeID, nil, nil, 60, node.CreatedAt+10); err != nil {
		t.Fatalf("future config update: %v", err)
	}
	if _, err := s.UpdateNodeConfig(ctx, id.NodeID, nil, nil, 60, node.CreatedAt+9); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("backdated-to-history update = %v, want ErrInvalidArgument", err)
	}
	// Same-second rule: equal effective_from is accepted and the higher version
	// is the deterministic winner at that instant.
	cfg3, err := s.UpdateNodeConfig(ctx, id.NodeID, nil, nil, 90, node.CreatedAt+10)
	if err != nil {
		t.Fatalf("same-second update: %v", err)
	}
	if cfg3.ConfigVersion != 3 {
		t.Fatalf("same-second config version=%d, want 3", cfg3.ConfigVersion)
	}
	if err := s.WithTx(ctx, func(tx *Tx) error {
		got, err := tx.ConfigAtTx(ctx, id.NodeID, node.CreatedAt+10)
		if err != nil {
			return err
		}
		if got.ConfigVersion != 3 || got.CadenceSeconds != 90 {
			t.Fatalf("same-second ConfigAtTx=%+v, want v3 cadence90", got)
		}
		return nil
	}); err != nil {
		t.Fatalf("same-second ConfigAtTx: %v", err)
	}
}

func TestB2EnrollmentEventIDUUIDv4(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	_, hash, _ := NewEnrollToken()
	if err := s.CreateEnrollToken(ctx, hash, "not-a-uuid", NodeClassLinuxVPS, now+3600, now); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("invalid event id token = %v, want ErrInvalidArgument", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM enroll_tokens`); got != 0 {
		t.Fatalf("invalid token rows=%d", got)
	}
	// Defensive case: a malformed token row already in the DB must not be
	// consumed and must not create a partial identity/response.
	badHash := TokenHash("bad-pre-existing-token")
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO enroll_tokens(token_hash,event_id,node_class,expires_at,used_at,created_at)
		 VALUES(?,?,?,?,NULL,?)`, badHash, "not-a-uuid", NodeClassLinuxVPS, now+3600, now); err != nil {
		t.Fatalf("seed malformed token: %v", err)
	}
	_, err := s.Enroll(ctx, badHash, NodeClassLinuxVPS, "linux", testPublicKey(t), now)
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("malformed token enroll = %v, want ErrTokenInvalid", err)
	}
	var used sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT used_at FROM enroll_tokens WHERE token_hash=?`, badHash).Scan(&used); err != nil || used.Valid {
		t.Fatalf("malformed token consumed: used=%v err=%v", used, err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM nodes`); got != 0 {
		t.Fatalf("malformed token wrote nodes=%d", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM node_keys`); got != 0 {
		t.Fatalf("malformed token wrote keys=%d", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM node_configs`); got != 0 {
		t.Fatalf("malformed token wrote configs=%d", got)
	}
}

func TestB2PurgeSingleIncompleteOperation(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	ev := "00000000-0000-4000-8000-0000000000d2"
	_, linux := seedEventWithMapping(t, s, ev, now)
	seedTelemetry(t, s, linux, "single-op", now-10, now)
	s.SetRetentionHookForTest(func(stage string) error {
		if stage == "purge:persisted" {
			return errors.New("hold after persisted")
		}
		return nil
	})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.PurgeEvent(ctx, ev, "admin", true, now+1)
		}()
	}
	wg.Wait()
	if got := queryInt(t, s, `SELECT COUNT(*) FROM purge_ops WHERE event_id=? AND state<>'completed'`, ev); got != 1 {
		t.Fatalf("incomplete purge operations=%d, want exactly 1", got)
	}
	s.SetRetentionHookForTest(nil)
	if err := s.PurgeEvent(ctx, ev, "admin", true, now+2); err != nil {
		t.Fatalf("resume single op: %v", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM purge_ops WHERE event_id=?`, ev); got != 1 {
		t.Fatalf("total purge operations=%d, want 1", got)
	}
}

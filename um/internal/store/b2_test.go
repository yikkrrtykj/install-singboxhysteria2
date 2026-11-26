package store

import (
	"crypto/rand"
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

func TestB2RetentionPhysicalPruningAndArchive(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	id := testEnroll(t, s, NodeClassLinuxVPS, now)
	// 300 seq rows in the current generation; retention keeps 256.
	for seq := uint64(1); seq <= 300; seq++ {
		if err := s.RecordSeq(ctx, id.NodeID, 1, "boot-b2", seq, fmt.Sprintf("fp-%d", seq), now); err != nil {
			t.Fatalf("RecordSeq(%d): %v", seq, err)
		}
	}
	mustPutBoot(t, s, id.NodeID, 1, "boot-b2", 300, "fp-300")
	// 10 boot generations; retention keeps 8.
	for gen := uint64(1); gen <= 10; gen++ {
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO boot_registry(node_id,boot_gen,boot_id,first_seen_at,last_seen_at,last_seq,state)
			 VALUES(?,?,?,?,?,1,'retired')`, id.NodeID, gen, fmt.Sprintf("boot-%d", gen), now, now); err != nil {
			t.Fatalf("seed boot_registry gen %d: %v", gen, err)
		}
	}
	if err := s.WithTx(ctx, func(tx *Tx) error {
		_, err := tx.StoreSnapshotTx(ctx, SnapshotRecord{NodeID: id.NodeID, EventID: id.EventID, NodeClass: id.NodeClass,
			ReportID: "old-snapshot", CollectedAt: now - 40*24*60*60, ReceivedAt: now - 40*24*60*60,
			BodySHA256: "old-hash", Payload: []byte(`{"v":1}`)})
		return err
	}); err != nil {
		t.Fatalf("seed old snapshot: %v", err)
	}
	deleted, err := s.RunRetentionB2(ctx, now)
	if err != nil {
		t.Fatalf("RunRetentionB2: %v", err)
	}
	if deleted["seq_dedupe"] != 44 {
		t.Fatalf("seq prune = %d, want 44", deleted["seq_dedupe"])
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM seq_dedupe WHERE node_id=? AND boot_gen=1`, id.NodeID); got != 256 {
		t.Fatalf("seq rows = %d, want 256", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM boot_registry WHERE node_id=?`, id.NodeID); got != 8 {
		t.Fatalf("boot_registry rows = %d, want 8", got)
	}
	// node_boot is authoritative and not deleted by retention.
	if _, err := s.GetBoot(ctx, id.NodeID); err != nil && !errors.Is(err, ErrNotFound) {
		t.Fatalf("node_boot read: %v", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM archive_records WHERE record_type='snapshot'`); got != 1 {
		t.Fatalf("archived snapshots = %d, want 1", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM snapshots WHERE report_id='old-snapshot'`); got != 0 {
		t.Fatalf("old snapshot still active = %d", got)
	}
	// Retention is repeatable/idempotent.
	if _, err := s.RunRetentionB2(ctx, now); err != nil {
		t.Fatalf("second retention run: %v", err)
	}
	stats, err := s.CapacityStats(ctx)
	if err != nil || stats.Snapshots != 0 || stats.Archive != 1 {
		t.Fatalf("capacity = %+v err=%v", stats, err)
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

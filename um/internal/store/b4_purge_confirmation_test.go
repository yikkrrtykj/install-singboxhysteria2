package store

import (
	"context"
	"errors"
	"testing"
)

// TestB4PurgeConfirmed50kResume proves the final management authorization path
// uses the existing durable purge engine across the 50,000-row batch boundary:
// the first attempt persists the operation after consuming the preview receipt,
// then a restart resumes the already-authorized operation even without a live
// receipt.
func TestB4PurgeConfirmed50kResume(t *testing.T) {
	path := tempStorePath(t)
	s := openTestStore(t, path)
	ctx := context.Background()
	now := int64(1_800_000_000)
	const eventID = "55555555-5555-4555-8555-555555555555"
	id := testEnrollEvent(t, s, eventID, NodeClassLinuxVPS, now)
	preview, err := s.PurgePreview(ctx, eventID)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	confirmation, err := s.IssuePurgeConfirmation(ctx, eventID, "platform-admin", preview.StateFingerprint, now)
	if err != nil {
		t.Fatalf("issue confirmation: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n < 50005)
		 INSERT INTO report_events(node_id,event_id,report_id,collected_at,received_at,event_id_json,event_at,kind,severity,details_json)
		 SELECT ?,?,printf('r-%06d',n),?,?,printf('e-%06d',n),?,'agent_started','info','{}' FROM seq`,
		id.NodeID, eventID, now, now, now); err != nil {
		t.Fatalf("seed 50k event rows: %v", err)
	}
	s.SetRetentionHookForTest(func(stage string) error {
		if stage == "purge:after_batch" {
			return errors.New("interrupt after committed batch")
		}
		return nil
	})
	if err := s.PurgeEventConfirmed(ctx, eventID, "platform-admin", confirmation.ID, true, now+1); err == nil {
		t.Fatal("batch-boundary interruption not reported")
	}
	s.SetRetentionHookForTest(nil)
	op, ok, err := s.loadPurgeOp(ctx, eventID)
	if err != nil || !ok || op.DeletedRows != RetentionBatchRows {
		t.Fatalf("persisted authorized op: ok=%v op=%+v err=%v", ok, op, err)
	}
	var consumed int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM purge_confirmations WHERE confirmation_id=? AND consumed_by_op_id=?`,
		confirmation.ID, op.OpID).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if consumed != 1 {
		t.Fatalf("preview receipt was not consumed with the operation: %d", consumed)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openTestStore(t, path)
	defer s.Close()
	// The operation is already durably authorized. Resume must not require the
	// now-consumed/expired receipt and must not create a second operation.
	if err := s.PurgeEventConfirmed(ctx, eventID, "platform-admin", "", true, now+1000); err != nil {
		t.Fatalf("resume authorized operation: %v", err)
	}
	if got := queryInt(t, s, `SELECT deleted_rows FROM purge_ops WHERE event_id=? AND state='completed'`, eventID); got != 50005 {
		t.Fatalf("completed deleted_rows=%d, want 50005", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM purge_ops WHERE event_id=?`, eventID); got != 1 {
		t.Fatalf("purge ops=%d, want exactly one", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM purge_confirmations WHERE event_id=?`, eventID); got != 0 {
		t.Fatalf("purge receipts remaining after completion=%d, want 0", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM security_ledger WHERE kind='event_purged'`); got != 1 {
		t.Fatalf("event_purged ledger rows=%d, want 1", got)
	}
}

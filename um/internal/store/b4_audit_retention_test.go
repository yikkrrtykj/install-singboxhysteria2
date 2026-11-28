package store

import (
	"context"
	"fmt"
	"testing"
)

func insertAdminAuditAt(t *testing.T, s *Store, at int64, eventID *string) {
	t.Helper()
	var event any
	if eventID != nil {
		event = *eventID
	}
	if _, err := s.db.ExecContext(context.Background(),
		`INSERT INTO admin_audit(at,actor,role,action,target,event_id,result,detail,request_id)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		at, "admin-retention-test", "platform_admin", "event_archive", "event", event, "ok", nil, nil); err != nil {
		t.Fatalf("insert admin_audit at %d: %v", at, err)
	}
}

func TestB4AdminAuditRetentionBoundedAgeAndIsolation(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := context.Background()
	now := int64(1_800_000_000)
	cutoff := now - SecurityRetentionSeconds

	// Strict boundary: rows older than 180d are eligible; the row exactly at
	// the cutoff is still inside the approved retention window.
	insertAdminAuditAt(t, s, cutoff-1, nil)
	insertAdminAuditAt(t, s, cutoff, nil)
	insertAdminAuditAt(t, s, now-1, nil)
	oldEvent := "11111111-1111-4111-8111-111111111111"
	youngEvent := "22222222-2222-4222-8222-222222222222"
	insertAdminAuditAt(t, s, now-1, &oldEvent)
	insertAdminAuditAt(t, s, now-1, &youngEvent)

	var ledgerBefore int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_ledger`).Scan(&ledgerBefore); err != nil {
		t.Fatal(err)
	}
	deleted, err := s.RunRetentionB2PolicyB(ctx, now)
	if err != nil {
		t.Fatalf("retention: %v", err)
	}
	if deleted["admin_audit"] != 1 {
		t.Fatalf("admin_audit deleted=%d, want 1 (all=%v)", deleted["admin_audit"], deleted)
	}
	var remaining int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_audit`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 4 {
		t.Fatalf("remaining admin_audit=%d, want 4; boundary/young/event audit rows must be preserved", remaining)
	}
	var ledgerAfter int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_ledger`).Scan(&ledgerAfter); err != nil {
		t.Fatal(err)
	}
	if ledgerAfter != ledgerBefore {
		t.Fatalf("security ledger changed by audit retention: before=%d after=%d", ledgerBefore, ledgerAfter)
	}
	// Repeat is idempotent.
	if deleted, err = s.RunRetentionB2PolicyB(ctx, now); err != nil {
		t.Fatalf("second retention: %v", err)
	}
	if deleted["admin_audit"] != 0 {
		t.Fatalf("second retention admin_audit=%d, want 0", deleted["admin_audit"])
	}
}

func TestB4AdminAuditRetentionBatchesAndInterruption(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := context.Background()
	now := int64(1_800_000_000)
	cutoff := now - SecurityRetentionSeconds
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	const rows = int64(RetentionBatchRows + 5)
	for i := int64(0); i < rows; i++ {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO admin_audit(at,actor,role,action,target,event_id,result,detail,request_id)
			 VALUES(?,?,?,?,?,?,?,?,?)`,
			cutoff-1-i, "batch", "platform_admin", "event_archive", "event", nil, "ok", nil, nil); err != nil {
			t.Fatalf("seed row %d: %v", i, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	injected := false
	s.SetRetentionHookForTest(func(stage string) error {
		if stage == "delete:admin_audit" && !injected {
			injected = true
			return fmt.Errorf("injected audit retention interruption")
		}
		return nil
	})
	if _, err := s.RunRetentionB2PolicyB(ctx, now); err == nil {
		t.Fatal("injected audit retention interruption was not surfaced")
	}
	s.SetRetentionHookForTest(nil)
	var seeded int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_audit`).Scan(&seeded); err != nil {
		t.Fatal(err)
	}
	if seeded != rows {
		t.Fatalf("interrupted retention partially deleted audit rows: %d/%d", seeded, rows)
	}
	deleted, err := s.RunRetentionB2PolicyB(ctx, now)
	if err != nil {
		t.Fatalf("resumed retention: %v", err)
	}
	if deleted["admin_audit"] != rows {
		t.Fatalf("resumed admin_audit deleted=%d, want %d", deleted["admin_audit"], rows)
	}
	var left int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_audit`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatalf("resumed retention left %d rows", left)
	}
}

func TestB4AdminAuditRetentionPreservesArchivedAndPurgedEventAudit(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := context.Background()
	now := int64(1_800_000_000)
	archivedEvent := "33333333-3333-4333-8333-333333333333"
	purgedEvent := "44444444-4444-4444-8444-444444444444"
	if _, err := s.CreateEvent(ctx, archivedEvent, "archived", now); err != nil {
		t.Fatal(err)
	}
	if err := s.ArchiveEvent(ctx, archivedEvent, now+1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateEvent(ctx, purgedEvent, "purged", now); err != nil {
		t.Fatal(err)
	}
	if err := s.ArchiveEvent(ctx, purgedEvent, now+1); err != nil {
		t.Fatal(err)
	}
	if err := s.PurgeEvent(ctx, purgedEvent, "admin", true, now+2); err != nil {
		t.Fatalf("purge setup: %v", err)
	}
	insertAdminAuditAt(t, s, now-1, &archivedEvent)
	insertAdminAuditAt(t, s, now-1, &purgedEvent)
	var ledgerBefore int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_ledger`).Scan(&ledgerBefore); err != nil {
		t.Fatal(err)
	}
	deleted, err := s.RunRetentionB2PolicyB(ctx, now+100)
	if err != nil {
		t.Fatal(err)
	}
	if deleted["admin_audit"] != 0 {
		t.Fatalf("unexpired archived/purged event audit was deleted: %v", deleted)
	}
	var count int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_audit WHERE event_id IN (?,?)`,
		archivedEvent, purgedEvent).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("archived/purged event audit count=%d, want 2", count)
	}
	var ledgerAfter int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_ledger`).Scan(&ledgerAfter); err != nil {
		t.Fatal(err)
	}
	if ledgerAfter != ledgerBefore {
		t.Fatalf("security ledger changed: before=%d after=%d", ledgerBefore, ledgerAfter)
	}
}

func TestB4AdminAuditRetentionDoesNotShortenGlobalContract(t *testing.T) {
	if SecurityRetentionSeconds != 180*24*60*60 {
		t.Fatalf("SecurityRetentionSeconds=%d, want frozen 180d", SecurityRetentionSeconds)
	}
}

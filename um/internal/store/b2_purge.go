package store

// F1/F2: durable, resumable event purge with a permanent identity graveyard.
//
// The purge operation is persisted BEFORE any destructive action. While an
// operation is incomplete, all normal event operations are blocked by the same
// lifecycle gate that rejects ingest/enrollment/mapping/config/rotation. Mapping
// deletion is allowed only inside the explicit purge authorization state; the B1
// immutability triggers remain in force for every other path.

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// PurgeOp is the durable progress record for one event purge.
type PurgeOp struct {
	OpID        string
	EventID     string
	Actor       string
	StartedAt   int64
	UpdatedAt   int64
	State       string
	Phase       string
	DeletedRows int64
	Error       string
}

func randomOpID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("store: purge op id: %w", err)
	}
	return "purge-" + hex.EncodeToString(b), nil
}

// eventBlockedTx reports the permanent/durable reasons an event ID may not be
// re-created or used for normal operations.
func eventBlockedTx(ctx context.Context, tx *sql.Tx, eventID string) error {
	var one int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM event_graveyard WHERE event_id=?`, eventID).Scan(&one); err == nil {
		return ErrEventPurged
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM purge_ops WHERE event_id=? AND state<>'completed' LIMIT 1`, eventID).Scan(&one); err == nil {
		return ErrEventPurged
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return nil
}

// EventActiveTx enforces the full event lifecycle gate for ingest/enrollment/
// config/rotation/mapping: permanent graveyard, incomplete purge, catalog state.
func (t *Tx) EventActiveTx(ctx context.Context, eventID string) (EventInfo, error) {
	if err := eventBlockedTx(ctx, t.tx, eventID); err != nil {
		return EventInfo{}, err
	}
	e, err := t.EventStateTx(ctx, eventID)
	if err != nil {
		return EventInfo{}, err
	}
	if e.State != EventActive {
		return e, ErrEventArchived
	}
	return e, nil
}

func (s *Store) loadPurgeOp(ctx context.Context, eventID string) (PurgeOp, bool, error) {
	var op PurgeOp
	var errText sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT op_id,event_id,actor,started_at,updated_at,state,phase,deleted_rows,error
		 FROM purge_ops WHERE event_id=? ORDER BY started_at DESC LIMIT 1`, eventID).
		Scan(&op.OpID, &op.EventID, &op.Actor, &op.StartedAt, &op.UpdatedAt, &op.State, &op.Phase, &op.DeletedRows, &errText)
	if errors.Is(err, sql.ErrNoRows) {
		return PurgeOp{}, false, nil
	}
	if err != nil {
		return PurgeOp{}, false, err
	}
	op.Error = errText.String
	return op, true, nil
}

func (s *Store) updatePurgeOp(ctx context.Context, op PurgeOp) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE purge_ops SET updated_at=?,state=?,phase=?,deleted_rows=?,error=? WHERE op_id=?`,
		op.UpdatedAt, op.State, op.Phase, op.DeletedRows, nullString(op.Error), op.OpID)
	if err != nil {
		return fmt.Errorf("store: update purge op: %w", err)
	}
	return nil
}

func (s *Store) addPurgeProgress(ctx context.Context, opID string, n int64, phase string, now int64) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE purge_ops SET updated_at=?, deleted_rows=deleted_rows+?, phase=? WHERE op_id=?`,
		now, n, phase, opID); err != nil {
		return fmt.Errorf("store: purge progress: %w", err)
	}
	return nil
}

// PurgeEvent performs a resumable, durable purge. confirm/actor are required.
// It returns nil if the event was already fully purged by a prior attempt.
func (s *Store) PurgeEvent(ctx context.Context, eventID, actor string, confirm bool, now int64) error {
	if !confirm {
		return invalidArgument("confirm", "explicit confirmation is required")
	}
	if strings.TrimSpace(actor) == "" {
		return invalidArgument("actor", "must not be empty")
	}
	if strings.TrimSpace(eventID) == "" {
		return invalidArgument("event_id", "must not be empty")
	}
	// Already fully purged: idempotent success only if the permanent graveyard
	// exists; otherwise a completed op without graveyard is inconsistent.
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM event_graveyard WHERE event_id=?`, eventID).Scan(&one)
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if _, err := s.EventState(ctx, eventID); err != nil {
		return err
	}
	op, ok, err := s.loadPurgeOp(ctx, eventID)
	if err != nil {
		return err
	}
	if !ok || op.State == "completed" {
		// Persist the authorized operation BEFORE any destructive step.
		opID, err := randomOpID()
		if err != nil {
			return err
		}
		op = PurgeOp{OpID: opID, EventID: eventID, Actor: actor, StartedAt: now, UpdatedAt: now,
			State: "purging", Phase: "telemetry", DeletedRows: 0}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if err := lockCapacity(ctx, tx); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := eventBlockedTx(ctx, tx, eventID); err != nil && !errors.Is(err, ErrEventPurged) {
			_ = tx.Rollback()
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO purge_ops(op_id,event_id,actor,started_at,updated_at,state,phase,deleted_rows,error)
			 VALUES(?,?,?,?,?,?,?,0,NULL)`,
			op.OpID, op.EventID, op.Actor, op.StartedAt, op.UpdatedAt, op.State, op.Phase); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: persist purge op: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	if s.retentionHook != nil {
		if err := s.retentionHook("purge:persisted"); err != nil {
			op.Error = "persisted; injected failure before first batch"
			op.UpdatedAt = now
			_ = s.updatePurgeOp(ctx, op)
			return err
		}
	}

	// Phase 1: telemetry batches. node_latest references snapshots, so clear
	// pointers before deleting snapshot rows.
	if op.State == "purging" {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM node_latest WHERE event_id=?`, eventID); err != nil {
			op.Error = "clear latest pointers: " + err.Error()
			op.UpdatedAt = now
			_ = s.updatePurgeOp(ctx, op)
			return fmt.Errorf("store: purge latest pointers: %w", err)
		}
		for i, table := range []string{"snapshots", "report_metrics", "report_events", "report_event_reports"} {
			where := "event_id = ?"
			n, err := purgeDeleteBatched(ctx, s.db, s.retentionHook, table, where, op.EventID)
			if err != nil {
				op.Error = "telemetry batch failed: " + err.Error()
				op.UpdatedAt = now
				_ = s.updatePurgeOp(ctx, op)
				return fmt.Errorf("store: purge telemetry %s: %w", table, err)
			}
			if n > 0 {
				op.DeletedRows += n
				if err := s.addPurgeProgress(ctx, op.OpID, n, fmt.Sprintf("telemetry:%s", table), now); err != nil {
					return err
				}
				if s.retentionHook != nil {
					if err := s.retentionHook("purge:after_batch"); err != nil {
						op.Error = "injected failure after telemetry batch"
						op.UpdatedAt = now
						_ = s.updatePurgeOp(ctx, op)
						return err
					}
				}
			}
			_ = i
		}
		op.State = "mapping"
		op.Phase = "mapping"
		op.UpdatedAt = now
		if err := s.updatePurgeOp(ctx, op); err != nil {
			return err
		}
	}

	// Phase 2: mapping deletion is allowed only by the authorized purge state.
	if op.State == "mapping" {
		if s.retentionHook != nil {
			if err := s.retentionHook("purge:mapping"); err != nil {
				op.Error = "injected failure before mapping delete"
				op.UpdatedAt = now
				_ = s.updatePurgeOp(ctx, op)
				return err
			}
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE purge_ops SET state='finalizing',phase='mapping',updated_at=? WHERE op_id=? AND state IN ('mapping','finalizing')`,
			now, op.OpID); err != nil {
			_ = tx.Rollback()
			op.Error = "set finalizing failed: " + err.Error()
			op.UpdatedAt = now
			_ = s.updatePurgeOp(ctx, op)
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM route_mapping_entries WHERE event_id=?`, eventID); err != nil {
			_ = tx.Rollback()
			op.Error = "mapping entries delete failed: " + err.Error()
			op.UpdatedAt = now
			_ = s.updatePurgeOp(ctx, op)
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM route_mapping_versions WHERE event_id=?`, eventID); err != nil {
			_ = tx.Rollback()
			op.Error = "mapping versions delete failed: " + err.Error()
			op.UpdatedAt = now
			_ = s.updatePurgeOp(ctx, op)
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		op.State = "finalizing"
		op.Phase = "tombstone"
	}

	// Phase 3: final tombstone/graveyard/audit, all-or-nothing.
	if op.State == "finalizing" {
		if s.retentionHook != nil {
			if err := s.retentionHook("purge:tombstone"); err != nil {
				op.Error = "injected failure before tombstone"
				op.UpdatedAt = now
				_ = s.updatePurgeOp(ctx, op)
				return err
			}
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.ExecContext(ctx,
			`UPDATE nodes SET state=?, retired_at=? WHERE event_id=?`, NodeRevoked, now, eventID); err != nil {
			return fmt.Errorf("store: purge revoke nodes: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE node_keys SET state=?, revoked_at=? WHERE node_id IN (SELECT node_id FROM nodes WHERE event_id=?) AND state<>?`,
			KeyRevoked, now, eventID, KeyRevoked); err != nil {
			return fmt.Errorf("store: purge revoke keys: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE key_rotations SET state=? WHERE node_id IN (SELECT node_id FROM nodes WHERE event_id=?) AND state=?`,
			RotationAborted, eventID, RotationAwaitingProof); err != nil {
			return fmt.Errorf("store: purge abort rotations: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM node_latest WHERE event_id=?`, eventID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM node_configs WHERE event_id=?`, eventID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM node_config_history WHERE event_id=?`, eventID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM enroll_tokens WHERE event_id=?`, eventID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM event_catalog WHERE event_id=?`, eventID); err != nil {
			return err
		}
		// Permanent identity isolation (independent of the 180-day audit row).
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO event_graveyard(event_id,purged_at,op_id) VALUES(?,?,?)`,
			eventID, now, op.OpID); err != nil {
			return fmt.Errorf("store: write event graveyard: %w", err)
		}
		counts := fmt.Sprintf(`{"deleted_rows":%d,"phase":"completed"}`, op.DeletedRows)
		if _, err := tx.ExecContext(ctx,
			`INSERT OR REPLACE INTO purge_tombstones(event_id,actor,purged_at,counts_json,retain_until)
			 VALUES(?,?,?,?,?)`, eventID, actor, now, counts, now+PurgeTombstoneSeconds); err != nil {
			return fmt.Errorf("store: purge tombstone: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE purge_ops SET state='completed',phase='completed',updated_at=?,error=NULL WHERE op_id=?`,
			now, op.OpID); err != nil {
			return err
		}
		if _, err := appendLedgerTx(ctx, tx, now, "event_purged", eventID,
			ledgerDetailHash(actor+"|"+counts)); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			op.Error = "final commit failed: " + err.Error()
			op.UpdatedAt = now
			_ = s.updatePurgeOp(ctx, op)
			return err
		}
	}
	return nil
}

func purgeDeleteBatched(ctx context.Context, db *sql.DB, hook func(string) error, table, where string, args ...any) (int64, error) {
	var total int64
	for {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return total, err
		}
		if hook != nil {
			if err := hook("delete:" + table); err != nil {
				_ = tx.Rollback()
				return total, err
			}
		}
		query := fmt.Sprintf(`DELETE FROM %s WHERE rowid IN (SELECT rowid FROM %s WHERE %s ORDER BY rowid LIMIT %d)`,
			table, table, where, RetentionBatchRows)
		res, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			_ = tx.Rollback()
			return total, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			_ = tx.Rollback()
			return total, err
		}
		if err := tx.Commit(); err != nil {
			return total, err
		}
		total += n
		if n < RetentionBatchRows {
			return total, nil
		}
	}
}

// EventGraveyardExists is a test/diagnostic helper for permanent isolation.
func (s *Store) EventGraveyardExists(ctx context.Context, eventID string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM event_graveyard WHERE event_id=?`, eventID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

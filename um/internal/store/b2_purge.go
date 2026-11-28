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
	"sync"
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

func (s *Store) lockPurgeEvent(eventID string) func() {
	s.purgeMu.Lock()
	if s.purgeLocks == nil {
		s.purgeLocks = make(map[string]*sync.Mutex)
	}
	mu := s.purgeLocks[eventID]
	if mu == nil {
		mu = &sync.Mutex{}
		s.purgeLocks[eventID] = mu
	}
	s.purgeMu.Unlock()
	mu.Lock()
	return mu.Unlock
}

func purgeStateRank(state string) int {
	switch state {
	case "purging":
		return 1
	case "mapping":
		return 2
	case "finalizing":
		return 3
	case "completed":
		return 4
	default:
		return 0
	}
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

func loadPurgeOpTx(ctx context.Context, tx *sql.Tx, eventID string) (PurgeOp, bool, error) {
	var op PurgeOp
	var errText sql.NullString
	err := tx.QueryRowContext(ctx,
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
	var curState, curPhase string
	if err := s.db.QueryRowContext(ctx, `SELECT state,phase FROM purge_ops WHERE op_id=?`, op.OpID).Scan(&curState, &curPhase); err != nil {
		return fmt.Errorf("store: read purge op state: %w", err)
	}
	// deleted_rows is intentionally never written here: it is only incremented
	// atomically with the DELETE batch that produced it.
	if purgeStateRank(op.State) > purgeStateRank(curState) {
		if _, err := s.db.ExecContext(ctx,
			`UPDATE purge_ops SET state=?,phase=?,updated_at=?,error=? WHERE op_id=?`,
			op.State, op.Phase, op.UpdatedAt, nullString(op.Error), op.OpID); err != nil {
			return fmt.Errorf("store: update purge op: %w", err)
		}
		return nil
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE purge_ops SET updated_at=?,error=? WHERE op_id=?`,
		op.UpdatedAt, nullString(op.Error), op.OpID); err != nil {
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

// PurgeEvent performs a resumable, durable purge using the legacy internal
// engine entry point (B1/B2 compatibility and engine-level tests). The
// management boundary must use PurgeEventConfirmed so a first permanent
// deletion also consumes a short-lived bound preview receipt.
//
// It returns nil if the event was already fully purged by a prior attempt.
func (s *Store) PurgeEvent(ctx context.Context, eventID, actor string, confirm bool, now int64) error {
	return s.purgeEvent(ctx, eventID, actor, confirm, now, nil)
}

// PurgeEventConfirmed is the B4 management entry point. For a first permanent
// deletion it atomically consumes a preview receipt in the same transaction
// that persists the authorized purge operation. Resume of an already-persisted
// incomplete operation and idempotent completion remain available even after
// the receipt expires; the receipt can never create a second operation.
func (s *Store) PurgeEventConfirmed(ctx context.Context, eventID, actor, confirmationID string, confirm bool, now int64) error {
	return s.purgeEvent(ctx, eventID, actor, confirm, now, &purgeAuthorization{ConfirmationID: confirmationID})
}

func (s *Store) purgeEvent(ctx context.Context, eventID, actor string, confirm bool, now int64, auth *purgeAuthorization) error {
	if !confirm {
		return invalidArgument("confirm", "explicit confirmation is required")
	}
	if strings.TrimSpace(actor) == "" {
		return invalidArgument("actor", "must not be empty")
	}
	if strings.TrimSpace(eventID) == "" {
		return invalidArgument("event_id", "must not be empty")
	}
	unlock := s.lockPurgeEvent(eventID)
	defer unlock()
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
	if ok && op.State == "completed" {
		return fmt.Errorf("store: purge op %s is completed but no graveyard exists", op.OpID)
	}
	if !ok {
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
		if existing, ok, err := loadPurgeOpTx(ctx, tx, eventID); err != nil {
			_ = tx.Rollback()
			return err
		} else if ok && existing.State != "completed" {
			// Another request won the race under the capacity lock; resume it
			// instead of creating a duplicate incomplete operation.
			op = existing
			if err := tx.Commit(); err != nil {
				return err
			}
		} else {
			if err := eventBlockedTx(ctx, tx, eventID); err != nil && !errors.Is(err, ErrEventPurged) {
				_ = tx.Rollback()
				return err
			}
			// First permanent deletion only: consume the short-lived receipt in
			// the same transaction that persists the authorized operation. The
			// event lifecycle fingerprint is re-read under the capacity lock, so a
			// preview/confirm race cannot authorize stale state. An existing
			// incomplete op took the resume branch above and does not need it.
			if auth != nil {
				if err := consumePurgeConfirmationTx(ctx, tx, eventID, actor, op.OpID, auth.ConfirmationID, now); err != nil {
					_ = tx.Rollback()
					return err
				}
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
	}
	if s.retentionHook != nil {
		if err := s.retentionHook("purge:persisted"); err != nil {
			op.Error = "persisted; injected failure before first batch"
			op.UpdatedAt = now
			_ = s.updatePurgeOp(ctx, op)
			return err
		}
	}

	// Phase 1: telemetry batches. Each DELETE batch and its deleted_rows progress
	// commit in one transaction; a crash therefore leaves exact on-disk progress.
	if op.State == "purging" {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM node_latest WHERE event_id=?`, eventID); err != nil {
			op.Error = "clear latest pointers: " + err.Error()
			op.UpdatedAt = now
			_ = s.updatePurgeOp(ctx, op)
			return fmt.Errorf("store: purge latest pointers: %w", err)
		}
		for _, table := range []string{"traffic_observation_buckets", "traffic_observation_reports", "snapshots", "report_metrics", "report_events", "report_event_reports"} {
			for {
				tx, err := s.db.BeginTx(ctx, nil)
				if err != nil {
					return err
				}
				if s.retentionHook != nil {
					if err := s.retentionHook("delete:" + table); err != nil {
						_ = tx.Rollback()
						op.Error = "injected failure before telemetry batch"
						op.UpdatedAt = now
						_ = s.updatePurgeOp(ctx, op)
						return err
					}
				}
				res, err := tx.ExecContext(ctx,
					fmt.Sprintf(`DELETE FROM %s WHERE rowid IN (SELECT rowid FROM %s WHERE event_id=? ORDER BY rowid LIMIT %d)`, table, table, RetentionBatchRows),
					eventID)
				if err != nil {
					_ = tx.Rollback()
					op.Error = "telemetry batch failed: " + err.Error()
					op.UpdatedAt = now
					_ = s.updatePurgeOp(ctx, op)
					return fmt.Errorf("store: purge telemetry %s: %w", table, err)
				}
				n, err := res.RowsAffected()
				if err != nil {
					_ = tx.Rollback()
					return err
				}
				if n > 0 {
					if _, err := tx.ExecContext(ctx,
						`UPDATE purge_ops SET deleted_rows=deleted_rows+?,updated_at=?,phase=? WHERE op_id=?`,
						n, now, "telemetry:"+table, op.OpID); err != nil {
						_ = tx.Rollback()
						return err
					}
				}
				if err := tx.Commit(); err != nil {
					return err
				}
				op.DeletedRows += n
				if n > 0 && s.retentionHook != nil {
					if err := s.retentionHook("purge:after_batch"); err != nil {
						op.Error = "injected failure after committed telemetry batch"
						op.UpdatedAt = now
						_ = s.updatePurgeOp(ctx, op)
						return err
					}
				}
				if n < RetentionBatchRows {
					break
				}
			}
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
		if err := lockCapacity(ctx, tx); err != nil {
			return err
		}
		var already int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM event_graveyard WHERE event_id=?`, eventID).Scan(&already); err == nil {
			// A prior attempt already completed the final transaction; do not
			// duplicate tombstone/audit writes.
			_ = tx.Rollback()
			return nil
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
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
		// UM-B4 event-scoped aliases are administrative metadata for the event's
		// nodes/routes; they must not outlive the event whose nodes they name.
		if _, err := tx.ExecContext(ctx, `DELETE FROM aliases WHERE event_id=?`, eventID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM umc_user_event_scopes WHERE event_id=?`, eventID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM event_catalog WHERE event_id=?`, eventID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM purge_confirmations WHERE event_id=?`, eventID); err != nil {
			return err
		}
		// Permanent identity isolation (independent of the 180-day audit row).
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO event_graveyard(event_id,purged_at,op_id) VALUES(?,?,?)`,
			eventID, now, op.OpID); err != nil {
			return fmt.Errorf("store: write event graveyard: %w", err)
		}
		var actualDeleted int64
		if err := tx.QueryRowContext(ctx, `SELECT deleted_rows FROM purge_ops WHERE op_id=?`, op.OpID).Scan(&actualDeleted); err != nil {
			return fmt.Errorf("store: read actual purge progress: %w", err)
		}
		counts := fmt.Sprintf(`{"deleted_rows":%d,"phase":"completed"}`, actualDeleted)
		if _, err := tx.ExecContext(ctx,
			`INSERT OR REPLACE INTO purge_tombstones(event_id,actor,purged_at,counts_json,retain_until)
			 VALUES(?,?,?,?,?)`, eventID, actor, now, counts, now+PurgeTombstoneSeconds); err != nil {
			return fmt.Errorf("store: purge tombstone: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE purge_ops SET state='completed',phase='completed',updated_at=?,error=NULL WHERE op_id=? AND state='finalizing'`,
			now, op.OpID); err != nil {
			return err
		}
		if _, err := appendLedgerTx(ctx, tx, now, "event_purged", eventID,
			ledgerDetailHash(actor+"|"+counts)); err != nil {
			return err
		}
		if err := appendAuditFromContextTxFields(ctx, tx, "ok", "event_purge", eventID); err != nil {
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

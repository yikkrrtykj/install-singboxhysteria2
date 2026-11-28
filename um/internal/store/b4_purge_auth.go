package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// B4 final-closure purge confirmation binding.
//
// A preview returns a short-lived, single-use server receipt. It is bound to the
// authenticated actor, event, purge action and the event lifecycle fingerprint
// observed at preview time. The receipt is consumed in the same transaction
// that persists the first durable purge operation; the B2 purge engine remains
// the only executor. Already-persisted incomplete operations resume and
// completed operations remain idempotent without requiring a live receipt.
const PurgeConfirmationTTLSeconds = 5 * 60

var (
	// ErrPurgeConfirmationRequired means this is a first purge start but no
	// preview receipt was supplied.
	ErrPurgeConfirmationRequired = errors.New("store: purge preview confirmation required")
	// ErrPurgeConfirmationInvalid covers unknown, mismatched, replayed or
	// already-consumed receipts.
	ErrPurgeConfirmationInvalid = errors.New("store: purge preview confirmation invalid")
	// ErrPurgeConfirmationExpired means the short-lived receipt expired before
	// the first durable purge operation was persisted.
	ErrPurgeConfirmationExpired = errors.New("store: purge preview confirmation expired")
	// ErrPurgeConfirmationStale means the event lifecycle/state changed since
	// preview, so the preview no longer describes the target being purged.
	ErrPurgeConfirmationStale = errors.New("store: purge preview confirmation stale")
)

// PurgeConfirmation is the server-side receipt returned by a purge preview.
type PurgeConfirmation struct {
	ID               string
	EventID          string
	Actor            string
	Action           string
	StateFingerprint string
	IssuedAt         int64
	ExpiresAt        int64
}

type purgeAuthorization struct {
	ConfirmationID string
}

// purgeStateFingerprint captures the lifecycle state that a purge preview is
// authorized against. Counts are intentionally not part of this fingerprint:
// retention may legitimately shrink telemetry between preview and confirm; the
// immutable authorization state is the event's lifecycle/catalog state.
func purgeStateFingerprint(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, eventID string) (string, error) {
	var state string
	var archived, purgeAfter, dataPurged, updated sql.NullInt64
	err := q.QueryRowContext(ctx,
		`SELECT state,archived_at,purge_after,data_purged_at,updated_at
		 FROM event_catalog WHERE event_id=?`, eventID).
		Scan(&state, &archived, &purgeAfter, &dataPurged, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrEventUnknown
	}
	if err != nil {
		return "", fmt.Errorf("store: read purge confirmation event state: %w", err)
	}
	return fmt.Sprintf("%s|%d|%d|%d|%d",
		state, archived.Int64, purgeAfter.Int64, dataPurged.Int64, updated.Int64), nil
}

// IssuePurgeConfirmation creates one short-lived single-use receipt for a
// platform-admin purge preview. It reads the lifecycle fingerprint in the same
// transaction as receipt insertion.
func (s *Store) IssuePurgeConfirmation(ctx context.Context, eventID, actor, expectedFingerprint string, now int64) (PurgeConfirmation, error) {
	if err := validateEventID("event_id", eventID); err != nil {
		return PurgeConfirmation{}, err
	}
	trimmedActor, err := validateBoundedText("actor", actor, b4MaxIdentifierBytes)
	if err != nil {
		return PurgeConfirmation{}, err
	}
	fingerprint, err := purgeStateFingerprint(ctx, s.db, eventID)
	if err != nil {
		if errors.Is(err, ErrEventUnknown) {
			if graveyard, gerr := s.EventGraveyardExists(ctx, eventID); gerr != nil {
				return PurgeConfirmation{}, gerr
			} else if graveyard {
				return PurgeConfirmation{}, ErrEventPurged
			}
		}
		return PurgeConfirmation{}, err
	}
	if fingerprint != expectedFingerprint {
		return PurgeConfirmation{}, ErrPurgeConfirmationStale
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return PurgeConfirmation{}, fmt.Errorf("store: purge confirmation id: %w", err)
	}
	pc := PurgeConfirmation{
		ID:               "pc-" + hex.EncodeToString(b[:]),
		EventID:          eventID,
		Actor:            trimmedActor,
		Action:           "event_purge",
		StateFingerprint: fingerprint,
		IssuedAt:         now,
		ExpiresAt:        now + PurgeConfirmationTTLSeconds,
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PurgeConfirmation{}, fmt.Errorf("store: begin purge confirmation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// Bounded best-effort cleanup of already-expired receipts. The table is
	// intentionally small; every row is single-use authorization metadata.
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM purge_confirmations WHERE rowid IN (
		   SELECT rowid FROM purge_confirmations WHERE expires_at < ? ORDER BY rowid LIMIT ?)`,
		now, RetentionBatchRows); err != nil {
		return PurgeConfirmation{}, fmt.Errorf("store: prune purge confirmations: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO purge_confirmations(confirmation_id,event_id,actor,action,state_fingerprint,issued_at,expires_at)
		 VALUES(?,?,?,?,?,?,?)`,
		pc.ID, pc.EventID, pc.Actor, pc.Action, pc.StateFingerprint, pc.IssuedAt, pc.ExpiresAt); err != nil {
		return PurgeConfirmation{}, fmt.Errorf("store: insert purge confirmation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return PurgeConfirmation{}, fmt.Errorf("store: commit purge confirmation: %w", err)
	}
	return pc, nil
}

// consumePurgeConfirmationTx atomically validates and consumes one receipt.
// The caller holds the capacity and per-event serialization locks and will
// insert the durable purge operation in this same transaction.
func consumePurgeConfirmationTx(ctx context.Context, tx *sql.Tx, eventID, actor, opID, confirmationID string, now int64) error {
	if strings.TrimSpace(confirmationID) == "" {
		return ErrPurgeConfirmationRequired
	}
	var rowEvent, rowActor, rowAction, rowFingerprint string
	var expiresAt int64
	var consumed sql.NullInt64
	err := tx.QueryRowContext(ctx,
		`SELECT event_id,actor,action,state_fingerprint,expires_at,consumed_at
		 FROM purge_confirmations WHERE confirmation_id=?`, confirmationID).
		Scan(&rowEvent, &rowActor, &rowAction, &rowFingerprint, &expiresAt, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrPurgeConfirmationInvalid
	}
	if err != nil {
		return fmt.Errorf("store: read purge confirmation: %w", err)
	}
	if rowEvent != eventID || rowActor != actor || rowAction != "event_purge" {
		return ErrPurgeConfirmationInvalid
	}
	if consumed.Valid {
		return ErrPurgeConfirmationInvalid
	}
	if now > expiresAt {
		return ErrPurgeConfirmationExpired
	}
	fingerprint, err := purgeStateFingerprint(ctx, tx, eventID)
	if err != nil {
		if errors.Is(err, ErrEventUnknown) {
			return ErrPurgeConfirmationStale
		}
		return err
	}
	if fingerprint != rowFingerprint {
		return ErrPurgeConfirmationStale
	}
	res, err := tx.ExecContext(ctx,
		`UPDATE purge_confirmations SET consumed_at=?,consumed_by_op_id=?
		 WHERE confirmation_id=? AND consumed_at IS NULL`,
		now, opID, confirmationID)
	if err != nil {
		return fmt.Errorf("store: consume purge confirmation: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: consume purge confirmation: %w", err)
	}
	if n != 1 {
		return ErrPurgeConfirmationInvalid
	}
	return nil
}

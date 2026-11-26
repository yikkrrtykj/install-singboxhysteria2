package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/protocol"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/wire"
)

// Typed sentinel errors. Every method returns one of these (possibly wrapped)
// or a storage error, so callers can map failures onto the frozen wire error
// table without string matching.
var (
	// ErrNotFound reports that the requested row does not exist.
	ErrNotFound = errors.New("store: not found")
	// ErrAlreadyExists reports an append-only/single-insert conflict.
	ErrAlreadyExists = errors.New("store: already exists")
	// ErrConflict reports a semantic conflict (transport replay conflict,
	// reused report_id with a different body hash, ...).
	ErrConflict = errors.New("store: conflict")
	// ErrInvalidArgument reports a caller-supplied value that violates the
	// frozen contract (numeric bounds, node class, route token, ...).
	ErrInvalidArgument = errors.New("store: invalid argument")
	// ErrLedgerTampered reports a broken security-ledger hash chain.
	ErrLedgerTampered = errors.New("store: security ledger verification failed")
)

// InvalidArgumentError is a typed caller error for contract validation
// failures. It never echoes the offending value.
type InvalidArgumentError struct {
	Field  string
	Detail string
}

func (e *InvalidArgumentError) Error() string {
	if e.Field == "" {
		return "store: invalid argument: " + e.Detail
	}
	return "store: invalid argument (" + e.Field + "): " + e.Detail
}

// Is lets errors.Is(err, ErrInvalidArgument) succeed.
func (e *InvalidArgumentError) Is(target error) bool { return target == ErrInvalidArgument }

func invalidArgument(field, detail string) error {
	return &InvalidArgumentError{Field: field, Detail: detail}
}

// TransportConflictError is returned by ApplyTransport for a non-accepted,
// non-duplicate transport outcome. The result is also returned so the HTTP
// layer can map the outcome onto its frozen status/error code. No state was
// written when this error is returned.
type TransportConflictError struct {
	Outcome protocol.Outcome
}

func (e *TransportConflictError) Error() string {
	return "store: transport conflict: " + string(e.Outcome)
}

// Unwrap exposes the generic conflict sentinel.
func (e *TransportConflictError) Unwrap() error { return ErrConflict }

// IsTransportConflict reports whether err is a typed transport rejection.
func IsTransportConflict(err error) bool {
	var target *TransportConflictError
	return errors.As(err, &target)
}

// TransportConflictOutcome returns the frozen protocol outcome of a transport
// rejection.
func TransportConflictOutcome(err error) (protocol.Outcome, bool) {
	var target *TransportConflictError
	if !errors.As(err, &target) {
		return "", false
	}
	return target.Outcome, true
}

// LedgerVerificationError describes the first broken link of the security
// ledger hash chain.
type LedgerVerificationError struct {
	Seq    int64
	Reason string
}

func (e *LedgerVerificationError) Error() string {
	return fmt.Sprintf("store: security ledger entry %d is invalid: %s", e.Seq, e.Reason)
}

// Unwrap exposes the generic tamper sentinel.
func (e *LedgerVerificationError) Unwrap() error { return ErrLedgerTampered }

// Route mapping token set accepted by the frozen rev-5 contract.
const (
	RouteTokenAReality = "a_reality"
	RouteTokenAHy2     = "a_hy2"
	RouteTokenBReality = "b_reality"
	RouteTokenBHy2     = "b_hy2"
	RouteTokenDirect   = "direct"
)

var allowedRouteTokens = map[string]struct{}{
	RouteTokenAReality: {},
	RouteTokenAHy2:     {},
	RouteTokenBReality: {},
	RouteTokenBHy2:     {},
	RouteTokenDirect:   {},
}

// SeqFingerprintHistoryLimit is the bounded seq_dedupe history used for
// exact-retry classification (frozen rev-5 bound). Rows beyond this bound are
// not consulted; B1 deliberately does not prune the table (the retention
// skeleton only sweeps age-based dedupe tables), so the bound is applied when
// reading the history.
const SeqFingerprintHistoryLimit = 256

// retention windows (seconds) for the basic policy-B sweep.
const (
	retentionNonceWindow    int64 = 24 * 60 * 60
	retentionReportWindow   int64 = 8 * 24 * 60 * 60
	retentionActivityWindow int64 = 30 * 24 * 60 * 60
)

func nowUnix() int64 { return time.Now().Unix() }

func nullString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// numericToInt64 validates a frozen protocol numeric field and converts it to
// the signed 64-bit INTEGER used by SQLite. The bound check happens before the
// conversion, so a wrapped value can never be stored.
func numericToInt64(field string, value uint64) (int64, error) {
	if value < 1 || value > wire.MaxNumeric {
		return 0, invalidArgument(field, fmt.Sprintf("must be in [1, %d]", uint64(wire.MaxNumeric)))
	}
	return int64(value), nil
}

// Node is one persisted node identity.
type Node struct {
	NodeID     string
	EventID    string
	NodeClass  string
	State      string
	CreatedAt  int64
	LastSeenAt *int64
}

// CreateNode inserts a node identity. The node class is validated in Go and by
// the database CHECK constraint; a duplicate node id is ErrAlreadyExists.
func (s *Store) CreateNode(ctx context.Context, node Node) error {
	if strings.TrimSpace(node.NodeID) == "" {
		return invalidArgument("node_id", "must not be empty")
	}
	if strings.TrimSpace(node.EventID) == "" {
		return invalidArgument("event_id", "must not be empty")
	}
	if node.NodeClass != NodeClassLinuxVPS && node.NodeClass != NodeClassWindowsTerminal {
		return invalidArgument("node_class", "must be one of linux_vps, windows_terminal")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO nodes(node_id, event_id, node_class, state, created_at, last_seen_at)
		 VALUES(?, ?, ?, ?, ?, ?)`,
		node.NodeID, node.EventID, node.NodeClass, node.State, node.CreatedAt, node.LastSeenAt)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: node %q", ErrAlreadyExists, node.NodeID)
		}
		return fmt.Errorf("store: create node: %w", err)
	}
	return nil
}

// GetNode loads one node identity.
func (s *Store) GetNode(ctx context.Context, nodeID string) (Node, error) {
	var node Node
	var lastSeen sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT node_id, event_id, node_class, state, created_at, last_seen_at
		 FROM nodes WHERE node_id = ?`, nodeID).
		Scan(&node.NodeID, &node.EventID, &node.NodeClass, &node.State, &node.CreatedAt, &lastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, fmt.Errorf("%w: node %q", ErrNotFound, nodeID)
	}
	if err != nil {
		return Node{}, fmt.Errorf("store: get node: %w", err)
	}
	if lastSeen.Valid {
		value := lastSeen.Int64
		node.LastSeenAt = &value
	}
	return node, nil
}

// rowQuerier is the read/write subset shared by *sql.DB and *sql.Tx.
type rowQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// loadBoot reads the authoritative high-water row. ok is false when the node
// has not yet had an accepted transport request (enrollment state).
func loadBoot(ctx context.Context, q rowQuerier, nodeID string) (protocol.Boot, bool, error) {
	var highestGen, lastSeq int64
	var bootID string
	var fingerprint sql.NullString
	err := q.QueryRowContext(ctx,
		`SELECT highest_gen, boot_id, last_seq, last_fingerprint FROM node_boot WHERE node_id = ?`,
		nodeID).Scan(&highestGen, &bootID, &lastSeq, &fingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		return protocol.Boot{}, false, nil
	}
	if err != nil {
		return protocol.Boot{}, false, fmt.Errorf("store: load boot state: %w", err)
	}
	return protocol.Boot{
		HighestGen:      uint64(highestGen),
		BootID:          bootID,
		LastSeq:         uint64(lastSeq),
		LastFingerprint: fingerprint.String,
	}, true, nil
}

// GetBoot returns the authoritative high-water of one node. A node that has not
// committed a transport attempt yet returns the enrollment zero value
// protocol.Boot{} together with ErrNotFound.
func (s *Store) GetBoot(ctx context.Context, nodeID string) (protocol.Boot, error) {
	boot, ok, err := loadBoot(ctx, s.db, nodeID)
	if err != nil {
		return protocol.Boot{}, err
	}
	if !ok {
		return protocol.Boot{}, fmt.Errorf("%w: boot state for node %q", ErrNotFound, nodeID)
	}
	return boot, nil
}

// PutBoot overwrites the authoritative high-water of one node. It exists for
// operator tooling and tests; normal ingestion must go through ApplyTransport so
// the high-water is only advanced inside the request transaction.
func (s *Store) PutBoot(ctx context.Context, nodeID string, gen uint64, bootID string, seq uint64, fingerprint string) error {
	if strings.TrimSpace(nodeID) == "" {
		return invalidArgument("node_id", "must not be empty")
	}
	if strings.TrimSpace(bootID) == "" {
		return invalidArgument("boot_id", "must not be empty")
	}
	genValue, err := numericToInt64("gen", gen)
	if err != nil {
		return err
	}
	seqValue, err := numericToInt64("seq", seq)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO node_boot(node_id, highest_gen, boot_id, last_seq, last_fingerprint, updated_at)
		 VALUES(?, ?, ?, ?, ?, ?)
		 ON CONFLICT(node_id) DO UPDATE SET
		   highest_gen = excluded.highest_gen,
		   boot_id = excluded.boot_id,
		   last_seq = excluded.last_seq,
		   last_fingerprint = excluded.last_fingerprint,
		   updated_at = excluded.updated_at`,
		nodeID, genValue, bootID, seqValue, nullString(fingerprint), nowUnix())
	if err != nil {
		return fmt.Errorf("store: put boot state: %w", err)
	}
	return nil
}

// InsertNonce records first use of a (node, nonce) pair. The returned bool is
// true when the nonce was already present (an idempotent replay); no write
// happens in that case.
func (s *Store) InsertNonce(ctx context.Context, nodeID, nonce, fingerprint string, at int64) (bool, error) {
	if strings.TrimSpace(nodeID) == "" {
		return false, invalidArgument("node_id", "must not be empty")
	}
	if strings.TrimSpace(nonce) == "" {
		return false, invalidArgument("nonce", "must not be empty")
	}
	result, err := s.db.ExecContext(ctx,
		`INSERT INTO nonce_dedupe(node_id, nonce, fingerprint, received_at)
		 VALUES(?, ?, ?, ?)
		 ON CONFLICT(node_id, nonce) DO NOTHING`,
		nodeID, nonce, fingerprint, at)
	if err != nil {
		return false, fmt.Errorf("store: insert nonce: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store: insert nonce: %w", err)
	}
	return affected == 0, nil
}

// NonceSeen reports whether a (node, nonce) pair is present.
func (s *Store) NonceSeen(ctx context.Context, nodeID, nonce string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM nonce_dedupe WHERE node_id = ? AND nonce = ?`, nodeID, nonce).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: read nonce: %w", err)
	}
	return true, nil
}

// NonceFingerprint returns the request fingerprint stored with a nonce, if the
// pair is present. Callers use it to distinguish an exact retry from a
// nonce_reuse (same nonce, different fingerprint).
func (s *Store) NonceFingerprint(ctx context.Context, nodeID, nonce string) (string, bool, error) {
	var fingerprint string
	err := s.db.QueryRowContext(ctx,
		`SELECT fingerprint FROM nonce_dedupe WHERE node_id = ? AND nonce = ?`,
		nodeID, nonce).Scan(&fingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("store: read nonce: %w", err)
	}
	return fingerprint, true, nil
}

// InsertReport records a report_id receipt. The returned bool is true when the
// report_id was already stored. A reused report_id with a different body hash is
// reported as (true, ErrConflict) after refreshing last_received_at; the caller
// maps that onto the frozen 409 report_conflict.
func (s *Store) InsertReport(ctx context.Context, nodeID, reportID, bodySHA256 string, at int64) (bool, error) {
	if strings.TrimSpace(nodeID) == "" {
		return false, invalidArgument("node_id", "must not be empty")
	}
	if strings.TrimSpace(reportID) == "" {
		return false, invalidArgument("report_id", "must not be empty")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("store: begin report dedupe: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var stored string
	err = tx.QueryRowContext(ctx,
		`SELECT body_sha256 FROM report_dedupe WHERE node_id = ? AND report_id = ?`,
		nodeID, reportID).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO report_dedupe(node_id, report_id, body_sha256, first_received_at, last_received_at)
			 VALUES(?, ?, ?, ?, ?)`,
			nodeID, reportID, bodySHA256, at, at); err != nil {
			return false, fmt.Errorf("store: insert report dedupe: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("store: commit report dedupe: %w", err)
		}
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: read report dedupe: %w", err)
	}
	// Existing report_id: only refresh the observation window and never rewrite
	// the stored hash, so a conflicting body cannot overwrite history.
	if _, err := tx.ExecContext(ctx,
		`UPDATE report_dedupe SET last_received_at = ?
		 WHERE node_id = ? AND report_id = ? AND (last_received_at IS NULL OR last_received_at < ?)`,
		at, nodeID, reportID, at); err != nil {
		return true, fmt.Errorf("store: refresh report dedupe: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return true, fmt.Errorf("store: commit report dedupe: %w", err)
	}
	if stored != bodySHA256 {
		return true, fmt.Errorf("%w: report_id %q was already stored with a different body hash", ErrConflict, reportID)
	}
	return true, nil
}

// ReportSeen returns the stored body hash of a report_id, if present.
func (s *Store) ReportSeen(ctx context.Context, nodeID, reportID string) (string, bool, error) {
	var stored string
	err := s.db.QueryRowContext(ctx,
		`SELECT body_sha256 FROM report_dedupe WHERE node_id = ? AND report_id = ?`,
		nodeID, reportID).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("store: read report dedupe: %w", err)
	}
	return stored, true, nil
}

// SeqLookup returns the exact-retry fingerprint recorded for one
// (node, boot generation, boot id, seq) attempt.
func (s *Store) SeqLookup(ctx context.Context, nodeID string, gen uint64, bootID string, seq uint64) (string, bool, error) {
	genValue, err := numericToInt64("gen", gen)
	if err != nil {
		return "", false, err
	}
	seqValue, err := numericToInt64("seq", seq)
	if err != nil {
		return "", false, err
	}
	var fingerprint string
	err = s.db.QueryRowContext(ctx,
		`SELECT fingerprint FROM seq_dedupe
		 WHERE node_id = ? AND boot_gen = ? AND boot_id = ? AND seq = ?`,
		nodeID, genValue, bootID, seqValue).Scan(&fingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("store: read seq dedupe: %w", err)
	}
	return fingerprint, true, nil
}

// RecordSeq upserts the exact-retry fingerprint of one accepted attempt. Normal
// ingestion records seq state inside ApplyTransport; this helper is for
// operator/tooling paths and tests.
func (s *Store) RecordSeq(ctx context.Context, nodeID string, gen uint64, bootID string, seq uint64, fingerprint string, at int64) error {
	if strings.TrimSpace(nodeID) == "" {
		return invalidArgument("node_id", "must not be empty")
	}
	if strings.TrimSpace(bootID) == "" {
		return invalidArgument("boot_id", "must not be empty")
	}
	genValue, err := numericToInt64("gen", gen)
	if err != nil {
		return err
	}
	seqValue, err := numericToInt64("seq", seq)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO seq_dedupe(node_id, boot_gen, boot_id, seq, fingerprint, received_at)
		 VALUES(?, ?, ?, ?, ?, ?)
		 ON CONFLICT(node_id, boot_gen, boot_id, seq) DO UPDATE SET
		   fingerprint = excluded.fingerprint,
		   received_at = excluded.received_at`,
		nodeID, genValue, bootID, seqValue, fingerprint, at)
	if err != nil {
		return fmt.Errorf("store: record seq dedupe: %w", err)
	}
	return nil
}

// loadSeqFingerprints reads the bounded exact-retry history for the current
// (node, generation, boot id). The map shape is the frozen protocol.Options
// input for protocol.Evaluate.
func loadSeqFingerprints(ctx context.Context, q rowQuerier, nodeID string, gen uint64, bootID string) (map[uint64]string, error) {
	genValue, err := numericToInt64("gen", gen)
	if err != nil {
		return nil, err
	}
	rows, err := q.QueryContext(ctx,
		`SELECT seq, fingerprint FROM seq_dedupe
		 WHERE node_id = ? AND boot_gen = ? AND boot_id = ?
		 ORDER BY seq DESC LIMIT ?`,
		nodeID, genValue, bootID, SeqFingerprintHistoryLimit)
	if err != nil {
		return nil, fmt.Errorf("store: load seq dedupe history: %w", err)
	}
	defer rows.Close()
	fingerprints := make(map[uint64]string)
	for rows.Next() {
		var seq int64
		var fingerprint string
		if err := rows.Scan(&seq, &fingerprint); err != nil {
			return nil, fmt.Errorf("store: load seq dedupe history: %w", err)
		}
		if seq < 1 {
			continue
		}
		fingerprints[uint64(seq)] = fingerprint
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: load seq dedupe history: %w", err)
	}
	return fingerprints, nil
}

// ApplyTransport decides and, when accepted, durably commits one transport
// attempt and its payload side effects in a single SQLite transaction.
//
//   - The authoritative node_boot high-water and the exact-retry history are
//     read inside the transaction, then protocol.Evaluate classifies the
//     attempt.
//   - Accepted: node_boot, boot_registry and seq_dedupe are updated and only
//     then is apply(tx) invoked. If apply returns an error the transaction is
//     rolled back, so a failed payload can never advance the high-water. The
//     Result is returned together with the apply error: it still describes the
//     decision, but nothing was committed, so the caller must not acknowledge
//     the request and must retry it.
//   - Duplicate: the attempt was already committed by the winning request. No
//     write is performed here (the caller's report dedupe handles payload
//     idempotency) and the Result carries the ACK next_seq.
//   - Any other outcome: rejected with a typed *TransportConflictError and no
//     write.
//
// attempt.Fingerprint is the canonical request fingerprint; the fingerprint
// parameter is a fallback so callers may pass it separately without duplicating
// it in Attempt.
func (s *Store) ApplyTransport(ctx context.Context, nodeID string, attempt protocol.Attempt, fingerprint string, apply func(*sql.Tx) error) (protocol.Result, error) {
	if strings.TrimSpace(nodeID) == "" {
		return protocol.Result{}, invalidArgument("node_id", "must not be empty")
	}
	if strings.TrimSpace(attempt.BootID) == "" {
		return protocol.Result{}, invalidArgument("boot_id", "must not be empty")
	}
	a := attempt
	if a.Fingerprint == "" {
		a.Fingerprint = fingerprint
	}
	if a.Fingerprint == "" {
		return protocol.Result{}, invalidArgument("fingerprint", "must not be empty")
	}
	// Validate before opening the transaction: conversion to signed INTEGER
	// happens only after the bound check.
	genValue, err := numericToInt64("gen", a.Gen)
	if err != nil {
		return protocol.Result{}, err
	}
	seqValue, err := numericToInt64("seq", a.Seq)
	if err != nil {
		return protocol.Result{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return protocol.Result{}, fmt.Errorf("store: begin transport transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	current, _, err := loadBoot(ctx, tx, nodeID)
	if err != nil {
		return protocol.Result{}, err
	}
	history, err := loadSeqFingerprints(ctx, tx, nodeID, a.Gen, a.BootID)
	if err != nil {
		return protocol.Result{}, err
	}
	result, err := protocol.Evaluate(current, a, protocol.Options{SeqFingerprints: history})
	if err != nil {
		return result, fmt.Errorf("store: evaluate transport attempt: %w", err)
	}

	switch result.Outcome {
	case protocol.Accepted:
		next := result.NextBoot
		if next.HighestGen == 0 {
			// Defensive fallback; protocol.Evaluate always populates NextBoot.
			next = protocol.Boot{HighestGen: a.Gen, BootID: a.BootID, LastSeq: a.Seq}
		}
		if next.LastFingerprint == "" {
			next.LastFingerprint = a.Fingerprint
		}
		// Evaluate validated the ranges, but re-validate before converting to
		// signed storage so a protocol regression cannot store a wrapped value.
		highestGen, err := numericToInt64("highest_gen", next.HighestGen)
		if err != nil {
			return result, err
		}
		lastSeq, err := numericToInt64("last_seq", next.LastSeq)
		if err != nil {
			return result, err
		}
		now := nowUnix()
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO node_boot(node_id, highest_gen, boot_id, last_seq, last_fingerprint, updated_at)
			 VALUES(?, ?, ?, ?, ?, ?)
			 ON CONFLICT(node_id) DO UPDATE SET
			   highest_gen = excluded.highest_gen,
			   boot_id = excluded.boot_id,
			   last_seq = excluded.last_seq,
			   last_fingerprint = excluded.last_fingerprint,
			   updated_at = excluded.updated_at`,
			nodeID, highestGen, next.BootID, lastSeq, nullString(next.LastFingerprint), now); err != nil {
			return result, fmt.Errorf("store: advance boot high-water: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO boot_registry(node_id, boot_gen, boot_id, first_seen_at, last_seen_at, last_seq, state)
			 VALUES(?, ?, ?, ?, ?, ?, 'active')
			 ON CONFLICT(node_id, boot_gen, boot_id) DO UPDATE SET
			   last_seen_at = excluded.last_seen_at,
			   last_seq = excluded.last_seq,
			   state = 'active'`,
			nodeID, genValue, a.BootID, now, now, seqValue); err != nil {
			return result, fmt.Errorf("store: record boot registry: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO seq_dedupe(node_id, boot_gen, boot_id, seq, fingerprint, received_at)
			 VALUES(?, ?, ?, ?, ?, ?)
			 ON CONFLICT(node_id, boot_gen, boot_id, seq) DO UPDATE SET
			   fingerprint = excluded.fingerprint,
			   received_at = excluded.received_at`,
			nodeID, genValue, a.BootID, seqValue, a.Fingerprint, now); err != nil {
			return result, fmt.Errorf("store: record seq dedupe: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE nodes SET last_seen_at = ? WHERE node_id = ?`, now, nodeID); err != nil {
			return result, fmt.Errorf("store: update node last seen: %w", err)
		}
		if apply != nil {
			if err := apply(tx); err != nil {
				// Deferred rollback reverts the high-water writes above.
				return result, fmt.Errorf("store: apply transport payload: %w", err)
			}
		}
		if err := tx.Commit(); err != nil {
			return result, fmt.Errorf("store: commit transport transaction: %w", err)
		}
		committed = true
		return result, nil

	case protocol.Duplicate:
		// Already committed by the winning attempt: no high-water change and no
		// payload write. The deferred rollback leaves the database untouched.
		return result, nil

	default:
		return result, &TransportConflictError{Outcome: result.Outcome}
	}
}

// CreateMappingVersion appends one immutable version of the Windows-terminal
// route mapping for an event. Target nodes must exist as linux_vps nodes of the
// same event; route tokens are the frozen five-token set. A version can never
// be overwritten: re-inserting an existing version returns ErrAlreadyExists.
func (s *Store) CreateMappingVersion(ctx context.Context, eventID, windowsNodeID string, version int, effectiveFrom int64, createdBy string, entries map[string]string) error {
	if strings.TrimSpace(eventID) == "" {
		return invalidArgument("event_id", "must not be empty")
	}
	if strings.TrimSpace(windowsNodeID) == "" {
		return invalidArgument("windows_node_id", "must not be empty")
	}
	if version < 1 {
		return invalidArgument("version", "must be a positive integer")
	}
	if len(entries) == 0 {
		return invalidArgument("entries", "must contain at least one route token")
	}
	tokens := make([]string, 0, len(entries))
	for token, target := range entries {
		if _, ok := allowedRouteTokens[token]; !ok {
			return invalidArgument("route_token", "must be one of the five frozen route tokens")
		}
		if strings.TrimSpace(target) == "" {
			return invalidArgument("target_node_id", "must not be empty")
		}
		tokens = append(tokens, token)
	}
	sort.Strings(tokens)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin mapping version: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var exists int
	err = tx.QueryRowContext(ctx,
		`SELECT 1 FROM route_mapping_versions
		 WHERE event_id = ? AND windows_node_id = ? AND version = ?`,
		eventID, windowsNodeID, version).Scan(&exists)
	if err == nil {
		return fmt.Errorf("%w: route mapping version %d for event %q / windows node %q is append-only",
			ErrAlreadyExists, version, eventID, windowsNodeID)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("store: read mapping version: %w", err)
	}

	// Validate target nodes before writing anything.
	for _, token := range tokens {
		target := entries[token]
		var nodeClass, nodeEvent string
		err := tx.QueryRowContext(ctx,
			`SELECT node_class, event_id FROM nodes WHERE node_id = ?`, target).
			Scan(&nodeClass, &nodeEvent)
		if errors.Is(err, sql.ErrNoRows) {
			return invalidArgument("target_node_id", fmt.Sprintf("target for route %q does not exist", token))
		}
		if err != nil {
			return fmt.Errorf("store: read mapping target: %w", err)
		}
		if nodeClass != NodeClassLinuxVPS {
			return invalidArgument("target_node_id", fmt.Sprintf("target for route %q must be a linux_vps node", token))
		}
		if nodeEvent != eventID {
			return invalidArgument("target_node_id", fmt.Sprintf("target for route %q belongs to a different event", token))
		}
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO route_mapping_versions(event_id, windows_node_id, version, effective_from, created_by, created_at)
		 VALUES(?, ?, ?, ?, ?, ?)`,
		eventID, windowsNodeID, version, effectiveFrom, createdBy, nowUnix()); err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: route mapping version %d", ErrAlreadyExists, version)
		}
		return fmt.Errorf("store: insert mapping version: %w", err)
	}
	for _, token := range tokens {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO route_mapping_entries(event_id, windows_node_id, version, route_token, target_node_id)
			 VALUES(?, ?, ?, ?, ?)`,
			eventID, windowsNodeID, version, token, entries[token]); err != nil {
			return fmt.Errorf("store: insert mapping entry: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit mapping version: %w", err)
	}
	return nil
}

// ResolveMapping resolves the mapping active at the given epoch second: the
// latest version whose effective_from is <= at, breaking ties deterministically
// on the highest version number. A missing mapping is ErrNotFound.
func (s *Store) ResolveMapping(ctx context.Context, eventID, windowsNodeID string, at int64) (map[string]string, int, error) {
	if strings.TrimSpace(eventID) == "" {
		return nil, 0, invalidArgument("event_id", "must not be empty")
	}
	if strings.TrimSpace(windowsNodeID) == "" {
		return nil, 0, invalidArgument("windows_node_id", "must not be empty")
	}
	var version int
	err := s.db.QueryRowContext(ctx,
		`SELECT version FROM route_mapping_versions
		 WHERE event_id = ? AND windows_node_id = ? AND effective_from <= ?
		 ORDER BY effective_from DESC, version DESC
		 LIMIT 1`,
		eventID, windowsNodeID, at).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, fmt.Errorf("%w: no route mapping for event %q / windows node %q at %d",
			ErrNotFound, eventID, windowsNodeID, at)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("store: resolve mapping version: %w", err)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT route_token, target_node_id FROM route_mapping_entries
		 WHERE event_id = ? AND windows_node_id = ? AND version = ?
		 ORDER BY route_token`,
		eventID, windowsNodeID, version)
	if err != nil {
		return nil, 0, fmt.Errorf("store: load mapping entries: %w", err)
	}
	defer rows.Close()
	entries := make(map[string]string)
	for rows.Next() {
		var token, target string
		if err := rows.Scan(&token, &target); err != nil {
			return nil, 0, fmt.Errorf("store: load mapping entries: %w", err)
		}
		entries[token] = target
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("store: load mapping entries: %w", err)
	}
	return entries, version, nil
}

var ledgerGenesisHash = strings.Repeat("0", 64)

// ledgerEntryHash computes the frozen hash-chain link:
// sha256(prev_hash | at | kind | subject | detail_sha256), hex encoded.
func ledgerEntryHash(prevHash string, at int64, kind, subject, detailSHA256 string) string {
	sum := sha256.Sum256([]byte(prevHash + "|" +
		strconv.FormatInt(at, 10) + "|" +
		kind + "|" + subject + "|" + detailSHA256))
	return hex.EncodeToString(sum[:])
}

// AppendLedger appends one hash-chained security-ledger entry and returns its
// entry hash. The entry is committed durably before the call returns; the
// genesis prev_hash is 64 zeros. Callers append in a well-defined causal order
// so the chain links each event to its predecessor.
func (s *Store) AppendLedger(ctx context.Context, at int64, kind, subject, detailSHA256 string) (string, error) {
	if strings.TrimSpace(kind) == "" {
		return "", invalidArgument("kind", "must not be empty")
	}
	if strings.TrimSpace(subject) == "" {
		return "", invalidArgument("subject", "must not be empty")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("store: begin ledger append: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	prevHash := ledgerGenesisHash
	err = tx.QueryRowContext(ctx,
		`SELECT entry_hash FROM security_ledger ORDER BY seq DESC LIMIT 1`).Scan(&prevHash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("store: read ledger head: %w", err)
	}
	entryHash := ledgerEntryHash(prevHash, at, kind, subject, detailSHA256)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO security_ledger(at, kind, subject, detail_sha256, prev_hash, entry_hash)
		 VALUES(?, ?, ?, ?, ?, ?)`,
		at, kind, subject, detailSHA256, prevHash, entryHash); err != nil {
		return "", fmt.Errorf("store: append ledger entry: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("store: commit ledger entry: %w", err)
	}
	return entryHash, nil
}

// VerifyChain recomputes the complete security-ledger hash chain and returns a
// typed *LedgerVerificationError (wrapping ErrLedgerTampered) at the first
// broken link.
func (s *Store) VerifyChain(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT seq, at, kind, subject, detail_sha256, prev_hash, entry_hash
		 FROM security_ledger ORDER BY seq ASC`)
	if err != nil {
		return fmt.Errorf("store: read security ledger: %w", err)
	}
	defer rows.Close()

	prevHash := ledgerGenesisHash
	var lastSeq int64
	for rows.Next() {
		var (
			seq        int64
			at         int64
			kind       string
			subject    string
			detailSHA  string
			prevStored string
			hashStored string
		)
		if err := rows.Scan(&seq, &at, &kind, &subject, &detailSHA, &prevStored, &hashStored); err != nil {
			return fmt.Errorf("store: read security ledger: %w", err)
		}
		if seq <= lastSeq {
			return &LedgerVerificationError{Seq: seq, Reason: "sequence not strictly increasing"}
		}
		if prevStored != prevHash {
			return &LedgerVerificationError{Seq: seq, Reason: "prev_hash does not match the previous entry"}
		}
		if want := ledgerEntryHash(prevHash, at, kind, subject, detailSHA); want != hashStored {
			return &LedgerVerificationError{Seq: seq, Reason: "entry_hash does not match the recomputed chain"}
		}
		prevHash = hashStored
		lastSeq = seq
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("store: read security ledger: %w", err)
	}
	return nil
}

// RunRetention applies the basic policy-B age sweep and returns the number of
// deleted rows per table. Windows are measured from now (epoch seconds):
//
//   - nonce_dedupe: 24 h (replay window);
//   - report_dedupe: 8 days (7-day spool plus margin);
//   - report_activity: 30 days.
//
// seq_dedupe is deliberately not pruned in B1: its frozen bound is "the current
// generation, last 256 seq entries", which is enforced when reading the history
// (SeqFingerprintHistoryLimit) rather than by deletion, so exact-retry
// classification cannot be lost by an age sweep. The bounded boot_registry
// compaction is likewise left to a later policy migration. Both are the
// documented B1 skeleton simplification.
func (s *Store) RunRetention(ctx context.Context, now int64) (map[string]int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin retention: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	deleted := make(map[string]int64, 3)
	sweep := func(table, deleteSQL string, cutoff int64) error {
		result, err := tx.ExecContext(ctx, deleteSQL, cutoff)
		if err != nil {
			return fmt.Errorf("store: retention delete %s: %w", table, err)
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("store: retention delete %s: %w", table, err)
		}
		deleted[table] = rows
		return nil
	}
	if err := sweep("nonce_dedupe",
		`DELETE FROM nonce_dedupe WHERE received_at < ?`, now-retentionNonceWindow); err != nil {
		return nil, err
	}
	if err := sweep("report_dedupe",
		`DELETE FROM report_dedupe WHERE last_received_at IS NOT NULL AND last_received_at < ?`,
		now-retentionReportWindow); err != nil {
		return nil, err
	}
	if err := sweep("report_activity",
		`DELETE FROM report_activity WHERE received_at IS NOT NULL AND received_at < ?`,
		now-retentionActivityWindow); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit retention: %w", err)
	}
	return deleted, nil
}

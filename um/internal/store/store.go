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

// execQuerier is the read/write subset shared by *sql.DB and *sql.Tx.
type execQuerier interface {
	rowQuerier
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// Tx exposes the B2-safe operations that must run inside an existing SQLite
// transaction. It deliberately wraps *sql.Tx and does not expose the raw handle:
// callers cannot open a nested transaction, issue arbitrary SQL or bypass the
// bounded/validated operations. Methods never start their own transaction and
// must only be used with the transaction from WithTx/ApplyTransport.
type Tx struct {
	tx *sql.Tx
}

// WithTx runs fn inside one SQLite transaction. On any error the transaction is
// rolled back; on success it is committed only after fn returns nil. This is the
// B2 entry point for combining nonce/report/seq/boot decisions with payload
// writes atomically.
func (s *Store) WithTx(ctx context.Context, fn func(*Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if err := fn(&Tx{tx: tx}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit transaction: %w", err)
	}
	committed = true
	return nil
}

// CheckOrInsertNonce classifies a nonce inside the caller's transaction.
func (t *Tx) CheckOrInsertNonce(ctx context.Context, nodeID, nonce, fingerprint string, at int64) (NonceStatus, error) {
	return checkOrInsertNonce(ctx, t.tx, nodeID, nonce, fingerprint, at)
}

// CheckOrInsertReport classifies a report_id inside the caller's transaction.
func (t *Tx) CheckOrInsertReport(ctx context.Context, nodeID, reportID, bodySHA256 string, at int64) (ReportStatus, error) {
	return checkOrInsertReport(ctx, t.tx, nodeID, reportID, bodySHA256, at)
}

// SeqLookup reads the exact-retry fingerprint inside the caller's transaction.
func (t *Tx) SeqLookup(ctx context.Context, nodeID string, gen uint64, bootID string, seq uint64) (string, bool, error) {
	return seqLookup(ctx, t.tx, nodeID, gen, bootID, seq)
}

// RecordSeq records one exact-retry fingerprint inside the caller's transaction.
func (t *Tx) RecordSeq(ctx context.Context, nodeID string, gen uint64, bootID string, seq uint64, fingerprint string, at int64) error {
	return recordSeq(ctx, t.tx, nodeID, gen, bootID, seq, fingerprint, at)
}

// LoadBoot reads the authoritative high-water inside the caller's transaction.
func (t *Tx) LoadBoot(ctx context.Context, nodeID string) (protocol.Boot, bool, error) {
	return loadBoot(ctx, t.tx, nodeID)
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

// putBoot is a test/development seeding helper. It is intentionally unexported:
// B2 ingest and operator code must not be able to lower or arbitrarily rewrite
// the authoritative high-water through a public Store method. Production code
// advances state only inside ApplyTransport.
func (s *Store) putBoot(ctx context.Context, nodeID string, gen uint64, bootID string, seq uint64, fingerprint string) error {
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
		return fmt.Errorf("store: seed boot state: %w", err)
	}
	return nil
}

// NonceStatus is the replay classification for one (node, nonce) pair.
type NonceStatus string

const (
	// NonceNew means the nonce was absent and has now been recorded.
	NonceNew NonceStatus = "new"
	// NonceExactRetry means the nonce exists with the exact same request
	// fingerprint; the caller may answer as an idempotent duplicate.
	NonceExactRetry NonceStatus = "exact_retry"
	// NonceReuse means the nonce exists with a different fingerprint; the
	// caller must answer 409 nonce_reuse and must not process the request.
	NonceReuse NonceStatus = "nonce_reuse"
)

// checkOrInsertNonce classifies and, when new, records a nonce inside the given
// transaction/connection. It never overwrites an existing fingerprint.
func checkOrInsertNonce(ctx context.Context, q execQuerier, nodeID, nonce, fingerprint string, at int64) (NonceStatus, error) {
	if strings.TrimSpace(nodeID) == "" {
		return "", invalidArgument("node_id", "must not be empty")
	}
	if strings.TrimSpace(nonce) == "" {
		return "", invalidArgument("nonce", "must not be empty")
	}
	if strings.TrimSpace(fingerprint) == "" {
		return "", invalidArgument("fingerprint", "must not be empty")
	}
	result, err := q.ExecContext(ctx,
		`INSERT INTO nonce_dedupe(node_id, nonce, fingerprint, received_at)
		 VALUES(?, ?, ?, ?)
		 ON CONFLICT(node_id, nonce) DO NOTHING`,
		nodeID, nonce, fingerprint, at)
	if err != nil {
		return "", fmt.Errorf("store: insert nonce: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return "", fmt.Errorf("store: insert nonce: %w", err)
	}
	if affected == 1 {
		return NonceNew, nil
	}
	var stored string
	if err := q.QueryRowContext(ctx,
		`SELECT fingerprint FROM nonce_dedupe WHERE node_id = ? AND nonce = ?`,
		nodeID, nonce).Scan(&stored); err != nil {
		return "", fmt.Errorf("store: read existing nonce: %w", err)
	}
	if stored == fingerprint {
		return NonceExactRetry, nil
	}
	return NonceReuse, nil
}

// NonceSeen reports whether a (node, nonce) pair is present.
func (s *Store) NonceSeen(ctx context.Context, nodeID, nonce string) (bool, error) {
	fingerprint, ok, err := s.NonceFingerprint(ctx, nodeID, nonce)
	if err != nil {
		return false, err
	}
	_ = fingerprint
	return ok, nil
}

// NonceFingerprint returns the request fingerprint stored with a nonce, if the
// pair is present. Callers use it for diagnostics; replay classification must
// use CheckOrInsertNonce/Tx.CheckOrInsertNonce so insert+classify is atomic.
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

// ReportStatus is the report_id idempotency classification.
type ReportStatus string

const (
	ReportNew       ReportStatus = "new"
	ReportDuplicate ReportStatus = "duplicate"
	ReportConflict  ReportStatus = "conflict"
)

// checkOrInsertReport classifies and records a report_id. A same-body retry may
// refresh last_received_at and is a duplicate; a different-body reuse is a
// conflict and MUST NOT update any stored timestamp.
func checkOrInsertReport(ctx context.Context, q execQuerier, nodeID, reportID, bodySHA256 string, at int64) (ReportStatus, error) {
	if strings.TrimSpace(nodeID) == "" {
		return "", invalidArgument("node_id", "must not be empty")
	}
	if strings.TrimSpace(reportID) == "" {
		return "", invalidArgument("report_id", "must not be empty")
	}
	var stored string
	err := q.QueryRowContext(ctx,
		`SELECT body_sha256 FROM report_dedupe WHERE node_id = ? AND report_id = ?`,
		nodeID, reportID).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := q.ExecContext(ctx,
			`INSERT INTO report_dedupe(node_id, report_id, body_sha256, first_received_at, last_received_at)
			 VALUES(?, ?, ?, ?, ?)`,
			nodeID, reportID, bodySHA256, at, at); err != nil {
			return "", fmt.Errorf("store: insert report dedupe: %w", err)
		}
		return ReportNew, nil
	}
	if err != nil {
		return "", fmt.Errorf("store: read report dedupe: %w", err)
	}
	if stored != bodySHA256 {
		return ReportConflict, nil
	}
	if _, err := q.ExecContext(ctx,
		`UPDATE report_dedupe SET last_received_at = ?
		 WHERE node_id = ? AND report_id = ? AND (last_received_at IS NULL OR last_received_at < ?)`,
		at, nodeID, reportID, at); err != nil {
		return "", fmt.Errorf("store: refresh report dedupe: %w", err)
	}
	return ReportDuplicate, nil
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
	return seqLookup(ctx, s.db, nodeID, gen, bootID, seq)
}

func seqLookup(ctx context.Context, q rowQuerier, nodeID string, gen uint64, bootID string, seq uint64) (string, bool, error) {
	genValue, err := numericToInt64("gen", gen)
	if err != nil {
		return "", false, err
	}
	seqValue, err := numericToInt64("seq", seq)
	if err != nil {
		return "", false, err
	}
	var fingerprint string
	err = q.QueryRowContext(ctx,
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

// recordSeq records the exact-retry fingerprint for one accepted attempt. It is
// insert-only: an existing row is never overwritten; a conflicting fingerprint
// is ErrConflict (the caller's transport decision must have rejected it first).
func recordSeq(ctx context.Context, q execQuerier, nodeID string, gen uint64, bootID string, seq uint64, fingerprint string, at int64) error {
	if strings.TrimSpace(nodeID) == "" {
		return invalidArgument("node_id", "must not be empty")
	}
	if strings.TrimSpace(bootID) == "" {
		return invalidArgument("boot_id", "must not be empty")
	}
	if strings.TrimSpace(fingerprint) == "" {
		return invalidArgument("fingerprint", "must not be empty")
	}
	genValue, err := numericToInt64("gen", gen)
	if err != nil {
		return err
	}
	seqValue, err := numericToInt64("seq", seq)
	if err != nil {
		return err
	}
	result, err := q.ExecContext(ctx,
		`INSERT INTO seq_dedupe(node_id, boot_gen, boot_id, seq, fingerprint, received_at)
		 VALUES(?, ?, ?, ?, ?, ?)
		 ON CONFLICT(node_id, boot_gen, boot_id, seq) DO NOTHING`,
		nodeID, genValue, bootID, seqValue, fingerprint, at)
	if err != nil {
		return fmt.Errorf("store: record seq dedupe: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: record seq dedupe: %w", err)
	}
	if affected == 1 {
		return nil
	}
	stored, ok, err := seqLookup(ctx, q, nodeID, gen, bootID, seq)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("store: seq dedupe row vanished during insert")
	}
	if stored != fingerprint {
		return fmt.Errorf("%w: seq %d for node %q already has a different fingerprint", ErrConflict, seq, nodeID)
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
//   - Accepted: node_boot, boot_registry and seq_dedupe are updated (insert-only
//     for seq dedupe) and only then is apply(*Tx) invoked. The callback receives
//     the B2-safe transaction wrapper; it must perform all reads/writes through
//     that wrapper and must NOT call public Store methods (they would open a new
//     transaction and contend with the single SQLite writer). If the callback
//     returns an error the transaction is rolled back, so a failed payload can
//     never advance the high-water.
//   - Duplicate: the attempt was already committed by the winning request. No
//     high-water change and no apply callback is invoked in B1; the Result
//     carries the ACK next_seq. B2 may extend duplicate-payload handling inside
//     the same transaction when it implements ingest.
//   - Any other outcome: rejected with a typed *TransportConflictError and no
//     write.
//
// On every error path the returned Result is the zero value. Callers must not
// treat a non-nil error as a committed success and must not emit an ACK unless
// the error is nil and the outcome is Accepted/Duplicate.
//
// attempt.Fingerprint is the canonical request fingerprint; the fingerprint
// parameter is a fallback so callers may pass it separately without duplicating
// it in Attempt.
func (s *Store) ApplyTransport(ctx context.Context, nodeID string, attempt protocol.Attempt, fingerprint string, apply func(*Tx) error) (protocol.Result, error) {
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
			return protocol.Result{}, fmt.Errorf("store: advance boot high-water: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO boot_registry(node_id, boot_gen, boot_id, first_seen_at, last_seen_at, last_seq, state)
			 VALUES(?, ?, ?, ?, ?, ?, 'active')
			 ON CONFLICT(node_id, boot_gen, boot_id) DO UPDATE SET
			   last_seen_at = excluded.last_seen_at,
			   last_seq = excluded.last_seq,
			   state = 'active'`,
			nodeID, genValue, a.BootID, now, now, seqValue); err != nil {
			return protocol.Result{}, fmt.Errorf("store: record boot registry: %w", err)
		}
		if err := recordSeq(ctx, tx, nodeID, a.Gen, a.BootID, a.Seq, a.Fingerprint, now); err != nil {
			return protocol.Result{}, err
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE nodes SET last_seen_at = ? WHERE node_id = ?`, now, nodeID); err != nil {
			return protocol.Result{}, fmt.Errorf("store: update node last seen: %w", err)
		}
		if apply != nil {
			if err := apply(&Tx{tx: tx}); err != nil {
				// Deferred rollback reverts the high-water writes above. Return
				// a zero Result: no caller may mistake this for a committed
				// success or emit an ACK.
				return protocol.Result{}, fmt.Errorf("store: apply transport payload: %w", err)
			}
		}
		if err := tx.Commit(); err != nil {
			return protocol.Result{}, fmt.Errorf("store: commit transport transaction: %w", err)
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

// CreateMappingVersion appends one immutable, effective-dated version of the
// Windows-terminal route mapping for an event.
//
// Validation (all inside one transaction, before any write):
//   - windows_node_id exists, has node_class=windows_terminal and belongs to
//     event_id;
//   - every target exists, has node_class=linux_vps and belongs to event_id;
//   - route tokens are exactly the four A/B protocol tokens
//     (a_reality/a_hy2/b_reality/b_hy2). direct/unknown are reserved display
//     tokens and can never be mapped to a VPS;
//   - version is strictly the next version (first version must be 1) and
//     effective_from is strictly later than the latest version's effective_from.
//     A backdated or same-time insert is rejected, preserving all previously
//     attributed history;
//   - a new version may be effective immediately (effective_from == write-time
//     now) or in the future; effective_from must never be in the past. This is
//     the normal mapping API rule: otherwise a later-than-previous but still
//     past effective time could retroactively change the attribution of data
//     already collected. A historical-import/admin path, if ever needed, is a
//     separate B2/B4 feature with its own audit.
//   - future-effective versions become effective only when ResolveMapping is
//     asked for a time at/after effective_from.
//
// An empty entries map is valid and means "all four tokens are unmapped" from
// effective_from (the UI renders them as unmapped/UNKNOWN; the previous version
// remains the historical attribution before that time). Versions and entries are
// immutable: SQL triggers reject UPDATE/DELETE.
func (s *Store) CreateMappingVersion(ctx context.Context, eventID, windowsNodeID string, version int, effectiveFrom int64, createdBy string, entries map[string]string) error {
	return s.createMappingVersion(ctx, eventID, windowsNodeID, version, effectiveFrom, createdBy, entries, nowUnix())
}

// createMappingVersion is CreateMappingVersion with an explicit write-time clock,
// used by deterministic tests.
func (s *Store) createMappingVersion(ctx context.Context, eventID, windowsNodeID string, version int, effectiveFrom int64, createdBy string, entries map[string]string, now int64) error {
	if strings.TrimSpace(eventID) == "" {
		return invalidArgument("event_id", "must not be empty")
	}
	if strings.TrimSpace(windowsNodeID) == "" {
		return invalidArgument("windows_node_id", "must not be empty")
	}
	if version < 1 {
		return invalidArgument("version", "must be a positive integer")
	}
	for token, target := range entries {
		if _, ok := allowedRouteTokens[token]; !ok {
			return invalidArgument("route_token", "must be one of the four A/B protocol tokens; direct/unknown are reserved")
		}
		if strings.TrimSpace(target) == "" {
			return invalidArgument("target_node_id", "must not be empty")
		}
	}

	if effectiveFrom < now {
		return invalidArgument("effective_from", "must be now or later; a past effective time would retroactively change already-attributed history")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin mapping version: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// A mapping write is a normal event mutation: it must obey the same durable
	// purge/graveyard/archive lifecycle gate as ingest/enrollment/config writes.
	if _, err := (&Tx{tx: tx}).EventActiveTx(ctx, eventID); err != nil {
		return err
	}

	// The window node must be a real windows_terminal node of this event.
	var winClass, winEvent string
	err = tx.QueryRowContext(ctx,
		`SELECT node_class, event_id FROM nodes WHERE node_id = ?`, windowsNodeID).
		Scan(&winClass, &winEvent)
	if errors.Is(err, sql.ErrNoRows) {
		return invalidArgument("windows_node_id", "windows node does not exist")
	}
	if err != nil {
		return fmt.Errorf("store: read windows node: %w", err)
	}
	if winClass != NodeClassWindowsTerminal {
		return invalidArgument("windows_node_id", "node class must be windows_terminal")
	}
	if winEvent != eventID {
		return invalidArgument("windows_node_id", "windows node belongs to a different event")
	}

	// Enforce the append-only version/effective-time ordering.
	var latestVersion int
	var latestEffective int64
	err = tx.QueryRowContext(ctx,
		`SELECT version, effective_from FROM route_mapping_versions
		 WHERE event_id = ? AND windows_node_id = ?
		 ORDER BY version DESC LIMIT 1`,
		eventID, windowsNodeID).Scan(&latestVersion, &latestEffective)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if version != 1 {
			return invalidArgument("version", "first mapping version must be 1")
		}
	case err != nil:
		return fmt.Errorf("store: read latest mapping version: %w", err)
	default:
		if version != latestVersion+1 {
			return invalidArgument("version", fmt.Sprintf("next mapping version must be %d", latestVersion+1))
		}
		if effectiveFrom <= latestEffective {
			return invalidArgument("effective_from", "must be strictly later than the latest version; backdated or same-time versions are rejected")
		}
	}

	// Validate every target inside the same transaction.
	for token, target := range entries {
		var targetClass, targetEvent string
		err := tx.QueryRowContext(ctx,
			`SELECT node_class, event_id FROM nodes WHERE node_id = ?`, target).
			Scan(&targetClass, &targetEvent)
		if errors.Is(err, sql.ErrNoRows) {
			return invalidArgument("target_node_id", fmt.Sprintf("target for route %q does not exist", token))
		}
		if err != nil {
			return fmt.Errorf("store: read mapping target: %w", err)
		}
		if targetClass != NodeClassLinuxVPS {
			return invalidArgument("target_node_id", fmt.Sprintf("target for route %q must be a linux_vps node", token))
		}
		if targetEvent != eventID {
			return invalidArgument("target_node_id", fmt.Sprintf("target for route %q belongs to a different event", token))
		}
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO route_mapping_versions(event_id, windows_node_id, version, effective_from, created_by, created_at)
		 VALUES(?, ?, ?, ?, ?, ?)`,
		eventID, windowsNodeID, version, effectiveFrom, createdBy, nowUnix()); err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: route mapping version %d or effective time already exists", ErrAlreadyExists, version)
		}
		return fmt.Errorf("store: insert mapping version: %w", err)
	}
	// Deterministic insertion order keeps concurrent writers' error handling
	// simple; the primary key makes duplicate tokens impossible.
	tokens := make([]string, 0, len(entries))
	for token := range entries {
		tokens = append(tokens, token)
	}
	sort.Strings(tokens)
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
//
// This is a BASIC tamper-evident structure only. It is not a signed checkpoint,
// has no offsite/recovery guarantee and cannot detect or prevent truncation of
// the chain tail. The ledger must not be represented as having those properties
// until a separate reviewed design adds them.
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
// broken link. It is a diagnostic/integrity check ONLY; it must never be used
// as authorization to recover, restore or re-enable a node. A chain that is
// internally consistent can still have been truncated at the tail.
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
// documented B1 skeleton simplification; physical pruning and the full policy-B
// archive engine are UM-B2 responsibilities and must include a capacity
// upper-bound validation before the center is put into operation.
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

// Package store implements the rev-5 UM center SQLite data layer: schema
// migrations, the transactional transport high-water, replay/dedupe state,
// versioned route mappings, a hash-chained security ledger and the basic
// policy-B retention sweep.
//
// Durability and ordering follow the frozen contract in
// docs/um/um-a/04-node-protocol-v1.md:
//
//   - WAL journaling and synchronous=FULL: a report is only acknowledged after
//     the data, dedupe and boot/seq high-water commit durably.
//   - All protocol numeric state (boot generation / sequence) is stored as a
//     signed SQLite INTEGER bounded by wire.MaxNumeric (2^63-2); it is never
//     stored as TEXT, BLOB or REAL.
//   - Open applies the versioned migrations in order and is idempotent, so a
//     restart re-opens the same state without re-running a migration.
//
// The package intentionally keeps policy decisions (HTTP status mapping,
// signature/identity checks) out of the store; callers map the typed errors
// returned here onto the wire error table.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the pure-Go "sqlite" database/sql driver
)

// SchemaVersion is the highest migration version this build knows. Open always
// migrates a database to exactly this version.
const SchemaVersion = 1

// Node classes accepted by the rev-5 platform isolation contract.
const (
	NodeClassLinuxVPS        = "linux_vps"
	NodeClassWindowsTerminal = "windows_terminal"
)

// Store owns one SQLite database handle. It is safe for concurrent use; Open
// pins the connection pool to a single connection so that the
// connection-scoped PRAGMAs (synchronous, foreign_keys, busy_timeout) apply to
// every statement and to transactions.
type Store struct {
	db   *sql.DB
	path string
}

// DB returns the underlying database handle. It is intended for integration
// code that needs raw read-only SQL; mutating shortcuts bypass the typed API
// and the transaction rules documented on the methods.
func (s *Store) DB() *sql.DB { return s.db }

// Path returns the filesystem path of the database.
func (s *Store) Path() string { return s.path }

type migration struct {
	version    int
	statements []string
}

// migrations is append-only: never edit an applied migration, add a new version
// instead. Version 1 is the rev-5 base schema.
var migrations = []migration{
	{version: 1, statements: []string{
		// Node trust anchors. node_class is frozen: a Windows terminal can never
		// be upgraded to a Linux VPS identity or vice versa.
		`CREATE TABLE IF NOT EXISTS nodes (
			node_id     TEXT PRIMARY KEY,
			event_id    TEXT NOT NULL,
			node_class  TEXT NOT NULL CHECK (node_class IN ('linux_vps','windows_terminal')),
			state       TEXT NOT NULL,
			created_at  INTEGER NOT NULL,
			last_seen_at INTEGER
		)`,
		// Ed25519 identity keys per node. Only public keys are stored; the
		// private key never leaves the node.
		`CREATE TABLE IF NOT EXISTS node_keys (
			key_id      TEXT PRIMARY KEY,
			node_id     TEXT NOT NULL REFERENCES nodes(node_id),
			public_key  TEXT NOT NULL,
			state       TEXT NOT NULL,
			created_at  INTEGER,
			activated_at INTEGER,
			revoked_at  INTEGER
		)`,
		// Persisted rotation intent, keyed by (node, nonce). The new key becomes
		// active only after the node proves possession of it.
		`CREATE TABLE IF NOT EXISTS key_rotations (
			node_id     TEXT NOT NULL,
			old_key_id  TEXT NOT NULL,
			new_key_id  TEXT NOT NULL,
			nonce       TEXT NOT NULL,
			body_sha256 TEXT NOT NULL,
			state       TEXT NOT NULL,
			expires_at  INTEGER,
			created_at  INTEGER,
			PRIMARY KEY (node_id, nonce)
		)`,
		// Single-use enrollment bootstrap tokens; only the token hash is stored.
		`CREATE TABLE IF NOT EXISTS enroll_tokens (
			token_hash  TEXT PRIMARY KEY,
			event_id    TEXT,
			node_class  TEXT,
			expires_at  INTEGER,
			used_at     INTEGER
		)`,
		// Authoritative transport high-water per node. Acceptance consults only
		// this row; the bounded boot_registry below is diagnostics-only.
		`CREATE TABLE IF NOT EXISTS node_boot (
			node_id          TEXT PRIMARY KEY REFERENCES nodes(node_id),
			highest_gen      INTEGER NOT NULL CHECK (highest_gen BETWEEN 1 AND 9223372036854775806),
			boot_id          TEXT NOT NULL,
			last_seq         INTEGER NOT NULL CHECK (last_seq BETWEEN 1 AND 9223372036854775806),
			last_fingerprint TEXT,
			updated_at       INTEGER NOT NULL
		)`,
		// Exact-retry classification for (node, boot generation, boot id, seq).
		// Only request fingerprints are stored, never bodies.
		`CREATE TABLE IF NOT EXISTS seq_dedupe (
			node_id     TEXT NOT NULL,
			boot_gen    INTEGER NOT NULL,
			boot_id     TEXT NOT NULL,
			seq         INTEGER NOT NULL,
			fingerprint TEXT NOT NULL,
			received_at INTEGER NOT NULL,
			PRIMARY KEY (node_id, boot_gen, boot_id, seq)
		)`,
		// Unique (node, nonce) replay protection with the full request
		// fingerprint; a nonce maps to exactly one request fingerprint.
		`CREATE TABLE IF NOT EXISTS nonce_dedupe (
			node_id     TEXT NOT NULL,
			nonce       TEXT NOT NULL,
			fingerprint TEXT NOT NULL,
			received_at INTEGER NOT NULL,
			PRIMARY KEY (node_id, nonce)
		)`,
		// report_id idempotency across retries/restarts; the body hash detects a
		// reused report_id with different content (report_conflict).
		`CREATE TABLE IF NOT EXISTS report_dedupe (
			node_id           TEXT NOT NULL,
			report_id         TEXT NOT NULL,
			body_sha256       TEXT NOT NULL,
			first_received_at INTEGER,
			last_received_at  INTEGER,
			PRIMARY KEY (node_id, report_id)
		)`,
		// Diagnostics history of boot generations. Never an authorization
		// source; retirement is enforced by node_boot.highest_gen.
		`CREATE TABLE IF NOT EXISTS boot_registry (
			node_id       TEXT NOT NULL,
			boot_gen      INTEGER NOT NULL,
			boot_id       TEXT NOT NULL,
			first_seen_at INTEGER,
			last_seen_at  INTEGER,
			last_seq      INTEGER,
			state         TEXT,
			PRIMARY KEY (node_id, boot_gen, boot_id)
		)`,
		// Append-only versioned route mappings. A version is immutable once
		// written; a change is a new version with a later effective_from.
		`CREATE TABLE IF NOT EXISTS route_mapping_versions (
			event_id        TEXT NOT NULL,
			windows_node_id TEXT NOT NULL,
			version         INTEGER NOT NULL,
			effective_from  INTEGER NOT NULL,
			created_by      TEXT,
			created_at      INTEGER,
			PRIMARY KEY (event_id, windows_node_id, version)
		)`,
		`CREATE TABLE IF NOT EXISTS route_mapping_entries (
			event_id        TEXT NOT NULL,
			windows_node_id TEXT NOT NULL,
			version         INTEGER NOT NULL,
			route_token     TEXT NOT NULL CHECK (route_token IN ('a_reality','a_hy2','b_reality','b_hy2','direct')),
			target_node_id  TEXT NOT NULL REFERENCES nodes(node_id),
			PRIMARY KEY (event_id, windows_node_id, version, route_token)
		)`,
		// Hash-chained security ledger. seq is autoincrement and gap-tolerant
		// (rolled-back appends never persist); every entry commits in its own
		// transaction before the caller treats the event as recorded.
		`CREATE TABLE IF NOT EXISTS security_ledger (
			seq          INTEGER PRIMARY KEY AUTOINCREMENT,
			at           INTEGER NOT NULL,
			kind         TEXT NOT NULL,
			subject      TEXT NOT NULL,
			detail_sha256 TEXT NOT NULL,
			prev_hash    TEXT NOT NULL,
			entry_hash   TEXT NOT NULL
		)`,
		// Activity rows used by the 30-day retention sweep. report_dedupe is the
		// idempotency table; report_activity records last observed activity.
		`CREATE TABLE IF NOT EXISTS report_activity (
			node_id      TEXT NOT NULL,
			report_id    TEXT NOT NULL,
			collected_at INTEGER,
			received_at  INTEGER,
			PRIMARY KEY (node_id, report_id)
		)`,
		// Retention-sweep indexes. They are not part of any protocol decision,
		// only bounded deletion by age.
		`CREATE INDEX IF NOT EXISTS idx_nonce_dedupe_received_at ON nonce_dedupe(received_at)`,
		`CREATE INDEX IF NOT EXISTS idx_report_dedupe_last_received_at ON report_dedupe(last_received_at)`,
		`CREATE INDEX IF NOT EXISTS idx_report_activity_received_at ON report_activity(received_at)`,
		// Mapping resolution is "latest version with effective_from <= at"; the
		// index covers the lookup and the deterministic tie-break on version.
		`CREATE INDEX IF NOT EXISTS idx_route_mapping_versions_lookup
			ON route_mapping_versions(event_id, windows_node_id, effective_from DESC, version DESC)`,
	}},
}

// Open creates the parent directory if needed, opens the SQLite database,
// applies the durability PRAGMAs and migrates the schema to SchemaVersion.
// Calling Open again on the same path is idempotent.
func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, &InvalidArgumentError{Field: "path", Detail: "must not be empty"}
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("store: create database directory: %w", err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: open sqlite database: %w", err)
	}
	// PRAGMAs other than journal_mode are connection-scoped, so the pool is
	// pinned to one connection. This also serializes writers on a single Store.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	s := &Store{db: db, path: path}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.configureConnection(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.applyMigrations(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// configureConnection applies the frozen durability/isolation PRAGMAs. The
// journal mode is persistent in the database file; the other settings are
// connection-scoped, which is why the pool holds a single connection.
func (s *Store) configureConnection(ctx context.Context) error {
	pragmas := []string{
		// busy_timeout first so later pragmas can wait for a lock.
		`PRAGMA busy_timeout=5000`,
		`PRAGMA foreign_keys=ON`,
		`PRAGMA synchronous=FULL`,
		`PRAGMA journal_mode=WAL`,
	}
	for _, stmt := range pragmas {
		// database/sql's Exec handles the row-returning forms (journal_mode)
		// and the plain assignment forms (foreign_keys) uniformly: the driver
		// steps every statement exactly once.
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("store: apply %q: %w", stmt, err)
		}
	}
	return nil
}

// SchemaVersion reports the highest applied migration version. A database that
// has never been migrated reports version 0.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var version int
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&version)
	if err != nil {
		// Only reachable for a raw connection that bypassed Open; Open always
		// creates the table. Report "unmigrated" rather than an opaque error.
		if isNoSuchTable(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("store: read schema version: %w", err)
	}
	return version, nil
}

// Close closes the database handle. It is safe to call more than once.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("store: close database: %w", err)
	}
	return nil
}

// applyMigrations creates the migrations bookkeeping table and applies every
// known migration newer than the current version, one transaction each.
func (s *Store) applyMigrations(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at INTEGER NOT NULL
	)`); err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}
	current, err := s.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		if err := s.applyMigration(ctx, m); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) applyMigration(ctx context.Context, m migration) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin migration %d: %w", m.version, err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, stmt := range m.statements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("store: migration %d: %w", m.version, err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)`,
		m.version, time.Now().Unix()); err != nil {
		return fmt.Errorf("store: record migration %d: %w", m.version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit migration %d: %w", m.version, err)
	}
	return nil
}

func isNoSuchTable(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no such table")
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the pure-Go "sqlite" database/sql driver
)

// SchemaVersion is the highest migration version this build knows. Open always
// migrates a database to exactly this version; a database with a newer version
// is rejected fail-closed instead of being silently used by older code.
const SchemaVersion = 8

// Node classes accepted by the rev-5 platform isolation contract.
const (
	NodeClassLinuxVPS        = "linux_vps"
	NodeClassWindowsTerminal = "windows_terminal"
)

// Store owns one SQLite database handle. It is safe for concurrent use. The
// per-connection PRAGMAs are applied through the driver DSN (see Open) rather
// than by assuming a single physical connection lives forever; Open verifies the
// actual PRAGMA values and every new pooled connection is initialised by the
// driver with the same DSN pragmas.
type Store struct {
	db   *sql.DB
	path string
	// retentionHook is a test-only fault injection point for bounded retention.
	retentionHook func(string) error
	// ingestHook is a test-only fault injection point inside the authenticated
	// ingest transaction (after high-water/dedupe writes, before commit).
	ingestHook func(string) error
	// overlapBudgetOverride is a test-only active-only planning basis override.
	overlapBudgetOverride int64
}

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
	{version: 2, statements: []string{
		// P1-01: rebuild the three protocol high-water tables with STRICT
		// typing and explicit typeof/range checks. Version 1 stays untouched
		// (append-only migrations); a v1 development database is upgraded by
		// copying its rows into the strict tables. If legacy rows violate the
		// strict bounds the migration fails closed rather than losing or
		// silently reinterpreting data.
		`CREATE TABLE node_boot_v2 (
			node_id          TEXT PRIMARY KEY REFERENCES nodes(node_id),
			highest_gen      INTEGER NOT NULL CHECK (typeof(highest_gen) = 'integer' AND highest_gen BETWEEN 1 AND 9223372036854775806),
			boot_id          TEXT NOT NULL,
			last_seq         INTEGER NOT NULL CHECK (typeof(last_seq) = 'integer' AND last_seq BETWEEN 1 AND 9223372036854775806),
			last_fingerprint TEXT,
			updated_at       INTEGER NOT NULL CHECK (typeof(updated_at) = 'integer')
		) STRICT`,
		`INSERT INTO node_boot_v2(node_id, highest_gen, boot_id, last_seq, last_fingerprint, updated_at)
		 SELECT node_id, highest_gen, boot_id, last_seq, last_fingerprint, updated_at FROM node_boot`,
		`DROP TABLE node_boot`,
		`ALTER TABLE node_boot_v2 RENAME TO node_boot`,

		`CREATE TABLE seq_dedupe_v2 (
			node_id     TEXT NOT NULL,
			boot_gen    INTEGER NOT NULL CHECK (typeof(boot_gen) = 'integer' AND boot_gen BETWEEN 1 AND 9223372036854775806),
			boot_id     TEXT NOT NULL,
			seq         INTEGER NOT NULL CHECK (typeof(seq) = 'integer' AND seq BETWEEN 1 AND 9223372036854775806),
			fingerprint TEXT NOT NULL,
			received_at INTEGER NOT NULL CHECK (typeof(received_at) = 'integer'),
			PRIMARY KEY (node_id, boot_gen, boot_id, seq)
		) STRICT`,
		`INSERT INTO seq_dedupe_v2(node_id, boot_gen, boot_id, seq, fingerprint, received_at)
		 SELECT node_id, boot_gen, boot_id, seq, fingerprint, received_at FROM seq_dedupe`,
		`DROP TABLE seq_dedupe`,
		`ALTER TABLE seq_dedupe_v2 RENAME TO seq_dedupe`,

		`CREATE TABLE boot_registry_v2 (
			node_id       TEXT NOT NULL,
			boot_gen      INTEGER NOT NULL CHECK (typeof(boot_gen) = 'integer' AND boot_gen BETWEEN 1 AND 9223372036854775806),
			boot_id       TEXT NOT NULL,
			first_seen_at INTEGER CHECK (first_seen_at IS NULL OR typeof(first_seen_at) = 'integer'),
			last_seen_at  INTEGER CHECK (last_seen_at IS NULL OR typeof(last_seen_at) = 'integer'),
			last_seq      INTEGER CHECK (last_seq IS NULL OR (typeof(last_seq) = 'integer' AND last_seq BETWEEN 1 AND 9223372036854775806)),
			state         TEXT,
			PRIMARY KEY (node_id, boot_gen, boot_id)
		) STRICT`,
		`INSERT INTO boot_registry_v2(node_id, boot_gen, boot_id, first_seen_at, last_seen_at, last_seq, state)
		 SELECT node_id, boot_gen, boot_id, first_seen_at, last_seen_at, last_seq, state FROM boot_registry`,
		`DROP TABLE boot_registry`,
		`ALTER TABLE boot_registry_v2 RENAME TO boot_registry`,

		// P1-02: strict mapping tables; only the four A/B protocol tokens may be
		// mapped. direct/unknown are reserved and never point at a VPS.
		`CREATE TABLE route_mapping_versions_v2 (
			event_id        TEXT NOT NULL,
			windows_node_id TEXT NOT NULL,
			version         INTEGER NOT NULL CHECK (typeof(version) = 'integer' AND version >= 1),
			effective_from  INTEGER NOT NULL CHECK (typeof(effective_from) = 'integer'),
			created_by      TEXT,
			created_at      INTEGER CHECK (created_at IS NULL OR typeof(created_at) = 'integer'),
			PRIMARY KEY (event_id, windows_node_id, version)
		) STRICT`,
		`INSERT INTO route_mapping_versions_v2(event_id, windows_node_id, version, effective_from, created_by, created_at)
		 SELECT event_id, windows_node_id, version, effective_from, created_by, created_at FROM route_mapping_versions`,
		`CREATE UNIQUE INDEX route_mapping_versions_effective_unique
			ON route_mapping_versions_v2(event_id, windows_node_id, effective_from)`,
		`DROP TABLE route_mapping_versions`,
		`ALTER TABLE route_mapping_versions_v2 RENAME TO route_mapping_versions`,

		`CREATE TABLE route_mapping_entries_v2 (
			event_id        TEXT NOT NULL,
			windows_node_id TEXT NOT NULL,
			version         INTEGER NOT NULL CHECK (typeof(version) = 'integer' AND version >= 1),
			route_token     TEXT NOT NULL CHECK (route_token IN ('a_reality','a_hy2','b_reality','b_hy2')),
			target_node_id  TEXT NOT NULL REFERENCES nodes(node_id),
			PRIMARY KEY (event_id, windows_node_id, version, route_token)
		) STRICT`,
		`INSERT INTO route_mapping_entries_v2(event_id, windows_node_id, version, route_token, target_node_id)
		 SELECT event_id, windows_node_id, version, route_token, target_node_id FROM route_mapping_entries`,
		`DROP TABLE route_mapping_entries`,
		`ALTER TABLE route_mapping_entries_v2 RENAME TO route_mapping_entries`,

		// Append-only history: reject UPDATE/DELETE through raw SQL as well as
		// through the typed API.
		`CREATE TRIGGER route_mapping_versions_no_update
			BEFORE UPDATE ON route_mapping_versions
			BEGIN SELECT RAISE(ABORT, 'route_mapping_versions are immutable'); END`,
		`CREATE TRIGGER route_mapping_versions_no_delete
			BEFORE DELETE ON route_mapping_versions
			BEGIN SELECT RAISE(ABORT, 'route_mapping_versions are immutable'); END`,
		`CREATE TRIGGER route_mapping_entries_no_update
			BEFORE UPDATE ON route_mapping_entries
			BEGIN SELECT RAISE(ABORT, 'route_mapping_entries are immutable'); END`,
		`CREATE TRIGGER route_mapping_entries_no_delete
			BEFORE DELETE ON route_mapping_entries
			BEGIN SELECT RAISE(ABORT, 'route_mapping_entries are immutable'); END`,

		`CREATE INDEX idx_route_mapping_versions_lookup
			ON route_mapping_versions(event_id, windows_node_id, effective_from DESC, version DESC)`,
	}},
	{version: 3, statements: []string{
		// P1-08 rotation persistence additions (B1 schema was minimal).
		`ALTER TABLE key_rotations ADD COLUMN new_public_key TEXT`,
		`ALTER TABLE key_rotations ADD COLUMN response_json TEXT`,
		`ALTER TABLE key_rotations ADD COLUMN confirmed_at INTEGER`,
		`ALTER TABLE enroll_tokens ADD COLUMN created_at INTEGER`,

		// Per-node center configuration. Defaults are fail-closed: no collection
		// source is enabled until an authorized admin/config path enables it.
		`CREATE TABLE IF NOT EXISTS node_configs (
			node_id       TEXT PRIMARY KEY REFERENCES nodes(node_id),
			event_id      TEXT NOT NULL,
			config_version INTEGER NOT NULL CHECK (typeof(config_version) = 'integer' AND config_version >= 1),
			cadence_seconds INTEGER NOT NULL CHECK (typeof(cadence_seconds) = 'integer' AND cadence_seconds BETWEEN 30 AND 300),
			sources_json  TEXT NOT NULL,
			expected_inbound_tags_json TEXT NOT NULL,
			device_salt   TEXT NOT NULL,
			updated_at    INTEGER NOT NULL CHECK (typeof(updated_at) = 'integer')
		) STRICT`,

		// Validated snapshot history. The payload is the exact decoded body after
		// schema/platform/privacy validation; it is never raw unvalidated input.
		`CREATE TABLE IF NOT EXISTS snapshots (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			node_id     TEXT NOT NULL REFERENCES nodes(node_id),
			event_id    TEXT NOT NULL,
			node_class  TEXT NOT NULL CHECK (node_class IN ('linux_vps','windows_terminal')),
			report_id   TEXT NOT NULL,
			collected_at INTEGER NOT NULL CHECK (typeof(collected_at) = 'integer'),
			received_at INTEGER NOT NULL CHECK (typeof(received_at) = 'integer'),
			body_sha256 TEXT NOT NULL,
			payload_json BLOB NOT NULL,
			UNIQUE(node_id, report_id)
		) STRICT`,
		`CREATE TABLE IF NOT EXISTS node_latest (
			node_id     TEXT PRIMARY KEY REFERENCES nodes(node_id),
			snapshot_id INTEGER NOT NULL REFERENCES snapshots(id),
			report_id   TEXT NOT NULL,
			event_id    TEXT NOT NULL,
			node_class  TEXT NOT NULL CHECK (node_class IN ('linux_vps','windows_terminal')),
			collected_at INTEGER NOT NULL CHECK (typeof(collected_at) = 'integer'),
			updated_at  INTEGER NOT NULL CHECK (typeof(updated_at) = 'integer')
		) STRICT`,

		`CREATE TABLE IF NOT EXISTS report_metrics (
			node_id     TEXT NOT NULL REFERENCES nodes(node_id),
			event_id    TEXT NOT NULL,
			report_id   TEXT NOT NULL,
			collected_at INTEGER NOT NULL CHECK (typeof(collected_at) = 'integer'),
			received_at INTEGER NOT NULL CHECK (typeof(received_at) = 'integer'),
			body_sha256 TEXT NOT NULL,
			payload_json BLOB NOT NULL,
			PRIMARY KEY (node_id, report_id)
		) STRICT`,
		`CREATE TABLE IF NOT EXISTS report_events (
			report_row_id INTEGER PRIMARY KEY AUTOINCREMENT,
			node_id     TEXT NOT NULL REFERENCES nodes(node_id),
			event_id    TEXT NOT NULL,
			report_id   TEXT NOT NULL,
			collected_at INTEGER NOT NULL CHECK (typeof(collected_at) = 'integer'),
			received_at INTEGER NOT NULL CHECK (typeof(received_at) = 'integer'),
			event_id_json TEXT NOT NULL,
			event_at    INTEGER NOT NULL CHECK (typeof(event_at) = 'integer'),
			kind        TEXT NOT NULL,
			details_json TEXT NOT NULL,
			body_sha256 TEXT NOT NULL,
			payload_json BLOB NOT NULL,
			UNIQUE(node_id, report_id, event_id_json)
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS idx_report_events_node_collected ON report_events(node_id, collected_at)`,

		// Policy-B archive records (active 30d + archive 30d) and retention runs.
		`CREATE TABLE IF NOT EXISTS archive_records (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			record_type TEXT NOT NULL CHECK (record_type IN ('snapshot','metrics','events')),
			node_id     TEXT NOT NULL,
			event_id    TEXT NOT NULL,
			report_id   TEXT NOT NULL,
			collected_at INTEGER NOT NULL CHECK (typeof(collected_at) = 'integer'),
			archived_at INTEGER NOT NULL CHECK (typeof(archived_at) = 'integer'),
			payload_json BLOB NOT NULL,
			UNIQUE(record_type, node_id, report_id)
		) STRICT`,
		`CREATE TABLE IF NOT EXISTS retention_runs (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			ran_at      INTEGER NOT NULL,
			result_json TEXT NOT NULL
		) STRICT`,
	}},
	{version: 4, statements: []string{
		// Policy-B event lifecycle. The archived event's own telemetry rows stay
		// in their normal tables for the archive tail; there is no second copy and
		// no per-table LIMIT-1 archive bug. A catalog row survives data deletion
		// until an explicit purge tombstone is written.
		`ALTER TABLE nodes ADD COLUMN retired_at INTEGER`,
		`CREATE TABLE IF NOT EXISTS event_catalog (
			event_id       TEXT PRIMARY KEY,
			state          TEXT NOT NULL CHECK (state IN ('active','archived')),
			created_at     INTEGER NOT NULL CHECK (typeof(created_at) = 'integer'),
			archived_at    INTEGER CHECK (archived_at IS NULL OR typeof(archived_at) = 'integer'),
			purge_after    INTEGER CHECK (purge_after IS NULL OR typeof(purge_after) = 'integer'),
			data_purged_at INTEGER CHECK (data_purged_at IS NULL OR typeof(data_purged_at) = 'integer'),
			updated_at     INTEGER NOT NULL CHECK (typeof(updated_at) = 'integer')
		) STRICT`,
		`INSERT OR IGNORE INTO event_catalog(event_id,state,created_at,archived_at,purge_after,data_purged_at,updated_at)
		 SELECT event_id,'active',MIN(created_at),NULL,NULL,NULL,MAX(created_at) FROM nodes GROUP BY event_id`,
		`CREATE TABLE IF NOT EXISTS purge_tombstones (
			event_id    TEXT PRIMARY KEY,
			actor       TEXT NOT NULL,
			purged_at   INTEGER NOT NULL,
			counts_json TEXT NOT NULL,
			retain_until INTEGER NOT NULL
		) STRICT`,
		`CREATE TABLE IF NOT EXISTS retention_state (
			id            INTEGER PRIMARY KEY CHECK (id = 1),
			degraded      INTEGER NOT NULL DEFAULT 0,
			failure_count INTEGER NOT NULL DEFAULT 0,
			last_run_at   INTEGER,
			last_error    TEXT
		) STRICT`,
		`INSERT OR IGNORE INTO retention_state(id,degraded,failure_count,last_run_at,last_error) VALUES(1,0,0,NULL,NULL)`,
		`CREATE TABLE IF NOT EXISTS capacity_state (
			id      INTEGER PRIMARY KEY CHECK (id = 1),
			version INTEGER NOT NULL DEFAULT 0
		) STRICT`,
		`INSERT OR IGNORE INTO capacity_state(id,version) VALUES(1,0)`,
		// B2 no longer uses the old per-table archive copy; live event tables plus
		// event lifecycle are the single source of truth.
		`DROP TABLE IF EXISTS archive_records`,
	}},
	{version: 5, statements: []string{
		// P1 review: events must not duplicate the complete report body on every
		// event row. Store the validated events report once, and normalized event
		// rows with severity/details only.
		`CREATE TABLE IF NOT EXISTS report_event_reports (
			node_id     TEXT NOT NULL REFERENCES nodes(node_id),
			event_id    TEXT NOT NULL,
			report_id   TEXT NOT NULL,
			collected_at INTEGER NOT NULL CHECK (typeof(collected_at) = 'integer'),
			received_at INTEGER NOT NULL CHECK (typeof(received_at) = 'integer'),
			body_sha256 TEXT NOT NULL,
			payload_json BLOB NOT NULL,
			PRIMARY KEY (node_id, report_id)
		) STRICT`,
		`CREATE TABLE IF NOT EXISTS report_events_new (
			report_row_id INTEGER PRIMARY KEY AUTOINCREMENT,
			node_id     TEXT NOT NULL REFERENCES nodes(node_id),
			event_id    TEXT NOT NULL,
			report_id   TEXT NOT NULL,
			collected_at INTEGER NOT NULL CHECK (typeof(collected_at) = 'integer'),
			received_at INTEGER NOT NULL CHECK (typeof(received_at) = 'integer'),
			event_id_json TEXT NOT NULL,
			event_at    INTEGER NOT NULL CHECK (typeof(event_at) = 'integer'),
			kind        TEXT NOT NULL,
			severity    TEXT NOT NULL CHECK (severity IN ('info','warning','critical')),
			details_json TEXT NOT NULL,
			UNIQUE(node_id, report_id, event_id_json)
		) STRICT`,
		`INSERT OR IGNORE INTO report_event_reports(node_id,event_id,report_id,collected_at,received_at,body_sha256,payload_json)
		 SELECT node_id,event_id,report_id,MIN(collected_at),MAX(received_at),body_sha256,payload_json
		 FROM report_events GROUP BY node_id,event_id,report_id,body_sha256`,
		`INSERT OR IGNORE INTO report_events_new(node_id,event_id,report_id,collected_at,received_at,event_id_json,event_at,kind,severity,details_json)
		 SELECT node_id,event_id,report_id,collected_at,received_at,event_id_json,event_at,kind,'info',details_json
		 FROM report_events`,
		`DROP TABLE report_events`,
		`ALTER TABLE report_events_new RENAME TO report_events`,
		`CREATE INDEX IF NOT EXISTS idx_report_events_node_collected ON report_events(node_id, collected_at)`,
		`CREATE INDEX IF NOT EXISTS idx_report_event_reports_event ON report_event_reports(event_id, collected_at)`,
	}},
	{version: 6, statements: []string{
		// F1: durable purge operation before any destructive step. The row is the
		// authorization context for mapping deletion; B1 immutability triggers stay
		// in force for every non-purge path.
		`CREATE TABLE IF NOT EXISTS purge_ops (
			op_id       TEXT PRIMARY KEY,
			event_id    TEXT NOT NULL,
			actor       TEXT NOT NULL,
			started_at  INTEGER NOT NULL,
			updated_at  INTEGER NOT NULL,
			state       TEXT NOT NULL CHECK (state IN ('purging','mapping','finalizing','completed')),
			phase       TEXT NOT NULL,
			deleted_rows INTEGER NOT NULL DEFAULT 0,
			error       TEXT
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS idx_purge_ops_event ON purge_ops(event_id, state)`,
		// Permanent event-id identity isolation; distinct from the 180-day audit
		// tombstone (purge_tombstones) and retained after the latter expires.
		`CREATE TABLE IF NOT EXISTS event_graveyard (
			event_id   TEXT PRIMARY KEY,
			purged_at  INTEGER NOT NULL,
			op_id      TEXT NOT NULL
		) STRICT`,
		`DROP TRIGGER IF EXISTS route_mapping_versions_no_delete`,
		`DROP TRIGGER IF EXISTS route_mapping_entries_no_delete`,
		`CREATE TRIGGER route_mapping_versions_no_delete
			BEFORE DELETE ON route_mapping_versions
			WHEN NOT EXISTS (SELECT 1 FROM purge_ops p WHERE p.event_id = OLD.event_id AND p.state IN ('mapping','finalizing'))
			BEGIN SELECT RAISE(ABORT, 'route_mapping_versions are immutable'); END`,
		`CREATE TRIGGER route_mapping_entries_no_delete
			BEFORE DELETE ON route_mapping_entries
			WHEN NOT EXISTS (SELECT 1 FROM purge_ops p WHERE p.event_id = OLD.event_id AND p.state IN ('mapping','finalizing'))
			BEGIN SELECT RAISE(ABORT, 'route_mapping_entries are immutable'); END`,
	}},
	{version: 7, statements: []string{
		// F4: effective-dated config history. Reports are validated against the
		// configuration that was effective at collected_at, not a mutable current
		// row or an "updated_at" bypass.
		`CREATE TABLE IF NOT EXISTS node_config_history (
			id             INTEGER PRIMARY KEY AUTOINCREMENT,
			node_id        TEXT NOT NULL REFERENCES nodes(node_id),
			event_id       TEXT NOT NULL,
			config_version INTEGER NOT NULL CHECK (config_version >= 1),
			effective_from INTEGER NOT NULL CHECK (typeof(effective_from) = 'integer'),
			sources_json   TEXT NOT NULL,
			expected_inbound_tags_json TEXT NOT NULL,
			cadence_seconds INTEGER NOT NULL,
			device_salt    TEXT NOT NULL,
			UNIQUE(node_id, config_version)
		) STRICT`,
		`INSERT OR IGNORE INTO node_config_history(node_id,event_id,config_version,effective_from,sources_json,expected_inbound_tags_json,cadence_seconds,device_salt)
		 SELECT node_id,event_id,config_version,updated_at,sources_json,expected_inbound_tags_json,cadence_seconds,device_salt FROM node_configs`,
		`CREATE INDEX IF NOT EXISTS idx_node_config_history_lookup ON node_config_history(node_id, effective_from DESC, config_version DESC)`,
	}},
	{version: 8, statements: []string{
		// C4: the v7 backfill copied a mutable current config as if it were
		// historical evidence. Re-anchor version 1 at registration time with the
		// fail-closed initial switches, and create that row when it is missing.
		`UPDATE node_config_history
		 SET effective_from=(SELECT created_at FROM nodes n WHERE n.node_id=node_config_history.node_id),
		     sources_json='{"system":false,"services":false,"singbox_api":false,"mihomo_api":false,"terminal":false,"events":false}',
		     expected_inbound_tags_json='[]'
		 WHERE config_version=1`,
		`INSERT OR IGNORE INTO node_config_history(node_id,event_id,config_version,effective_from,sources_json,expected_inbound_tags_json,cadence_seconds,device_salt)
		 SELECT n.node_id,n.event_id,1,n.created_at,
		        '{"system":false,"services":false,"singbox_api":false,"mihomo_api":false,"terminal":false,"events":false}',
		        '[]',COALESCE(c.cadence_seconds,60),COALESCE(c.device_salt,'')
		 FROM nodes n LEFT JOIN node_configs c ON c.node_id=n.node_id`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_purge_ops_single_incomplete
		 ON purge_ops(event_id) WHERE state <> 'completed'`,
	}},
}

// Open creates the parent directory if needed, opens the SQLite database,
// applies the durability/isolation PRAGMAs through the driver's per-connection
// DSN initialisation, verifies the actual PRAGMA values and migrates the schema
// to SchemaVersion. Calling Open again on the same path is idempotent.
func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, &InvalidArgumentError{Field: "path", Detail: "must not be empty"}
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("store: create database directory: %w", err)
		}
	}
	// Apply PRAGMAs through the driver DSN. This is the per-connection
	// initialisation guarantee: every pooled physical connection, including a
	// replacement after the original connection dies, is configured by the
	// driver before it is handed to database/sql. MaxOpenConns(1) below only
	// serializes writers; correctness must not depend on a single physical
	// connection living forever.
	query := url.Values{}
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "foreign_keys(ON)")
	query.Add("_pragma", "journal_mode(WAL)")
	query.Add("_pragma", "synchronous(FULL)")
	dsn := "file:" + filepath.ToSlash(path) + "?" + query.Encode()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open sqlite database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	s := &Store{db: db, path: path}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.verifyPragmas(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.applyMigrations(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// verifyPragmas verifies the actual returned values, not merely that Exec
// succeeded. A mismatch is fail-closed: running with an unverified durability
// or isolation setting is worse than refusing to start.
func (s *Store) verifyPragmas(ctx context.Context) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("store: get verification connection: %w", err)
	}
	defer conn.Close()

	var journalMode string
	if err := conn.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		return fmt.Errorf("store: read journal_mode: %w", err)
	}
	if !strings.EqualFold(journalMode, "wal") {
		return fmt.Errorf("store: journal_mode=%q, want wal", journalMode)
	}
	var synchronous int
	if err := conn.QueryRowContext(ctx, `PRAGMA synchronous`).Scan(&synchronous); err != nil {
		return fmt.Errorf("store: read synchronous: %w", err)
	}
	// SQLite: 0=OFF, 1=NORMAL, 2=FULL, 3=EXTRA.
	if synchronous != 2 {
		return fmt.Errorf("store: synchronous=%d, want 2 (FULL)", synchronous)
	}
	var foreignKeys int
	if err := conn.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		return fmt.Errorf("store: read foreign_keys: %w", err)
	}
	if foreignKeys != 1 {
		return fmt.Errorf("store: foreign_keys=%d, want 1", foreignKeys)
	}
	var busyTimeout int
	if err := conn.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&busyTimeout); err != nil {
		return fmt.Errorf("store: read busy_timeout: %w", err)
	}
	if busyTimeout != 5000 {
		return fmt.Errorf("store: busy_timeout=%d, want 5000", busyTimeout)
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
	if current > SchemaVersion {
		// Fail-closed: a newer database may have semantics this build does not
		// know. Never silently use or downgrade it.
		return fmt.Errorf("store: database schema version %d is newer than supported version %d", current, SchemaVersion)
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

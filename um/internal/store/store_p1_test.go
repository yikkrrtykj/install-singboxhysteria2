package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/protocol"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/wire"
)

// --- P1-01: strict numeric storage and migration fail-closed ---------------

func TestStrictNumericTablesRejectNonIntegerStorage(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	mustCreateNode(t, s, "node-a", "event-a", NodeClassLinuxVPS)

	// Valid typed writes are stored as INTEGER.
	mustPutBoot(t, s, "node-a", wire.MaxNumeric, testBootA, wire.MaxNumeric, "fp-max")
	for _, q := range []string{
		`SELECT typeof(highest_gen) FROM node_boot WHERE node_id='node-a'`,
		`SELECT typeof(last_seq) FROM node_boot WHERE node_id='node-a'`,
	} {
		if got := queryString(t, s, q); got != "integer" {
			t.Fatalf("%s = %q, want integer", q, got)
		}
	}

	// Every protocol generation/seq column must reject REAL, non-numeric TEXT,
	// BLOB, negative and out-of-range values inserted through raw SQL. Each case
	// uses an independent primary key/node so the test cannot pass merely because
	// an existing row caused a UNIQUE/PK conflict. The error category is checked:
	// STRICT rejects wrong types; CHECK rejects numeric range violations.
	type negativeCase struct {
		name      string
		nodeID    string
		stmt      string
		args      []any
		wantError string
	}
	cases := []negativeCase{
		{
			name: "node_boot real gen", nodeID: "neg-boot-real",
			stmt:      `INSERT INTO node_boot(node_id,highest_gen,boot_id,last_seq,last_fingerprint,updated_at) VALUES(?,1.5,'b',1,NULL,1)`,
			wantError: "cannot store",
		},
		{
			name: "node_boot nonnumeric text gen", nodeID: "neg-boot-text",
			stmt:      `INSERT INTO node_boot(node_id,highest_gen,boot_id,last_seq,last_fingerprint,updated_at) VALUES(?,'not-an-int','b',1,NULL,1)`,
			wantError: "cannot store",
		},
		{
			name: "node_boot blob gen", nodeID: "neg-boot-blob",
			stmt:      `INSERT INTO node_boot(node_id,highest_gen,boot_id,last_seq,last_fingerprint,updated_at) VALUES(?,?, 'b',1,NULL,1)`,
			args:      []any{[]byte{0x01, 0x02}},
			wantError: "cannot store",
		},
		{
			name: "node_boot negative gen", nodeID: "neg-boot-negative",
			stmt:      `INSERT INTO node_boot(node_id,highest_gen,boot_id,last_seq,last_fingerprint,updated_at) VALUES(?,-1,'b',1,NULL,1)`,
			wantError: "CHECK constraint",
		},
		{
			name: "node_boot over max seq", nodeID: "neg-boot-over",
			stmt:      `INSERT INTO node_boot(node_id,highest_gen,boot_id,last_seq,last_fingerprint,updated_at) VALUES(?,1,'b',9223372036854775807,NULL,1)`,
			wantError: "CHECK constraint",
		},
		{
			name: "seq_dedupe real gen", nodeID: "",
			stmt:      `INSERT INTO seq_dedupe(node_id,boot_gen,boot_id,seq,fingerprint,received_at) VALUES('node-a',1.5,'neg-seq-real',1,'fp',1)`,
			wantError: "cannot store",
		},
		{
			name: "seq_dedupe nonnumeric text seq", nodeID: "",
			stmt:      `INSERT INTO seq_dedupe(node_id,boot_gen,boot_id,seq,fingerprint,received_at) VALUES('node-a',1,'neg-seq-text','bad','fp',1)`,
			wantError: "cannot store",
		},
		{
			name: "seq_dedupe negative seq", nodeID: "",
			stmt:      `INSERT INTO seq_dedupe(node_id,boot_gen,boot_id,seq,fingerprint,received_at) VALUES('node-a',1,'neg-seq-negative',-1,'fp',1)`,
			wantError: "CHECK constraint",
		},
		{
			name: "seq_dedupe over max", nodeID: "",
			stmt:      `INSERT INTO seq_dedupe(node_id,boot_gen,boot_id,seq,fingerprint,received_at) VALUES('node-a',1,'neg-seq-over',9223372036854775807,'fp',1)`,
			wantError: "CHECK constraint",
		},
		{
			name: "boot_registry real gen", nodeID: "",
			stmt:      `INSERT INTO boot_registry(node_id,boot_gen,boot_id,first_seen_at,last_seen_at,last_seq,state) VALUES('node-a',1.5,'neg-reg-real',1,1,1,'active')`,
			wantError: "cannot store",
		},
		{
			name: "boot_registry nonnumeric text last_seq", nodeID: "",
			stmt:      `INSERT INTO boot_registry(node_id,boot_gen,boot_id,first_seen_at,last_seen_at,last_seq,state) VALUES('node-a',1,'neg-reg-text',1,1,'x','active')`,
			wantError: "cannot store",
		},
		{
			name: "boot_registry negative last_seq", nodeID: "",
			stmt:      `INSERT INTO boot_registry(node_id,boot_gen,boot_id,first_seen_at,last_seen_at,last_seq,state) VALUES('node-a',1,'neg-reg-negative',1,1,-1,'active')`,
			wantError: "CHECK constraint",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.nodeID != "" {
				mustCreateNode(t, s, tc.nodeID, "event-a", NodeClassLinuxVPS)
				tc.args = append([]any{tc.nodeID}, tc.args...)
			}
			args := tc.args
			if tc.nodeID == "" {
				args = nil
			}
			if _, err := s.db.ExecContext(ctx, tc.stmt, args...); err == nil {
				t.Fatalf("raw SQL accepted non-strict/invalid value; want error containing %q", tc.wantError)
			} else if !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("error = %v, want category %q", err, tc.wantError)
			}
		})
	}

	// Legal lossless TEXT->INTEGER conversion is allowed, but the stored value
	// must be INTEGER, never TEXT/REAL/BLOB.
	for _, tc := range []struct {
		name  string
		node  string
		stmt  string
		table string
		col   string
	}{
		{"node_boot numeric text", "lossless-boot", `INSERT INTO node_boot(node_id,highest_gen,boot_id,last_seq,last_fingerprint,updated_at) VALUES(?, '9','b','10',NULL,'1')`, "node_boot", "highest_gen"},
		{"seq_dedupe numeric text", "", `INSERT INTO seq_dedupe(node_id,boot_gen,boot_id,seq,fingerprint,received_at) VALUES('node-a','9','lossless-seq','10','fp','1')`, "seq_dedupe", "seq"},
		{"boot_registry numeric text", "", `INSERT INTO boot_registry(node_id,boot_gen,boot_id,first_seen_at,last_seen_at,last_seq,state) VALUES('node-a',9,'lossless-reg',1,1,'10','active')`, "boot_registry", "last_seq"},
	} {
		args := []any(nil)
		if tc.node != "" {
			mustCreateNode(t, s, tc.node, "event-a", NodeClassLinuxVPS)
			args = []any{tc.node}
		}
		if _, err := s.db.ExecContext(ctx, tc.stmt, args...); err != nil {
			t.Fatalf("%s: legal lossless conversion rejected: %v", tc.name, err)
		}
		if got := queryString(t, s, `SELECT typeof(`+tc.col+`) FROM `+tc.table+` WHERE rowid = (SELECT MAX(rowid) FROM `+tc.table+`)`); got != "integer" {
			t.Fatalf("%s stored as %q, want integer", tc.name, got)
		}
	}

	// The three tables are actually STRICT, not only CHECK-constrained.
	for _, table := range []string{"node_boot", "seq_dedupe", "boot_registry"} {
		ddl := queryString(t, s, `SELECT sql FROM sqlite_master WHERE type='table' AND name=?`, table)
		if !strings.Contains(strings.ToUpper(ddl), "STRICT") {
			t.Fatalf("%s is not STRICT: %s", table, ddl)
		}
	}
}

func TestMigrationNewerThanSupportedFailsClosed(t *testing.T) {
	path := tempStorePath(t)
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	if _, err := raw.Exec(`CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		t.Fatalf("create migrations: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)`, SchemaVersion+1, 1); err != nil {
		t.Fatalf("insert higher version: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw: %v", err)
	}
	if s, err := Open(path); err == nil {
		_ = s.Close()
		t.Fatal("Open accepted a database with a newer schema version")
	} else if !strings.Contains(err.Error(), "newer than supported") {
		t.Fatalf("Open error = %v, want newer-than-supported", err)
	}
}

func TestLegacyV1DatabaseIsMigratedWithoutSilentLoss(t *testing.T) {
	path := tempStorePath(t)
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	ctx := context.Background()
	for _, stmt := range migrations[0].statements {
		if _, err := raw.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("create v1 schema: %v", err)
		}
	}
	if _, err := raw.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		t.Fatalf("create migrations: %v", err)
	}
	if _, err := raw.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES(1, 1)`); err != nil {
		t.Fatalf("record v1: %v", err)
	}
	if _, err := raw.ExecContext(ctx, `INSERT INTO nodes(node_id,event_id,node_class,state,created_at) VALUES('node-a','event-a','linux_vps','active',1)`); err != nil {
		t.Fatalf("seed node: %v", err)
	}
	if _, err := raw.ExecContext(ctx, `INSERT INTO node_boot(node_id,highest_gen,boot_id,last_seq,last_fingerprint,updated_at) VALUES('node-a',7,'bb',42,'fp',1)`); err != nil {
		t.Fatalf("seed boot: %v", err)
	}
	if _, err := raw.ExecContext(ctx, `INSERT INTO seq_dedupe(node_id,boot_gen,boot_id,seq,fingerprint,received_at) VALUES('node-a',7,'bb',42,'fp',1)`); err != nil {
		t.Fatalf("seed seq: %v", err)
	}
	if _, err := raw.ExecContext(ctx, `INSERT INTO boot_registry(node_id,boot_gen,boot_id,first_seen_at,last_seen_at,last_seq,state) VALUES('node-a',7,'bb',1,1,42,'active')`); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw: %v", err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open legacy v1: %v", err)
	}
	defer s.Close()
	if v, err := s.SchemaVersion(ctx); err != nil || v != SchemaVersion {
		t.Fatalf("schema version = (%d, %v), want %d", v, err, SchemaVersion)
	}
	boot, err := s.GetBoot(ctx, "node-a")
	if err != nil || boot.HighestGen != 7 || boot.LastSeq != 42 || boot.LastFingerprint != "fp" {
		t.Fatalf("legacy boot not preserved: %+v err=%v", boot, err)
	}
	if got := queryString(t, s, `SELECT typeof(highest_gen) FROM node_boot WHERE node_id='node-a'`); got != "integer" {
		t.Fatalf("migrated type = %q", got)
	}
}

// --- P1-03: connection lifecycle and per-connection PRAGMAs -----------------

func checkPragmas(t *testing.T, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) {
	t.Helper()
	ctx := context.Background()
	var journal string
	if err := q.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&journal); err != nil || !strings.EqualFold(journal, "wal") {
		t.Fatalf("journal_mode=(%q,%v)", journal, err)
	}
	var synchronous, foreignKeys, busyTimeout int
	if err := q.QueryRowContext(ctx, `PRAGMA synchronous`).Scan(&synchronous); err != nil || synchronous != 2 {
		t.Fatalf("synchronous=(%d,%v), want 2", synchronous, err)
	}
	if err := q.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil || foreignKeys != 1 {
		t.Fatalf("foreign_keys=(%d,%v), want 1", foreignKeys, err)
	}
	if err := q.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&busyTimeout); err != nil || busyTimeout != 5000 {
		t.Fatalf("busy_timeout=(%d,%v), want 5000", busyTimeout, err)
	}
}

func TestConnectionReplacementKeepsPragmas(t *testing.T) {
	path := tempStorePath(t)
	s := openTestStore(t, path)
	ctx := context.Background()
	checkPragmas(t, s.db)

	conn1, err := s.db.Conn(ctx)
	if err != nil {
		t.Fatalf("conn1: %v", err)
	}
	checkPragmas(t, conn1)
	if err := conn1.Close(); err != nil {
		t.Fatalf("close conn1: %v", err)
	}
	// Force a new physical connection instead of relying on MaxOpenConns(1) to
	// keep the original alive forever.
	s.db.SetMaxIdleConns(0)
	conn2, err := s.db.Conn(ctx)
	if err != nil {
		t.Fatalf("conn2: %v", err)
	}
	checkPragmas(t, conn2)
	// Foreign key enforcement is active on the replacement connection.
	_, err = conn2.ExecContext(ctx, `INSERT INTO node_keys(key_id,node_id,public_key,state) VALUES('key-deadbeef','node-missing','pk','active')`)
	if err == nil {
		t.Fatal("replacement connection did not enforce foreign_keys=ON")
	}
	_ = conn2.Close()
	if err := s.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	checkPragmas(t, reopened.db)
	if _, err := reopened.GetNode(ctx, "node-a"); err != nil {
		// no node needed; the PRAGMA check above is the assertion
		t.Logf("expected no node: %v", err)
	}
}

// --- P1-04: replay transaction boundaries -----------------------------------

func TestNoExportedHighWaterRewriteAPI(t *testing.T) {
	typ := reflect.TypeOf(&Store{})
	for _, forbidden := range []string{"PutBoot", "DB"} {
		if _, ok := typ.MethodByName(forbidden); ok {
			t.Fatalf("Store exposes forbidden raw high-water/DB API %q", forbidden)
		}
	}
	for _, required := range []string{"WithTx", "ApplyTransport", "GetBoot", "GetNode"} {
		if _, ok := typ.MethodByName(required); !ok {
			t.Fatalf("Store missing required transactional API %q", required)
		}
	}
	txType := reflect.TypeOf(&Tx{})
	for _, required := range []string{"CheckOrInsertNonce", "CheckOrInsertReport", "RecordSeq", "LoadBoot"} {
		if _, ok := txType.MethodByName(required); !ok {
			t.Fatalf("Tx missing required in-transaction security API %q", required)
		}
	}
}

func TestRecordSeqNeverOverwritesFingerprint(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	mustCreateNode(t, s, "node-a", "event-a", NodeClassLinuxVPS)
	if err := recordSeq(ctx, s.db, "node-a", 1, testBootA, 1, "fp-1", 100); err != nil {
		t.Fatalf("first RecordSeq: %v", err)
	}
	if err := recordSeq(ctx, s.db, "node-a", 1, testBootA, 1, "fp-1", 200); err != nil {
		t.Fatalf("idempotent RecordSeq: %v", err)
	}
	err := recordSeq(ctx, s.db, "node-a", 1, testBootA, 1, "fp-other", 300)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting RecordSeq error = %v, want ErrConflict", err)
	}
	fp, ok, err := s.SeqLookup(ctx, "node-a", 1, testBootA, 1)
	if err != nil || !ok || fp != "fp-1" {
		t.Fatalf("stored seq fingerprint = (%q,%v,%v), want fp-1", fp, ok, err)
	}
}

func TestApplyTransportTxAndRollback(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	mustCreateNode(t, s, "node-a", "event-a", NodeClassLinuxVPS)
	attempt := protocol.Attempt{Gen: 1, BootID: testBootA, Seq: 1, Fingerprint: "fp-1"}
	boom := errors.New("payload rejected")

	res, err := s.ApplyTransport(ctx, "node-a", attempt, "fp-1", func(tx *Tx) error {
		if st, err := tx.CheckOrInsertNonce(ctx, "node-a", "nonce-1", "fp-nonce", 100); err != nil || st != NonceNew {
			return fmt.Errorf("nonce: %q %w", st, err)
		}
		if st, err := tx.CheckOrInsertReport(ctx, "node-a", "report-1", "sha-1", 100); err != nil || st != ReportNew {
			return fmt.Errorf("report: %q %w", st, err)
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("apply error = %v", err)
	}
	if res != (protocol.Result{}) {
		t.Fatalf("failed transaction returned result %+v, want zero", res)
	}
	if seen, _ := s.NonceSeen(ctx, "node-a", "nonce-1"); seen {
		t.Fatal("failed transaction persisted nonce")
	}
	if _, ok, _ := s.ReportSeen(ctx, "node-a", "report-1"); ok {
		t.Fatal("failed transaction persisted report dedupe")
	}
	if _, ok, _ := s.SeqLookup(ctx, "node-a", 1, testBootA, 1); ok {
		t.Fatal("failed transaction persisted seq")
	}
	if _, err := s.GetBoot(ctx, "node-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed transaction advanced high-water: %v", err)
	}

	// Retry commits high-water, nonce/report and payload together.
	res, err = s.ApplyTransport(ctx, "node-a", attempt, "fp-1", func(tx *Tx) error {
		if st, err := tx.CheckOrInsertNonce(ctx, "node-a", "nonce-1", "fp-nonce", 100); err != nil || st != NonceNew {
			return fmt.Errorf("nonce retry: %q %w", st, err)
		}
		if st, err := tx.CheckOrInsertReport(ctx, "node-a", "report-1", "sha-1", 100); err != nil || st != ReportNew {
			return fmt.Errorf("report retry: %q %w", st, err)
		}
		return nil
	})
	if err != nil || res.Outcome != protocol.Accepted {
		t.Fatalf("retry = (%+v, %v), want accepted", res, err)
	}
	if seen, _ := s.NonceSeen(ctx, "node-a", "nonce-1"); !seen {
		t.Fatal("committed nonce missing")
	}
	if _, ok, _ := s.ReportSeen(ctx, "node-a", "report-1"); !ok {
		t.Fatal("committed report missing")
	}
}

func TestWithTxRollsBackAllReplayState(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	mustCreateNode(t, s, "node-a", "event-a", NodeClassLinuxVPS)
	boom := errors.New("rollback")
	err := s.WithTx(ctx, func(tx *Tx) error {
		if _, err := tx.CheckOrInsertNonce(ctx, "node-a", "n-1", "fp-n", 1); err != nil {
			return err
		}
		if _, err := tx.CheckOrInsertReport(ctx, "node-a", "r-1", "sha", 1); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("WithTx error = %v", err)
	}
	if seen, _ := s.NonceSeen(ctx, "node-a", "n-1"); seen {
		t.Fatal("WithTx rollback left nonce")
	}
	if _, ok, _ := s.ReportSeen(ctx, "node-a", "r-1"); ok {
		t.Fatal("WithTx rollback left report")
	}
}

// --- P1-02: mapping history and event isolation -----------------------------

func TestMappingVersionHistoryAndValidation(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	const eventA, eventB = "event-a", "event-b"
	mustCreateNode(t, s, "win-a", eventA, NodeClassWindowsTerminal)
	mustCreateNode(t, s, "win-b", eventB, NodeClassWindowsTerminal)
	mustCreateNode(t, s, "linux-a", eventA, NodeClassLinuxVPS)
	mustCreateNode(t, s, "linux-b", eventA, NodeClassLinuxVPS)
	mustCreateNode(t, s, "linux-c", eventA, NodeClassLinuxVPS)
	mustCreateNode(t, s, "linux-other", eventB, NodeClassLinuxVPS)
	const mappingNow int64 = 1_000_000

	v1 := map[string]string{RouteTokenAReality: "linux-a", RouteTokenBReality: "linux-b"}
	if err := s.createMappingVersion(ctx, eventA, "win-a", 1, mappingNow, "admin", v1, mappingNow); err != nil {
		t.Fatalf("v1 immediate: %v", err)
	}
	got, version, err := s.ResolveMapping(ctx, eventA, "win-a", mappingNow)
	if err != nil || version != 1 || !mapsEqual(got, v1) {
		t.Fatalf("resolve@now = (v%d,%v,%v), want v1", version, got, err)
	}
	if _, _, err := s.ResolveMapping(ctx, eventA, "win-a", mappingNow-1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("resolve before first effective_from error=%v, want ErrNotFound", err)
	}

	v2 := map[string]string{RouteTokenAReality: "linux-c", RouteTokenBHy2: "linux-b"}
	if err := s.createMappingVersion(ctx, eventA, "win-a", 2, mappingNow+1_000, "admin", v2, mappingNow); err != nil {
		t.Fatalf("v2 future: %v", err)
	}
	if got, version, err = s.ResolveMapping(ctx, eventA, "win-a", mappingNow+500); err != nil || version != 1 || !mapsEqual(got, v1) {
		t.Fatalf("future version applied early / history changed: (v%d,%v,%v)", version, got, err)
	}
	if got, version, err = s.ResolveMapping(ctx, eventA, "win-a", mappingNow+1_500); err != nil || version != 2 || !mapsEqual(got, v2) {
		t.Fatalf("resolve@future = (v%d,%v,%v), want v2", version, got, err)
	}

	// Future-effective unmapping: empty entries means all four tokens unmapped
	// from this version onward; earlier attribution is unchanged.
	if err := s.createMappingVersion(ctx, eventA, "win-a", 3, mappingNow+2_000, "admin", map[string]string{}, mappingNow); err != nil {
		t.Fatalf("future unmapping v3: %v", err)
	}
	if got, version, err = s.ResolveMapping(ctx, eventA, "win-a", mappingNow+1_500); err != nil || version != 2 || !mapsEqual(got, v2) {
		t.Fatalf("unmapping applied before effective time: (v%d,%v,%v)", version, got, err)
	}
	if got, version, err = s.ResolveMapping(ctx, eventA, "win-a", mappingNow+2_500); err != nil || version != 3 || len(got) != 0 {
		t.Fatalf("unmapped v3 resolve = (v%d,%v,%v), want v3 empty", version, got, err)
	}

	// Backdating relative to the write clock is rejected even when the new
	// effective time is later than the previous version's effective time. This is
	// the final-review correction: normal mapping must not rewrite attribution of
	// data already collected before "now".
	if err := s.createMappingVersion(ctx, eventA, "win-a", 4, mappingNow+3_000, "admin", map[string]string{RouteTokenAReality: "linux-a"}, mappingNow+4_000); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("later-than-previous but past effective time error = %v, want ErrInvalidArgument", err)
	}
	if got, version, err = s.ResolveMapping(ctx, eventA, "win-a", mappingNow+2_500); err != nil || version != 3 {
		t.Fatalf("rejected backdated version changed history: (v%d,%v,%v)", version, got, err)
	}

	// Immutability at the SQL layer.
	if _, err := s.db.ExecContext(ctx, `UPDATE route_mapping_versions SET effective_from=1 WHERE event_id=? AND windows_node_id=? AND version=1`, eventA, "win-a"); err == nil {
		t.Fatal("raw UPDATE of mapping version was allowed")
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM route_mapping_entries WHERE event_id=? AND windows_node_id=? AND version=1`, eventA, "win-a"); err == nil {
		t.Fatal("raw DELETE of mapping entries was allowed")
	}

	// Validation failures must not create versions. Valid future effective times
	// keep these cases exercising the intended validation, not the clock rule.
	invalid := []struct {
		name          string
		event, win    string
		version       int
		effectiveFrom int64
		entries       map[string]string
	}{
		{"missing windows node", eventA, "win-missing", 4, mappingNow + 3_000, map[string]string{RouteTokenAReality: "linux-a"}},
		{"windows node other event", eventA, "win-b", 4, mappingNow + 3_000, map[string]string{RouteTokenAReality: "linux-a"}},
		{"linux node as windows", eventA, "linux-a", 4, mappingNow + 3_000, map[string]string{RouteTokenAReality: "linux-a"}},
		{"cross-event target", eventA, "win-a", 4, mappingNow + 3_000, map[string]string{RouteTokenAReality: "linux-other"}},
		{"missing target", eventA, "win-a", 4, mappingNow + 3_000, map[string]string{RouteTokenAReality: "linux-missing"}},
		{"windows target", eventA, "win-a", 4, mappingNow + 3_000, map[string]string{RouteTokenAReality: "win-a"}},
		{"direct mapping", eventA, "win-a", 4, mappingNow + 3_000, map[string]string{RouteTokenDirect: "linux-a"}},
		{"unknown mapping", eventA, "win-a", 4, mappingNow + 3_000, map[string]string{"unknown": "linux-a"}},
		{"zero version", eventA, "win-a", 0, mappingNow + 3_000, map[string]string{RouteTokenAReality: "linux-a"}},
		{"skipped version", eventA, "win-a", 5, mappingNow + 3_000, map[string]string{RouteTokenAReality: "linux-a"}},
		{"past effective_from", eventA, "win-a", 4, mappingNow - 1, map[string]string{RouteTokenAReality: "linux-a"}},
		{"same-time effective", eventA, "win-a", 4, mappingNow + 2_000, map[string]string{RouteTokenAReality: "linux-a"}},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			err := s.createMappingVersion(ctx, tc.event, tc.win, tc.version, tc.effectiveFrom, "admin", tc.entries, mappingNow+3_000)
			if !errors.Is(err, ErrInvalidArgument) && !errors.Is(err, ErrAlreadyExists) {
				t.Fatalf("error = %v, want invalid/append-only conflict", err)
			}
		})
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM route_mapping_versions WHERE event_id=? AND windows_node_id=?`, eventA, "win-a"); got != 3 {
		t.Fatalf("versions after rejected inserts = %d, want 3", got)
	}

	// Concurrent next-version inserts: exactly one wins; history stays valid.
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- s.createMappingVersion(ctx, eventA, "win-a", 4, mappingNow+3_000, "admin", map[string]string{RouteTokenAReality: "linux-a"}, mappingNow)
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent insert successes = %d, want exactly 1", successes)
	}
	if got, version, err = s.ResolveMapping(ctx, eventA, "win-a", mappingNow+3_500); err != nil || version != 4 || got[RouteTokenAReality] != "linux-a" {
		t.Fatalf("post-concurrency resolve = (v%d,%v,%v)", version, got, err)
	}
	if got, version, err = s.ResolveMapping(ctx, eventA, "win-a", mappingNow+2_500); err != nil || version != 3 {
		t.Fatalf("history after concurrency = (v%d,%v,%v), want v3", version, got, err)
	}
}

// TestMappingEffectiveNowOrLaterRule pins the immediate/future/backdated rules
// independently from the history test above.
func TestMappingEffectiveNowOrLaterRule(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	mustCreateNode(t, s, "win-a", "event-a", NodeClassWindowsTerminal)
	mustCreateNode(t, s, "linux-a", "event-a", NodeClassLinuxVPS)
	const now int64 = 10_000
	entries := map[string]string{RouteTokenAReality: "linux-a"}
	if err := s.createMappingVersion(ctx, "event-a", "win-a", 1, now, "admin", entries, now); err != nil {
		t.Fatalf("immediate version: %v", err)
	}
	if err := s.createMappingVersion(ctx, "event-a", "win-a", 2, now+1, "admin", entries, now); err != nil {
		t.Fatalf("future version: %v", err)
	}
	if got, version, err := s.ResolveMapping(ctx, "event-a", "win-a", now); err != nil || version != 1 || !mapsEqual(got, entries) {
		t.Fatalf("immediate version not effective at now: (v%d,%v,%v)", version, got, err)
	}
	if got, version, err := s.ResolveMapping(ctx, "event-a", "win-a", now+1); err != nil || version != 2 {
		t.Fatalf("future version not effective at its effective time: (v%d,%v,%v)", version, got, err)
	}
	// Same write clock, a new version whose effective_from is in the past but
	// later than the previous effective time must be rejected.
	if err := s.createMappingVersion(ctx, "event-a", "win-a", 3, now-1, "admin", entries, now); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("past effective_from error = %v, want ErrInvalidArgument", err)
	}
	// Exported API uses the real clock: past is rejected, future is accepted.
	realNow := nowUnix()
	if err := s.CreateMappingVersion(ctx, "event-a", "win-a", 3, realNow-10, "admin", entries); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("exported past effective_from error = %v, want ErrInvalidArgument", err)
	}
	if err := s.CreateMappingVersion(ctx, "event-a", "win-a", 3, realNow+3600, "admin", entries); err != nil {
		t.Fatalf("exported future effective_from: %v", err)
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func queryString(t *testing.T, s *Store, query string, args ...any) string {
	t.Helper()
	var out string
	if err := s.db.QueryRowContext(context.Background(), query, args...).Scan(&out); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return out
}

package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/protocol"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/wire"
)

var (
	testBootA = strings.Repeat("a", 32)
	testBootB = strings.Repeat("b", 32)
	testBootC = strings.Repeat("c", 32)
)

func testContext() context.Context { return context.Background() }

func tempStorePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "um.db")
}

func openTestStore(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open(%q): %v", path, err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close(%q): %v", path, err)
		}
	})
	return s
}

func mustCreateNode(t *testing.T, s *Store, nodeID, eventID, class string) {
	t.Helper()
	if _, err := s.db.Exec(`INSERT OR IGNORE INTO event_catalog(event_id,state,created_at,archived_at,purge_after,data_purged_at,updated_at)
		VALUES(?,?,?,NULL,NULL,NULL,?)`, eventID, EventActive, int64(1000), int64(1000)); err != nil {
		t.Fatalf("seed event catalog(%q): %v", eventID, err)
	}
	err := s.CreateNode(testContext(), Node{
		NodeID:    nodeID,
		EventID:   eventID,
		NodeClass: class,
		State:     "active",
		CreatedAt: 1000,
	})
	if err != nil {
		t.Fatalf("CreateNode(%q): %v", nodeID, err)
	}
}

func mustPutBoot(t *testing.T, s *Store, nodeID string, gen uint64, bootID string, seq uint64, fingerprint string) {
	t.Helper()
	if err := s.putBoot(testContext(), nodeID, gen, bootID, seq, fingerprint); err != nil {
		t.Fatalf("PutBoot(%q, gen=%d): %v", nodeID, gen, err)
	}
}

func queryInt(t *testing.T, s *Store, query string, args ...any) int64 {
	t.Helper()
	var value int64
	if err := s.db.QueryRowContext(testContext(), query, args...).Scan(&value); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return value
}

func sha256Hex(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func TestOpenSetsDurabilityPragmas(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "deeper", "um.db")
	s := openTestStore(t, path)
	ctx := testContext()

	var journalMode string
	if err := s.db.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		t.Fatalf("read journal_mode: %v", err)
	}
	if !strings.EqualFold(journalMode, "wal") {
		t.Fatalf("journal_mode = %q, want wal", journalMode)
	}
	var synchronous int
	if err := s.db.QueryRowContext(ctx, `PRAGMA synchronous`).Scan(&synchronous); err != nil {
		t.Fatalf("read synchronous: %v", err)
	}
	if synchronous != 2 {
		t.Fatalf("synchronous = %d, want 2 (FULL)", synchronous)
	}
	var foreignKeys int
	if err := s.db.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		t.Fatalf("read foreign_keys: %v", err)
	}
	if foreignKeys != 1 {
		t.Fatalf("foreign_keys = %d, want 1 (ON)", foreignKeys)
	}
	var busyTimeout int
	if err := s.db.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&busyTimeout); err != nil {
		t.Fatalf("read busy_timeout: %v", err)
	}
	if busyTimeout != 5000 {
		t.Fatalf("busy_timeout = %d, want 5000", busyTimeout)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("database file was not created at %q: %v", path, err)
	}
}

func TestMigrationIdempotentAndSchemaTables(t *testing.T) {
	path := tempStorePath(t)
	ctx := testContext()
	s := openTestStore(t, path)

	version, err := s.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if version != SchemaVersion {
		t.Fatalf("SchemaVersion = %d, want %d", version, SchemaVersion)
	}

	requiredTables := []string{
		"schema_migrations",
		"nodes",
		"node_keys",
		"key_rotations",
		"enroll_tokens",
		"node_boot",
		"seq_dedupe",
		"nonce_dedupe",
		"report_dedupe",
		"boot_registry",
		"route_mapping_versions",
		"route_mapping_entries",
		"security_ledger",
		"report_activity",
	}
	for _, name := range requiredTables {
		if got := queryInt(t, s, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name); got != 1 {
			t.Errorf("table %q: found %d definitions, want 1", name, got)
		}
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM schema_migrations`); got != int64(SchemaVersion) {
		t.Fatalf("schema_migrations rows = %d, want %d", got, SchemaVersion)
	}

	// A reopen on the same path must not re-apply the migration.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	reopened := openTestStore(t, path)
	version, err = reopened.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("SchemaVersion after reopen: %v", err)
	}
	if version != SchemaVersion {
		t.Fatalf("SchemaVersion after reopen = %d, want %d", version, SchemaVersion)
	}
	if got := queryInt(t, reopened, `SELECT COUNT(*) FROM schema_migrations`); got != int64(SchemaVersion) {
		t.Fatalf("schema_migrations rows after reopen = %d, want %d", got, SchemaVersion)
	}
	var journalMode string
	if err := reopened.db.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		t.Fatalf("read journal_mode after reopen: %v", err)
	}
	if !strings.EqualFold(journalMode, "wal") {
		t.Fatalf("journal_mode after reopen = %q, want wal", journalMode)
	}
}

func TestNodeAndBootRoundTrip(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()

	mustCreateNode(t, s, "node-a", "event-a", NodeClassLinuxVPS)
	node, err := s.GetNode(ctx, "node-a")
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	want := Node{NodeID: "node-a", EventID: "event-a", NodeClass: NodeClassLinuxVPS, State: "active", CreatedAt: 1000}
	if node.NodeID != want.NodeID || node.EventID != want.EventID || node.NodeClass != want.NodeClass ||
		node.State != want.State || node.CreatedAt != want.CreatedAt || node.LastSeenAt != nil {
		t.Fatalf("GetNode = %+v, want %+v", node, want)
	}
	if _, err := s.GetNode(ctx, "node-missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetNode(missing) error = %v, want ErrNotFound", err)
	}
	if err := s.CreateNode(ctx, want); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate CreateNode error = %v, want ErrAlreadyExists", err)
	}
	// node_boot is keyed by an existing node identity.
	if err := s.putBoot(ctx, "node-missing", 1, testBootA, 1, "fp"); err == nil {
		t.Fatal("PutBoot for an unknown node must fail the nodes foreign key")
	}

	boot, err := s.GetBoot(ctx, "node-a")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetBoot before any attempt error = %v, want ErrNotFound", err)
	}
	if boot != (protocol.Boot{}) {
		t.Fatalf("GetBoot before any attempt = %+v, want zero protocol.Boot", boot)
	}

	mustPutBoot(t, s, "node-a", 7, testBootA, 42, "fp-7-42")
	boot, err = s.GetBoot(ctx, "node-a")
	if err != nil {
		t.Fatalf("GetBoot: %v", err)
	}
	if boot != (protocol.Boot{HighestGen: 7, BootID: testBootA, LastSeq: 42, LastFingerprint: "fp-7-42"}) {
		t.Fatalf("GetBoot = %+v", boot)
	}
	mustPutBoot(t, s, "node-a", 8, testBootB, 1, "fp-8-1")
	boot, err = s.GetBoot(ctx, "node-a")
	if err != nil {
		t.Fatalf("GetBoot after update: %v", err)
	}
	if boot != (protocol.Boot{HighestGen: 8, BootID: testBootB, LastSeq: 1, LastFingerprint: "fp-8-1"}) {
		t.Fatalf("GetBoot after update = %+v", boot)
	}
}

func TestNumericBoundRoundTrip(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	mustCreateNode(t, s, "node-a", "event-a", NodeClassLinuxVPS)

	mustPutBoot(t, s, "node-a", wire.MaxNumeric, testBootA, wire.MaxNumeric, "fp-max")
	boot, err := s.GetBoot(ctx, "node-a")
	if err != nil {
		t.Fatalf("GetBoot: %v", err)
	}
	if boot.HighestGen != wire.MaxNumeric || boot.LastSeq != wire.MaxNumeric {
		t.Fatalf("GetBoot = %+v, want gen/seq %d", boot, uint64(wire.MaxNumeric))
	}

	var rawHighest, rawLast int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT highest_gen, last_seq FROM node_boot WHERE node_id = ?`, "node-a").
		Scan(&rawHighest, &rawLast); err != nil {
		t.Fatalf("read raw numeric high-water: %v", err)
	}
	if rawHighest != int64(wire.MaxNumeric) || rawLast != int64(wire.MaxNumeric) {
		t.Fatalf("stored numerics = (%d, %d), want (%d, %d)",
			rawHighest, rawLast, int64(wire.MaxNumeric), int64(wire.MaxNumeric))
	}
	var highestType, lastType string
	if err := s.db.QueryRowContext(ctx,
		`SELECT typeof(highest_gen), typeof(last_seq) FROM node_boot WHERE node_id = ?`, "node-a").
		Scan(&highestType, &lastType); err != nil {
		t.Fatalf("read typeof numerics: %v", err)
	}
	if highestType != "integer" || lastType != "integer" {
		t.Fatalf("numeric storage types = (%q, %q), want integer/integer", highestType, lastType)
	}

	// Out-of-range values are rejected before conversion and never touch state.
	if err := s.putBoot(ctx, "node-a", wire.MaxNumeric+1, testBootA, 1, "fp"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("PutBoot(gen=MaxNumeric+1) error = %v, want ErrInvalidArgument", err)
	}
	if err := s.putBoot(ctx, "node-a", 1, testBootA, wire.MaxNumeric+1, "fp"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("PutBoot(seq=MaxNumeric+1) error = %v, want ErrInvalidArgument", err)
	}
	if err := s.putBoot(ctx, "node-a", 0, testBootA, 1, "fp"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("PutBoot(gen=0) error = %v, want ErrInvalidArgument", err)
	}
	boot, err = s.GetBoot(ctx, "node-a")
	if err != nil {
		t.Fatalf("GetBoot after rejected writes: %v", err)
	}
	if boot.HighestGen != wire.MaxNumeric || boot.LastSeq != wire.MaxNumeric {
		t.Fatalf("rejected writes changed the high-water: %+v", boot)
	}

	// The SQL CHECK constraints are the last line of defence for raw SQL.
	mustCreateNode(t, s, "node-check", "event-a", NodeClassLinuxVPS)
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO node_boot(node_id, highest_gen, boot_id, last_seq, last_fingerprint, updated_at)
		 VALUES(?, 0, ?, 1, NULL, 1)`, "node-check", testBootA); err == nil {
		t.Fatal("node_boot CHECK must reject highest_gen = 0")
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO node_boot(node_id, highest_gen, boot_id, last_seq, last_fingerprint, updated_at)
		 VALUES(?, ?, ?, 1, NULL, 1)`, "node-check", int64(9223372036854775807), testBootA); err == nil {
		t.Fatal("node_boot CHECK must reject highest_gen above 9223372036854775806")
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO node_boot(node_id, highest_gen, boot_id, last_seq, last_fingerprint, updated_at)
		 VALUES(?, 1, ?, 0, NULL, 1)`, "node-check", testBootA); err == nil {
		t.Fatal("node_boot CHECK must reject last_seq = 0")
	}
}

func TestNodeClassConstraint(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()

	mustCreateNode(t, s, "node-linux", "event-a", NodeClassLinuxVPS)
	mustCreateNode(t, s, "node-windows", "event-a", NodeClassWindowsTerminal)
	for nodeID, wantClass := range map[string]string{
		"node-linux":   NodeClassLinuxVPS,
		"node-windows": NodeClassWindowsTerminal,
	} {
		node, err := s.GetNode(ctx, nodeID)
		if err != nil {
			t.Fatalf("GetNode(%q): %v", nodeID, err)
		}
		if node.NodeClass != wantClass {
			t.Fatalf("GetNode(%q).NodeClass = %q, want %q", nodeID, node.NodeClass, wantClass)
		}
	}

	err := s.CreateNode(ctx, Node{NodeID: "node-bad", EventID: "event-a", NodeClass: "router", State: "active", CreatedAt: 1})
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("CreateNode(invalid class) error = %v, want ErrInvalidArgument", err)
	}
	// Bypass the Go validation: the database CHECK must still reject it.
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO nodes(node_id, event_id, node_class, state, created_at)
		 VALUES('node-raw', 'event-a', 'router', 'active', 1)`); err == nil {
		t.Fatal("nodes CHECK must reject node_class = router")
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM nodes WHERE node_id = 'node-raw'`); got != 0 {
		t.Fatalf("invalid node_class row was stored (%d rows)", got)
	}
}

func TestApplyTransportStaleGeneration(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	mustCreateNode(t, s, "node-a", "event-a", NodeClassLinuxVPS)
	mustPutBoot(t, s, "node-a", 5, testBootA, 10, "fp-5-10")
	before, err := s.GetBoot(ctx, "node-a")
	if err != nil {
		t.Fatalf("GetBoot: %v", err)
	}

	applied := false
	res, err := s.ApplyTransport(ctx, "node-a",
		protocol.Attempt{Gen: 4, BootID: testBootC, Seq: 11, Fingerprint: "fp-4-11"}, "fp-4-11",
		func(tx *Tx) error {
			applied = true
			return nil
		})
	if err == nil {
		t.Fatal("stale generation must be rejected")
	}
	if !IsTransportConflict(err) {
		t.Fatalf("error = %v, want a typed transport conflict", err)
	}
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("error = %v, want it to wrap ErrConflict", err)
	}
	outcome, ok := TransportConflictOutcome(err)
	if !ok || outcome != protocol.StaleBootGeneration {
		t.Fatalf("conflict outcome = %q (ok=%v), want stale_boot_generation", outcome, ok)
	}
	if res.Outcome != protocol.StaleBootGeneration {
		t.Fatalf("result outcome = %q, want stale_boot_generation", res.Outcome)
	}
	if applied {
		t.Fatal("apply must not run for a rejected transport attempt")
	}
	after, err := s.GetBoot(ctx, "node-a")
	if err != nil {
		t.Fatalf("GetBoot after rejection: %v", err)
	}
	if after != before {
		t.Fatalf("rejected attempt changed high-water: before=%+v after=%+v", before, after)
	}
	if _, ok, err := s.SeqLookup(ctx, "node-a", 4, testBootC, 11); err != nil || ok {
		t.Fatalf("rejected attempt left seq dedupe state (ok=%v, err=%v)", ok, err)
	}
}

func TestApplyTransportBootIdentityAndGap(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	mustCreateNode(t, s, "node-a", "event-a", NodeClassLinuxVPS)
	mustPutBoot(t, s, "node-a", 1, testBootA, 1, "fp-1-1")
	before, err := s.GetBoot(ctx, "node-a")
	if err != nil {
		t.Fatalf("GetBoot: %v", err)
	}

	// Same generation with a different boot id.
	res, err := s.ApplyTransport(ctx, "node-a",
		protocol.Attempt{Gen: 1, BootID: testBootB, Seq: 2, Fingerprint: "fp-conflict"}, "fp-conflict", nil)
	if res.Outcome != protocol.BootIdentityConflict || !IsTransportConflict(err) {
		t.Fatalf("same-gen boot id mismatch = (%q, %v), want boot_identity_conflict", res.Outcome, err)
	}

	// A forward jump above wire.MaxBootGap is a boot identity conflict.
	tooFar := 1 + wire.MaxBootGap + 1
	res, err = s.ApplyTransport(ctx, "node-a",
		protocol.Attempt{Gen: tooFar, BootID: testBootB, Seq: 1, Fingerprint: "fp-gap"}, "fp-gap", nil)
	if res.Outcome != protocol.BootIdentityConflict || !IsTransportConflict(err) {
		t.Fatalf("gap > MaxBootGap = (%q, %v), want boot_identity_conflict", res.Outcome, err)
	}
	after, err := s.GetBoot(ctx, "node-a")
	if err != nil {
		t.Fatalf("GetBoot after rejections: %v", err)
	}
	if after != before {
		t.Fatalf("rejected attempts changed high-water: before=%+v after=%+v", before, after)
	}

	// The exact boundary (gap == wire.MaxBootGap) is accepted and audited.
	boundary := 1 + wire.MaxBootGap
	res, err = s.ApplyTransport(ctx, "node-a",
		protocol.Attempt{Gen: boundary, BootID: testBootB, Seq: 1, Fingerprint: "fp-boundary"}, "fp-boundary", nil)
	if err != nil || res.Outcome != protocol.Accepted {
		t.Fatalf("gap == MaxBootGap = (%q, %v), want accepted", res.Outcome, err)
	}
	if res.Gap != wire.MaxBootGap || !res.AuditGap {
		t.Fatalf("gap result = %d / audited=%v, want %d / true", res.Gap, res.AuditGap, uint64(wire.MaxBootGap))
	}
	boot, err := s.GetBoot(ctx, "node-a")
	if err != nil {
		t.Fatalf("GetBoot after boundary accept: %v", err)
	}
	if boot.HighestGen != boundary || boot.BootID != testBootB || boot.LastSeq != 1 {
		t.Fatalf("high-water = %+v, want gen %d boot %q seq 1", boot, boundary, testBootB)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM boot_registry WHERE node_id = ? AND boot_gen = ?`,
		"node-a", int64(boundary)); got != 1 {
		t.Fatalf("boot_registry rows for the accepted generation = %d, want 1", got)
	}

	// First contact of a fresh node may start at gen > 1 and seq > 1; the gap is
	// recorded but never rejected.
	mustCreateNode(t, s, "node-fresh", "event-a", NodeClassLinuxVPS)
	res, err = s.ApplyTransport(ctx, "node-fresh",
		protocol.Attempt{Gen: 5, BootID: testBootA, Seq: 3, Fingerprint: "fp-fresh"}, "fp-fresh", nil)
	if err != nil || res.Outcome != protocol.Accepted {
		t.Fatalf("fresh first contact = (%q, %v), want accepted", res.Outcome, err)
	}
	if res.Gap != 5 || !res.AuditGap {
		t.Fatalf("fresh gap = %d / audited=%v, want 5 / true", res.Gap, res.AuditGap)
	}
	boot, err = s.GetBoot(ctx, "node-fresh")
	if err != nil {
		t.Fatalf("GetBoot(node-fresh): %v", err)
	}
	if boot != (protocol.Boot{HighestGen: 5, BootID: testBootA, LastSeq: 3, LastFingerprint: "fp-fresh"}) {
		t.Fatalf("fresh high-water = %+v", boot)
	}
}

func TestApplyTransportAcceptedDuplicateAndSequence(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	mustCreateNode(t, s, "node-a", "event-a", NodeClassLinuxVPS)
	mustPutBoot(t, s, "node-a", 3, testBootA, 5, "fp-3-5")

	applied := 0
	apply := func(tx *Tx) error {
		applied++
		_, err := tx.tx.ExecContext(ctx,
			`INSERT INTO report_activity(node_id, report_id, collected_at, received_at) VALUES(?, ?, ?, ?)`,
			"node-a", "report-9", 100, 101)
		return err
	}

	acceptedAttempt := protocol.Attempt{Gen: 4, BootID: testBootB, Seq: 9, Fingerprint: "fp-4-9"}
	res, err := s.ApplyTransport(ctx, "node-a", acceptedAttempt, "fp-4-9", apply)
	if err != nil {
		t.Fatalf("accepted ApplyTransport: %v", err)
	}
	if res.Outcome != protocol.Accepted || !res.HighWaterCommitted {
		t.Fatalf("result = %+v, want accepted with committed high-water", res)
	}
	if applied != 1 {
		t.Fatalf("apply calls = %d, want 1", applied)
	}
	boot, err := s.GetBoot(ctx, "node-a")
	if err != nil {
		t.Fatalf("GetBoot: %v", err)
	}
	if boot != (protocol.Boot{HighestGen: 4, BootID: testBootB, LastSeq: 9, LastFingerprint: "fp-4-9"}) {
		t.Fatalf("high-water after accept = %+v", boot)
	}
	if fingerprint, ok, err := s.SeqLookup(ctx, "node-a", 4, testBootB, 9); err != nil || !ok || fingerprint != "fp-4-9" {
		t.Fatalf("seq dedupe = (%q, %v, %v), want fp-4-9", fingerprint, ok, err)
	}
	var registryGen, registrySeq int64
	var registryState string
	if err := s.db.QueryRowContext(ctx,
		`SELECT boot_gen, last_seq, state FROM boot_registry WHERE node_id = ? AND boot_gen = ? AND boot_id = ?`,
		"node-a", 4, testBootB).Scan(&registryGen, &registrySeq, &registryState); err != nil {
		t.Fatalf("boot_registry row: %v", err)
	}
	if registryGen != 4 || registrySeq != 9 || registryState != "active" {
		t.Fatalf("boot_registry = (%d, %d, %q), want (4, 9, active)", registryGen, registrySeq, registryState)
	}

	// An exact retry of the committed attempt is a Duplicate: no apply, no
	// high-water change, and the ACK next_seq is last_seq+1.
	res, err = s.ApplyTransport(ctx, "node-a", acceptedAttempt, "fp-4-9", apply)
	if err != nil {
		t.Fatalf("duplicate ApplyTransport: %v", err)
	}
	if res.Outcome != protocol.Duplicate {
		t.Fatalf("retry outcome = %q, want duplicate", res.Outcome)
	}
	if res.NextSeq == nil || *res.NextSeq != 10 {
		t.Fatalf("duplicate NextSeq = %v, want 10", res.NextSeq)
	}
	if applied != 1 {
		t.Fatalf("apply calls after duplicate = %d, want 1", applied)
	}

	// Same seq with a different fingerprint is a sequence conflict.
	res, err = s.ApplyTransport(ctx, "node-a",
		protocol.Attempt{Gen: 4, BootID: testBootB, Seq: 9, Fingerprint: "fp-4-9-other"}, "fp-4-9-other", apply)
	if res.Outcome != protocol.SequenceConflict || !IsTransportConflict(err) {
		t.Fatalf("same seq different fingerprint = (%q, %v), want sequence_conflict", res.Outcome, err)
	}
	if applied != 1 {
		t.Fatalf("apply calls after conflict = %d, want 1", applied)
	}
	boot, err = s.GetBoot(ctx, "node-a")
	if err != nil {
		t.Fatalf("GetBoot after conflict: %v", err)
	}
	if boot.LastSeq != 9 || boot.LastFingerprint != "fp-4-9" {
		t.Fatalf("high-water after conflict = %+v", boot)
	}

	// A delayed exact retry of an already superseded seq is a Duplicate only if
	// the bounded history holds the matching fingerprint.
	if err := recordSeq(ctx, s.db, "node-a", 4, testBootB, 2, "fp-4-2", 500); err != nil {
		t.Fatalf("RecordSeq: %v", err)
	}
	res, err = s.ApplyTransport(ctx, "node-a",
		protocol.Attempt{Gen: 4, BootID: testBootB, Seq: 2, Fingerprint: "fp-4-2"}, "", nil)
	if err != nil || res.Outcome != protocol.Duplicate {
		t.Fatalf("historical exact retry = (%q, %v), want duplicate", res.Outcome, err)
	}
	res, err = s.ApplyTransport(ctx, "node-a",
		protocol.Attempt{Gen: 4, BootID: testBootB, Seq: 2, Fingerprint: "fp-4-2-other"}, "", nil)
	if res.Outcome != protocol.SequenceConflict || !IsTransportConflict(err) {
		t.Fatalf("historical mismatched retry = (%q, %v), want sequence_conflict", res.Outcome, err)
	}

	// A forward sequence jump is accepted (lost attempts are legitimate).
	res, err = s.ApplyTransport(ctx, "node-a",
		protocol.Attempt{Gen: 4, BootID: testBootB, Seq: 20, Fingerprint: "fp-4-20"}, "", nil)
	if err != nil || res.Outcome != protocol.Accepted {
		t.Fatalf("seq gap = (%q, %v), want accepted", res.Outcome, err)
	}
	boot, err = s.GetBoot(ctx, "node-a")
	if err != nil {
		t.Fatalf("GetBoot after seq gap: %v", err)
	}
	if boot.LastSeq != 20 {
		t.Fatalf("last_seq after seq gap = %d, want 20", boot.LastSeq)
	}

	// attempt.Fingerprint may be omitted when the caller passes fingerprint
	// separately; both must converge on the same durable state.
	res, err = s.ApplyTransport(ctx, "node-a",
		protocol.Attempt{Gen: 4, BootID: testBootB, Seq: 21}, "fp-4-21", nil)
	if err != nil || res.Outcome != protocol.Accepted {
		t.Fatalf("fingerprint fallback = (%q, %v), want accepted", res.Outcome, err)
	}
	boot, err = s.GetBoot(ctx, "node-a")
	if err != nil {
		t.Fatalf("GetBoot after fingerprint fallback: %v", err)
	}
	if boot.LastFingerprint != "fp-4-21" {
		t.Fatalf("stored fingerprint = %q, want fp-4-21", boot.LastFingerprint)
	}

	// Numeric exhaustion: the last representable seq is accepted and next_seq
	// becomes nil, so the agent must start a new generation.
	mustPutBoot(t, s, "node-a", 1, testBootA, wire.MaxNumeric-1, "fp-near-max")
	res, err = s.ApplyTransport(ctx, "node-a",
		protocol.Attempt{Gen: 1, BootID: testBootA, Seq: wire.MaxNumeric, Fingerprint: "fp-max"}, "fp-max", nil)
	if err != nil || res.Outcome != protocol.Accepted {
		t.Fatalf("max numeric accept = (%q, %v), want accepted", res.Outcome, err)
	}
	if res.NextSeq != nil {
		t.Fatalf("NextSeq at exhaustion = %v, want nil", *res.NextSeq)
	}
	boot, err = s.GetBoot(ctx, "node-a")
	if err != nil {
		t.Fatalf("GetBoot after max numeric: %v", err)
	}
	if boot.LastSeq != wire.MaxNumeric {
		t.Fatalf("last_seq = %d, want %d", boot.LastSeq, uint64(wire.MaxNumeric))
	}
}

func TestApplyTransportRollbackOnApplyError(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	mustCreateNode(t, s, "node-a", "event-a", NodeClassLinuxVPS)
	mustPutBoot(t, s, "node-a", 2, testBootA, 1, "fp-2-1")
	before, err := s.GetBoot(ctx, "node-a")
	if err != nil {
		t.Fatalf("GetBoot: %v", err)
	}

	attempt := protocol.Attempt{Gen: 3, BootID: testBootB, Seq: 1, Fingerprint: "fp-3-1"}
	applyErr := errors.New("downstream payload validation rejected the report")
	res, err := s.ApplyTransport(ctx, "node-a", attempt, "fp-3-1", func(tx *Tx) error {
		if _, err := tx.tx.ExecContext(ctx,
			`INSERT INTO report_activity(node_id, report_id, collected_at, received_at) VALUES(?, ?, ?, ?)`,
			"node-a", "rollback-report", 1, 2); err != nil {
			return err
		}
		return applyErr
	})
	if !errors.Is(err, applyErr) {
		t.Fatalf("apply error = %v, want it to wrap the callback error", err)
	}
	if IsTransportConflict(err) {
		t.Fatalf("apply failure must not be reported as a transport conflict: %v", err)
	}
	if res != (protocol.Result{}) {
		t.Fatalf("apply failure returned a non-zero decision/result %+v; callers could mistake it for a committed success", res)
	}
	after, err := s.GetBoot(ctx, "node-a")
	if err != nil {
		t.Fatalf("GetBoot after rollback: %v", err)
	}
	if after != before {
		t.Fatalf("failed apply advanced the high-water: before=%+v after=%+v", before, after)
	}
	if _, ok, err := s.SeqLookup(ctx, "node-a", 3, testBootB, 1); err != nil || ok {
		t.Fatalf("failed apply left seq dedupe state (ok=%v, err=%v)", ok, err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM boot_registry WHERE node_id = ? AND boot_gen = 3`, "node-a"); got != 0 {
		t.Fatalf("failed apply left %d boot_registry rows, want 0", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM report_activity WHERE report_id = 'rollback-report'`); got != 0 {
		t.Fatalf("failed apply persisted %d payload rows, want 0", got)
	}

	// The agent retries the same attempt; now it commits the high-water and the
	// payload together.
	res, err = s.ApplyTransport(ctx, "node-a", attempt, "fp-3-1", nil)
	if err != nil || res.Outcome != protocol.Accepted {
		t.Fatalf("retry = (%q, %v), want accepted", res.Outcome, err)
	}
	after, err = s.GetBoot(ctx, "node-a")
	if err != nil {
		t.Fatalf("GetBoot after retry: %v", err)
	}
	if after != (protocol.Boot{HighestGen: 3, BootID: testBootB, LastSeq: 1, LastFingerprint: "fp-3-1"}) {
		t.Fatalf("high-water after retry = %+v", after)
	}
}

func TestDedupeNonceAndReport(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	mustCreateNode(t, s, "node-a", "event-a", NodeClassLinuxVPS)

	status, err := checkOrInsertNonce(ctx, s.db, "node-a", "nonce-1", "fp-nonce-1", 100)
	if err != nil || status != NonceNew {
		t.Fatalf("first nonce = (%q, %v), want new", status, err)
	}
	status, err = checkOrInsertNonce(ctx, s.db, "node-a", "nonce-1", "fp-nonce-1", 200)
	if err != nil || status != NonceExactRetry {
		t.Fatalf("exact nonce retry = (%q, %v), want exact_retry", status, err)
	}
	status, err = checkOrInsertNonce(ctx, s.db, "node-a", "nonce-1", "fp-nonce-1-other", 300)
	if err != nil || status != NonceReuse {
		t.Fatalf("nonce reuse = (%q, %v), want nonce_reuse", status, err)
	}
	seen, err := s.NonceSeen(ctx, "node-a", "nonce-1")
	if err != nil || !seen {
		t.Fatalf("NonceSeen = (%v, %v), want true", seen, err)
	}
	seen, err = s.NonceSeen(ctx, "node-a", "nonce-2")
	if err != nil || seen {
		t.Fatalf("NonceSeen(other) = (%v, %v), want false", seen, err)
	}
	fingerprint, ok, err := s.NonceFingerprint(ctx, "node-a", "nonce-1")
	if err != nil || !ok || fingerprint != "fp-nonce-1" {
		t.Fatalf("NonceFingerprint = (%q, %v, %v), want fp-nonce-1", fingerprint, ok, err)
	}

	if _, ok, err := s.ReportSeen(ctx, "node-a", "report-1"); err != nil || ok {
		t.Fatalf("ReportSeen before insert = (ok=%v, err=%v), want false", ok, err)
	}
	reportStatus, err := checkOrInsertReport(ctx, s.db, "node-a", "report-1", "sha-report-1", 300)
	if err != nil || reportStatus != ReportNew {
		t.Fatalf("first report = (%q, %v), want new", reportStatus, err)
	}
	reportStatus, err = checkOrInsertReport(ctx, s.db, "node-a", "report-1", "sha-report-1", 400)
	if err != nil || reportStatus != ReportDuplicate {
		t.Fatalf("duplicate report = (%q, %v), want duplicate", reportStatus, err)
	}
	stored, ok, err := s.ReportSeen(ctx, "node-a", "report-1")
	if err != nil || !ok || stored != "sha-report-1" {
		t.Fatalf("ReportSeen = (%q, %v, %v), want sha-report-1", stored, ok, err)
	}
	// A reused report_id with different content is a report_conflict; the
	// original hash and the last_received_at of the previous accepted retry are
	// never overwritten by the conflicting request.
	beforeLast := queryInt(t, s, `SELECT last_received_at FROM report_dedupe WHERE node_id = ? AND report_id = ?`, "node-a", "report-1")
	reportStatus, err = checkOrInsertReport(ctx, s.db, "node-a", "report-1", "sha-report-1-other", 500)
	if err != nil || reportStatus != ReportConflict {
		t.Fatalf("conflicting report = (%q, %v), want conflict", reportStatus, err)
	}
	stored, ok, err = s.ReportSeen(ctx, "node-a", "report-1")
	if err != nil || !ok || stored != "sha-report-1" {
		t.Fatalf("ReportSeen after conflict = (%q, %v, %v), want the original hash", stored, ok, err)
	}
	if afterLast := queryInt(t, s, `SELECT last_received_at FROM report_dedupe WHERE node_id = ? AND report_id = ?`, "node-a", "report-1"); afterLast != beforeLast {
		t.Fatalf("report_conflict changed last_received_at: before=%d after=%d", beforeLast, afterLast)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM report_dedupe WHERE node_id = ? AND report_id = ?`, "node-a", "report-1"); got != 1 {
		t.Fatalf("report_dedupe rows = %d, want 1", got)
	}
}

func TestRestartPersistence(t *testing.T) {
	path := tempStorePath(t)
	ctx := testContext()
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	mustCreateNode(t, s, "node-a", "event-a", NodeClassLinuxVPS)
	mustPutBoot(t, s, "node-a", 3, testBootA, 7, "fp-3-7")
	if _, err := checkOrInsertNonce(ctx, s.db, "node-a", "nonce-1", "fp-nonce-1", 100); err != nil {
		t.Fatalf("CheckOrInsertNonce: %v", err)
	}
	if _, err := checkOrInsertReport(ctx, s.db, "node-a", "report-1", "sha-report-1", 200); err != nil {
		t.Fatalf("CheckOrInsertReport: %v", err)
	}
	if _, err := s.AppendLedger(ctx, 300, "node_enrolled", "node-a", "detail-1"); err != nil {
		t.Fatalf("AppendLedger: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("Close reopened: %v", err)
		}
	}()
	version, err := reopened.SchemaVersion(ctx)
	if err != nil || version != SchemaVersion {
		t.Fatalf("SchemaVersion after restart = (%d, %v), want %d", version, err, SchemaVersion)
	}
	boot, err := reopened.GetBoot(ctx, "node-a")
	if err != nil {
		t.Fatalf("GetBoot after restart: %v", err)
	}
	if boot != (protocol.Boot{HighestGen: 3, BootID: testBootA, LastSeq: 7, LastFingerprint: "fp-3-7"}) {
		t.Fatalf("high-water after restart = %+v", boot)
	}
	if seen, err := reopened.NonceSeen(ctx, "node-a", "nonce-1"); err != nil || !seen {
		t.Fatalf("NonceSeen after restart = (%v, %v), want true", seen, err)
	}
	if _, ok, err := reopened.ReportSeen(ctx, "node-a", "report-1"); err != nil || !ok {
		t.Fatalf("ReportSeen after restart = (ok=%v, err=%v), want true", ok, err)
	}
	if err := reopened.VerifyChain(ctx); err != nil {
		t.Fatalf("VerifyChain after restart: %v", err)
	}
	// The persisted seq_dedupe state still classifies the retry as a duplicate.
	res, err := reopened.ApplyTransport(ctx, "node-a",
		protocol.Attempt{Gen: 3, BootID: testBootA, Seq: 7, Fingerprint: "fp-3-7"}, "fp-3-7",
		func(tx *Tx) error {
			t.Fatal("duplicate after restart must not apply payload")
			return nil
		})
	if err != nil || res.Outcome != protocol.Duplicate {
		t.Fatalf("post-restart retry = (%q, %v), want duplicate", res.Outcome, err)
	}
}

func TestLedgerChainAndTamper(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()

	if err := s.VerifyChain(ctx); err != nil {
		t.Fatalf("VerifyChain on empty ledger: %v", err)
	}
	genesis := strings.Repeat("0", 64)
	h1, err := s.AppendLedger(ctx, 1000, "node_enrolled", "node-a", "detail-a")
	if err != nil {
		t.Fatalf("AppendLedger: %v", err)
	}
	want1 := sha256Hex(genesis + "|1000|node_enrolled|node-a|detail-a")
	if h1 != want1 {
		t.Fatalf("genesis entry hash = %s, want %s", h1, want1)
	}
	h2, err := s.AppendLedger(ctx, 1001, "key_rotated", "node-a", "detail-b")
	if err != nil {
		t.Fatalf("AppendLedger: %v", err)
	}
	if h2 == h1 {
		t.Fatal("chained entry hash must differ from its predecessor")
	}
	var prev string
	if err := s.db.QueryRowContext(ctx,
		`SELECT prev_hash FROM security_ledger ORDER BY seq ASC LIMIT 1`).Scan(&prev); err != nil {
		t.Fatalf("read genesis prev_hash: %v", err)
	}
	if prev != genesis {
		t.Fatalf("genesis prev_hash = %q, want 64 zeros", prev)
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT prev_hash FROM security_ledger ORDER BY seq DESC LIMIT 1`).Scan(&prev); err != nil {
		t.Fatalf("read head prev_hash: %v", err)
	}
	if prev != h1 {
		t.Fatalf("second entry prev_hash = %q, want %q", prev, h1)
	}
	if err := s.VerifyChain(ctx); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}

	// Tampering with a committed row must break verification.
	if _, err := s.db.ExecContext(ctx,
		`UPDATE security_ledger SET detail_sha256 = 'tampered' WHERE seq = 2`); err != nil {
		t.Fatalf("tamper ledger: %v", err)
	}
	err = s.VerifyChain(ctx)
	if !errors.Is(err, ErrLedgerTampered) {
		t.Fatalf("VerifyChain after tamper = %v, want ErrLedgerTampered", err)
	}
	var verification *LedgerVerificationError
	if !errors.As(err, &verification) {
		t.Fatalf("VerifyChain error = %T, want *LedgerVerificationError", err)
	}
	if verification.Seq != 2 {
		t.Fatalf("tampered entry reported as seq %d, want 2", verification.Seq)
	}
}

func TestRetentionSweep(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	mustCreateNode(t, s, "node-a", "event-a", NodeClassLinuxVPS)
	now := int64(1_700_000_000)

	type nonceCase struct {
		nonce string
		at    int64
	}
	nonces := []nonceCase{
		{"old-nonce", now - 25*60*60},
		{"new-nonce", now - 1*60*60},
	}
	for _, tc := range nonces {
		if _, err := checkOrInsertNonce(ctx, s.db, "node-a", tc.nonce, "fp", tc.at); err != nil {
			t.Fatalf("CheckOrInsertNonce(%q): %v", tc.nonce, err)
		}
	}
	type reportCase struct {
		reportID string
		at       int64
	}
	reports := []reportCase{
		{"old-report", now - 9*24*60*60},
		{"new-report", now - 1*24*60*60},
	}
	for _, tc := range reports {
		if _, err := checkOrInsertReport(ctx, s.db, "node-a", tc.reportID, "sha", tc.at); err != nil {
			t.Fatalf("CheckOrInsertReport(%q): %v", tc.reportID, err)
		}
	}
	for _, tc := range []struct {
		reportID string
		at       int64
	}{
		{"old-activity", now - 31*24*60*60},
		{"new-activity", now - 1*24*60*60},
	} {
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO report_activity(node_id, report_id, collected_at, received_at) VALUES(?, ?, ?, ?)`,
			"node-a", tc.reportID, 1, tc.at); err != nil {
			t.Fatalf("insert report_activity(%q): %v", tc.reportID, err)
		}
	}
	// seq_dedupe is intentionally outside the age sweep (bounded by read limit).
	if err := recordSeq(ctx, s.db, "node-a", 1, testBootA, 1, "fp-old-seq", now-100*24*60*60); err != nil {
		t.Fatalf("RecordSeq: %v", err)
	}

	deleted, err := s.RunRetention(ctx, now)
	if err != nil {
		t.Fatalf("RunRetention: %v", err)
	}
	wantDeleted := map[string]int64{
		"nonce_dedupe":    1,
		"report_dedupe":   1,
		"report_activity": 1,
	}
	if !maps.Equal(deleted, wantDeleted) {
		t.Fatalf("deleted = %v, want %v", deleted, wantDeleted)
	}
	for _, tc := range nonces {
		seen, err := s.NonceSeen(ctx, "node-a", tc.nonce)
		if err != nil {
			t.Fatalf("NonceSeen(%q): %v", tc.nonce, err)
		}
		want := tc.nonce != "old-nonce"
		if seen != want {
			t.Fatalf("NonceSeen(%q) = %v, want %v", tc.nonce, seen, want)
		}
	}
	for _, tc := range reports {
		_, ok, err := s.ReportSeen(ctx, "node-a", tc.reportID)
		if err != nil {
			t.Fatalf("ReportSeen(%q): %v", tc.reportID, err)
		}
		want := tc.reportID != "old-report"
		if ok != want {
			t.Fatalf("ReportSeen(%q) = %v, want %v", tc.reportID, ok, want)
		}
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM report_activity WHERE report_id = 'old-activity'`); got != 0 {
		t.Fatalf("old report_activity rows = %d, want 0", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM report_activity WHERE report_id = 'new-activity'`); got != 1 {
		t.Fatalf("recent report_activity rows = %d, want 1", got)
	}
	// seq_dedupe survives the sweep so exact-retry classification is not lost.
	if fingerprint, ok, err := s.SeqLookup(ctx, "node-a", 1, testBootA, 1); err != nil || !ok || fingerprint != "fp-old-seq" {
		t.Fatalf("seq dedupe after retention = (%q, %v, %v), want preserved", fingerprint, ok, err)
	}

	// A second sweep on an already-clean window deletes nothing.
	deleted, err = s.RunRetention(ctx, now)
	if err != nil {
		t.Fatalf("second RunRetention: %v", err)
	}
	for table, count := range deleted {
		if count != 0 {
			t.Fatalf("second sweep deleted %d rows from %s, want 0", count, table)
		}
	}
}

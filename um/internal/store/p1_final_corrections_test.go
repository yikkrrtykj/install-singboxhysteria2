package store

import (
	"context"
	"strings"
	"testing"
)

// Final B1 corrections: these regression tests were first run against HEAD
// 9ac492ad (before the immediate/future mapping fix) and captured in
// um127-round5-evidence/final-red.log. They remain as regression tests.

func TestMappingBackdateRelativeToNowRejected(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := context.Background()
	mustCreateNode(t, s, "win-a", "event-a", NodeClassWindowsTerminal)
	mustCreateNode(t, s, "linux-a", "event-a", NodeClassLinuxVPS)
	const mappingNow int64 = 1_000_000
	entries := map[string]string{RouteTokenAReality: "linux-a"}
	if err := s.createMappingVersion(ctx, "event-a", "win-a", 1, mappingNow, "admin", entries, mappingNow); err != nil {
		t.Fatalf("v1 immediate: %v", err)
	}
	// Later clock: effective time is later than v1's effective time but still in
	// the past relative to write time; accepting it would retroactively change
	// already-attributed history.
	if err := s.createMappingVersion(ctx, "event-a", "win-a", 2, mappingNow+500, "admin", entries, mappingNow+1000); err == nil {
		t.Fatal("mapping version with effective time before write clock was accepted (backdated history)")
	}
}

// TestStrictUpdateConstraints rejects wrong-typed/out-of-range UPDATEs on
// existing rows and verifies the failed statement did not silently coerce or
// replace the stored value. This cannot pass via a primary-key conflict.
func TestStrictUpdateConstraints(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := context.Background()
	mustCreateNode(t, s, "node-a", "event-a", NodeClassLinuxVPS)
	mustPutBoot(t, s, "node-a", 7, "b", 7, "fp")
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO seq_dedupe(node_id,boot_gen,boot_id,seq,fingerprint,received_at) VALUES('node-a',7,'b',7,'fp',1)`); err != nil {
		t.Fatalf("seed seq: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO boot_registry(node_id,boot_gen,boot_id,first_seen_at,last_seen_at,last_seq,state) VALUES('node-a',7,'b',1,1,7,'active')`); err != nil {
		t.Fatalf("seed registry: %v", err)
	}

	cases := []struct {
		name      string
		stmt      string
		table     string
		col       string
		where     string
		wantError string
	}{
		{"node_boot REAL update", `UPDATE node_boot SET highest_gen=1.5 WHERE node_id='node-a'`, "node_boot", "highest_gen", "node_id='node-a'", "cannot store"},
		{"node_boot nonnumeric TEXT update", `UPDATE node_boot SET highest_gen='x' WHERE node_id='node-a'`, "node_boot", "highest_gen", "node_id='node-a'", "cannot store"},
		{"node_boot negative update", `UPDATE node_boot SET last_seq=-1 WHERE node_id='node-a'`, "node_boot", "last_seq", "node_id='node-a'", "CHECK constraint"},
		{"node_boot over-max update", `UPDATE node_boot SET last_seq=9223372036854775807 WHERE node_id='node-a'`, "node_boot", "last_seq", "node_id='node-a'", "CHECK constraint"},
		{"seq_dedupe REAL update", `UPDATE seq_dedupe SET boot_gen=2.5 WHERE node_id='node-a' AND boot_gen=7`, "seq_dedupe", "boot_gen", "node_id='node-a' AND boot_gen=7", "cannot store"},
		{"seq_dedupe negative update", `UPDATE seq_dedupe SET seq=-1 WHERE node_id='node-a' AND boot_gen=7`, "seq_dedupe", "seq", "node_id='node-a' AND boot_gen=7", "CHECK constraint"},
		{"boot_registry REAL update", `UPDATE boot_registry SET last_seen_at=1.5 WHERE node_id='node-a'`, "boot_registry", "last_seen_at", "node_id='node-a'", "cannot store"},
		{"boot_registry negative update", `UPDATE boot_registry SET last_seq=-1 WHERE node_id='node-a'`, "boot_registry", "last_seq", "node_id='node-a'", "CHECK constraint"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := queryString(t, s, `SELECT typeof(`+tc.col+`) || ':' || CAST(`+tc.col+` AS TEXT) FROM `+tc.table+` WHERE `+tc.where)
			if _, err := s.db.ExecContext(ctx, tc.stmt); err == nil {
				t.Fatalf("UPDATE accepted invalid typed/range value: %s", tc.stmt)
			} else if !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("error = %v, want category %q (not a PK/other conflict)", err, tc.wantError)
			}
			after := queryString(t, s, `SELECT typeof(`+tc.col+`) || ':' || CAST(`+tc.col+` AS TEXT) FROM `+tc.table+` WHERE `+tc.where)
			if after != before {
				t.Fatalf("failed UPDATE changed stored value/type: before=%q after=%q", before, after)
			}
			if !strings.HasPrefix(after, "integer:") {
				t.Fatalf("stored type after failed UPDATE = %q, want integer", after)
			}
		})
	}
}

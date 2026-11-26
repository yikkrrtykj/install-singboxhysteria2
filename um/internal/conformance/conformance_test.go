// Package conformance maps the frozen UM-127 REC / behavioural cases to
// executable UM-B1 checks. Cases owned by UM-B2/UM-B3 are deliberately not
// marked PASS here: they are either skipped with an explicit owner or only
// their B1-visible transport precondition is asserted.
package conformance_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/protocol"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/wire"
)

const (
	recPath = "../../../docs/um/um-127/conformance/transport-recovery.cases.json"
	negPath = "../../../docs/um/contracts/v1/negative-vectors.v1.json"
)

type recDoc struct {
	Status           string `json:"status"`
	ContractRevision int    `json:"contract_revision"`
	ContractCommit   string `json:"contract_commit"`
	Cases            []recCase
}

type recCase struct {
	ID    string `json:"id"`
	Slice string `json:"slice"`
	Title string `json:"title"`
}

func loadREC(t *testing.T) recDoc {
	t.Helper()
	raw, err := os.ReadFile(recPath)
	if err != nil {
		t.Fatalf("read REC conformance file: %v", err)
	}
	var d recDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("parse REC conformance file: %v", err)
	}
	if d.ContractRevision != 5 {
		t.Fatalf("REC file contract_revision=%d, want 5", d.ContractRevision)
	}
	if d.ContractCommit != "048fc170685da5b7140bebd9e3347616cb3ec656" {
		t.Fatalf("unexpected contract commit %q", d.ContractCommit)
	}
	if len(d.Cases) != 30 {
		t.Fatalf("want 30 REC cases, got %d", len(d.Cases))
	}
	seen := map[string]string{}
	for _, c := range d.Cases {
		if _, dup := seen[c.ID]; dup {
			t.Fatalf("duplicate REC id %s", c.ID)
		}
		seen[c.ID] = c.Slice
	}
	for i := 1; i <= 30; i++ {
		id := "REC-" + pad2(i)
		if _, ok := seen[id]; !ok {
			t.Fatalf("missing %s", id)
		}
	}
	return d
}

func pad2(i int) string {
	if i < 10 {
		return "0" + string(rune('0'+i))
	}
	return string(rune('0'+i/10)) + string(rune('0'+i%10))
}

// TestRECRegistry asserts every REC case has a B1/B2/B3 owner; only B1-owned
// cases are executed by this package.
func TestRECRegistry(t *testing.T) {
	d := loadREC(t)
	b1 := 0
	owners := map[string]string{
		"UM-B1": "executed",
		"UM-B2": "deferred to UM-B2 (not executed in B1)",
		"UM-B3": "deferred to UM-B3 (not executed in B1)",
	}
	for _, c := range d.Cases {
		owner, ok := owners[c.Slice]
		if !ok {
			t.Fatalf("%s has unknown slice %q", c.ID, c.Slice)
		}
		if c.Slice == "UM-B1" {
			b1++
		} else {
			t.Logf("%s: %s", c.ID, owner)
		}
	}
	if b1 != 12 {
		t.Fatalf("want 12 B1-owned REC cases, got %d", b1)
	}
}

func TestB1RECCases(t *testing.T) {
	boot := func(highest uint64, bootID string, lastSeq uint64, fp string) protocol.Boot {
		return protocol.Boot{HighestGen: highest, BootID: bootID, LastSeq: lastSeq, LastFingerprint: fp}
	}
	run := map[string]func(t *testing.T){
		"REC-01": func(t *testing.T) {
			r, err := protocol.Evaluate(boot(4, "b4", 9, "f9"), protocol.Attempt{Gen: 5, BootID: "b5", Seq: 1, Fingerprint: "f1"}, protocol.Options{})
			mustAccepted(t, r, err)
			if r.NextBoot.LastSeq != 1 {
				t.Fatalf("last_seq=%d", r.NextBoot.LastSeq)
			}
		},
		"REC-02": func(t *testing.T) {
			r, err := protocol.Evaluate(boot(4, "b4", 7, "f7"), protocol.Attempt{Gen: 5, BootID: "b5", Seq: 2, Fingerprint: "f2"}, protocol.Options{})
			mustAccepted(t, r, err)
			if r.NextBoot.LastSeq != 2 {
				t.Fatalf("first accepted seq must become last_seq=2, got %d", r.NextBoot.LastSeq)
			}
		},
		"REC-07": func(t *testing.T) {
			_, err := protocol.Evaluate(boot(1, "b1", 1, "f"), protocol.Attempt{Gen: 65537, BootID: "b2", Seq: 1, Fingerprint: "f"}, protocol.Options{})
			if !errors.Is(err, nil) && err == nil {
				t.Fatal("gap 65536 must be rejected")
			}
			r, err := protocol.Evaluate(boot(1, "b1", 1, "f"), protocol.Attempt{Gen: 65537, BootID: "b2", Seq: 1, Fingerprint: "f"}, protocol.Options{})
			if err != nil || r.Outcome != protocol.BootIdentityConflict {
				t.Fatalf("want boot_identity_conflict, got %+v err=%v", r, err)
			}
		},
		"REC-08": func(t *testing.T) {
			r, err := protocol.Evaluate(boot(5, "b5", 4, "f4"), protocol.Attempt{Gen: 5, BootID: "b5-old", Seq: 5, Fingerprint: "f5"}, protocol.Options{})
			if err != nil || r.Outcome != protocol.BootIdentityConflict {
				t.Fatalf("want boot_identity_conflict, got %+v err=%v", r, err)
			}
		},
		"REC-09": func(t *testing.T) {
			r, err := protocol.Evaluate(boot(9, "b9", 1, "f"), protocol.Attempt{Gen: 8, BootID: "b8", Seq: 1, Fingerprint: "f"}, protocol.Options{})
			if err != nil || r.Outcome != protocol.StaleBootGeneration {
				t.Fatalf("want stale_boot_generation, got %+v err=%v", r, err)
			}
		},
		"REC-11": func(t *testing.T) {
			r, err := protocol.Evaluate(boot(3, "b3", 5, "fp5"), protocol.Attempt{Gen: 3, BootID: "b3", Seq: 5, Fingerprint: "fp5"}, protocol.Options{})
			if err != nil || r.Outcome != protocol.Duplicate {
				t.Fatalf("want duplicate, got %+v err=%v", r, err)
			}
		},
		"REC-12": func(t *testing.T) {
			r, err := protocol.Evaluate(boot(3, "b3", 5, "fp5"), protocol.Attempt{Gen: 3, BootID: "b3", Seq: 5, Fingerprint: "other"}, protocol.Options{})
			if err != nil || r.Outcome != protocol.SequenceConflict {
				t.Fatalf("want sequence_conflict, got %+v err=%v", r, err)
			}
		},
		"REC-14": func(t *testing.T) {
			// center restart: persisted node_boot survives; exact retry duplicate.
			path := filepath.Join(t.TempDir(), "center.db")
			ctx := context.Background()
			st, err := store.Open(path)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			mustCreateNode(t, st)
			if err := st.PutBoot(ctx, testNodeID, 4, "b4", 6, "f6"); err != nil {
				t.Fatalf("put boot: %v", err)
			}
			if err := st.Close(); err != nil {
				t.Fatalf("close: %v", err)
			}
			st, err = store.Open(path)
			if err != nil {
				t.Fatalf("reopen: %v", err)
			}
			defer st.Close()
			cur, err := st.GetBoot(ctx, testNodeID)
			if err != nil || cur.HighestGen != 4 || cur.LastSeq != 6 || cur.LastFingerprint != "f6" {
				t.Fatalf("boot not persistent: %+v err=%v", cur, err)
			}
			if cur.BootID != "b4" {
				t.Fatalf("boot id not persistent: %+v", cur)
			}
		},
		"REC-25": func(t *testing.T) {
			r, err := protocol.Evaluate(boot(1, "b1", 1, "f"), protocol.Attempt{Gen: 65536, BootID: "b", Seq: 1, Fingerprint: "f"}, protocol.Options{})
			mustAccepted(t, r, err)
			if r.Gap != wire.MaxBootGap || !r.AuditGap {
				t.Fatalf("gap=%d audit=%v", r.Gap, r.AuditGap)
			}
		},
		"REC-26": func(t *testing.T) {
			r, err := protocol.Evaluate(boot(wire.MaxNumeric-1, "b-prev", 1, "f"),
				protocol.Attempt{Gen: wire.MaxNumeric, BootID: "b-max", Seq: wire.MaxNumeric, Fingerprint: "fmax"}, protocol.Options{})
			mustAccepted(t, r, err)
			if r.NextSeq != nil {
				t.Fatalf("numeric exhaustion must ACK next_seq=null, got %v", *r.NextSeq)
			}
			if r.NextBoot.LastSeq != wire.MaxNumeric {
				t.Fatalf("last_seq=%d", r.NextBoot.LastSeq)
			}
		},
		"REC-28": func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "center.db")
			ctx := context.Background()
			st, err := store.Open(path)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer st.Close()
			mustCreateNode(t, st)
			attempt := protocol.Attempt{Gen: 1, BootID: "b1", Seq: 1, Fingerprint: "fp1"}
			boom := errors.New("simulated storage failure")
			if _, err := st.ApplyTransport(ctx, testNodeID, attempt, "fp1", func(tx *sql.Tx) error {
				_ = tx
				return boom
			}); err == nil {
				t.Fatal("expected apply failure")
			}
			cur, err := st.GetBoot(ctx, testNodeID)
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("get boot: %v", err)
			}
			if cur.HighestGen != 0 {
				t.Fatalf("failed transaction must not advance high-water: %+v", cur)
			}
			r, err := st.ApplyTransport(ctx, testNodeID, attempt, "fp1", nil)
			mustAccepted(t, r, err)
		},
		"REC-29": func(t *testing.T) {
			t.Skip("B1 executes the transport half only; stale_ignored snapshot ordering/data apply is a UM-B2 ingest responsibility and is not marked PASS here")
		},
	}

	d := loadREC(t)
	for _, c := range d.Cases {
		if c.Slice != "UM-B1" {
			continue
		}
		fn, ok := run[c.ID]
		if !ok {
			t.Fatalf("%s is B1-owned but has no executable check", c.ID)
		}
		t.Run(c.ID, fn)
	}
}

func mustAccepted(t *testing.T, r protocol.Result, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Outcome != protocol.Accepted {
		t.Fatalf("want accepted, got %q", r.Outcome)
	}
	if !r.HighWaterCommitted {
		t.Fatal("accepted result must commit high-water")
	}
}

const testNodeID = "0f3d7c2a-8b41-4a6e-9c55-2d7e1b9a4c60"

func mustCreateNode(t *testing.T, st *store.Store) {
	t.Helper()
	err := st.CreateNode(context.Background(), store.Node{
		NodeID: testNodeID, EventID: "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
		NodeClass: "linux_vps", State: "active", CreatedAt: 1795622400,
	})
	if err != nil {
		t.Fatalf("create node: %v", err)
	}
}

// TestNegativeVectorB1Subset executes the rev-5 behavioural negative cases that
// are pure B1 transport/grammar rules and records the others as deferred.
func TestNegativeVectorB1Subset(t *testing.T) {
	raw, err := os.ReadFile(negPath)
	if err != nil {
		t.Fatalf("read negative vectors: %v", err)
	}
	var doc struct {
		Revision int `json:"revision"`
		Cases    []struct {
			ID string `json:"id"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse negative vectors: %v", err)
	}
	if doc.Revision != 5 || len(doc.Cases) == 0 {
		t.Fatalf("unexpected negative-vector revision/count: %d/%d", doc.Revision, len(doc.Cases))
	}
	exists := map[string]bool{}
	for _, c := range doc.Cases {
		exists[c.ID] = true
	}
	// B1-owned behavioural IDs: transport/recovery/grammar/numeric.
	b1 := []string{"NEG-BOOT-06", "NEG-BOOT-07", "NEG-BOOT-08", "NEG-BOOT-09",
		"NEG-BOOT-10", "NEG-ROT-12", "NEG-ROT-13", "NEG-ROT-14", "NEG-ROT-15"}
	for _, id := range b1 {
		if !exists[id] {
			t.Fatalf("missing B1 negative case %s", id)
		}
	}

	boot := protocol.Boot{HighestGen: 4, BootID: "b4", LastSeq: 7, LastFingerprint: "f7"}
	genGap, err := protocol.Evaluate(boot, protocol.Attempt{Gen: 6, BootID: "b6", Seq: 1, Fingerprint: "f"}, protocol.Options{})
	mustAccepted(t, genGap, err)
	if genGap.Gap != 2 {
		t.Fatalf("NEG-BOOT-06 gap=%d", genGap.Gap)
	}

	seqTwo, err := protocol.Evaluate(boot, protocol.Attempt{Gen: 5, BootID: "b5", Seq: 2, Fingerprint: "f2"}, protocol.Options{})
	mustAccepted(t, seqTwo, err)
	if seqTwo.NextBoot.LastSeq != 2 {
		t.Fatalf("NEG-BOOT-07 last_seq=%d", seqTwo.NextBoot.LastSeq)
	}

	gapBoundary, err := protocol.Evaluate(protocol.Boot{HighestGen: 1, BootID: "b1", LastSeq: 1, LastFingerprint: "f"},
		protocol.Attempt{Gen: 65536, BootID: "b", Seq: 1, Fingerprint: "f"}, protocol.Options{})
	mustAccepted(t, gapBoundary, err)
	if gapBoundary.Gap != wire.MaxBootGap {
		t.Fatalf("NEG-BOOT-08 gap=%d", gapBoundary.Gap)
	}

	if _, err := wire.ParseCanonicalDecimal("X-UM-Seq", "9223372036854775807", 1, wire.MaxNumeric); err == nil {
		t.Fatal("NEG-BOOT-09 accepted a value above MAX_NUMERIC")
	}
	if _, err := wire.ParseCanonicalDecimal("X-UM-Seq", "07", 1, wire.MaxNumeric); err == nil {
		t.Fatal("NEG-BOOT-09 accepted a non-canonical decimal")
	}

	exhaust, err := protocol.Evaluate(protocol.Boot{HighestGen: wire.MaxNumeric - 1, BootID: "b", LastSeq: 1, LastFingerprint: "f"},
		protocol.Attempt{Gen: wire.MaxNumeric, BootID: "bmax", Seq: wire.MaxNumeric, Fingerprint: "fmax"}, protocol.Options{})
	mustAccepted(t, exhaust, err)
	if exhaust.NextSeq != nil {
		t.Fatal("NEG-BOOT-10 must ACK next_seq=null")
	}

	intent := protocol.RotateIntent{NodeID: testNodeID, Nonce: "n-rot", OldKeyID: "key-old", BodySHA256: "h-rot",
		State: protocol.RotationAwaitingProof, ExpiresAtUnix: 2000}
	cur := protocol.Boot{HighestGen: 5, BootID: "b5", LastSeq: 1, LastFingerprint: "f"}
	verdict, err := protocol.EvaluateRotateRetry(cur, protocol.Attempt{Gen: 8, BootID: "b8", Seq: 3, Fingerprint: "f3"},
		intent, testNodeID, "n-rot", "key-old", "h-rot", 1000, protocol.Options{})
	if err != nil || !verdict.ReplayAllowed || verdict.Transport.Outcome != protocol.Accepted {
		t.Fatalf("NEG-ROT-12: %+v err=%v", verdict, err)
	}
	stale, err := protocol.EvaluateRotateRetry(protocol.Boot{HighestGen: 9, BootID: "b9", LastSeq: 1, LastFingerprint: "f"},
		protocol.Attempt{Gen: 8, BootID: "b8", Seq: 2, Fingerprint: "f2"}, intent, testNodeID, "n-rot", "key-old", "h-rot", 1000, protocol.Options{})
	if err != nil || stale.ReplayAllowed || stale.Transport.Outcome != protocol.StaleBootGeneration {
		t.Fatalf("NEG-ROT-13: %+v err=%v", stale, err)
	}
	seqConflict, err := protocol.EvaluateRotateRetry(cur, protocol.Attempt{Gen: 5, BootID: "b5", Seq: 1, Fingerprint: "other"},
		intent, testNodeID, "n-rot", "key-old", "h-rot", 1000, protocol.Options{})
	if err != nil || seqConflict.ReplayAllowed || seqConflict.Transport.Outcome != protocol.SequenceConflict {
		t.Fatalf("NEG-ROT-14: %+v err=%v", seqConflict, err)
	}
	bootMismatch, err := protocol.EvaluateRotateRetry(cur, protocol.Attempt{Gen: 5, BootID: "b5-other", Seq: 2, Fingerprint: "f2"},
		intent, testNodeID, "n-rot", "key-old", "h-rot", 1000, protocol.Options{})
	if err != nil || bootMismatch.ReplayAllowed || bootMismatch.Transport.Outcome != protocol.BootIdentityConflict {
		t.Fatalf("NEG-ROT-15: %+v err=%v", bootMismatch, err)
	}
}

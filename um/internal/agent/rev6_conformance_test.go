package agent

// Executable rev-6 contract conformance (AMEND-REC-27-A..F).
//
// The fixture is the normative machine fixture
// docs/um/contracts/v1/power-loss-generation.rev6.json. These tests run the
// real HTTP center + SQLite + agent persisted state. Process-level crash
// injection for case B is additionally covered by
// internal/agentintegration/crash_recovery_test.go.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

const rev6FixturePath = "../../../docs/um/contracts/v1/power-loss-generation.rev6.json"

type rev6Doc struct {
	Schema               string     `json:"schema"`
	Status               string     `json:"status"`
	Normative            bool       `json:"normative"`
	ContractRevision     int        `json:"contract_revision"`
	BaseContractRevision int        `json:"base_contract_revision"`
	BaseContractCommit   string     `json:"base_contract_commit"`
	MaxBootGap           uint64     `json:"max_boot_gap"`
	Cases                []rev6Case `json:"cases"`
}

type rev6Case struct {
	ID       string `json:"id"`
	Slice    string `json:"slice"`
	Kind     string `json:"kind"`
	Restart  bool   `json:"restart"`
	Owner    string `json:"owner_slice"`
	Executed string `json:"executed_by"`
	Setup    struct {
		Center struct {
			HighestGen      uint64            `json:"highest_gen"`
			BootID          string            `json:"boot_id"`
			LastSeq         uint64            `json:"last_seq"`
			LastFingerprint string            `json:"last_fingerprint"`
			ReportDedupe    map[string]string `json:"report_dedupe"`
		} `json:"center"`
		Agent struct {
			Generation   uint64 `json:"generation"`
			BootID       string `json:"boot_id"`
			NextSeq      uint64 `json:"next_seq"`
			SpoolRecords int    `json:"spool_records"`
		} `json:"agent"`
	} `json:"setup"`
	Attempt struct {
		Endpoint    string `json:"endpoint"`
		Gen         uint64 `json:"gen"`
		BootID      string `json:"boot_id"`
		Seq         uint64 `json:"seq"`
		Fingerprint string `json:"fingerprint"`
		ReportID    string `json:"report_id"`
	} `json:"attempt"`
	Expected struct {
		Generation  uint64 `json:"generation"`
		BootID      string `json:"boot_id"`
		HTTPStatus  int    `json:"http_status"`
		Result      string `json:"result"`
		Error       string `json:"error"`
		CenterState struct {
			HighestGen uint64 `json:"highest_gen"`
			BootID     string `json:"boot_id"`
			LastSeq    uint64 `json:"last_seq"`
		} `json:"center_state"`
		ACK struct {
			NextSeq uint64 `json:"next_seq"`
		} `json:"ack"`
		Gap             uint64 `json:"gap"`
		GapAudit        string `json:"gap_audit"`
		Data            string `json:"data"`
		StateChange     string `json:"state_change"`
		SpoolChange     string `json:"spool_change"`
		NetworkRequired bool   `json:"network_required"`
	} `json:"expected"`
}

func loadRev6(t *testing.T) rev6Doc {
	t.Helper()
	raw, err := os.ReadFile(rev6FixturePath)
	if err != nil {
		t.Fatalf("read rev-6 fixture %s: %v", rev6FixturePath, err)
	}
	var d rev6Doc
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("parse rev-6 fixture: %v", err)
	}
	if d.Schema != "um-node-protocol-power-loss-generation/v6" ||
		d.Status != "NORMATIVE_REV6" || !d.Normative ||
		d.ContractRevision != 6 || d.BaseContractRevision != 5 ||
		d.BaseContractCommit != "048fc170685da5b7140bebd9e3347616cb3ec656" ||
		d.MaxBootGap != 65535 || len(d.Cases) != 6 {
		t.Fatalf("rev-6 fixture metadata drift: %+v", d)
	}
	return d
}

func rev6CaseByID(t *testing.T, d rev6Doc, id string) rev6Case {
	t.Helper()
	for _, c := range d.Cases {
		if c.ID == id {
			if c.Slice != "UM-B3" || c.Executed != "UM-B3" {
				t.Fatalf("%s slice metadata drift: %+v", id, c)
			}
			return c
		}
	}
	t.Fatalf("rev-6 case %s missing", id)
	return rev6Case{}
}

func seedRev6Boot(t *testing.T, r *Runtime, gen uint64, bootID string, nextSeq uint64) {
	t.Helper()
	if err := r.state.saveBoot(BootState{
		Version: stateVersion, Generation: gen, BootID: bootID, NextSeq: nextSeq,
	}); err != nil {
		t.Fatalf("seed boot: %v", err)
	}
}

func seedRev6Reports(t *testing.T, r *Runtime, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := r.QueueReport(context.Background(), "snapshot"); err != nil {
			t.Fatalf("seed queue %d: %v", i, err)
		}
		if err := r.Flush(context.Background()); err != nil {
			t.Fatalf("seed flush %d: %v", i, err)
		}
	}
}

func advanceRev6Clock(r *Runtime) {
	advanceRev6ClockAt(r, time.Now().Unix()+1)
}

func advanceRev6ClockAt(r *Runtime, base int64) {
	n := int64(0)
	r.opts.Now = func() time.Time {
		n++
		return time.Unix(base+n, 0)
	}
}

func assertRev6Center(t *testing.T, tc *agentCenter, r *Runtime, wantGen, wantSeq uint64, wantBootID string) {
	t.Helper()
	ident, ok := r.Identity()
	if !ok {
		t.Fatal("identity missing")
	}
	boot, err := tc.st.GetBoot(context.Background(), ident.NodeID)
	if err != nil {
		t.Fatalf("center GetBoot: %v", err)
	}
	if boot.HighestGen != wantGen || boot.LastSeq != wantSeq || (wantBootID != "" && boot.BootID != wantBootID) {
		t.Fatalf("center state = gen %d seq %d boot %q, want gen %d seq %d boot %q",
			boot.HighestGen, boot.LastSeq, boot.BootID, wantGen, wantSeq, wantBootID)
	}
}

func TestRev6AMENDREC27A(t *testing.T) {
	c := rev6CaseByID(t, loadRev6(t), "AMEND-REC-27-A")
	tc := startAgentCenter(t)
	r := newTestRuntime(t, tc, t.TempDir(), unavailableCollector{}, nil)
	defer r.Close()
	ctx := context.Background()
	if err := r.Enroll(ctx, tc.token); err != nil {
		t.Fatal(err)
	}
	if err := r.PullConfig(ctx); err != nil {
		t.Fatal(err)
	}
	advanceRev6Clock(r)
	seedRev6Boot(t, r, c.Setup.Agent.Generation, c.Setup.Agent.BootID, 1)
	// Fixture center last_seq=4: three ACKed reports, then the fourth commits
	// but only its ACK is lost.
	seedRev6Reports(t, r, int(c.Setup.Center.LastSeq)-1)
	if _, err := r.QueueReport(ctx, "snapshot"); err != nil {
		t.Fatal(err)
	}
	recs, err := r.state.spool.List()
	if err != nil || len(recs) != 1 || recs[0].Attempt.Generation != c.Setup.Agent.Generation ||
		recs[0].Attempt.BootID != c.Setup.Agent.BootID || recs[0].Attempt.Seq != c.Setup.Center.LastSeq {
		t.Fatalf("fixture A fourth attempt: %v %+v", err, recs)
	}
	ident, _ := r.Identity()
	ack, err := r.client.Report(ctx, ident, recs[0].Attempt, recs[0].Kind, recs[0].Body)
	if err != nil || ack.Result != "accepted" {
		t.Fatalf("direct accepted report: ack=%+v err=%v", ack, err)
	}
	if err := r.Flush(ctx); err != nil {
		t.Fatalf("exact retry: %v", err)
	}
	if got := r.LastResult(); got != c.Expected.Result {
		t.Fatalf("A result=%q, want fixture %q", got, c.Expected.Result)
	}
	boot, _ := r.Boot()
	if boot.Generation != c.Setup.Agent.Generation || boot.NextSeq != c.Expected.ACK.NextSeq {
		t.Fatalf("agent boot after A = %+v", boot)
	}
	assertRev6Center(t, tc, r, c.Expected.CenterState.HighestGen, c.Expected.CenterState.LastSeq, c.Expected.CenterState.BootID)
	if stats, err := tc.st.CapacityStats(ctx); err != nil || stats.Snapshots != int64(c.Setup.Center.LastSeq) {
		t.Fatalf("A stored snapshots=%+v err=%v, want %d", stats, err, c.Setup.Center.LastSeq)
	}
}

func TestRev6AMENDREC27BC(t *testing.T) {
	d := loadRev6(t)
	b := rev6CaseByID(t, d, "AMEND-REC-27-B")
	c := rev6CaseByID(t, d, "AMEND-REC-27-C")
	tc := startAgentCenter(t)
	dir := t.TempDir()
	r := newTestRuntime(t, tc, dir, unavailableCollector{}, nil)
	ctx := context.Background()
	if err := r.Enroll(ctx, tc.token); err != nil {
		t.Fatal(err)
	}
	if err := r.PullConfig(ctx); err != nil {
		t.Fatal(err)
	}
	advanceRev6Clock(r)
	seedRev6Boot(t, r, b.Setup.Agent.Generation-1, b.Setup.Center.BootID, 1)
	seedRev6Reports(t, r, int(b.Setup.Center.LastSeq)-1)
	if _, err := r.QueueReport(ctx, "snapshot"); err != nil {
		t.Fatal(err)
	}
	recs, err := r.state.spool.List()
	if err != nil || len(recs) != 1 {
		t.Fatalf("B fourth attempt: %v %+v", err, recs)
	}
	old := recs[0]
	ident, _ := r.Identity()
	if _, err := r.client.Report(ctx, ident, old.Attempt, old.Kind, old.Body); err != nil {
		t.Fatalf("B direct committed report: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, cleanShutdownFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	r2 := newTestRuntime(t, tc, dir, unavailableCollector{}, nil)
	defer r2.Close()
	newBoot, _ := r2.Boot()
	if newBoot.Generation != b.Setup.Agent.Generation || newBoot.BootID == old.Attempt.BootID {
		t.Fatalf("B restart boot = %+v, old attempt = %+v", newBoot, old.Attempt)
	}
	// Same report_id/body must still be in the fsynced spool.
	afterRestart, err := r2.state.spool.List()
	if err != nil || len(afterRestart) != 1 || afterRestart[0].ID != old.ID ||
		afterRestart[0].Kind != old.Kind || !bytes.Equal(afterRestart[0].Body, old.Body) {
		t.Fatalf("B payload identity changed: %v %+v", err, afterRestart)
	}
	if err := r2.Flush(ctx); err != nil {
		t.Fatalf("B replay: %v", err)
	}
	if got := r2.LastResult(); got != b.Expected.Result {
		t.Fatalf("B result=%q, want fixture %q", got, b.Expected.Result)
	}
	assertRev6Center(t, tc, r2, b.Expected.CenterState.HighestGen, b.Expected.CenterState.LastSeq, "")
	b2, _ := r2.Boot()
	if b2.BootID == "" {
		t.Fatal("B agent boot id missing")
	}
	identB, _ := r2.Identity()
	centerB, _ := tc.st.GetBoot(ctx, identB.NodeID)
	if centerB.BootID != b2.BootID {
		t.Fatalf("B center boot id=%q, want agent new-generation boot %q", centerB.BootID, b2.BootID)
	}
	if b2.NextSeq != b.Expected.ACK.NextSeq {
		t.Fatalf("B next_seq=%d, want fixture %d", b2.NextSeq, b.Expected.ACK.NextSeq)
	}
	if stats, err := tc.st.CapacityStats(ctx); err != nil || stats.Snapshots != int64(b.Setup.Center.LastSeq) {
		t.Fatalf("B stored snapshots=%+v err=%v, want %d (no second data copy)", stats, err, b.Setup.Center.LastSeq)
	}
	// C: late retired-generation request after the new high-water.
	ident2, _ := r2.Identity()
	_, err = r2.client.Report(ctx, ident2, old.Attempt, old.Kind, old.Body)
	var ce *CenterError
	if !errors.As(err, &ce) || c.Expected.Result != "rejected" ||
		ce.Status != c.Expected.HTTPStatus || ce.Code != c.Expected.Error {
		t.Fatalf("C stale request err=%v, want fixture rejected status %d %s", err, c.Expected.HTTPStatus, c.Expected.Error)
	}
	assertRev6Center(t, tc, r2, c.Setup.Center.HighestGen, c.Setup.Center.LastSeq, "")
}

func TestRev6AMENDREC27D(t *testing.T) {
	c := rev6CaseByID(t, loadRev6(t), "AMEND-REC-27-D")
	dir := t.TempDir()
	s, err := OpenState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.saveIdentity(testIdentity(t)); err != nil {
		t.Fatal(err)
	}
	if err := s.saveBoot(BootState{Version: stateVersion,
		Generation: c.Setup.Agent.Generation, BootID: c.Setup.Agent.BootID,
		NextSeq: c.Setup.Agent.NextSeq}); err != nil {
		t.Fatal(err)
	}
	if err := s.Spool().Enqueue(SpoolRecord{
		Version: stateVersion, ID: "11111111-1111-4111-8111-111111111111",
		Kind: "snapshot", CreatedAt: 1795622400,
		Attempt: Attempt{Generation: c.Setup.Agent.Generation, BootID: c.Setup.Agent.BootID,
			Seq: c.Setup.Agent.NextSeq, SentAt: 1795622400, Nonce: "AAAAAAAAAAAAAAAAAAAAAA"},
		Body: unavailableSnapshot(ReportContext{ReportID: "11111111-1111-4111-8111-111111111111",
			CollectedAt: 1795622400, Host: HostInfo{OS: "linux"}}),
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	before := treeDigest(t, dir)
	inspection, err := InspectState(dir)
	if err != nil {
		t.Fatalf("read-only inspection: %v", err)
	}
	if inspection.Generation != c.Setup.Agent.Generation || inspection.NextSeq != c.Setup.Agent.NextSeq {
		t.Fatalf("inspection generation/seq=%d/%d, want %d/%d", inspection.Generation, inspection.NextSeq,
			c.Setup.Agent.Generation, c.Setup.Agent.NextSeq)
	}
	if inspection.Pending != c.Setup.Agent.SpoolRecords {
		t.Fatalf("inspection pending=%d, want fixture %d", inspection.Pending, c.Setup.Agent.SpoolRecords)
	}
	if c.Expected.StateChange != "none" || c.Expected.SpoolChange != "none" ||
		c.Expected.NetworkRequired || c.Expected.Generation != c.Setup.Agent.Generation ||
		c.Expected.BootID != c.Setup.Agent.BootID {
		t.Fatalf("D fixture expectations are not non-mutating: %+v", c.Expected)
	}
	rawBoot, err := os.ReadFile(filepath.Join(dir, bootStateFile))
	if err != nil {
		t.Fatal(err)
	}
	var persisted BootState
	if err := json.Unmarshal(rawBoot, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Generation != c.Expected.Generation || persisted.BootID != c.Expected.BootID {
		t.Fatalf("D persisted generation/boot=%d/%q, want %d/%q",
			persisted.Generation, persisted.BootID, c.Expected.Generation, c.Expected.BootID)
	}
	if after := treeDigest(t, dir); after != before {
		t.Fatalf("read-only inspection mutated state tree: %s != %s", after, before)
	}
}

func TestRev6AMENDREC27E(t *testing.T) {
	c := rev6CaseByID(t, loadRev6(t), "AMEND-REC-27-E")
	tc := startAgentCenter(t)
	r := newTestRuntime(t, tc, t.TempDir(), unavailableCollector{}, nil)
	defer r.Close()
	ctx := context.Background()
	if err := r.Enroll(ctx, tc.token); err != nil {
		t.Fatal(err)
	}
	if err := r.PullConfig(ctx); err != nil {
		t.Fatal(err)
	}
	advanceRev6Clock(r)
	seedRev6Boot(t, r, c.Setup.Center.HighestGen, c.Setup.Center.BootID, 1)
	seedRev6Reports(t, r, int(c.Setup.Center.LastSeq))
	ident, _ := r.Identity()
	body := unavailableSnapshot(ReportContext{ReportID: "00000000-0000-4000-8000-000000000000", CollectedAt: time.Now().Unix(),
		Host: HostInfo{OS: "linux"}})
	_, err := r.client.Report(ctx, ident, Attempt{
		Generation: c.Attempt.Gen, BootID: c.Attempt.BootID, Seq: c.Attempt.Seq,
		SentAt: time.Now().Unix(), Nonce: "AAAAAAAAAAAAAAAAAAAAAA",
	}, "snapshot", body)
	var ce *CenterError
	if !errors.As(err, &ce) || c.Expected.Result != "rejected" ||
		ce.Status != c.Expected.HTTPStatus || ce.Code != c.Expected.Error {
		t.Fatalf("E request err=%v, want fixture rejected status %d %s", err, c.Expected.HTTPStatus, c.Expected.Error)
	}
	assertRev6Center(t, tc, r, c.Setup.Center.HighestGen, c.Setup.Center.LastSeq, c.Setup.Center.BootID)
}

func TestRev6AMENDREC27F(t *testing.T) {
	d := loadRev6(t)
	c := rev6CaseByID(t, d, "AMEND-REC-27-F")
	tc := startAgentCenter(t)
	dir := t.TempDir()
	r := newTestRuntime(t, tc, dir, unavailableCollector{}, nil)
	ctx := context.Background()
	if err := r.Enroll(ctx, tc.token); err != nil {
		t.Fatal(err)
	}
	if err := r.PullConfig(ctx); err != nil {
		t.Fatal(err)
	}
	advanceRev6Clock(r)
	seedRev6Boot(t, r, c.Setup.Center.HighestGen, c.Setup.Center.BootID, 1)
	seedRev6Reports(t, r, int(c.Setup.Center.LastSeq))
	// Consecutive offline restarts: 3 -> 6 (bounded gap 3).
	for {
		b, _ := r.Boot()
		if b.Generation >= c.Setup.Agent.Generation {
			break
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(dir, cleanShutdownFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		r = newTestRuntime(t, tc, dir, unavailableCollector{}, nil)
	}
	defer r.Close()
	advanceRev6ClockAt(r, time.Now().Unix()+10)
	boot, _ := r.Boot()
	if boot.Generation != c.Setup.Agent.Generation || boot.BootID == c.Setup.Center.BootID {
		t.Fatalf("F gap boot=%+v", boot)
	}
	gap := boot.Generation - c.Setup.Center.HighestGen
	if gap != c.Expected.Gap || gap > d.MaxBootGap {
		t.Fatalf("F gap=%d, want %d", gap, c.Expected.Gap)
	}
	identF, _ := r.Identity()
	latest, lerr := tc.st.GetLatestSnapshot(ctx, identF.NodeID)
	if lerr != nil {
		t.Fatalf("F latest snapshot: %v", lerr)
	}
	advanceRev6ClockAt(r, latest.CollectedAt+10)
	if _, err := r.QueueReport(ctx, "snapshot"); err != nil {
		t.Fatal(err)
	}
	if err := r.Flush(ctx); err != nil {
		t.Fatalf("F accepted gap report: %v", err)
	}
	if got := r.LastResult(); got != c.Expected.Result {
		t.Fatalf("F result=%q, want fixture %q", got, c.Expected.Result)
	}
	assertRev6Center(t, tc, r, c.Expected.CenterState.HighestGen, c.Expected.CenterState.LastSeq, "")
	bootF, _ := r.Boot()
	identF2, _ := r.Identity()
	centerF, _ := tc.st.GetBoot(ctx, identF2.NodeID)
	if centerF.BootID != bootF.BootID {
		t.Fatalf("F center boot id=%q, want agent new-generation boot %q", centerF.BootID, bootF.BootID)
	}
	if err := tc.st.VerifyChain(ctx); err != nil {
		t.Fatalf("F gap audit ledger: %v", err)
	}
	db, err := sql.Open("sqlite", tc.st.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var gapAudits int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_ledger WHERE kind = ?`, c.Expected.GapAudit).Scan(&gapAudits); err != nil {
		t.Fatalf("F gap audit query: %v", err)
	}
	if gapAudits < 1 {
		t.Fatalf("F gap audit %q rows=%d, want >=1", c.Expected.GapAudit, gapAudits)
	}
}

func treeDigest(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		b.WriteString(rel)
		if info.IsDir() {
			b.WriteString("/\n")
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		b.WriteString(":")
		b.WriteString(hex.EncodeToString(sum[:]))
		b.WriteString(":")
		b.WriteString(fmt.Sprint(info.Mode()))
		b.WriteString("\n")
		return nil
	})
	if err != nil {
		t.Fatalf("tree digest: %v", err)
	}
	return b.String()
}

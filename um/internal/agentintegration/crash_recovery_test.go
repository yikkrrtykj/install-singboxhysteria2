package agentintegration

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/agent"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/linuxobs"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
)

// This is a parent/child process-level crash harness. The child is the same
// test binary; it enrolls and performs one real center request, then exits
// without Close (no clean-shutdown marker). The parent reopens the exact state
// directory and verifies the frozen recovery behavior.
const (
	crashScenarioEnv = "UM_B3_CRASH_SCENARIO"
	crashCenterEnv   = "UM_B3_CRASH_CENTER"
	crashStateEnv    = "UM_B3_CRASH_STATE"
	crashTokenEnv    = "UM_B3_CRASH_TOKEN"
)

type dropACKTransport struct {
	base   http.RoundTripper
	dropAt int64
	count  atomic.Int64
}

func (transport *dropACKTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := transport.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	// Commit happened on the center, but the agent must not see the ACK: this
	// simulates a lost response at the process-crash boundary.
	if req.URL.Path == "/v1/agent/report" && resp.StatusCode == http.StatusOK {
		n := transport.count.Add(1)
		if transport.dropAt == 0 || n == transport.dropAt {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			return nil, errors.New("simulated ACK loss")
		}
	}
	return resp, nil
}

func TestB3CrashHelper(t *testing.T) {
	scenario := os.Getenv(crashScenarioEnv)
	if scenario == "" {
		t.Skip("parent/child crash helper; executed only by TestB3RecoveryProcessCrash")
	}
	tcURL := os.Getenv(crashCenterEnv)
	stateDir := os.Getenv(crashStateEnv)
	token := os.Getenv(crashTokenEnv)
	col := &linuxobs.Collector{AgentVersion: "1.0.0"}
	var httpClient *http.Client
	if scenario == "rec27" {
		// The fourth report commits at the center and only its ACK is lost.
		httpClient = &http.Client{Transport: &dropACKTransport{base: http.DefaultTransport, dropAt: 4}}
	}
	r, err := agent.NewRuntime(agent.Options{
		StateDir: stateDir, CenterURL: tcURL, NodeClass: store.NodeClassLinuxVPS,
		HostOS: "linux", AgentVersion: "1.0.0", Collector: col, HTTPClient: httpClient,
	})
	if err != nil {
		t.Fatalf("helper runtime: %v", err)
	}
	ctx := context.Background()
	if err := r.Enroll(ctx, token); err != nil {
		t.Fatalf("helper enroll: %v", err)
	}
	if err := r.PullConfig(ctx); err != nil {
		t.Fatalf("helper config: %v", err)
	}
	switch scenario {
	case "rec18":
		// Reach generation 12 through real runtime restarts, commit a report,
		// then exit abruptly. The parent restores gen9; the next restart advances
		// it to gen10, still below the center high-water 12, so the report is stale.
		for i := 0; i < 11; i++ {
			if err := r.Close(); err != nil {
				t.Fatalf("helper rec18 close %d: %v", i, err)
			}
			r, err = agent.NewRuntime(agent.Options{
				StateDir: stateDir, CenterURL: tcURL, NodeClass: store.NodeClassLinuxVPS,
				HostOS: "linux", AgentVersion: "1.0.0", Collector: col,
			})
			if err != nil {
				t.Fatalf("helper rec18 reopen %d: %v", i, err)
			}
		}
		if _, err := r.QueueReport(ctx, "snapshot"); err != nil {
			t.Fatalf("helper rec18 queue: %v", err)
		}
		if err := r.Flush(ctx); err != nil {
			t.Fatalf("helper rec18 flush: %v", err)
		}
	case "rec17":
		// Simulate durable boot-state loss after the record is fsynced, then die
		// without any clean-shutdown marker.
		if _, err := r.QueueReport(ctx, "snapshot"); err != nil {
			t.Fatalf("helper rec17 queue: %v", err)
		}
		if err := os.Remove(filepath.Join(stateDir, "boot_state.json")); err != nil {
			t.Fatalf("helper remove boot: %v", err)
		}
	case "rec27":
		// Natural generation 1: three ACKed reports, then the fourth report commits
		// at the center and only its ACK is lost. Rewrite the persisted next_seq to
		// the boundary before exiting (no clean marker).
		for i := 0; i < 3; i++ {
			if _, err := r.QueueReport(ctx, "snapshot"); err != nil {
				t.Fatalf("helper rec27 seed queue %d: %v", i, err)
			}
			if err := r.Flush(ctx); err != nil {
				t.Fatalf("helper rec27 seed flush %d: %v", i, err)
			}
		}
		if _, err := r.QueueReport(ctx, "snapshot"); err != nil {
			t.Fatalf("helper rec27 fourth queue: %v", err)
		}
		_ = r.Flush(ctx) // center commits; fourth ACK is dropped
		path := filepath.Join(stateDir, "boot_state.json")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("helper rec27 read boot: %v", err)
		}
		var boot agent.BootState
		if err := json.Unmarshal(raw, &boot); err != nil {
			t.Fatalf("helper rec27 parse boot: %v", err)
		}
		boot.NextSeq = 5
		boot.Exhausted = false
		raw, _ = json.Marshal(boot)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatalf("helper rec27 persisted boundary: %v", err)
		}
	default:
		t.Fatalf("unknown scenario %q", scenario)
	}
	// Exit without r.Close so no clean-shutdown marker is written.
	os.Exit(99)
}

func runCrashChild(t *testing.T, scenario, centerURL, stateDir, token string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestB3CrashHelper$")
	cmd.Env = append(os.Environ(),
		crashScenarioEnv+"="+scenario,
		crashCenterEnv+"="+centerURL,
		crashStateEnv+"="+stateDir,
		crashTokenEnv+"="+token,
	)
	output, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 99 {
		t.Fatalf("crash helper exit: err=%v output=%s", err, output)
	}
}

type rev6ProcessFixture struct {
	ContractRevision int `json:"contract_revision"`
	Cases            []struct {
		ID       string `json:"id"`
		Restart  bool   `json:"restart"`
		Expected struct {
			Result      string `json:"result"`
			CenterState struct {
				HighestGen uint64 `json:"highest_gen"`
				LastSeq    uint64 `json:"last_seq"`
			} `json:"center_state"`
			Data string `json:"data"`
		} `json:"expected"`
	} `json:"cases"`
}

func loadRev6ProcessB(t *testing.T) rev6ProcessFixture {
	t.Helper()
	raw, err := os.ReadFile("../../../docs/um/contracts/v1/power-loss-generation.rev6.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc rev6ProcessFixture
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.ContractRevision != 6 {
		t.Fatalf("rev-6 fixture revision=%d", doc.ContractRevision)
	}
	for _, c := range doc.Cases {
		if c.ID != "AMEND-REC-27-B" {
			continue
		}
		if !c.Restart || c.Expected.Result != "duplicate" ||
			c.Expected.Data != "no_second_copy" ||
			c.Expected.CenterState.HighestGen == 0 || c.Expected.CenterState.LastSeq != 1 {
			t.Fatalf("rev-6 B fixture drift: %+v", c)
		}
		return doc
	}
	t.Fatal("rev-6 AMEND-REC-27-B missing")
	return doc
}

func TestB3RecoveryProcessCrashREC27(t *testing.T) {
	loadRev6ProcessB(t) // fixture binding: real process restart must be duplicate/no-second-copy
	const eventID = "cc1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5e"
	tc := startRealCenter(t, store.NodeClassLinuxVPS, eventID)
	stateDir := t.TempDir()
	runCrashChild(t, "rec27", tc.url, stateDir, tc.token)

	before, err := tc.store.CapacityStats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if before.Snapshots != 4 {
		t.Fatalf("child did not commit the three seed snapshots plus the ACK-lost fourth: %+v", before)
	}
	identRaw, _ := os.ReadFile(filepath.Join(stateDir, "identity.json"))
	var ident agent.Identity
	_ = json.Unmarshal(identRaw, &ident)
	boot, err := tc.store.GetBoot(context.Background(), ident.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if boot.HighestGen != 1 || boot.LastSeq != 5 {
		t.Fatalf("center high-water = %+v, want gen1/seq5", boot)
	}
	entries, err := os.ReadDir(filepath.Join(stateDir, "spool"))
	if err != nil {
		t.Fatal(err)
	}
	var persisted []agent.SpoolRecord
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		raw, rerr := os.ReadFile(filepath.Join(stateDir, "spool", entry.Name()))
		if rerr != nil {
			t.Fatal(rerr)
		}
		var rec agent.SpoolRecord
		if uerr := json.Unmarshal(raw, &rec); uerr != nil {
			t.Fatal(uerr)
		}
		persisted = append(persisted, rec)
	}
	if len(persisted) != 1 {
		t.Fatalf("persisted spool after ACK loss=%d, want exactly the fourth record", len(persisted))
	}
	rec := persisted[0]
	if rec.Attempt.Generation != 1 || rec.Attempt.Seq != 5 ||
		rec.Attempt.BootID == "" || rec.Attempt.Fingerprint == "" {
		t.Fatalf("persisted attempt = %+v, want gen1/seq5 with fingerprint", rec.Attempt)
	}
	r, err := agent.NewRuntime(agent.Options{
		StateDir: stateDir, CenterURL: tc.url, NodeClass: store.NodeClassLinuxVPS,
		HostOS: "linux", AgentVersion: "1.0.0", Collector: &linuxobs.Collector{AgentVersion: "1.0.0"},
	})
	if err != nil {
		t.Fatalf("reopen after child crash: %v", err)
	}
	defer r.Close()
	if err := r.Flush(context.Background()); err != nil {
		t.Fatalf("resend after ACK loss: %v", err)
	}
	if got := r.LastResult(); got != "duplicate" {
		t.Fatalf("resend result=%q, want duplicate (center already committed)", got)
	}
	if n := r.Status().Pending; n != 0 {
		t.Fatalf("spool pending after duplicate=%d, want 0", n)
	}
	after, err := tc.store.CapacityStats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if after.Snapshots != 4 || after.ReportDedupe != before.ReportDedupe {
		t.Fatalf("duplicate reinserted data: before=%+v after=%+v", before, after)
	}
	newBoot, _ := r.Boot()
	if newBoot.Generation != 2 || newBoot.BootID == rec.Attempt.BootID {
		t.Fatalf("restart did not advance to a new generation/boot id: %+v", newBoot)
	}
	centerBoot, err := tc.store.GetBoot(context.Background(), ident.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if centerBoot.HighestGen != newBoot.Generation || centerBoot.LastSeq != 1 {
		t.Fatalf("new-generation duplicate did not advance high-water: boot=%+v center=%+v", newBoot, centerBoot)
	}
	if _, seen, err := tc.store.ReportSeen(context.Background(), ident.NodeID, rec.ID); err != nil || !seen {
		t.Fatalf("restart replay report_id was not deduped as the same payload: seen=%v err=%v", seen, err)
	}
}

func TestB3RecoveryProcessCrashREC18(t *testing.T) {
	const eventID = "ee1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5e"
	tc := startRealCenter(t, store.NodeClassLinuxVPS, eventID)
	stateDir := t.TempDir()
	runCrashChild(t, "rec18", tc.url, stateDir, tc.token)
	stats, err := tc.store.CapacityStats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Snapshots != 1 {
		t.Fatalf("child generation-12 report not committed: %+v", stats)
	}
	identRaw, _ := os.ReadFile(filepath.Join(stateDir, "identity.json"))
	var ident agent.Identity
	_ = json.Unmarshal(identRaw, &ident)
	centerBefore, berr := tc.store.GetBoot(context.Background(), ident.NodeID)
	if berr != nil {
		t.Fatal(berr)
	}
	if centerBefore.HighestGen != 12 {
		t.Fatalf("child did not reach generation 12: %+v", centerBefore)
	}
	// Restore an old boot snapshot after the crash: restart advances gen9 -> gen10, still < center 12.
	path := filepath.Join(stateDir, "boot_state.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var boot agent.BootState
	if err := json.Unmarshal(raw, &boot); err != nil {
		t.Fatal(err)
	}
	boot.Generation = 9
	boot.BootID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	boot.NextSeq = 1
	boot.Exhausted = false
	raw, _ = json.Marshal(boot)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := agent.NewRuntime(agent.Options{
		StateDir: stateDir, CenterURL: tc.url, NodeClass: store.NodeClassLinuxVPS,
		HostOS: "linux", AgentVersion: "1.0.0", Collector: &linuxobs.Collector{AgentVersion: "1.0.0"},
	})
	if err != nil {
		t.Fatalf("reopen old snapshot: %v", err)
	}
	defer r.Close()
	ctx := context.Background()
	if _, err := r.QueueReport(ctx, "snapshot"); err != nil {
		t.Fatalf("stale queue: %v", err)
	}
	errFlush := r.Flush(ctx)
	t.Logf("rec18 parent pre-status=%+v flush=%v last=%q", r.Status(), errFlush, r.LastResult())
	if !errors.Is(errFlush, agent.ErrStaleGeneration) {
		t.Fatalf("stale report = %v, want ErrStaleGeneration", errFlush)
	}
	b, _ := r.Boot()
	if b.Generation != 10 {
		t.Fatalf("old snapshot was not advanced to the next restart generation: %d", b.Generation)
	}
	if n := r.Status().Pending; n != 1 {
		t.Fatalf("spool retained=%d, want 1", n)
	}
}

func TestB3RecoveryProcessCrashREC17(t *testing.T) {
	const eventID = "dd1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5e"
	tc := startRealCenter(t, store.NodeClassLinuxVPS, eventID)
	stateDir := t.TempDir()
	runCrashChild(t, "rec17", tc.url, stateDir, tc.token)

	if _, err := agent.NewRuntime(agent.Options{
		StateDir: stateDir, CenterURL: tc.url, NodeClass: store.NodeClassLinuxVPS,
		HostOS: "linux", AgentVersion: "1.0.0", Collector: &linuxobs.Collector{AgentVersion: "1.0.0"},
	}); !errors.Is(err, agent.ErrBootStateCorrupt) {
		t.Fatalf("reopen with missing boot state = %v, want ErrBootStateCorrupt", err)
	}
	stats, err := tc.store.CapacityStats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Snapshots != 0 {
		t.Fatalf("boot-corrupt child sent a report: %+v", stats)
	}
	// The fsynced spool record must remain for operator inspection.
	spoolDir := filepath.Join(stateDir, "spool")
	entries, err := os.ReadDir(spoolDir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("spool not retained after boot corruption: entries=%d err=%v", len(entries), err)
	}
}

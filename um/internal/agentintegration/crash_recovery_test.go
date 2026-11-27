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
	r, err := agent.NewRuntime(agent.Options{
		StateDir: stateDir, CenterURL: tcURL, NodeClass: store.NodeClassLinuxVPS,
		HostOS: "linux", AgentVersion: "1.0.0", Collector: col,
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
		// Persist a newer generation, reopen the exact state (removing the clean
		// marker so it is treated as an abrupt restart), let the real center
		// accept gen12, then exit abruptly. The parent restores gen9.
		if err := r.Close(); err != nil {
			t.Fatalf("helper rec18 close: %v", err)
		}
		raw, err := os.ReadFile(filepath.Join(stateDir, "boot_state.json"))
		if err != nil {
			t.Fatalf("helper read boot: %v", err)
		}
		var boot agent.BootState
		if err := json.Unmarshal(raw, &boot); err != nil {
			t.Fatalf("helper parse boot: %v", err)
		}
		boot.Generation = 12
		boot.BootID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		boot.NextSeq = 1
		boot.Exhausted = false
		raw, _ = json.Marshal(boot)
		if err := os.WriteFile(filepath.Join(stateDir, "boot_state.json"), raw, 0o600); err != nil {
			t.Fatalf("helper write boot: %v", err)
		}
		if err := os.Remove(filepath.Join(stateDir, "clean_shutdown")); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("helper remove clean marker: %v", err)
		}
		r2, err := agent.NewRuntime(agent.Options{
			StateDir: stateDir, CenterURL: tcURL, NodeClass: store.NodeClassLinuxVPS,
			HostOS: "linux", AgentVersion: "1.0.0", Collector: col,
		})
		if err != nil {
			t.Fatalf("helper rec18 reopen: %v", err)
		}
		if _, err := r2.QueueReport(ctx, "snapshot"); err != nil {
			t.Fatalf("helper rec18 queue: %v", err)
		}
		if err := r2.Flush(ctx); err != nil {
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
		// Fixture setup: center generation 3/boot b3, last_seq 4. Reopen the
		// persisted state as generation 3, send three ACKed reports, then drop
		// only the fourth report's ACK and rewrite the persisted next_seq to the
		// REC-27 boundary before the abrupt exit.
		if err := r.Close(); err != nil {
			t.Fatalf("helper rec27 initial close: %v", err)
		}
		raw, err := os.ReadFile(filepath.Join(stateDir, "boot_state.json"))
		if err != nil {
			t.Fatalf("helper rec27 read boot: %v", err)
		}
		var boot agent.BootState
		if err := json.Unmarshal(raw, &boot); err != nil {
			t.Fatalf("helper rec27 parse boot: %v", err)
		}
		boot.Generation = 3
		boot.BootID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		boot.NextSeq = 1
		boot.Exhausted = false
		raw, _ = json.Marshal(boot)
		if err := os.WriteFile(filepath.Join(stateDir, "boot_state.json"), raw, 0o600); err != nil {
			t.Fatalf("helper rec27 write boot: %v", err)
		}
		if err := os.Remove(filepath.Join(stateDir, "clean_shutdown")); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("helper rec27 remove clean: %v", err)
		}
		rec27Drop := &dropACKTransport{base: http.DefaultTransport, dropAt: 4}
		r2, err := agent.NewRuntime(agent.Options{
			StateDir: stateDir, CenterURL: tcURL, NodeClass: store.NodeClassLinuxVPS,
			HostOS: "linux", AgentVersion: "1.0.0", Collector: col,
			HTTPClient: &http.Client{Transport: rec27Drop},
		})
		if err != nil {
			t.Fatalf("helper rec27 reopen: %v", err)
		}
		for i := 0; i < 3; i++ {
			if _, err := r2.QueueReport(ctx, "snapshot"); err != nil {
				t.Fatalf("helper rec27 seed queue %d: %v", i, err)
			}
			if err := r2.Flush(ctx); err != nil {
				t.Fatalf("helper rec27 seed flush %d: %v", i, err)
			}
		}
		if _, err := r2.QueueReport(ctx, "snapshot"); err != nil {
			t.Fatalf("helper rec27 fourth queue: %v", err)
		}
		_ = r2.Flush(ctx) // center commits; fourth ACK is dropped
		raw, err = os.ReadFile(filepath.Join(stateDir, "boot_state.json"))
		if err != nil {
			t.Fatalf("helper rec27 reread boot: %v", err)
		}
		if err := json.Unmarshal(raw, &boot); err != nil {
			t.Fatalf("helper rec27 reparse boot: %v", err)
		}
		boot.NextSeq = 4
		raw, _ = json.Marshal(boot)
		if err := os.WriteFile(filepath.Join(stateDir, "boot_state.json"), raw, 0o600); err != nil {
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

func TestB3RecoveryProcessCrashREC27(t *testing.T) {
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
	if boot.HighestGen != 3 || boot.LastSeq != 4 {
		t.Fatalf("center high-water = %+v, want gen3/seq4", boot)
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
	if rec.Attempt.Generation != 3 || rec.Attempt.Seq != 4 ||
		rec.Attempt.BootID != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" || rec.Attempt.Fingerprint == "" {
		t.Fatalf("persisted attempt = %+v, want gen3/seq4/b3 with fingerprint", rec.Attempt)
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
	if b, berr := tc.store.GetBoot(context.Background(), ident.NodeID); berr == nil {
		t.Logf("center boot after child=%+v", b)
	} else {
		t.Logf("center GetBoot: %v", berr)
	}
	// Restore an old boot snapshot after the crash: generation 9 < center 12.
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
	if b.Generation != 9 {
		t.Fatalf("agent reset old snapshot generation to %d", b.Generation)
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

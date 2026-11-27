package agentintegration

import (
	"context"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/agent"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/windowsagent"
)

// TestWindowsActiveOnlyEventsAcceptedByRealCenter covers the legal
// mihomo_api=true / terminal=false configuration. The collector must not emit
// terminal_source_unavailable (the center only permits that kind when the
// `terminal` source is enabled); it emits the generic agent_error diagnostic.
func TestWindowsActiveOnlyEventsAcceptedByRealCenter(t *testing.T) {
	const eventID = "ab1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5f"
	tc := startRealCenter(t, store.NodeClassWindowsTerminal, eventID)
	col, err := windowsagent.New(windowsagent.Options{AgentVersion: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	r, err := agent.NewRuntime(agent.Options{
		StateDir: t.TempDir(), CenterURL: tc.url, NodeClass: store.NodeClassWindowsTerminal,
		HostOS: "windows", AgentVersion: "1.0.0", Collector: col,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx := context.Background()
	if err := r.Enroll(ctx, tc.token); err != nil {
		t.Fatal(err)
	}
	ident, _ := r.Identity()
	if _, err := tc.store.UpdateNodeConfig(ctx, ident.NodeID, map[string]bool{
		"system": false, "services": false, "singbox_api": false,
		"mihomo_api": true, "terminal": false, "events": true,
	}, nil, 60, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if err := r.PullConfig(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := r.QueueReport(ctx, "events"); err != nil {
		t.Fatal(err)
	}
	if err := r.Flush(ctx); err != nil {
		t.Fatalf("events flush: %v", err)
	}
	if n := r.Status().Quarantined; n != 0 {
		t.Fatalf("active-only events quarantined=%d", n)
	}
	stats, err := tc.store.CapacityStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Events != 2 {
		t.Fatalf("center events=%d, want agent_started + agent_error: %+v", stats.Events, stats)
	}
}

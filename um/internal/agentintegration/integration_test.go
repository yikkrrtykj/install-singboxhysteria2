package agentintegration

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/agent"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/center"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/linuxobs"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/schema"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/windowsagent"
)

const contractsDir = "../../../docs/um/contracts/v1"

type realCenter struct {
	store *store.Store
	url   string
	token string
}

func startRealCenter(t *testing.T, class, eventID string) *realCenter {
	t.Helper()
	dir := t.TempDir()
	db := filepath.Join(dir, "center.db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	schemas, err := schema.Load(contractsDir)
	if err != nil {
		t.Fatalf("schema.Load: %v", err)
	}
	svc, err := center.NewService(center.ServiceConfig{Store: st, Schemas: schemas})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	srv, err := center.NewServer(center.Config{
		IngestAddr: "127.0.0.1:0", AdminAddr: "127.0.0.1:0",
		DBPath: db, ContractDir: contractsDir, RateLimitPerSecond: -1,
	}, svc)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	token, hash, err := store.NewEnrollToken()
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	now := time.Now().Unix()
	if err := st.CreateEnrollToken(context.Background(), hash, eventID, class, now+3600, now); err != nil {
		t.Fatalf("CreateEnrollToken: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close(); _ = st.Close() })
	return &realCenter{store: st, url: "http://" + srv.IngestAddr(), token: token}
}

func TestLinuxCollectorToRealCenter(t *testing.T) {
	const eventID = "8a1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5e"
	tc := startRealCenter(t, store.NodeClassLinuxVPS, eventID)
	col := &linuxobs.Collector{AgentVersion: "1.0.0"}
	r, err := agent.NewRuntime(agent.Options{
		StateDir: t.TempDir(), CenterURL: tc.url, NodeClass: store.NodeClassLinuxVPS,
		HostOS: "linux", AgentVersion: "1.0.0", Collector: col,
	})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	defer r.Close()
	ctx := context.Background()
	if err := r.Enroll(ctx, tc.token); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if err := r.PullConfig(ctx); err != nil {
		t.Fatalf("PullConfig: %v", err)
	}
	if _, err := r.QueueReport(ctx, "snapshot"); err != nil {
		t.Fatalf("QueueReport: %v", err)
	}
	if err := r.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	ident, _ := r.Identity()
	if _, err := tc.store.GetLatestSnapshot(ctx, ident.NodeID); err != nil {
		t.Fatalf("real center did not persist Linux snapshot: %v", err)
	}
}

func TestWindowsCollectorToRealCenter(t *testing.T) {
	const eventID = "9a1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5f"
	tc := startRealCenter(t, store.NodeClassWindowsTerminal, eventID)
	col, err := windowsagent.New(windowsagent.Options{AgentVersion: "1.0.0"})
	if err != nil {
		t.Fatalf("windowsagent.New: %v", err)
	}
	r, err := agent.NewRuntime(agent.Options{
		StateDir: t.TempDir(), CenterURL: tc.url, NodeClass: store.NodeClassWindowsTerminal,
		HostOS: "windows", AgentVersion: "1.0.0", Collector: col,
	})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	defer r.Close()
	ctx := context.Background()
	if err := r.Enroll(ctx, tc.token); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if err := r.PullConfig(ctx); err != nil {
		t.Fatalf("PullConfig: %v", err)
	}
	if _, err := r.QueueReport(ctx, "snapshot"); err != nil {
		t.Fatalf("QueueReport: %v", err)
	}
	if err := r.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	ident, _ := r.Identity()
	if _, err := tc.store.GetLatestSnapshot(ctx, ident.NodeID); err != nil {
		t.Fatalf("real center did not persist Windows snapshot: %v", err)
	}
}

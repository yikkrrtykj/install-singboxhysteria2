package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/agent"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/center"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/schema"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
)

const statusTestEvent = "aa1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5d"

type statusTestCollector struct{}

func (statusTestCollector) Snapshot(_ context.Context, rc agent.ReportContext) ([]byte, error) {
	body := map[string]any{
		"v": 1, "type": "snapshot", "report_id": rc.ReportID, "collected_at": rc.CollectedAt,
		"agent": map[string]any{"version": "1.0.0", "uptime_s": 1},
		"host":  map[string]any{"os": rc.Host.OS, "kernel": "test", "arch": "amd64"},
		"availability": map[string]any{
			"system": "unavailable", "services": "unavailable", "protocols": "unavailable",
			"traffic": "unavailable", "clients": "unavailable",
		},
		"counter_epoch": "0123456789abcdef0123456789abcdef",
		"system": map[string]any{
			"cpu_pct": nil, "load1": nil, "mem_total_bytes": nil, "mem_used_bytes": nil,
			"disk_total_bytes": nil, "disk_used_bytes": nil, "net_rx_bytes": nil, "net_tx_bytes": nil,
		},
		"services": []any{}, "protocols": []any{}, "traffic": []any{},
		"clients": map[string]any{"active": nil, "tracked": nil, "summaries": []any{}},
	}
	return json.Marshal(body)
}
func (statusTestCollector) Metrics(context.Context, agent.ReportContext) ([]byte, error) {
	return nil, agent.ErrUnsupported
}
func (statusTestCollector) Events(context.Context, agent.ReportContext) ([]byte, error) {
	return nil, agent.ErrUnsupported
}

func statusTreeDigest(t *testing.T, dir string) string {
	t.Helper()
	var names []string
	if err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			rel, _ := filepath.Rel(dir, path)
			names = append(names, rel)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		h.Write([]byte(name))
		h.Write([]byte{0})
		h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestStatusCommandIsNonMutating(t *testing.T) {
	centerDir := t.TempDir()
	dbPath := filepath.Join(centerDir, "private", "center.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	schemas, err := schema.Load("../../../docs/um/contracts/v1")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := center.NewService(center.ServiceConfig{Store: st, Schemas: schemas})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := center.NewServer(center.Config{
		IngestAddr: "127.0.0.1:0", AdminAddr: "127.0.0.1:0",
		DBPath: dbPath, ContractDir: "../../../docs/um/contracts/v1", RateLimitPerSecond: -1,
	}, svc)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close(); _ = st.Close() })
	token, hash, err := store.NewEnrollToken()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if err := st.CreateEnrollToken(context.Background(), hash, statusTestEvent, store.NodeClassLinuxVPS, now+3600, now); err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	runtime, err := agent.NewRuntime(agent.Options{
		StateDir: stateDir, CenterURL: "http://" + srv.IngestAddr(), NodeClass: "linux_vps",
		HostOS: "linux", AgentVersion: "1.0.0", Collector: statusTestCollector{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Enroll(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	if err := runtime.PullConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	beforeInspection, err := agent.InspectState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	before := statusTreeDigest(t, stateDir)
	if rc := runStatus([]string{"--state-dir", stateDir}); rc != 0 {
		t.Fatalf("status exit code=%d", rc)
	}
	afterInspection, err := agent.InspectState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if before != statusTreeDigest(t, stateDir) {
		t.Fatal("status mutated the persisted state tree")
	}
	if beforeInspection.Generation != afterInspection.Generation || beforeInspection.NextSeq != afterInspection.NextSeq {
		t.Fatalf("status changed generation/seq: before=%+v after=%+v", beforeInspection, afterInspection)
	}
}

package center_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/agent"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
)

type tlsLabCollector struct{}

func (tlsLabCollector) Snapshot(_ context.Context, rc agent.ReportContext) ([]byte, error) {
	return json.Marshal(map[string]any{
		"v": 1, "type": "snapshot", "report_id": rc.ReportID, "collected_at": rc.CollectedAt,
		"agent": map[string]any{"version": "1.0.0", "uptime_s": 1},
		"host":  map[string]any{"os": "linux", "kernel": "test", "arch": "amd64"},
		"availability": map[string]any{"system": "unavailable", "services": "unavailable",
			"protocols": "unavailable", "traffic": "unavailable", "clients": "unavailable"},
		"counter_epoch": "0123456789abcdef0123456789abcdef",
		"system":        map[string]any{"cpu_pct": nil, "load1": nil, "mem_total_bytes": nil, "mem_used_bytes": nil, "disk_total_bytes": nil, "disk_used_bytes": nil, "net_rx_bytes": nil, "net_tx_bytes": nil},
		"services":      []any{}, "protocols": []any{}, "traffic": []any{},
		"clients": map[string]any{"active": nil, "tracked": nil, "summaries": []any{}},
	})
}
func (tlsLabCollector) Metrics(_ context.Context, rc agent.ReportContext) ([]byte, error) {
	return nil, agent.ErrUnsupported
}
func (tlsLabCollector) Events(_ context.Context, rc agent.ReportContext) ([]byte, error) {
	return json.Marshal(map[string]any{"v": 1, "type": "events", "report_id": rc.ReportID,
		"collected_at": rc.CollectedAt, "events": []any{}})
}

// TestUMCMachineTLSIndependentListener proves the optional machine listener uses
// TLS 1.3 and serves only the frozen ingest handler, with real enrollment and a
// real accepted report over the existing Ed25519 protocol.
func TestUMCMachineTLSIndependentListener(t *testing.T) {
	tc := startTestCenter(t)
	ctx := context.Background()
	now := time.Now().Unix()
	eventID := "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
	if _, err := tc.store.CreateEvent(ctx, eventID, "TLS lab", now); err != nil {
		t.Fatal(err)
	}
	token, tokenHash, err := store.NewEnrollToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := tc.store.CreateEnrollToken(ctx, tokenHash, eventID, store.NodeClassLinuxVPS, now+600, now); err != nil {
		t.Fatal(err)
	}
	var sawTLS13 atomic.Bool
	inner := tc.server.Handler()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && r.TLS.Version == tls.VersionTLS13 {
			sawTLS13.Store(true)
		}
		inner.ServeHTTP(w, r)
	})
	ts := httptest.NewUnstartedServer(handler)
	ts.StartTLS()
	defer ts.Close()

	// The machine handler must not expose browser/admin routes.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/health", nil)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("machine TLS listener exposed admin route: %d", resp.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/auth/context", nil)
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("machine TLS listener exposed web route: %d", resp.StatusCode)
	}

	r, err := agent.NewRuntime(agent.Options{
		StateDir: filepath.Join(t.TempDir(), "agent-state"), CenterURL: ts.URL,
		NodeClass: store.NodeClassLinuxVPS, HostOS: "linux", AgentVersion: "1.0.0",
		Collector: tlsLabCollector{}, HTTPClient: ts.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.Enroll(ctx, token); err != nil {
		t.Fatalf("machine TLS enroll: %v", err)
	}
	if err := r.PullConfig(ctx); err != nil {
		t.Fatalf("machine TLS config: %v", err)
	}
	if _, err := r.QueueReport(ctx, "snapshot"); err != nil {
		t.Fatalf("machine TLS queue: %v", err)
	}
	if err := r.Flush(ctx); err != nil {
		t.Fatalf("machine TLS flush: %v", err)
	}
	ident, ok := r.Identity()
	if !ok {
		t.Fatal("machine TLS enrollment identity missing")
	}
	if _, err := tc.store.GetLatestSnapshot(ctx, ident.NodeID); err != nil {
		t.Fatalf("machine TLS report not persisted: %v", err)
	}
	if !sawTLS13.Load() {
		t.Fatal("machine TLS listener did not negotiate TLS 1.3")
	}

	// An agent that does not trust the synthetic CA must fail closed.
	bad, err := agent.NewRuntime(agent.Options{
		StateDir: filepath.Join(t.TempDir(), "bad-state"), CenterURL: ts.URL,
		NodeClass: store.NodeClassLinuxVPS, HostOS: "linux", AgentVersion: "1.0.0",
		Collector: tlsLabCollector{}, HTTPClient: &http.Client{Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	if err := bad.Enroll(ctx, token); err == nil {
		t.Fatal("untrusted machine TLS CA was accepted")
	}
}

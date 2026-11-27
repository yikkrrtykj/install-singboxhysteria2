package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/center"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/schema"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/wire"
)

const testEventID = "7a1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5d"
const testContracts = "../../../docs/um/contracts/v1"

type unavailableCollector struct{}

func unavailableSnapshot(rc ReportContext) []byte {
	doc := map[string]any{
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
	raw, _ := json.Marshal(doc)
	return raw
}

func (unavailableCollector) Snapshot(_ context.Context, rc ReportContext) ([]byte, error) {
	return unavailableSnapshot(rc), nil
}
func (unavailableCollector) Metrics(context.Context, ReportContext) ([]byte, error) {
	return nil, ErrUnsupported
}
func (unavailableCollector) Events(context.Context, ReportContext) ([]byte, error) {
	return nil, ErrUnsupported
}

type agentCenter struct {
	st    *store.Store
	srv   *center.Server
	url   string
	token string
}

func startAgentCenter(t *testing.T) *agentCenter {
	t.Helper()
	dir := t.TempDir()
	db := filepath.Join(dir, "center.db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	schemas, err := schema.Load(testContracts)
	if err != nil {
		t.Fatalf("schema.Load: %v", err)
	}
	svc, err := center.NewService(center.ServiceConfig{Store: st, Schemas: schemas})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	srv, err := center.NewServer(center.Config{
		IngestAddr: "127.0.0.1:0", AdminAddr: "127.0.0.1:0",
		DBPath: db, ContractDir: testContracts, RateLimitPerSecond: -1,
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
	if err := st.CreateEnrollToken(context.Background(), hash, testEventID, store.NodeClassLinuxVPS, now+3600, now); err != nil {
		t.Fatalf("CreateEnrollToken: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close(); _ = st.Close() })
	return &agentCenter{st: st, srv: srv, url: "http://" + srv.IngestAddr(), token: token}
}

func newTestRuntime(t *testing.T, tc *agentCenter, stateDir string, col Collector, httpClient *http.Client) *Runtime {
	t.Helper()
	r, err := NewRuntime(Options{
		StateDir: stateDir, CenterURL: tc.url, NodeClass: "linux_vps", HostOS: "linux",
		Collector: col, HTTPClient: httpClient,
		Sleep:      func(context.Context, time.Duration) error { return nil },
		MaxBackoff: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	return r
}

func TestAgentEnrollConfigReportAndRestart(t *testing.T) {
	tc := startAgentCenter(t)
	dir := t.TempDir()
	col := unavailableCollector{}
	r := newTestRuntime(t, tc, dir, col, nil)
	defer r.Close()
	ctx := context.Background()
	if err := r.Enroll(ctx, tc.token); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if _, ok := r.Identity(); !ok {
		t.Fatal("identity not persisted")
	}
	if err := r.PullConfig(ctx); err != nil {
		t.Fatalf("PullConfig: %v", err)
	}
	cfg, ok := r.Config()
	if !ok || cfg.ConfigVersion < 1 || len(cfg.Collect) != 6 {
		t.Fatalf("config not persisted: %+v", cfg)
	}
	id, err := r.QueueReport(ctx, "snapshot")
	if err != nil {
		t.Fatalf("QueueReport: %v", err)
	}
	if id == "" {
		t.Fatal("empty report id")
	}
	if n := r.Status().Pending; n != 1 {
		t.Fatalf("pending=%d, want 1", n)
	}
	if err := r.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if n := r.Status().Pending; n != 0 {
		t.Fatalf("pending after ACK=%d, want 0", n)
	}
	if got := r.LastResult(); got != "accepted" && got != "duplicate" {
		t.Fatalf("last result=%q, want accepted/duplicate", got)
	}
	boot, _ := r.Boot()
	if boot.NextSeq < 2 {
		t.Fatalf("next_seq=%d, want >=2", boot.NextSeq)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Restart must not re-enroll or reset generation/sequence.
	r2 := newTestRuntime(t, tc, dir, col, nil)
	defer r2.Close()
	b2, ok := r2.Boot()
	if !ok || b2.Generation != boot.Generation+1 || b2.NextSeq != 1 || b2.BootID == boot.BootID {
		t.Fatalf("clean restart boot=%+v, want generation+1/new boot/seq1", b2)
	}
	if err := r2.Flush(ctx); err != nil {
		t.Fatalf("restart Flush: %v", err)
	}
}

func TestAgentBootStateCorruptREC17(t *testing.T) {
	tc := startAgentCenter(t)
	dir := t.TempDir()
	var requests atomic.Int64
	counting := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests.Add(1)
		return http.DefaultTransport.RoundTrip(r)
	})}
	r := newTestRuntime(t, tc, dir, unavailableCollector{}, counting)
	if err := r.Enroll(context.Background(), tc.token); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if err := r.PullConfig(context.Background()); err != nil {
		t.Fatalf("PullConfig: %v", err)
	}
	if _, err := r.QueueReport(context.Background(), "snapshot"); err != nil {
		t.Fatalf("QueueReport: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, bootStateFile)); err != nil {
		t.Fatalf("remove boot state: %v", err)
	}
	before := requests.Load()
	if _, err := NewRuntime(Options{StateDir: dir, CenterURL: tc.url, NodeClass: "linux_vps",
		HostOS: "linux", Collector: unavailableCollector{}, HTTPClient: counting,
		Sleep: func(context.Context, time.Duration) error { return nil }}); !errors.Is(err, ErrBootStateCorrupt) {
		t.Fatalf("NewRuntime with corrupt/missing boot = %v, want ErrBootStateCorrupt", err)
	}
	if requests.Load() != before {
		t.Fatal("corrupt boot state caused a center request")
	}
	entries, _ := os.ReadDir(filepath.Join(dir, spoolDir))
	if len(entries) == 0 {
		t.Fatal("boot corruption deleted retained spool data")
	}
}

func TestAgentStaleGenerationREC18(t *testing.T) {
	tc := startAgentCenter(t)
	dir := t.TempDir()
	r := newTestRuntime(t, tc, dir, unavailableCollector{}, nil)
	ctx := context.Background()
	if err := r.Enroll(ctx, tc.token); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if err := r.PullConfig(ctx); err != nil {
		t.Fatalf("PullConfig: %v", err)
	}
	// First contact at generation 12 is accepted as a bounded forward gap.
	if err := r.state.saveBoot(BootState{Version: stateVersion, Generation: 12, BootID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", NextSeq: 1}); err != nil {
		t.Fatalf("save boot: %v", err)
	}
	if _, err := r.QueueReport(ctx, "snapshot"); err != nil {
		t.Fatalf("gen12 queue: %v", err)
	}
	if err := r.Flush(ctx); err != nil {
		t.Fatalf("gen12 flush: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Simulate an abrupt restore of an old snapshot (no clean-shutdown marker).
	if err := os.Remove(filepath.Join(dir, cleanShutdownFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("remove clean marker: %v", err)
	}
	var boot BootState
	raw, err := os.ReadFile(filepath.Join(dir, bootStateFile))
	if err != nil {
		t.Fatalf("read boot: %v", err)
	}
	if err := json.Unmarshal(raw, &boot); err != nil {
		t.Fatalf("parse boot: %v", err)
	}
	boot.Generation = 9
	boot.NextSeq = 1
	boot.Exhausted = false
	if err := writeAtomic(filepath.Join(dir, bootStateFile), mustJSON(boot)); err != nil {
		t.Fatalf("rewrite boot: %v", err)
	}
	r2 := newTestRuntime(t, tc, dir, unavailableCollector{}, nil)
	defer r2.Close()
	if _, err := r2.QueueReport(ctx, "snapshot"); err != nil {
		t.Fatalf("stale queue: %v", err)
	}
	if err := r2.Flush(ctx); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("stale report = %v, want ErrStaleGeneration", err)
	}
	b, _ := r2.Boot()
	if b.Generation != 10 {
		t.Fatalf("old snapshot was not advanced to the next restart generation: %d", b.Generation)
	}
	if n := r2.Status().Pending; n != 1 {
		t.Fatalf("spool retained=%d, want 1", n)
	}
}

func TestAgentACKLossDuplicateREC27(t *testing.T) {
	tc := startAgentCenter(t)
	dir := t.TempDir()
	r := newTestRuntime(t, tc, dir, unavailableCollector{}, nil)
	defer r.Close()
	ctx := context.Background()
	if err := r.Enroll(ctx, tc.token); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if err := r.PullConfig(ctx); err != nil {
		t.Fatalf("PullConfig: %v", err)
	}
	// Fixture REC-27 setup: center generation 3, boot b3, last_seq 4.
	if err := r.state.saveBoot(BootState{Version: stateVersion, Generation: 3,
		BootID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", NextSeq: 1}); err != nil {
		t.Fatalf("save boot: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := r.QueueReport(ctx, "snapshot"); err != nil {
			t.Fatalf("seed queue %d: %v", i, err)
		}
		if err := r.Flush(ctx); err != nil {
			t.Fatalf("seed flush %d: %v", i, err)
		}
	}
	// Fourth attempt is accepted by the center but its ACK is lost locally.
	if _, err := r.QueueReport(ctx, "snapshot"); err != nil {
		t.Fatalf("queue fourth: %v", err)
	}
	recs, err := r.state.spool.List()
	if err != nil || len(recs) != 1 || recs[0].Attempt.Seq != 4 ||
		recs[0].Attempt.Generation != 3 || recs[0].Attempt.BootID != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("fourth spool record: %v %+v", err, recs)
	}
	ident, _ := r.Identity()
	ack, err := r.client.Report(ctx, ident, recs[0].Attempt, recs[0].Kind, recs[0].Body)
	if err != nil || (ack.Result != "accepted" && ack.Result != "stale_ignored") {
		t.Fatalf("direct accepted report: ack=%+v err=%v", ack, err)
	}
	// Same-runtime ACK loss: the persisted attempt is retried exactly, within the
	// same generation/boot/seq. This preserves the frozen REC-27 exact-duplicate
	// consistency case even under the stricter restart rule.
	if err := r.Flush(ctx); err != nil {
		t.Fatalf("retry duplicate: %v", err)
	}
	if got := r.LastResult(); got != "duplicate" {
		t.Fatalf("retry result=%q, want duplicate", got)
	}
	if n := r.Status().Pending; n != 0 {
		t.Fatalf("spool after duplicate=%d, want 0", n)
	}
	if b, _ := r.Boot(); b.Generation != 3 || b.NextSeq != 5 {
		t.Fatalf("same-runtime duplicate boot=%+v, want gen3/seq5", b)
	}
}

// TestAgentRestartAfterLostACKNewGeneration covers the proposed power-loss
// amendment: a process restart always enters a new generation, preserves the
// fsynced report_id/body, and the first new-generation report is a duplicate
// that advances the new generation high-water.
func TestAgentRestartAfterLostACKNewGeneration(t *testing.T) {
	tc := startAgentCenter(t)
	dir := t.TempDir()
	r := newTestRuntime(t, tc, dir, unavailableCollector{}, nil)
	ctx := context.Background()
	if err := r.Enroll(ctx, tc.token); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if err := r.PullConfig(ctx); err != nil {
		t.Fatalf("PullConfig: %v", err)
	}
	if err := r.state.saveBoot(BootState{Version: stateVersion, Generation: 3,
		BootID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", NextSeq: 1}); err != nil {
		t.Fatalf("save boot: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := r.QueueReport(ctx, "snapshot"); err != nil {
			t.Fatalf("seed queue %d: %v", i, err)
		}
		if err := r.Flush(ctx); err != nil {
			t.Fatalf("seed flush %d: %v", i, err)
		}
	}
	if _, err := r.QueueReport(ctx, "snapshot"); err != nil {
		t.Fatalf("queue fourth: %v", err)
	}
	recs, err := r.state.spool.List()
	if err != nil || len(recs) != 1 {
		t.Fatalf("fourth spool: %v %+v", err, recs)
	}
	ident, _ := r.Identity()
	ack, err := r.client.Report(ctx, ident, recs[0].Attempt, recs[0].Kind, recs[0].Body)
	if err != nil || (ack.Result != "accepted" && ack.Result != "stale_ignored") {
		t.Fatalf("direct accepted report: ack=%+v err=%v", ack, err)
	}
	oldBoot, _ := r.Boot()
	if err := r.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Abrupt restart: no clean marker.
	if err := os.Remove(filepath.Join(dir, cleanShutdownFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("remove clean marker: %v", err)
	}
	r2 := newTestRuntime(t, tc, dir, unavailableCollector{}, nil)
	defer r2.Close()
	newBoot, _ := r2.Boot()
	if newBoot.Generation != oldBoot.Generation+1 || newBoot.BootID == oldBoot.BootID {
		t.Fatalf("restart boot=%+v, old=%+v, want gen+1/new boot", newBoot, oldBoot)
	}
	if err := r2.Flush(ctx); err != nil {
		t.Fatalf("restart duplicate: %v", err)
	}
	if got := r2.LastResult(); got != "duplicate" {
		t.Fatalf("restart result=%q, want duplicate", got)
	}
	if n := r2.Status().Pending; n != 0 {
		t.Fatalf("spool after restart duplicate=%d, want 0", n)
	}
	gotBoot, _ := r2.Boot()
	if gotBoot.Generation != newBoot.Generation || gotBoot.NextSeq != 2 {
		t.Fatalf("new-generation boot after duplicate=%+v, want gen %d/seq2", gotBoot, newBoot.Generation)
	}
	stats, err := tc.st.CapacityStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Snapshots != 4 {
		t.Fatalf("restart duplicate stored extra snapshot: %+v", stats)
	}
}

func TestAgentRotationIntentSurvivesRestart(t *testing.T) {
	tc := startAgentCenter(t)
	dir := t.TempDir()
	r := newTestRuntime(t, tc, dir, unavailableCollector{}, nil)
	ctx := context.Background()
	if err := r.Enroll(ctx, tc.token); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if err := r.PullConfig(ctx); err != nil {
		t.Fatalf("PullConfig: %v", err)
	}
	if err := r.Rotate(ctx); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	rot, ok := r.state.Rotation()
	if !ok || rot.NewKeyID == "" {
		t.Fatalf("rotation not persisted: %+v", rot)
	}
	oldKey := r.state.identity.KeyID
	if err := r.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Unclean restart: the next runtime start advances generation/boot and
	// refreshes the pending control/proof attempt; payload identity is preserved.
	if err := os.Remove(filepath.Join(dir, cleanShutdownFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("remove clean marker: %v", err)
	}
	r2 := newTestRuntime(t, tc, dir, unavailableCollector{}, nil)
	defer r2.Close()
	if err := r2.Flush(ctx); err != nil {
		t.Fatalf("proof after restart: %v", err)
	}
	ident, _ := r2.Identity()
	if ident.KeyID == oldKey {
		t.Fatalf("rotation proof did not switch key: %s", ident.KeyID)
	}
	if _, ok := r2.state.Rotation(); ok {
		t.Fatal("rotation state not cleared after accepted proof")
	}
}

func TestAgentRotationWithPendingSpoolUsesNewIdentity(t *testing.T) {
	tc := startAgentCenter(t)
	r := newTestRuntime(t, tc, t.TempDir(), unavailableCollector{}, nil)
	defer r.Close()
	ctx := context.Background()
	if err := r.Enroll(ctx, tc.token); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if err := r.PullConfig(ctx); err != nil {
		t.Fatalf("PullConfig: %v", err)
	}
	oldIdent, ok := r.Identity()
	if !ok {
		t.Fatal("identity missing")
	}
	if _, err := r.QueueReport(ctx, "snapshot"); err != nil {
		t.Fatalf("QueueReport: %v", err)
	}
	if n := r.Status().Pending; n != 1 {
		t.Fatalf("pending before rotation=%d, want 1", n)
	}
	if err := r.Rotate(ctx); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if n := r.Status().Pending; n != 1 {
		t.Fatalf("pending before proof=%d, want 1", n)
	}
	// Flush first completes the persisted proof (activating the new key), then
	// must drain the pending report with the reloaded identity.
	if err := r.Flush(ctx); err != nil {
		t.Fatalf("flush after rotation proof: %v", err)
	}
	newIdent, ok := r.Identity()
	if !ok || newIdent.KeyID == oldIdent.KeyID {
		t.Fatalf("rotation did not activate new identity: %+v", newIdent)
	}
	if n := r.Status().Pending; n != 0 {
		t.Fatalf("pending after new-key flush=%d, want 0", n)
	}
	if got := r.LastResult(); got != "accepted" && got != "duplicate" && got != "stale_ignored" {
		t.Fatalf("new-key report result=%q", got)
	}
}

func TestAgentRunResumesAfterRecoveredConfigRetry(t *testing.T) {
	tc := startAgentCenter(t)
	var failConfig atomic.Bool
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if strings.HasSuffix(req.URL.Path, "/config") && failConfig.CompareAndSwap(true, false) {
			return nil, errors.New("transient config failure")
		}
		return http.DefaultTransport.RoundTrip(req)
	})}
	r := newTestRuntime(t, tc, t.TempDir(), unavailableCollector{}, client)
	defer r.Close()
	if err := r.Enroll(context.Background(), tc.token); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if err := r.PullConfig(context.Background()); err != nil {
		t.Fatalf("initial PullConfig: %v", err)
	}
	r.opts.Sleep = func(ctx context.Context, _ time.Duration) error {
		select {
		case <-time.After(10 * time.Millisecond):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	r.lastConfigCheck = 0
	failConfig.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	runErr := r.Run(ctx)
	if !errors.Is(runErr, context.DeadlineExceeded) {
		t.Fatalf("Run returned %v after a recovered config retry; want context deadline (loop must continue)", runErr)
	}
	if stats, err := tc.st.CapacityStats(context.Background()); err != nil || stats.Snapshots == 0 {
		t.Fatalf("collection did not resume after recovery: stats=%+v err=%v", stats, err)
	}
}

func TestAgentRunRecoversCommittedProofBeforeConfig(t *testing.T) {
	tc := startAgentCenter(t)
	var dropProof atomic.Bool
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			return nil, err
		}
		if dropProof.Load() && strings.HasSuffix(req.URL.Path, "/report") {
			// The center has committed the proof (and revoked the old key), but
			// the agent never sees the ACK.
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			return nil, errors.New("simulated proof ACK loss")
		}
		return resp, nil
	})}
	dir := t.TempDir()
	r := newTestRuntime(t, tc, dir, unavailableCollector{}, client)
	ctx := context.Background()
	if err := r.Enroll(ctx, tc.token); err != nil {
		t.Fatal(err)
	}
	if err := r.PullConfig(ctx); err != nil {
		t.Fatal(err)
	}
	if err := r.Rotate(ctx); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if rot, ok := r.state.Rotation(); !ok || rot.NewKeyID == "" {
		t.Fatalf("rotation intent missing: %+v", rot)
	}
	dropProof.Store(true)
	_ = r.Flush(ctx) // center commits proof; ACK lost; local identity stays old
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	// Abrupt restart: no clean-shutdown marker.
	if err := os.Remove(filepath.Join(dir, cleanShutdownFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	r2 := newTestRuntime(t, tc, dir, unavailableCollector{}, nil)
	defer r2.Close()
	r2.opts.Sleep = func(ctx context.Context, _ time.Duration) error {
		select {
		case <-time.After(5 * time.Millisecond):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	runCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	err := r2.Run(runCtx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run after proof ACK loss = %v, want continued loop until deadline", err)
	}
	if _, err := os.Stat(filepath.Join(dir, failClosedFile)); err == nil {
		t.Fatal("agent wrote fail-closed marker instead of recovering provisional identity")
	}
	ident, ok := r2.Identity()
	if !ok || ident.KeyID == "" {
		t.Fatal("identity missing after recovery")
	}
}

func TestAgentOnceFlushRecoversProofBeforeConfig(t *testing.T) {
	tc := startAgentCenter(t)
	var dropProof atomic.Bool
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			return nil, err
		}
		if dropProof.Load() && strings.HasSuffix(req.URL.Path, "/report") {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			return nil, errors.New("simulated proof ACK loss")
		}
		return resp, nil
	})}
	dir := t.TempDir()
	r := newTestRuntime(t, tc, dir, unavailableCollector{}, client)
	ctx := context.Background()
	if err := r.Enroll(ctx, tc.token); err != nil {
		t.Fatal(err)
	}
	if err := r.PullConfig(ctx); err != nil {
		t.Fatal(err)
	}
	old, _ := r.Identity()
	if err := r.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	dropProof.Store(true)
	_ = r.Flush(ctx) // center commits the proof, ACK lost
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, cleanShutdownFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	r2 := newTestRuntime(t, tc, dir, unavailableCollector{}, nil)
	defer r2.Close()
	// This is exactly the `um-agent run --once` ordering.
	if err := r2.Flush(ctx); err != nil {
		t.Fatalf("once proof recovery: %v", err)
	}
	if err := r2.PullConfig(ctx); err != nil {
		t.Fatalf("once config after proof recovery: %v", err)
	}
	got, _ := r2.Identity()
	if got.KeyID == old.KeyID {
		t.Fatal("once path did not persist the recovered identity")
	}
	if _, err := os.Stat(filepath.Join(dir, failClosedFile)); err == nil {
		t.Fatal("once path wrote fail-closed marker")
	}
}

func TestAgentProofRotationExpiredClearsIntent(t *testing.T) {
	tc := startAgentCenter(t)
	var expire atomic.Bool
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if expire.Load() && strings.HasSuffix(req.URL.Path, "/report") {
			return &http.Response{StatusCode: http.StatusBadRequest,
				Header: http.Header{"Content-Type": []string{"application/json"}},
				Body: io.NopCloser(strings.NewReader(
					`{"v":1,"error":"rotation_expired","retryable":false,"server_time":1795622400}`)),
				Request: req}, nil
		}
		return http.DefaultTransport.RoundTrip(req)
	})}
	dir := t.TempDir()
	r := newTestRuntime(t, tc, dir, unavailableCollector{}, client)
	defer r.Close()
	ctx := context.Background()
	if err := r.Enroll(ctx, tc.token); err != nil {
		t.Fatal(err)
	}
	if err := r.PullConfig(ctx); err != nil {
		t.Fatal(err)
	}
	old, _ := r.Identity()
	if err := r.Rotate(ctx); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	expire.Store(true)
	if err := r.Flush(ctx); err != nil {
		t.Fatalf("rotation_expired proof became fatal: %v", err)
	}
	if rot, ok := r.state.Rotation(); ok {
		t.Fatalf("expired rotation intent retained: %+v", rot)
	}
	got, ok := r.Identity()
	if !ok || got.KeyID != old.KeyID {
		t.Fatalf("identity changed on rotation_expired: %+v", got)
	}
	if _, err := os.Stat(filepath.Join(dir, failClosedFile)); err == nil {
		t.Fatal("rotation_expired wrote fail-closed marker")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

var _ = fmt.Sprintf

func TestAgentRevokedFailsClosed(t *testing.T) {
	tc := startAgentCenter(t)
	r := newTestRuntime(t, tc, t.TempDir(), unavailableCollector{}, nil)
	defer r.Close()
	ctx := context.Background()
	if err := r.Enroll(ctx, tc.token); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if err := r.PullConfig(ctx); err != nil {
		t.Fatalf("PullConfig: %v", err)
	}
	ident, _ := r.Identity()
	if err := tc.st.RevokeNode(ctx, ident.NodeID, time.Now().Unix()); err != nil {
		t.Fatalf("RevokeNode: %v", err)
	}
	if _, err := r.QueueReport(ctx, "snapshot"); err != nil {
		t.Fatalf("queue: %v", err)
	}
	if err := r.Flush(ctx); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked flush = %v, want ErrRevoked", err)
	}
	if !r.Status().Revoked {
		t.Fatal("runtime did not expose revoked fail-closed status")
	}
	pending := r.Status().Pending
	if err := r.Close(); err != nil {
		t.Fatalf("close revoked runtime: %v", err)
	}
	if _, err := NewRuntime(Options{StateDir: r.state.StateDir(), CenterURL: tc.url, NodeClass: "linux_vps",
		HostOS: "linux", Collector: unavailableCollector{},
		Sleep: func(context.Context, time.Duration) error { return nil }}); !errors.Is(err, ErrFailClosed) {
		t.Fatalf("restart after revoked = %v, want ErrFailClosed", err)
	}
	if pending == 0 {
		t.Fatal("revocation should retain spooled payload for operator inspection")
	}
}

func TestAgentGenerationExhaustion(t *testing.T) {
	tc := startAgentCenter(t)
	r := newTestRuntime(t, tc, t.TempDir(), unavailableCollector{}, nil)
	defer r.Close()
	ctx := context.Background()
	if err := r.Enroll(ctx, tc.token); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if err := r.PullConfig(ctx); err != nil {
		t.Fatalf("PullConfig: %v", err)
	}
	boot, _ := r.Boot()
	boot.NextSeq = wire.MaxNumeric
	boot.Exhausted = false
	if err := r.state.saveBoot(boot); err != nil {
		t.Fatalf("save max boot: %v", err)
	}
	if _, err := r.QueueReport(ctx, "snapshot"); err != nil {
		t.Fatalf("queue max: %v", err)
	}
	if err := r.Flush(ctx); !errors.Is(err, ErrGenerationExhausted) {
		t.Fatalf("max numeric flush = %v, want ErrGenerationExhausted", err)
	}
	b, _ := r.Boot()
	if !b.Exhausted {
		t.Fatal("boot state not marked exhausted after null next_seq")
	}
	if n := r.Status().Pending; n != 0 {
		t.Fatalf("exhausted ACK spool=%d, want 0", n)
	}
}

func TestAgentCleanRestartReplaysSpoolUnderNewGeneration(t *testing.T) {
	tc := startAgentCenter(t)
	dir := t.TempDir()
	r := newTestRuntime(t, tc, dir, unavailableCollector{}, nil)
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
	before, _ := r.Boot()
	if err := r.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	r2 := newTestRuntime(t, tc, dir, unavailableCollector{}, nil)
	defer r2.Close()
	after, _ := r2.Boot()
	if after.Generation != before.Generation+1 || after.BootID == before.BootID || after.NextSeq != 2 {
		t.Fatalf("clean restart boot=%+v, want new generation/boot with seq advanced by replay", after)
	}
	recs, err := r2.state.spool.List()
	if err != nil || len(recs) != 1 || recs[0].Attempt.Generation != after.Generation || recs[0].Attempt.Seq != 1 {
		t.Fatalf("replayed spool attempt: %v %+v", err, recs)
	}
	if err := r2.Flush(ctx); err != nil {
		t.Fatalf("flush replayed spool: %v", err)
	}
	if n := r2.Status().Pending; n != 0 {
		t.Fatalf("pending after replay=%d", n)
	}
}

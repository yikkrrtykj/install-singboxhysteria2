package center_test

// B2 conformance: the 15 REC cases owned by UM-B2 plus REC-29, executed through
// the real HTTP listener, real SQLite store and real service execution path.
// B1's conformance package remains the regression suite for the 11 B1 cases.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/center"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/schema"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/wire"
)

func b2BaseCollected(t *testing.T) int64 {
	t.Helper()
	doc := b2Example(t, "report-snapshot.v1.json")
	return int64(doc["collected_at"].(float64))
}

func b2SnapshotDoc(t *testing.T, collectedAt int64) map[string]any {
	t.Helper()
	doc := b2Example(t, "report-snapshot.v1.json")
	doc["report_id"] = b2UUID(t)
	doc["collected_at"] = collectedAt
	return doc
}

func b2SendReport(t *testing.T, tc *testCenter, a *syntheticAgent, doc map[string]any, nonce string) (int, map[string]any) {
	t.Helper()
	body := b2JSON(t, doc)
	now := time.Now().Unix()
	a.seq++
	h, err := a.headers(wire.Report, now, nonce, body)
	if err != nil {
		t.Fatalf("headers: %v", err)
	}
	return doPost(t, tc, "/v1/agent/report", h, body)
}

func b2ReportWithSeq(t *testing.T, tc *testCenter, a *syntheticAgent, doc map[string]any, nonce string, seq uint64) (int, map[string]any) {
	t.Helper()
	body := b2JSON(t, doc)
	a.seq = seq
	h, err := a.headers(wire.Report, time.Now().Unix(), nonce, body)
	if err != nil {
		t.Fatalf("headers: %v", err)
	}
	return doPost(t, tc, "/v1/agent/report", h, body)
}

func b2CloseCenter(t *testing.T, tc *testCenter) {
	t.Helper()
	if err := tc.server.Shutdown(contextWithTimeout(t, 5*time.Second)); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if err := tc.store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
}

func b2FaultService(t *testing.T, dbPath string, failOnce bool) (*testCenter, *center.Server) {
	t.Helper()
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	schemas, err := schema.Load(contractsDir)
	if err != nil {
		t.Fatalf("schemas: %v", err)
	}
	real, err := center.NewService(center.ServiceConfig{Store: st, Schemas: schemas})
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	wrapped := &faultOnceService{Service: real, fail: failOnce}
	cfg := center.Config{IngestAddr: "127.0.0.1:0", AdminAddr: "127.0.0.1:0", DBPath: dbPath, ContractDir: contractsDir, RateLimitPerSecond: -1}
	srv, err := center.NewServer(cfg, wrapped)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	tc := &testCenter{store: st, server: srv, url: "http://" + srv.IngestAddr(), dbPath: dbPath}
	t.Cleanup(func() { _ = srv.Close(); _ = st.Close() })
	return tc, srv
}

type faultOnceService struct {
	center.Service
	fail bool
}

func (f *faultOnceService) Report(ctx context.Context, req center.ReportRequest) (center.ReportResult, error) {
	if f.fail {
		f.fail = false
		return center.ReportResult{}, center.NewAPIError(503, "storage_unavailable", true)
	}
	return f.Service.Report(ctx, req)
}

func TestB2REC03LostACKDuplicate(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	a.gen = 5 // fixture setup: generation 5 high-water
	base := b2BaseCollected(t)
	doc := b2SnapshotDoc(t, base)
	nonce := b2Nonce(t)
	status, resp := b2SendReport(t, tc, a, doc, nonce)
	if status != 200 || resp["result"] != "accepted" {
		t.Fatalf("REC-03 first: %d %v", status, resp)
	}
	// Lost ACK: new seq/nonce, same report_id/body content.
	status, resp = b2SendReport(t, tc, a, doc, b2Nonce(t))
	if status != 200 || resp["result"] != "duplicate" {
		t.Fatalf("REC-03 retry: %d %v", status, resp)
	}
	boot, _ := tc.store.GetBoot(context.Background(), a.nodeID)
	if boot.LastSeq != a.seq {
		t.Fatalf("REC-03 high-water=%d want %d", boot.LastSeq, a.seq)
	}
	b2AssertREC(t, "REC-03", status, resp)
	b2AssertRECCenter(t, "REC-03", tc, a.nodeID)
}

func TestB2REC04NewGenerationFirstReportDuplicate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "center.db")
	tc := startTestCenterAt(t, path)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	base := b2BaseCollected(t)
	doc := b2SnapshotDoc(t, base)
	a.gen = 5
	a.seq = 2 // fixture setup: gen5/last_seq3
	if status, resp := b2SendReport(t, tc, a, doc, b2Nonce(t)); status != 200 || resp["result"] != "accepted" {
		t.Fatalf("REC-04 seed: %d %v", status, resp)
	}
	b2CloseCenter(t, tc)
	// New center/restart; agent generation 6, new boot id, replay duplicate report.
	tc = startTestCenterAt(t, path)
	a.gen = 6
	a.bootID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	a.seq = 0
	status, resp := b2SendReport(t, tc, a, doc, b2Nonce(t))
	if status != 200 || resp["result"] != "duplicate" {
		t.Fatalf("REC-04 first new-gen report: %d %v", status, resp)
	}
	boot, _ := tc.store.GetBoot(context.Background(), a.nodeID)
	if boot.HighestGen != a.gen || boot.LastSeq != a.seq {
		t.Fatalf("REC-04 high-water=%+v want gen=%d seq=%d", boot, a.gen, a.seq)
	}
	b2AssertREC(t, "REC-04", status, resp)
	b2AssertRECCenter(t, "REC-04", tc, a.nodeID)
}

func TestB2REC05GenerationGap(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	base := b2BaseCollected(t)
	// Fixture setup: existing high-water at generation 4, then two offline
	// restarts (generation 6, forward gap 2).
	db := rawDB(t, tc)
	before := rawCount(t, db, `SELECT COUNT(*) FROM security_ledger WHERE kind='boot_generation_gap'`)
	a.gen = 4
	if status, resp := b2SendReport(t, tc, a, b2SnapshotDoc(t, base), b2Nonce(t)); status != 200 || resp["result"] != "accepted" {
		t.Fatalf("REC-05 seed high-water: %d %v", status, resp)
	}
	a.gen = 6
	a.seq = 0
	a.bootID = "abababababababababababababababab"
	status, resp := b2SendReport(t, tc, a, b2SnapshotDoc(t, base+1), b2Nonce(t))
	if status != 200 || resp["result"] != "accepted" {
		t.Fatalf("REC-05 gap: %d %v", status, resp)
	}
	b2AssertREC(t, "REC-05", status, resp)
	b2AssertRECCenter(t, "REC-05", tc, a.nodeID)
	boot, err := tc.store.GetBoot(context.Background(), a.nodeID)
	if err != nil || boot.HighestGen != 6 {
		t.Fatalf("REC-05 high-water = %+v err=%v", boot, err)
	}
	if n := rawCount(t, db, `SELECT COUNT(*) FROM security_ledger WHERE kind='boot_generation_gap'`); n-before != 1 {
		t.Fatalf("REC-05 boot_generation_gap audit delta=%d, want 1", n-before)
	}
}

func TestB2REC06SpoolReplayOldestFirst(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	a.gen = 6 // fixture setup: agent generation 6, center highest_gen 2
	base := b2BaseCollected(t)
	first := b2SnapshotDoc(t, base)
	second := b2SnapshotDoc(t, base+10)
	if status, resp := b2SendReport(t, tc, a, first, b2Nonce(t)); status != 200 || resp["result"] != "accepted" {
		t.Fatalf("REC-06 first: %d %v", status, resp)
	}
	if status, resp := b2SendReport(t, tc, a, second, b2Nonce(t)); status != 200 || resp["result"] != "accepted" {
		t.Fatalf("REC-06 second: %d %v", status, resp)
	}
	// Duplicate replay of the first report after the second is acknowledged as
	// duplicate without overwriting newest data.
	status, resp := b2SendReport(t, tc, a, first, b2Nonce(t))
	if status != 200 || resp["result"] != "duplicate" {
		t.Fatalf("REC-06 duplicate: %d %v", status, resp)
	}
	latest, err := tc.store.GetLatestSnapshot(context.Background(), a.nodeID)
	if err != nil || latest.ReportID != second["report_id"] {
		t.Fatalf("REC-06 latest=%+v err=%v", latest, err)
	}
	b2AssertREC(t, "REC-06", status, resp)
	b2AssertRECCenter(t, "REC-06", tc, a.nodeID)
}

func TestB2REC10DelayedLowerSequenceConflict(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	base := b2BaseCollected(t)
	if status, resp := b2ReportWithSeq(t, tc, a, b2SnapshotDoc(t, base), b2Nonce(t), 3); status != 200 || resp["result"] != "accepted" {
		t.Fatalf("REC-10 seed: %d %v", status, resp)
	}
	status, resp := b2ReportWithSeq(t, tc, a, b2SnapshotDoc(t, base+1), b2Nonce(t), 2)
	if status != 409 || resp["error"] != "sequence_conflict" {
		t.Fatalf("REC-10 delayed: %d %v, want 409 sequence_conflict", status, resp)
	}
	b2AssertREC(t, "REC-10", status, resp)
}

func TestB2REC13ACKNextSeqReconciliation(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	a.gen = 2 // fixture setup: center high-water last_seq 7, agent next_seq 9
	for _, attempt := range []struct {
		seq  uint64
		next float64
	}{{7, 8}, {9, 10}} {
		status, resp := b2ReportWithSeq(t, tc, a, b2SnapshotDoc(t, b2BaseCollected(t)+int64(attempt.seq)), b2Nonce(t), attempt.seq)
		if status != 200 || resp["result"] != "accepted" {
			t.Fatalf("REC-13 report seq%d: %d %v", attempt.seq, status, resp)
		}
		if next, _ := resp["next_seq"].(float64); next != attempt.next {
			t.Fatalf("REC-13 seq%d next_seq=%v want %.0f", attempt.seq, resp["next_seq"], attempt.next)
		}
		b2AssertREC(t, "REC-13", status, resp)
	}
	b2AssertRECCenter(t, "REC-13", tc, a.nodeID)
}

func TestB2REC15AbortedTransactionThenRetry(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	a.gen = 3
	doc := b2SnapshotDoc(t, b2BaseCollected(t))
	tc.store.SetIngestHookForTest(func(stage string) error {
		if stage == "after_highwater" {
			return errors.New("injected SQLite transaction failure")
		}
		return nil
	})
	status, resp := b2SendReport(t, tc, a, doc, b2Nonce(t))
	if status != 503 || resp["error"] != "storage_unavailable" {
		t.Fatalf("REC-15 injected transaction failure: %d %v", status, resp)
	}
	db := rawDB(t, tc)
	for _, q := range []string{
		`SELECT COUNT(*) FROM node_boot`, `SELECT COUNT(*) FROM seq_dedupe`,
		`SELECT COUNT(*) FROM nonce_dedupe`, `SELECT COUNT(*) FROM report_dedupe`,
		`SELECT COUNT(*) FROM snapshots`,
	} {
		if n := rawCount(t, db, q); n != 0 {
			t.Fatalf("REC-15 failed transaction left rows: %s=%d", q, n)
		}
	}
	tc.store.SetIngestHookForTest(nil)
	status, resp = b2SendReport(t, tc, a, doc, b2Nonce(t))
	if status != 200 || resp["result"] != "accepted" {
		t.Fatalf("REC-15 retry: %d %v", status, resp)
	}
	b2AssertREC(t, "REC-15", status, resp)
	b2AssertRECCenter(t, "REC-15", tc, a.nodeID)
}

func TestB2REC16NonRetryablePayloadThenNextRecord(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	a.gen = 3
	bad := map[string]any{"v": 1, "type": "snapshot", "report_id": b2UUID(t), "collected_at": b2BaseCollected(t)}
	a.seq++
	h, _ := a.headers(wire.Report, time.Now().Unix(), b2Nonce(t), b2JSON(t, bad))
	status, resp := doPost(t, tc, "/v1/agent/report", h, b2JSON(t, bad))
	if status != 400 || resp["error"] != "invalid_request" {
		t.Fatalf("REC-16 bad payload: %d %v", status, resp)
	}
	status, resp = b2SendReport(t, tc, a, b2SnapshotDoc(t, b2BaseCollected(t)+1), b2Nonce(t))
	if status != 200 || resp["result"] != "accepted" {
		t.Fatalf("REC-16 next record: %d %v", status, resp)
	}
	b2AssertREC(t, "REC-16", status, resp)
	b2AssertRECCenter(t, "REC-16", tc, a.nodeID)
}

func b2RotateBody(t *testing.T) []byte {
	t.Helper()
	rotate := b2Example(t, "rotate-request.v1.json")
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("rotate key: %v", err)
	}
	rotate["new_pubkey"] = base64URL(pub)
	return b2JSON(t, rotate)
}

func b2RotateSigned(t *testing.T, tc *testCenter, a *syntheticAgent, body []byte, nonce string, seq uint64, gen uint64, bootID string) (int, map[string]any) {
	t.Helper()
	a.seq, a.gen, a.bootID = seq, gen, bootID
	h, err := a.headers(wire.Rotate, time.Now().Unix(), nonce, body)
	if err != nil {
		t.Fatalf("rotate headers: %v", err)
	}
	return doPost(t, tc, "/v1/agent/rotate", h, body)
}

func TestB2REC19RotateIntentAcrossRestarts(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	nonce := b2Nonce(t)
	rotateBody := b2RotateBody(t)
	status, first := b2RotateSigned(t, tc, a, rotateBody, nonce, 2, 1, a.bootID)
	if status != 200 || first["new_key_id"] == nil {
		t.Fatalf("REC-19 create: %d %v", status, first)
	}
	// Two offline restarts: refreshed gen/seq but same nonce/body while awaiting.
	status, replay := b2RotateSigned(t, tc, a, rotateBody, nonce, 5, 3, "cccccccccccccccccccccccccccccccc")
	if status != 200 || replay["new_key_id"] != first["new_key_id"] {
		t.Fatalf("REC-19 replay: %d %v", status, replay)
	}
	boot, _ := tc.store.GetBoot(context.Background(), a.nodeID)
	if boot.HighestGen != 3 {
		t.Fatalf("REC-19 high-water gen=%d want 3", boot.HighestGen)
	}
	b2AssertREC(t, "REC-19", status, replay)
}

func TestB2REC20RotateExpired(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	nonce := b2Nonce(t)
	rotateBody := b2RotateBody(t)
	status, first := b2RotateSigned(t, tc, a, rotateBody, nonce, 2, 1, a.bootID)
	if status != 200 || first["new_key_id"] == nil {
		t.Fatalf("REC-20 create: %d %v", status, first)
	}
	// Advance the intent expiry directly in SQLite to avoid a 300s wall clock.
	db, err := sql.Open("sqlite", tc.dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE key_rotations SET expires_at=? WHERE node_id=? AND nonce=?`, time.Now().Unix()-1, a.nodeID, nonce); err != nil {
		t.Fatalf("expire rotation: %v", err)
	}
	status, resp := b2RotateSigned(t, tc, a, rotateBody, nonce, 5, 2, "dddddddddddddddddddddddddddddddd")
	if status != 409 || resp["error"] != "rotation_expired" {
		t.Fatalf("REC-20 replay: %d %v, want 409 rotation_expired", status, resp)
	}
	b2AssertREC(t, "REC-20", status, resp)
}

func TestB2REC21RevokedDuringBacklog(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	if status, resp := b2SendReport(t, tc, a, b2SnapshotDoc(t, b2BaseCollected(t)), b2Nonce(t)); status != 200 || resp["result"] != "accepted" {
		t.Fatalf("REC-21 seed: %d %v", status, resp)
	}
	if err := tc.store.RevokeNode(context.Background(), a.nodeID, time.Now().Unix()); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	status, resp := b2SendReport(t, tc, a, b2SnapshotDoc(t, b2BaseCollected(t)+1), b2Nonce(t))
	if status != 401 || resp["error"] != "revoked_key" {
		t.Fatalf("REC-21 after revoke: %d %v", status, resp)
	}
	b2AssertREC(t, "REC-21", status, resp)
}

func TestB2REC22FirstContactConfig(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	body := []byte("{}")
	a.gen = 5
	a.seq = 2 // fixture setup: gen5/last_seq2
	h, _ := a.headers(wire.Config, time.Now().Unix(), b2Nonce(t), body)
	status, resp := doPost(t, tc, "/v1/agent/config", h, body)
	if status != 200 || resp["v"].(float64) != 1 {
		t.Fatalf("REC-22: %d %v", status, resp)
	}
	b2AssertREC(t, "REC-22", status, resp)
	b2AssertRECCenter(t, "REC-22", tc, a.nodeID)
}

func TestB2REC23FirstContactRotate(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	status, resp := b2RotateSigned(t, tc, a, b2RotateBody(t), b2Nonce(t), 2, 6, a.bootID)
	if status != 200 || resp["new_key_id"] == nil {
		t.Fatalf("REC-23: %d %v", status, resp)
	}
	b2AssertREC(t, "REC-23", status, resp)
	b2AssertRECCenter(t, "REC-23", tc, a.nodeID)
}

func TestB2REC24EnrollmentResponseLoss(t *testing.T) {
	tc := startTestCenter(t)
	a := newAgent(t)
	body := b2Example(t, "enroll-request.v1.json")
	body["node_class"] = store.NodeClassLinuxVPS
	body["host"].(map[string]any)["os"] = "linux"
	raw := b2JSON(t, body)
	token, hash, _ := store.NewEnrollToken()
	now := time.Now().Unix()
	if err := tc.store.CreateEnrollToken(context.Background(), hash, eventUUID, store.NodeClassLinuxVPS, now+3600, now); err != nil {
		t.Fatalf("token: %v", err)
	}
	h, _ := a.headers(wire.Enroll, now, b2Nonce(t), raw)
	h.Set(wire.HeaderAuthorization, "Bearer "+token)
	status, first := doPost(t, tc, "/v1/agent/enroll", h, raw)
	if status != 200 || first["node_id"] == nil {
		t.Fatalf("REC-24 first enroll: %d %v", status, first)
	}
	// Simulated response loss: replay token.
	h2, _ := a.headers(wire.Enroll, now, b2Nonce(t), raw)
	h2.Set(wire.HeaderAuthorization, "Bearer "+token)
	status, resp := doPost(t, tc, "/v1/agent/enroll", h2, raw)
	if status != 401 || resp["error"] != "token_used" {
		t.Fatalf("REC-24 token replay: %d %v", status, resp)
	}
	orphan, _ := first["node_id"].(string)
	if err := tc.store.RevokeNode(context.Background(), orphan, now); err != nil {
		t.Fatalf("revoke orphan: %v", err)
	}
	b2AssertREC(t, "REC-24", status, resp)
}

func TestB2REC29StaleSnapshot(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	base := b2BaseCollected(t)
	newer := b2SnapshotDoc(t, base+100)
	status, resp := b2SendReport(t, tc, a, newer, b2Nonce(t))
	if status != 200 || resp["result"] != "accepted" {
		t.Fatalf("REC-29 newer: %d %v", status, resp)
	}
	older := b2SnapshotDoc(t, base)
	status, resp = b2SendReport(t, tc, a, older, b2Nonce(t))
	if status != 200 || resp["result"] != "stale_ignored" {
		t.Fatalf("REC-29 older: %d %v", status, resp)
	}
	latest, _ := tc.store.GetLatestSnapshot(context.Background(), a.nodeID)
	if latest.ReportID != newer["report_id"] {
		t.Fatalf("REC-29 stale overwrote latest: %s", latest.ReportID)
	}
	b2AssertREC(t, "REC-29", status, resp)
}

func TestB2REC30InterleavedGenerations(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	base := b2BaseCollected(t)
	if status, resp := b2ReportWithSeq(t, tc, a, b2SnapshotDoc(t, base), b2Nonce(t), 1); status != 200 || resp["result"] != "accepted" {
		t.Fatalf("REC-30 gen1: %d %v", status, resp)
	}
	// New generation first contact, then queued spool records 2..4.
	a.gen = 2
	a.bootID = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	for seq := 1; seq <= 4; seq++ {
		if status, resp := b2ReportWithSeq(t, tc, a, b2SnapshotDoc(t, base+int64(seq)*10), b2Nonce(t), uint64(seq)); status != 200 || resp["result"] != "accepted" {
			t.Fatalf("REC-30 gen2 seq%d: %d %v", seq, status, resp)
		}
	}
	// Delayed old-generation attempt is stale, never re-activated.
	a.gen = 1
	a.bootID = "ffffffffffffffffffffffffffffffff"
	status, resp := b2ReportWithSeq(t, tc, a, b2SnapshotDoc(t, base+20), b2Nonce(t), 2)
	if status != 409 || resp["error"] != "stale_boot_generation" {
		t.Fatalf("REC-30 stale: %d %v", status, resp)
	}
	b2AssertREC(t, "REC-30", status, resp)
	b2AssertRECCenter(t, "REC-30", tc, a.nodeID)
}

func base64URL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

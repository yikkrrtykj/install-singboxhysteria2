package center_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/center"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/schema"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/wire"
)

const (
	contractsDir = "../../../docs/um/contracts/v1"
	examplesDir  = contractsDir + "/examples"
	eventUUID    = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
)

func b2Nonce(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func b2UUID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("uuid: %v", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func b2Example(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(examplesDir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return doc
}

func b2JSON(t *testing.T, doc any) []byte {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

type testCenter struct {
	store  *store.Store
	server *center.Server
	url    string
	dbPath string
}

func startTestCenterAt(t *testing.T, dbPath string) *testCenter {
	t.Helper()
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	schemas, err := schema.Load(contractsDir)
	if err != nil {
		t.Fatalf("load schemas: %v", err)
	}
	svc, err := center.NewService(center.ServiceConfig{Store: st, Schemas: schemas})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	cfg := center.Config{
		IngestAddr: "127.0.0.1:0", AdminAddr: "127.0.0.1:0",
		DBPath: dbPath, ContractDir: contractsDir,
		RateLimitPerSecond: -1, // disable rate limiting for focused integration tests
	}
	srv, err := center.NewServer(cfg, svc)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	tc := &testCenter{store: st, server: srv, url: "http://" + srv.IngestAddr(), dbPath: dbPath}
	t.Cleanup(func() {
		_ = srv.Close()
		_ = st.Close()
	})
	return tc
}

func startTestCenter(t *testing.T) *testCenter {
	t.Helper()
	return startTestCenterAt(t, filepath.Join(t.TempDir(), "center.db"))
}

type syntheticAgent struct {
	priv   ed25519.PrivateKey
	pub    string
	nodeID string
	keyID  string
	bootID string
	gen    uint64
	seq    uint64
}

func newAgent(t *testing.T) *syntheticAgent {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	boot := make([]byte, 16)
	if _, err := rand.Read(boot); err != nil {
		t.Fatalf("boot: %v", err)
	}
	return &syntheticAgent{priv: priv, pub: base64.RawURLEncoding.EncodeToString(pub), bootID: fmt.Sprintf("%x", boot), gen: 1}
}

func (a *syntheticAgent) headers(endpoint wire.Endpoint, sentAt int64, nonce string, body []byte) (http.Header, error) {
	f := wire.Fields{
		Endpoint: endpoint, Protocol: wire.ProtocolVersion, Encoding: "identity",
		SentAt: strconv.FormatInt(sentAt, 10), Nonce: nonce,
	}
	if endpoint == wire.Enroll {
		f.PublicKey = a.pub
	} else {
		f.NodeID, f.KeyID = a.nodeID, a.keyID
		f.BootGen = strconv.FormatUint(a.gen, 10)
		f.BootID = a.bootID
		f.Sequence = strconv.FormatUint(a.seq, 10)
	}
	sig, err := wire.Sign(a.priv, f, body)
	if err != nil {
		return nil, err
	}
	h := http.Header{}
	h.Set(wire.HeaderProtocol, f.Protocol)
	h.Set(wire.HeaderContentType, "application/json")
	h.Set(wire.HeaderSentAt, f.SentAt)
	h.Set(wire.HeaderNonce, f.Nonce)
	h.Set(wire.HeaderContentEnc, f.Encoding)
	h.Set(wire.HeaderSignature, sig)
	if endpoint == wire.Enroll {
		h.Set(wire.HeaderPubkey, f.PublicKey)
	} else {
		h.Set(wire.HeaderNodeID, f.NodeID)
		h.Set(wire.HeaderKeyID, f.KeyID)
		h.Set(wire.HeaderBootGen, f.BootGen)
		h.Set(wire.HeaderBootID, f.BootID)
		h.Set(wire.HeaderSeq, f.Sequence)
	}
	return h, nil
}

func doPost(t *testing.T, tc *testCenter, path string, headers http.Header, body []byte) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, tc.url+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	for k, values := range headers {
		for _, v := range values {
			req.Header.Add(k, v)
		}
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	var doc map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("response JSON (%d): %s err=%v", resp.StatusCode, string(raw), err)
		}
	}
	return resp.StatusCode, doc
}

func doPostRaw(t *testing.T, tc *testCenter, path string, headers http.Header, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, tc.url+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	for k, values := range headers {
		for _, v := range values {
			req.Header.Add(k, v)
		}
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp.StatusCode, raw
}

func enrollAgent(t *testing.T, tc *testCenter, class, host string) *syntheticAgent {
	t.Helper()
	return enrollAgentA(t, tc, class, host, eventUUID)
}

func enrollAgentA(t *testing.T, tc *testCenter, class, host, eventID string) *syntheticAgent {
	t.Helper()
	a := newAgent(t)
	body := b2Example(t, "enroll-request.v1.json")
	body["node_class"] = class
	body["host"].(map[string]any)["os"] = host
	raw := b2JSON(t, body)
	token, hash, err := store.NewEnrollToken()
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	now := time.Now().Unix()
	if err := tc.store.CreateEnrollToken(contextBackground(), hash, eventID, class, now+3600, now); err != nil {
		t.Fatalf("create token: %v", err)
	}
	a.seq = 0
	h, err := a.headers(wire.Enroll, now, b2Nonce(t), raw)
	if err != nil {
		t.Fatalf("enroll headers: %v", err)
	}
	h.Set(wire.HeaderAuthorization, "Bearer "+token)
	status, resp := doPost(t, tc, "/v1/agent/enroll", h, raw)
	if status != http.StatusOK {
		t.Fatalf("enroll status=%d resp=%v", status, resp)
	}
	a.nodeID, _ = resp["node_id"].(string)
	a.keyID, _ = resp["key_id"].(string)
	if a.nodeID == "" || a.keyID == "" {
		t.Fatalf("enroll response missing ids: %v", resp)
	}
	if resp["center_spki_sha256"] != nil {
		t.Fatalf("test center SPKI should be null: %v", resp["center_spki_sha256"])
	}
	return a
}

func contextBackground() context.Context { return context.Background() }

// reportAttempt signs and sends one report with the current agent seq.
func reportAttempt(t *testing.T, tc *testCenter, a *syntheticAgent, doc map[string]any) (int, map[string]any, map[string]any) {
	t.Helper()
	body := b2JSON(t, doc)
	now := time.Now().Unix()
	a.seq++
	nonce := b2Nonce(t)
	h, err := a.headers(wire.Report, now, nonce, body)
	if err != nil {
		t.Fatalf("report headers: %v", err)
	}
	status, resp := doPost(t, tc, "/v1/agent/report", h, body)
	return status, resp, doc
}

func TestB2CenterEnrollmentTelemetryRotation(t *testing.T) {
	tc := startTestCenter(t)
	linux := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")

	// Token is single-use.
	body := b2Example(t, "enroll-request.v1.json")
	body["node_class"] = store.NodeClassLinuxVPS
	raw := b2JSON(t, body)
	token, hash, _ := store.NewEnrollToken()
	now := time.Now().Unix()
	if err := tc.store.CreateEnrollToken(contextBackground(), hash, eventUUID, store.NodeClassLinuxVPS, now+3600, now); err != nil {
		t.Fatalf("token: %v", err)
	}
	_ = token
	h, err := linux.headers(wire.Enroll, now, b2Nonce(t), raw)
	if err != nil {
		t.Fatalf("enroll headers: %v", err)
	}
	h.Set(wire.HeaderAuthorization, "Bearer "+token)
	if status, _ := doPost(t, tc, "/v1/agent/enroll", h, raw); status != http.StatusOK {
		t.Fatalf("first enroll failed: %d", status)
	}
	h2, _ := linux.headers(wire.Enroll, now, b2Nonce(t), raw)
	h2.Set(wire.HeaderAuthorization, "Bearer "+token)
	if status, resp := doPost(t, tc, "/v1/agent/enroll", h2, raw); status != http.StatusUnauthorized || resp["error"] != "token_used" {
		t.Fatalf("token reuse status=%d resp=%v, want 401 token_used", status, resp)
	}

	// Config pull (first transport contact with seq=1).
	configBody := []byte("{}")
	linux.seq++
	cfgH, err := linux.headers(wire.Config, time.Now().Unix(), b2Nonce(t), configBody)
	if err != nil {
		t.Fatalf("config headers: %v", err)
	}
	status, cfgResp := doPost(t, tc, "/v1/agent/config", cfgH, configBody)
	if status != http.StatusOK {
		t.Fatalf("config status=%d resp=%v", status, cfgResp)
	}
	if cfgResp["node_class"] != store.NodeClassLinuxVPS || cfgResp["v"].(float64) != 1 {
		t.Fatalf("config response = %v", cfgResp)
	}

	// Fresh linux snapshot accepted; latest applied.
	snap := b2Example(t, "report-snapshot.v1.json")
	base := int64(snap["collected_at"].(float64))
	snap["report_id"] = b2UUID(t)
	snap["collected_at"] = base
	status, resp, _ := reportAttempt(t, tc, linux, snap)
	if status != http.StatusOK || resp["result"] != "accepted" {
		t.Fatalf("snapshot status=%d resp=%v", status, resp)
	}
	if resp["next_seq"] == nil || int64(resp["next_seq"].(float64)) != int64(linux.seq)+1 {
		t.Fatalf("snapshot next_seq=%v seq=%d", resp["next_seq"], linux.seq)
	}
	latest, err := tc.store.GetLatestSnapshot(contextBackground(), linux.nodeID)
	if err != nil || latest.ReportID != snap["report_id"] {
		t.Fatalf("latest = %+v err=%v", latest, err)
	}

	// Newer snapshot replaces latest; older stale snapshot is authenticated but
	// stale_ignored and must not overwrite latest.
	newer := b2Example(t, "report-snapshot.v1.json")
	newer["report_id"] = b2UUID(t)
	newer["collected_at"] = base + 10
	status, resp, _ = reportAttempt(t, tc, linux, newer)
	if status != http.StatusOK || resp["result"] != "accepted" {
		t.Fatalf("newer snapshot status=%d resp=%v", status, resp)
	}
	older := b2Example(t, "report-snapshot.v1.json")
	older["report_id"] = b2UUID(t)
	older["collected_at"] = base - 10
	status, resp, _ = reportAttempt(t, tc, linux, older)
	if status != http.StatusOK || resp["result"] != "stale_ignored" {
		t.Fatalf("stale snapshot status=%d resp=%v", status, resp)
	}
	latest, _ = tc.store.GetLatestSnapshot(contextBackground(), linux.nodeID)
	if latest.ReportID != newer["report_id"] {
		t.Fatalf("stale snapshot overwrote latest: %s", latest.ReportID)
	}

	// Metrics and events are stored under historical report ids.
	metrics := b2Example(t, "report-metrics.v1.json")
	metrics["report_id"] = b2UUID(t)
	status, resp, _ = reportAttempt(t, tc, linux, metrics)
	if status != http.StatusOK || resp["result"] != "accepted" {
		t.Fatalf("metrics status=%d resp=%v", status, resp)
	}
	events := b2Example(t, "report-events.v1.json")
	events["report_id"] = b2UUID(t)
	status, resp, _ = reportAttempt(t, tc, linux, events)
	if status != http.StatusOK || resp["result"] != "accepted" {
		t.Fatalf("events status=%d resp=%v", status, resp)
	}
	stats, err := tc.store.CapacityStats(contextBackground())
	if err != nil || stats.Snapshots < 3 || stats.Metrics < 1 || stats.Events < 2 {
		t.Fatalf("capacity = %+v err=%v", stats, err)
	}

	// Bad signature must not be accepted (use a schema-valid body so the failure
	// is genuinely signature verification, not a schema 400).
	badDoc := b2Example(t, "report-snapshot.v1.json")
	badDoc["report_id"] = b2UUID(t)
	badDoc["collected_at"] = base + 5
	badBody := b2JSON(t, badDoc)
	linux.seq++
	badH, _ := linux.headers(wire.Report, time.Now().Unix(), b2Nonce(t), badBody)
	badH.Set(wire.HeaderSignature, base64.RawURLEncoding.EncodeToString(make([]byte, 64)))
	if status, resp := doPost(t, tc, "/v1/agent/report", badH, badBody); status != http.StatusUnauthorized || resp["error"] != "bad_signature" {
		t.Fatalf("bad signature status=%d resp=%v", status, resp)
	}

	// Rotation: create intent, replay identical response while awaiting proof,
	// then prove with the new key and verify old key revocation.
	rotate := b2Example(t, "rotate-request.v1.json")
	newPub, newPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("rotate key: %v", err)
	}
	rotate["new_pubkey"] = base64.RawURLEncoding.EncodeToString(newPub)
	rotateBody := b2JSON(t, rotate)
	now = time.Now().Unix()
	linux.seq++
	rotateNonce := b2Nonce(t)
	rotH, err := linux.headers(wire.Rotate, now, rotateNonce, rotateBody)
	if err != nil {
		t.Fatalf("rotate headers: %v", err)
	}
	status, rotResp := doPost(t, tc, "/v1/agent/rotate", rotH, rotateBody)
	if status != http.StatusOK {
		t.Fatalf("rotate status=%d resp=%v", status, rotResp)
	}
	newKeyID, _ := rotResp["new_key_id"].(string)
	if newKeyID == "" {
		t.Fatalf("rotate response missing new_key_id: %v", rotResp)
	}
	// Refreshed retry with the same nonce/body while awaiting proof replays.
	linux.seq++
	retryH, _ := linux.headers(wire.Rotate, time.Now().Unix(), rotateNonce, rotateBody)
	status, retryResp := doPost(t, tc, "/v1/agent/rotate", retryH, rotateBody)
	if status != http.StatusOK || retryResp["new_key_id"] != newKeyID {
		t.Fatalf("rotate replay status=%d resp=%v", status, retryResp)
	}
	// New-key proof report confirms the rotation atomically.
	proofAgent := &syntheticAgent{priv: newPriv, pub: linux.pub, nodeID: linux.nodeID, keyID: newKeyID,
		bootID: linux.bootID, gen: linux.gen, seq: linux.seq}
	proof := b2Example(t, "report-snapshot.v1.json")
	proof["report_id"] = b2UUID(t)
	proof["collected_at"] = base + 20
	status, resp, _ = reportAttempt(t, tc, proofAgent, proof)
	if status != http.StatusOK || resp["result"] != "accepted" {
		t.Fatalf("proof report status=%d resp=%v", status, resp)
	}
	oldKey, err := tc.store.GetKey(contextBackground(), linux.nodeID, linux.keyID)
	if err != nil || oldKey.State != store.KeyRevoked {
		t.Fatalf("old key after proof = %+v err=%v", oldKey, err)
	}
	newKey, err := tc.store.GetKey(contextBackground(), linux.nodeID, newKeyID)
	if err != nil || newKey.State != store.KeyActive {
		t.Fatalf("new key after proof = %+v err=%v", newKey, err)
	}

	// Cross-platform rejection: a Linux node cannot send a terminal snapshot.
	terminal := b2Example(t, "terminal-snapshot.v1.json")
	terminal["report_id"] = b2UUID(t)
	terminal["collected_at"] = base + 30
	status, resp, _ = reportAttempt(t, tc, proofAgent, terminal)
	if status != http.StatusBadRequest || resp["error"] != "platform_mismatch" {
		t.Fatalf("linux terminal status=%d resp=%v", status, resp)
	}
}

func TestB2CenterWindowsTerminalFlow(t *testing.T) {
	tc := startTestCenter(t)
	win := enrollAgent(t, tc, store.NodeClassWindowsTerminal, "windows")
	// Enable the terminal source using the explicitly test-only store primitive.
	if _, err := tc.store.UpdateNodeConfig(contextBackground(), win.nodeID, map[string]bool{
		"system": false, "services": false, "singbox_api": false,
		"mihomo_api": true, "terminal": true, "events": true,
	}, nil, 60, time.Now().Unix()); err != nil {
		t.Fatalf("enable terminal source: %v", err)
	}
	snap := b2Example(t, "terminal-snapshot.v1.json")
	snap["report_id"] = b2UUID(t)
	status, resp, _ := reportAttempt(t, tc, win, snap)
	if status != http.StatusOK || resp["result"] != "accepted" {
		t.Fatalf("windows terminal snapshot status=%d resp=%v", status, resp)
	}
	latest, err := tc.store.GetLatestSnapshot(contextBackground(), win.nodeID)
	if err != nil || latest.NodeClass != store.NodeClassWindowsTerminal {
		t.Fatalf("windows latest = %+v err=%v", latest, err)
	}
	// Windows metrics are forbidden in v1.
	metrics := b2Example(t, "report-metrics.v1.json")
	metrics["report_id"] = b2UUID(t)
	status, resp, _ = reportAttempt(t, tc, win, metrics)
	if status != http.StatusBadRequest || resp["error"] != "platform_mismatch" {
		t.Fatalf("windows metrics status=%d resp=%v", status, resp)
	}
}

func TestB2CenterRestartPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "center.db")
	tc := startTestCenterAt(t, path)
	linux := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	snap := b2Example(t, "report-snapshot.v1.json")
	snap["report_id"] = b2UUID(t)
	base := int64(snap["collected_at"].(float64))
	snap["collected_at"] = base
	status, resp, _ := reportAttempt(t, tc, linux, snap)
	if status != http.StatusOK || resp["result"] != "accepted" {
		t.Fatalf("initial snapshot status=%d resp=%v", status, resp)
	}
	// Persist the exact attempt values for the post-restart retry. A lost ACK
	// retry uses a new seq/nonce but the same report_id: transport is accepted
	// and the payload answer is duplicate.
	attempt := snap
	linux.seq++
	seq := linux.seq
	nonce := b2Nonce(t)
	body := b2JSON(t, attempt)
	sentAt := time.Now().Unix()
	h1, _ := linux.headers(wire.Report, sentAt, nonce, body)
	status, resp2 := doPost(t, tc, "/v1/agent/report", h1, body)
	if status != http.StatusOK || resp2["result"] != "duplicate" {
		t.Fatalf("pre-restart duplicate status=%d resp=%v", status, resp2)
	}
	// Stop and reopen a fresh store/server over the same SQLite file.
	if err := tc.server.Shutdown(contextWithTimeout(t, 5*time.Second)); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if err := tc.store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	reopened := startTestCenterAt(t, path)
	// Same node/boot/seq/nonce/body still resolves to duplicate after restart.
	reopenedAgent := &syntheticAgent{priv: linux.priv, nodeID: linux.nodeID, keyID: linux.keyID,
		bootID: linux.bootID, gen: linux.gen, seq: seq}
	h2, err := reopenedAgent.headers(wire.Report, sentAt, nonce, body)
	if err != nil {
		t.Fatalf("restart headers: %v", err)
	}
	status, resp = doPost(t, reopened, "/v1/agent/report", h2, body)
	if status != http.StatusOK || resp["result"] != "duplicate" {
		t.Fatalf("post-restart duplicate status=%d resp=%v", status, resp)
	}
	latest, err := reopened.store.GetLatestSnapshot(contextBackground(), linux.nodeID)
	if err != nil || latest.ReportID != attempt["report_id"] {
		t.Fatalf("latest after restart = %+v err=%v", latest, err)
	}
}

func contextWithTimeout(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

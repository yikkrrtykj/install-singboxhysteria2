package center_test

// Targeted regression tests for the UM-B2 independent review corrections.

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/center"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/wire"
)

func rawDB(t *testing.T, tc *testCenter) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", tc.dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func rawCount(t *testing.T, db *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("query %q: %v", q, err)
	}
	return n
}

func newTokenFor(t *testing.T, tc *testCenter, event, class string, now int64) (token, hash string) {
	t.Helper()
	token, hash, err := store.NewEnrollToken()
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if err := tc.store.CreateEnrollToken(context.Background(), hash, event, class, now+3600, now); err != nil {
		t.Fatalf("create token: %v", err)
	}
	return token, hash
}

func signedEnrollAttempt(t *testing.T, a *syntheticAgent, token string, sentAt int64) (http.Header, []byte) {
	t.Helper()
	body := b2Example(t, "enroll-request.v1.json")
	body["node_class"] = store.NodeClassLinuxVPS
	body["host"].(map[string]any)["os"] = "linux"
	raw := b2JSON(t, body)
	h, err := a.headers(wire.Enroll, sentAt, b2Nonce(t), raw)
	if err != nil {
		t.Fatalf("headers: %v", err)
	}
	h.Set(wire.HeaderAuthorization, "Bearer "+token)
	return h, raw
}

func TestB2EnrollFreshnessAndNoPartialWrites(t *testing.T) {
	tc := startTestCenter(t)
	now := time.Now().Unix()
	_, hash := newTokenFor(t, tc, eventUUID, store.NodeClassLinuxVPS, now)
	_ = hash
	a := newAgent(t)
	// Past/future outside ±300: token must remain unused.
	for _, sent := range []int64{now - 600, now + 600} {
		// Fresh token per attempt so no stale attempt consumes another token.
		tok, hsh := newTokenFor(t, tc, eventUUID, store.NodeClassLinuxVPS, now)
		h, raw := signedEnrollAttempt(t, a, tok, sent)
		status, resp := doPost(t, tc, "/v1/agent/enroll", h, raw)
		if status != 401 || resp["error"] != "stale_timestamp" {
			t.Fatalf("sent_at=%d: %d %v, want 401 stale_timestamp", sent, status, resp)
		}
		info, err := tc.store.TokenInfo(context.Background(), hsh)
		if err != nil || info.UsedAt != nil {
			t.Fatalf("stale enrollment consumed token: %+v err=%v", info, err)
		}
	}
	if n := rawCount(t, rawDB(t, tc), `SELECT COUNT(*) FROM nodes`); n != 0 {
		t.Fatalf("stale enrollment wrote nodes: %d", n)
	}
	// Exact boundary accepted.
	tok, _ := newTokenFor(t, tc, eventUUID, store.NodeClassLinuxVPS, now)
	h, raw := signedEnrollAttempt(t, a, tok, now+300)
	status, resp := doPost(t, tc, "/v1/agent/enroll", h, raw)
	if status != 200 || resp["node_id"] == nil {
		t.Fatalf("boundary enrollment: %d %v", status, resp)
	}
}

func TestB2EnrollBadSignatureDoesNotConsumeToken(t *testing.T) {
	tc := startTestCenter(t)
	now := time.Now().Unix()
	tok, hash := newTokenFor(t, tc, eventUUID, store.NodeClassLinuxVPS, now)
	a := newAgent(t)
	h, raw := signedEnrollAttempt(t, a, tok, now)
	h.Set(wire.HeaderSignature, base64.RawURLEncoding.EncodeToString(make([]byte, 64)))
	status, resp := doPost(t, tc, "/v1/agent/enroll", h, raw)
	if status != 401 || resp["error"] != "bad_signature" {
		t.Fatalf("bad signature: %d %v", status, resp)
	}
	info, err := tc.store.TokenInfo(context.Background(), hash)
	if err != nil || info.UsedAt != nil {
		t.Fatalf("bad-signature enrollment consumed token: %+v err=%v", info, err)
	}
}

func TestB2EventArchiveRejectsIngestAndEnrollment(t *testing.T) {
	tc := startTestCenter(t)
	now := time.Now().Unix()
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	base := b2BaseCollected(t)
	if status, resp := b2SendReport(t, tc, a, b2SnapshotDoc(t, base), b2Nonce(t)); status != 200 || resp["result"] != "accepted" {
		t.Fatalf("seed report: %d %v", status, resp)
	}
	// Token created before archive must not enroll after archive.
	tok, _ := newTokenFor(t, tc, eventUUID, store.NodeClassLinuxVPS, now)
	if err := tc.store.ArchiveEvent(context.Background(), eventUUID, now); err != nil {
		t.Fatalf("archive: %v", err)
	}
	if status, resp := b2SendReport(t, tc, a, b2SnapshotDoc(t, base+1), b2Nonce(t)); status != 409 || resp["error"] != "identity_mismatch" {
		t.Fatalf("report after archive: %d %v, want 409 identity_mismatch", status, resp)
	}
	b := newAgent(t)
	h, raw := signedEnrollAttempt(t, b, tok, now)
	if status, resp := doPost(t, tc, "/v1/agent/enroll", h, raw); status != 409 || resp["error"] != "identity_mismatch" {
		t.Fatalf("enrollment after archive: %d %v, want 409 identity_mismatch", status, resp)
	}
	// New token creation for the archived event is refused.
	if err := tc.store.CreateEnrollToken(context.Background(), "deadbeef", eventUUID, store.NodeClassLinuxVPS, now+3600, now); !errors.Is(err, store.ErrEventArchived) {
		t.Fatalf("archived token creation = %v, want ErrEventArchived", err)
	}
}

func TestB2NodeRetireKeepsHistory(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	base := b2BaseCollected(t)
	if status, resp := b2SendReport(t, tc, a, b2SnapshotDoc(t, base), b2Nonce(t)); status != 200 || resp["result"] != "accepted" {
		t.Fatalf("seed: %d %v", status, resp)
	}
	if err := tc.store.RevokeNode(context.Background(), a.nodeID, time.Now().Unix()); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if status, resp := b2SendReport(t, tc, a, b2SnapshotDoc(t, base+1), b2Nonce(t)); status != 401 || resp["error"] != "revoked_key" {
		t.Fatalf("report after retire: %d %v", status, resp)
	}
	if _, err := tc.store.GetLatestSnapshot(context.Background(), a.nodeID); err != nil {
		t.Fatalf("node retire removed history: %v", err)
	}
}

func TestB2SourceSwitchHistoricalSpoolAndCurrentData(t *testing.T) {
	tc := startTestCenter(t)
	base := b2BaseCollected(t)
	disabled := map[string]bool{"system": false, "services": false, "singbox_api": false, "mihomo_api": false, "terminal": false, "events": false}
	// Current node: disable before the sample's collected_at, so current data is
	// rejected.
	cur := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	if _, err := tc.store.UpdateNodeConfig(context.Background(), cur.nodeID, disabled, nil, 60, base-1); err != nil {
		t.Fatalf("disable current node: %v", err)
	}
	if status, resp := b2SendReport(t, tc, cur, b2SnapshotDoc(t, base), b2Nonce(t)); status != 400 {
		t.Fatalf("current data with disabled sources: %d %v, want 400", status, resp)
	}
	// Historical node: data was collected while the enabled config was effective;
	// the later disable must not erase that historical authorization.
	hist := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	if _, err := tc.store.UpdateNodeConfig(context.Background(), hist.nodeID, disabled, nil, 60, base+1000); err != nil {
		t.Fatalf("disable historical node: %v", err)
	}
	if status, resp := b2SendReport(t, tc, hist, b2SnapshotDoc(t, base), b2Nonce(t)); status != 200 || resp["result"] != "accepted" {
		t.Fatalf("historical spool: %d %v, want accepted", status, resp)
	}
}

func TestB2ACKUsesTransactionNextSeqAndExhaustion(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	base := b2BaseCollected(t)
	// First report establishes high-water.
	if status, resp := b2SendReport(t, tc, a, b2SnapshotDoc(t, base), b2Nonce(t)); status != 200 || resp["result"] != "accepted" {
		t.Fatalf("seed: %d %v", status, resp)
	}
	// Advance the authoritative high-water to MAX_NUMERIC-1 over raw SQLite.
	db := rawDB(t, tc)
	now := time.Now().Unix()
	if _, err := db.ExecContext(context.Background(),
		`UPDATE node_boot SET last_seq=?, updated_at=? WHERE node_id=?`, wire.MaxNumeric-1, now, a.nodeID); err != nil {
		t.Fatalf("set high-water: %v", err)
	}
	doc := b2SnapshotDoc(t, base+1)
	a.seq = wire.MaxNumeric
	body := b2JSON(t, doc)
	// Rebuild headers with seq=MAX_NUMERIC.
	a.seq = wire.MaxNumeric
	h, err := a.headers(wire.Report, b2SentAt(t, body), b2Nonce(t), body)
	if err != nil {
		t.Fatalf("headers: %v", err)
	}
	status, resp := doPost(t, tc, "/v1/agent/report", h, body)
	if status != 200 || resp["result"] != "accepted" {
		t.Fatalf("max numeric report: %d %v", status, resp)
	}
	if resp["next_seq"] != nil {
		t.Fatalf("exhausted ACK next_seq=%v, want explicit null", resp["next_seq"])
	}
	// The committed ACK came from this transaction; a second generation's
	// high-water cannot retarget it.
	if got := rawCount(t, db, `SELECT COUNT(*) FROM node_boot WHERE node_id=? AND last_seq=?`, a.nodeID, wire.MaxNumeric); got != 1 {
		t.Fatalf("max numeric high-water not committed")
	}
}

func TestB2NonceReuseHasPriorityOverBootConflict(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	nonce := b2Nonce(t)
	cfgBody := []byte("{}")
	a.seq = 1
	h, _ := a.headers(wire.Config, time.Now().Unix(), nonce, cfgBody)
	if status, resp := doPost(t, tc, "/v1/agent/config", h, cfgBody); status != 200 {
		t.Fatalf("config: %d %v", status, resp)
	}
	// Same nonce with a deliberately stale generation: nonce_reuse must win
	// over stale_boot_generation.
	a.seq = 2
	a.gen = 1
	a.bootID = "99999999999999999999999999999999" // same generation, different boot
	body := b2JSON(t, b2SnapshotDoc(t, b2BaseCollected(t)))
	h2, _ := a.headers(wire.Report, b2SentAt(t, body), nonce, body)
	status, resp := doPost(t, tc, "/v1/agent/report", h2, body)
	if status != 409 || resp["error"] != "nonce_reuse" {
		t.Fatalf("nonce priority: %d %v, want nonce_reuse", status, resp)
	}
}

func TestB2RotationExpiredUnblocksNewRotation(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	rotateBody := b2RotateBody(t)
	nonce := b2Nonce(t)
	status, first := b2RotateSigned(t, tc, a, rotateBody, nonce, 1, 1, a.bootID)
	if status != 200 || first["new_key_id"] == nil {
		t.Fatalf("create rotation: %d %v", status, first)
	}
	oldKeyID := a.keyID
	// Expire the intent through SQLite, then use a new nonce/body rotation. The
	// service aborts expired pending intents before the new request.
	db := rawDB(t, tc)
	if _, err := db.ExecContext(context.Background(), `UPDATE key_rotations SET expires_at=? WHERE node_id=? AND nonce=?`, time.Now().Unix()-1, a.nodeID, nonce); err != nil {
		t.Fatalf("expire: %v", err)
	}
	newBody := b2RotateBody(t)
	status, second := b2RotateSigned(t, tc, a, newBody, b2Nonce(t), 2, 1, a.bootID)
	if status != 200 || second["new_key_id"] == nil {
		t.Fatalf("new rotation after expiry: %d %v", status, second)
	}
	// Same-nonce retry of the expired intent is rotation_expired, not replay.
	status, resp := b2RotateSigned(t, tc, a, rotateBody, nonce, 3, 1, a.bootID)
	if status != 409 || resp["error"] != "rotation_expired" {
		t.Fatalf("expired retry: %d %v", status, resp)
	}
	// Old key remains active (expiry revokes only provisional keys).
	oldKey, err := tc.store.GetKey(context.Background(), a.nodeID, oldKeyID)
	if err != nil || oldKey.State != store.KeyActive {
		// It may have become inactive if a new rotation already confirmed; in this
		// test only intent creation happened, so active is required.
		t.Fatalf("old key after expiry: %+v err=%v", oldKey, err)
	}
}

func TestB2BootGapAuditLedger(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	base := b2BaseCollected(t)
	if status, resp := b2SendReport(t, tc, a, b2SnapshotDoc(t, base), b2Nonce(t)); status != 200 || resp["result"] != "accepted" {
		t.Fatalf("gen1: %d %v", status, resp)
	}
	a.gen = 3 // forward gap 2
	if status, resp := b2SendReport(t, tc, a, b2SnapshotDoc(t, base+1), b2Nonce(t)); status != 200 || resp["result"] != "accepted" {
		t.Fatalf("gen3: %d %v", status, resp)
	}
	db := rawDB(t, tc)
	if got := rawCount(t, db, `SELECT COUNT(*) FROM security_ledger WHERE kind='boot_generation_gap'`); got != 1 {
		t.Fatalf("boot_generation_gap audit entries=%d, want 1", got)
	}
}

func TestB2ConfigUpdateRejectsInvalidAndServiceUsesValid(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	// Linux cannot enable terminal/mihomo, and cannot drop expected tags.
	if _, err := tc.store.UpdateNodeConfig(context.Background(), a.nodeID, map[string]bool{
		"system": true, "services": true, "singbox_api": true, "mihomo_api": false, "terminal": true, "events": true,
	}, nil, 60, time.Now().Unix()); !errors.Is(err, store.ErrInvalidArgument) {
		t.Fatalf("invalid config update = %v, want ErrInvalidArgument", err)
	}
	cfg, err := tc.store.GetNodeConfig(context.Background(), a.nodeID)
	if err != nil || cfg.Sources["terminal"] {
		t.Fatalf("invalid config persisted: %+v err=%v", cfg, err)
	}
	// Valid class config is returned by the service.
	body := []byte("{}")
	a.seq = 1
	h, _ := a.headers(wire.Config, time.Now().Unix(), b2Nonce(t), body)
	status, resp := doPost(t, tc, "/v1/agent/config", h, body)
	if status != 200 || resp["node_class"] != store.NodeClassLinuxVPS {
		t.Fatalf("config pull: %d %v", status, resp)
	}
}

func TestB2REC15RealTransactionFaultRollsBackEverything(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	doc := b2SnapshotDoc(t, b2BaseCollected(t))
	tc.store.SetIngestHookForTest(func(stage string) error {
		if stage == "after_highwater" {
			return errors.New("injected sqlite transaction failure")
		}
		return nil
	})
	status, resp := b2SendReport(t, tc, a, doc, b2Nonce(t))
	if status != 503 || resp["error"] != "storage_unavailable" {
		t.Fatalf("injected transaction failure: %d %v", status, resp)
	}
	db := rawDB(t, tc)
	for _, q := range []string{
		`SELECT COUNT(*) FROM node_boot`,
		`SELECT COUNT(*) FROM seq_dedupe`,
		`SELECT COUNT(*) FROM nonce_dedupe`,
		`SELECT COUNT(*) FROM report_dedupe`,
		`SELECT COUNT(*) FROM snapshots`,
	} {
		if n := rawCount(t, db, q); n != 0 {
			t.Fatalf("failed transaction left rows: %s = %d", q, n)
		}
	}
	tc.store.SetIngestHookForTest(nil)
	status, resp = b2SendReport(t, tc, a, doc, b2Nonce(t))
	if status != 200 || resp["result"] != "accepted" {
		t.Fatalf("retry after fault: %d %v", status, resp)
	}
}

func TestB2REC19RotateResponseBytesAcrossRestart(t *testing.T) {
	path := t.TempDir() + "/center.db"
	tc := startTestCenterAt(t, path)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	rotateBody := b2RotateBody(t)
	nonce := b2Nonce(t)
	a.seq = 1
	h, _ := a.headers(wire.Rotate, time.Now().Unix(), nonce, rotateBody)
	status, firstRaw := doPostRaw(t, tc, "/v1/agent/rotate", h, rotateBody)
	if status != 200 {
		t.Fatalf("rotate create: %d %s", status, firstRaw)
	}
	// Restart center over the same DB.
	b2CloseCenter(t, tc)
	tc2 := startTestCenterAt(t, path)
	// Retry the persisted intent with refreshed generation/seq; response bytes
	// must be identical.
	a.gen = 2
	a.seq = 2
	h2, err := a.headers(wire.Rotate, time.Now().Unix(), nonce, rotateBody)
	if err != nil {
		t.Fatalf("headers: %v", err)
	}
	status, secondRaw := doPostRaw(t, tc2, "/v1/agent/rotate", h2, rotateBody)
	if status != 200 {
		t.Fatalf("rotate replay: %d %s", status, secondRaw)
	}
	if string(firstRaw) != string(secondRaw) {
		t.Fatalf("rotate response bytes changed across restart:\nfirst=%s\nsecond=%s", firstRaw, secondRaw)
	}
}

var _ = center.NewAPIError
var _ = base64.RawURLEncoding
var _ = json.Marshal
var _ = fmt.Sprintf
var _ = strconv.Itoa
var _ = strings.TrimSpace

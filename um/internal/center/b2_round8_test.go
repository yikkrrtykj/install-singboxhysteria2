package center_test

// Round-8 targeted regressions: config authorization history, endpoint-specific
// key permissions, rotate ordering, report identity across the dedupe window and
// rejection-audit behavior.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/wire"
)

func TestB2F4NeverEnabledSourceCannotBorrowLaterAuthorization(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	db := rawDB(t, tc)
	// Remove the synthetic enabled history and leave only a fail-closed initial
	// config; an old report must not borrow a later/other authorization.
	if _, err := db.Exec(`DELETE FROM node_config_history WHERE node_id=?`, a.nodeID); err != nil {
		t.Fatalf("delete history: %v", err)
	}
	// Make the node's current config fail-closed, then preserve it as the only
	// initial history row.
	if _, err := db.Exec(`UPDATE node_configs SET sources_json='{"system":false,"services":false,"singbox_api":false,"mihomo_api":false,"terminal":false,"events":false}' WHERE node_id=?`, a.nodeID); err != nil {
		t.Fatalf("disable current config: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO node_config_history(node_id,event_id,config_version,effective_from,sources_json,expected_inbound_tags_json,cadence_seconds,device_salt)
		SELECT node_id,event_id,config_version,updated_at,sources_json,expected_inbound_tags_json,cadence_seconds,device_salt FROM node_configs WHERE node_id=?`, a.nodeID); err != nil {
		t.Fatalf("insert disabled initial history: %v", err)
	}
	base := b2BaseCollected(t)
	status, resp := b2SendReport(t, tc, a, b2SnapshotDoc(t, base), b2Nonce(t))
	if status != 400 || resp["error"] != "invalid_request" {
		t.Fatalf("never-enabled source report: %d %v, want invalid_request", status, resp)
	}
}

func TestB2F4TagChangeBoundaryAndHistoricalSpool(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	base := b2BaseCollected(t)
	// New tags effective at base+20: historical report at base uses old tags.
	if _, err := tc.store.UpdateNodeConfig(context.Background(), a.nodeID, nil,
		[]store.InboundTag{{InboundTag: "other-in", Kind: "other"}}, 60, base+20); err != nil {
		t.Fatalf("tag update: %v", err)
	}
	// A report collected before the boundary uses the old allowlist (vless-in).
	if status, resp := b2SendReport(t, tc, a, b2SnapshotDoc(t, base), b2Nonce(t)); status != 200 || resp["result"] != "accepted" {
		t.Fatalf("historical tag report: %d %v", status, resp)
	}
	// A report collected at the exact boundary uses the new tags and must reject
	// the old inbound tag.
	if status, resp := b2SendReport(t, tc, a, b2SnapshotDoc(t, base+20), b2Nonce(t)); status != 400 {
		t.Fatalf("boundary tag report: %d %v, want 400", status, resp)
	}
}

func TestB2F5ConfigRejectsProvisionalKey(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	newPub, newPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	var newKeyID string
	if err := tc.store.WithTx(context.Background(), func(tx *store.Tx) error {
		if err := tx.CreateRotationTx(context.Background(), store.RotationRecord{
			NodeID: a.nodeID, OldKeyID: a.keyID, Nonce: "manual-proof", BodySHA256: "h",
			ExpiresAt: time.Now().Unix() + 300, CreatedAt: time.Now().Unix(),
		}, base64URL(newPub)); err != nil {
			return err
		}
		rec, _, err := tx.RotationTx(context.Background(), a.nodeID, "manual-proof")
		newKeyID = rec.NewKeyID
		return err
	}); err != nil {
		t.Fatalf("create rotation: %v", err)
	}
	proof := &syntheticAgent{priv: newPriv, nodeID: a.nodeID, keyID: newKeyID,
		bootID: a.bootID, gen: 1, seq: 2}
	body := []byte("{}")
	h, err := proof.headers(wire.Config, time.Now().Unix(), b2Nonce(t), body)
	if err != nil {
		t.Fatalf("headers: %v", err)
	}
	status, resp := doPost(t, tc, "/v1/agent/config", h, body)
	if status != 401 || resp["error"] != "revoked_key" {
		t.Fatalf("provisional config: %d %v, want 401 revoked_key", status, resp)
	}
	// The provisional key is still allowed as a report proof.
	doc := b2SnapshotDoc(t, b2BaseCollected(t))
	status, resp = b2SendReport(t, tc, proof, doc, b2Nonce(t))
	if status != 200 || resp["result"] != "accepted" {
		t.Fatalf("provisional proof report: %d %v", status, resp)
	}
}

func TestB2F5RotateBootSequenceBeforeNonce(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	nonce := b2Nonce(t)
	body := []byte("{}")
	a.seq = 1
	h, _ := a.headers(wire.Config, time.Now().Unix(), nonce, body)
	if status, resp := doPost(t, tc, "/v1/agent/config", h, body); status != 200 {
		t.Fatalf("config seed: %d %v", status, resp)
	}
	// Rotate with the same nonce but a conflicting sequence. Frozen §7 checks
	// boot/sequence before nonce intent, so sequence_conflict must win.
	rotateBody := b2RotateBody(t)
	a.seq = 1
	a.gen = 1
	h2, err := a.headers(wire.Rotate, time.Now().Unix(), nonce, rotateBody)
	if err != nil {
		t.Fatalf("rotate headers: %v", err)
	}
	status, resp := doPost(t, tc, "/v1/agent/rotate", h2, rotateBody)
	if status != 409 || resp["error"] != "sequence_conflict" {
		t.Fatalf("rotate ordering: %d %v, want 409 sequence_conflict", status, resp)
	}
}

func TestB2F6ReportIdentityAcrossDedupeWindow(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	base := b2BaseCollected(t)
	snap := b2SnapshotDoc(t, base)
	if status, resp := b2SendReport(t, tc, a, snap, b2Nonce(t)); status != 200 || resp["result"] != "accepted" {
		t.Fatalf("seed snapshot: %d %v", status, resp)
	}
	reportID, _ := snap["report_id"].(string)
	db := rawDB(t, tc)
	// Simulate the 8-day report_dedupe expiry while the 30-day telemetry remains.
	if _, err := db.Exec(`DELETE FROM report_dedupe WHERE node_id=? AND report_id=?`, a.nodeID, reportID); err != nil {
		t.Fatalf("expire dedupe: %v", err)
	}
	// Same report_id as metrics => cross-type conflict.
	metrics := b2Example(t, "report-metrics.v1.json")
	metrics["report_id"] = reportID
	metrics["collected_at"] = base
	b2ShiftReportTimes(metrics, base)
	if status, resp := b2SendReport(t, tc, a, metrics, b2Nonce(t)); status != 409 || resp["error"] != "report_conflict" {
		t.Fatalf("cross-type dedupe expiry: %d %v, want report_conflict", status, resp)
	}
	if n := rawCount(t, db, `SELECT COUNT(*) FROM report_metrics WHERE report_id=?`, reportID); n != 0 {
		t.Fatalf("conflicting metrics row was written: %d", n)
	}
	// Same type, different body => conflict.
	changed := b2SnapshotDoc(t, base+1)
	changed["report_id"] = reportID
	if status, resp := b2SendReport(t, tc, a, changed, b2Nonce(t)); status != 409 || resp["error"] != "report_conflict" {
		t.Fatalf("same-type different body: %d %v, want report_conflict", status, resp)
	}
	// Rejection audits must exist and not claim success.
	if n := rawCount(t, db, `SELECT COUNT(*) FROM security_ledger WHERE kind='report_conflict'`); n < 2 {
		t.Fatalf("report_conflict audit rows=%d, want >=2", n)
	}
	// Exact retry still resolves as duplicate without another snapshot row.
	if status, resp := b2SendReport(t, tc, a, snap, b2Nonce(t)); status != 200 || resp["result"] != "duplicate" {
		t.Fatalf("exact duplicate: %d %v", status, resp)
	}
	if n := rawCount(t, db, `SELECT COUNT(*) FROM snapshots WHERE report_id=?`, reportID); n != 1 {
		t.Fatalf("exact duplicate wrote %d snapshot rows", n)
	}
}

var _ = sql.ErrNoRows
var _ = errors.Is
var _ = context.Background

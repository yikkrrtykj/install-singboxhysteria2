package center_test

// Cross-endpoint replay, privacy sentinel and proof-retry checks through the real
// HTTP listener.

import (
	"context"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/wire"
)

func TestB2CrossEndpointNonceReuseRejected(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	nonce := b2Nonce(t)
	// First use on config (first contact).
	cfgBody := []byte("{}")
	a.seq = 1
	now := time.Now().Unix()
	h, _ := a.headers(wire.Config, now, nonce, cfgBody)
	if status, resp := doPost(t, tc, "/v1/agent/config", h, cfgBody); status != 200 {
		t.Fatalf("config first use: %d %v", status, resp)
	}
	// Same nonce on report endpoint: cross-endpoint nonce reuse.
	doc := b2SnapshotDoc(t, b2BaseCollected(t))
	body := b2JSON(t, doc)
	a.seq = 2
	h2, _ := a.headers(wire.Report, b2SentAt(t, body), nonce, body)
	status, resp := doPost(t, tc, "/v1/agent/report", h2, body)
	if status != 409 || resp["error"] != "nonce_reuse" {
		t.Fatalf("cross-endpoint nonce: %d %v, want 409 nonce_reuse", status, resp)
	}
}

func TestB2PrivacySentinelRejectedBeforeStorage(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	base := b2BaseCollected(t)
	doc := b2Example(t, "report-snapshot.v1.json")
	doc["report_id"] = b2UUID(t)
	b2ShiftReportTimes(doc, base)
	doc["collected_at"] = base
	// Plant a credential-shaped sentinel in a non-identifier field.
	doc["agent"].(map[string]any)["version"] = "password=supersecret"
	body := b2JSON(t, doc)
	a.seq = 1
	h, _ := a.headers(wire.Report, b2SentAt(t, body), b2Nonce(t), body)
	status, resp := doPost(t, tc, "/v1/agent/report", h, body)
	if status != 400 || (resp["error"] != "invalid_request" && resp["error"] != "platform_mismatch") {
		t.Fatalf("privacy sentinel: %d %v, want boundary rejection", status, resp)
	}
	stats, err := tc.store.CapacityStats(context.Background())
	if err != nil {
		t.Fatalf("capacity: %v", err)
	}
	if stats.Snapshots != 0 {
		t.Fatalf("privacy sentinel stored %d snapshots", stats.Snapshots)
	}
}

func TestB2EventTagBindingAndPrivacyAudit(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	base := b2BaseCollected(t)
	events := b2Example(t, "report-events.v1.json")
	events["report_id"] = b2UUID(t)
	b2ShiftReportTimes(events, base)
	events["collected_at"] = base
	// The event example's detail uses the configured allowlisted inbound tag, so
	// the first event report is accepted.
	if status, resp := b2SendReport(t, tc, a, events, b2Nonce(t)); status != 200 || resp["result"] != "accepted" {
		t.Fatalf("tag-bound events: %d %v", status, resp)
	}
	// Mutate an event detail inbound_tag to an unknown value: reject at the
	// center tag binding, not at storage.
	bad := b2Example(t, "report-events.v1.json")
	bad["report_id"] = b2UUID(t)
	bad["collected_at"] = base + 1
	b2ShiftReportTimes(bad, base+1)
	evs := bad["events"].([]any)
	detail := evs[0].(map[string]any)["detail"].(map[string]any)
	detail["inbound_tag"] = "not-configured"
	if status, resp := b2SendReport(t, tc, a, bad, b2Nonce(t)); status != 400 || resp["error"] != "invalid_request" {
		t.Fatalf("unknown tag: %d %v, want 400 invalid_request", status, resp)
	}
	// Privacy sentinel rejection is recorded in the security ledger without
	// storing payload or secret text.
	privacy := b2Example(t, "report-snapshot.v1.json")
	privacy["report_id"] = b2UUID(t)
	b2ShiftReportTimes(privacy, base)
	privacy["collected_at"] = base
	privacy["agent"].(map[string]any)["version"] = "password=anothersecret"
	if status, _ := b2SendReport(t, tc, a, privacy, b2Nonce(t)); status != 400 {
		t.Fatalf("privacy sentinel status=%d, want 400", status)
	}
	if n := rawCount(t, rawDB(t, tc), `SELECT COUNT(*) FROM security_ledger WHERE kind='report_rejected'`); n != 1 {
		t.Fatalf("privacy audit entries=%d, want 1", n)
	}
	if n := rawCount(t, rawDB(t, tc), `SELECT COUNT(*) FROM report_event_reports WHERE node_id=?`, a.nodeID); n != 1 {
		t.Fatalf("privacy/tag test expected only the first accepted events report, got %d", n)
	}
	if n := rawCount(t, rawDB(t, tc), `SELECT COUNT(*) FROM snapshots WHERE node_id=?`, a.nodeID); n != 0 {
		t.Fatalf("rejected tag/privacy reports wrote snapshots: %d", n)
	}
}

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
	h2, _ := a.headers(wire.Report, time.Now().Unix(), nonce, body)
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
	doc["collected_at"] = base
	// Plant a credential-shaped sentinel in a non-identifier field.
	doc["agent"].(map[string]any)["version"] = "password=supersecret"
	body := b2JSON(t, doc)
	a.seq = 1
	h, _ := a.headers(wire.Report, time.Now().Unix(), b2Nonce(t), body)
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

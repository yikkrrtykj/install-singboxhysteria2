package center_test

// Round-9 C4 focused tests: terminal source independence, historical config
// validation, current-config ACK version and source-switch boundaries.

import (
	"context"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
)

func c4WindowsSources(terminal, mihomo bool) map[string]bool {
	return map[string]bool{
		"system": false, "services": false, "singbox_api": false,
		"mihomo_api": mihomo, "terminal": terminal, "events": true,
	}
}

func TestC4WindowsTerminalAndControllerSourcesIndependent(t *testing.T) {
	tc := startTestCenter(t)
	win := enrollAgent(t, tc, store.NodeClassWindowsTerminal, "windows")
	base := b2BaseCollected(t)
	// terminal=true/mihomo=false: real selection is authorized, but real
	// active_connections Controller data must be unavailable.
	if _, err := tc.store.UpdateNodeConfig(context.Background(), win.nodeID, c4WindowsSources(true, false), nil, 60, time.Now().Unix()); err != nil {
		t.Fatalf("terminal-only config: %v", err)
	}
	doc := b2Example(t, "terminal-snapshot.v1.json")
	doc["report_id"] = b2UUID(t)
	b2ShiftReportTimes(doc, base)
	doc["collected_at"] = base
	status, resp := b2SendReport(t, tc, win, doc, b2Nonce(t))
	if status != 400 || resp["error"] != "invalid_request" {
		t.Fatalf("terminal=true/mihomo=false with ok active_connections: %d %v", status, resp)
	}
	// Honest unavailable Controller data is legal with the same config.
	doc2 := b2Example(t, "terminal-snapshot.v1.json")
	doc2["report_id"] = b2UUID(t)
	doc2["collected_at"] = base
	term := doc2["terminal"].(map[string]any)
	term["active_connections"] = map[string]any{
		"availability": "unavailable", "sampled_at": base - 1,
		"total": nil, "by_route": map[string]any{
			"a_reality": nil, "a_hy2": nil, "b_reality": nil,
			"b_hy2": nil, "direct": nil, "unknown": nil,
		},
	}
	b2ShiftReportTimes(doc2, base)
	if status, resp := b2SendReport(t, tc, win, doc2, b2Nonce(t)); status != 200 || resp["result"] != "accepted" {
		t.Fatalf("honest unavailable controller data: %d %v", status, resp)
	}
	// terminal=false/mihomo=true: selection is not authorized, active Controller
	// observations are.
	if _, err := tc.store.UpdateNodeConfig(context.Background(), win.nodeID, c4WindowsSources(false, true), nil, 60, time.Now().Unix()); err != nil {
		t.Fatalf("controller-only config: %v", err)
	}
	doc3 := b2Example(t, "terminal-snapshot.v1.json")
	doc3["report_id"] = b2UUID(t)
	b2ShiftReportTimes(doc3, base)
	doc3["collected_at"] = base
	if status, resp := b2SendReport(t, tc, win, doc3, b2Nonce(t)); status != 400 || resp["error"] != "invalid_request" {
		t.Fatalf("terminal=false with ok selection: %d %v", status, resp)
	}
	doc4 := b2Example(t, "terminal-snapshot.v1.json")
	doc4["report_id"] = b2UUID(t)
	doc4["collected_at"] = base + 50
	term4 := doc4["terminal"].(map[string]any)
	term4["selection"] = map[string]any{
		"availability": "unavailable", "sampled_at": base - 2,
		"route": nil, "reason_code": "source_authorization_unproven",
	}
	b2ShiftReportTimes(doc4, base+50)
	if status, resp := b2SendReport(t, tc, win, doc4, b2Nonce(t)); status != 200 || resp["result"] != "accepted" {
		t.Fatalf("honest unavailable selection: %d %v", status, resp)
	}
}

func TestC4HistoricalConfigAndCurrentACKVersion(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	now := time.Now().Unix()
	// New current config version effective after the historical collection time.
	if _, err := tc.store.UpdateNodeConfig(context.Background(), a.nodeID, nil, nil, 90, now+30); err != nil {
		t.Fatalf("future config update: %v", err)
	}
	collected := now + 10
	doc := b2SnapshotDoc(t, collected)
	status, resp := b2SendReport(t, tc, a, doc, b2Nonce(t))
	if status != 200 || resp["result"] != "accepted" {
		t.Fatalf("historical-config report: %d %v", status, resp)
	}
	if got := int(resp["config_version"].(float64)); got != 3 {
		t.Fatalf("ACK config_version=%d, want current version 3", got)
	}
	// The report used the version effective at collected_at (v2), not the future
	// v3 for source policy; v2/v3 share sources here but the ACK pins the latter.
}

func TestC4LinuxServicesAndSingboxApprovalIndependent(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgent(t, tc, store.NodeClassLinuxVPS, "linux")
	base := b2BaseCollected(t)
	// Disable singbox_api but leave services enabled: protocol events must fail.
	if _, err := tc.store.UpdateNodeConfig(context.Background(), a.nodeID, map[string]bool{
		"system": true, "services": true, "singbox_api": false, "mihomo_api": false, "terminal": false, "events": true,
	}, nil, 60, time.Now().Unix()); err != nil {
		t.Fatalf("services-only config: %v", err)
	}
	events := b2Example(t, "report-events.v1.json")
	events["report_id"] = b2UUID(t)
	b2ShiftReportTimes(events, base)
	events["collected_at"] = base
	status, resp := b2SendReport(t, tc, a, events, b2Nonce(t))
	if status != 400 || resp["error"] != "invalid_request" {
		t.Fatalf("protocol event without singbox_api: %d %v", status, resp)
	}
	// Generic diagnostic remains legal without the protocol source.
	generic := b2Example(t, "report-events.v1.json")
	generic["report_id"] = b2UUID(t)
	b2ShiftReportTimes(generic, base)
	generic["collected_at"] = base
	evs := generic["events"].([]any)
	evs[0].(map[string]any)["kind"] = "agent_started"
	evs[0].(map[string]any)["detail"] = map[string]any{"agent_version": "1.0.0"}
	evs = evs[:1]
	generic["events"] = evs
	if status, resp := b2SendReport(t, tc, a, generic, b2Nonce(t)); status != 200 || resp["result"] != "accepted" {
		t.Fatalf("generic diagnostic: %d %v", status, resp)
	}
	// services=false + singbox_api=true: a service_restart event is still
	// rejected because the service source is independently unauthorized.
	if _, err := tc.store.UpdateNodeConfig(context.Background(), a.nodeID, map[string]bool{
		"system": true, "services": false, "singbox_api": true, "mihomo_api": false, "terminal": false, "events": true,
	}, nil, 60, time.Now().Unix()); err != nil {
		t.Fatalf("singbox-only config: %v", err)
	}
	svc := b2Example(t, "report-events.v1.json")
	svc["report_id"] = b2UUID(t)
	svc["collected_at"] = base + 50
	b2ShiftReportTimes(svc, base+50)
	evs2 := svc["events"].([]any)
	evs2[0].(map[string]any)["kind"] = "service_restart"
	evs2[0].(map[string]any)["detail"] = map[string]any{"service": "sing-box"}
	svc["events"] = evs2[:1]
	if status, resp := b2SendReport(t, tc, a, svc, b2Nonce(t)); status != 400 || resp["error"] != "invalid_request" {
		t.Fatalf("service event without services source: %d %v", status, resp)
	}
}

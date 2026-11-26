package center_test

// H1: Windows default-config snapshot existence/terminal source regression.

import (
	"context"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/wire"
)

func enrollDefaultH1(t *testing.T, tc *testCenter, class, host string) *syntheticAgent {
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
	if err := tc.store.CreateEnrollToken(context.Background(), hash, eventUUID, class, now+3600, now); err != nil {
		t.Fatalf("token create: %v", err)
	}
	a.seq = 0
	h, err := a.headers(wire.Enroll, now, b2Nonce(t), raw)
	if err != nil {
		t.Fatalf("enroll headers: %v", err)
	}
	h.Set(wire.HeaderAuthorization, "Bearer "+token)
	status, resp := doPost(t, tc, "/v1/agent/enroll", h, raw)
	if status != 200 {
		t.Fatalf("enroll: %d %v", status, resp)
	}
	a.nodeID, _ = resp["node_id"].(string)
	a.keyID, _ = resp["key_id"].(string)
	return a
}

func h1TerminalDoc(t *testing.T, collected int64) map[string]any {
	t.Helper()
	doc := b2Example(t, "terminal-snapshot.v1.json")
	doc["report_id"] = b2UUID(t)
	b2ShiftReportTimes(doc, collected)
	doc["collected_at"] = collected
	return doc
}

func h1SetAvailable(t *testing.T, tc *testCenter, nodeID string, terminal, mihomo bool) {
	t.Helper()
	if _, err := tc.store.UpdateNodeConfig(context.Background(), nodeID, map[string]bool{
		"system": false, "services": false, "singbox_api": false,
		"mihomo_api": mihomo, "terminal": terminal, "events": true,
	}, nil, 60, time.Now().Unix()); err != nil {
		t.Fatalf("config update: %v", err)
	}
}

func TestH1WindowsTerminalSourceMatrix(t *testing.T) {
	tc := startTestCenter(t)
	win := enrollDefaultH1(t, tc, store.NodeClassWindowsTerminal, "windows")
	base := b2BaseCollected(t)

	// Default config (all sources false), no terminal object: legal snapshot.
	noTerminal := h1TerminalDoc(t, base)
	delete(noTerminal, "terminal")
	if status, resp := b2SendReport(t, tc, win, noTerminal, b2Nonce(t)); status != 200 || resp["result"] != "accepted" {
		t.Fatalf("false/false without terminal: %d %v", status, resp)
	}
	// false/false with a terminal observation object: rejected.
	withTerminal := h1TerminalDoc(t, base+10)
	if status, resp := b2SendReport(t, tc, win, withTerminal, b2Nonce(t)); status != 400 {
		t.Fatalf("false/false with terminal: %d %v, want 400", status, resp)
	}
	// true/false: selection legal, real active_connections rejected.
	h1SetAvailable(t, tc, win.nodeID, true, false)
	activeOK := h1TerminalDoc(t, base+20)
	if status, resp := b2SendReport(t, tc, win, activeOK, b2Nonce(t)); status != 400 {
		t.Fatalf("true/false active ok: %d %v, want 400", status, resp)
	}
	activeUnavailable := h1TerminalDoc(t, base+30)
	term := activeUnavailable["terminal"].(map[string]any)
	term["active_connections"] = map[string]any{
		"availability": "unavailable", "sampled_at": base + 28,
		"total": nil, "by_route": map[string]any{
			"a_reality": nil, "a_hy2": nil, "b_reality": nil,
			"b_hy2": nil, "direct": nil, "unknown": nil,
		},
	}
	if status, resp := b2SendReport(t, tc, win, activeUnavailable, b2Nonce(t)); status != 200 || resp["result"] != "accepted" {
		t.Fatalf("true/false active unavailable: %d %v", status, resp)
	}
	// false/true: selection must be honest unavailable.
	h1SetAvailable(t, tc, win.nodeID, false, true)
	selectionOK := h1TerminalDoc(t, base+40)
	if status, resp := b2SendReport(t, tc, win, selectionOK, b2Nonce(t)); status != 400 {
		t.Fatalf("false/true selection ok: %d %v, want 400", status, resp)
	}
	selectionUnavailable := h1TerminalDoc(t, base+50)
	term = selectionUnavailable["terminal"].(map[string]any)
	term["selection"] = map[string]any{
		"availability": "unavailable", "sampled_at": base + 48,
		"route": nil, "reason_code": "source_authorization_unproven",
	}
	if status, resp := b2SendReport(t, tc, win, selectionUnavailable, b2Nonce(t)); status != 200 || resp["result"] != "accepted" {
		t.Fatalf("false/true selection unavailable: %d %v", status, resp)
	}
	// true/true: existing legal terminal snapshot remains accepted.
	h1SetAvailable(t, tc, win.nodeID, true, true)
	if status, resp := b2SendReport(t, tc, win, h1TerminalDoc(t, base+60), b2Nonce(t)); status != 200 || resp["result"] != "accepted" {
		t.Fatalf("true/true terminal snapshot: %d %v", status, resp)
	}
}

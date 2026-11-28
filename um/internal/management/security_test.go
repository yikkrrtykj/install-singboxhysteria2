package management_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/agent"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/management"
)

func mustToken(t *testing.T, c *management.Client, event, class string) management.EnrollmentTokenCreated {
	t.Helper()
	var out management.EnrollmentTokenCreated
	if err := c.Call(context.Background(), http.MethodPost, "/api/v1/events/"+event+"/tokens", nil,
		map[string]any{"node_class": class, "ttl_seconds": 120}, &out); err != nil {
		t.Fatalf("token create: %v", err)
	}
	return out
}

func TestTokenLifecycleAndRevocation(t *testing.T) {
	bc := startB4Center(t)
	platform := clientFor(t, bc, "platform")
	adminA := clientFor(t, bc, "admin-a")
	viewerA := clientFor(t, bc, "viewer-a")
	createEvent(t, platform, eventA, "A")
	created := mustToken(t, adminA, eventA, "linux_vps")

	var list map[string]any
	if err := adminA.Call(context.Background(), http.MethodGet, "/api/v1/events/"+eventA+"/tokens", nil, nil, &list); err != nil {
		t.Fatal(err)
	}
	tokens, _ := list["tokens"].([]any)
	if len(tokens) != 1 {
		t.Fatalf("token list=%+v", list)
	}
	var status management.EnrollmentTokenView
	if err := adminA.Call(context.Background(), http.MethodGet, "/api/v1/events/"+eventA+"/tokens/"+created.TokenID, nil, nil, &status); err != nil {
		t.Fatal(err)
	}
	if status.Status != "unused" {
		t.Fatalf("token status=%q", status.Status)
	}
	// A viewer can read token metadata but not revoke.
	if err := viewerA.Call(context.Background(), http.MethodPost, "/api/v1/events/"+eventA+"/tokens/"+created.TokenID+"/revoke", nil, nil, nil); err == nil {
		t.Fatal("viewer revoked token")
	}
	if err := adminA.Call(context.Background(), http.MethodPost, "/api/v1/events/"+eventA+"/tokens/"+created.TokenID+"/revoke", nil, nil, nil); err != nil {
		t.Fatalf("revoke token: %v", err)
	}
	if err := adminA.Call(context.Background(), http.MethodGet, "/api/v1/events/"+eventA+"/tokens/"+created.TokenID, nil, nil, &status); err != nil {
		t.Fatal(err)
	}
	if status.Status != "revoked" {
		t.Fatalf("revoked token status=%q", status.Status)
	}
	// Real agent enrollment must fail after the token is revoked.
	dir := t.TempDir()
	r, err := agent.NewRuntime(agent.Options{StateDir: dir, CenterURL: bc.ingest,
		NodeClass: "linux_vps", HostOS: "linux", AgentVersion: "1.0.0",
		Collector: exampleCollector{class: "linux_vps"}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.Enroll(context.Background(), created.Token); err == nil {
		t.Fatal("revoked enrollment token accepted by real agent")
	} else {
		var ce *agent.CenterError
		if !errors.As(err, &ce) || ce.Status != http.StatusUnauthorized || ce.Code != "token_invalid" || ce.Retryable {
			t.Fatalf("revoked token error=%v, want closed 401 token_invalid non-retryable", err)
		}
	}
}

func TestConfigSourceSecurityAndHistory(t *testing.T) {
	bc := startB4Center(t)
	platform := clientFor(t, bc, "platform")
	createEvent(t, platform, eventA, "A")
	linuxTok := mustToken(t, platform, eventA, "linux_vps")
	winTok := mustToken(t, platform, eventA, "windows_terminal")
	linux, _ := enrollAgent(t, bc, "linux_vps", linuxTok.Token)
	defer linux.Close()
	win, _ := enrollAgent(t, bc, "windows_terminal", winTok.Token)
	defer win.Close()
	linuxID, _ := linux.Identity()
	winID, _ := win.Identity()
	full := func(system, services, terminal, events bool) map[string]bool {
		return map[string]bool{"system": system, "services": services, "singbox_api": false,
			"mihomo_api": false, "terminal": terminal, "events": events}
	}
	if err := platform.Call(context.Background(), http.MethodPut,
		"/api/v1/events/"+eventA+"/nodes/"+linuxID.NodeID+"/config", nil,
		map[string]any{"cadence_seconds": 60, "sources": full(true, true, false, true),
			"expected_inbound_tags": []map[string]string{{"inbound_tag": "vless-in", "kind": "reality"}}}, nil); err != nil {
		t.Fatal(err)
	}
	// Center config cannot enable the unavailable Linux singbox_api source.
	if err := platform.Call(context.Background(), http.MethodPut,
		"/api/v1/events/"+eventA+"/nodes/"+linuxID.NodeID+"/config", nil,
		map[string]any{"cadence_seconds": 60,
			"sources": map[string]bool{"system": false, "services": false, "singbox_api": true,
				"mihomo_api": false, "terminal": false, "events": false},
			"expected_inbound_tags": []map[string]string{{"inbound_tag": "vless-in", "kind": "reality"}}}, nil); err == nil {
		t.Fatal("singbox_api enabled via center config")
	}
	// Windows R1/controller remains local-bundle-only.
	if err := platform.Call(context.Background(), http.MethodPut,
		"/api/v1/events/"+eventA+"/nodes/"+winID.NodeID+"/config", nil,
		map[string]any{"cadence_seconds": 60,
			"sources": map[string]bool{"system": false, "services": false, "singbox_api": false,
				"mihomo_api": true, "terminal": true, "events": false}}, nil); err == nil {
		t.Fatal("mihomo_api/R1 enabled via center config")
	}
	if err := platform.Call(context.Background(), http.MethodPut,
		"/api/v1/events/"+eventA+"/nodes/"+winID.NodeID+"/config", nil,
		map[string]any{"cadence_seconds": 60, "sources": full(false, false, true, true)}, nil); err != nil {
		t.Fatal(err)
	}
	var history []management.ConfigHistoryView
	if err := platform.Call(context.Background(), http.MethodGet,
		"/api/v1/events/"+eventA+"/nodes/"+linuxID.NodeID+"/config/history", nil, nil, &history); err != nil {
		t.Fatal(err)
	}
	if len(history) < 2 {
		t.Fatalf("config history=%d, want >=2", len(history))
	}
}

func TestAliasOptimisticConcurrency(t *testing.T) {
	bc := startB4Center(t)
	platform := clientFor(t, bc, "platform")
	adminA := clientFor(t, bc, "admin-a")
	createEvent(t, platform, eventA, "A")
	adminB := clientFor(t, bc, "admin-b")
	_ = adminB
	tok := mustToken(t, adminA, eventA, "linux_vps")
	r, _ := enrollAgent(t, bc, "linux_vps", tok.Token)
	defer r.Close()
	id, _ := r.Identity()
	var a management.AliasView
	if err := adminA.Call(context.Background(), http.MethodPut,
		"/api/v1/events/"+eventA+"/aliases/node/"+id.NodeID, nil,
		map[string]any{"display_name": "vps-one"}, &a); err != nil {
		t.Fatal(err)
	}
	if a.Version != 1 {
		t.Fatalf("version=%d", a.Version)
	}
	// Blind second write is a conflict.
	var apiErr *management.APIError
	err := adminA.Call(context.Background(), http.MethodPut,
		"/api/v1/events/"+eventA+"/aliases/node/"+id.NodeID, nil,
		map[string]any{"display_name": "blind"}, nil)
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusConflict {
		t.Fatalf("blind alias update err=%v, want 409", err)
	}
	expected := int64(1)
	if err := adminA.Call(context.Background(), http.MethodPut,
		"/api/v1/events/"+eventA+"/aliases/node/"+id.NodeID, nil,
		map[string]any{"display_name": "vps-one-renamed", "expected_version": expected}, &a); err != nil {
		t.Fatal(err)
	}
	if a.Version != 2 || a.DisplayName != "vps-one-renamed" {
		t.Fatalf("alias update=%+v", a)
	}
}

func TestMappingRejectsInvalidTargetsAndPreservesHistory(t *testing.T) {
	// History preservation is exercised by the two-event E2E; here the boundary
	// rejects direct/unknown targets and cross-event node references.
	bc := startB4Center(t)
	platform := clientFor(t, bc, "platform")
	createEvent(t, platform, eventA, "A")
	createEvent(t, platform, eventB, "B")
	winTok := mustToken(t, platform, eventA, "windows_terminal")
	linuxATok := mustToken(t, platform, eventA, "linux_vps")
	linuxBTok := mustToken(t, platform, eventB, "linux_vps")
	win, _ := enrollAgent(t, bc, "windows_terminal", winTok.Token)
	defer win.Close()
	linuxA, _ := enrollAgent(t, bc, "linux_vps", linuxATok.Token)
	defer linuxA.Close()
	linuxB, _ := enrollAgent(t, bc, "linux_vps", linuxBTok.Token)
	defer linuxB.Close()
	winID, _ := win.Identity()
	linuxAID, _ := linuxA.Identity()
	linuxBID, _ := linuxB.Identity()
	base := "/api/v1/events/" + eventA + "/mapping/" + winID.NodeID
	// direct/unknown cannot be mapping entries.
	for _, token := range []string{"direct", "unknown"} {
		if err := platform.Call(context.Background(), http.MethodPost, base, nil,
			map[string]any{"version": 1, "effective_from": timeNow() + 60,
				"entries": []map[string]string{{"route_token": token, "target_node_id": linuxAID.NodeID}}}, nil); err == nil {
			t.Fatalf("mapping accepted reserved token %s", token)
		}
	}
	// A cross-event target must be rejected by the store even though it exists.
	if err := platform.Call(context.Background(), http.MethodPost, base, nil,
		map[string]any{"version": 1, "effective_from": timeNow() + 60,
			"entries": []map[string]string{{"route_token": "a_reality", "target_node_id": linuxBID.NodeID}}}, nil); err == nil {
		t.Fatal("mapping accepted cross-event target")
	}
	if err := platform.Call(context.Background(), http.MethodPost, base, nil,
		map[string]any{"version": 1, "effective_from": timeNow() + 60,
			"entries": []map[string]string{{"route_token": "a_reality", "target_node_id": linuxAID.NodeID}}}, nil); err != nil {
		t.Fatal(err)
	}
	// A revoked/non-active target cannot be used by a later version.
	if err := platform.Call(context.Background(), http.MethodPost,
		"/api/v1/events/"+eventA+"/nodes/"+linuxAID.NodeID+"/revoke", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := platform.Call(context.Background(), http.MethodPost, base, nil,
		map[string]any{"version": 2, "effective_from": timeNow() + 120,
			"entries": []map[string]string{{"route_token": "a_reality", "target_node_id": linuxAID.NodeID}}}, nil); err == nil {
		t.Fatal("mapping accepted revoked target")
	}
	// Existing version cannot be rewritten.
	if err := platform.Call(context.Background(), http.MethodPost, base, nil,
		map[string]any{"version": 1, "effective_from": timeNow() + 120,
			"entries": []map[string]string{{"route_token": "a_reality", "target_node_id": linuxAID.NodeID}}}, nil); err == nil {
		t.Fatal("mapping version 1 rewritten")
	}
}

func timeNow() int64 { return time.Now().Unix() }

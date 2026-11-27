package management_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/agent"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/management"
)

type exampleCollector struct {
	class string
}

func (c exampleCollector) load(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(contractsDir, "examples", name))
}

func (c exampleCollector) body(kind string, rc agent.ReportContext) ([]byte, error) {
	switch kind {
	case "snapshot":
		availability := map[string]any{
			"system": "unavailable", "services": "unavailable", "protocols": "unavailable",
			"traffic": "unavailable", "clients": "unavailable",
		}
		system := map[string]any{
			"cpu_pct": nil, "load1": nil, "mem_total_bytes": nil, "mem_used_bytes": nil,
			"disk_total_bytes": nil, "disk_used_bytes": nil, "net_rx_bytes": nil, "net_tx_bytes": nil,
		}
		doc := map[string]any{
			"v": 1, "type": "snapshot", "report_id": rc.ReportID, "collected_at": rc.CollectedAt,
			"agent":         map[string]any{"version": "1.0.0", "uptime_s": 1},
			"host":          map[string]any{"os": "linux", "kernel": "test", "arch": "amd64"},
			"availability":  availability,
			"counter_epoch": "0123456789abcdef0123456789abcdef",
			"system":        system, "services": []any{}, "protocols": []any{}, "traffic": []any{},
			"clients": map[string]any{"active": nil, "tracked": nil, "summaries": []any{}},
		}
		if c.class == "windows_terminal" {
			doc["host"] = map[string]any{"os": "windows", "kernel": "10.0.26100", "arch": "amd64"}
			doc["terminal"] = map[string]any{
				"selection": map[string]any{"availability": "ok", "sampled_at": rc.CollectedAt, "route": "a_reality", "reason_code": nil},
				"active_connections": map[string]any{"availability": "unavailable", "sampled_at": rc.CollectedAt,
					"total": nil, "by_route": map[string]any{"a_reality": nil, "a_hy2": nil, "b_reality": nil, "b_hy2": nil, "direct": nil, "unknown": nil}},
			}
		}
		return json.Marshal(doc)
	case "metrics":
		doc := map[string]any{
			"v": 1, "type": "metrics", "report_id": rc.ReportID, "collected_at": rc.CollectedAt,
			"availability": map[string]any{"system": "unavailable", "services": "unavailable",
				"protocols": "unavailable", "traffic": "unavailable", "clients": "unavailable"},
			"samples": []any{map[string]any{"at": rc.CollectedAt, "cpu_pct": nil, "load1": nil,
				"mem_used_bytes": nil, "disk_used_bytes": nil, "net_rx_bytes_total": nil,
				"net_tx_bytes_total": nil, "active_connections": nil}},
		}
		return json.Marshal(doc)
	case "events":
		return json.Marshal(map[string]any{"v": 1, "type": "events", "report_id": rc.ReportID,
			"collected_at": rc.CollectedAt, "events": []any{
				map[string]any{"event_id": "6d1a9b3e-7c2f-4e8a-a5b0-9c3d1e7f2a64",
					"at": rc.CollectedAt - 10, "kind": "agent_error", "severity": "info",
					"detail": map[string]any{"code": "source_authorization_unproven"}},
			}})
	default:
		return nil, agent.ErrUnsupported
	}
}

func (c exampleCollector) Snapshot(_ context.Context, rc agent.ReportContext) ([]byte, error) {
	return c.body("snapshot", rc)
}
func (c exampleCollector) Metrics(_ context.Context, rc agent.ReportContext) ([]byte, error) {
	return c.body("metrics", rc)
}
func (c exampleCollector) Events(_ context.Context, rc agent.ReportContext) ([]byte, error) {
	return c.body("events", rc)
}

func enrollAgent(t *testing.T, bc *b4Center, class, token string) (*agent.Runtime, string) {
	t.Helper()
	dir := t.TempDir()
	r, err := agent.NewRuntime(agent.Options{
		StateDir: dir, CenterURL: bc.ingest, NodeClass: class,
		HostOS:       map[string]string{"linux_vps": "linux", "windows_terminal": "windows"}[class],
		AgentVersion: "1.0.0", Collector: exampleCollector{class: class},
		Sleep: func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Enroll(context.Background(), token); err != nil {
		t.Fatalf("agent enroll: %v", err)
	}
	if err := r.PullConfig(context.Background()); err != nil {
		t.Fatalf("agent config: %v", err)
	}
	return r, dir
}

func sendReports(t *testing.T, r *agent.Runtime, class string) {
	t.Helper()
	kinds := []string{"snapshot", "events"}
	if class == "linux_vps" {
		kinds = []string{"snapshot", "metrics", "events"}
	}
	for _, kind := range kinds {
		if _, err := r.QueueReport(context.Background(), kind); err != nil {
			t.Fatalf("queue %s: %v", kind, err)
		}
		if err := r.Flush(context.Background()); err != nil {
			t.Fatalf("flush %s: %v", kind, err)
		}
		if got := r.LastResult(); got != "accepted" && got != "duplicate" {
			t.Fatalf("report %s result=%q, want accepted/duplicate", kind, got)
		}
	}
}

func TestTwoEventManagementE2E(t *testing.T) {
	bc := startB4Center(t)
	platform := clientFor(t, bc, "platform")
	adminA := clientFor(t, bc, "admin-a")
	viewerA := clientFor(t, bc, "viewer-a")
	createEvent(t, platform, eventA, "Event A")
	createEvent(t, platform, eventB, "Event B")

	createToken := func(c *management.Client, event, class string) string {
		var out management.EnrollmentTokenCreated
		if err := c.Call(context.Background(), http.MethodPost, "/api/v1/events/"+event+"/tokens", nil,
			map[string]any{"node_class": class, "ttl_seconds": 600}, &out); err != nil {
			t.Fatalf("token create %s/%s: %v", event, class, err)
		}
		if out.Token == "" || out.TokenID == "" {
			t.Fatal("token not returned")
		}
		return out.Token
	}

	// Event A: one real Linux agent and one real Windows agent.
	linuxToken := createToken(adminA, eventA, "linux_vps")
	winToken := createToken(adminA, eventA, "windows_terminal")
	linuxAgent, _ := enrollAgent(t, bc, "linux_vps", linuxToken)
	defer linuxAgent.Close()
	winAgent, _ := enrollAgent(t, bc, "windows_terminal", winToken)
	defer winAgent.Close()
	linuxID, _ := linuxAgent.Identity()
	winID, _ := winAgent.Identity()

	// Configure the real agents through the management API, then pull config.
	var cfg management.ConfigView
	if err := platform.Call(context.Background(), http.MethodPut,
		"/api/v1/events/"+eventA+"/nodes/"+linuxID.NodeID+"/config", nil,
		map[string]any{"cadence_seconds": 60,
			"sources":               map[string]bool{"system": true, "services": true, "singbox_api": false, "mihomo_api": false, "terminal": false, "events": true},
			"expected_inbound_tags": []map[string]string{{"inbound_tag": "vless-in", "kind": "reality"}, {"inbound_tag": "hy2-in", "kind": "hysteria2"}}}, &cfg); err != nil {
		t.Fatalf("linux config update: %v", err)
	}
	if err := platform.Call(context.Background(), http.MethodPut,
		"/api/v1/events/"+eventA+"/nodes/"+winID.NodeID+"/config", nil,
		map[string]any{"cadence_seconds": 60,
			"sources": map[string]bool{"system": false, "services": false, "singbox_api": false, "mihomo_api": false, "terminal": true, "events": true}}, &cfg); err != nil {
		t.Fatalf("windows config update: %v", err)
	}
	if err := linuxAgent.PullConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := winAgent.PullConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	sendReports(t, linuxAgent, "linux_vps")
	sendReports(t, winAgent, "windows_terminal")

	// Node list/detail and alias.
	var nodes management.NodeList
	if err := adminA.Call(context.Background(), http.MethodGet, "/api/v1/events/"+eventA+"/nodes", nil, nil, &nodes); err != nil {
		t.Fatal(err)
	}
	if nodes.Total != 2 {
		t.Fatalf("nodes total=%d, want 2: %+v", nodes.Total, nodes.Nodes)
	}
	if nodes.Nodes[0].DerivedStatus == "" || nodes.Nodes[1].DerivedStatus == "" {
		t.Fatal("node derived status missing")
	}
	var node management.NodeView
	if err := viewerA.Call(context.Background(), http.MethodGet, "/api/v1/events/"+eventA+"/nodes/"+linuxID.NodeID, nil, nil, &node); err != nil {
		t.Fatal(err)
	}
	if len(node.Keys) == 0 || node.LatestSnapshotAt == nil {
		t.Fatalf("linux node detail incomplete: %+v", node)
	}
	var winNode management.NodeView
	if err := viewerA.Call(context.Background(), http.MethodGet, "/api/v1/events/"+eventA+"/nodes/"+winID.NodeID, nil, nil, &winNode); err != nil {
		t.Fatal(err)
	}
	if winNode.LatestSnapshotAt == nil || winNode.NodeClass != "windows_terminal" {
		t.Fatalf("windows node detail incomplete: %+v", winNode)
	}
	var alias management.AliasView
	if err := adminA.Call(context.Background(), http.MethodPut, "/api/v1/events/"+eventA+"/aliases/node/"+linuxID.NodeID, nil,
		map[string]any{"display_name": "primary-vps"}, &alias); err != nil {
		t.Fatalf("alias set: %v", err)
	}
	if alias.Version != 1 {
		t.Fatalf("alias version=%d", alias.Version)
	}
	var aliased management.NodeView
	if err := viewerA.Call(context.Background(), http.MethodGet, "/api/v1/events/"+eventA+"/nodes/"+linuxID.NodeID, nil, nil, &aliased); err != nil {
		t.Fatal(err)
	}
	if aliased.DisplayAlias != "primary-vps" {
		t.Fatalf("node alias projection=%q", aliased.DisplayAlias)
	}

	// Versioned mapping: create v1, resolve historical, then create v2 only
	// after v1 effective time and prove the historical attribution is stable.
	now := time.Now().Unix()
	v1Effective := now + 5
	if err := platform.Call(context.Background(), http.MethodPost,
		"/api/v1/events/"+eventA+"/mapping/"+winID.NodeID, nil,
		map[string]any{"version": 1, "effective_from": v1Effective,
			"entries": []map[string]string{{"route_token": "a_reality", "target_node_id": linuxID.NodeID}}},
		nil); err != nil {
		t.Fatalf("mapping v1: %v", err)
	}
	v2Effective := now + 10
	// A second, independent Linux node is needed as the new mapping target.
	linux2Token := createToken(adminA, eventA, "linux_vps")
	linux2, _ := enrollAgent(t, bc, "linux_vps", linux2Token)
	defer linux2.Close()
	linux2Identity, _ := linux2.Identity()
	if err := platform.Call(context.Background(), http.MethodPost,
		"/api/v1/events/"+eventA+"/mapping/"+winID.NodeID, nil,
		map[string]any{"version": 2, "effective_from": v2Effective,
			"entries": []map[string]string{{"route_token": "a_reality", "target_node_id": linux2Identity.NodeID}}},
		nil); err != nil {
		t.Fatalf("mapping v2: %v", err)
	}
	var resolved1, resolved2 management.MappingResolutionView
	if err := viewerA.Call(context.Background(), http.MethodGet,
		"/api/v1/events/"+eventA+"/mapping/"+winID.NodeID+"/resolve?at="+strconvI(v1Effective), nil, nil, &resolved1); err != nil {
		t.Fatal(err)
	}
	if resolved1.Version != 1 || resolved1.Entries["a_reality"] != linuxID.NodeID {
		t.Fatalf("historical v1 = %+v", resolved1)
	}
	if err := viewerA.Call(context.Background(), http.MethodGet,
		"/api/v1/events/"+eventA+"/mapping/"+winID.NodeID+"/resolve?at="+strconvI(v2Effective), nil, nil, &resolved2); err != nil {
		t.Fatal(err)
	}
	if resolved2.Version != 2 || resolved2.Entries["a_reality"] != linux2Identity.NodeID {
		t.Fatalf("v2 = %+v", resolved2)
	}
	// Unmapped window node resolves as empty, not as a fabricated target.
	var unmapped management.MappingResolutionView
	if err := viewerA.Call(context.Background(), http.MethodGet,
		"/api/v1/events/"+eventB+"/mapping/"+winID.NodeID+"/resolve", nil, nil, &unmapped); err != nil {
		// Event B has no mapping; the windows node belongs to A, so this is an
		// expected scoped/membership miss (404), never a leaked mapping.
		var apiErr *management.APIError
		if !errors.As(err, &apiErr) || apiErr.Status != http.StatusNotFound {
			t.Fatalf("cross-event mapping resolution err=%v", err)
		}
	} else if len(unmapped.Entries) != 0 {
		t.Fatalf("unmapped resolution invented entries: %+v", unmapped)
	}

	// Revoke the Linux node as event_admin A; the agent must stop reporting.
	if err := adminA.Call(context.Background(), http.MethodPost,
		"/api/v1/events/"+eventA+"/nodes/"+linuxID.NodeID+"/revoke", nil, nil, nil); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := linuxAgent.QueueReport(context.Background(), "snapshot"); err == nil {
		if err := linuxAgent.Flush(context.Background()); err == nil {
			t.Fatal("revoked agent continued reporting")
		}
	}
	// Event A still exists; Event B independent lifecycle.
	var events management.EventList
	if err := viewerA.Call(context.Background(), http.MethodGet, "/api/v1/events", nil, nil, &events); err != nil {
		t.Fatal(err)
	}
	if len(events.Events) != 1 || events.Events[0].EventID != eventA {
		t.Fatalf("event A scope list = %+v", events.Events)
	}
	if err := platform.Call(context.Background(), http.MethodPost, "/api/v1/events/"+eventB+"/archive", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	var audit management.AuditList
	if err := adminA.Call(context.Background(), http.MethodGet, "/api/v1/audit", nil, nil, &audit); err != nil {
		t.Fatalf("scoped audit: %v", err)
	}
	for _, e := range audit.Entries {
		if e.EventID != nil && *e.EventID == eventB {
			t.Fatalf("event A admin saw event B audit: %+v", e)
		}
	}
	if err := viewerA.Call(context.Background(), http.MethodGet, "/api/v1/audit", nil, nil, &audit); err == nil {
		t.Fatal("viewer read audit")
	}
}

func strconvI(v int64) string { return strconv.FormatInt(v, 10) }

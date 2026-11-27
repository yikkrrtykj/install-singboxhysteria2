package windowsagent

// MOCK / UNIT test harness only.
//
// The R1-style loopback Mihomo controller client (windowsobs) is exercised in
// these tests against in-process httptest servers and a synthetic observer. No
// real controller, credential, Windows service or production account is used,
// and nothing here is evidence of a proven read-only source (R1 is not
// authorized; R2 remains future work). Every such test is labelled MOCK in its
// name or comment.

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/agent"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/contract"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/windowsobs"
)

// mockObserver is the injected RouteObserver used by MOCK-UNIT tests. It never
// performs I/O and counts how often each independent sample is requested.
type mockObserver struct {
	mu        sync.Mutex
	selection windowsobs.Selection
	active    windowsobs.Active
	selCalls  int
	actCalls  int
}

func (m *mockObserver) ObserveSelection(context.Context) windowsobs.Selection {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.selCalls++
	return m.selection
}

func (m *mockObserver) ObserveActive(context.Context) windowsobs.Active {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.actCalls++
	return m.active
}

func (m *mockObserver) calls() (int, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.selCalls, m.actCalls
}

// testUUID returns a canonical lowercase UUIDv4 for report identity.
func testUUID(t *testing.T) string {
	t.Helper()
	id, err := newUUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func testHost() agent.HostInfo {
	return agent.HostInfo{OS: "windows", Kernel: "10.0.26100", Arch: "amd64"}
}

func testSources(terminal, mihomo bool) map[string]bool {
	return map[string]bool{
		"system": false, "services": false, "singbox_api": false,
		"mihomo_api": mihomo, "terminal": terminal, "events": true,
	}
}

func testReportContext(t *testing.T, sources map[string]bool) agent.ReportContext {
	t.Helper()
	return agent.ReportContext{
		ReportID:    testUUID(t),
		CollectedAt: time.Now().Unix(),
		Host:        testHost(),
		Config: agent.CollectConfig{
			ConfigVersion: 1,
			Cadence:       60,
			Sources:       sources,
			DeviceSalt:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
	}
}

// newCollector builds a collector for tests (MOCK source or nil).
func newCollector(t *testing.T, observer RouteObserver) *Collector {
	t.Helper()
	collector, err := New(Options{
		AgentVersion: "1.4.0",
		Uptime:       func() int64 { return 3600 },
		Observer:     observer,
	})
	if err != nil {
		t.Fatal(err)
	}
	return collector
}

// decodeSnapshot decodes a produced snapshot body into the internal shape.
func decodeSnapshot(t *testing.T, raw []byte) snapshotBody {
	t.Helper()
	var body snapshotBody
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("snapshot body is not valid JSON: %v", err)
	}
	return body
}

func decodeEvents(t *testing.T, raw []byte) eventsBody {
	t.Helper()
	var body eventsBody
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("events body is not valid JSON: %v", err)
	}
	return body
}

// requireContractSnapshot validates a produced body with the same frozen
// contract runtime rules the centre applies. terminalConfigured must mirror the
// centre's `terminal || mihomo_api` source decision.
func requireContractSnapshot(t *testing.T, raw []byte, terminalConfigured bool) {
	t.Helper()
	err := contract.ValidateReportBodyWithOptions(contract.NodeClassWindowsTerminal, contract.ReportTypeSnapshot, raw,
		contract.ValidateOptions{TerminalConfigured: terminalConfigured})
	if err != nil {
		t.Fatalf("produced snapshot rejected by frozen contract: %v\nbody: %s", err, raw)
	}
}

func requireContractEvents(t *testing.T, raw []byte) {
	t.Helper()
	if err := contract.ValidateReportBody(contract.NodeClassWindowsTerminal, contract.ReportTypeEvents, raw); err != nil {
		t.Fatalf("produced events body rejected by frozen contract: %v\nbody: %s", err, raw)
	}
}

// requireNoPrivacySentinels asserts that no raw controller value, local name or
// credential leaked into the encoded body.
func requireNoPrivacySentinels(t *testing.T, raw []byte, sentinels []string) {
	t.Helper()
	body := string(raw)
	for _, sentinel := range sentinels {
		if sentinel == "" {
			continue
		}
		if strings.Contains(body, sentinel) {
			t.Fatalf("privacy sentinel leaked into report body: %q", sentinel)
		}
	}
}

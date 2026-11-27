package windowsagent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/agent"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/windowsobs"
)

func observedSelection(role windowsobs.Role, sampledAt int64) windowsobs.Selection {
	return windowsobs.Selection{State: windowsobs.StateObserved, Role: role, SampledAt: sampledAt}
}

func observedActive(counts map[windowsobs.Role]int, unknown int, sampledAt int64) windowsobs.Active {
	return windowsobs.Active{
		State: windowsobs.StateObserved, Counts: counts, Unknown: &unknown, SampledAt: sampledAt,
	}
}

func fullCounts(values map[windowsobs.Role]int) map[windowsobs.Role]int {
	counts := map[windowsobs.Role]int{
		windowsobs.AReality: 0, windowsobs.AHY2: 0, windowsobs.BReality: 0,
		windowsobs.BHY2: 0, windowsobs.Direct: 0,
	}
	for role, value := range values {
		counts[role] = value
	}
	return counts
}

// TestNewDefaultsAndInvalidOptions pins the zero-value constructor behaviour and
// the option validation that keeps bodies contract-valid.
func TestNewDefaultsAndInvalidOptions(t *testing.T) {
	collector, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if collector.version != DefaultAgentVersion {
		t.Fatalf("default version = %q", collector.version)
	}
	for _, opts := range []Options{
		{AgentVersion: "not a version"},
		{AgentVersion: "1.2.3.4"},
		{CounterEpoch: "ABCDEF0123456789ABCDEF0123456789"},
		{CounterEpoch: "tooshort"},
	} {
		if _, err := New(opts); !errors.Is(err, ErrInvalidReportContext) {
			t.Errorf("options %+v accepted or wrong error: %v", opts, err)
		}
	}
}

// TestSnapshotH1DefaultAbsence proves the frozen H1 default-config shape:
// with both terminal sources false the terminal object is absent (legal), the
// base telemetry is honest unavailable/null/empty, and no source is touched.
func TestSnapshotH1DefaultAbsence(t *testing.T) {
	mock := &mockObserver{selection: observedSelection(windowsobs.AReality, 0)}
	collector := newCollector(t, mock)
	rc := testReportContext(t, testSources(false, false))

	raw, err := collector.Snapshot(context.Background(), rc)
	if err != nil {
		t.Fatal(err)
	}
	requireContractSnapshot(t, raw, false)
	requireNoPrivacySentinels(t, raw, []string{rc.Config.DeviceSalt, rc.ReportID + "-not-a-leak"})
	if strings.Contains(string(raw), `"terminal"`) {
		t.Fatalf("terminal object present without authorization: %s", raw)
	}
	if selectionCalls, activeCalls := mock.calls(); selectionCalls != 0 || activeCalls != 0 {
		t.Fatalf("unauthorized source was sampled: selection=%d active=%d", selectionCalls, activeCalls)
	}

	body := decodeSnapshot(t, raw)
	if body.V != 1 || body.Type != "snapshot" || body.ReportID != rc.ReportID || body.CollectedAt != rc.CollectedAt {
		t.Fatalf("identity fields = %+v", body)
	}
	if body.Agent.Version != "1.4.0" || body.Agent.UptimeS != 3600 {
		t.Fatalf("agent = %+v", body.Agent)
	}
	if body.Host != (hostInfo{OS: "windows", Kernel: "10.0.26100", Arch: "amd64"}) {
		t.Fatalf("host = %+v", body.Host)
	}
	wantAvailability := unavailableAvailability()
	if body.Availability != wantAvailability {
		t.Fatalf("availability = %+v", body.Availability)
	}
	if body.Services == nil || body.Protocols == nil || body.Traffic == nil {
		t.Fatal("base arrays encoded as null instead of []")
	}
	if body.Clients.Active != nil || body.Clients.Tracked != nil || body.Clients.Summaries == nil {
		t.Fatalf("clients = %+v", body.Clients)
	}
	if body.System.CPUPct != nil || body.System.Load1 != nil || body.System.MemTotalBytes != nil ||
		body.System.MemUsedBytes != nil || body.System.DiskTotalBytes != nil ||
		body.System.DiskUsedBytes != nil || body.System.NetRxBytes != nil || body.System.NetTxBytes != nil {
		t.Fatalf("system = %+v", body.System)
	}
	if !counterEpochPattern.MatchString(body.CounterEpoch) {
		t.Fatalf("counter_epoch = %q", body.CounterEpoch)
	}
}

// TestSnapshotSelectionOnlyAuthorization proves selection and active connections
// are independently authorized: with `terminal` only, selection is sampled and
// active_connections is honest unavailable.
func TestSnapshotSelectionOnlyAuthorization(t *testing.T) {
	rc := testReportContext(t, testSources(true, false))
	mock := &mockObserver{
		selection: observedSelection(windowsobs.BHY2, rc.CollectedAt-1),
		active:    observedActive(fullCounts(map[windowsobs.Role]int{windowsobs.BHY2: 9}), 0, rc.CollectedAt+1),
	}
	collector := newCollector(t, mock)
	raw, err := collector.Snapshot(context.Background(), rc)
	if err != nil {
		t.Fatal(err)
	}
	requireContractSnapshot(t, raw, true)

	if selectionCalls, activeCalls := mock.calls(); selectionCalls != 1 || activeCalls != 0 {
		t.Fatalf("source sampling calls selection=%d active=%d", selectionCalls, activeCalls)
	}
	body := decodeSnapshot(t, raw)
	if body.Terminal == nil {
		t.Fatal("terminal object missing for an authorized source")
	}
	selection := body.Terminal.Selection
	if selection.Availability != "ok" || selection.Route == nil || *selection.Route != "b_hy2" ||
		selection.ReasonCode != nil || selection.SampledAt != rc.CollectedAt-1 {
		t.Fatalf("selection = %+v", selection)
	}
	active := body.Terminal.ActiveConnections
	if active.Availability != "unavailable" || active.Total != nil || len(active.ByRoute) != 6 {
		t.Fatalf("active = %+v", active)
	}
	for token, count := range active.ByRoute {
		if count != nil {
			t.Fatalf("unauthorized active route %q has non-null count", token)
		}
	}
}

// TestSnapshotActiveOnlyAuthorization is the inverse independence case
// (terminal=false, mihomo_api=true): selection must be honest unavailable with
// source_authorization_unproven while active connections are sampled.
func TestSnapshotActiveOnlyAuthorization(t *testing.T) {
	rc := testReportContext(t, testSources(false, true))
	mock := &mockObserver{
		selection: observedSelection(windowsobs.AReality, rc.CollectedAt-1),
		active: observedActive(fullCounts(map[windowsobs.Role]int{
			windowsobs.AReality: 2, windowsobs.Direct: 1,
		}), 3, rc.CollectedAt+2),
	}
	collector := newCollector(t, mock)
	raw, err := collector.Snapshot(context.Background(), rc)
	if err != nil {
		t.Fatal(err)
	}
	requireContractSnapshot(t, raw, true)

	if selectionCalls, activeCalls := mock.calls(); selectionCalls != 0 || activeCalls != 1 {
		t.Fatalf("source sampling calls selection=%d active=%d", selectionCalls, activeCalls)
	}
	terminal := decodeSnapshot(t, raw).Terminal
	selection := terminal.Selection
	if selection.Availability != "unavailable" || selection.Route != nil ||
		selection.ReasonCode == nil || *selection.ReasonCode != reasonSourceAuthorizationUnproven {
		t.Fatalf("selection = %+v", selection)
	}
	active := terminal.ActiveConnections
	if active.Availability != "ok" || active.Total == nil || *active.Total != 6 || active.SampledAt != rc.CollectedAt+2 {
		t.Fatalf("active = %+v", active)
	}
}

// TestSnapshotBothSourcesIndependentSampling proves the two sources keep
// separate timestamps and separate availability even when both are authorized.
func TestSnapshotBothSourcesIndependentSampling(t *testing.T) {
	rc := testReportContext(t, testSources(true, true))
	selectionAt := rc.CollectedAt - 4
	activeAt := rc.CollectedAt + 2
	mock := &mockObserver{
		selection: observedSelection(windowsobs.AHY2, selectionAt),
		active: observedActive(fullCounts(map[windowsobs.Role]int{
			windowsobs.AReality: 20, windowsobs.AHY2: 5, windowsobs.BReality: 10,
			windowsobs.BHY2: 2, windowsobs.Direct: 3,
		}), 2, activeAt),
	}
	collector := newCollector(t, mock)
	raw, err := collector.Snapshot(context.Background(), rc)
	if err != nil {
		t.Fatal(err)
	}
	requireContractSnapshot(t, raw, true)

	terminal := decodeSnapshot(t, raw).Terminal
	if terminal.Selection.SampledAt != selectionAt || terminal.ActiveConnections.SampledAt != activeAt {
		t.Fatalf("independent timestamps = %d / %d", terminal.Selection.SampledAt, terminal.ActiveConnections.SampledAt)
	}
	active := terminal.ActiveConnections
	if active.Availability != "ok" || active.Total == nil || *active.Total != 42 {
		t.Fatalf("total = %+v", active.Total)
	}
	var sum int64
	for _, token := range windowsobs.Tokens() {
		count, ok := active.ByRoute[string(token)]
		if !ok || count == nil {
			t.Fatalf("by_route token %q missing or null", token)
		}
		sum += *count
	}
	if sum != *active.Total || len(active.ByRoute) != 6 {
		t.Fatalf("sum=%d total=%d keys=%d", sum, *active.Total, len(active.ByRoute))
	}
}

// TestSnapshotUnmappedRouteIsUnknownNotDirect is the NEG-PLAT-08 guard at the
// collector layer: an unresolvable selection maps to the frozen unknown token
// (partial), and unmapped connections count as unknown, never direct.
func TestSnapshotUnmappedRouteIsUnknownNotDirect(t *testing.T) {
	rc := testReportContext(t, testSources(true, true))
	mock := &mockObserver{
		selection: windowsobs.Selection{
			State: windowsobs.StateUnknown, Reason: windowsobs.ReasonRouteUnbound, SampledAt: rc.CollectedAt - 2,
		},
		active: observedActive(fullCounts(map[windowsobs.Role]int{windowsobs.AReality: 1}), 2, rc.CollectedAt+1),
	}
	collector := newCollector(t, mock)
	raw, err := collector.Snapshot(context.Background(), rc)
	if err != nil {
		t.Fatal(err)
	}
	requireContractSnapshot(t, raw, true)

	terminal := decodeSnapshot(t, raw).Terminal
	selection := terminal.Selection
	if selection.Availability != "partial" || selection.Route == nil ||
		*selection.Route != string(windowsobs.UnknownRoute) || selection.ReasonCode != nil {
		t.Fatalf("selection = %+v", selection)
	}
	direct := terminal.ActiveConnections.ByRoute["direct"]
	unknown := terminal.ActiveConnections.ByRoute["unknown"]
	if direct == nil || *direct != 0 || unknown == nil || *unknown != 2 {
		t.Fatalf("direct=%v unknown=%v", direct, unknown)
	}
}

// TestSnapshotObserverFailureMapping maps injected observer states onto the
// frozen availability/reason_code vocabulary and sanitizes anything outside it.
func TestSnapshotObserverFailureMapping(t *testing.T) {
	const freeForm = "password: hunter2"
	tests := []struct {
		name           string
		selection      windowsobs.Selection
		wantAvail      string
		wantRoute      string
		wantReason     string
		forbiddenValue string
	}{
		{
			name: "controller auth",
			selection: windowsobs.Selection{
				State: windowsobs.StateUnavailable, Reason: windowsobs.ReasonControllerAuth, SampledAt: 0,
			},
			wantAvail: "unavailable", wantReason: reasonControllerAuth,
		},
		{
			name: "controller unreachable",
			selection: windowsobs.Selection{
				State: windowsobs.StateUnavailable, Reason: windowsobs.ReasonControllerUnreachable, SampledAt: 0,
			},
			wantAvail: "unavailable", wantReason: reasonControllerUnreachable,
		},
		{
			name: "malformed",
			selection: windowsobs.Selection{
				State: windowsobs.StateUnknown, Reason: windowsobs.ReasonMalformedResponse, SampledAt: 0,
			},
			wantAvail: "unavailable", wantReason: reasonMalformedResponse,
		},
		{
			name: "unknown token role",
			selection: windowsobs.Selection{
				State: windowsobs.StateObserved, Role: windowsobs.UnknownRoute, SampledAt: 0,
			},
			wantAvail: "partial", wantRoute: string(windowsobs.UnknownRoute),
		},
		{
			name: "free-form role is sanitized",
			selection: windowsobs.Selection{
				State: windowsobs.StateObserved, Role: windowsobs.Role(freeForm), SampledAt: 0,
			},
			wantAvail: "partial", wantRoute: string(windowsobs.UnknownRoute), forbiddenValue: freeForm,
		},
		{
			name: "free-form reason is sanitized",
			selection: windowsobs.Selection{
				State: windowsobs.StateUnavailable, Reason: freeForm, SampledAt: 0,
			},
			wantAvail: "unavailable", wantReason: reasonMalformedResponse, forbiddenValue: freeForm,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			collector := newCollector(t, &mockObserver{
				selection: tc.selection,
				active:    observedActive(fullCounts(nil), 0, 0),
			})
			raw, err := collector.Snapshot(context.Background(), testReportContext(t, testSources(true, false)))
			if err != nil {
				t.Fatal(err)
			}
			requireContractSnapshot(t, raw, true)
			if tc.forbiddenValue != "" {
				requireNoPrivacySentinels(t, raw, []string{tc.forbiddenValue})
			}
			selection := decodeSnapshot(t, raw).Terminal.Selection
			if selection.Availability != tc.wantAvail {
				t.Fatalf("availability = %q, want %q", selection.Availability, tc.wantAvail)
			}
			if tc.wantRoute == "" {
				if selection.Route != nil {
					t.Fatalf("route = %q, want null", *selection.Route)
				}
			} else if selection.Route == nil || *selection.Route != tc.wantRoute {
				t.Fatalf("route = %v, want %q", selection.Route, tc.wantRoute)
			}
			if tc.wantReason == "" {
				if selection.ReasonCode != nil {
					t.Fatalf("reason_code = %q, want null", *selection.ReasonCode)
				}
			} else if selection.ReasonCode == nil || *selection.ReasonCode != tc.wantReason {
				t.Fatalf("reason_code = %v, want %q", selection.ReasonCode, tc.wantReason)
			}
		})
	}
}

// TestSnapshotActiveSanitization proves an observed aggregate with impossible
// values is degraded to honest unavailable instead of being clipped/fabricated.
func TestSnapshotActiveSanitization(t *testing.T) {
	badActive := []windowsobs.Active{
		{State: windowsobs.StateObserved, Counts: fullCounts(map[windowsobs.Role]int{windowsobs.AReality: -1}), Unknown: intPtr(0)},
		{State: windowsobs.StateObserved, Counts: fullCounts(nil), Unknown: nil},
		{State: windowsobs.StateObserved, Counts: fullCounts(nil), Unknown: intPtr(-1)},
		{State: windowsobs.StateUnavailable, Reason: windowsobs.ReasonControllerUnreachable},
	}
	for index, active := range badActive {
		collector := newCollector(t, &mockObserver{
			selection: observedSelection(windowsobs.AReality, 0),
			active:    active,
		})
		raw, err := collector.Snapshot(context.Background(), testReportContext(t, testSources(true, true)))
		if err != nil {
			t.Fatalf("case %d: %v", index, err)
		}
		requireContractSnapshot(t, raw, true)
		connections := decodeSnapshot(t, raw).Terminal.ActiveConnections
		if connections.Availability != "unavailable" || connections.Total != nil {
			t.Fatalf("case %d active = %+v", index, connections)
		}
		for _, count := range connections.ByRoute {
			if count != nil {
				t.Fatalf("case %d has non-null route count", index)
			}
		}
	}
}

// TestSnapshotNoObserverAuthorized proves an authorized-but-not-locally-configured
// source reports honest unavailable/authorization-unproven instead of
// fabricating data (P1-10).
func TestSnapshotNoObserverAuthorized(t *testing.T) {
	collector := newCollector(t, nil)
	raw, err := collector.Snapshot(context.Background(), testReportContext(t, testSources(true, true)))
	if err != nil {
		t.Fatal(err)
	}
	requireContractSnapshot(t, raw, true)
	terminal := decodeSnapshot(t, raw).Terminal
	if terminal == nil {
		t.Fatal("terminal object missing for an authorized source")
	}
	if terminal.Selection.Availability != "unavailable" || terminal.Selection.Route != nil ||
		terminal.Selection.ReasonCode == nil || *terminal.Selection.ReasonCode != reasonSourceAuthorizationUnproven {
		t.Fatalf("selection = %+v", terminal.Selection)
	}
	if terminal.ActiveConnections.Availability != "unavailable" || terminal.ActiveConnections.Total != nil {
		t.Fatalf("active = %+v", terminal.ActiveConnections)
	}
}

// TestSnapshotSampledAtFallback proves a missing observer timestamp falls back to
// the report collection time and stays inside the frozen sampling window.
func TestSnapshotSampledAtFallback(t *testing.T) {
	collector := newCollector(t, &mockObserver{
		selection: observedSelection(windowsobs.BReality, 0),
		active:    observedActive(fullCounts(nil), 0, 0),
	})
	rc := testReportContext(t, testSources(true, true))
	raw, err := collector.Snapshot(context.Background(), rc)
	if err != nil {
		t.Fatal(err)
	}
	requireContractSnapshot(t, raw, true)
	terminal := decodeSnapshot(t, raw).Terminal
	if terminal.Selection.SampledAt != rc.CollectedAt || terminal.ActiveConnections.SampledAt != rc.CollectedAt {
		t.Fatalf("sampled_at fallback = %d / %d, want %d",
			terminal.Selection.SampledAt, terminal.ActiveConnections.SampledAt, rc.CollectedAt)
	}
}

// TestSnapshotInvalidReportContext proves invalid host/report identity input is
// rejected instead of producing a non-contract body.
func TestSnapshotInvalidReportContext(t *testing.T) {
	collector := newCollector(t, nil)
	tests := []func(*agent.ReportContext){
		func(rc *agent.ReportContext) { rc.ReportID = "" },
		func(rc *agent.ReportContext) { rc.ReportID = "not-a-uuid" },
		func(rc *agent.ReportContext) { rc.ReportID = strings.ToUpper(rc.ReportID) },
		func(rc *agent.ReportContext) { rc.CollectedAt = -1 },
		func(rc *agent.ReportContext) { rc.CollectedAt = maxCollectedAt + 1 },
		func(rc *agent.ReportContext) { rc.Host.OS = "linux" },
		func(rc *agent.ReportContext) { rc.Host.Kernel = "not a kernel" },
		func(rc *agent.ReportContext) { rc.Host.Arch = "386" },
	}
	for index, mutate := range tests {
		rc := testReportContext(t, testSources(false, false))
		mutate(&rc)
		if _, err := collector.Snapshot(context.Background(), rc); !errors.Is(err, ErrInvalidReportContext) {
			t.Fatalf("case %d error = %v", index, err)
		}
	}
}

// TestMetricsUnsupported pins the deferred Windows metrics v1 contract.
func TestMetricsUnsupported(t *testing.T) {
	collector := newCollector(t, nil)
	if _, err := collector.Metrics(context.Background(), testReportContext(t, testSources(true, true))); !errors.Is(err, agent.ErrUnsupported) {
		t.Fatalf("metrics error = %v", err)
	}
}

// TestEventsContract covers the generic events body, the authorized terminal
// source fault event and the no-terminal-kind rule when the source is not
// authorized.
func TestEventsContract(t *testing.T) {
	t.Run("authorized source without local observer", func(t *testing.T) {
		collector := newCollector(t, nil)
		rc := testReportContext(t, testSources(true, true))
		raw, err := collector.Events(context.Background(), rc)
		if err != nil {
			t.Fatal(err)
		}
		requireContractEvents(t, raw)
		body := decodeEvents(t, raw)
		if body.Type != "events" || body.ReportID != rc.ReportID || body.CollectedAt != rc.CollectedAt {
			t.Fatalf("identity = %+v", body)
		}
		if len(body.Events) != 2 {
			t.Fatalf("events = %+v", body.Events)
		}
		started, unavailable := body.Events[0], body.Events[1]
		if started.Kind != "agent_started" || started.Severity != "info" {
			t.Fatalf("started = %+v", started)
		}
		detail, ok := started.Detail.(map[string]any)
		if !ok || detail["agent_version"] != "1.4.0" {
			t.Fatalf("started detail = %#v", started.Detail)
		}
		if unavailable.Kind != "terminal_source_unavailable" || unavailable.Severity != "warning" {
			t.Fatalf("unavailable = %+v", unavailable)
		}
		detail, ok = unavailable.Detail.(map[string]any)
		if !ok || detail["source"] != sourceMihomoAPI ||
			detail["reason_code"] != reasonSourceAuthorizationUnproven {
			t.Fatalf("unavailable detail = %#v", unavailable.Detail)
		}
		for index, event := range body.Events {
			if !uuidV4Pattern.MatchString(event.EventID) {
				t.Fatalf("event %d id = %q", index, event.EventID)
			}
			if event.At != rc.CollectedAt {
				t.Fatalf("event %d at = %d", index, event.At)
			}
		}
		requireNoPrivacySentinels(t, raw, []string{rc.Config.DeviceSalt})
	})

	t.Run("no source authorized", func(t *testing.T) {
		mock := &mockObserver{selection: observedSelection(windowsobs.AReality, 0)}
		collector := newCollector(t, mock)
		raw, err := collector.Events(context.Background(), testReportContext(t, testSources(false, false)))
		if err != nil {
			t.Fatal(err)
		}
		requireContractEvents(t, raw)
		body := decodeEvents(t, raw)
		if len(body.Events) != 1 || body.Events[0].Kind != "agent_started" {
			t.Fatalf("events = %+v", body.Events)
		}
	})

	t.Run("active-connections source only without observer", func(t *testing.T) {
		collector := newCollector(t, nil)
		raw, err := collector.Events(context.Background(), testReportContext(t, testSources(false, true)))
		if err != nil {
			t.Fatal(err)
		}
		requireContractEvents(t, raw)
		body := decodeEvents(t, raw)
		if len(body.Events) != 2 || body.Events[1].Kind != "agent_error" {
			t.Fatalf("events = %+v", body.Events)
		}
		detail, ok := body.Events[1].Detail.(map[string]any)
		if !ok || detail["code"] != reasonSourceAuthorizationUnproven {
			t.Fatalf("active-only agent_error detail = %#v", body.Events[1].Detail)
		}
	})

	t.Run("authorized source with observer", func(t *testing.T) {
		collector := newCollector(t, &mockObserver{})
		raw, err := collector.Events(context.Background(), testReportContext(t, testSources(true, true)))
		if err != nil {
			t.Fatal(err)
		}
		requireContractEvents(t, raw)
		body := decodeEvents(t, raw)
		if len(body.Events) != 1 || body.Events[0].Kind != "agent_started" {
			t.Fatalf("events = %+v", body.Events)
		}
	})

	t.Run("invalid report context", func(t *testing.T) {
		collector := newCollector(t, nil)
		rc := testReportContext(t, testSources(true, true))
		rc.ReportID = "bad"
		if _, err := collector.Events(context.Background(), rc); !errors.Is(err, ErrInvalidReportContext) {
			t.Fatalf("events error = %v", err)
		}
	})
}

// TestCounterEpoch covers the explicit epoch, the stable opaque derivation from
// the centre-issued device salt and the no-leak rule for the salt itself.
func TestCounterEpoch(t *testing.T) {
	rc := testReportContext(t, testSources(false, false))
	explicit, err := New(Options{CounterEpoch: "0123456789abcdef0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := explicit.Snapshot(context.Background(), rc)
	if err != nil {
		t.Fatal(err)
	}
	if body := decodeSnapshot(t, raw); body.CounterEpoch != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("explicit counter epoch = %q", body.CounterEpoch)
	}

	collector := newCollector(t, nil)
	first, err := collector.Snapshot(context.Background(), rc)
	if err != nil {
		t.Fatal(err)
	}
	second, err := collector.Snapshot(context.Background(), rc)
	if err != nil {
		t.Fatal(err)
	}
	firstBody, secondBody := decodeSnapshot(t, first), decodeSnapshot(t, second)
	if firstBody.CounterEpoch != secondBody.CounterEpoch {
		t.Fatalf("derived counter epoch is not stable: %q vs %q", firstBody.CounterEpoch, secondBody.CounterEpoch)
	}
	if !counterEpochPattern.MatchString(firstBody.CounterEpoch) {
		t.Fatalf("derived counter epoch = %q", firstBody.CounterEpoch)
	}
	requireNoPrivacySentinels(t, first, []string{rc.Config.DeviceSalt})

	otherSalt := rc
	otherSalt.Config.DeviceSalt = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	other, err := collector.Snapshot(context.Background(), otherSalt)
	if err != nil {
		t.Fatal(err)
	}
	if decodeSnapshot(t, other).CounterEpoch == firstBody.CounterEpoch {
		t.Fatal("counter epoch did not change with the device salt")
	}
}

// TestUptimeBounds proves the uptime projection stays in the frozen integer
// bounds instead of producing an invalid body.
func TestUptimeBounds(t *testing.T) {
	tests := []struct {
		name  string
		value int64
		want  int64
	}{
		{"negative is clamped", -10, 0},
		{"normal", 7200, 7200},
		{"too large is clamped", maxUptimeSeconds + 5, maxUptimeSeconds},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			collector, err := New(Options{Uptime: func() int64 { return tc.value }})
			if err != nil {
				t.Fatal(err)
			}
			raw, err := collector.Snapshot(context.Background(), testReportContext(t, testSources(false, false)))
			if err != nil {
				t.Fatal(err)
			}
			requireContractSnapshot(t, raw, false)
			if body := decodeSnapshot(t, raw); body.Agent.UptimeS != tc.want {
				t.Fatalf("uptime = %d, want %d", body.Agent.UptimeS, tc.want)
			}
		})
	}
}

// TestSnapshotSixTokenShapeForEveryAvailability proves every active_connections
// object (ok or unavailable) always carries exactly the six frozen tokens.
func TestSnapshotSixTokenShapeForEveryAvailability(t *testing.T) {
	cases := []struct {
		name  string
		state windowsobs.Active
	}{
		{
			name:  "observed",
			state: observedActive(fullCounts(map[windowsobs.Role]int{windowsobs.Direct: 1}), 2, 0),
		},
		{
			name:  "unavailable",
			state: windowsobs.Active{State: windowsobs.StateUnavailable, Reason: windowsobs.ReasonControllerUnreachable},
		},
		{
			name:  "malformed",
			state: windowsobs.Active{State: windowsobs.StateUnknown, Reason: windowsobs.ReasonMalformedResponse},
		},
	}
	want := make(map[string]bool, 6)
	for _, token := range windowsobs.Tokens() {
		want[string(token)] = true
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			collector := newCollector(t, &mockObserver{
				selection: observedSelection(windowsobs.AReality, 0),
				active:    tc.state,
			})
			raw, err := collector.Snapshot(context.Background(), testReportContext(t, testSources(false, true)))
			if err != nil {
				t.Fatal(err)
			}
			requireContractSnapshot(t, raw, true)
			connections := decodeSnapshot(t, raw).Terminal.ActiveConnections
			got := make(map[string]bool, len(connections.ByRoute))
			for token := range connections.ByRoute {
				got[token] = true
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("by_route keys = %v, want %v", got, want)
			}
		})
	}
}

// TestSnapshotDirectBindingEndToEnd is a MOCK-UNIT test: a real *windowsobs
// observer talks to an httptest Mihomo-shaped server and the collector projects
// the six tokens. It proves direct appears only with an explicit operator-local
// binding, and that no local name/target/secret leaks.
func TestSnapshotDirectBindingEndToEnd(t *testing.T) {
	const (
		secret     = "mock-controller-secret-never-uploaded"
		group      = "EVENT"
		directLeaf = "local-direct-leaf"
		aLeaf      = "local-a-leaf"
	)
	var (
		requestedMu sync.Mutex
		requested   []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		requestedMu.Lock()
		requested = append(requested, r.URL.Path)
		requestedMu.Unlock()
		switch r.URL.Path {
		case "/proxies":
			_, _ = w.Write([]byte(`{"proxies":{
				"` + group + `":{"now":"` + directLeaf + `","all":["` + directLeaf + `","` + aLeaf + `"]},
				"` + directLeaf + `":{"type":"Direct"},
				"` + aLeaf + `":{"type":"Vless"}
			}}`))
		case "/connections":
			_, _ = w.Write([]byte(`{"connections":[
				{"chains":["` + directLeaf + `","` + group + `"],"metadata":{"destination":"10.9.8.7:443","host":"private.example"},"id":"conn-id-sentinel"},
				{"chains":["` + aLeaf + `","` + group + `"]}
			]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	t.Run("explicit binding", func(t *testing.T) {
		observer, err := windowsobs.New(windowsobs.Profile{
			Controller: server.URL,
			Group:      group,
			Routes: map[windowsobs.Role]string{
				windowsobs.Direct:   directLeaf,
				windowsobs.AReality: aLeaf,
			},
		}, secret)
		if err != nil {
			t.Fatal(err)
		}
		collector := newCollector(t, observer)
		raw, err := collector.Snapshot(context.Background(), testReportContext(t, testSources(true, true)))
		if err != nil {
			t.Fatal(err)
		}
		requireContractSnapshot(t, raw, true)
		requireNoPrivacySentinels(t, raw, []string{
			secret, group, directLeaf, aLeaf, "10.9.8.7", "private.example", "conn-id-sentinel",
		})
		terminal := decodeSnapshot(t, raw).Terminal
		if terminal.Selection.Route == nil || *terminal.Selection.Route != "direct" {
			t.Fatalf("selection = %+v", terminal.Selection)
		}
		direct := terminal.ActiveConnections.ByRoute["direct"]
		aReality := terminal.ActiveConnections.ByRoute["a_reality"]
		if direct == nil || *direct != 1 || aReality == nil || *aReality != 1 {
			t.Fatalf("direct=%v a_reality=%v", direct, aReality)
		}
	})

	t.Run("no direct binding means unknown", func(t *testing.T) {
		observer, err := windowsobs.New(windowsobs.Profile{
			Controller: server.URL,
			Group:      group,
			Routes:     map[windowsobs.Role]string{windowsobs.AReality: aLeaf},
		}, secret)
		if err != nil {
			t.Fatal(err)
		}
		collector := newCollector(t, observer)
		raw, err := collector.Snapshot(context.Background(), testReportContext(t, testSources(true, true)))
		if err != nil {
			t.Fatal(err)
		}
		requireContractSnapshot(t, raw, true)
		requireNoPrivacySentinels(t, raw, []string{secret, group, directLeaf, aLeaf})
		terminal := decodeSnapshot(t, raw).Terminal
		if terminal.Selection.Route == nil || *terminal.Selection.Route != "unknown" {
			t.Fatalf("selection = %+v", terminal.Selection)
		}
		direct := terminal.ActiveConnections.ByRoute["direct"]
		unknown := terminal.ActiveConnections.ByRoute["unknown"]
		if direct == nil || *direct != 0 || unknown == nil || *unknown != 1 {
			t.Fatalf("direct=%v unknown=%v", direct, unknown)
		}
	})

	requestedMu.Lock()
	requestedPaths := append([]string(nil), requested...)
	requestedMu.Unlock()
	if len(requestedPaths) == 0 {
		t.Fatal("mock controller was never exercised")
	}
	for _, path := range requestedPaths {
		if path != "/proxies" && path != "/connections" {
			t.Fatalf("observer issued an unexpected controller request path %q", path)
		}
	}
}

// TestSnapshotFreeFormObserverValuesNeverLeak proves a hostile/future observer
// implementation cannot smuggle raw local values into the report body.
func TestSnapshotFreeFormObserverValuesNeverLeak(t *testing.T) {
	const sentinel = "vps-a-reality.internal.example-10.1.2.3"
	collector := newCollector(t, &mockObserver{
		selection: windowsobs.Selection{State: windowsobs.StateObserved, Role: windowsobs.Role(sentinel), SampledAt: 0},
		active: windowsobs.Active{
			State: windowsobs.StateObserved,
			Counts: map[windowsobs.Role]int{
				windowsobs.Role(sentinel): 5,
				windowsobs.AReality:       1,
			},
			Unknown: intPtr(0), SampledAt: 0,
		},
	})
	raw, err := collector.Snapshot(context.Background(), testReportContext(t, testSources(true, true)))
	if err != nil {
		t.Fatal(err)
	}
	requireContractSnapshot(t, raw, true)
	requireNoPrivacySentinels(t, raw, []string{sentinel, "10.1.2.3"})
}

func intPtr(value int) *int { return &value }

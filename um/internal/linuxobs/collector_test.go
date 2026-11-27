package linuxobs

import (
	"context"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/agent"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/schema"
)

func float64Ptr(value float64) *float64 { return &value }
func int64Ptr(value int64) *int64       { return &value }

func requireInt64Ptr(t *testing.T, label string, got *int64, want int64) {
	t.Helper()
	if got == nil {
		t.Fatalf("%s is null, want %d", label, want)
	}
	if *got != want {
		t.Fatalf("%s = %d, want %d", label, *got, want)
	}
}

func requireFloat64Ptr(t *testing.T, label string, got *float64, want float64) {
	t.Helper()
	if got == nil {
		t.Fatalf("%s is null, want %v", label, want)
	}
	if math.Abs(*got-want) > 1e-9 {
		t.Fatalf("%s = %v, want %v", label, *got, want)
	}
}

// TestSnapshotContractValidAndHonestProjection is the synthetic-fixture happy
// path: contract-valid snapshot, exact numeric projection and no terminal
// object (forbidden for linux_vps).
func TestSnapshotContractValidAndHonestProjection(t *testing.T) {
	arch := requireSupportedArch(t)
	collector, _, _, _ := newFakeCollector(t)
	raw, err := collector.Snapshot(context.Background(),
		reportContext([]string{"system", "services", "singbox_api", "events"}, testExpectedTags()))
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	validateSnapshotBody(t, raw)

	body := unmarshalSnapshot(t, raw)
	if body.V != 1 || body.Type != reportTypeSnapshot ||
		body.ReportID != testReportID || body.CollectedAt != testCollectedAt {
		t.Fatalf("envelope = %+v", body)
	}
	if body.Agent.Version != "1.2.3" || body.Agent.UptimeS != 9995 {
		t.Fatalf("agent = %+v", body.Agent)
	}
	if body.Host != (hostInfo{OS: "linux", Kernel: testKernel, Arch: arch}) {
		t.Fatalf("host = %+v", body.Host)
	}
	wantAvailability := availabilityInfo{
		System:    availabilityOK,
		Services:  availabilityOK,
		Protocols: availabilityPartial,
		Traffic:   availabilityUnavailable,
		Clients:   availabilityUnavailable,
	}
	if body.Availability != wantAvailability {
		t.Fatalf("availability = %+v, want %+v", body.Availability, wantAvailability)
	}
	if body.CounterEpoch != testCounterEpoch {
		t.Fatalf("counter_epoch = %q, want %q", body.CounterEpoch, testCounterEpoch)
	}

	// CPU: 11000 total jiffies, 9000 idle+iowait => 18.181...%.
	requireFloat64Ptr(t, "system.cpu_pct", body.System.CPUPercent, 2000.0/11000.0*100)
	requireFloat64Ptr(t, "system.load1", body.System.Load1, 0.42)
	requireInt64Ptr(t, "system.mem_total_bytes", body.System.MemTotalBytes, 4294967296)
	requireInt64Ptr(t, "system.mem_used_bytes", body.System.MemUsedBytes, 2147483648)
	requireInt64Ptr(t, "system.disk_total_bytes", body.System.DiskTotalBytes, 42949672960)
	requireInt64Ptr(t, "system.disk_used_bytes", body.System.DiskUsedBytes, 10737418240)
	requireInt64Ptr(t, "system.net_rx_bytes", body.System.NetRxBytes, 123456789)
	requireInt64Ptr(t, "system.net_tx_bytes", body.System.NetTxBytes, 987654321)

	wantServices := []serviceEntry{{Name: "sing-box", State: "active"}}
	if !reflect.DeepEqual(body.Services, wantServices) {
		t.Fatalf("services = %+v, want %+v", body.Services, wantServices)
	}
	wantProtocols := []protocolEntry{
		{Kind: "reality", InboundTag: "vless-in", State: "up", Reason: "ok", ObservedAt: testCollectedAt},
		{Kind: "hysteria2", InboundTag: "hy2-in", State: "unknown", Reason: "unknown", ObservedAt: testCollectedAt},
	}
	if !reflect.DeepEqual(body.Protocols, wantProtocols) {
		t.Fatalf("protocols = %+v, want %+v", body.Protocols, wantProtocols)
	}
	wantTraffic := []trafficEntry{}
	if !reflect.DeepEqual(body.Traffic, wantTraffic) {
		t.Fatalf("traffic = %+v, want %+v", body.Traffic, wantTraffic)
	}
	if body.Clients.Active != nil || body.Clients.Tracked != nil || len(body.Clients.Summaries) != 0 {
		t.Fatalf("clients = %+v, want null/null/empty", body.Clients)
	}
	if strings.Contains(string(raw), `"terminal"`) {
		t.Fatal("linux_vps snapshot must never carry a terminal object")
	}
	if strings.Contains(string(raw), `"summaries":null`) {
		t.Fatal("clients.summaries must be an empty array, not null")
	}
}

// TestMetricsContractValidAndSample verifies the one-sample metrics body, the
// minute-aligned at value and availability parity with the snapshot.
func TestMetricsContractValidAndSample(t *testing.T) {
	requireSupportedArch(t)
	collector, _, _, _ := newFakeCollector(t)
	rc := reportContext([]string{"system", "services", "singbox_api"}, testExpectedTags())

	snapshotRaw, err := collector.Snapshot(context.Background(), rc)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	metricsRaw, err := collector.Metrics(context.Background(), rc)
	if err != nil {
		t.Fatalf("Metrics: %v", err)
	}
	validateSnapshotBody(t, snapshotRaw)
	validateMetricsBody(t, metricsRaw)

	if got, want := decodeMetricsAvailability(t, metricsRaw), decodeSnapshotAvailability(t, snapshotRaw); got != want {
		t.Fatalf("metrics availability %+v does not match snapshot %+v", got, want)
	}
	body := unmarshalMetrics(t, metricsRaw)
	if body.V != 1 || body.Type != reportTypeMetrics || body.ReportID != testReportID {
		t.Fatalf("envelope = %+v", body)
	}
	if len(body.Samples) != 1 {
		t.Fatalf("samples = %d, want 1", len(body.Samples))
	}
	sample := body.Samples[0]
	if sample.At != testCollectedAt {
		t.Fatalf("sample.at = %d, want %d", sample.At, testCollectedAt)
	}
	requireFloat64Ptr(t, "sample.cpu_pct", sample.CPUPercent, 2000.0/11000.0*100)
	requireFloat64Ptr(t, "sample.load1", sample.Load1, 0.42)
	requireInt64Ptr(t, "sample.mem_used_bytes", sample.MemUsedBytes, 2147483648)
	requireInt64Ptr(t, "sample.disk_used_bytes", sample.DiskUsedBytes, 10737418240)
	requireInt64Ptr(t, "sample.net_rx_bytes_total", sample.NetRxBytesTotal, 123456789)
	requireInt64Ptr(t, "sample.net_tx_bytes_total", sample.NetTxBytesTotal, 987654321)
	requireInt64Ptr(t, "sample.active_connections", sample.ActiveConnections, 2)

	// A collected_at that is not minute-aligned must be floored to the minute
	// grid, not rounded up or copied verbatim.
	unaligned := rc
	unaligned.ReportID = "2b7e4c6a-9d1f-4a3b-8c5e-0d2f7a9b4c61"
	unaligned.CollectedAt = testCollectedAt + 17
	unalignedRaw, err := collector.Metrics(context.Background(), unaligned)
	if err != nil {
		t.Fatalf("Metrics (unaligned): %v", err)
	}
	validateMetricsBody(t, unalignedRaw)
	unalignedBody := unmarshalMetrics(t, unalignedRaw)
	if unalignedBody.Samples[0].At != testCollectedAt {
		t.Fatalf("unaligned sample.at = %d, want %d", unalignedBody.Samples[0].At, testCollectedAt)
	}
}

// TestEventsContractValidAgentStarted verifies the single closed agent_started
// event, deterministic retry identity and its freedom from paths/secrets.
func TestEventsContractValidAgentStarted(t *testing.T) {
	collector, _, _, _ := newFakeCollector(t)
	rc := reportContext([]string{"events"}, testExpectedTags())

	raw, err := collector.Events(context.Background(), rc)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	validateEventsBody(t, raw)
	body := unmarshalEvents(t, raw)
	if body.V != 1 || body.Type != reportTypeEvents ||
		body.ReportID != testReportID || body.CollectedAt != testCollectedAt {
		t.Fatalf("envelope = %+v", body)
	}
	if len(body.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(body.Events))
	}
	event := body.Events[0]
	if event.Kind != "agent_started" || event.Severity != "info" || event.At != testCollectedAt {
		t.Fatalf("event = %+v", event)
	}
	if detail, ok := event.Detail.(map[string]any); !ok || detail["agent_version"] != "1.2.3" {
		t.Fatalf("event detail = %+v", event.Detail)
	}
	if !reportIDPattern.MatchString(event.EventID) {
		t.Fatalf("event_id %q is not the frozen UUIDv4 shape", event.EventID)
	}

	// A spool retry of the same immutable report keeps one event identity; a
	// different report gets a different identity.
	retryRaw, err := collector.Events(context.Background(), rc)
	if err != nil {
		t.Fatalf("Events retry: %v", err)
	}
	if retry := unmarshalEvents(t, retryRaw); retry.Events[0].EventID != event.EventID {
		t.Fatalf("event id is not stable across retries: %q vs %q", retry.Events[0].EventID, event.EventID)
	}
	other := rc
	other.ReportID = "2b7e4c6a-9d1f-4a3b-8c5e-0d2f7a9b4c61"
	otherRaw, err := collector.Events(context.Background(), other)
	if err != nil {
		t.Fatalf("Events other: %v", err)
	}
	if otherEvent := unmarshalEvents(t, otherRaw).Events[0]; otherEvent.EventID == event.EventID {
		t.Fatal("different reports must not share an event id")
	}

	bodyText := string(raw)
	for _, forbidden := range []string{collector.ProcRoot, "/proc", "/sys", "/var/lib", "DeviceSalt", testDeviceSalt} {
		if forbidden != "" && strings.Contains(bodyText, forbidden) {
			t.Fatalf("events body leaked local path/config value %q", forbidden)
		}
	}
}

// TestSourceSwitchesFailClosed verifies every center source switch: disabled
// sources are unavailable/empty/null, probes are not consulted, and metrics
// availability matches the snapshot.
func TestSourceSwitchesFailClosed(t *testing.T) {
	requireSupportedArch(t)
	unavailable := availabilityInfo{
		System:    availabilityUnavailable,
		Services:  availabilityUnavailable,
		Protocols: availabilityUnavailable,
		Traffic:   availabilityUnavailable,
		Clients:   availabilityUnavailable,
	}
	cases := []struct {
		name             string
		enabled          []string
		want             availabilityInfo
		wantServiceCalls int
		wantSingBoxCalls int
	}{
		{
			name:    "no sources",
			enabled: nil,
			want:    unavailable,
		},
		{
			name:    "system only",
			enabled: []string{"system"},
			want: availabilityInfo{
				System: availabilityOK, Services: availabilityUnavailable,
				Protocols: availabilityUnavailable, Traffic: availabilityUnavailable,
				Clients: availabilityUnavailable,
			},
		},
		{
			name:    "services only",
			enabled: []string{"services"},
			want: availabilityInfo{
				System: availabilityUnavailable, Services: availabilityOK,
				Protocols: availabilityUnavailable, Traffic: availabilityUnavailable,
				Clients: availabilityUnavailable,
			},
			wantServiceCalls: 1,
		},
		{
			name:    "singbox only",
			enabled: []string{"singbox_api"},
			want: availabilityInfo{
				System: availabilityUnavailable, Services: availabilityUnavailable,
				Protocols: availabilityPartial, Traffic: availabilityUnavailable,
				Clients: availabilityUnavailable,
			},
			wantSingBoxCalls: 1,
		},
		{
			name:             "all linux sources",
			enabled:          []string{"system", "services", "singbox_api"},
			want:             availabilityInfo{System: availabilityOK, Services: availabilityOK, Protocols: availabilityPartial, Traffic: availabilityUnavailable, Clients: availabilityUnavailable},
			wantServiceCalls: 1,
			wantSingBoxCalls: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			collector, disk, service, singbox := newFakeCollector(t)
			rc := reportContext(tc.enabled, testExpectedTags())
			raw, err := collector.Snapshot(context.Background(), rc)
			if err != nil {
				t.Fatalf("Snapshot: %v", err)
			}
			validateSnapshotBody(t, raw)
			body := unmarshalSnapshot(t, raw)
			if body.Availability != tc.want {
				t.Fatalf("availability = %+v, want %+v", body.Availability, tc.want)
			}
			if service.calls != tc.wantServiceCalls {
				t.Fatalf("service probe calls = %d, want %d", service.calls, tc.wantServiceCalls)
			}
			if singbox.calls != tc.wantSingBoxCalls {
				t.Fatalf("singbox probe calls = %d, want %d", singbox.calls, tc.wantSingBoxCalls)
			}

			// Center source gating: a disabled source must be unavailable, not
			// fabricated. The disk probe is likewise not consulted when system is
			// disabled.
			enabled := map[string]bool{}
			for _, name := range tc.enabled {
				enabled[name] = true
			}
			if !enabled["system"] {
				if body.Availability.System != availabilityUnavailable {
					t.Fatalf("system availability = %q with the source disabled", body.Availability.System)
				}
				if disk.calls != 0 {
					t.Fatalf("disk probe consulted with system disabled: %d calls", disk.calls)
				}
				if body.System != (systemValues{}) {
					t.Fatalf("system fields are not all null with the source disabled: %+v", body.System)
				}
			}
			if !enabled["services"] && len(body.Services) != 0 {
				t.Fatalf("services array is not empty with the source disabled: %+v", body.Services)
			}
			if !enabled["singbox_api"] {
				if body.Availability.Protocols != availabilityUnavailable ||
					body.Availability.Traffic != availabilityUnavailable {
					t.Fatalf("protocols/traffic availability = %q/%q with the source disabled",
						body.Availability.Protocols, body.Availability.Traffic)
				}
				if len(body.Protocols) != 0 || len(body.Traffic) != 0 {
					t.Fatalf("protocols/traffic arrays are not empty with the source disabled")
				}
				if body.Availability.Clients != availabilityUnavailable {
					t.Fatalf("clients availability = %q, want unavailable", body.Availability.Clients)
				}
			}

			metricsRaw, err := collector.Metrics(context.Background(), rc)
			if err != nil {
				t.Fatalf("Metrics: %v", err)
			}
			validateMetricsBody(t, metricsRaw)
			if got := decodeMetricsAvailability(t, metricsRaw); got != tc.want {
				t.Fatalf("metrics availability = %+v, want %+v", got, tc.want)
			}
			sample := unmarshalMetrics(t, metricsRaw).Samples[0]
			if enabled["singbox_api"] {
				requireInt64Ptr(t, "metrics.active_connections", sample.ActiveConnections, 2)
			} else if sample.ActiveConnections != nil {
				t.Fatalf("active_connections = %d with singbox_api disabled", *sample.ActiveConnections)
			}
		})
	}
}

// TestDefaultProbesReportUnavailable proves the shipped defaults are honest:
// no D-Bus/systemctl path, no sing-box probe, and an unavailable disk probe
// leave every source unavailable while the bodies stay contract-valid.
func TestDefaultProbesReportUnavailable(t *testing.T) {
	requireSupportedArch(t)
	collector := &Collector{
		ProcRoot:     writeTree(t, map[string]string{}),
		SysRoot:      writeTree(t, map[string]string{}),
		AgentVersion: "1.0.0",
		DiskProbe:    &fakeDiskProbe{err: ErrProbeUnavailable},
	}
	rc := reportContext([]string{"system", "services", "singbox_api", "events"}, testExpectedTags())
	raw, err := collector.Snapshot(context.Background(), rc)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	validateSnapshotBody(t, raw)
	body := unmarshalSnapshot(t, raw)
	want := availabilityInfo{
		System:    availabilityUnavailable,
		Services:  availabilityUnavailable,
		Protocols: availabilityUnavailable,
		Traffic:   availabilityUnavailable,
		Clients:   availabilityUnavailable,
	}
	if body.Availability != want {
		t.Fatalf("availability = %+v, want all unavailable", body.Availability)
	}
	if body.System != (systemValues{}) {
		t.Fatalf("system fields are not all null: %+v", body.System)
	}
	if len(body.Services) != 0 || len(body.Protocols) != 0 || len(body.Traffic) != 0 {
		t.Fatalf("unavailable sources produced data: %+v %+v %+v", body.Services, body.Protocols, body.Traffic)
	}
	if body.CounterEpoch != zeroCounterEpoch {
		t.Fatalf("counter_epoch = %q, want the documented all-zero epoch", body.CounterEpoch)
	}
	if body.Agent.UptimeS != 0 {
		t.Fatalf("agent uptime = %d without procfs evidence, want 0", body.Agent.UptimeS)
	}

	metricsRaw, err := collector.Metrics(context.Background(), rc)
	if err != nil {
		t.Fatalf("Metrics: %v", err)
	}
	validateMetricsBody(t, metricsRaw)
	sample := unmarshalMetrics(t, metricsRaw).Samples[0]
	if sample.CPUPercent != nil || sample.Load1 != nil || sample.MemUsedBytes != nil ||
		sample.DiskUsedBytes != nil || sample.NetRxBytesTotal != nil ||
		sample.NetTxBytesTotal != nil || sample.ActiveConnections != nil {
		t.Fatalf("unavailable sample carried fabricated values: %+v", sample)
	}

	eventsRaw, err := collector.Events(context.Background(), rc)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	validateEventsBody(t, eventsRaw)
}

// TestZeroValueCollectorProducesContractBodies exercises the documented
// default roots and probes on the real host. Values are environment-dependent;
// only contract validity and the disabled-source invariants are asserted.
func TestZeroValueCollectorProducesContractBodies(t *testing.T) {
	requireSupportedArch(t)
	collector := &Collector{}
	rc := reportContext([]string{"system", "services", "singbox_api", "events"}, nil)
	raw, err := collector.Snapshot(context.Background(), rc)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	validateSnapshotBody(t, raw)
	metricsRaw, err := collector.Metrics(context.Background(), rc)
	if err != nil {
		t.Fatalf("Metrics: %v", err)
	}
	validateMetricsBody(t, metricsRaw)
	eventsRaw, err := collector.Events(context.Background(), rc)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	validateEventsBody(t, eventsRaw)
}

// TestSnapshotReportsInvalidContext ensures malformed report contexts are
// rejected rather than wrapped into schema-invalid bodies.
func TestSnapshotReportsInvalidContext(t *testing.T) {
	collector, _, _, _ := newFakeCollector(t)
	cases := []struct {
		name   string
		mutate func(*agent.ReportContext)
	}{
		{"empty report id", func(rc *agent.ReportContext) { rc.ReportID = "" }},
		{"uppercase report id", func(rc *agent.ReportContext) { rc.ReportID = strings.ToUpper(testReportID) }},
		{"negative collected_at", func(rc *agent.ReportContext) { rc.CollectedAt = -1 }},
		{"collected_at above contract", func(rc *agent.ReportContext) { rc.CollectedAt = maxContractTimestamp + 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc := reportContext([]string{"events"}, nil)
			tc.mutate(&rc)
			ctx := context.Background()
			if _, err := collector.Snapshot(ctx, rc); err == nil {
				t.Fatal("Snapshot accepted an invalid report context")
			}
			if _, err := collector.Metrics(ctx, rc); err == nil {
				t.Fatal("Metrics accepted an invalid report context")
			}
			if _, err := collector.Events(ctx, rc); err == nil {
				t.Fatal("Events accepted an invalid report context")
			}
		})
	}
}

// TestHostResolution covers the kernel fallback, the frozen arch guard and the
// snapshot-only identity requirement.
func TestHostResolution(t *testing.T) {
	procWithKernel := writeTree(t, map[string]string{"sys/kernel/osrelease": "5.15.0-1-generic\n"})
	host, err := buildHostInfo(procWithKernel, "ignored", "amd64")
	if err != nil || host != (hostInfo{OS: "linux", Kernel: "5.15.0-1-generic", Arch: "amd64"}) {
		t.Fatalf("buildHostInfo = %+v, %v", host, err)
	}

	emptyRoot := writeTree(t, map[string]string{})
	host, err = buildHostInfo(emptyRoot, "4.19.0-fallback", "arm64")
	if err != nil || host != (hostInfo{OS: "linux", Kernel: "4.19.0-fallback", Arch: "arm64"}) {
		t.Fatalf("fallback buildHostInfo = %+v, %v", host, err)
	}

	if _, err := buildHostInfo(emptyRoot, "not a kernel!", "amd64"); err == nil {
		t.Fatal("buildHostInfo accepted an invalid fallback kernel")
	}
	if _, err := buildHostInfo(procWithKernel, "5.15.0-1", "386"); !errors.Is(err, agent.ErrUnsupported) {
		t.Fatalf("unsupported arch error = %v, want agent.ErrUnsupported", err)
	}

	collector := &Collector{
		ProcRoot:     emptyRoot,
		AgentVersion: "1.0.0",
		DiskProbe:    &fakeDiskProbe{err: ErrProbeUnavailable},
	}
	rc := reportContext([]string{"events"}, nil)
	rc.Host.Kernel = ""
	if _, err := collector.Snapshot(context.Background(), rc); err == nil {
		t.Fatal("Snapshot succeeded without a usable kernel release")
	}
	// Metrics carries no host object, so it must still be producible.
	metricsRaw, err := collector.Metrics(context.Background(), rc)
	if err != nil {
		t.Fatalf("Metrics: %v", err)
	}
	validateMetricsBody(t, metricsRaw)
}

// TestAgentVersionResolution covers the frozen version grammar and the
// BuildVersion fallback.
func TestAgentVersionResolution(t *testing.T) {
	cases := []struct {
		configured string
		want       string
		wantErr    bool
	}{
		{"", BuildVersion, false},
		{"1.2.3", "1.2.3", false},
		{"0.0.0-dev", "0.0.0-dev", false},
		{"1.2.3+build.5", "1.2.3+build.5", false},
		{"1.2", "", true},
		{"v1.2.3", "", true},
		{"1.2.3 extra", "", true},
		{strings.Repeat("1", 40), "", true},
	}
	for _, tc := range cases {
		collector := &Collector{AgentVersion: tc.configured}
		got, err := collector.agentVersionValue()
		if tc.wantErr {
			if err == nil {
				t.Fatalf("agentVersionValue(%q) accepted an invalid version", tc.configured)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("agentVersionValue(%q) = %q, %v; want %q", tc.configured, got, err, tc.want)
		}
	}
}

// TestCounterEpochResolution covers the override validation, the procfs boot
// id derivation and the documented all-zero fallback.
func TestCounterEpochResolution(t *testing.T) {
	collector := &Collector{ProcRoot: writeTree(t, fakeProcFiles())}
	epoch, err := collector.counterEpochValue()
	if err != nil || epoch != testCounterEpoch {
		t.Fatalf("counterEpochValue = %q, %v; want %q", epoch, err, testCounterEpoch)
	}

	override := &Collector{CounterEpoch: "aaaaaaaabbbbbbbbccccccccdddddddd"}
	epoch, err = override.counterEpochValue()
	if err != nil || epoch != "aaaaaaaabbbbbbbbccccccccdddddddd" {
		t.Fatalf("override counterEpochValue = %q, %v", epoch, err)
	}
	badOverride := &Collector{CounterEpoch: "NOT_HEX"}
	if _, err := badOverride.counterEpochValue(); err == nil {
		t.Fatal("invalid counter epoch override was accepted")
	}

	missing := &Collector{ProcRoot: writeTree(t, map[string]string{})}
	epoch, err = missing.counterEpochValue()
	if err != nil || epoch != zeroCounterEpoch {
		t.Fatalf("missing boot id counterEpochValue = %q, %v; want %q", epoch, err, zeroCounterEpoch)
	}
}

// TestAgentUptimeResolution covers the procfs derivation, the runtime-supplied
// start time and missing-evidence behavior.
func TestAgentUptimeResolution(t *testing.T) {
	collector := &Collector{ProcRoot: writeTree(t, fakeProcFiles())}
	rc := testReportContext()
	if got := collector.agentUptimeSeconds(rc); got != 9995 {
		t.Fatalf("procfs uptime = %d, want 9995", got)
	}

	started := &Collector{AgentStartedAt: time.Unix(testCollectedAt-3600, 0)}
	if got := started.agentUptimeSeconds(rc); got != 3600 {
		t.Fatalf("AgentStartedAt uptime = %d, want 3600", got)
	}
	future := &Collector{AgentStartedAt: time.Unix(testCollectedAt+100, 0)}
	if got := future.agentUptimeSeconds(rc); got != 0 {
		t.Fatalf("future start uptime = %d, want 0", got)
	}

	missing := &Collector{ProcRoot: writeTree(t, map[string]string{})}
	if got := missing.agentUptimeSeconds(rc); got != 0 {
		t.Fatalf("missing uptime evidence = %d, want 0", got)
	}
}

// TestInboundTagAuthorization ensures only validated, deduplicated expected
// tags can reach protocols/traffic; rogue observed tags and malformed expected
// tags are dropped.
func TestInboundTagAuthorization(t *testing.T) {
	requireSupportedArch(t)
	collector, _, _, singbox := newFakeCollector(t)
	singbox.observation.Inbounds["rogue-in"] = InboundEvidence{ActiveConnections: 9, UplinkBytes: 9, DownlinkBytes: 9}
	expected := []agent.InboundTag{
		{InboundTag: "vless-in", Kind: "reality"},
		{InboundTag: "vless-in", Kind: "other"},  // duplicate: first wins
		{InboundTag: "bad tag", Kind: "reality"}, // invalid tag grammar
		{InboundTag: "", Kind: "reality"},        // empty tag
		{InboundTag: "hy2-in", Kind: "ftp"},      // invalid kind
		{InboundTag: "unobserved-in", Kind: "other"},
	}
	raw, err := collector.Snapshot(context.Background(),
		reportContext([]string{"singbox_api"}, expected))
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	validateSnapshotBody(t, raw)
	body := unmarshalSnapshot(t, raw)
	wantProtocols := []protocolEntry{
		{Kind: "reality", InboundTag: "vless-in", State: "up", Reason: "ok", ObservedAt: testCollectedAt},
		{Kind: "other", InboundTag: "unobserved-in", State: "unknown", Reason: "unknown", ObservedAt: testCollectedAt},
	}
	if !reflect.DeepEqual(body.Protocols, wantProtocols) {
		t.Fatalf("protocols = %+v, want %+v", body.Protocols, wantProtocols)
	}
	wantTraffic := []trafficEntry{}
	if !reflect.DeepEqual(body.Traffic, wantTraffic) {
		t.Fatalf("traffic = %+v, want %+v", body.Traffic, wantTraffic)
	}
	if strings.Contains(string(raw), "rogue-in") {
		t.Fatal("an unauthorized observed tag leaked into the snapshot")
	}
}

// TestServiceProbeStates covers the frozen service-state vocabulary and the
// availability mapping.
func TestServiceProbeStates(t *testing.T) {
	requireSupportedArch(t)
	cases := []struct {
		name      string
		probe     *fakeServiceProbe
		wantState string
		wantAvail string
	}{
		{"active", &fakeServiceProbe{observation: ServiceObservation{SingBox: ServiceActive}}, "active", availabilityOK},
		{"inactive", &fakeServiceProbe{observation: ServiceObservation{SingBox: ServiceInactive}}, "inactive", availabilityOK},
		{"failed", &fakeServiceProbe{observation: ServiceObservation{SingBox: ServiceFailed}}, "failed", availabilityOK},
		{"unknown value", &fakeServiceProbe{observation: ServiceObservation{SingBox: "activating"}}, "unknown", availabilityPartial},
		{"unavailable", &fakeServiceProbe{err: ErrProbeUnavailable}, "", availabilityUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			collector, _, _, _ := newFakeCollector(t)
			collector.ServiceProbe = tc.probe
			raw, err := collector.Snapshot(context.Background(),
				reportContext([]string{"services"}, nil))
			if err != nil {
				t.Fatalf("Snapshot: %v", err)
			}
			validateSnapshotBody(t, raw)
			body := unmarshalSnapshot(t, raw)
			if body.Availability.Services != tc.wantAvail {
				t.Fatalf("services availability = %q, want %q", body.Availability.Services, tc.wantAvail)
			}
			if tc.wantState == "" {
				if len(body.Services) != 0 {
					t.Fatalf("services = %+v, want empty", body.Services)
				}
				return
			}
			if len(body.Services) != 1 || body.Services[0].Name != "sing-box" ||
				body.Services[0].State != tc.wantState {
				t.Fatalf("services = %+v, want sing-box/%s", body.Services, tc.wantState)
			}
		})
	}
}

// TestOutOfContractValuesBecomeNull ensures out-of-range observations are
// rendered null (partial), never clamped or fabricated.
func TestOutOfContractValuesBecomeNull(t *testing.T) {
	requireSupportedArch(t)
	files := fakeProcFiles()
	// 2 TiB MemTotal and one net counter above the frozen safe-integer cap.
	files["meminfo"] = "MemTotal:        2147483648 kB\nMemAvailable:    1073741824 kB\n"
	files["net/dev"] = "Inter-|   Receive |  Transmit\n" +
		" face |bytes ...\n" +
		"  eth0: 9007199254740992 0 0 0 0 0 0 0 123 0 0 0 0 0 0 0\n"
	collector := &Collector{
		ProcRoot:     writeTree(t, files),
		AgentVersion: "1.0.0",
		DiskProbe:    &fakeDiskProbe{total: 4 * 1024 * 1024 * 1024 * 1024, used: 1024},
	}
	raw, err := collector.Snapshot(context.Background(), reportContext([]string{"system"}, nil))
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	validateSnapshotBody(t, raw)
	body := unmarshalSnapshot(t, raw)
	if body.Availability.System != availabilityPartial {
		t.Fatalf("system availability = %q, want partial", body.Availability.System)
	}
	if body.System.MemTotalBytes != nil {
		t.Fatalf("out-of-contract memory total was reported: %v", *body.System.MemTotalBytes)
	}
	// MemAvailable still yields a used value that is inside the contract range;
	// it may be reported on its own (partial system availability).
	if body.System.MemUsedBytes != nil && *body.System.MemUsedBytes != maxContractSizeBytes {
		t.Fatalf("system.mem_used_bytes = %d, want %d", *body.System.MemUsedBytes, maxContractSizeBytes)
	}
	if body.System.DiskTotalBytes != nil || body.System.DiskUsedBytes != nil {
		t.Fatalf("out-of-contract disk was reported: %+v", body.System)
	}
	if body.System.NetRxBytes != nil {
		t.Fatalf("out-of-range net rx was reported: %v", *body.System.NetRxBytes)
	}
	requireInt64Ptr(t, "system.net_tx_bytes", body.System.NetTxBytes, 123)
	requireFloat64Ptr(t, "system.cpu_pct", body.System.CPUPercent, 2000.0/11000.0*100)

	// The metrics availability object is the same projection.
	metricsRaw, err := collector.Metrics(context.Background(), reportContext([]string{"system"}, nil))
	if err != nil {
		t.Fatalf("Metrics: %v", err)
	}
	validateMetricsBody(t, metricsRaw)
	if got := decodeMetricsAvailability(t, metricsRaw); got != body.Availability {
		t.Fatalf("metrics availability = %+v, want snapshot %+v", got, body.Availability)
	}
}

// TestWindowsOnlySourcesAreIgnoredOnLinux proves the Linux collector never
// emits Windows-only telemetry even if a malformed center config enables those
// switches: the terminal object stays absent and only Linux sources are read.
func TestWindowsOnlySourcesAreIgnoredOnLinux(t *testing.T) {
	requireSupportedArch(t)
	collector, _, service, singbox := newFakeCollector(t)
	raw, err := collector.Snapshot(context.Background(),
		reportContext([]string{"system", "terminal", "mihomo_api"}, nil))
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	validateSnapshotBody(t, raw)
	body := unmarshalSnapshot(t, raw)
	if body.Availability.System != availabilityOK {
		t.Fatalf("system availability = %q, want ok", body.Availability.System)
	}
	if body.Availability.Services != availabilityUnavailable ||
		body.Availability.Protocols != availabilityUnavailable ||
		body.Availability.Traffic != availabilityUnavailable {
		t.Fatalf("windows-only switches affected Linux sources: %+v", body.Availability)
	}
	if service.calls != 0 || singbox.calls != 0 {
		t.Fatalf("probes consulted without their source switches: service=%d singbox=%d",
			service.calls, singbox.calls)
	}
	if strings.Contains(string(raw), `"terminal"`) {
		t.Fatal("linux_vps snapshot must never carry a terminal object")
	}
}

// TestSysfsNetFallback covers the read-only sysfs fallback when /proc/net/dev
// is unreadable and the fail-closed behavior for unreadable interface files.
func TestSysfsNetFallback(t *testing.T) {
	sysRoot := writeTree(t, map[string]string{
		"class/net/lo/statistics/rx_bytes":   "111\n",
		"class/net/lo/statistics/tx_bytes":   "222\n",
		"class/net/eth0/statistics/rx_bytes": "333\n",
		"class/net/eth0/statistics/tx_bytes": "444\n",
		"class/net/eth1/statistics/rx_bytes": "555\n",
		"class/net/eth1/statistics/tx_bytes": "666\n",
		"class/net/bonding_masters":          "bond0\n",
	})
	procRoot := writeTree(t, map[string]string{"stat": fakeProcStat})
	collector := &Collector{ProcRoot: procRoot, SysRoot: sysRoot}
	rx, tx, err := collector.netCounters()
	if err != nil {
		t.Fatalf("netCounters: %v", err)
	}
	if rx != 888 || tx != 1110 {
		t.Fatalf("sysfs counters = %d/%d, want 888/1110", rx, tx)
	}

	broken := writeTree(t, map[string]string{
		"class/net/eth0/statistics/rx_bytes": "333\n",
		"class/net/eth0/statistics/tx_bytes": "not-a-counter\n",
	})
	collector = &Collector{ProcRoot: procRoot, SysRoot: broken}
	if _, _, err := collector.netCounters(); err == nil {
		t.Fatal("netCounters accepted a malformed sysfs counter")
	}

	emptySys := writeTree(t, map[string]string{})
	collector = &Collector{ProcRoot: procRoot, SysRoot: emptySys}
	if _, _, err := collector.netCounters(); err == nil {
		t.Fatal("netCounters accepted an empty sysfs tree")
	}
}

// TestMalformedProcDataIsUnavailable ensures malformed local kernel files
// produce null fields (partial/unavailable), never a panic or a fabricated
// value.
func TestMalformedProcDataIsUnavailable(t *testing.T) {
	requireSupportedArch(t)
	files := map[string]string{
		"stat":                 "not a stat document\n",
		"loadavg":              "nan not-a-load\n",
		"meminfo":              "garbage\n",
		"net/dev":              "garbage\n",
		"sys/kernel/osrelease": testKernel + "\n",
	}
	collector := &Collector{
		ProcRoot:     writeTree(t, files),
		AgentVersion: "1.0.0",
		DiskProbe:    &fakeDiskProbe{err: ErrProbeUnavailable},
	}
	raw, err := collector.Snapshot(context.Background(), reportContext([]string{"system"}, nil))
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	validateSnapshotBody(t, raw)
	body := unmarshalSnapshot(t, raw)
	if body.Availability.System != availabilityUnavailable {
		t.Fatalf("system availability = %q, want unavailable", body.Availability.System)
	}
	if body.System != (systemValues{}) {
		t.Fatalf("malformed sources produced values: %+v", body.System)
	}
}

// TestEventsG7SourceAuthorizationUnproven verifies the frozen diagnostic event
// is emitted when singbox_api is enabled without the versioned P1-10 proof, and
// is absent once the proof is explicitly recorded locally.
func TestEventsG7SourceAuthorizationUnproven(t *testing.T) {
	collector, _, _, _ := newFakeCollector(t)
	collector.SingBoxSourceAuthorized = false
	rc := reportContext([]string{"system", "singbox_api", "events"}, testExpectedTags())
	raw, err := collector.Events(context.Background(), rc)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	validateEventsBody(t, raw)
	body := unmarshalEvents(t, raw)
	if len(body.Events) != 2 {
		t.Fatalf("events=%d, want agent_started + agent_error", len(body.Events))
	}
	errEvent := body.Events[1]
	if errEvent.Kind != "agent_error" || errEvent.Severity != "warning" ||
		errEvent.EventID == body.Events[0].EventID || !reportIDPattern.MatchString(errEvent.EventID) {
		t.Fatalf("agent_error event = %+v", errEvent)
	}
	detail, ok := errEvent.Detail.(map[string]any)
	if !ok || detail["code"] != "source_authorization_unproven" {
		t.Fatalf("agent_error detail = %+v", errEvent.Detail)
	}
	// Retrying the same payload keeps the same event id (spool idempotency).
	retryRaw, err := collector.Events(context.Background(), rc)
	if err != nil {
		t.Fatalf("Events retry: %v", err)
	}
	if retry := unmarshalEvents(t, retryRaw); retry.Events[1].EventID != errEvent.EventID {
		t.Fatalf("agent_error event id is not retry-stable")
	}
	collector.SingBoxSourceAuthorized = true
	provenRaw, err := collector.Events(context.Background(), rc)
	if err != nil {
		t.Fatalf("Events proven: %v", err)
	}
	if proven := unmarshalEvents(t, provenRaw); len(proven.Events) != 1 {
		t.Fatalf("proven events=%d, want only agent_started", len(proven.Events))
	}
	// A disabled source never emits the source-specific diagnostic.
	disabledRaw, err := collector.Events(context.Background(), reportContext([]string{"system"}, testExpectedTags()))
	if err != nil {
		t.Fatalf("Events disabled: %v", err)
	}
	if disabled := unmarshalEvents(t, disabledRaw); len(disabled.Events) != 1 {
		t.Fatalf("disabled events=%d, want only agent_started", len(disabled.Events))
	}
}

func TestEventsWithoutEventsSourceStaysLegal(t *testing.T) {
	collector, _, _, _ := newFakeCollector(t)
	raw, err := collector.Events(context.Background(), reportContext([]string{"system"}, nil))
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	validateEventsBody(t, raw)
	body := unmarshalEvents(t, raw)
	if len(body.Events) != 1 || body.Events[0].Kind != "agent_started" {
		t.Fatalf("events = %+v", body.Events)
	}
}

// TestJSONBodiesAreStrict confirms the emitted bodies pass the strict-JSON
// grammar check the center applies before schema validation.
func TestJSONBodiesAreStrict(t *testing.T) {
	requireSupportedArch(t)
	collector, _, _, _ := newFakeCollector(t)
	rc := reportContext([]string{"system", "services", "singbox_api", "events"}, testExpectedTags())
	for name, build := range map[string]func() ([]byte, error){
		"snapshot": func() ([]byte, error) { return collector.Snapshot(context.Background(), rc) },
		"metrics":  func() ([]byte, error) { return collector.Metrics(context.Background(), rc) },
		"events":   func() ([]byte, error) { return collector.Events(context.Background(), rc) },
	} {
		raw, err := build()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := schema.CheckStrictJSON(raw); err != nil {
			t.Fatalf("%s body is not strict JSON: %v", name, err)
		}
	}
}

// TestCancelledContextIsHonored ensures a canceled context is surfaced instead
// of being reported as unavailable data.
func TestCancelledContextIsHonored(t *testing.T) {
	collector, _, _, _ := newFakeCollector(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rc := reportContext([]string{"system"}, nil)
	if _, err := collector.Snapshot(ctx, rc); !errors.Is(err, context.Canceled) {
		t.Fatalf("Snapshot error = %v, want context.Canceled", err)
	}
	if _, err := collector.Metrics(ctx, rc); !errors.Is(err, context.Canceled) {
		t.Fatalf("Metrics error = %v, want context.Canceled", err)
	}
	if _, err := collector.Events(ctx, rc); !errors.Is(err, context.Canceled) {
		t.Fatalf("Events error = %v, want context.Canceled", err)
	}
}

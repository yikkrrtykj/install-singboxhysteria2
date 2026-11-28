package linuxobs

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/agent"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/contract"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/schema"
)

// Synthetic fixture values used by this package's unit tests. They are
// deliberately fake procfs content, never live host observations.
const (
	testReportID     = "5a0d9e3c-1b2f-4c8a-9d6e-7f3a1c5b2e90"
	testCollectedAt  = int64(1795622400) // exactly on a minute boundary
	testKernel       = "6.8.0-45-generic"
	testBootID       = "5f0c2d7a-91b4-46c8-a3d1-f9052b7e4c6a"
	testCounterEpoch = "5f0c2d7a91b446c8a3d1f9052b7e4c6a" // testBootID without dashes
	testDeviceSalt   = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

// fakeProcStat has one aggregate cpu line: total 11000 jiffies, idle+iowait
// 9000, so the since-boot busy ratio is 18.181...%.
const fakeProcStat = `cpu  1000 0 500 8000 1000 0 0 500 0 0
cpu0 1000 0 500 8000 1000 0 0 500 0 0
intr 12345 0 0 0 0
ctxt 999999
btime 1795522400
processes 4242
procs_running 3
procs_blocked 0
`

// fakeProcSelfStat puts the process start time (field 22) at 500 clock ticks.
const fakeProcSelfStat = `1234 (um-agent) S 1 1234 1234 0 -1 4194560 100 0 0 0 5 6 0 0 20 0 1 0 500 12345678 100 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
`

const fakeProcLoadAvg = "0.42 0.38 0.30 2/234 5678\n"

const fakeProcMemInfo = `MemTotal:        4194304 kB
MemFree:         1048576 kB
MemAvailable:    2097152 kB
Buffers:           65536 kB
Cached:          1048576 kB
`

const fakeProcNetDev = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:       100       1    0    0    0     0          0         0      200       2    0    0    0     0       0          0
  eth0: 123456789      10    0    0    0     0          0         0 987654321      20    0    0    0     0       0          0
`

const fakeProcUptime = "10000.00 50000.00\n"

// testReportContext returns a valid ReportContext with the runtime host's
// actual GOARCH.
func testReportContext() agent.ReportContext {
	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		// Synthetic fallback so docs-level tests can still build a context.
		// Tests that produce a snapshot first call requireSupportedArch.
		arch = "amd64"
	}
	return agent.ReportContext{
		ReportID:    testReportID,
		CollectedAt: testCollectedAt,
		Host:        agent.HostInfo{OS: "linux", Kernel: testKernel, Arch: arch},
	}
}

// fakeProcFiles returns the complete synthetic procfs tree used by the happy
// path tests.
func fakeProcFiles() map[string]string {
	return map[string]string{
		"stat":                      fakeProcStat,
		"loadavg":                   fakeProcLoadAvg,
		"meminfo":                   fakeProcMemInfo,
		"net/dev":                   fakeProcNetDev,
		"uptime":                    fakeProcUptime,
		"self/stat":                 fakeProcSelfStat,
		"sys/kernel/osrelease":      testKernel + "\n",
		"sys/kernel/random/boot_id": testBootID + "\n",
	}
}

// writeTree materialises a synthetic directory tree below a fresh temp dir.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatalf("create fixture dir: %v", err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
	}
	return root
}

// testSourceSwitches builds a frozen source map with the listed sources enabled
// and every other switch disabled. Revision 7 adds the optional monitor_export
// switch; it defaults to disabled here like the center fail-closed default.
func testSourceSwitches(enabled ...string) map[string]bool {
	sources := map[string]bool{
		"system":         false,
		"services":       false,
		"singbox_api":    false,
		"mihomo_api":     false,
		"terminal":       false,
		"events":         false,
		"monitor_export": false,
	}
	for _, name := range enabled {
		sources[name] = true
	}
	return sources
}

// testExpectedTags returns a realistic two-tag center allowlist.
func testExpectedTags() []agent.InboundTag {
	return []agent.InboundTag{
		{InboundTag: "vless-in", Kind: "reality"},
		{InboundTag: "hy2-in", Kind: "hysteria2"},
	}
}

// reportContext builds a ReportContext with the given source switches and
// expected tags.
func reportContext(sources []string, tags []agent.InboundTag) agent.ReportContext {
	rc := testReportContext()
	rc.Config = agent.CollectConfig{
		ConfigVersion: 3,
		Cadence:       60,
		Sources:       testSourceSwitches(sources...),
		ExpectedTags:  tags,
		DeviceSalt:    testDeviceSalt,
	}
	return rc
}

// fakeDiskProbe is an injected DiskProbe fixture.
type fakeDiskProbe struct {
	total uint64
	used  uint64
	err   error
	calls int
}

func (probe *fakeDiskProbe) Usage() (uint64, uint64, error) {
	probe.calls++
	if probe.err != nil {
		return 0, 0, probe.err
	}
	return probe.total, probe.used, nil
}

// fakeServiceProbe is an injected ServiceProbe fixture.
type fakeServiceProbe struct {
	observation ServiceObservation
	err         error
	calls       int
}

func (probe *fakeServiceProbe) ObserveServices(context.Context) (ServiceObservation, error) {
	probe.calls++
	return probe.observation, probe.err
}

// fakeSingBoxProbe is an injected SingBoxProbe fixture.
type fakeSingBoxProbe struct {
	observation SingBoxObservation
	err         error
	calls       int
}

func (probe *fakeSingBoxProbe) ObserveSingBox(context.Context) (SingBoxObservation, error) {
	probe.calls++
	return probe.observation, probe.err
}

// newFakeCollector wires the synthetic procfs tree and the default fixture
// probes.
func newFakeCollector(t *testing.T) (*Collector, *fakeDiskProbe, *fakeServiceProbe, *fakeSingBoxProbe) {
	t.Helper()
	disk := &fakeDiskProbe{total: 42949672960, used: 10737418240}
	service := &fakeServiceProbe{observation: ServiceObservation{SingBox: ServiceActive}}
	singbox := &fakeSingBoxProbe{observation: SingBoxObservation{Inbounds: map[string]InboundEvidence{
		"vless-in": {ActiveConnections: 2, UplinkBytes: 1000, DownlinkBytes: 2000},
	}}}
	collector := &Collector{
		ProcRoot:                writeTree(t, fakeProcFiles()),
		AgentVersion:            "1.2.3",
		DiskProbe:               disk,
		ServiceProbe:            service,
		SingBoxProbe:            singbox,
		SingBoxSourceAuthorized: true,
	}
	return collector, disk, service, singbox
}

// requireSupportedArch skips a snapshot test on a GOARCH the frozen host.arch
// enum cannot express.
func requireSupportedArch(t *testing.T) string {
	t.Helper()
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skipf("host arch %s is outside the frozen host.arch enum", runtime.GOARCH)
	}
	return runtime.GOARCH
}

// contractSchemas compiles the frozen contract schemas once per test binary.
var (
	schemaSetOnce sync.Once
	schemaSet     *schema.Set
	schemaSetErr  error
)

func contractSchemas(t *testing.T) *schema.Set {
	t.Helper()
	schemaSetOnce.Do(func() {
		schemaSet, schemaSetErr = schema.Load("../../../docs/um/contracts/v1")
	})
	if schemaSetErr != nil {
		t.Fatalf("load frozen contract schemas: %v", schemaSetErr)
	}
	return schemaSet
}

func validateSnapshotBody(t *testing.T, raw []byte) {
	t.Helper()
	if err := contractSchemas(t).Validate("report-snapshot.schema.json", raw); err != nil {
		t.Fatalf("snapshot schema validation: %v", err)
	}
	if err := contract.ValidateReportBody(contract.NodeClassLinuxVPS, contract.ReportTypeSnapshot, raw); err != nil {
		t.Fatalf("snapshot runtime contract validation: %v", err)
	}
}

func validateMetricsBody(t *testing.T, raw []byte) {
	t.Helper()
	if err := contractSchemas(t).Validate("report-metrics.schema.json", raw); err != nil {
		t.Fatalf("metrics schema validation: %v", err)
	}
	if err := contract.ValidateReportBody(contract.NodeClassLinuxVPS, contract.ReportTypeMetrics, raw); err != nil {
		t.Fatalf("metrics runtime contract validation: %v", err)
	}
}

func validateEventsBody(t *testing.T, raw []byte) {
	t.Helper()
	if err := contractSchemas(t).Validate("report-events.schema.json", raw); err != nil {
		t.Fatalf("events schema validation: %v", err)
	}
	if err := contract.ValidateReportBody(contract.NodeClassLinuxVPS, contract.ReportTypeEvents, raw); err != nil {
		t.Fatalf("events runtime contract validation: %v", err)
	}
}

// decodeSnapshotAvailability decodes just the availability object.
func decodeSnapshotAvailability(t *testing.T, raw []byte) availabilityInfo {
	t.Helper()
	var body struct {
		Availability availabilityInfo `json:"availability"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode snapshot availability: %v", err)
	}
	return body.Availability
}

// decodeMetricsAvailability decodes just the metrics availability object.
func decodeMetricsAvailability(t *testing.T, raw []byte) availabilityInfo {
	t.Helper()
	var body struct {
		Availability availabilityInfo `json:"availability"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode metrics availability: %v", err)
	}
	return body.Availability
}

// unmarshalSnapshot decodes a snapshot body with the package's own types.
func unmarshalSnapshot(t *testing.T, raw []byte) snapshotBody {
	t.Helper()
	var body snapshotBody
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode snapshot body: %v", err)
	}
	return body
}

// unmarshalMetrics decodes a metrics body with the package's own types.
func unmarshalMetrics(t *testing.T, raw []byte) metricsBody {
	t.Helper()
	var body metricsBody
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode metrics body: %v", err)
	}
	return body
}

// unmarshalEvents decodes an events body with the package's own types.
func unmarshalEvents(t *testing.T, raw []byte) eventsBody {
	t.Helper()
	var body eventsBody
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode events body: %v", err)
	}
	return body
}

// Package linuxobs implements the read-only Linux VPS collector for the
// Unified Monitor (UM) v1 node protocol, revision 5, with the additive revision
// 7 read-only traffic observation (monitor-v2 export).
//
// The collector observes only local, unprivileged, read-only sources:
//
//   - a procfs mount (configurable ProcRoot, default "/proc"): CPU jiffies,
//     load average, memory, network counters, the kernel release, the agent
//     process start time and the boot id;
//   - one configured mount point measured with syscall.Statfs (DiskMountPath,
//     default "/");
//   - a read-only systemd ServiceProbe using the system D-Bus
//     (SystemdDBusProbe: exactly Manager.GetUnit and Properties.Get for
//     ActiveState; no root/exec/systemctl fallback);
//   - an optional ServiceAPIProbe for the official sing-box 1.14 service.api
//     gRPC-Web StartedService/SubscribeConnections stream (fixed loopback
//     origin, optional credential, no write RPCs);
//   - a legacy SingBoxProbe for the old Clash-compatible API (kept only for
//     compatibility/tests; it cannot provide daemon-lifetime totals);
//   - an optional revision-7 monitor-v2 read-only JSON traffic export
//     (MonitorExportFile): per-inbound OBSERVED LOWER-BOUND bytes plus observed
//     rates/freshness/epoch/sequence. It is enabled only by center config
//     collect.monitor_export AND an operator-local fixed absolute path; the
//     agent reads it read-only, never writes it, and never receives the path
//     from the center.
//
// It never starts a process, never writes a file, never listens on a socket
// and never needs a privileged uid. Report bodies are frozen-contract
// report-snapshot.v1 / report-metrics.v1 / report-events.v1 documents; data
// that cannot be observed is rendered as null / empty / unavailable, never as
// a fake zero and never as "up" without evidence.
//
// # Honest limitations
//
// These are deliberate and must be treated as implemented-vs-deferred notes,
// not as production evidence:
//
//   - CPU percent is the kernel's aggregate user/system/irq busy ratio since
//     boot (a single /proc/stat read), not a cadence-window rate. It is honest
//     observed data but it is not an instantaneous sample.
//   - The official service.api exposes no per-inbound daemon-lifetime counter.
//     The traffic projection uses probe-observed cumulative totals (active
//     authoritative counters plus finalized closed/abandoned lifecycles banked
//     once, and recently closed replay where available); they are lower bounds,
//     never active-connection-only sums presented as lifetime totals. The
//     legacy Clash compatibility probe exposes active lower bounds only.
//   - The D-Bus client is fixed-call and read-only; failures degrade to
//     unavailable. It is not a live-systemd-lab claim until the isolated lab is
//     executed.
//   - The service.api client is validated against synthetic gRPC-Web fixtures
//     and an isolated sing-box 1.14.5 service.api instance; it is not a
//     production claim. The center's singbox_api source stays disabled until
//     the UM-B3 server-side authorization audit exists (UM-A 04 §11 P1-10).
//   - Services/protocols/traffic are only rendered from their center source
//     switches; a disabled source yields an honest unavailable/empty/null
//     projection.
package linuxobs

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/agent"
)

// Frozen report-body discriminators and bounded contract values.
const (
	reportVersion      = 1
	reportTypeSnapshot = "snapshot"
	reportTypeMetrics  = "metrics"
	reportTypeEvents   = "events"

	// contractRevision7 is the snapshot contract revision that carries the
	// optional monitor_export traffic_observation object.
	contractRevision7 = 7

	serviceNameSingBox    = "sing-box"
	trafficScopeProtocol  = "protocol"
	eventKindAgentStarted = "agent_started"
	eventSeverityInfo     = "info"

	defaultProcRoot      = "/proc"
	defaultSysRoot       = "/sys"
	defaultDiskMountPath = "/"

	// Contract bounds from docs/um/contracts/v1 (frozen). Values outside these
	// bounds are reported as null instead of being clamped, because a clamped
	// value would be invented data.
	maxContractTimestamp    = int64(1000000000000)
	maxContractSizeBytes    = int64(1099511627776)
	maxContractCounter      = int64(9007199254740991)
	maxContractActiveConns  = int64(1000000)
	maxContractArrayItems   = 16
	secondsPerMinute        = int64(60)
	clockTicksPerSecond     = 100.0
	zeroCounterEpoch        = "00000000000000000000000000000000"
	agentStartedEventIDSalt = "um-linuxobs-agent-started-v1"
)

// Frozen center source-switch names (agent-config.schema.json collect object).
// mihomo_api and terminal are Windows-only and are never read here.
const (
	sourceSystem        = "system"
	sourceServices      = "services"
	sourceSingBoxAPI    = "singbox_api"
	sourceMonitorExport = "monitor_export"
)

// Frozen availability vocabulary.
const (
	availabilityOK          = "ok"
	availabilityPartial     = "partial"
	availabilityUnavailable = "unavailable"
)

// Frozen revision-7 traffic_observation tokens.
const (
	trafficCounterScopeObservationEpoch = "observation_epoch"
	trafficExactnessLowerBound          = "lower_bound"
)

// BuildVersion is embedded in agent.version and the agent_started event when
// Collector.AgentVersion is empty. Release builds set it with
// -ldflags "-X github.com/yikkrrtykj/install-singboxhysteria2/um/internal/linuxobs.BuildVersion=x.y.z".
// The default is a syntactically valid placeholder, never a claimed release.
var BuildVersion = "0.0.0"

// Collector implements agent.Collector for a Linux VPS.
//
// The zero value is usable: ProcRoot defaults to /proc, SysRoot to /sys,
// DiskMountPath to /, AgentVersion to BuildVersion, and the optional probes
// default to honest unavailable implementations. All fields are read-only
// configuration; the collector never mutates them. A Collector is safe for
// concurrent use as long as the injected probes are.
type Collector struct {
	// ProcRoot is the procfs mount to read (default "/proc"). Unit tests point
	// it at a fake procfs tree.
	ProcRoot string
	// SysRoot is the sysfs mount, used only as a bounded fallback network
	// counter source when /proc/net/dev is unreadable (default "/sys").
	SysRoot string
	// DiskMountPath is the single mount point measured with statfs
	// (default "/").
	DiskMountPath string
	// DiskProbe overrides the platform statfs probe. When nil, statfs is used
	// on Linux; on other platforms (where the package must also compile and
	// test) the disk fields are null.
	DiskProbe DiskProbe
	// ServiceProbe overrides the read-only systemd unit observer. When nil,
	// services are reported unavailable: no D-Bus client, no systemctl exec.
	ServiceProbe ServiceProbe
	// SingBoxProbe overrides the legacy Clash-compatible observer. When nil,
	// protocols/traffic use ServiceAPIProbe if present, otherwise unavailable.
	SingBoxProbe SingBoxProbe
	// ServiceAPIProbe is the official sing-box 1.14 service.api observer. It
	// carries probe-observed cumulative totals and is preferred over the legacy
	// active-connection-only SingBoxProbe.
	ServiceAPIProbe ServiceAPIObserver
	// SingBoxSourceAuthorized is the versioned server-side authorization-proof
	// gate (P1-10). It defaults to false: an enabled but unproven source emits
	// agent_error code=source_authorization_unproven and stays unavailable.
	SingBoxSourceAuthorized bool
	// MonitorExportFile is the operator-local fixed absolute path of the optional
	// monitor-v2 read-only traffic export. Empty disables local export reading
	// even when the center config enables collect.monitor_export; the snapshot
	// then carries an honest unavailable traffic_observation. The path is never
	// accepted from center config, a URL or a command.
	MonitorExportFile string
	// monitorExport is the in-memory monotonic epoch/sequence guard for the
	// optional export. It is never persisted and never a data source.
	monitorExport monitorExportTracker
	// AgentVersion is the semantic version embedded in agent.version and in
	// the agent_started event. Empty uses BuildVersion. A value that does not
	// match the frozen version grammar is a configuration error.
	AgentVersion string
	// AgentStartedAt, when non-zero, computes agent.uptime_s as
	// CollectedAt - AgentStartedAt (clamped at zero). When zero, uptime is
	// derived from procfs (/proc/uptime minus this process's start time); when
	// that evidence is missing the value is 0 (the contract has no null
	// uptime).
	AgentStartedAt time.Time
	// CounterEpoch overrides the frozen 32-hex counter_epoch. Empty derives it
	// from the procfs boot id, so the epoch changes on reboot; an unreadable
	// boot id is rendered as the all-zero epoch rather than an invented id.
	CounterEpoch string
}

var _ agent.Collector = (*Collector)(nil)

// collectedReport is the internal projection shared by the three report
// kinds.
type collectedReport struct {
	agentVersion      string
	host              hostInfo
	uptime            int64
	counterEpoch      string
	system            systemValues
	services          []serviceEntry
	protocols         []protocolEntry
	traffic           []trafficEntry
	activeConnections *int64
	availability      availabilityInfo
}

// Snapshot returns a contract-valid report-snapshot.v1 body for a linux_vps
// node.
func (c *Collector) Snapshot(ctx context.Context, rc agent.ReportContext) ([]byte, error) {
	report, err := c.collectObservations(ctx, rc)
	if err != nil {
		return nil, err
	}
	// Identity fields below are only part of the snapshot body; metrics and
	// events do not require them.
	version, err := c.agentVersionValue()
	if err != nil {
		return nil, err
	}
	host, err := c.hostInfo(rc)
	if err != nil {
		return nil, err
	}
	counterEpoch, err := c.counterEpochValue()
	if err != nil {
		return nil, err
	}
	report.agentVersion = version
	report.host = host
	report.uptime = c.agentUptimeSeconds(rc)
	report.counterEpoch = counterEpoch
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	body := snapshotBody{
		V:           reportVersion,
		Type:        reportTypeSnapshot,
		ReportID:    rc.ReportID,
		CollectedAt: rc.CollectedAt,
		Agent: agentInfo{
			Version: report.agentVersion,
			UptimeS: report.uptime,
		},
		Host:         report.host,
		Availability: report.availability,
		CounterEpoch: report.counterEpoch,
		System:       report.system,
		Services:     report.services,
		Protocols:    report.protocols,
		Traffic:      report.traffic,
		Clients: clientsInfo{
			Active:    nil,
			Tracked:   nil,
			Summaries: make([]clientSummary, 0),
		},
	}
	// The rev-7 traffic observation is emitted only when the center config
	// enables collect.monitor_export. With the source absent/disabled the body
	// above is byte-identical to the frozen rev-5 snapshot body: both rev-7
	// fields are omitempty and never set.
	if sourceEnabled(rc, sourceMonitorExport) {
		body.ContractRevision = contractRevision7
		body.TrafficObservation = c.trafficObservation(rc)
	}
	return marshalReport("snapshot", body)
}

// Metrics returns a contract-valid report-metrics.v1 body with one
// minute-aligned sample. Unavailable values are null; the availability object
// is the same honest projection the snapshot uses.
func (c *Collector) Metrics(ctx context.Context, rc agent.ReportContext) ([]byte, error) {
	report, err := c.collectObservations(ctx, rc)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	body := metricsBody{
		V:            reportVersion,
		Type:         reportTypeMetrics,
		ReportID:     rc.ReportID,
		CollectedAt:  rc.CollectedAt,
		Availability: report.availability,
		Samples: []metricSample{{
			At:                minuteAligned(rc.CollectedAt),
			CPUPercent:        report.system.CPUPercent,
			Load1:             report.system.Load1,
			MemUsedBytes:      report.system.MemUsedBytes,
			DiskUsedBytes:     report.system.DiskUsedBytes,
			NetRxBytesTotal:   report.system.NetRxBytes,
			NetTxBytesTotal:   report.system.NetTxBytes,
			ActiveConnections: report.activeConnections,
		}},
	}
	return marshalReport("metrics", body)
}

// Events returns a contract-valid report-events.v1 body carrying one generic
// agent_started info event. The event is an agent-lifecycle fact and stays
// legal when the center's events source switch is disabled (the center ingest
// rules accept generic agent kinds in that case); it contains no paths,
// secrets or free text.
func (c *Collector) Events(ctx context.Context, rc agent.ReportContext) ([]byte, error) {
	if err := validateReportContext(rc); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	version, err := c.agentVersionValue()
	if err != nil {
		return nil, err
	}
	body := eventsBody{
		V:           reportVersion,
		Type:        reportTypeEvents,
		ReportID:    rc.ReportID,
		CollectedAt: rc.CollectedAt,
		Events: []eventEntry{{
			EventID:  agentStartedEventID(rc.ReportID),
			At:       rc.CollectedAt,
			Kind:     eventKindAgentStarted,
			Severity: eventSeverityInfo,
			Detail:   agentStartedDetail{AgentVersion: version},
		}},
	}
	// P1-10/G7: an enabled source without a versioned server-side authorization
	// proof is still unavailable and MUST emit the closed diagnostic event. The
	// event is stable across retries of the same report.
	if sourceEnabled(rc, sourceSingBoxAPI) && !c.SingBoxSourceAuthorized {
		body.Events = append(body.Events, eventEntry{
			EventID:  agentErrorEventID(rc.ReportID, "source_authorization_unproven"),
			At:       rc.CollectedAt,
			Kind:     "agent_error",
			Severity: "warning",
			Detail:   agentErrorDetail{Code: "source_authorization_unproven"},
		})
	}
	// The events source switch is intentionally not required for the generic
	// agent_started lifecycle event; source-specific diagnostics above are only
	// emitted when their source is configured.
	return marshalReport("events", body)
}

// collectObservations assembles the source-gated telemetry shared by snapshot
// and metrics. It renders honest unavailable/empty/null projections for every
// source that is disabled or cannot be observed; identity fields (agent
// version, host, uptime, counter epoch) are added by Snapshot only.
func (c *Collector) collectObservations(ctx context.Context, rc agent.ReportContext) (*collectedReport, error) {
	if err := validateReportContext(rc); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	report := &collectedReport{
		services:  make([]serviceEntry, 0),
		protocols: make([]protocolEntry, 0),
		traffic:   make([]trafficEntry, 0),
	}

	systemAvailability := availabilityUnavailable
	if sourceEnabled(rc, sourceSystem) {
		report.system = c.readSystemValues()
		systemAvailability = report.system.availability()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	servicesAvailability := availabilityUnavailable
	if sourceEnabled(rc, sourceServices) {
		report.services, servicesAvailability = c.observeServices(ctx)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	protocolsAvailability := availabilityUnavailable
	trafficAvailability := availabilityUnavailable
	if sourceEnabled(rc, sourceSingBoxAPI) {
		report.protocols, report.traffic, report.activeConnections,
			protocolsAvailability, trafficAvailability = c.observeSingBox(ctx, rc)
	}

	report.availability = availabilityInfo{
		System:    systemAvailability,
		Services:  servicesAvailability,
		Protocols: protocolsAvailability,
		Traffic:   trafficAvailability,
		Clients:   availabilityUnavailable,
	}
	return report, nil
}

// observeServices projects the optional systemd probe. A missing or failing
// probe keeps the service array empty and services unavailable.
func (c *Collector) observeServices(ctx context.Context) ([]serviceEntry, string) {
	observation, err := c.serviceProbe().ObserveServices(ctx)
	if err != nil {
		return make([]serviceEntry, 0), availabilityUnavailable
	}
	state := normalizeServiceState(observation.SingBox)
	entries := []serviceEntry{{Name: serviceNameSingBox, State: string(state)}}
	if state == ServiceUnknown {
		return entries, availabilityPartial
	}
	return entries, availabilityOK
}

// observeSingBox projects authorized expected inbound tags onto the frozen
// protocols/traffic objects. Only center-configured expected tags may appear;
// a tag without observed evidence stays unknown and its traffic counters stay
// null. The source switch controls whether the probe is consulted at all.
func (c *Collector) observeSingBox(ctx context.Context, rc agent.ReportContext) (
	protocols []protocolEntry,
	traffic []trafficEntry,
	activeConnections *int64,
	protocolsAvailability string,
	trafficAvailability string,
) {
	protocols = make([]protocolEntry, 0)
	traffic = make([]trafficEntry, 0)
	protocolsAvailability = availabilityUnavailable
	trafficAvailability = availabilityUnavailable

	expected := authorizedInboundTags(rc.Config.ExpectedTags)
	if len(expected) == 0 {
		return protocols, traffic, nil, protocolsAvailability, trafficAvailability
	}
	if !c.SingBoxSourceAuthorized {
		// The probe may be constructed by an operator, but collection remains
		// off until the versioned P1-10 authorization proof exists. Events()
		// emits the stable source_authorization_unproven diagnostic.
		return protocols, traffic, nil, protocolsAvailability, trafficAvailability
	}

	// Prefer the official service.api observer: it carries probe-observed
	// cumulative per-inbound totals rather than only active-connection bytes.
	if c.ServiceAPIProbe != nil {
		rich, err := c.ServiceAPIProbe.ObserveServiceAPI(ctx)
		if err == nil {
			return projectServiceAPIObservation(expected, rich, rc.CollectedAt)
		}
		return protocols, traffic, nil, protocolsAvailability, trafficAvailability
	}

	observation, err := c.singBoxProbe().ObserveSingBox(ctx)
	if err != nil {
		return protocols, traffic, nil, protocolsAvailability, trafficAvailability
	}

	observed := 0
	var activeTotal int64
	activeValid := true
	for _, tag := range expected {
		evidence, seen := observation.Inbounds[tag.tag]
		state := "unknown"
		reason := "unknown"
		if seen {
			observed++
			state, reason = "up", "ok"
			if evidence.ActiveConnections < 0 ||
				evidence.ActiveConnections > maxContractActiveConns-activeTotal {
				activeValid = false
			} else {
				activeTotal += evidence.ActiveConnections
			}
		}
		protocols = append(protocols, protocolEntry{
			Kind:       tag.kind,
			InboundTag: tag.tag,
			State:      state,
			Reason:     reason,
			ObservedAt: rc.CollectedAt,
		})
		// The legacy Clash API exposes active-connection byte counters, not
		// lifetime per-inbound totals. The frozen traffic fields are totals and
		// an unavailable projection requires an empty array, so no traffic
		// entry is emitted for this observation.
	}

	if observed == len(expected) {
		protocolsAvailability = availabilityOK
	} else {
		protocolsAvailability = availabilityPartial
	}
	trafficAvailability = availabilityUnavailable
	if activeValid && activeTotal <= maxContractActiveConns {
		activeConnections = &activeTotal
	}
	return protocols, traffic, activeConnections, protocolsAvailability, trafficAvailability
}

// projectServiceAPIObservation maps the richer service.api accumulator to the
// frozen snapshot traffic/protocol shapes. Totals are probe-observed cumulative
// lower bounds (active authoritative counters plus finalized closed lifecycles
// banked once); if the accumulator could not attribute any event, traffic is
// rendered unavailable instead of presenting a potentially incomplete total as
// exact. Active-connection bytes are never used as lifetime totals. When a tag
// is absent, its counters stay null and traffic is partial.
func projectServiceAPIObservation(expected []authorizedTag, obs ServiceAPIObservation,
	collectedAt int64) (
	protocols []protocolEntry,
	traffic []trafficEntry,
	activeConnections *int64,
	protocolsAvailability string,
	trafficAvailability string,
) {
	protocols = make([]protocolEntry, 0, len(expected))
	traffic = make([]trafficEntry, 0, len(expected))
	protocolsAvailability = availabilityUnavailable
	trafficAvailability = availabilityUnavailable
	if !obs.Connected || obs.SkippedEvents > 0 || obs.IdentityConflicts > 0 {
		return protocols, traffic, nil, protocolsAvailability, trafficAvailability
	}

	observed := 0
	var activeTotal int64
	activeValid := true
	for _, tag := range expected {
		evidence, seen := obs.Inbounds[tag.tag]
		state := "unknown"
		reason := "unknown"
		if seen {
			observed++
			state, reason = "up", "ok"
			if evidence.ActiveConnections < 0 ||
				evidence.ActiveConnections > maxContractActiveConns-activeTotal {
				activeValid = false
			} else {
				activeTotal += evidence.ActiveConnections
			}
		}
		protocols = append(protocols, protocolEntry{
			Kind:       tag.kind,
			InboundTag: tag.tag,
			State:      state,
			Reason:     reason,
			ObservedAt: collectedAt,
		})
		// service.api exposes no daemon-lifetime per-inbound counter. Its
		// probe-observed cumulative value is a lower bound, and the frozen
		// traffic fields have no lower-bound representation. Do not present the
		// estimate as a total: traffic is unavailable and its array must be
		// empty under the frozen coherence rules.
	}
	if observed == len(expected) {
		protocolsAvailability = availabilityOK
	} else {
		protocolsAvailability = availabilityPartial
	}
	trafficAvailability = availabilityUnavailable
	if activeValid && activeTotal <= maxContractActiveConns {
		activeConnections = &activeTotal
	}
	return protocols, traffic, activeConnections, protocolsAvailability, trafficAvailability
}

// Close releases optional persistent probes. The agent runtime calls this at
// shutdown so a service.api reader goroutine and its loopback connection do not
// survive the process lifetime.
func (c *Collector) Close() error {
	var first error
	if c.ServiceAPIProbe != nil {
		if closer, ok := c.ServiceAPIProbe.(interface{ Close() error }); ok {
			if err := closer.Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	if c.ServiceProbe != nil {
		if closer, ok := c.ServiceProbe.(interface{ Close() error }); ok {
			if err := closer.Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

// authorizedTag is one validated center-expected inbound tag.
type authorizedTag struct {
	tag  string
	kind string
}

// authorizedInboundTags validates and deduplicates the center-managed expected
// inbound tag allowlist. Invalid or duplicate entries are dropped rather than
// normalized, and the frozen 16-entry array cap is enforced defensively (the
// agent-config schema bounds the configured list to 8).
func authorizedInboundTags(expected []agent.InboundTag) []authorizedTag {
	tags := make([]authorizedTag, 0, len(expected))
	seen := make(map[string]struct{}, len(expected))
	for _, entry := range expected {
		if len(tags) >= maxContractArrayItems {
			break
		}
		if len(entry.InboundTag) == 0 || len(entry.InboundTag) > 64 ||
			!inboundTagPattern.MatchString(entry.InboundTag) {
			continue
		}
		if !validProtocolKind(entry.Kind) {
			continue
		}
		if _, duplicate := seen[entry.InboundTag]; duplicate {
			continue
		}
		seen[entry.InboundTag] = struct{}{}
		tags = append(tags, authorizedTag{tag: entry.InboundTag, kind: entry.Kind})
	}
	return tags
}

func validProtocolKind(kind string) bool {
	switch kind {
	case "reality", "hysteria2", "other":
		return true
	default:
		return false
	}
}

// contractCounter bounds one traffic counter to the frozen schema range.
// Out-of-range values become null (unavailable), never a clamped lie.
func contractCounter(value int64) (int64, bool) {
	if value < 0 || value > maxContractCounter {
		return 0, false
	}
	return value, true
}

// agentVersionValue resolves and validates the reported agent version.
func (c *Collector) agentVersionValue() (string, error) {
	version := c.AgentVersion
	if version == "" {
		version = BuildVersion
	}
	if len(version) > 32 || !agentVersionPattern.MatchString(version) {
		return "", fmt.Errorf("linuxobs: configured agent version is not contract-valid")
	}
	return version, nil
}

// hostInfo resolves the frozen host object. The kernel release comes from
// procfs with the runtime-supplied HostInfo.Kernel as a fallback; arch comes
// from runtime.GOARCH and the frozen enum only permits amd64/arm64.
func (c *Collector) hostInfo(rc agent.ReportContext) (hostInfo, error) {
	return buildHostInfo(c.procRoot(), rc.Host.Kernel, runtime.GOARCH)
}

func buildHostInfo(procRoot, fallbackKernel, goarch string) (hostInfo, error) {
	if goarch != "amd64" && goarch != "arm64" {
		return hostInfo{}, fmt.Errorf("linuxobs: unsupported host architecture %q: %w", goarch, agent.ErrUnsupported)
	}
	kernel, err := readKernelRelease(procRoot)
	if err != nil || !validKernelRelease(kernel) {
		kernel = strings.TrimSpace(fallbackKernel)
		if !validKernelRelease(kernel) {
			return hostInfo{}, fmt.Errorf("linuxobs: host kernel release is unavailable")
		}
	}
	return hostInfo{OS: "linux", Kernel: kernel, Arch: goarch}, nil
}

// agentUptimeSeconds reports the agent process uptime as an integer second
// count. The contract has no null uptime, so missing evidence is 0.
func (c *Collector) agentUptimeSeconds(rc agent.ReportContext) int64 {
	if !c.AgentStartedAt.IsZero() {
		started := c.AgentStartedAt.Unix()
		if rc.CollectedAt <= started {
			return 0
		}
		delta := rc.CollectedAt - started
		if delta > maxContractTimestamp {
			return maxContractTimestamp
		}
		return delta
	}
	procRoot := c.procRoot()
	uptimeData, err := os.ReadFile(filepath.Join(procRoot, "uptime"))
	if err != nil {
		return 0
	}
	hostUptime, err := parseUptimeSeconds(uptimeData)
	if err != nil {
		return 0
	}
	statData, err := os.ReadFile(filepath.Join(procRoot, "self", "stat"))
	if err != nil {
		return 0
	}
	startTicks, err := parseProcessStartTicks(statData)
	if err != nil {
		return 0
	}
	seconds := hostUptime - float64(startTicks)/clockTicksPerSecond
	if seconds < 0 || math.IsNaN(seconds) || math.IsInf(seconds, 0) {
		return 0
	}
	if seconds > float64(maxContractTimestamp) {
		return maxContractTimestamp
	}
	return int64(math.Floor(seconds))
}

// counterEpochValue resolves the counter rotation epoch. The override is
// validated; otherwise the procfs boot id supplies a 32-hex epoch so network
// counters that reset on reboot are distinguishable. A missing boot id is
// rendered as the documented all-zero epoch.
func (c *Collector) counterEpochValue() (string, error) {
	if c.CounterEpoch != "" {
		if !counterEpochPattern.MatchString(c.CounterEpoch) {
			return "", fmt.Errorf("linuxobs: configured counter epoch is not 32 lowercase hex")
		}
		return c.CounterEpoch, nil
	}
	return readCounterEpoch(c.procRoot()), nil
}

// procRoot resolves the configured procfs root.
func (c *Collector) procRoot() string {
	if c.ProcRoot != "" {
		return c.ProcRoot
	}
	return defaultProcRoot
}

// sysRoot resolves the configured sysfs root.
func (c *Collector) sysRoot() string {
	if c.SysRoot != "" {
		return c.SysRoot
	}
	return defaultSysRoot
}

// diskMountPath resolves the configured disk mount point.
func (c *Collector) diskMountPath() string {
	if c.DiskMountPath != "" {
		return c.DiskMountPath
	}
	return defaultDiskMountPath
}

// serviceProbe resolves the optional systemd observer.
func (c *Collector) serviceProbe() ServiceProbe {
	if c.ServiceProbe != nil {
		return c.ServiceProbe
	}
	return unavailableServiceProbe{}
}

// singBoxProbe resolves the optional sing-box observer.
func (c *Collector) singBoxProbe() SingBoxProbe {
	if c.SingBoxProbe != nil {
		return c.SingBoxProbe
	}
	return unavailableSingBoxProbe{}
}

// sourceEnabled reports whether a frozen center source switch is enabled. A
// nil Sources map means every source is disabled (fail-closed).
func sourceEnabled(rc agent.ReportContext, source string) bool {
	return rc.Config.Sources != nil && rc.Config.Sources[source]
}

// minuteAligned floors a Unix timestamp to the minute grid required by
// metrics.samples[].at.
func minuteAligned(at int64) int64 {
	return at - at%secondsPerMinute
}

// marshalReport marshals one already-assembled body.
func marshalReport(kind string, body any) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("linuxobs: marshal %s report body: %w", kind, err)
	}
	return raw, nil
}

package linuxobs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/agent"
)

var (
	// reportIDPattern is the frozen lowercase UUIDv4 report_id grammar.
	reportIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	// agentVersionPattern is the frozen agent.version grammar.
	agentVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)
	// counterEpochPattern is the frozen 32-lowercase-hex counter_epoch grammar.
	counterEpochPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	// inboundTagPattern is the frozen inbound_tag grammar.
	inboundTagPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

// hostInfo is the frozen host object.
type hostInfo struct {
	OS     string `json:"os"`
	Kernel string `json:"kernel"`
	Arch   string `json:"arch"`
}

// agentInfo is the frozen agent object.
type agentInfo struct {
	Version string `json:"version"`
	UptimeS int64  `json:"uptime_s"`
}

// availabilityInfo is the frozen availability object.
type availabilityInfo struct {
	System    string `json:"system"`
	Services  string `json:"services"`
	Protocols string `json:"protocols"`
	Traffic   string `json:"traffic"`
	Clients   string `json:"clients"`
}

// serviceEntry is one frozen services[] element.
type serviceEntry struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

// protocolEntry is one frozen protocols[] element.
type protocolEntry struct {
	Kind       string `json:"kind"`
	InboundTag string `json:"inbound_tag"`
	State      string `json:"state"`
	Reason     string `json:"reason"`
	ObservedAt int64  `json:"observed_at"`
}

// trafficEntry is one frozen traffic[] element. Null counters are unavailable
// counters, never zero.
type trafficEntry struct {
	Scope              string `json:"scope"`
	InboundTag         string `json:"inbound_tag"`
	UplinkTotalBytes   *int64 `json:"uplink_total_bytes"`
	DownlinkTotalBytes *int64 `json:"downlink_total_bytes"`
}

// clientSummary is one frozen clients.summaries[] element. Linux v1 never
// reports client telemetry, so the array is always empty.
type clientSummary struct {
	DeviceRef     string `json:"device_ref"`
	Active        int64  `json:"active"`
	UplinkBytes   int64  `json:"uplink_bytes"`
	DownlinkBytes int64  `json:"downlink_bytes"`
	LastSeen      int64  `json:"last_seen"`
}

// clientsInfo is the frozen clients object. Linux v1 is always the honest
// unavailable/null/empty projection.
type clientsInfo struct {
	Active    *int64          `json:"active"`
	Tracked   *int64          `json:"tracked"`
	Summaries []clientSummary `json:"summaries"`
}

// snapshotBody is a report-snapshot.v1 body.
type snapshotBody struct {
	V            int              `json:"v"`
	Type         string           `json:"type"`
	ReportID     string           `json:"report_id"`
	CollectedAt  int64            `json:"collected_at"`
	Agent        agentInfo        `json:"agent"`
	Host         hostInfo         `json:"host"`
	Availability availabilityInfo `json:"availability"`
	CounterEpoch string           `json:"counter_epoch"`
	System       systemValues     `json:"system"`
	Services     []serviceEntry   `json:"services"`
	Protocols    []protocolEntry  `json:"protocols"`
	Traffic      []trafficEntry   `json:"traffic"`
	Clients      clientsInfo      `json:"clients"`
}

// metricSample is one frozen metrics.samples[] element.
type metricSample struct {
	At                int64    `json:"at"`
	CPUPercent        *float64 `json:"cpu_pct"`
	Load1             *float64 `json:"load1"`
	MemUsedBytes      *int64   `json:"mem_used_bytes"`
	DiskUsedBytes     *int64   `json:"disk_used_bytes"`
	NetRxBytesTotal   *int64   `json:"net_rx_bytes_total"`
	NetTxBytesTotal   *int64   `json:"net_tx_bytes_total"`
	ActiveConnections *int64   `json:"active_connections"`
}

// metricsBody is a report-metrics.v1 body.
type metricsBody struct {
	V            int              `json:"v"`
	Type         string           `json:"type"`
	ReportID     string           `json:"report_id"`
	CollectedAt  int64            `json:"collected_at"`
	Availability availabilityInfo `json:"availability"`
	Samples      []metricSample   `json:"samples"`
}

// agentStartedDetail is the closed detail object of an agent_started event.
type agentStartedDetail struct {
	AgentVersion string `json:"agent_version"`
}

// agentErrorDetail is the closed detail object of an agent_error event.
type agentErrorDetail struct {
	Code string `json:"code"`
}

// eventEntry is one frozen events[] element. Detail is one of the closed
// per-kind detail objects; the JSON shape is selected by Kind.
type eventEntry struct {
	EventID  string `json:"event_id"`
	At       int64  `json:"at"`
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Detail   any    `json:"detail"`
}

// eventsBody is a report-events.v1 body.
type eventsBody struct {
	V           int          `json:"v"`
	Type        string       `json:"type"`
	ReportID    string       `json:"report_id"`
	CollectedAt int64        `json:"collected_at"`
	Events      []eventEntry `json:"events"`
}

// validateReportContext rejects report contexts that cannot form a
// contract-valid body. The error deliberately does not echo the values.
func validateReportContext(rc agent.ReportContext) error {
	if !reportIDPattern.MatchString(rc.ReportID) {
		return fmt.Errorf("linuxobs: report context carries an invalid report id")
	}
	if rc.CollectedAt < 0 || rc.CollectedAt > maxContractTimestamp {
		return fmt.Errorf("linuxobs: report context collected_at is outside the frozen bounds")
	}
	return nil
}

// agentStartedEventID derives the agent_started event id from the immutable
// report id. The derivation is deterministic so a spooled report keeps one
// identity across retries, and it is deliberately version-4 UUID shaped (the
// frozen event_id grammar requires that shape even though the value is not
// random, because it is an idempotency key rather than a secret).
func agentStartedEventID(reportID string) string {
	return derivedEventID(agentStartedEventIDSalt, reportID)
}

// agentErrorEventID derives a stable idempotency key from the report identity
// and the closed error code. A retry of the same spooled report keeps the same
// event id.
func agentErrorEventID(reportID, code string) string {
	return derivedEventID(agentStartedEventIDSalt+"|error|"+code, reportID)
}

func derivedEventID(salt, reportID string) string {
	sum := sha256.Sum256([]byte(salt + "\n" + reportID))
	var bytes [16]byte
	copy(bytes[:], sum[:16])
	bytes[6] = (bytes[6] & 0x0f) | 0x40
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(bytes[:])
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" +
		encoded[16:20] + "-" + encoded[20:32]
}

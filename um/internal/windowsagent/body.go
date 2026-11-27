package windowsagent

// This file defines the frozen report-body shapes produced by the Windows
// terminal collector. Field order and json tags follow
// docs/um/contracts/v1/report-snapshot.schema.json and
// report-events.schema.json. Nullable contract fields use pointers so the
// encoder always emits an explicit JSON null (never a fabricated zero), and
// arrays are always non-nil so they encode as [] rather than null.
//
// Only fields the Windows terminal collector can legitimately produce exist
// here: the Linux-side telemetry element arrays (services/protocols/traffic/
// clients summaries) are typed empty because base Windows metrics are deferred
// in v1, and keeping their concrete types out of the wire surface prevents
// accidental fabrication later.

// snapshotBody is the frozen report-snapshot.schema.json body. Terminal is a
// pointer: the frozen contract allows its absence only for the H1 default
// configuration where no terminal source is authorized.
type snapshotBody struct {
	V            int             `json:"v"`
	Type         string          `json:"type"`
	ReportID     string          `json:"report_id"`
	CollectedAt  int64           `json:"collected_at"`
	Agent        agentInfo       `json:"agent"`
	Host         hostInfo        `json:"host"`
	Availability availabilitySet `json:"availability"`
	CounterEpoch string          `json:"counter_epoch"`
	System       systemBody      `json:"system"`
	Services     []serviceBody   `json:"services"`
	Protocols    []protocolBody  `json:"protocols"`
	Traffic      []trafficBody   `json:"traffic"`
	Clients      clientsBody     `json:"clients"`
	Terminal     *terminalBody   `json:"terminal,omitempty"`
}

type agentInfo struct {
	Version string `json:"version"`
	UptimeS int64  `json:"uptime_s"`
}

type hostInfo struct {
	OS     string `json:"os"`
	Kernel string `json:"kernel"`
	Arch   string `json:"arch"`
}

type availabilitySet struct {
	System    string `json:"system"`
	Services  string `json:"services"`
	Protocols string `json:"protocols"`
	Traffic   string `json:"traffic"`
	Clients   string `json:"clients"`
}

// systemBody stays all-null: the optional rev-5 Windows system source is not
// collected in this slice (Windows metrics v1 deferred).
type systemBody struct {
	CPUPct         *float64 `json:"cpu_pct"`
	Load1          *float64 `json:"load1"`
	MemTotalBytes  *int64   `json:"mem_total_bytes"`
	MemUsedBytes   *int64   `json:"mem_used_bytes"`
	DiskTotalBytes *int64   `json:"disk_total_bytes"`
	DiskUsedBytes  *int64   `json:"disk_used_bytes"`
	NetRxBytes     *int64   `json:"net_rx_bytes"`
	NetTxBytes     *int64   `json:"net_tx_bytes"`
}

// The base telemetry element types are empty by design (see file comment).
type (
	serviceBody       struct{}
	protocolBody      struct{}
	trafficBody       struct{}
	clientSummaryBody struct{}
)

type clientsBody struct {
	Active    *int64              `json:"active"`
	Tracked   *int64              `json:"tracked"`
	Summaries []clientSummaryBody `json:"summaries"`
}

// terminalBody is the frozen Windows terminal object. Selection and
// active_connections are independently sampled and independently authorized.
type terminalBody struct {
	Selection         selectionBody   `json:"selection"`
	ActiveConnections connectionsBody `json:"active_connections"`
}

type selectionBody struct {
	Availability string  `json:"availability"`
	SampledAt    int64   `json:"sampled_at"`
	Route        *string `json:"route"`
	ReasonCode   *string `json:"reason_code"`
}

type connectionsBody struct {
	Availability string            `json:"availability"`
	SampledAt    int64             `json:"sampled_at"`
	Total        *int64            `json:"total"`
	ByRoute      map[string]*int64 `json:"by_route"`
}

// eventsBody is the frozen report-events.schema.json body. The report-events
// schema requires at least one event, so the collector always emits the generic
// agent_started event and adds a terminal source fault event when one is known.
type eventsBody struct {
	V           int         `json:"v"`
	Type        string      `json:"type"`
	ReportID    string      `json:"report_id"`
	CollectedAt int64       `json:"collected_at"`
	Events      []eventBody `json:"events"`
}

type eventBody struct {
	EventID  string `json:"event_id"`
	At       int64  `json:"at"`
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Detail   any    `json:"detail"`
}

type agentStartedDetail struct {
	AgentVersion string `json:"agent_version"`
}

type agentErrorDetail struct {
	Code string `json:"code"`
}

type terminalSourceUnavailableDetail struct {
	Source     string `json:"source"`
	ReasonCode string `json:"reason_code"`
}

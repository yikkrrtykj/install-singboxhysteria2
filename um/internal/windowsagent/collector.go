// Package windowsagent implements the frozen-contract Windows terminal
// collector for the shared UM-B3 node agent (agent.Collector).
//
// Scope and honesty rules:
//
//   - Snapshot produces a contract-valid windows_terminal v1 snapshot. The base
//     Linux-side telemetry (system/services/protocols/traffic/clients) stays in
//     its honest unavailable/null/empty state because Windows metrics v1 is
//     deferred; the optional `system` source is not collected in this slice.
//   - The `terminal` object is the only real observation. Selection and
//     active_connections are sampled independently and each carries its own
//     availability/sampled_at. The terminal object is emitted only when the
//     centre authorized at least one terminal source (`terminal` for selection,
//     `mihomo_api` for active connections); with both switches false the object
//     is absent, which is the frozen H1 "default Windows config" shape. A
//     partially authorized source reports honest unavailable/null data.
//   - Route tokens are exactly the six frozen tokens owned by windowsobs. There
//     is no second role enum. `direct` can only come from an explicit
//     operator-local binding; an unmapped/ambiguous route is the `unknown`
//     token, never DIRECT.
//   - Metrics returns agent.ErrUnsupported: per-minute Windows metrics are
//     deferred in contract v1.
//   - Events emits contract-valid generic terminal events only (agent_started
//     plus terminal_source_unavailable when the authorized source is not
//     locally configured). No free text, proxy names, IPs, URLs, connection
//     ids, YAML or credentials ever enter a body.
//
// R2/R1 boundary (see docs/um/um-127/02-dual-platform-contract.md §4 and the
// UM-B3 Windows-sources ADR):
//
//   - R1: the current windowsobs loopback HTTP client is an R1-style
//     controller prototype (the controller credential is generally
//     write-capable; using it from a GET-only client is a residual risk, not a
//     read-only proof). It is never enabled implicitly here: the collector only
//     touches an explicitly injected RouteObserver, defaults to no source, and
//     the shipped windowsobs client is exercised only against httptest MOCK
//     servers in unit tests. Enabling a real R1 source requires a separate
//     Owner risk acceptance and is NOT done by this package.
//   - R2: a truly read-only local source (no controller secret) may later
//     implement RouteObserver. No R2 result exists in this slice; this package
//     only reserves the interface and documents the hook.
//   - Operator-local route binding (controller address, watched group, local
//     proxy names -> six tokens) is configuration injected in code by the host
//     process. It is never uploaded, never persisted in a report and never
//     returned in diagnostics.
//
// Service account / DPAPI / ACL decision (OD-P7) is pending: service_windows.go
// provides only an isolated, dependency-free DPAPI protection helper and ADR
// hooks; it does not install, run or configure a Windows service and requires
// no production account.
package windowsagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/agent"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/windowsobs"
)

// DefaultAgentVersion is used when the host does not inject the real build
// version. It keeps report bodies contract-valid; production wiring must pass
// the actual agent version.
const DefaultAgentVersion = "1.0.0"

// Frozen contract limits reused for local validation.
const (
	reportBodyV        = 1
	maxCollectedAt     = 1000000000000
	maxUptimeSeconds   = 1000000000000
	maxRouteCount      = 1000000
	counterEpochLength = 32
)

// Frozen Windows terminal reason codes. Values are accepted from an injected
// observer only if they are members of the frozen closed enum; anything else is
// downgraded to malformed_response (never echoed).
const (
	reasonControllerUnreachable       = "controller_unreachable"
	reasonControllerAuth              = "controller_auth"
	reasonMalformedResponse           = "malformed_response"
	reasonRouteUnbound                = "route_unbound"
	reasonSourceAuthorizationUnproven = "source_authorization_unproven"
)

// Terminal source names from the frozen event detail enum.
const (
	sourceMihomoAPI = "mihomo_api"
)

var (
	uuidV4Pattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	agentVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)
	kernelPattern       = regexp.MustCompile(`^[0-9A-Za-z.+-]+$`)
	counterEpochPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// ErrInvalidReportContext reports that the host supplied runtime identity or
// timestamp values that cannot be embedded in a frozen-contract body. It never
// carries payload or secret content.
var ErrInvalidReportContext = errors.New("windowsagent: invalid report context")

// RouteObserver is one injected operator-local read-only terminal route source.
//
// The two methods are sampled independently because the centre authorizes
// selection (`terminal`) and active connections (`mihomo_api`) separately. The
// shipped *windowsobs.Observer implements this interface; a future R2 truly
// read-only local source must implement the same two methods. An observer is
// nil by default: no local source is configured and no network/file access is
// attempted.
type RouteObserver interface {
	ObserveSelection(ctx context.Context) windowsobs.Selection
	ObserveActive(ctx context.Context) windowsobs.Active
}

// Options configures a Windows terminal collector. The zero value is a valid
// collector with no terminal source and contract-valid default identity.
type Options struct {
	// AgentVersion is the node agent release version (contract form 1.2.3).
	// Empty uses DefaultAgentVersion.
	AgentVersion string
	// Uptime returns the agent process uptime in seconds. It is evaluated per
	// report; nil reports 0.
	Uptime func() int64
	// CounterEpoch is the 32-lowercase-hex counter rotation epoch supplied by the
	// runtime. Empty derives a stable opaque value from the centre-issued device
	// salt when a report is built.
	CounterEpoch string
	// Observer is the explicitly injected operator-local terminal route source.
	// nil means no local source is configured; nothing is sampled.
	Observer RouteObserver
}

// Collector implements agent.Collector for a windows_terminal node.
type Collector struct {
	version      string
	uptime       func() int64
	counterEpoch string
	observer     RouteObserver
}

// Compile-time interface assertions.
var (
	_ agent.Collector = (*Collector)(nil)
	_ RouteObserver   = (*windowsobs.Observer)(nil)
)

// New validates the options and creates a read-only Windows terminal collector.
func New(opts Options) (*Collector, error) {
	version := opts.AgentVersion
	if version == "" {
		version = DefaultAgentVersion
	}
	if !agentVersionPattern.MatchString(version) || len(version) > 32 {
		return nil, fmt.Errorf("%w: agent version must be semver-like", ErrInvalidReportContext)
	}
	counterEpoch := opts.CounterEpoch
	if counterEpoch != "" && !counterEpochPattern.MatchString(counterEpoch) {
		return nil, fmt.Errorf("%w: counter epoch must be 32 lowercase hex characters", ErrInvalidReportContext)
	}
	return &Collector{
		version:      version,
		uptime:       opts.Uptime,
		counterEpoch: counterEpoch,
		observer:     opts.Observer,
	}, nil
}

// Snapshot builds one contract-valid windows_terminal snapshot body.
func (c *Collector) Snapshot(ctx context.Context, rc agent.ReportContext) ([]byte, error) {
	if err := validateReportContext(rc); err != nil {
		return nil, err
	}
	host, err := hostBody(rc.Host)
	if err != nil {
		return nil, err
	}
	body := snapshotBody{
		V:            reportBodyV,
		Type:         "snapshot",
		ReportID:     rc.ReportID,
		CollectedAt:  rc.CollectedAt,
		Agent:        agentInfo{Version: c.version, UptimeS: c.uptimeSeconds()},
		Host:         host,
		Availability: unavailableAvailability(),
		CounterEpoch: c.counterEpochFor(rc),
		System:       systemBody{},
		Services:     []serviceBody{},
		Protocols:    []protocolBody{},
		Traffic:      []trafficBody{},
		Clients:      clientsBody{Summaries: []clientSummaryBody{}},
	}
	body.Terminal = c.terminalObject(ctx, rc)
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, errors.New("windowsagent: cannot encode snapshot body")
	}
	return encoded, nil
}

// Metrics always returns agent.ErrUnsupported: per-minute Windows terminal
// metrics are deferred in frozen contract v1 (the centre rejects the report
// kind for windows_terminal).
func (c *Collector) Metrics(context.Context, agent.ReportContext) ([]byte, error) {
	return nil, agent.ErrUnsupported
}

// Events builds one contract-valid generic terminal events body. It never
// probes a source; it reports the locally known authorization state only.
func (c *Collector) Events(_ context.Context, rc agent.ReportContext) ([]byte, error) {
	if err := validateReportContext(rc); err != nil {
		return nil, err
	}
	events := []eventBody{{
		Kind:     "agent_started",
		Severity: "info",
		Detail:   agentStartedDetail{AgentVersion: c.version},
	}}
	// terminal_source_unavailable is a Windows-terminal-only event kind and the
	// centre requires the `terminal` source switch before accepting it. Emit it
	// only when the authorized source is not configured locally, which is the
	// honest reason code available without a live probe.
	if rc.Config.Sources["terminal"] && c.observer == nil {
		events = append(events, eventBody{
			Kind:     "terminal_source_unavailable",
			Severity: "warning",
			Detail: terminalSourceUnavailableDetail{
				Source:     sourceMihomoAPI,
				ReasonCode: reasonSourceAuthorizationUnproven,
			},
		})
	}
	for index := range events {
		id, err := newUUIDv4()
		if err != nil {
			return nil, errors.New("windowsagent: cannot generate event id")
		}
		events[index].EventID = id
		events[index].At = rc.CollectedAt
	}
	body := eventsBody{
		V:           reportBodyV,
		Type:        "events",
		ReportID:    rc.ReportID,
		CollectedAt: rc.CollectedAt,
		Events:      events,
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, errors.New("windowsagent: cannot encode events body")
	}
	return encoded, nil
}

// terminalObject returns the terminal object, or nil when no terminal source is
// authorized (frozen H1 default-config absence).
func (c *Collector) terminalObject(ctx context.Context, rc agent.ReportContext) *terminalBody {
	selectionAuthorized := rc.Config.Sources["terminal"]
	activeAuthorized := rc.Config.Sources["mihomo_api"]
	if !selectionAuthorized && !activeAuthorized {
		return nil
	}
	fallbackAt := rc.CollectedAt
	terminal := &terminalBody{
		Selection:         unavailableSelection(fallbackAt, reasonSourceAuthorizationUnproven),
		ActiveConnections: unavailableConnections(fallbackAt),
	}
	if selectionAuthorized && c.observer != nil {
		terminal.Selection = selectionFromObservation(c.observer.ObserveSelection(ctx), fallbackAt)
	}
	if activeAuthorized && c.observer != nil {
		terminal.ActiveConnections = connectionsFromObservation(c.observer.ObserveActive(ctx), fallbackAt)
	}
	return terminal
}

// uptimeSeconds evaluates and bounds the injected uptime function.
func (c *Collector) uptimeSeconds() int64 {
	if c.uptime == nil {
		return 0
	}
	uptime := c.uptime()
	switch {
	case uptime < 0:
		return 0
	case uptime > maxUptimeSeconds:
		return maxUptimeSeconds
	default:
		return uptime
	}
}

// counterEpochFor returns the runtime-supplied counter epoch, or a stable
// opaque 32-hex epoch derived from the centre-issued device salt. The salt
// itself is never embedded or returned.
func (c *Collector) counterEpochFor(rc agent.ReportContext) string {
	if c.counterEpoch != "" {
		return c.counterEpoch
	}
	digest := sha256.Sum256([]byte("um-b3-terminal-counter-epoch\x00" + rc.Config.DeviceSalt))
	return hex.EncodeToString(digest[:counterEpochLength/2])
}

// validateReportContext rejects identity/timestamp inputs that cannot form a
// frozen-contract body.
func validateReportContext(rc agent.ReportContext) error {
	if !uuidV4Pattern.MatchString(rc.ReportID) {
		return fmt.Errorf("%w: report_id must be a canonical lowercase uuidv4", ErrInvalidReportContext)
	}
	if rc.CollectedAt < 0 || rc.CollectedAt > maxCollectedAt {
		return fmt.Errorf("%w: collected_at is outside the frozen numeric bounds", ErrInvalidReportContext)
	}
	return nil
}

// hostBody validates and projects the frozen host object.
func hostBody(host agent.HostInfo) (hostInfo, error) {
	if host.OS != "windows" {
		return hostInfo{}, fmt.Errorf("%w: windows_terminal requires host.os=windows", ErrInvalidReportContext)
	}
	if host.Kernel == "" || len(host.Kernel) > 64 || !kernelPattern.MatchString(host.Kernel) {
		return hostInfo{}, fmt.Errorf("%w: host.kernel is not a contract kernel string", ErrInvalidReportContext)
	}
	switch host.Arch {
	case "amd64", "arm64":
	default:
		return hostInfo{}, fmt.Errorf("%w: host.arch must be amd64 or arm64", ErrInvalidReportContext)
	}
	return hostInfo{OS: host.OS, Kernel: host.Kernel, Arch: host.Arch}, nil
}

// frozenReasonCode maps an observer reason to the frozen closed enum. Unknown,
// empty or free-form values are downgraded instead of being echoed.
func frozenReasonCode(reason string) string {
	switch reason {
	case reasonControllerUnreachable, reasonControllerAuth, reasonMalformedResponse,
		reasonRouteUnbound, reasonSourceAuthorizationUnproven:
		return reason
	default:
		return reasonMalformedResponse
	}
}

// frozenRouteToken reports whether role is one of the six frozen tokens.
func frozenRouteToken(role windowsobs.Role) (string, bool) {
	for _, token := range windowsobs.Tokens() {
		if role == token {
			return string(token), true
		}
	}
	return "", false
}

// unavailableAvailability is the honest Windows base availability triple set.
func unavailableAvailability() availabilitySet {
	return availabilitySet{
		System:    "unavailable",
		Services:  "unavailable",
		Protocols: "unavailable",
		Traffic:   "unavailable",
		Clients:   "unavailable",
	}
}

// selectionFromObservation maps the independently sampled route selection to
// the frozen selection object. It never emits a token outside the six frozen
// tokens and never guesses direct.
func selectionFromObservation(selection windowsobs.Selection, fallbackAt int64) selectionBody {
	sampledAt := sampledAtOr(selection.SampledAt, fallbackAt)
	if selection.State == windowsobs.StateObserved {
		if token, ok := frozenRouteToken(selection.Role); ok && token != string(windowsobs.UnknownRoute) {
			return selectionBody{Availability: "ok", SampledAt: sampledAt, Route: stringPtr(token)}
		}
		// Observed but unbound/unknown: the frozen vocabulary has an explicit
		// unknown token; partial signals that the classification is incomplete.
		return unknownRouteSelection(sampledAt)
	}
	if selection.State == windowsobs.StateUnknown && selection.Reason == windowsobs.ReasonRouteUnbound {
		// The source answered but the observed path cannot be bound to exactly
		// one local route: classify it with the frozen unknown token, never
		// direct and never a fabricated concrete route.
		return unknownRouteSelection(sampledAt)
	}
	return selectionBody{
		Availability: "unavailable",
		SampledAt:    sampledAt,
		ReasonCode:   stringPtr(frozenReasonCode(selection.Reason)),
	}
}

// connectionsFromObservation maps the independently sampled open-connection
// aggregate to the frozen active_connections object. Every accepted sample
// carries exactly six non-null token counts with total == sum.
func connectionsFromObservation(active windowsobs.Active, fallbackAt int64) connectionsBody {
	sampledAt := sampledAtOr(active.SampledAt, fallbackAt)
	counts, total, ok := sanitizeConnectionCounts(active)
	if !ok {
		return unavailableConnections(sampledAt)
	}
	return connectionsBody{
		Availability: "ok",
		SampledAt:    sampledAt,
		Total:        &total,
		ByRoute:      counts,
	}
}

// sanitizeConnectionCounts validates an observed aggregate before it reaches
// the wire: every count must be a non-negative integer within the frozen bound
// and the total must stay in range. A sample that cannot be proven is reported
// unavailable instead of fabricating zeros.
func sanitizeConnectionCounts(active windowsobs.Active) (map[string]*int64, int64, bool) {
	if active.State != windowsobs.StateObserved || active.Unknown == nil || *active.Unknown < 0 {
		return nil, 0, false
	}
	counts := make(map[string]*int64, len(windowsobs.Tokens()))
	var total int64
	for _, token := range windowsobs.Tokens() {
		var count int
		if token == windowsobs.UnknownRoute {
			count = *active.Unknown
		} else {
			count = active.Counts[token]
		}
		if count < 0 || count > maxRouteCount {
			return nil, 0, false
		}
		total += int64(count)
		if total > maxRouteCount {
			return nil, 0, false
		}
		counts[string(token)] = int64Ptr(int64(count))
	}
	return counts, total, true
}

// unknownRouteSelection is the observed-but-unresolvable selection shape: the
// frozen unknown token with partial availability (the contract's partial rule
// explicitly covers unknown values) and no fabricated reason.
func unknownRouteSelection(sampledAt int64) selectionBody {
	return selectionBody{
		Availability: "partial",
		SampledAt:    sampledAt,
		Route:        stringPtr(string(windowsobs.UnknownRoute)),
	}
}

// unavailableSelection is the honest unavailable selection object with a
// non-null frozen reason code.
func unavailableSelection(sampledAt int64, reason string) selectionBody {
	return selectionBody{
		Availability: "unavailable",
		SampledAt:    sampledAt,
		ReasonCode:   stringPtr(frozenReasonCode(reason)),
	}
}

// unavailableConnections is the honest all-null active_connections object.
func unavailableConnections(sampledAt int64) connectionsBody {
	counts := make(map[string]*int64, len(windowsobs.Tokens()))
	for _, token := range windowsobs.Tokens() {
		counts[string(token)] = nil
	}
	return connectionsBody{Availability: "unavailable", SampledAt: sampledAt, ByRoute: counts}
}

func sampledAtOr(sampledAt, fallback int64) int64 {
	if sampledAt <= 0 {
		return fallback
	}
	return sampledAt
}

func stringPtr(value string) *string { return &value }

func int64Ptr(value int64) *int64 { return &value }

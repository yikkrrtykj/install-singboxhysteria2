package linuxobs

// Revision-7 read-only traffic export ingestion.
//
// The Linux agent never talks to a sing-box/monitor API and never receives a
// service.api credential. Instead a separately deployed, non-root monitor-v2
// writes a restricted atomic JSON export to a local fixed path; the agent reads
// that file read-only on each snapshot when (and only when) the center config
// enables collect.monitor_export and the operator configured
// --monitor-export-file / UM_AGENT_MONITOR_EXPORT_FILE locally.
//
// The export carries per-inbound OBSERVED LOWER-BOUND bytes relative to the
// monitor observation epoch, observed rates, freshness metadata and an
// independent source_epoch/sequence pair. The agent validates the file strictly,
// never invents zeros, never reuses an older export as fresh, and emits the
// frozen rev-7 traffic_observation object. If the source is disabled by the
// center config, the snapshot body stays byte-identical to the rev-5 body.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/agent"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/schema"
)

// Frozen monitor export contract tokens and bounds.
const (
	monitorExportSchema        = "singbox-monitor-traffic-export"
	monitorExportSchemaVersion = 1
	monitorExportSource        = "monitor-v2"
	monitorExportSourceToken   = "monitor_readonly_export"

	maxMonitorExportBytes = int64(64 << 10)

	// monitorFreshMinAgeSeconds is the floor of the frozen freshness bound
	// fresh iff age <= max(2*cadence_seconds, 120). The runtime computes the
	// effective bound from the signed center config cadence.
	monitorFreshMinAgeSeconds = int64(120)
	// monitorFreshMaxAgeSeconds is the contract's maximum freshness bound for a
	// 300 s cadence (2*300 = 600); it is a defensive upper clamp.
	monitorFreshMaxAgeSeconds = int64(600)
	// monitorFutureToleranceSeconds is the small clock-skew allowance for
	// observed/generated timestamps relative to collected_at.
	monitorFutureToleranceSeconds = int64(5)
	// monitorMaxAgeSeconds bounds how old an export may be before it is
	// unusable even as stale lower-bound data.
	monitorMaxAgeSeconds = int64(86400)
	// monitorMaxRateBps/monitorMaxRateWindowSeconds/monitorMaxActiveConns are the
	// frozen traversal bounds shared with the report contract.
	monitorMaxRateBps           = 1e12
	monitorMaxRateWindowSeconds = 3600.0
	// monitorMaxCohortSeconds bounds generated_at-observed_at coherence.
	monitorMaxCohortSeconds = int64(86400)
)

var (
	monitorExportSourceEpochRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
	// monitorExportRequiredFields is the exact closed top-level member set. The
	// export is a restricted monitor-v2 output; unknown members (IDs, users, IPs
	// or any other privacy sentinel) are rejected instead of ignored.
	monitorExportRequiredFields = []string{
		"schema", "schema_version", "source", "source_epoch", "sequence",
		"generated_at", "observed_at", "monitor_stale",
		"monitor_last_success_at", "counter_scope", "exactness",
		"active_connections", "rate_window_seconds", "inbounds",
	}
	monitorExportInboundFields = []string{
		"inbound_tag", "kind", "observed_uplink_bytes", "observed_downlink_bytes",
		"uplink_observed_rate_bps", "downlink_observed_rate_bps",
		"active_connections", "observed_at", "quality",
	}
)

// Errors returned by the guarded export reader. They are internal: the emitted
// report only carries freshness=unavailable, never a path or reason string.
var (
	errMonitorExportPathInvalid = errors.New("linuxobs: monitor export path is not a fixed absolute path")
	errMonitorExportNotRegular  = errors.New("linuxobs: monitor export path is not a regular file")
	errMonitorExportTooLarge    = errors.New("linuxobs: monitor export exceeds the bounded read size")
	errMonitorExportEmpty       = errors.New("linuxobs: monitor export file is empty")
)

// monitorTrafficExport is the strict on-disk monitor-v2 export shape.
type monitorTrafficExport struct {
	Schema               string                  `json:"schema"`
	SchemaVersion        int                     `json:"schema_version"`
	Source               string                  `json:"source"`
	SourceEpoch          string                  `json:"source_epoch"`
	Sequence             int64                   `json:"sequence"`
	GeneratedAt          int64                   `json:"generated_at"`
	ObservedAt           int64                   `json:"observed_at"`
	MonitorStale         bool                    `json:"monitor_stale"`
	MonitorLastSuccessAt *int64                  `json:"monitor_last_success_at"`
	CounterScope         string                  `json:"counter_scope"`
	Exactness            string                  `json:"exactness"`
	ActiveConnections    *int64                  `json:"active_connections"`
	RateWindowSeconds    *float64                `json:"rate_window_seconds"`
	Inbounds             []monitorTrafficInbound `json:"inbounds"`
}

// monitorTrafficInbound is one per-inbound export entry.
type monitorTrafficInbound struct {
	InboundTag              string   `json:"inbound_tag"`
	Kind                    string   `json:"kind"`
	ObservedUplinkBytes     *int64   `json:"observed_uplink_bytes"`
	ObservedDownlinkBytes   *int64   `json:"observed_downlink_bytes"`
	UplinkObservedRateBps   *float64 `json:"uplink_observed_rate_bps"`
	DownlinkObservedRateBps *float64 `json:"downlink_observed_rate_bps"`
	ActiveConnections       int64    `json:"active_connections"`
	ObservedAt              int64    `json:"observed_at"`
	Quality                 string   `json:"quality"`
}

// trafficObservationBody is the rev-7 snapshot traffic_observation object. It
// is emitted only for a linux_vps snapshot whose center config enables
// collect.monitor_export; everything below is copied from validated observation
// data, never invented.
type trafficObservationBody struct {
	Source            string                      `json:"source"`
	SourceEpoch       string                      `json:"source_epoch"`
	Sequence          int64                       `json:"sequence"`
	ObservedAt        int64                       `json:"observed_at"`
	AgeSeconds        int64                       `json:"age_seconds"`
	Freshness         string                      `json:"freshness"`
	Availability      string                      `json:"availability"`
	CounterScope      string                      `json:"counter_scope"`
	Exactness         string                      `json:"exactness"`
	ActiveConnections *int64                      `json:"active_connections"`
	RateWindowSeconds *float64                    `json:"rate_window_seconds"`
	Inbounds          []trafficInboundObservation `json:"inbounds"`
}

// trafficInboundObservation is one rev-7 per-inbound lower-bound observation.
type trafficInboundObservation struct {
	InboundTag                      string   `json:"inbound_tag"`
	Kind                            string   `json:"kind"`
	ObservedAt                      int64    `json:"observed_at"`
	Availability                    string   `json:"availability"`
	Quality                         string   `json:"quality"`
	UplinkObservedLowerBoundBytes   *int64   `json:"uplink_observed_lower_bound_bytes"`
	DownlinkObservedLowerBoundBytes *int64   `json:"downlink_observed_lower_bound_bytes"`
	UplinkObservedRateBps           *float64 `json:"uplink_observed_rate_bps"`
	DownlinkObservedRateBps         *float64 `json:"downlink_observed_rate_bps"`
	ActiveConnections               int64    `json:"active_connections"`
}

// monitorExportTracker is the in-memory monotonic guard. It is intentionally not
// persisted: after an agent restart the first export is accepted if otherwise
// valid, and the guard then prevents replay/regression within the process
// lifetime. It is never used as a data source.
type monitorExportTracker struct {
	mu          sync.Mutex
	seen        bool
	sourceEpoch string
	sequence    int64
	observedAt  int64
}

// ValidateMonitorExportPath enforces the operator-local fixed absolute path
// contract. The path is never center-controlled; a relative path, a path with
// traversal components or a non-absolute path is a startup configuration error.
func ValidateMonitorExportPath(path string) error {
	if path == "" {
		return nil
	}
	if !filepath.IsAbs(path) {
		return errMonitorExportPathInvalid
	}
	if filepath.Clean(path) != path {
		return errMonitorExportPathInvalid
	}
	if len(path) > 4096 {
		return errMonitorExportPathInvalid
	}
	return nil
}

// readMonitorExportFile reads the configured export with a bounded read and
// rejects symlinks, non-regular files and oversized contents. Every read is
// checked, so a file replaced after startup is re-validated.
func readMonitorExportFile(path string, expectedOwnerUID, expectedGroupGID int, expectedMode uint32) ([]byte, error) {
	if err := ValidateMonitorExportPath(path); err != nil {
		return nil, err
	}
	// Reject a symlinked parent or final component. The unix open path also uses
	// O_NOFOLLOW for the final component, so a swap between Lstat and Open cannot
	// follow a symlink there; checking every ancestor closes the parent-directory
	// redirection variant before the bounded read.
	clean := filepath.Clean(path)
	for current := clean; ; current = filepath.Dir(current) {
		component, statErr := os.Lstat(current)
		if statErr != nil {
			return nil, statErr
		}
		if component.Mode()&os.ModeSymlink != 0 {
			return nil, errMonitorExportNotRegular
		}
		if parent := filepath.Dir(current); parent == current {
			break
		}
	}
	// Reject a symlink final component before opening. The unix open path also
	// uses O_NOFOLLOW, so the check cannot be bypassed by a swap between Lstat
	// and Open.
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errMonitorExportNotRegular
	}
	file, err := openMonitorExportFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() {
		return nil, errMonitorExportNotRegular
	}
	// POSIX permissions are meaningful only on Unix; Windows ACLs are checked by
	// the OS group/ACL deployment, and Go reports synthetic modes there.
	if runtime.GOOS != "windows" {
		if opened.Mode().Perm()&0o007 != 0 {
			return nil, errMonitorExportNotRegular
		}
		if expectedMode != 0 && uint32(opened.Mode().Perm()) != expectedMode {
			return nil, errMonitorExportNotRegular
		}
		if expectedOwnerUID != 0 || expectedGroupGID != 0 {
			uid, gid, ok := monitorExportPOSIXOwner(opened)
			if !ok {
				return nil, errMonitorExportNotRegular
			}
			if expectedOwnerUID != 0 && uid != uint32(expectedOwnerUID) {
				return nil, errMonitorExportNotRegular
			}
			if expectedGroupGID != 0 && gid != uint32(expectedGroupGID) {
				return nil, errMonitorExportNotRegular
			}
		}
	}
	if opened.Size() > maxMonitorExportBytes {
		return nil, errMonitorExportTooLarge
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxMonitorExportBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxMonitorExportBytes {
		return nil, errMonitorExportTooLarge
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, errMonitorExportEmpty
	}
	return raw, nil
}

// parseMonitorExport strictly decodes and validates the export. Unknown members
// are rejected (the export is not an extensible carrier for IDs/IPs/users/raw
// data), numeric bounds are checked without float conversion of byte counters.
func parseMonitorExport(raw []byte) (*monitorTrafficExport, error) {
	// Strict JSON first: duplicate member names and trailing data are forbidden,
	// not silently resolved by encoding/json.
	if err := schema.CheckStrictJSON(raw); err != nil {
		return nil, err
	}
	// Presence of every required member is checked before typed decoding because
	// encoding/json does not distinguish "absent" from the zero value.
	var members map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&members); err != nil {
		return nil, err
	}
	if members == nil {
		return nil, errors.New("linuxobs: monitor export is not a JSON object")
	}
	for _, field := range monitorExportRequiredFields {
		if _, ok := members[field]; !ok {
			return nil, fmt.Errorf("linuxobs: monitor export is missing a required member")
		}
	}
	// Every inbound entry is also a closed object with an exact required member
	// set: a missing counter member must never be read as "null/unobserved".
	var inboundMembers []map[string]json.RawMessage
	if err := json.Unmarshal(members["inbounds"], &inboundMembers); err != nil {
		return nil, err
	}
	for _, entry := range inboundMembers {
		for _, field := range monitorExportInboundFields {
			if _, ok := entry[field]; !ok {
				return nil, fmt.Errorf("linuxobs: monitor export inbound entry is missing a required member")
			}
		}
	}
	var export monitorTrafficExport
	typed := json.NewDecoder(bytes.NewReader(raw))
	typed.DisallowUnknownFields()
	if err := typed.Decode(&export); err != nil {
		return nil, err
	}
	if err := ensureNoTrailingJSON(typed); err != nil {
		return nil, err
	}
	if err := validateMonitorExport(&export); err != nil {
		return nil, err
	}
	return &export, nil
}

func ensureNoTrailingJSON(dec *json.Decoder) error {
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("linuxobs: monitor export has trailing data")
	}
	return nil
}

// validateMonitorExport applies the frozen export bounds and coherence rules.
func validateMonitorExport(export *monitorTrafficExport) error {
	if export.Schema != monitorExportSchema || export.SchemaVersion != monitorExportSchemaVersion ||
		export.Source != monitorExportSource {
		return errors.New("linuxobs: unsupported monitor export schema/version/source")
	}
	if !monitorExportSourceEpochRE.MatchString(export.SourceEpoch) {
		return errors.New("linuxobs: monitor export source_epoch is not 32 lowercase hex")
	}
	if export.Sequence < 0 || export.Sequence > maxContractCounter {
		return errors.New("linuxobs: monitor export sequence is outside the safe integer range")
	}
	if export.GeneratedAt < 0 || export.GeneratedAt > maxContractTimestamp ||
		export.ObservedAt < 0 || export.ObservedAt > maxContractTimestamp {
		return errors.New("linuxobs: monitor export timestamp is outside the frozen bounds")
	}
	if export.ObservedAt > export.GeneratedAt {
		return errors.New("linuxobs: monitor export observed_at is after generated_at")
	}
	if export.GeneratedAt-export.ObservedAt > monitorMaxCohortSeconds {
		return errors.New("linuxobs: monitor export generated/observed timestamps are incoherent")
	}
	if export.MonitorStale {
		if export.MonitorLastSuccessAt != nil && *export.MonitorLastSuccessAt > export.GeneratedAt {
			return errors.New("linuxobs: monitor export last success is in the future")
		}
	} else if export.MonitorLastSuccessAt == nil {
		return errors.New("linuxobs: monitor export claims fresh data without a last success timestamp")
	} else if *export.MonitorLastSuccessAt > export.GeneratedAt {
		return errors.New("linuxobs: monitor export last success is in the future")
	}
	if export.CounterScope != trafficCounterScopeObservationEpoch || export.Exactness != trafficExactnessLowerBound {
		return errors.New("linuxobs: monitor export counter scope/exactness token is unsupported")
	}
	if export.ActiveConnections != nil &&
		(*export.ActiveConnections < 0 || *export.ActiveConnections > maxContractActiveConns) {
		return errors.New("linuxobs: monitor export active_connections is outside the frozen bound")
	}
	if err := validateMonitorRateWindow(export.RateWindowSeconds); err != nil {
		return err
	}
	if len(export.Inbounds) > maxContractArrayItems {
		return errors.New("linuxobs: monitor export carries too many inbounds")
	}
	seen := make(map[string]struct{}, len(export.Inbounds))
	var activeSum int64
	anyRate := false
	for index := range export.Inbounds {
		inbound := &export.Inbounds[index]
		if !inboundTagPattern.MatchString(inbound.InboundTag) || len(inbound.InboundTag) > 64 {
			return errors.New("linuxobs: monitor export inbound tag is not contract-shaped")
		}
		if _, duplicate := seen[inbound.InboundTag]; duplicate {
			return errors.New("linuxobs: monitor export carries a duplicate inbound tag")
		}
		seen[inbound.InboundTag] = struct{}{}
		switch inbound.Kind {
		case "reality", "hysteria2", "other":
		default:
			return errors.New("linuxobs: monitor export carries an unknown inbound kind")
		}
		if inbound.ObservedAt < 0 || inbound.ObservedAt > export.GeneratedAt+monitorFutureToleranceSeconds ||
			inbound.ObservedAt < export.GeneratedAt-monitorMaxCohortSeconds {
			return errors.New("linuxobs: monitor export inbound observed_at is outside the observation window")
		}
		if inbound.ActiveConnections < 0 || inbound.ActiveConnections > maxContractActiveConns {
			return errors.New("linuxobs: monitor export inbound active_connections is outside the frozen bound")
		}
		if activeSum > maxContractActiveConns-inbound.ActiveConnections {
			return errors.New("linuxobs: monitor export active connection sum exceeds the frozen bound")
		}
		activeSum += inbound.ActiveConnections
		if err := validateMonitorCounters(*inbound); err != nil {
			return err
		}
		switch inbound.Quality {
		case "lower_bound":
			if inbound.ObservedUplinkBytes == nil || inbound.ObservedDownlinkBytes == nil {
				return errors.New("linuxobs: lower_bound export entry requires both byte counters")
			}
		case "partial":
			// A partial quality entry means the monitor could not produce every
			// sample (stale monitor, over-range/absent counter, unsupported rate
			// window). Null counters are honest here; only "unavailable" requires
			// every value to be absent, and "lower_bound" requires both counters.
		case "unavailable":
			if inbound.ObservedUplinkBytes != nil || inbound.ObservedDownlinkBytes != nil ||
				inbound.UplinkObservedRateBps != nil || inbound.DownlinkObservedRateBps != nil {
				return errors.New("linuxobs: unavailable export entry carries observed data")
			}
		default:
			return errors.New("linuxobs: monitor export carries an unknown inbound quality")
		}
		if inbound.UplinkObservedRateBps != nil || inbound.DownlinkObservedRateBps != nil {
			anyRate = true
		}
	}
	if anyRate && export.RateWindowSeconds == nil {
		return errors.New("linuxobs: monitor export carries rates without a rate window")
	}
	if export.ActiveConnections != nil && *export.ActiveConnections < activeSum {
		return errors.New("linuxobs: monitor export total active count is inconsistent with its inbounds")
	}
	return nil
}

func validateMonitorCounters(inbound monitorTrafficInbound) error {
	for _, counter := range []*int64{inbound.ObservedUplinkBytes, inbound.ObservedDownlinkBytes} {
		if counter == nil {
			continue
		}
		if *counter < 0 || *counter > maxContractCounter {
			return errors.New("linuxobs: monitor export byte counter is outside the safe integer range")
		}
	}
	for _, rate := range []*float64{inbound.UplinkObservedRateBps, inbound.DownlinkObservedRateBps} {
		if rate == nil {
			continue
		}
		if math.IsNaN(*rate) || math.IsInf(*rate, 0) || *rate < 0 || *rate > monitorMaxRateBps {
			return errors.New("linuxobs: monitor export observed rate is outside the frozen bounds")
		}
	}
	return nil
}

func validateMonitorRateWindow(window *float64) error {
	if window == nil {
		return nil
	}
	if math.IsNaN(*window) || math.IsInf(*window, 0) || *window <= 0 || *window > monitorMaxRateWindowSeconds {
		return errors.New("linuxobs: monitor export rate_window_seconds is outside (0,3600]")
	}
	return nil
}

// trafficObservation projects the optional read-only export into the rev-7
// object. It is called only when the center config enables collect.monitor_export
// and never fails the snapshot: any missing/invalid/stale/replayed data degrades
// to an honest unavailable/partial observation with null counters.
func (c *Collector) trafficObservation(rc agent.ReportContext) *trafficObservationBody {
	collectedAt := rc.CollectedAt
	unavailable := unavailableTrafficObservation(collectedAt)
	if c.MonitorExportFile == "" {
		return unavailable
	}
	raw, err := readMonitorExportFile(c.MonitorExportFile, c.MonitorExportOwnerUID, c.MonitorExportGroupGID, c.MonitorExportMode)
	if err != nil {
		return unavailable
	}
	export, err := parseMonitorExport(raw)
	if err != nil {
		return unavailable
	}
	// The export must describe the same time window as the snapshot. An export
	// observed in the future beyond the skew tolerance, or older than the
	// maximum age, is unusable rather than "fresh".
	age := collectedAt - export.ObservedAt
	if age < -monitorFutureToleranceSeconds || age > monitorMaxAgeSeconds {
		return unavailable
	}
	if age < 0 {
		age = 0
	}
	if export.MonitorLastSuccessAt != nil && *export.MonitorLastSuccessAt > collectedAt+monitorFutureToleranceSeconds {
		return unavailable
	}
	expected := authorizedInboundTags(rc.Config.ExpectedTags)
	if len(expected) == 0 {
		return unavailable
	}
	byTag := make(map[string]*monitorTrafficInbound, len(export.Inbounds))
	for index := range export.Inbounds {
		byTag[export.Inbounds[index].InboundTag] = &export.Inbounds[index]
	}
	// Only center-authorized tags may be forwarded. An export may legitimately
	// contain a superset while the center allow-list is narrower (operator
	// config drift or a tag removed in a staged change): drop non-matching
	// entries and forward only the authorized subset. Never leak an unapproved
	// tag or kind downstream.
	for tag, inbound := range byTag {
		allowedKind, ok := expectedKind(expected, tag)
		if !ok || allowedKind != inbound.Kind {
			delete(byTag, tag)
		}
	}
	// In-memory monotonic guard. It is advanced only for a fully acceptable
	// observation, so a malformed/unknown-tag publication cannot poison the next
	// cycle with a false sequence regression. A stale file or a sequence
	// regression is never reused as fresh.
	if !c.monitorExport.accept(export) {
		return unavailable
	}
	observation := &trafficObservationBody{
		Source:            monitorExportSourceToken,
		SourceEpoch:       export.SourceEpoch,
		Sequence:          export.Sequence,
		ObservedAt:        export.ObservedAt,
		AgeSeconds:        age,
		CounterScope:      trafficCounterScopeObservationEpoch,
		Exactness:         trafficExactnessLowerBound,
		ActiveConnections: cloneInt64(export.ActiveConnections),
		RateWindowSeconds: cloneFloat64(export.RateWindowSeconds),
		Inbounds:          make([]trafficInboundObservation, 0, len(expected)),
	}
	observed := 0
	allLowerBound := true
	for _, tag := range expected {
		inbound, present := byTag[tag.tag]
		entry := trafficInboundObservation{
			InboundTag:        tag.tag,
			Kind:              tag.kind,
			ObservedAt:        export.ObservedAt,
			Availability:      availabilityUnavailable,
			Quality:           "unavailable",
			ActiveConnections: 0,
		}
		if present {
			entry.ObservedAt = inbound.ObservedAt
			entry.ActiveConnections = inbound.ActiveConnections
			entry.UplinkObservedLowerBoundBytes = cloneInt64(inbound.ObservedUplinkBytes)
			entry.DownlinkObservedLowerBoundBytes = cloneInt64(inbound.ObservedDownlinkBytes)
			entry.UplinkObservedRateBps = cloneFloat64(inbound.UplinkObservedRateBps)
			entry.DownlinkObservedRateBps = cloneFloat64(inbound.DownlinkObservedRateBps)
			switch inbound.Quality {
			case "lower_bound":
				entry.Availability = availabilityOK
				entry.Quality = "lower_bound"
				observed++
			case "partial":
				entry.Availability = availabilityPartial
				entry.Quality = "partial"
				allLowerBound = false
				observed++
			default:
				// unavailable quality keeps the honest unavailable/null entry.
				entry.UplinkObservedLowerBoundBytes = nil
				entry.DownlinkObservedLowerBoundBytes = nil
				entry.UplinkObservedRateBps = nil
				entry.DownlinkObservedRateBps = nil
			}
		}
		observation.Inbounds = append(observation.Inbounds, entry)
	}
	freshMaxAge := monitorFreshMinAgeSeconds
	if rc.Config.Cadence > 0 {
		freshMaxAge = int64(2 * rc.Config.Cadence)
		if freshMaxAge < monitorFreshMinAgeSeconds {
			freshMaxAge = monitorFreshMinAgeSeconds
		}
		if freshMaxAge > monitorFreshMaxAgeSeconds {
			freshMaxAge = monitorFreshMaxAgeSeconds
		}
	}
	stale := export.MonitorStale || age > freshMaxAge
	switch {
	case stale && observed > 0:
		observation.Freshness = "stale"
		observation.Availability = availabilityPartial
	case stale:
		// A stale export that observed nothing is honestly unavailable, not a
		// "stale but ok" claim.
		observation.Freshness = "unavailable"
		observation.Availability = availabilityUnavailable
		observation.ActiveConnections = nil
		observation.RateWindowSeconds = nil
		observation.Inbounds = make([]trafficInboundObservation, 0)
	case observed == 0:
		// A fresh file that observed nothing is honestly unavailable.
		observation.Freshness = "unavailable"
		observation.Availability = availabilityUnavailable
		observation.ActiveConnections = nil
		observation.RateWindowSeconds = nil
		observation.Inbounds = make([]trafficInboundObservation, 0)
	case observed < len(expected) || !allLowerBound:
		observation.Freshness = "fresh"
		observation.Availability = availabilityPartial
	default:
		observation.Freshness = "fresh"
		observation.Availability = availabilityOK
	}
	return observation
}

// accept reports whether export advances the in-memory epoch/sequence guard and,
// if so, records it. A same-epoch sequence must strictly increase; an epoch
// change is allowed (monitor restart) only when the observation time does not go
// backwards.
func (t *monitorExportTracker) accept(export *monitorTrafficExport) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.seen {
		if export.SourceEpoch == t.sourceEpoch {
			if export.Sequence <= t.sequence {
				return false
			}
		} else if export.ObservedAt < t.observedAt {
			return false
		}
	}
	t.seen = true
	t.sourceEpoch = export.SourceEpoch
	t.sequence = export.Sequence
	t.observedAt = export.ObservedAt
	return true
}

// unavailableTrafficObservation is the honest "source enabled but no usable
// observation" projection: no counters, no active count, no rate window. The
// all-zero source epoch is the documented unknown epoch token; observed_at is the
// snapshot collection instant because no valid observation timestamp exists.
func unavailableTrafficObservation(collectedAt int64) *trafficObservationBody {
	return &trafficObservationBody{
		Source:       monitorExportSourceToken,
		SourceEpoch:  zeroCounterEpoch,
		Sequence:     0,
		ObservedAt:   0,
		AgeSeconds:   86400,
		Freshness:    "unavailable",
		Availability: availabilityUnavailable,
		CounterScope: trafficCounterScopeObservationEpoch,
		Exactness:    trafficExactnessLowerBound,
		Inbounds:     make([]trafficInboundObservation, 0),
	}
}

func expectedKind(expected []authorizedTag, tag string) (string, bool) {
	for _, entry := range expected {
		if entry.tag == tag {
			return entry.kind, true
		}
	}
	return "", false
}

func cloneInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func cloneFloat64(value *float64) *float64 {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

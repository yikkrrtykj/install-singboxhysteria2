package contract

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
)

// Revision 7 adds an OPTIONAL read-only traffic observation block to a
// linux_vps snapshot. The block carries per-inbound OBSERVED LOWER-BOUND byte
// counters and observed rates read from a restricted, monitor-v2-authored local
// JSON export (source=monitor_readonly_export). It is not a daemon-lifetime
// total and never replaces the frozen rev-5 `traffic` array (which stays empty
// for this source because lower bounds are not totals).
//
// The schema files are authored by the contract change and may be absent from a
// deployment/branch that predates it. The runtime selects the rev-7 schema only
// when the body declares contract_revision=7 and fails closed when the selected
// schema is not loaded.
const (
	// ContractRevision7 is the only contract revision newer than rev 5 that this
	// build understands.
	ContractRevision7 = 7
	// SnapshotRev7SchemaFile is the rev-7 snapshot contract schema file name.
	SnapshotRev7SchemaFile = "report-snapshot.rev7.schema.json"
	// AgentConfigRev7SchemaFile is the rev-7 agent-config schema file name. The
	// rev-7 config only adds the OPTIONAL boolean collect.monitor_export.
	AgentConfigRev7SchemaFile = "agent-config.rev7.schema.json"

	// TrafficSourceMonitorReadonlyExport is the frozen source discriminator.
	TrafficSourceMonitorReadonlyExport = "monitor_readonly_export"
	// TrafficCounterScopeObservationEpoch freezes the counter scope: counters are
	// relative to the monitor observation epoch, not daemon lifetime.
	TrafficCounterScopeObservationEpoch = "observation_epoch"
	// TrafficExactnessLowerBound freezes that bytes are observed lower bounds.
	TrafficExactnessLowerBound = "lower_bound"
)

// Bounded rev-7 traffic values (schema duplicates these; runtime re-checks).
const (
	trafficMaxSafeInteger       = int64(9007199254740991)
	trafficMaxActiveConnections = int64(1000000)
	trafficMaxRateBps           = 1e12
	trafficMaxRateWindowSeconds = 3600
	trafficMaxAgeSeconds        = 86400
	trafficFreshMaxAgeSeconds   = 15
	trafficFutureToleranceSec   = 5
	trafficMaxArrayItems        = 16
)

var trafficSourceEpochRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

const zeroTrafficSourceEpoch = "00000000000000000000000000000000"

// TrafficObservation is the rev-7 snapshot traffic_observation object.
//
// Bytes are integers (never floats) so no precision is lost between the monitor
// export, the agent report and normalized storage. Null means "not observed";
// a lower-bound source never renders an unavailable counter as zero.
type TrafficObservation struct {
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
	Inbounds          []TrafficInboundObservation `json:"inbounds"`
}

// TrafficInboundObservation is one per-inbound lower-bound observation.
type TrafficInboundObservation struct {
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

// ValidateTrafficObservation decodes and validates one rev-7 traffic
// observation against collected_at. Structural closure/typing is enforced by the
// rev-7 JSON schema; this function enforces the coherence rules the schema
// cannot express. It returns the decoded object for normalized storage.
func ValidateTrafficObservation(collectedAt int64, raw json.RawMessage) (*TrafficObservation, error) {
	var obs TrafficObservation
	if err := json.Unmarshal(raw, &obs); err != nil {
		return nil, invalid("traffic_observation", "malformed traffic observation object")
	}
	if err := validateTrafficObservationSemantics(collectedAt, &obs); err != nil {
		return nil, err
	}
	return &obs, nil
}

// validateTrafficObservationSemantics enforces:
//   - frozen source/counter scope/exactness tokens;
//   - safe integer bounds and a 32-hex independent source epoch;
//   - observed_at <= collected_at + 5s (clock skew) and age_seconds recomputable
//     as clamp(collected_at-observed_at, 0, 86400);
//   - freshness/availability coherence: fresh <= 15s and observed, unavailable
//     never observed, stale never fully fresh; counters null unless observed;
//   - per-inbound tags are unique, the kind is a frozen enum, lower_bound quality
//     carries non-null byte counters and every rate is covered by a positive
//     rate window;
//   - the reported observations are not double counted: a total active count, if
//     supplied, must cover the sum of per-inbound active counts.
func validateTrafficObservationSemantics(collectedAt int64, obs *TrafficObservation) error {
	if obs.Source != TrafficSourceMonitorReadonlyExport {
		return invalid("traffic_observation.source", "source must be monitor_readonly_export")
	}
	if !trafficSourceEpochRE.MatchString(obs.SourceEpoch) {
		return invalid("traffic_observation.source_epoch", "source_epoch must be 32 lowercase hex characters")
	}
	if obs.SourceEpoch == zeroTrafficSourceEpoch {
		// The no-observation sentinel is the only legal use of the all-zero
		// source epoch. It is a closed exact shape: no measured data may be
		// smuggled in alongside the sentinel.
		if obs.Sequence != 0 || obs.ObservedAt != 0 || obs.AgeSeconds != trafficMaxAgeSeconds ||
			obs.Freshness != "unavailable" || obs.Availability != "unavailable" ||
			obs.ActiveConnections != nil || obs.RateWindowSeconds != nil || len(obs.Inbounds) != 0 {
			return invalid("traffic_observation", "malformed no-observation sentinel")
		}
		return nil
	}
	if obs.Sequence < 0 || obs.Sequence > trafficMaxSafeInteger {
		return invalid("traffic_observation.sequence", "sequence is outside the safe integer range")
	}
	if obs.CounterScope != TrafficCounterScopeObservationEpoch {
		return invalid("traffic_observation.counter_scope", "counter_scope must be observation_epoch")
	}
	if obs.Exactness != TrafficExactnessLowerBound {
		return invalid("traffic_observation.exactness", "exactness must be lower_bound")
	}
	switch obs.Freshness {
	case "fresh", "stale", "unavailable":
	default:
		return invalid("traffic_observation.freshness", "unknown freshness")
	}
	switch obs.Availability {
	case "ok", "partial", "unavailable":
	default:
		return invalid("traffic_observation.availability", "unknown availability")
	}
	if obs.ObservedAt < 0 || obs.ObservedAt > collectedAt+trafficFutureToleranceSec {
		return invalid("traffic_observation.observed_at", "observed_at is outside the collection window")
	}
	expectedAge := collectedAt - obs.ObservedAt
	if expectedAge < 0 {
		expectedAge = 0
	}
	if expectedAge > trafficMaxAgeSeconds {
		return invalid("traffic_observation.observed_at", "observed_at is older than the maximum age bound")
	}
	if obs.AgeSeconds != expectedAge {
		return invalid("traffic_observation.age_seconds", "age_seconds must equal clamp(collected_at-observed_at, 0)")
	}
	// Freshness/coherence matrix. Stale is legal with a small age because the
	// monitor itself can declare its counters stale; fresh must be recent and
	// observed; unavailable is always fully unavailable.
	switch obs.Freshness {
	case "fresh":
		if obs.AgeSeconds > trafficFreshMaxAgeSeconds {
			return invalid("traffic_observation.age_seconds", "fresh observation age exceeds the fresh bound")
		}
		if obs.Availability == "unavailable" {
			return invalid("traffic_observation.freshness", "fresh observation cannot be unavailable")
		}
	case "stale":
		if obs.Availability == "ok" {
			return invalid("traffic_observation.freshness", "stale observation cannot be fully ok")
		}
	case "unavailable":
		if obs.Availability != "unavailable" {
			return invalid("traffic_observation.freshness", "unavailable freshness requires unavailable availability")
		}
	}
	if obs.Availability == "unavailable" && obs.Freshness != "unavailable" {
		return invalid("traffic_observation.availability", "unavailable availability requires unavailable freshness")
	}
	if err := validateOptionalCount("traffic_observation.active_connections", obs.ActiveConnections, trafficMaxActiveConnections); err != nil {
		return err
	}
	if obs.RateWindowSeconds != nil {
		if math.IsNaN(*obs.RateWindowSeconds) || math.IsInf(*obs.RateWindowSeconds, 0) ||
			*obs.RateWindowSeconds <= 0 || *obs.RateWindowSeconds > trafficMaxRateWindowSeconds {
			return invalid("traffic_observation.rate_window_seconds", "rate_window_seconds is outside (0,3600]")
		}
	}
	if len(obs.Inbounds) > trafficMaxArrayItems {
		return invalid("traffic_observation.inbounds", "too many inbound observations")
	}
	seen := make(map[string]int, len(obs.Inbounds))
	var inboundActiveSum int64
	anyRate := false
	observed := 0
	for index := range obs.Inbounds {
		inbound := &obs.Inbounds[index]
		field := fmt.Sprintf("traffic_observation.inbounds[%d]", index)
		if first, duplicate := seen[inbound.InboundTag]; duplicate {
			return invalid(field+".inbound_tag", fmt.Sprintf("duplicate inbound_tag within one observation (first seen at inbounds[%d])", first))
		}
		seen[inbound.InboundTag] = index
		switch inbound.Kind {
		case "reality", "hysteria2", "other":
		default:
			return invalid(field+".kind", "unknown inbound kind")
		}
		switch inbound.Availability {
		case "ok", "partial", "unavailable":
		default:
			return invalid(field+".availability", "unknown inbound availability")
		}
		switch inbound.Quality {
		case "lower_bound", "partial", "unavailable":
		default:
			return invalid(field+".quality", "unknown inbound quality")
		}
		switch inbound.Availability {
		case "ok":
			if inbound.Quality != "lower_bound" {
				return invalid(field+".quality", "ok inbound availability requires lower_bound quality")
			}
			observed++
		case "partial":
			if inbound.Quality != "partial" {
				return invalid(field+".quality", "partial inbound availability requires partial quality")
			}
			observed++
		case "unavailable":
			if inbound.Quality != "unavailable" {
				return invalid(field+".quality", "unavailable inbound availability requires unavailable quality")
			}
		}
		if inbound.ObservedAt < 0 || inbound.ObservedAt > collectedAt+trafficFutureToleranceSec ||
			inbound.ObservedAt < collectedAt-trafficMaxAgeSeconds {
			return invalid(field+".observed_at", "inbound observed_at is outside the collection window")
		}
		if err := validateOptionalCounter(field+".uplink_observed_lower_bound_bytes", inbound.UplinkObservedLowerBoundBytes); err != nil {
			return err
		}
		if err := validateOptionalCounter(field+".downlink_observed_lower_bound_bytes", inbound.DownlinkObservedLowerBoundBytes); err != nil {
			return err
		}
		switch inbound.Quality {
		case "lower_bound":
			if inbound.UplinkObservedLowerBoundBytes == nil || inbound.DownlinkObservedLowerBoundBytes == nil {
				return invalid(field, "lower_bound inbound quality requires non-null byte counters")
			}
		case "partial":
			// Partial quality means the observation is incomplete, not that a
			// counter must exist: a stale monitor or an over-range counter is
			// published as null with partial quality. Only lower_bound requires
			// both byte counters and unavailable forbids observed values.
		case "unavailable":
			if inbound.UplinkObservedLowerBoundBytes != nil || inbound.DownlinkObservedLowerBoundBytes != nil ||
				inbound.UplinkObservedRateBps != nil || inbound.DownlinkObservedRateBps != nil {
				return invalid(field, "unavailable inbound quality requires null counters and rates")
			}
		}
		if err := validateOptionalRate(field+".uplink_observed_rate_bps", inbound.UplinkObservedRateBps); err != nil {
			return err
		}
		if err := validateOptionalRate(field+".downlink_observed_rate_bps", inbound.DownlinkObservedRateBps); err != nil {
			return err
		}
		if inbound.UplinkObservedRateBps != nil || inbound.DownlinkObservedRateBps != nil {
			anyRate = true
		}
		if inbound.ActiveConnections < 0 || inbound.ActiveConnections > trafficMaxActiveConnections {
			return invalid(field+".active_connections", "active_connections is outside the frozen bound")
		}
		if inboundActiveSum > trafficMaxActiveConnections-inbound.ActiveConnections {
			return invalid(field+".active_connections", "sum of inbound active connections is outside the frozen bound")
		}
		inboundActiveSum += inbound.ActiveConnections
	}
	if anyRate && obs.RateWindowSeconds == nil {
		return invalid("traffic_observation.rate_window_seconds", "observed rates require a rate_window_seconds")
	}
	if obs.ActiveConnections != nil && *obs.ActiveConnections < inboundActiveSum {
		return invalid("traffic_observation.active_connections", "total active connections must cover the per-inbound sum")
	}
	// Availability coherence across the inbound set. "ok" requires every reported
	// inbound fully observed; "partial" needs at least one observed and one
	// unavailable/partial entry; "unavailable" must carry no observed counters.
	switch obs.Availability {
	case "ok":
		if len(obs.Inbounds) == 0 {
			return invalid("traffic_observation.inbounds", "ok observation availability requires at least one inbound")
		}
		for index := range obs.Inbounds {
			inbound := &obs.Inbounds[index]
			field := fmt.Sprintf("traffic_observation.inbounds[%d]", index)
			if inbound.Availability != "ok" || inbound.Quality != "lower_bound" {
				return invalid(field, "ok observation availability requires every inbound to be fully observed")
			}
		}
	case "partial":
		// The observation is incomplete: a missing expected tag (enforced by the
		// center against its allowlist), a partial export entry or a stale reading
		// is possible. At least one inbound row must exist so partial is never an
		// empty claim.
		if len(obs.Inbounds) == 0 {
			return invalid("traffic_observation.inbounds", "partial observation availability requires at least one inbound row")
		}
	case "unavailable":
		if observed != 0 {
			return invalid("traffic_observation.inbounds", "unavailable observation availability must not carry observed counters")
		}
	}
	if obs.Availability == "unavailable" {
		if obs.ActiveConnections != nil {
			return invalid("traffic_observation.active_connections", "unavailable observation must not carry a total active count")
		}
	}
	return nil
}

func countPartial(inbounds []TrafficInboundObservation) int {
	n := 0
	for _, inbound := range inbounds {
		if inbound.Availability == "partial" {
			n++
		}
	}
	return n
}

func validateOptionalCount(field string, value *int64, max int64) error {
	if value == nil {
		return nil
	}
	if *value < 0 || *value > max {
		return invalid(field, "value is outside the frozen bound")
	}
	return nil
}

func validateOptionalCounter(field string, value *int64) error {
	if value == nil {
		return nil
	}
	if *value < 0 || *value > trafficMaxSafeInteger {
		return invalid(field, "byte lower bound is outside the safe integer range")
	}
	return nil
}

func validateOptionalRate(field string, value *float64) error {
	if value == nil {
		return nil
	}
	if math.IsNaN(*value) || math.IsInf(*value, 0) || *value < 0 || *value > trafficMaxRateBps {
		return invalid(field, "observed rate is outside the frozen bounds")
	}
	return nil
}

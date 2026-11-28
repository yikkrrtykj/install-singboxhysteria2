package store

// Revision-7 normalized read-only traffic observation storage and the bounded
// query surface used by the UM-C web API.
//
// One traffic_observation_reports row is stored per snapshot report that carried
// a validated traffic_observation object, with one traffic_observations row per
// inbound. Only normalized allowlisted fields are written: the raw monitor export
// JSON (and the raw report body) are never copied into these tables. Both rows
// are inserted in the same authenticated ingest transaction as the snapshot, so a
// duplicate/replayed report can never duplicate traffic history.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
)

// Bounded revision-7 traffic query limits.
const (
	// TrafficQueryMaxLimit is the maximum number of rows one query returns.
	TrafficQueryMaxLimit = 2000
	// TrafficQueryDefaultLimit is used when the caller does not specify a limit.
	TrafficQueryDefaultLimit = 500
	// TrafficQueryMaxRangeSeconds caps an explicit history range at 30 days.
	TrafficQueryMaxRangeSeconds = int64(30 * 24 * 60 * 60)
	// TrafficQueryMaxStepSeconds caps the optional downsample step.
	TrafficQueryMaxStepSeconds = int64(3600)
	trafficMaxSafeInteger      = int64(9007199254740991)
)

// TrafficObservationRecord is the normalized revision-7 observation attached to
// one stored snapshot. It is validated by the contract package before it reaches
// the store; these fields are the allowlisted storage projection.
type TrafficObservationRecord struct {
	Source            string
	SourceEpoch       string
	Sequence          int64
	ObservedAt        int64
	CollectedAt       int64
	ReceivedAt        int64
	Availability      string
	Freshness         string
	ActiveConnections *int64
	RateWindowSeconds *float64
	CounterScope      string
	Exactness         string
	BytesEstimate     int64
	Inbounds          []TrafficInboundRecord
}

// TrafficInboundRecord is one normalized per-inbound lower-bound observation.
type TrafficInboundRecord struct {
	InboundTag                      string
	Kind                            string
	ObservedAt                      int64
	Availability                    string
	Quality                         string
	UplinkObservedLowerBoundBytes   *int64
	DownlinkObservedLowerBoundBytes *int64
	UplinkObservedRateBps           *float64
	DownlinkObservedRateBps         *float64
	ActiveConnections               int64
}

// TrafficEventScope is the SQL-evaluated event authorization scope. AllEvents is
// only supplied for a platform_admin principal; every other caller supplies the
// explicit resolved event allowlist. An empty non-global scope matches nothing.
type TrafficEventScope struct {
	AllEvents bool
	EventIDs  []string
}

func (scope TrafficEventScope) clause(column string) (string, []any) {
	if scope.AllEvents {
		return "", nil
	}
	if len(scope.EventIDs) == 0 {
		return "0", nil
	}
	placeholders := make([]string, len(scope.EventIDs))
	args := make([]any, len(scope.EventIDs))
	for index, eventID := range scope.EventIDs {
		placeholders[index] = "?"
		args[index] = eventID
	}
	return column + " IN (" + strings.Join(placeholders, ",") + ")", args
}

// TrafficQuery is the bounded filter for the latest/history queries. Times are
// Unix seconds of the observation clock (observed_at), never received_at.
type TrafficQuery struct {
	EventID     string
	NodeID      string
	InboundTag  string
	Kind        string
	From        int64
	To          int64
	Limit       int
	StepSeconds int64
}

// TrafficPoint is one normalized query row. GapBeforeSeconds is only set for
// history rows of the same series/epoch as the previous returned row; nil means
// "series start, epoch change or unsampled boundary".
type TrafficPoint struct {
	EventID                         string
	NodeID                          string
	InboundTag                      string
	Kind                            string
	ObservedAt                      int64
	CollectedAt                     int64
	Availability                    string
	Freshness                       string
	Quality                         string
	SourceEpoch                     string
	Sequence                        int64
	CounterScope                    string
	Exactness                       string
	ActiveConnections               int64
	UplinkObservedLowerBoundBytes   *int64
	DownlinkObservedLowerBoundBytes *int64
	UplinkObservedRateBps           *float64
	DownlinkObservedRateBps         *float64
	GapBeforeSeconds                *int64
}

// validateTrafficQuery normalizes the limit/default and rejects unbounded or
// nonsensical filters. It never builds SQL from caller text.
func validateTrafficQuery(query *TrafficQuery, history bool) error {
	if query.Limit == 0 {
		query.Limit = TrafficQueryDefaultLimit
	}
	if query.Limit < 1 || query.Limit > TrafficQueryMaxLimit {
		return invalidArgument("limit", "must be in [1,2000]")
	}
	if query.From < 0 || query.To < 0 {
		return invalidArgument("range", "timestamps must be non-negative")
	}
	if query.From > 0 && query.To > 0 && query.From > query.To {
		return invalidArgument("range", "from must not be after to")
	}
	if query.From > 0 && query.To > 0 && query.To-query.From > TrafficQueryMaxRangeSeconds {
		return invalidArgument("range", "history range exceeds the 30-day bound")
	}
	if history && (query.From == 0 || query.To == 0) {
		return invalidArgument("range", "history requires an explicit bounded from/to")
	}
	if history {
		if query.StepSeconds < 0 || query.StepSeconds > TrafficQueryMaxStepSeconds {
			return invalidArgument("step_seconds", "must be in [1,3600]")
		}
	}
	if len(query.EventID) > 64 || len(query.NodeID) > 64 || len(query.InboundTag) > 64 {
		return invalidArgument("filter", "filter value exceeds the bounded length")
	}
	switch query.Kind {
	case "", "reality", "hysteria2", "other":
	default:
		return invalidArgument("kind", "unknown inbound kind")
	}
	return nil
}

func trafficFilterSQL(query TrafficQuery, alias string) (string, []any) {
	prefix := ""
	if alias != "" {
		prefix = alias + "."
	}
	clauses := make([]string, 0, 4)
	args := make([]any, 0, 4)
	if query.EventID != "" {
		clauses = append(clauses, prefix+"event_id = ?")
		args = append(args, query.EventID)
	}
	if query.NodeID != "" {
		clauses = append(clauses, prefix+"node_id = ?")
		args = append(args, query.NodeID)
	}
	if query.InboundTag != "" {
		clauses = append(clauses, prefix+"inbound_tag = ?")
		args = append(args, query.InboundTag)
	}
	if query.Kind != "" {
		clauses = append(clauses, prefix+"kind = ?")
		args = append(args, query.Kind)
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return " AND " + strings.Join(clauses, " AND "), args
}

// validStoredAgentVersion is a defense-in-depth check for the node capability
// metadata recorded from a signed snapshot. The contract already enforces this
// grammar; an unexpected value is simply not stored rather than persisted raw.
var storedAgentVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)

func validStoredAgentVersion(version string) bool {
	return len(version) <= 32 && storedAgentVersionPattern.MatchString(version)
}

// LastAgentVersionTx returns the node's latest authenticated snapshot
// agent.version, or "" when no snapshot has been recorded yet.
func (t *Tx) LastAgentVersionTx(ctx context.Context, nodeID string) (string, error) {
	var version sql.NullString
	err := t.tx.QueryRowContext(ctx,
		`SELECT last_agent_version FROM nodes WHERE node_id=?`, nodeID).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("store: read latest agent version: %w", err)
	}
	return version.String, nil
}

// GetLastAgentVersion loads the node's latest authenticated snapshot
// agent.version outside an explicit transaction ("" when unknown).
func (s *Store) GetLastAgentVersion(ctx context.Context, nodeID string) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()
	return (&Tx{tx: tx}).LastAgentVersionTx(ctx, nodeID)
}

// insertTrafficObservationTx persists one normalized observation inside the
// caller's ingest transaction. The report row is idempotent on (node_id,
// report_id): if it already exists (for example a report whose dedupe row expired
// while the snapshot remained), no child rows are inserted again.
func (t *Tx) insertTrafficObservationTx(ctx context.Context, rec SnapshotRecord, snapshotID int64) error {
	obs := rec.TrafficObservation
	if obs == nil {
		return nil
	}
	if err := validateTrafficObservationRecord(rec, obs); err != nil {
		return err
	}
	res, err := t.tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO traffic_observation_reports(
			node_id,event_id,report_id,snapshot_id,source,source_epoch,sequence,
			observed_at,collected_at,received_at,availability,freshness,
			active_connections,rate_window_seconds,counter_scope,exactness,bytes_estimate)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		rec.NodeID, rec.EventID, rec.ReportID, snapshotID, obs.Source, obs.SourceEpoch, obs.Sequence,
		obs.ObservedAt, obs.CollectedAt, obs.ReceivedAt, obs.Availability, obs.Freshness,
		nullableInt64(obs.ActiveConnections), nullableFloat64(obs.RateWindowSeconds),
		obs.CounterScope, obs.Exactness, obs.BytesEstimate)
	if err != nil {
		return fmt.Errorf("store: insert traffic observation report: %w", err)
	}
	inserted, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: read traffic observation insert: %w", err)
	}
	if inserted == 0 {
		// Same (node, report) already stored: do not duplicate per-inbound rows.
		return nil
	}
	reportRowID, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("store: read traffic observation row id: %w", err)
	}
	for _, inbound := range obs.Inbounds {
		if _, err := t.tx.ExecContext(ctx,
			`INSERT INTO traffic_observations(
				report_row_id,node_id,event_id,inbound_tag,kind,observed_at,availability,quality,
				uplink_observed_lower_bound_bytes,downlink_observed_lower_bound_bytes,
				uplink_observed_rate_bps,downlink_observed_rate_bps,active_connections)
			 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			reportRowID, rec.NodeID, rec.EventID, inbound.InboundTag, inbound.Kind, inbound.ObservedAt,
			inbound.Availability, inbound.Quality,
			nullableInt64(inbound.UplinkObservedLowerBoundBytes), nullableInt64(inbound.DownlinkObservedLowerBoundBytes),
			nullableFloat64(inbound.UplinkObservedRateBps), nullableFloat64(inbound.DownlinkObservedRateBps),
			inbound.ActiveConnections); err != nil {
			return fmt.Errorf("store: insert traffic observation: %w", err)
		}
		if inbound.ObservedAt <= 0 || !trafficInboundHasMeasuredValues(inbound) {
			continue
		}
		const bucketSeconds int64 = 900
		bucketStart := (inbound.ObservedAt / bucketSeconds) * bucketSeconds
		if _, err := t.tx.ExecContext(ctx,
			`INSERT INTO traffic_observation_buckets(
				node_id,event_id,inbound_tag,kind,source_epoch,bucket_start,sequence,
				observed_at,collected_at,received_at,availability,freshness,quality,active_connections,
				uplink_observed_lower_bound_bytes,downlink_observed_lower_bound_bytes,
				uplink_observed_rate_bps,downlink_observed_rate_bps,bytes_estimate)
			 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
			 ON CONFLICT(node_id,inbound_tag,source_epoch,bucket_start) DO UPDATE SET
				event_id=excluded.event_id,
				observed_at=CASE WHEN excluded.observed_at >= traffic_observation_buckets.observed_at THEN excluded.observed_at ELSE traffic_observation_buckets.observed_at END,
				collected_at=CASE WHEN excluded.observed_at >= traffic_observation_buckets.observed_at THEN excluded.collected_at ELSE traffic_observation_buckets.collected_at END,
				received_at=CASE WHEN excluded.observed_at >= traffic_observation_buckets.observed_at THEN excluded.received_at ELSE traffic_observation_buckets.received_at END,
				sequence=CASE WHEN excluded.observed_at >= traffic_observation_buckets.observed_at THEN excluded.sequence ELSE traffic_observation_buckets.sequence END,
				availability=CASE WHEN excluded.observed_at >= traffic_observation_buckets.observed_at THEN excluded.availability ELSE traffic_observation_buckets.availability END,
				freshness=CASE WHEN excluded.observed_at >= traffic_observation_buckets.observed_at THEN excluded.freshness ELSE traffic_observation_buckets.freshness END,
				quality=CASE WHEN excluded.observed_at >= traffic_observation_buckets.observed_at THEN excluded.quality ELSE traffic_observation_buckets.quality END,
				uplink_observed_lower_bound_bytes=MAX(COALESCE(traffic_observation_buckets.uplink_observed_lower_bound_bytes,0),COALESCE(excluded.uplink_observed_lower_bound_bytes,0)),
				downlink_observed_lower_bound_bytes=MAX(COALESCE(traffic_observation_buckets.downlink_observed_lower_bound_bytes,0),COALESCE(excluded.downlink_observed_lower_bound_bytes,0)),
				uplink_observed_rate_bps=CASE WHEN excluded.observed_at >= traffic_observation_buckets.observed_at THEN excluded.uplink_observed_rate_bps ELSE traffic_observation_buckets.uplink_observed_rate_bps END,
				downlink_observed_rate_bps=CASE WHEN excluded.observed_at >= traffic_observation_buckets.observed_at THEN excluded.downlink_observed_rate_bps ELSE traffic_observation_buckets.downlink_observed_rate_bps END,
				active_connections=CASE WHEN excluded.observed_at >= traffic_observation_buckets.observed_at THEN excluded.active_connections ELSE traffic_observation_buckets.active_connections END,
				bytes_estimate=MAX(traffic_observation_buckets.bytes_estimate,excluded.bytes_estimate)`,
			rec.NodeID, rec.EventID, inbound.InboundTag, inbound.Kind, obs.SourceEpoch, bucketStart,
			obs.Sequence, inbound.ObservedAt, obs.CollectedAt, obs.ReceivedAt,
			inbound.Availability, obs.Freshness, inbound.Quality, inbound.ActiveConnections,
			nullableInt64(inbound.UplinkObservedLowerBoundBytes), nullableInt64(inbound.DownlinkObservedLowerBoundBytes),
			nullableFloat64(inbound.UplinkObservedRateBps), nullableFloat64(inbound.DownlinkObservedRateBps),
			trafficBucketBytesEstimate(inbound)); err != nil {
			return fmt.Errorf("store: upsert traffic observation bucket: %w", err)
		}
	}
	// Keep a bounded recent raw ring per node (64 reports). Older reports are
	// already represented by their 15-minute lower-bound bucket, so dropping the
	// raw row (and its per-inbound child rows via ON DELETE CASCADE) cannot lose
	// a distinct history sample. The node's latest row is always retained.
	if _, err := t.tx.ExecContext(ctx,
		`DELETE FROM traffic_observation_reports
		 WHERE node_id=? AND report_row_id NOT IN (
			SELECT report_row_id FROM traffic_observation_reports
			WHERE node_id=? ORDER BY collected_at DESC, report_row_id DESC LIMIT 64)`,
		rec.NodeID, rec.NodeID); err != nil {
		return fmt.Errorf("store: prune traffic raw ring: %w", err)
	}
	return nil
}

func trafficInboundHasMeasuredValues(inbound TrafficInboundRecord) bool {
	return inbound.UplinkObservedLowerBoundBytes != nil ||
		inbound.DownlinkObservedLowerBoundBytes != nil ||
		inbound.UplinkObservedRateBps != nil ||
		inbound.DownlinkObservedRateBps != nil
}

func trafficBucketBytesEstimate(inbound TrafficInboundRecord) int64 {
	estimate := int64(192 + len(inbound.InboundTag) + len(inbound.Kind))
	if inbound.UplinkObservedLowerBoundBytes != nil {
		estimate += 8
	}
	if inbound.DownlinkObservedLowerBoundBytes != nil {
		estimate += 8
	}
	return estimate
}

// validateTrafficObservationRecord is defense in depth before the constrained
// insert. The contract layer already validated the report body; a violation here
// is a server bug mapped to a storage failure rather than persisted bad data.
func validateTrafficObservationRecord(rec SnapshotRecord, obs *TrafficObservationRecord) error {
	if obs.Source != "monitor_readonly_export" || obs.CounterScope != "observation_epoch" ||
		obs.Exactness != "lower_bound" {
		return invalidArgument("traffic_observation", "unsupported observation tokens")
	}
	if len(obs.SourceEpoch) != 32 {
		return invalidArgument("traffic_observation", "invalid source epoch")
	}
	for _, runeValue := range obs.SourceEpoch {
		if !((runeValue >= '0' && runeValue <= '9') || (runeValue >= 'a' && runeValue <= 'f')) {
			return invalidArgument("traffic_observation", "invalid source epoch")
		}
	}
	if obs.Sequence < 0 || obs.Sequence > trafficMaxSafeInteger || obs.ObservedAt < 0 || obs.CollectedAt < 0 {
		return invalidArgument("traffic_observation", "observation identity is out of bounds")
	}
	if !validTrafficAvailability(obs.Availability) || !validTrafficFreshness(obs.Freshness) {
		return invalidArgument("traffic_observation", "invalid availability/freshness")
	}
	if obs.BytesEstimate < 0 {
		obs.BytesEstimate = 0
	}
	if obs.ActiveConnections != nil && (*obs.ActiveConnections < 0 || *obs.ActiveConnections > 1000000) {
		return invalidArgument("traffic_observation", "invalid active connections")
	}
	if obs.RateWindowSeconds != nil &&
		(math.IsNaN(*obs.RateWindowSeconds) || math.IsInf(*obs.RateWindowSeconds, 0) ||
			*obs.RateWindowSeconds <= 0 || *obs.RateWindowSeconds > 3600) {
		return invalidArgument("traffic_observation", "invalid rate window")
	}
	if len(obs.Inbounds) > 16 {
		return invalidArgument("traffic_observation", "too many inbound rows")
	}
	for _, inbound := range obs.Inbounds {
		if inbound.InboundTag == "" || len(inbound.InboundTag) > 64 {
			return invalidArgument("traffic_observation", "invalid inbound tag")
		}
		switch inbound.Kind {
		case "reality", "hysteria2", "other":
		default:
			return invalidArgument("traffic_observation", "invalid inbound kind")
		}
		if !validTrafficAvailability(inbound.Availability) || !validTrafficQuality(inbound.Quality) {
			return invalidArgument("traffic_observation", "invalid inbound availability/quality")
		}
		if inbound.ObservedAt < 0 {
			return invalidArgument("traffic_observation", "invalid inbound observed_at")
		}
		if err := validTrafficBytes(inbound.UplinkObservedLowerBoundBytes); err != nil {
			return err
		}
		if err := validTrafficBytes(inbound.DownlinkObservedLowerBoundBytes); err != nil {
			return err
		}
		if err := validTrafficRate(inbound.UplinkObservedRateBps); err != nil {
			return err
		}
		if err := validTrafficRate(inbound.DownlinkObservedRateBps); err != nil {
			return err
		}
		if inbound.ActiveConnections < 0 || inbound.ActiveConnections > 1000000 {
			return invalidArgument("traffic_observation", "invalid inbound active connections")
		}
	}
	return nil
}

func validTrafficAvailability(value string) bool {
	return value == "ok" || value == "partial" || value == "unavailable"
}

func validTrafficFreshness(value string) bool {
	return value == "fresh" || value == "stale" || value == "unavailable"
}

func validTrafficQuality(value string) bool {
	return value == "lower_bound" || value == "partial" || value == "unavailable"
}

func validTrafficBytes(value *int64) error {
	if value == nil {
		return nil
	}
	if *value < 0 || *value > trafficMaxSafeInteger {
		return invalidArgument("traffic_observation", "byte lower bound out of range")
	}
	return nil
}

func validTrafficRate(value *float64) error {
	if value == nil {
		return nil
	}
	if math.IsNaN(*value) || math.IsInf(*value, 0) || *value < 0 || *value > 1e12 {
		return invalidArgument("traffic_observation", "observed rate out of range")
	}
	return nil
}

func nullableInt64(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}

func nullableFloat64(value *float64) any {
	if value == nil {
		return nil
	}
	return *value
}

func scanNullableInt64(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	v := value.Int64
	return &v
}

func scanNullableFloat64(value sql.NullFloat64) *float64 {
	if !value.Valid {
		return nil
	}
	v := value.Float64
	return &v
}

// TrafficObservationState is the report-level (node/event) latest observation
// header. It is returned even when an unavailable sentinel carries no per-inbound
// rows, so a query can distinguish "no data" from "not requested" and render an
// honest unavailable/freshness state.
type TrafficObservationState struct {
	EventID           string
	NodeID            string
	SourceEpoch       string
	Sequence          int64
	ObservedAt        int64
	CollectedAt       int64
	ReceivedAt        int64
	Availability      string
	Freshness         string
	ActiveConnections *int64
	RateWindowSeconds *float64
	CounterScope      string
	Exactness         string
}

// QueryLatestTrafficStates returns the newest observation header per
// (event,node) by observed_at. It preserves unavailable sentinels (which have no
// inbound rows) and never uses received_at as the traffic clock.
func (s *Store) QueryLatestTrafficStates(ctx context.Context, scope TrafficEventScope, query TrafficQuery) ([]TrafficObservationState, error) {
	if err := validateTrafficQuery(&query, false); err != nil {
		return nil, err
	}
	scopeClause, scopeArgs := scope.clause("r.event_id")
	where := "WHERE 1=1"
	args := make([]any, 0, len(scopeArgs)+3)
	if scopeClause != "" {
		where += " AND " + scopeClause
		args = append(args, scopeArgs...)
	}
	if query.EventID != "" {
		where += " AND r.event_id = ?"
		args = append(args, query.EventID)
	}
	if query.NodeID != "" {
		where += " AND r.node_id = ?"
		args = append(args, query.NodeID)
	}
	if query.From > 0 {
		where += " AND r.observed_at >= ?"
		args = append(args, query.From)
	}
	if query.To > 0 {
		where += " AND r.observed_at <= ?"
		args = append(args, query.To)
	}
	args = append(args, query.Limit)
	rows, err := s.db.QueryContext(ctx, `
		SELECT event_id,node_id,source_epoch,sequence,observed_at,collected_at,received_at,
		       availability,freshness,active_connections,rate_window_seconds,counter_scope,exactness
		FROM (
			SELECT r.event_id AS event_id,r.node_id AS node_id,r.source_epoch AS source_epoch,
			       r.sequence AS sequence,r.observed_at AS observed_at,r.collected_at AS collected_at,
			       r.received_at AS received_at,r.availability AS availability,r.freshness AS freshness,
			       r.active_connections AS active_connections,r.rate_window_seconds AS rate_window_seconds,
			       r.counter_scope AS counter_scope,r.exactness AS exactness,
			       ROW_NUMBER() OVER (PARTITION BY r.event_id,r.node_id
			           ORDER BY r.collected_at DESC,r.report_row_id DESC) AS rn
			FROM traffic_observation_reports r
			`+where+`
		) latest WHERE rn=1
		ORDER BY collected_at DESC,event_id,node_id LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query traffic observation states: %w", err)
	}
	defer rows.Close()
	states := make([]TrafficObservationState, 0, 32)
	for rows.Next() {
		var state TrafficObservationState
		var active sql.NullInt64
		var rateWindow sql.NullFloat64
		if err := rows.Scan(&state.EventID, &state.NodeID, &state.SourceEpoch, &state.Sequence,
			&state.ObservedAt, &state.CollectedAt, &state.ReceivedAt, &state.Availability,
			&state.Freshness, &active, &rateWindow, &state.CounterScope, &state.Exactness); err != nil {
			return nil, fmt.Errorf("store: scan traffic observation state: %w", err)
		}
		state.ActiveConnections = scanNullableInt64(active)
		state.RateWindowSeconds = scanNullableFloat64(rateWindow)
		states = append(states, state)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate traffic observation states: %w", err)
	}
	return states, nil
}

// QueryLatestTraffic returns the newest observation per (event, node, inbound_tag,
// kind) series by observed_at. received_at is never used as the traffic time, so
// a late/offline replay is ordered by when it was observed, not when it arrived.
func (s *Store) QueryLatestTraffic(ctx context.Context, scope TrafficEventScope, query TrafficQuery) ([]TrafficPoint, error) {
	if err := validateTrafficQuery(&query, false); err != nil {
		return nil, err
	}
	scopeClause, scopeArgs := scope.clause("o.event_id")
	filterClause, filterArgs := trafficFilterSQL(query, "o")
	where := "WHERE 1=1"
	args := make([]any, 0, len(scopeArgs)+len(filterArgs)+1)
	if scopeClause != "" {
		where += " AND " + scopeClause
		args = append(args, scopeArgs...)
	}
	if filterClause != "" {
		where += filterClause
		args = append(args, filterArgs...)
	}
	if query.From > 0 {
		where += " AND o.observed_at >= ?"
		args = append(args, query.From)
	}
	if query.To > 0 {
		where += " AND o.observed_at <= ?"
		args = append(args, query.To)
	}
	args = append(args, query.Limit)
	rows, err := s.db.QueryContext(ctx, `
		SELECT event_id,node_id,inbound_tag,kind,observed_at,collected_at,availability,freshness,
		       quality,source_epoch,sequence,counter_scope,exactness,active_connections,
		       uplink_observed_lower_bound_bytes,downlink_observed_lower_bound_bytes,
		       uplink_observed_rate_bps,downlink_observed_rate_bps
		FROM (
			SELECT o.event_id AS event_id, o.node_id AS node_id, o.inbound_tag AS inbound_tag,
			       o.kind AS kind, o.observed_at AS observed_at, r.collected_at AS collected_at,
			       r.availability AS availability, r.freshness AS freshness, o.quality AS quality,
			       r.source_epoch AS source_epoch, r.sequence AS sequence,
			       r.counter_scope AS counter_scope, r.exactness AS exactness,
			       o.active_connections AS active_connections,
			       o.uplink_observed_lower_bound_bytes AS uplink_observed_lower_bound_bytes,
			       o.downlink_observed_lower_bound_bytes AS downlink_observed_lower_bound_bytes,
			       o.uplink_observed_rate_bps AS uplink_observed_rate_bps,
			       o.downlink_observed_rate_bps AS downlink_observed_rate_bps,
			       ROW_NUMBER() OVER (
			           PARTITION BY o.event_id, o.node_id, o.inbound_tag, o.kind
			           ORDER BY o.observed_at DESC, o.report_row_id DESC) AS rn
			FROM traffic_observations o
			JOIN traffic_observation_reports r ON r.report_row_id = o.report_row_id
			`+where+`
		) latest
		WHERE rn = 1
		ORDER BY observed_at DESC, event_id, node_id, inbound_tag, kind
		LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query latest traffic: %w", err)
	}
	defer rows.Close()
	return scanTrafficPoints(rows, false)
}

// QueryTrafficHistory returns bounded, observed_at-ordered normalized rows plus
// whether the limit truncated the result. An optional step_seconds downsamples by
// keeping the newest row per series/downsample bucket. GapBeforeSeconds is
// computed only inside the same series and epoch, so a monitor epoch reset is an
// explicit boundary instead of a fabricated gap.
func (s *Store) QueryTrafficHistory(ctx context.Context, scope TrafficEventScope, query TrafficQuery) ([]TrafficPoint, bool, error) {
	if err := validateTrafficQuery(&query, true); err != nil {
		return nil, false, err
	}
	scopeClause, scopeArgs := scope.clause("o.event_id")
	filterClause, filterArgs := trafficFilterSQL(query, "o")
	where := "WHERE o.observed_at >= ? AND o.observed_at <= ?"
	args := make([]any, 0, len(scopeArgs)+len(filterArgs)+3)
	args = append(args, query.From, query.To)
	if scopeClause != "" {
		where += " AND " + scopeClause
		args = append(args, scopeArgs...)
	}
	if filterClause != "" {
		where += filterClause
		args = append(args, filterArgs...)
	}
	// One extra row detects truncation without counting the whole range.
	args = append(args, query.Limit+1)
	selectList := `SELECT o.event_id AS event_id, o.node_id AS node_id, o.inbound_tag AS inbound_tag,
	       o.kind AS kind, o.observed_at AS observed_at, o.collected_at AS collected_at,
	       o.availability AS availability, o.freshness AS freshness, o.quality AS quality,
	       o.source_epoch AS source_epoch, o.sequence AS sequence,
	       o.counter_scope AS counter_scope, o.exactness AS exactness,
	       o.active_connections AS active_connections,
	       o.uplink_observed_lower_bound_bytes AS uplink_observed_lower_bound_bytes,
	       o.downlink_observed_lower_bound_bytes AS downlink_observed_lower_bound_bytes,
	       o.uplink_observed_rate_bps AS uplink_observed_rate_bps,
	       o.downlink_observed_rate_bps AS downlink_observed_rate_bps`
	fromWhere := ` FROM traffic_history_view o ` + where
	source := selectList + fromWhere
	outerSelect := `SELECT event_id,node_id,inbound_tag,kind,observed_at,collected_at,
	       availability,freshness,quality,source_epoch,sequence,counter_scope,exactness,
	       active_connections,uplink_observed_lower_bound_bytes,downlink_observed_lower_bound_bytes,
	       uplink_observed_rate_bps,downlink_observed_rate_bps `
	orderBy := ` ORDER BY event_id, node_id, inbound_tag, kind, observed_at, collected_at LIMIT ?`
	var statement string
	if query.StepSeconds > 0 {
		// The downsample step placeholder precedes the WHERE placeholders in the
		// generated statement, so it is prepended to the argument list.
		source = selectList + `,
	       ROW_NUMBER() OVER (
	           PARTITION BY o.event_id, o.node_id, o.inbound_tag, o.kind,
	               (o.observed_at - (o.observed_at % ?))
	           ORDER BY o.observed_at DESC) AS bucket_rn` + fromWhere
		args = append([]any{query.StepSeconds}, args...)
		statement = outerSelect + `FROM (` + source + `) sampled WHERE bucket_rn = 1` + orderBy
	} else {
		statement = outerSelect + `FROM (` + source + `)` + orderBy
	}
	rows, err := s.db.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, false, fmt.Errorf("store: query traffic history: %w", err)
	}
	defer rows.Close()
	points, err := scanTrafficPoints(rows, true)
	if err != nil {
		return nil, false, err
	}
	truncated := false
	if len(points) > query.Limit {
		points = points[:query.Limit]
		truncated = true
	}
	return points, truncated, nil
}

func scanTrafficPoints(rows *sql.Rows, history bool) ([]TrafficPoint, error) {
	points := make([]TrafficPoint, 0, 64)
	var (
		previousSeries  string
		previousEpoch   string
		previousObserve int64
	)
	for rows.Next() {
		var point TrafficPoint
		var (
			active        sql.NullInt64
			uplinkBytes   sql.NullInt64
			downlinkBytes sql.NullInt64
			uplinkRate    sql.NullFloat64
			downlinkRate  sql.NullFloat64
		)
		if err := rows.Scan(&point.EventID, &point.NodeID, &point.InboundTag, &point.Kind,
			&point.ObservedAt, &point.CollectedAt, &point.Availability, &point.Freshness,
			&point.Quality, &point.SourceEpoch, &point.Sequence, &point.CounterScope,
			&point.Exactness, &active, &uplinkBytes, &downlinkBytes, &uplinkRate, &downlinkRate); err != nil {
			return nil, fmt.Errorf("store: scan traffic row: %w", err)
		}
		point.ActiveConnections = active.Int64
		point.UplinkObservedLowerBoundBytes = scanNullableInt64(uplinkBytes)
		point.DownlinkObservedLowerBoundBytes = scanNullableInt64(downlinkBytes)
		point.UplinkObservedRateBps = scanNullableFloat64(uplinkRate)
		point.DownlinkObservedRateBps = scanNullableFloat64(downlinkRate)
		if history {
			series := point.EventID + "\x00" + point.NodeID + "\x00" + point.InboundTag + "\x00" + point.Kind
			if series == previousSeries && point.SourceEpoch == previousEpoch {
				gap := point.ObservedAt - previousObserve
				if gap >= 0 {
					point.GapBeforeSeconds = &gap
				}
			}
			previousSeries = series
			previousEpoch = point.SourceEpoch
			previousObserve = point.ObservedAt
		}
		points = append(points, point)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate traffic rows: %w", err)
	}
	return points, nil
}

// SeedTrafficObservationForTest inserts a synthetic node, snapshot report and
// normalized traffic rows for query/RBAC tests. It is never called by production
// code paths; it exists so the web package can test scoped reads without a full
// authenticated machine ingest.
func (s *Store) SeedTrafficObservationForTest(ctx context.Context, rec SnapshotRecord) error {
	if rec.TrafficObservation == nil {
		return invalidArgument("traffic_observation", "test seed requires an observation")
	}
	now := rec.ReceivedAt
	if now == 0 {
		now = time.Now().Unix()
		rec.ReceivedAt = now
	}
	if rec.TrafficObservation.ReceivedAt == 0 {
		rec.TrafficObservation.ReceivedAt = now
	}
	if rec.TrafficObservation.CollectedAt == 0 {
		rec.TrafficObservation.CollectedAt = rec.CollectedAt
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO nodes(node_id,event_id,node_class,state,created_at) VALUES(?,?,?,?,?)`,
		rec.NodeID, rec.EventID, "linux_vps", "active", rec.CollectedAt); err != nil {
		return fmt.Errorf("store: seed node: %w", err)
	}
	payload := rec.Payload
	if payload == nil {
		payload = []byte("{}")
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO snapshots(node_id,event_id,node_class,report_id,collected_at,received_at,body_sha256,payload_json)
		 VALUES(?,?,?,?,?,?,?,?)`,
		rec.NodeID, rec.EventID, "linux_vps", rec.ReportID, rec.CollectedAt, rec.ReceivedAt, rec.BodySHA256, payload)
	if err != nil {
		return fmt.Errorf("store: seed snapshot: %w", err)
	}
	snapshotID, err := res.LastInsertId()
	if err != nil {
		return err
	}
	t := &Tx{tx: tx}
	if err := t.insertTrafficObservationTx(ctx, rec, snapshotID); err != nil {
		return err
	}
	return tx.Commit()
}

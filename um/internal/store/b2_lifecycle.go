package store

// UM-B2 policy-B event lifecycle, quotas and bounded retention.
//
// Normative source: docs/um/um-a/05-retention-capacity-backup.md.
//   - Active event: rolling 30 days by collected_at.
//   - Archive at T: stop ingest; keep the remaining history until T+30d; the
//     event row's own telemetry stays in its normal tables (no second copy).
//   - After T+30d: delete event telemetry; the event catalog row survives until
//     an explicit purge, which writes an audited tombstone.
//   - Node retire never shortens event history.
//   - Deletions are bounded to 50000 rows per transaction, resumable/idempotent.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Policy-B frozen constants (planning defaults; owner may only raise with
// capacity evidence, which is UM-E work).
const (
	PolicyBActiveRetentionSeconds = 30 * 24 * 60 * 60
	PolicyBArchiveTailSeconds     = 30 * 24 * 60 * 60
	RetentionBatchRows            = 50000
	RetentionRunsKeep             = 100
	PurgeTombstoneSeconds         = 180 * 24 * 60 * 60
	SecurityRetentionSeconds      = 180 * 24 * 60 * 60

	MaxActiveNodesAllEvents   = 150 // 40 GB policy-B hard quota
	MaxActiveNodesPerEvent    = 100
	MaxArchivedEventsWithData = 10
	MaxEventsCatalog          = 50

	// Overlap planning constants (explicit bytes, not a promise about SQLite disk
	// size). Active-only planning payload basis is 5 GiB; policy-B worst case is
	// capped at 2x, i.e. 10 GiB of projected telemetry payload.
	ActiveOnlyPlanningPayloadBytes int64 = 5 * 1024 * 1024 * 1024
	OverlapBudgetMultiplier        int64 = 2
)

// Event lifecycle states.
const (
	EventActive   = "active"
	EventArchived = "archived"
)

var (
	ErrEventUnknown      = errors.New("store: event unknown")
	ErrEventArchived     = errors.New("store: event archived")
	ErrEventPurged       = errors.New("store: event purged")
	ErrQuotaExceeded     = errors.New("store: capacity quota exceeded")
	ErrArchiveQuota      = errors.New("store: archived-event quota exceeded")
	ErrRotationState     = errors.New("store: rotation state invalid")
	ErrRetentionDegraded = errors.New("store: retention degraded")
)

// QuotaError identifies the frozen quota that was hit.
type QuotaError struct {
	Kind    string
	Limit   int64
	Current int64
}

func (e *QuotaError) Error() string {
	return fmt.Sprintf("store: quota %s exceeded (limit=%d current=%d)", e.Kind, e.Limit, e.Current)
}
func (e *QuotaError) Unwrap() error { return ErrQuotaExceeded }

// EventInfo is the persistent lifecycle row.
type EventInfo struct {
	EventID      string
	State        string
	CreatedAt    int64
	ArchivedAt   *int64
	PurgeAfter   *int64
	DataPurgedAt *int64
	UpdatedAt    int64
}

// EventStateTx reads one event lifecycle row inside a transaction.
func (t *Tx) EventStateTx(ctx context.Context, eventID string) (EventInfo, error) {
	var e EventInfo
	var archived, purgeAfter, purged sql.NullInt64
	err := t.tx.QueryRowContext(ctx,
		`SELECT event_id,state,created_at,archived_at,purge_after,data_purged_at,updated_at
		 FROM event_catalog WHERE event_id=?`, eventID).
		Scan(&e.EventID, &e.State, &e.CreatedAt, &archived, &purgeAfter, &purged, &e.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return EventInfo{}, ErrEventUnknown
	}
	if err != nil {
		return EventInfo{}, fmt.Errorf("store: read event state: %w", err)
	}
	if archived.Valid {
		v := archived.Int64
		e.ArchivedAt = &v
	}
	if purgeAfter.Valid {
		v := purgeAfter.Int64
		e.PurgeAfter = &v
	}
	if purged.Valid {
		v := purged.Int64
		e.DataPurgedAt = &v
	}
	return e, nil
}

func (s *Store) EventState(ctx context.Context, eventID string) (EventInfo, error) {
	var e EventInfo
	var archived, purgeAfter, purged sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT event_id,state,created_at,archived_at,purge_after,data_purged_at,updated_at
		 FROM event_catalog WHERE event_id=?`, eventID).
		Scan(&e.EventID, &e.State, &e.CreatedAt, &archived, &purgeAfter, &purged, &e.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return EventInfo{}, ErrEventUnknown
	}
	if err != nil {
		return EventInfo{}, fmt.Errorf("store: read event state: %w", err)
	}
	if archived.Valid {
		v := archived.Int64
		e.ArchivedAt = &v
	}
	if purgeAfter.Valid {
		v := purgeAfter.Int64
		e.PurgeAfter = &v
	}
	if purged.Valid {
		v := purged.Int64
		e.DataPurgedAt = &v
	}
	return e, nil
}

// lockCapacity takes the SQLite write lock before a quota check/insert so two
// concurrent token/enrollment operations cannot both observe a free slot.
func lockCapacity(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `UPDATE capacity_state SET version=version+1 WHERE id=1`); err != nil {
		return fmt.Errorf("store: lock capacity state: %w", err)
	}
	return nil
}

func countActiveNodesTx(ctx context.Context, tx *sql.Tx, eventID string) (int64, int64, error) {
	var total int64
	// Only nodes whose event is active count against the active-node quota; an
	// archived event's identities no longer consume the active budget.
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM nodes n JOIN event_catalog e ON e.event_id=n.event_id
		 WHERE n.state=? AND e.state=?`, NodeActive, EventActive).Scan(&total); err != nil {
		return 0, 0, err
	}
	var perEvent int64
	if eventID != "" {
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM nodes n JOIN event_catalog e ON e.event_id=n.event_id
			 WHERE n.state=? AND n.event_id=? AND e.state=?`, NodeActive, eventID, EventActive).Scan(&perEvent); err != nil {
			return 0, 0, err
		}
	}
	return total, perEvent, nil
}

func checkNodeQuotaTx(ctx context.Context, tx *sql.Tx, eventID string) error {
	total, perEvent, err := countActiveNodesTx(ctx, tx, eventID)
	if err != nil {
		return err
	}
	if total >= MaxActiveNodesAllEvents {
		return &QuotaError{Kind: "active_nodes", Limit: MaxActiveNodesAllEvents, Current: total}
	}
	if perEvent >= MaxActiveNodesPerEvent {
		return &QuotaError{Kind: "active_nodes_per_event", Limit: MaxActiveNodesPerEvent, Current: perEvent}
	}
	return nil
}

// ensureEventActiveTx returns the event row, creating an active catalog row when
// absent (subject to the event-catalog quota). Archived/purged events fail.
func ensureEventActiveTx(ctx context.Context, tx *sql.Tx, eventID string, now int64) (EventInfo, error) {
	if strings.TrimSpace(eventID) == "" {
		return EventInfo{}, invalidArgument("event_id", "must not be empty")
	}
	if err := eventBlockedTx(ctx, tx, eventID); err != nil {
		return EventInfo{}, err
	}
	var e EventInfo
	var archived, purgeAfter, purged sql.NullInt64
	err := tx.QueryRowContext(ctx,
		`SELECT event_id,state,created_at,archived_at,purge_after,data_purged_at,updated_at
		 FROM event_catalog WHERE event_id=?`, eventID).
		Scan(&e.EventID, &e.State, &e.CreatedAt, &archived, &purgeAfter, &purged, &e.UpdatedAt)
	if err == nil {
		if e.State != EventActive {
			return e, ErrEventArchived
		}
		return e, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return EventInfo{}, fmt.Errorf("store: read event catalog: %w", err)
	}
	var count int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM event_catalog`).Scan(&count); err != nil {
		return EventInfo{}, err
	}
	if count >= MaxEventsCatalog {
		return EventInfo{}, &QuotaError{Kind: "events_catalog", Limit: MaxEventsCatalog, Current: count}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO event_catalog(event_id,state,created_at,archived_at,purge_after,data_purged_at,updated_at)
		 VALUES(?,?,?,NULL,NULL,NULL,?)`, eventID, EventActive, now, now); err != nil {
		return EventInfo{}, fmt.Errorf("store: create event catalog: %w", err)
	}
	return EventInfo{EventID: eventID, State: EventActive, CreatedAt: now, UpdatedAt: now}, nil
}

// OverlapBudget makes the policy-B cap explicit: unit-bearing actual archived
// payload, the candidate event payload, the projected archived history and the
// stable active-only planning limit. It is a payload-budget decision, NOT a
// claim that it equals the SQLite file/disk hard limit.
type OverlapBudget struct {
	Unit                   string
	ActiveOnlyPlanBytes    int64
	BudgetBytes            int64 // 2x active-only plan, applied to active+archived total
	ActiveStoredBytes      int64
	ArchivedStoredBytes    int64
	CandidateBytes         int64
	ProjectedActiveBytes   int64
	ProjectedArchivedBytes int64
	ProjectedTotalBytes    int64
}

// ComputeOverlapBudget applies the 2x active-only planning budget to the
// combined active+archived projected history. The candidate is currently part of
// active storage, so it is moved from active to archived, never counted twice.
func ComputeOverlapBudget(activeOnlyPlanBytes, activeStoredBytes, archivedStoredBytes, candidateBytes int64) OverlapBudget {
	projectedActive := activeStoredBytes - candidateBytes
	if projectedActive < 0 {
		projectedActive = 0
	}
	projectedArchived := archivedStoredBytes + candidateBytes
	return OverlapBudget{
		Unit:                   "bytes",
		ActiveOnlyPlanBytes:    activeOnlyPlanBytes,
		BudgetBytes:            OverlapBudgetMultiplier * activeOnlyPlanBytes,
		ActiveStoredBytes:      activeStoredBytes,
		ArchivedStoredBytes:    archivedStoredBytes,
		CandidateBytes:         candidateBytes,
		ProjectedActiveBytes:   projectedActive,
		ProjectedArchivedBytes: projectedArchived,
		ProjectedTotalBytes:    projectedActive + projectedArchived,
	}
}

func (b OverlapBudget) Exceeds() bool { return b.ProjectedTotalBytes > b.BudgetBytes }

func (s *Store) overlapBudgetBasisBytes() int64 {
	if s.overlapBudgetOverride > 0 {
		return s.overlapBudgetOverride
	}
	return ActiveOnlyPlanningPayloadBytes
}

// SetOverlapBudgetForTest overrides only the planning basis for boundary tests.
func (s *Store) SetOverlapBudgetForTest(activeOnlyPlanBytes int64) {
	s.overlapBudgetOverride = activeOnlyPlanBytes
}

// eventPayloadBytesTx estimates the stored telemetry bytes of one event without
// using row counts as a disk-capacity proof.
func eventPayloadBytesTx(ctx context.Context, tx *sql.Tx, eventID string) (int64, error) {
	var n int64
	queries := []struct {
		sql  string
		args []any
	}{
		{`SELECT COALESCE(SUM(LENGTH(payload_json)),0) FROM snapshots WHERE event_id=?`, []any{eventID}},
		{`SELECT COALESCE(SUM(LENGTH(payload_json)),0) FROM report_metrics WHERE event_id=?`, []any{eventID}},
		{`SELECT COALESCE(SUM(LENGTH(details_json)),0) FROM report_events WHERE event_id=?`, []any{eventID}},
		{`SELECT COALESCE(SUM(LENGTH(payload_json)),0) FROM report_event_reports WHERE event_id=?`, []any{eventID}},
		// Normalized revision-7 traffic rows carry a bounded per-report byte
		// estimate instead of raw payload; the child rows are accounted inside it.
		{`SELECT (SELECT COALESCE(SUM(bytes_estimate),0) FROM traffic_observation_reports WHERE event_id=?) + (SELECT COALESCE(SUM(bytes_estimate),0) FROM traffic_observation_buckets WHERE event_id=?)`, []any{eventID, eventID}},
	}
	for _, q := range queries {
		var v int64
		if err := tx.QueryRowContext(ctx, q.sql, q.args...).Scan(&v); err != nil {
			return 0, err
		}
		n += v
	}
	return n, nil
}

func activeArchivedPayloadBytesTx(ctx context.Context, tx *sql.Tx) (active, archived int64, err error) {
	rows, err := tx.QueryContext(ctx, `SELECT event_id,state FROM event_catalog`)
	if err != nil {
		return 0, 0, err
	}
	type ev struct{ id, state string }
	var evs []ev
	for rows.Next() {
		var e ev
		if err := rows.Scan(&e.id, &e.state); err != nil {
			rows.Close()
			return 0, 0, err
		}
		evs = append(evs, e)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, 0, err
	}
	rows.Close()
	for _, e := range evs {
		b, err := eventPayloadBytesTx(ctx, tx, e.id)
		if err != nil {
			return 0, 0, err
		}
		if e.state == EventActive {
			active += b
		} else {
			archived += b
		}
	}
	return active, archived, nil
}

// ArchiveEvent implements policy-B archive at T: active event becomes archived,
// ingest is closed, and the archive tail (remaining 30-day history) is retained
// until T+30d. It does not copy telemetry into another table.
func (s *Store) ArchiveEvent(ctx context.Context, eventID string, now int64) error {
	if _, err := s.EventState(ctx, eventID); err != nil {
		return err
	}
	if s.retentionHook != nil {
		if err := s.retentionHook("archive:begin"); err != nil {
			return fmt.Errorf("store: archive fault injection: %w", err)
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin event archive: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockCapacity(ctx, tx); err != nil {
		return err
	}
	e, err := ensureEventActiveTx(ctx, tx, eventID, now)
	if err != nil {
		return err
	}
	if e.State == EventArchived {
		return ErrEventArchived
	}
	var retained int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM event_catalog WHERE state=? AND data_purged_at IS NULL`, EventArchived).Scan(&retained); err != nil {
		return err
	}
	if retained >= MaxArchivedEventsWithData {
		return &QuotaError{Kind: "archived_events_with_data", Limit: MaxArchivedEventsWithData, Current: retained}
	}
	// Conservative policy-B overlap gate: active+archive payload must stay within
	// 2x the active-only estimate, i.e. archived bytes may not exceed active bytes.
	eventBytes, err := eventPayloadBytesTx(ctx, tx, eventID)
	if err != nil {
		return err
	}
	activeBytes, archivedBytes, err := activeArchivedPayloadBytesTx(ctx, tx)
	if err != nil {
		return err
	}
	budget := ComputeOverlapBudget(s.overlapBudgetBasisBytes(), activeBytes, archivedBytes, eventBytes)
	if budget.Exceeds() {
		return &QuotaError{Kind: "retention_overlap", Limit: budget.BudgetBytes, Current: budget.ProjectedTotalBytes}
	}
	purgeAfter := now + PolicyBArchiveTailSeconds
	if _, err := tx.ExecContext(ctx,
		`UPDATE event_catalog SET state=?, archived_at=?, purge_after=?, updated_at=? WHERE event_id=?`,
		EventArchived, now, purgeAfter, now, eventID); err != nil {
		return fmt.Errorf("store: archive event: %w", err)
	}
	if _, err := appendLedgerTx(ctx, tx, now, "event_archived", eventID, ledgerDetailHash(fmt.Sprintf("T=%d", now))); err != nil {
		return err
	}
	if err := appendAuditFromContextTxFields(ctx, tx, "ok", "event", eventID); err != nil {
		return err
	}
	if s.retentionHook != nil {
		if err := s.retentionHook("archive:write"); err != nil {
			return fmt.Errorf("store: archive fault injection: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit event archive: %w", err)
	}
	return nil
}

// deleteBatched deletes at most RetentionBatchRows per transaction. The helper is
// resumable and idempotent; the optional hook is a test-only fault injection point.
func deleteBatched(ctx context.Context, db *sql.DB, hook func(string) error, table, where string, args ...any) (int64, error) {
	var total int64
	for {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return total, err
		}
		if hook != nil {
			if err := hook("delete:" + table); err != nil {
				_ = tx.Rollback()
				return total, err
			}
		}
		query := fmt.Sprintf(`DELETE FROM %s WHERE rowid IN (SELECT rowid FROM %s WHERE %s ORDER BY rowid LIMIT %d)`,
			table, table, where, RetentionBatchRows)
		res, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			_ = tx.Rollback()
			return total, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			_ = tx.Rollback()
			return total, err
		}
		if err := tx.Commit(); err != nil {
			return total, err
		}
		total += n
		if n < RetentionBatchRows {
			return total, nil
		}
	}
}

// retentionHook is a test-only fault injection point. It must never be set in
// production code paths.
func (s *Store) SetRetentionHookForTest(hook func(string) error) { s.retentionHook = hook }

// RetentionState is the persisted soft-failure/degraded state.
type RetentionState struct {
	Degraded     bool
	FailureCount int64
	LastRunAt    *int64
	LastError    string
}

func (s *Store) GetRetentionState(ctx context.Context) (RetentionState, error) {
	var st RetentionState
	var degraded int
	var last sql.NullInt64
	var lastErr sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT degraded,failure_count,last_run_at,last_error FROM retention_state WHERE id=1`).
		Scan(&degraded, &st.FailureCount, &last, &lastErr)
	if err != nil {
		return RetentionState{}, err
	}
	st.Degraded = degraded != 0
	if last.Valid {
		v := last.Int64
		st.LastRunAt = &v
	}
	st.LastError = lastErr.String
	return st, nil
}

// RetentionTimeline is the testable event lifecycle view.
type RetentionTimeline struct {
	ActiveEvents     int64
	ArchivedEvents   int64
	ArchivedRetained int64
	EventsCatalog    int64
	PurgeTombstones  int64
}

func (s *Store) RetentionTimeline(ctx context.Context) (RetentionTimeline, error) {
	var t RetentionTimeline
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM event_catalog WHERE state=?`, EventActive).Scan(&t.ActiveEvents); err != nil {
		return t, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM event_catalog WHERE state=?`, EventArchived).Scan(&t.ArchivedEvents); err != nil {
		return t, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM event_catalog WHERE state=? AND data_purged_at IS NULL`, EventArchived).Scan(&t.ArchivedRetained); err != nil {
		return t, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM event_catalog`).Scan(&t.EventsCatalog); err != nil {
		return t, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM purge_tombstones`).Scan(&t.PurgeTombstones); err != nil {
		return t, err
	}
	return t, nil
}

// CapacityStatsExtended adds database/WAL bytes and event lifecycle counters.
type CapacityStatsExtended struct {
	CapacityStats
	ActiveEvents        int64
	ArchivedEvents      int64
	ArchivedRetained    int64
	EventsCatalog       int64
	PurgeTombstones     int64
	AdminAuditRows      int64
	DBSizeBytes         int64
	WALSizeBytes        int64
	NodesBytes          int64
	SnapshotsBytes      int64
	MetricsBytes        int64
	EventsBytes         int64
	TrafficBytes        int64
	TrafficReports      int64
	TrafficObservations int64
}

func (s *Store) CapacityStatsExtended(ctx context.Context) (CapacityStatsExtended, error) {
	base, err := s.CapacityStats(ctx)
	if err != nil {
		return CapacityStatsExtended{}, err
	}
	var c CapacityStatsExtended
	c.CapacityStats = base
	if info, err := os.Stat(s.path); err == nil {
		c.DBSizeBytes = info.Size()
	}
	if info, err := os.Stat(s.path + "-wal"); err == nil {
		c.WALSizeBytes = info.Size()
	}
	for _, q := range []struct {
		dst *int64
		sql string
	}{
		{&c.ActiveEvents, `SELECT COUNT(*) FROM event_catalog WHERE state='active'`},
		{&c.ArchivedEvents, `SELECT COUNT(*) FROM event_catalog WHERE state='archived'`},
		{&c.ArchivedRetained, `SELECT COUNT(*) FROM event_catalog WHERE state='archived' AND data_purged_at IS NULL`},
		{&c.EventsCatalog, `SELECT COUNT(*) FROM event_catalog`},
		{&c.PurgeTombstones, `SELECT COUNT(*) FROM purge_tombstones`},
		{&c.AdminAuditRows, `SELECT COUNT(*) FROM admin_audit`},
		{&c.TrafficReports, `SELECT COUNT(*) FROM traffic_observation_reports`},
		{&c.TrafficObservations, `SELECT (SELECT COUNT(*) FROM traffic_observations) + (SELECT COUNT(*) FROM traffic_observation_buckets)`},
	} {
		if err := s.db.QueryRowContext(ctx, q.sql).Scan(q.dst); err != nil {
			return CapacityStatsExtended{}, err
		}
	}
	// Approximate row bytes for the main telemetry tables (payload storage).
	for _, q := range []struct {
		dst *int64
		sql string
	}{
		{&c.NodesBytes, `SELECT COALESCE(SUM(LENGTH(node_id)+LENGTH(event_id)+LENGTH(node_class)+64),0) FROM nodes`},
		{&c.SnapshotsBytes, `SELECT COALESCE(SUM(LENGTH(payload_json)+128),0) FROM snapshots`},
		{&c.MetricsBytes, `SELECT COALESCE(SUM(LENGTH(payload_json)+128),0) FROM report_metrics`},
		{&c.EventsBytes, `SELECT COALESCE((SELECT SUM(LENGTH(details_json)+128) FROM report_events),0) + COALESCE((SELECT SUM(LENGTH(payload_json)+128) FROM report_event_reports),0)`},
		{&c.TrafficBytes, `SELECT (SELECT COALESCE(SUM(bytes_estimate),0) FROM traffic_observation_reports) + (SELECT COALESCE(SUM(bytes_estimate),0) FROM traffic_observation_buckets)`},
	} {
		if err := s.db.QueryRowContext(ctx, q.sql).Scan(q.dst); err != nil {
			return CapacityStatsExtended{}, err
		}
	}
	return c, nil
}

// RunRetentionB2PolicyB applies the frozen policy-B sweep. Each class is pruned
// in bounded transactions; failure is soft and persisted as degraded state.
func (s *Store) RunRetentionB2PolicyB(ctx context.Context, now int64) (map[string]int64, error) {
	deleted := map[string]int64{}
	fail := func(stage string, err error) (map[string]int64, error) {
		msg := stage + ": " + err.Error()
		if len(msg) > 512 {
			msg = msg[:512]
		}
		_, _ = s.db.ExecContext(ctx,
			`UPDATE retention_state SET degraded=1,failure_count=failure_count+1,last_error=? WHERE id=1`, msg)
		return deleted, fmt.Errorf("%w: %v", ErrRetentionDegraded, err)
	}
	hook := s.retentionHook

	// seq_dedupe: delete all old generation rows and keep 256 current rows.
	cutoffSQL := func() (int64, error) {
		return deleteBatched(ctx, s.db, hook, "seq_dedupe",
			`NOT EXISTS (SELECT 1 FROM node_boot b WHERE b.node_id=seq_dedupe.node_id AND b.highest_gen=seq_dedupe.boot_gen AND b.boot_id=seq_dedupe.boot_id)`)
	}
	if n, err := cutoffSQL(); err != nil {
		return fail("seq_dedupe_old_generations", err)
	} else {
		deleted["seq_dedupe_old_generations"] = n
	}
	if n, err := deleteBatched(ctx, s.db, hook, "seq_dedupe", `
		EXISTS (SELECT 1 FROM node_boot b WHERE b.node_id=seq_dedupe.node_id AND b.highest_gen=seq_dedupe.boot_gen AND b.boot_id=seq_dedupe.boot_id)
		AND (SELECT COUNT(*) FROM seq_dedupe d2
		     WHERE d2.node_id=seq_dedupe.node_id AND d2.boot_gen=seq_dedupe.boot_gen
		       AND d2.boot_id=seq_dedupe.boot_id AND d2.seq >= seq_dedupe.seq) > 256`); err != nil {
		return fail("seq_dedupe_current", err)
	} else {
		deleted["seq_dedupe"] = n
	}
	// boot_registry: last 8 generations per node.
	if n, err := deleteBatched(ctx, s.db, hook, "boot_registry", `
		(SELECT COUNT(*) FROM boot_registry r2
		 WHERE r2.node_id=boot_registry.node_id AND r2.boot_gen >= boot_registry.boot_gen) > 8`); err != nil {
		return fail("boot_registry", err)
	} else {
		deleted["boot_registry"] = n
	}
	// nonce/report/activity windows.
	for _, spec := range []struct {
		name  string
		table string
		where string
		arg   int64
	}{
		{"nonce_dedupe", "nonce_dedupe", "received_at < ?", now - 24*60*60},
		{"report_dedupe", "report_dedupe", "COALESCE(last_received_at,first_received_at,0) < ?", now - 8*24*60*60},
		{"report_activity", "report_activity", "received_at < ?", now - 30*24*60*60},
	} {
		if n, err := deleteBatched(ctx, s.db, hook, spec.table, spec.where, spec.arg); err != nil {
			return fail(spec.name, err)
		} else {
			deleted[spec.name] = n
		}
	}
	// Event lifecycle: active rolling 30d; archived tail until T+30d.
	if hook != nil {
		if err := hook("retention:scan_events"); err != nil {
			return fail("event_scan", err)
		}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT event_id,state,archived_at,purge_after,data_purged_at FROM event_catalog`)
	if err != nil {
		return fail("event_scan", err)
	}
	type eventRow struct {
		id                           string
		state                        string
		archived, purgeAfter, purged sql.NullInt64
	}
	var events []eventRow
	for rows.Next() {
		var e eventRow
		if err := rows.Scan(&e.id, &e.state, &e.archived, &e.purgeAfter, &e.purged); err != nil {
			rows.Close()
			return fail("event_scan", err)
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fail("event_scan", err)
	}
	rows.Close()
	for _, e := range events {
		// Re-read lifecycle state inside the per-event step so a concurrent
		// archive/purge cannot make this loop act on a stale state.
		fresh, err := s.EventState(ctx, e.id)
		if err != nil {
			if errors.Is(err, ErrEventUnknown) {
				continue
			}
			return fail("event_refresh", err)
		}
		e.state = fresh.State
		e.archived = nullInt(fresh.ArchivedAt)
		e.purgeAfter = nullInt(fresh.PurgeAfter)
		e.purged = nullInt(fresh.DataPurgedAt)
		var purgeActive int
		if err := s.db.QueryRowContext(ctx, `SELECT 1 FROM purge_ops WHERE event_id=? AND state<>'completed' LIMIT 1`, e.id).Scan(&purgeActive); err == nil {
			// An in-progress purge owns this event's deletion; retention must not
			// race it with a stale lifecycle decision.
			continue
		} else if !errors.Is(err, sql.ErrNoRows) {
			return fail("event_purge_state", err)
		}
		if e.state == EventActive {
			cutoff := now - PolicyBActiveRetentionSeconds
			if _, err := s.db.ExecContext(ctx,
				`DELETE FROM node_latest WHERE event_id=? AND snapshot_id IN (SELECT id FROM snapshots WHERE event_id=? AND collected_at < ?)`,
				e.id, e.id, cutoff); err != nil {
				return fail("active_event_latest", err)
			}
			for _, table := range []string{"traffic_observation_buckets", "traffic_observation_reports", "snapshots", "report_metrics", "report_events", "report_event_reports"} {
				if n, err := deleteBatched(ctx, s.db, hook, table, "event_id=? AND collected_at < ?", e.id, cutoff); err != nil {
					return fail("active_event:"+table, err)
				} else {
					deleted["event:"+table] += n
				}
			}
			continue
		}
		if !e.archived.Valid || !e.purgeAfter.Valid {
			continue
		}
		if now >= e.purgeAfter.Int64 {
			if _, err := s.db.ExecContext(ctx, `DELETE FROM node_latest WHERE event_id=?`, e.id); err != nil {
				return fail("archived_event_latest", err)
			}
			for _, table := range []string{"traffic_observation_buckets", "traffic_observation_reports", "snapshots", "report_metrics", "report_events", "report_event_reports"} {
				if n, err := deleteBatched(ctx, s.db, hook, table, "event_id=?", e.id); err != nil {
					return fail("archived_event:"+table, err)
				} else {
					deleted["event:"+table] += n
				}
			}
			if _, err := s.db.ExecContext(ctx,
				`UPDATE event_catalog SET data_purged_at=?, updated_at=? WHERE event_id=? AND data_purged_at IS NULL`,
				now, now, e.id); err != nil {
				return fail("archived_event_mark", err)
			}
			continue
		}
		// Archive tail: keep only the window that was active at archive time.
		cutoff := e.archived.Int64 - PolicyBActiveRetentionSeconds
		if _, err := s.db.ExecContext(ctx,
			`DELETE FROM node_latest WHERE event_id=? AND snapshot_id IN (SELECT id FROM snapshots WHERE event_id=? AND collected_at < ?)`,
			e.id, e.id, cutoff); err != nil {
			return fail("archive_tail_latest", err)
		}
		for _, table := range []string{"traffic_observation_buckets", "traffic_observation_reports", "snapshots", "report_metrics", "report_events", "report_event_reports"} {
			if n, err := deleteBatched(ctx, s.db, hook, table, "event_id=? AND collected_at < ?", e.id, cutoff); err != nil {
				return fail("archive_tail:"+table, err)
			} else {
				deleted["event:"+table] += n
			}
		}
	}
	// Latest state removal: 30d after last update, or 30d after node retire.
	latestSQL := `(updated_at < ?) OR (node_id IN (SELECT node_id FROM nodes WHERE retired_at IS NOT NULL AND retired_at < ?))`
	// node_latest has updated_at, not collected_at.
	if n, err := deleteBatched(ctx, s.db, hook, "node_latest", latestSQL, now-PolicyBActiveRetentionSeconds, now-PolicyBActiveRetentionSeconds); err != nil {
		return fail("node_latest", err)
	} else {
		deleted["node_latest"] = n
	}
	// UM-B4 admin audit is a formal 180d security-audit class. Age is the only
	// deletion criterion: archived/purged event audits remain until their own
	// 180d boundary, and the independent security ledger is never touched here.
	if n, err := deleteBatched(ctx, s.db, hook, "admin_audit", "at < ?", now-SecurityRetentionSeconds); err != nil {
		return fail("admin_audit", err)
	} else {
		deleted["admin_audit"] = n
	}
	// Retention runs and purge tombstones are themselves bounded.
	if n, err := deleteBatched(ctx, s.db, hook, "retention_runs", `id NOT IN (SELECT id FROM retention_runs ORDER BY id DESC LIMIT ?)`, RetentionRunsKeep-1); err != nil {
		return fail("retention_runs", err)
	} else {
		deleted["retention_runs"] = n
	}
	if n, err := deleteBatched(ctx, s.db, hook, "purge_tombstones", "retain_until < ?", now); err != nil {
		return fail("purge_tombstones", err)
	} else {
		deleted["purge_tombstones"] = n
	}
	// Short-lived purge preview receipts are authorization metadata, not audit;
	// expired rows are safe to prune in the same bounded maintenance path.
	if n, err := deleteBatched(ctx, s.db, hook, "purge_confirmations", "expires_at < ?", now); err != nil {
		return fail("purge_confirmations", err)
	} else {
		deleted["purge_confirmations"] = n
	}
	result, _ := jsonMarshal(deleted)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO retention_runs(ran_at,result_json) VALUES(?,?)`, now, result); err != nil {
		return fail("retention_record", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE retention_state SET degraded=0,last_run_at=?,last_error=NULL WHERE id=1`, now); err != nil {
		return fail("retention_state", err)
	}
	return deleted, nil
}

func jsonMarshal(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}

func nullInt(p *int64) sql.NullInt64 {
	if p == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *p, Valid: true}
}

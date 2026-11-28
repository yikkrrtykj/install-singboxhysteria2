package store

// UM-B4 management store layer: event catalog read/create/rename, scoped node
// inventory and detail, enrollment-token administration and revocation, aliases,
// route-mapping history, purge preview/status and retention-run history.
//
// The layer reuses the existing B1/B2 engines (one SQLite database, the same
// lifecycle gate, purge engine, mapping tables, config history and enrollment
// token table). It does not add a second database or a second source of truth.
//
// Authorization is resolved before the store is called: the caller passes the
// already-resolved event scope (nil = platform-wide, empty = no events). Every
// method additionally validates its ids/strings and applies bounded paging so a
// malformed or hostile management request cannot widen a query or exhaust
// memory. Administrative mutations append the caller-supplied AuditMeta row in
// the same transaction as the mutation (see b4_audit.go); internal/agent calls
// without AuditMeta are unaffected.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// UM-B4 bounded page/string limits. The management boundary keeps the same
// upper bound; the store clamps defensively rather than trusting the caller.
const (
	// B4MaxPageLimit is the largest page a management list may request.
	B4MaxPageLimit = 100
	// B4MaxOffset is the largest row offset a management list may request.
	B4MaxOffset = 100000
	// B4DefaultPageLimit is used when the caller passes a non-positive limit.
	B4DefaultPageLimit = 50

	b4MaxIdentifierBytes  = 128
	b4MaxDisplayNameBytes = 128
	// b4MaxDetailSnapshotBytes bounds the raw latest-snapshot body returned by
	// GetNodeDetail. Stored snapshots are already decoded-body bounded by the
	// center; this is a second, hard store-side ceiling.
	b4MaxDetailSnapshotBytes = 1 << 20
)

// UM-B4 sentinel errors. ErrEventUnknown is the B2 lifecycle sentinel reused for
// every scope miss so an out-of-scope event is indistinguishable from a missing
// one. ErrAliasConflict covers optimistic-concurrency alias writes.
var (
	// ErrAliasConflict reports an alias create/update that does not match the
	// caller's expected version (or a blind upsert of an existing alias).
	ErrAliasConflict = errors.New("store: alias conflict")
	// ErrTokenRevoked reports enrollment with an administratively revoked token.
	ErrTokenRevoked = errors.New("store: enrollment token revoked")
)

// Alias target types (closed vocabulary, also enforced by the schema CHECK).
const (
	AliasTargetNode      = "node"
	AliasTargetDeviceRef = "device_ref"
	AliasTargetRoute     = "route"
)

var allowedAliasTargetTypes = map[string]struct{}{
	AliasTargetNode:      {},
	AliasTargetDeviceRef: {},
	AliasTargetRoute:     {},
}

// allowedAliasRouteTokens is the frozen display route vocabulary: the four A/B
// protocol tokens plus the reserved direct/unknown display tokens (six total).
var allowedAliasRouteTokens = map[string]struct{}{
	RouteTokenAReality: {},
	RouteTokenAHy2:     {},
	RouteTokenBReality: {},
	RouteTokenBHy2:     {},
	RouteTokenDirect:   {},
	"unknown":          {},
}

// Enrollment-token administrative status values.
const (
	EnrollTokenStatusUnused  = "unused"
	EnrollTokenStatusUsed    = "used"
	EnrollTokenStatusRevoked = "revoked"
	EnrollTokenStatusExpired = "expired"
)

var tokenHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// EventRecord is one management-view event catalog row. DisplayName is empty for
// catalog rows auto-created by the pre-B4 enrollment/ingest lifecycle.
type EventRecord struct {
	EventID      string
	DisplayName  string
	State        string
	CreatedAt    int64
	ArchivedAt   *int64
	PurgeAfter   *int64
	DataPurgedAt *int64
	NodeCount    int64
	ActiveNodes  int64
	LinuxNodes   int64
	WindowsNodes int64
}

// EventListFilter is a closed, bounded event-catalog filter. States may contain
// only active/archived; an empty States slice means all lifecycle states.
type EventListFilter struct {
	States []string
	Limit  int
	Offset int
}

// NodeKeyInfo is one node identity key as exposed to management. It deliberately
// omits the public key and every private-key field.
type NodeKeyInfo struct {
	KeyID       string
	State       string
	CreatedAt   *int64
	ActivatedAt *int64
	RevokedAt   *int64
}

// RotationInfo is one persisted rotation intent for management display.
type RotationInfo struct {
	OldKeyID  string
	NewKeyID  string
	Nonce     string
	State     string
	ExpiresAt *int64
	CreatedAt *int64
}

// NodeSummary is one scoped node inventory row, enriched with the current config,
// latest snapshot pointer and the node alias (no N+1 queries).
type NodeSummary struct {
	NodeID    string
	EventID   string
	NodeClass string
	State     string
	CreatedAt int64

	LastSeenAt       *int64
	RetiredAt        *int64
	ConfigVersion    *int64
	CadenceSeconds   *int64
	LatestSnapshotAt *int64
	LatestReportID   string
	Alias            string
}

// NodeDetail is one node's full management view. LatestSnapshot is the raw
// stored snapshot body of the current latest snapshot, bounded by
// b4MaxDetailSnapshotBytes.
type NodeDetail struct {
	NodeSummary
	Keys           []NodeKeyInfo
	Rotations      []RotationInfo
	LatestSnapshot []byte
}

// ConfigHistoryEntry is one effective-dated node configuration history row.
type ConfigHistoryEntry struct {
	ConfigVersion    int64
	EffectiveFrom    int64
	CadenceSeconds   int64
	SourcesJSON      string
	ExpectedTagsJSON string
	DeviceSalt       string
}

// EnrollTokenAdmin is the management view of an enrollment token. Only the hash
// is exposed; the plaintext token is never stored and never readable.
type EnrollTokenAdmin struct {
	TokenHash string
	EventID   string
	NodeClass string
	CreatedAt *int64
	ExpiresAt *int64
	UsedAt    *int64
	RevokedAt *int64
	Status    string
}

// Alias is one event-scoped display alias.
type Alias struct {
	EventID     string
	TargetType  string
	TargetKey   string
	DisplayName string
	Version     int64
	UpdatedAt   int64
	UpdatedBy   string
}

// MappingVersion is one immutable route-mapping version with its entries.
type MappingVersion struct {
	Version       int64
	EffectiveFrom int64
	CreatedBy     string
	CreatedAt     int64
	Entries       map[string]string
}

// PurgePreview is the bounded pre-purge inventory of one event. TableCounts is
// keyed by the fixed table names this store knows; no raw SQL or schema text is
// exposed.
type PurgePreview struct {
	Event       EventRecord
	TableCounts map[string]int64
	TotalRows   int64
	DataPurged  bool
	Incomplete  bool
}

// PurgeStatus is the latest durable purge state plus permanent graveyard and
// 180-day tombstone retention information.
type PurgeStatus struct {
	EventID        string
	Phase          string
	State          string
	DeletedRows    int64
	Error          string
	Graveyard      bool
	Purged         bool
	TombstoneUntil *int64
}

// RetentionRun is one recorded bounded-retention run.
type RetentionRun struct {
	ID            int64
	StartedAt     *int64
	FinishedAt    *int64
	Status        string
	DeletedCounts map[string]int64
}

// --- validation helpers -----------------------------------------------------

func hasControlOrNewline(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// validateDisplayName validates the bounded human label used for event display
// names and aliases: trimmed, 1..128 bytes of valid UTF-8, no control/line-break
// characters. It returns the trimmed value that must be persisted.
func validateDisplayName(field, raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", invalidArgument(field, "must not be empty")
	}
	if len(value) > b4MaxDisplayNameBytes {
		return "", invalidArgument(field, "must be at most 128 bytes")
	}
	if !utf8.ValidString(value) {
		return "", invalidArgument(field, "must be valid UTF-8")
	}
	if hasControlOrNewline(value) {
		return "", invalidArgument(field, "must not contain control or line-break characters")
	}
	return value, nil
}

// validateBoundedText validates a bounded identifier/text value: trimmed, 1..max
// bytes of valid UTF-8, no control/line-break characters.
func validateBoundedText(field, raw string, max int) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", invalidArgument(field, "must not be empty")
	}
	if len(value) > max {
		return "", invalidArgument(field, fmt.Sprintf("must be at most %d bytes", max))
	}
	if !utf8.ValidString(value) {
		return "", invalidArgument(field, "must be valid UTF-8")
	}
	if hasControlOrNewline(value) {
		return "", invalidArgument(field, "must not contain control or line-break characters")
	}
	return value, nil
}

func validateEventID(field, eventID string) error {
	if !IsUUIDv4(eventID) {
		return invalidArgument(field, "must be a canonical lowercase UUIDv4")
	}
	return nil
}

// validateNodeID accepts the bounded opaque node-id form. Enrolled node ids are
// UUIDv4; the opaque form keeps older/imported identities addressable without
// weakening the SQL (values are always bound parameters).
func validateNodeID(field, nodeID string) error {
	_, err := validateBoundedText(field, nodeID, b4MaxIdentifierBytes)
	return err
}

func validateTokenHash(tokenHash string) error {
	if !tokenHashPattern.MatchString(tokenHash) {
		return invalidArgument("token_hash", "must be a lowercase hex SHA-256")
	}
	return nil
}

func b4NormalizeLimit(limit int) int {
	if limit <= 0 {
		return B4DefaultPageLimit
	}
	if limit > B4MaxPageLimit {
		return B4MaxPageLimit
	}
	return limit
}

func b4NormalizeOffset(offset int) (int, error) {
	if offset < 0 {
		return 0, nil
	}
	if offset > B4MaxOffset {
		return 0, invalidArgument("offset", "must be at most 100000")
	}
	return offset, nil
}

// scopeAllows reports whether an already-resolved event scope permits eventID.
// nil means platform-wide; an empty non-nil scope permits nothing.
func scopeAllows(scope []string, eventID string) bool {
	if scope == nil {
		return true
	}
	for _, id := range scope {
		if id == eventID {
			return true
		}
	}
	return false
}

// buildScopeClause builds a bound IN predicate for an already-resolved scope.
// nil returns an empty clause (platform-wide); an empty non-nil scope returns a
// "1=0" clause so the caller cannot accidentally read platform-wide.
func buildScopeClause(column string, scope []string) (string, []any) {
	if scope == nil {
		return "", nil
	}
	if len(scope) == 0 {
		return "1=0", nil
	}
	placeholders := make([]string, len(scope))
	args := make([]any, len(scope))
	for i, id := range scope {
		placeholders[i] = "?"
		args[i] = id
	}
	return column + " IN (" + strings.Join(placeholders, ",") + ")", args
}

func combineWhereClauses(clauses []string) string {
	filtered := make([]string, 0, len(clauses))
	for _, clause := range clauses {
		if clause != "" {
			filtered = append(filtered, clause)
		}
	}
	if len(filtered) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(filtered, " AND ")
}

func nullInt64Pointer(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	v := value.Int64
	return &v
}

// --- event catalog ----------------------------------------------------------

const eventRecordSelect = `SELECT e.event_id, COALESCE(e.display_name,''), e.state, e.created_at,
	e.archived_at, e.purge_after, e.data_purged_at,
	(SELECT COUNT(*) FROM nodes n WHERE n.event_id=e.event_id),
	(SELECT COUNT(*) FROM nodes n WHERE n.event_id=e.event_id AND n.state='active'),
	(SELECT COUNT(*) FROM nodes n WHERE n.event_id=e.event_id AND n.node_class='linux_vps'),
	(SELECT COUNT(*) FROM nodes n WHERE n.event_id=e.event_id AND n.node_class='windows_terminal')
 FROM event_catalog e`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanEventRecordInto(scanner rowScanner, rec *EventRecord) error {
	var archived, purgeAfter, purged sql.NullInt64
	if err := scanner.Scan(&rec.EventID, &rec.DisplayName, &rec.State, &rec.CreatedAt,
		&archived, &purgeAfter, &purged,
		&rec.NodeCount, &rec.ActiveNodes, &rec.LinuxNodes, &rec.WindowsNodes); err != nil {
		return err
	}
	rec.ArchivedAt = nullInt64Pointer(archived)
	rec.PurgeAfter = nullInt64Pointer(purgeAfter)
	rec.DataPurgedAt = nullInt64Pointer(purged)
	return nil
}

func (s *Store) loadEventRecord(ctx context.Context, eventID string) (EventRecord, error) {
	var rec EventRecord
	err := scanEventRecordInto(s.db.QueryRowContext(ctx, eventRecordSelect+" WHERE e.event_id=?", eventID), &rec)
	return rec, err
}

// CreateEvent creates one explicit management event catalog entry. It fails if
// the identity exists in the catalog, is in the permanent graveyard, or has an
// incomplete purge; it enforces MaxEventsCatalog and records both the
// hash-chained event_created ledger and the caller's admin_audit row in the same
// transaction.
func (s *Store) CreateEvent(ctx context.Context, eventID, displayName string, now int64) (EventRecord, error) {
	if err := validateEventID("event_id", eventID); err != nil {
		return EventRecord{}, err
	}
	name, err := validateDisplayName("display_name", displayName)
	if err != nil {
		return EventRecord{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return EventRecord{}, fmt.Errorf("store: begin event create: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockCapacity(ctx, tx); err != nil {
		return EventRecord{}, err
	}
	// Permanent graveyard and in-progress purge both fail closed.
	if err := eventBlockedTx(ctx, tx, eventID); err != nil {
		return EventRecord{}, err
	}
	var existing int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM event_catalog WHERE event_id=?`, eventID).Scan(&existing)
	switch {
	case err == nil:
		return EventRecord{}, fmt.Errorf("%w: event %q", ErrAlreadyExists, eventID)
	case !errors.Is(err, sql.ErrNoRows):
		return EventRecord{}, fmt.Errorf("store: read event catalog: %w", err)
	}
	var count int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM event_catalog`).Scan(&count); err != nil {
		return EventRecord{}, fmt.Errorf("store: count event catalog: %w", err)
	}
	if count >= MaxEventsCatalog {
		return EventRecord{}, &QuotaError{Kind: "events_catalog", Limit: MaxEventsCatalog, Current: count}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO event_catalog(event_id,state,created_at,archived_at,purge_after,data_purged_at,updated_at,display_name)
		 VALUES(?,?,?,NULL,NULL,NULL,?,?)`,
		eventID, EventActive, now, now, name); err != nil {
		if isUniqueViolation(err) {
			return EventRecord{}, fmt.Errorf("%w: event %q", ErrAlreadyExists, eventID)
		}
		return EventRecord{}, fmt.Errorf("store: create event catalog: %w", err)
	}
	if _, err := appendLedgerTx(ctx, tx, now, "event_created", eventID, ledgerDetailHash(name)); err != nil {
		return EventRecord{}, err
	}
	if err := appendAuditFromContextTxFields(ctx, tx, "ok", "event", eventID); err != nil {
		return EventRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return EventRecord{}, fmt.Errorf("store: commit event create: %w", err)
	}
	return EventRecord{EventID: eventID, DisplayName: name, State: EventActive, CreatedAt: now}, nil
}

// RenameEvent updates the display name of an existing, not permanently purged
// event. Archived events keep their identity and can be renamed; an event whose
// telemetry was already retention-purged, an in-progress purge and the permanent
// graveyard are rejected.
func (s *Store) RenameEvent(ctx context.Context, eventID, displayName string, now int64) error {
	if err := validateEventID("event_id", eventID); err != nil {
		return err
	}
	name, err := validateDisplayName("display_name", displayName)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin event rename: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := eventBlockedTx(ctx, tx, eventID); err != nil {
		return err
	}
	var purgedAt sql.NullInt64
	err = tx.QueryRowContext(ctx,
		`SELECT data_purged_at FROM event_catalog WHERE event_id=?`, eventID).Scan(&purgedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrEventUnknown
	}
	if err != nil {
		return fmt.Errorf("store: read event catalog: %w", err)
	}
	if purgedAt.Valid {
		return ErrEventPurged
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE event_catalog SET display_name=?, updated_at=? WHERE event_id=?`,
		name, now, eventID); err != nil {
		return fmt.Errorf("store: rename event: %w", err)
	}
	if err := appendAuditFromContextTxFields(ctx, tx, "ok", "event", eventID); err != nil {
		return err
	}
	return tx.Commit()
}

// ListEvents returns one bounded page of the event catalog visible under the
// already-resolved scope plus the total match count. Ordering is stable:
// created_at then event_id.
func (s *Store) ListEvents(ctx context.Context, scope []string, filter EventListFilter) ([]EventRecord, int64, error) {
	limit := b4NormalizeLimit(filter.Limit)
	offset, err := b4NormalizeOffset(filter.Offset)
	if err != nil {
		return nil, 0, err
	}
	for _, state := range filter.States {
		if state != EventActive && state != EventArchived {
			return nil, 0, invalidArgument("states", "must contain only active or archived")
		}
	}
	scopeClause, args := buildScopeClause("e.event_id", scope)
	clauses := []string{scopeClause}
	if len(filter.States) > 0 {
		placeholders := make([]string, len(filter.States))
		for i, state := range filter.States {
			placeholders[i] = "?"
			args = append(args, state)
		}
		clauses = append(clauses, "e.state IN ("+strings.Join(placeholders, ",")+")")
	}
	where := combineWhereClauses(clauses)
	var total int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM event_catalog e`+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: count events: %w", err)
	}
	rows, err := s.db.QueryContext(ctx,
		eventRecordSelect+where+" ORDER BY e.created_at, e.event_id LIMIT ? OFFSET ?",
		append(args, limit, offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("store: list events: %w", err)
	}
	defer rows.Close()
	events := make([]EventRecord, 0)
	for rows.Next() {
		var rec EventRecord
		if err := scanEventRecordInto(rows, &rec); err != nil {
			return nil, 0, fmt.Errorf("store: list events: %w", err)
		}
		events = append(events, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("store: list events: %w", err)
	}
	return events, total, nil
}

// GetEvent returns one event visible under the already-resolved scope. A scope
// miss is ErrEventUnknown so a caller cannot distinguish it from a missing
// event; permanently purged identities are ErrEventPurged.
func (s *Store) GetEvent(ctx context.Context, eventID string, scope []string) (EventRecord, error) {
	if err := validateEventID("event_id", eventID); err != nil {
		return EventRecord{}, err
	}
	if !scopeAllows(scope, eventID) {
		return EventRecord{}, ErrEventUnknown
	}
	rec, err := s.loadEventRecord(ctx, eventID)
	if errors.Is(err, sql.ErrNoRows) {
		graveyard, gerr := s.EventGraveyardExists(ctx, eventID)
		if gerr != nil {
			return EventRecord{}, gerr
		}
		if graveyard {
			return EventRecord{}, ErrEventPurged
		}
		return EventRecord{}, ErrEventUnknown
	}
	if err != nil {
		return EventRecord{}, fmt.Errorf("store: get event: %w", err)
	}
	return rec, nil
}

// --- node inventory ---------------------------------------------------------

const nodeSummarySelect = `SELECT n.node_id, n.event_id, n.node_class, n.state, n.created_at,
	n.last_seen_at, n.retired_at, c.config_version, c.cadence_seconds,
	l.collected_at, COALESCE(l.report_id,''), COALESCE(a.display_name,'')
 FROM nodes n
 LEFT JOIN node_configs c ON c.node_id=n.node_id
 LEFT JOIN node_latest l ON l.node_id=n.node_id
 LEFT JOIN aliases a ON a.event_id=n.event_id AND a.target_type='node' AND a.target_key=n.node_id`

func scanNodeSummaryInto(scanner rowScanner, node *NodeSummary) error {
	var lastSeen, retiredAt, configVersion, cadence, latestSnapshot sql.NullInt64
	if err := scanner.Scan(&node.NodeID, &node.EventID, &node.NodeClass, &node.State, &node.CreatedAt,
		&lastSeen, &retiredAt, &configVersion, &cadence, &latestSnapshot, &node.LatestReportID, &node.Alias); err != nil {
		return err
	}
	node.LastSeenAt = nullInt64Pointer(lastSeen)
	node.RetiredAt = nullInt64Pointer(retiredAt)
	node.ConfigVersion = nullInt64Pointer(configVersion)
	node.CadenceSeconds = nullInt64Pointer(cadence)
	node.LatestSnapshotAt = nullInt64Pointer(latestSnapshot)
	return nil
}

func validateNodeClassFilter(class string) error {
	if class != "" && class != NodeClassLinuxVPS && class != NodeClassWindowsTerminal {
		return invalidArgument("node_class", "must be linux_vps or windows_terminal")
	}
	return nil
}

func validateNodeStateFilter(state string) error {
	if state != "" && state != NodeActive && state != NodeRevoked && state != "retired" {
		return invalidArgument("state", "must be active, revoked or retired")
	}
	return nil
}

// ListNodes returns a bounded page of the scoped node inventory with config,
// latest-snapshot pointer and node alias joined in a single query (no N+1).
func (s *Store) ListNodes(ctx context.Context, scope []string, eventID, class, state string, limit, offset int) ([]NodeSummary, int64, error) {
	if eventID != "" {
		if err := validateEventID("event_id", eventID); err != nil {
			return nil, 0, err
		}
		if !scopeAllows(scope, eventID) {
			return nil, 0, ErrEventUnknown
		}
	}
	if err := validateNodeClassFilter(class); err != nil {
		return nil, 0, err
	}
	if err := validateNodeStateFilter(state); err != nil {
		return nil, 0, err
	}
	limit = b4NormalizeLimit(limit)
	offset, err := b4NormalizeOffset(offset)
	if err != nil {
		return nil, 0, err
	}
	scopeClause, args := buildScopeClause("n.event_id", scope)
	clauses := []string{scopeClause}
	if eventID != "" {
		clauses = append(clauses, "n.event_id=?")
		args = append(args, eventID)
	}
	if class != "" {
		clauses = append(clauses, "n.node_class=?")
		args = append(args, class)
	}
	switch state {
	case NodeActive, NodeRevoked:
		clauses = append(clauses, "n.state=?")
		args = append(args, state)
	case "retired":
		// Retirement is recorded by retired_at; the frozen node state vocabulary
		// keeps revoked. The management filter exposes it as "retired".
		clauses = append(clauses, "n.retired_at IS NOT NULL")
	}
	where := combineWhereClauses(clauses)
	var total int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM nodes n`+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: count nodes: %w", err)
	}
	rows, err := s.db.QueryContext(ctx,
		nodeSummarySelect+where+" ORDER BY n.created_at DESC, n.node_id ASC LIMIT ? OFFSET ?",
		append(args, limit, offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("store: list nodes: %w", err)
	}
	defer rows.Close()
	nodes := make([]NodeSummary, 0)
	for rows.Next() {
		var node NodeSummary
		if err := scanNodeSummaryInto(rows, &node); err != nil {
			return nil, 0, fmt.Errorf("store: list nodes: %w", err)
		}
		nodes = append(nodes, node)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("store: list nodes: %w", err)
	}
	return nodes, total, nil
}

// GetNodeDetail returns one scoped node with its non-secret key history, rotation
// intents and the raw latest snapshot bounded by b4MaxDetailSnapshotBytes.
func (s *Store) GetNodeDetail(ctx context.Context, scope []string, eventID, nodeID string) (NodeDetail, error) {
	if err := validateEventID("event_id", eventID); err != nil {
		return NodeDetail{}, err
	}
	if !scopeAllows(scope, eventID) {
		return NodeDetail{}, ErrEventUnknown
	}
	if err := validateNodeID("node_id", nodeID); err != nil {
		return NodeDetail{}, err
	}
	var detail NodeDetail
	err := scanNodeSummaryInto(s.db.QueryRowContext(ctx,
		nodeSummarySelect+" WHERE n.node_id=? AND n.event_id=?", nodeID, eventID), &detail.NodeSummary)
	if errors.Is(err, sql.ErrNoRows) {
		return NodeDetail{}, fmt.Errorf("%w: node %q", ErrNotFound, nodeID)
	}
	if err != nil {
		return NodeDetail{}, fmt.Errorf("store: get node detail: %w", err)
	}
	detail.Keys = make([]NodeKeyInfo, 0)
	keyRows, err := s.db.QueryContext(ctx,
		`SELECT key_id, state, created_at, activated_at, revoked_at
		 FROM node_keys WHERE node_id=? ORDER BY created_at, key_id`, nodeID)
	if err != nil {
		return NodeDetail{}, fmt.Errorf("store: list node keys: %w", err)
	}
	for keyRows.Next() {
		var key NodeKeyInfo
		var created, activated, revoked sql.NullInt64
		if err := keyRows.Scan(&key.KeyID, &key.State, &created, &activated, &revoked); err != nil {
			keyRows.Close()
			return NodeDetail{}, fmt.Errorf("store: list node keys: %w", err)
		}
		key.CreatedAt = nullInt64Pointer(created)
		key.ActivatedAt = nullInt64Pointer(activated)
		key.RevokedAt = nullInt64Pointer(revoked)
		detail.Keys = append(detail.Keys, key)
	}
	if err := keyRows.Err(); err != nil {
		keyRows.Close()
		return NodeDetail{}, fmt.Errorf("store: list node keys: %w", err)
	}
	keyRows.Close()

	detail.Rotations = make([]RotationInfo, 0)
	rotationRows, err := s.db.QueryContext(ctx,
		`SELECT old_key_id, new_key_id, nonce, state, expires_at, created_at
		 FROM key_rotations WHERE node_id=? ORDER BY created_at DESC, nonce ASC`, nodeID)
	if err != nil {
		return NodeDetail{}, fmt.Errorf("store: list node rotations: %w", err)
	}
	for rotationRows.Next() {
		var rotation RotationInfo
		var expiresAt, createdAt sql.NullInt64
		if err := rotationRows.Scan(&rotation.OldKeyID, &rotation.NewKeyID, &rotation.Nonce,
			&rotation.State, &expiresAt, &createdAt); err != nil {
			rotationRows.Close()
			return NodeDetail{}, fmt.Errorf("store: list node rotations: %w", err)
		}
		rotation.ExpiresAt = nullInt64Pointer(expiresAt)
		rotation.CreatedAt = nullInt64Pointer(createdAt)
		detail.Rotations = append(detail.Rotations, rotation)
	}
	if err := rotationRows.Err(); err != nil {
		rotationRows.Close()
		return NodeDetail{}, fmt.Errorf("store: list node rotations: %w", err)
	}
	rotationRows.Close()

	var payload []byte
	err = s.db.QueryRowContext(ctx,
		`SELECT s.payload_json FROM node_latest l JOIN snapshots s ON s.id=l.snapshot_id
		 WHERE l.node_id=? AND l.event_id=?`, nodeID, eventID).Scan(&payload)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		detail.LatestSnapshot = nil
	case err != nil:
		return NodeDetail{}, fmt.Errorf("store: read latest snapshot: %w", err)
	default:
		if len(payload) > b4MaxDetailSnapshotBytes {
			return NodeDetail{}, fmt.Errorf("store: latest snapshot for node %q exceeds the bounded detail size", nodeID)
		}
		detail.LatestSnapshot = payload
	}
	return detail, nil
}

// ListConfigHistory returns the newest bounded page of effective-dated config
// history for one existing node.
func (s *Store) ListConfigHistory(ctx context.Context, nodeID string, limit int) ([]ConfigHistoryEntry, error) {
	if err := validateNodeID("node_id", nodeID); err != nil {
		return nil, err
	}
	limit = b4NormalizeLimit(limit)
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM nodes WHERE node_id=?`, nodeID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: node %q", ErrNotFound, nodeID)
	}
	if err != nil {
		return nil, fmt.Errorf("store: read config history node: %w", err)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT config_version, effective_from, cadence_seconds, sources_json,
		        expected_inbound_tags_json, device_salt
		 FROM node_config_history WHERE node_id=?
		 ORDER BY effective_from DESC, config_version DESC LIMIT ?`, nodeID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list config history: %w", err)
	}
	defer rows.Close()
	entries := make([]ConfigHistoryEntry, 0)
	for rows.Next() {
		var entry ConfigHistoryEntry
		if err := rows.Scan(&entry.ConfigVersion, &entry.EffectiveFrom, &entry.CadenceSeconds,
			&entry.SourcesJSON, &entry.ExpectedTagsJSON, &entry.DeviceSalt); err != nil {
			return nil, fmt.Errorf("store: list config history: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list config history: %w", err)
	}
	return entries, nil
}

// --- enrollment token administration ---------------------------------------

func enrollTokenStatus(usedAt, revokedAt, expiresAt sql.NullInt64, now int64) string {
	if revokedAt.Valid {
		return EnrollTokenStatusRevoked
	}
	if usedAt.Valid {
		return EnrollTokenStatusUsed
	}
	if !expiresAt.Valid || expiresAt.Int64 <= now {
		return EnrollTokenStatusExpired
	}
	return EnrollTokenStatusUnused
}

// ListEnrollTokens returns one bounded page of hashed enrollment-token metadata
// visible under the already-resolved scope. The status is derived from the
// stored timestamps relative to now.
func (s *Store) ListEnrollTokens(ctx context.Context, scope []string, eventID string, limit, offset int) ([]EnrollTokenAdmin, int64, error) {
	if eventID != "" {
		if err := validateEventID("event_id", eventID); err != nil {
			return nil, 0, err
		}
		if !scopeAllows(scope, eventID) {
			return nil, 0, ErrEventUnknown
		}
	}
	limit = b4NormalizeLimit(limit)
	offset, err := b4NormalizeOffset(offset)
	if err != nil {
		return nil, 0, err
	}
	scopeClause, args := buildScopeClause("t.event_id", scope)
	clauses := []string{scopeClause}
	if eventID != "" {
		clauses = append(clauses, "t.event_id=?")
		args = append(args, eventID)
	}
	where := combineWhereClauses(clauses)
	var total int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM enroll_tokens t`+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: count enrollment tokens: %w", err)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT t.token_hash, t.event_id, t.node_class, t.created_at, t.expires_at, t.used_at, t.revoked_at
		 FROM enroll_tokens t`+where+`
		 ORDER BY COALESCE(t.created_at,0) DESC, t.token_hash ASC LIMIT ? OFFSET ?`,
		append(args, limit, offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("store: list enrollment tokens: %w", err)
	}
	defer rows.Close()
	now := nowUnix()
	tokens := make([]EnrollTokenAdmin, 0)
	for rows.Next() {
		var token EnrollTokenAdmin
		var tokenEvent, nodeClass sql.NullString
		var createdAt, expiresAt, usedAt, revokedAt sql.NullInt64
		if err := rows.Scan(&token.TokenHash, &tokenEvent, &nodeClass, &createdAt, &expiresAt, &usedAt, &revokedAt); err != nil {
			return nil, 0, fmt.Errorf("store: list enrollment tokens: %w", err)
		}
		token.EventID = tokenEvent.String
		token.NodeClass = nodeClass.String
		token.CreatedAt = nullInt64Pointer(createdAt)
		token.ExpiresAt = nullInt64Pointer(expiresAt)
		token.UsedAt = nullInt64Pointer(usedAt)
		token.RevokedAt = nullInt64Pointer(revokedAt)
		token.Status = enrollTokenStatus(usedAt, revokedAt, expiresAt, now)
		tokens = append(tokens, token)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("store: list enrollment tokens: %w", err)
	}
	return tokens, total, nil
}

// RevokeEnrollToken revokes one unused, unexpired enrollment token. Revoking an
// already revoked token is idempotent success; a used token, an expired token
// and an unknown hash are distinct errors. The security ledger and the caller's
// admin_audit row commit in the same transaction as the revocation.
func (s *Store) RevokeEnrollToken(ctx context.Context, eventID, tokenHash string, now int64) error {
	if err := validateEventID("event_id", eventID); err != nil {
		return err
	}
	if err := validateTokenHash(tokenHash); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin revoke enrollment token: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var usedAt, revokedAt, expiresAt sql.NullInt64
	err = tx.QueryRowContext(ctx,
		`SELECT used_at, revoked_at, expires_at FROM enroll_tokens WHERE token_hash=? AND event_id=?`,
		tokenHash, eventID).Scan(&usedAt, &revokedAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrTokenInvalid
	}
	if err != nil {
		return fmt.Errorf("store: read enrollment token: %w", err)
	}
	if revokedAt.Valid {
		// Idempotent: the audit/ledger row was already written by the first
		// successful revocation.
		return nil
	}
	if usedAt.Valid {
		return ErrTokenUsed
	}
	if !expiresAt.Valid || expiresAt.Int64 <= now {
		return ErrTokenExpired
	}
	result, err := tx.ExecContext(ctx,
		`UPDATE enroll_tokens SET revoked_at=? WHERE token_hash=? AND event_id=? AND used_at IS NULL AND revoked_at IS NULL`,
		now, tokenHash, eventID)
	if err != nil {
		return fmt.Errorf("store: revoke enrollment token: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: revoke enrollment token: %w", err)
	}
	if affected != 1 {
		return ErrTokenUsed
	}
	actor := auditActorFromContext(ctx, "admin")
	if _, err := appendLedgerTx(ctx, tx, now, "enroll_token_revoked", eventID,
		ledgerDetailHash(tokenHash+"|"+actor)); err != nil {
		return err
	}
	if err := appendAuditFromContextTxFields(ctx, tx, "ok", "enroll_token", eventID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit revoke enrollment token: %w", err)
	}
	return nil
}

// --- aliases ----------------------------------------------------------------

func validateAliasTarget(targetType, targetKey string) (string, error) {
	if _, ok := allowedAliasTargetTypes[targetType]; !ok {
		return "", invalidArgument("target_type", "must be node, device_ref or route")
	}
	key, err := validateBoundedText("target_key", targetKey, b4MaxIdentifierBytes)
	if err != nil {
		return "", err
	}
	switch targetType {
	case AliasTargetRoute:
		if _, ok := allowedAliasRouteTokens[key]; !ok {
			return "", invalidArgument("target_key", "must be one of the six route display tokens")
		}
	}
	return key, nil
}

// SetAlias creates or version-updates one event-scoped display alias with
// optimistic concurrency: creating requires expectedVersion == nil (version 1),
// updating requires the caller's expected version to match the stored version.
// Node targets must exist in the event; route targets must be one of the six
// frozen display tokens. The caller's admin_audit row commits in the same
// transaction when present.
func (s *Store) SetAlias(ctx context.Context, eventID, targetType, targetKey, displayName, actor string, expectedVersion *int64, now int64) (Alias, error) {
	if err := validateEventID("event_id", eventID); err != nil {
		return Alias{}, err
	}
	key, err := validateAliasTarget(targetType, targetKey)
	if err != nil {
		return Alias{}, err
	}
	display, err := validateDisplayName("display_name", displayName)
	if err != nil {
		return Alias{}, err
	}
	trimmedActor, err := validateBoundedText("actor", actor, b4MaxIdentifierBytes)
	if err != nil {
		return Alias{}, err
	}
	if expectedVersion != nil && *expectedVersion < 1 {
		return Alias{}, invalidArgument("expected_version", "must be a positive integer")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Alias{}, fmt.Errorf("store: begin alias write: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := (&Tx{tx: tx}).EventActiveTx(ctx, eventID); err != nil {
		return Alias{}, err
	}
	if targetType == AliasTargetNode {
		var nodeExists int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM nodes WHERE node_id=? AND event_id=?`, key, eventID).Scan(&nodeExists)
		if errors.Is(err, sql.ErrNoRows) {
			return Alias{}, invalidArgument("target_key", "node target must exist in the event")
		}
		if err != nil {
			return Alias{}, fmt.Errorf("store: read alias node target: %w", err)
		}
	}
	alias := Alias{EventID: eventID, TargetType: targetType, TargetKey: key, UpdatedAt: now, UpdatedBy: trimmedActor}
	var currentVersion int64
	err = tx.QueryRowContext(ctx,
		`SELECT version FROM aliases WHERE event_id=? AND target_type=? AND target_key=?`,
		eventID, targetType, key).Scan(&currentVersion)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if expectedVersion != nil {
			return Alias{}, ErrAliasConflict
		}
		alias.Version = 1
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO aliases(event_id,target_type,target_key,display_name,version,updated_at,updated_by)
			 VALUES(?,?,?,?,1,?,?)`,
			eventID, targetType, key, display, now, trimmedActor); err != nil {
			if isUniqueViolation(err) {
				return Alias{}, ErrAliasConflict
			}
			return Alias{}, fmt.Errorf("store: create alias: %w", err)
		}
	case err != nil:
		return Alias{}, fmt.Errorf("store: read alias version: %w", err)
	default:
		if expectedVersion == nil || *expectedVersion != currentVersion {
			return Alias{}, ErrAliasConflict
		}
		alias.Version = currentVersion + 1
		result, err := tx.ExecContext(ctx,
			`UPDATE aliases SET display_name=?, version=?, updated_at=?, updated_by=?
			 WHERE event_id=? AND target_type=? AND target_key=? AND version=?`,
			display, alias.Version, now, trimmedActor, eventID, targetType, key, currentVersion)
		if err != nil {
			return Alias{}, fmt.Errorf("store: update alias: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return Alias{}, fmt.Errorf("store: update alias: %w", err)
		}
		if affected != 1 {
			return Alias{}, ErrAliasConflict
		}
	}
	alias.DisplayName = display
	if err := appendAuditFromContextTxFields(ctx, tx, "ok", "alias", eventID); err != nil {
		return Alias{}, err
	}
	if err := tx.Commit(); err != nil {
		return Alias{}, fmt.Errorf("store: commit alias write: %w", err)
	}
	return alias, nil
}

// ListAliases returns the event-scoped aliases, optionally restricted to one
// target type, ordered deterministically by (target_type, target_key).
func (s *Store) ListAliases(ctx context.Context, eventID, targetType string) ([]Alias, error) {
	if err := validateEventID("event_id", eventID); err != nil {
		return nil, err
	}
	if targetType != "" {
		if _, ok := allowedAliasTargetTypes[targetType]; !ok {
			return nil, invalidArgument("target_type", "must be node, device_ref or route")
		}
	}
	query := `SELECT event_id, target_type, target_key, display_name, version, updated_at, updated_by
	          FROM aliases WHERE event_id=?`
	args := []any{eventID}
	if targetType != "" {
		query += " AND target_type=?"
		args = append(args, targetType)
	}
	query += " ORDER BY target_type ASC, target_key ASC"
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list aliases: %w", err)
	}
	defer rows.Close()
	aliases := make([]Alias, 0)
	for rows.Next() {
		var alias Alias
		if err := rows.Scan(&alias.EventID, &alias.TargetType, &alias.TargetKey, &alias.DisplayName,
			&alias.Version, &alias.UpdatedAt, &alias.UpdatedBy); err != nil {
			return nil, fmt.Errorf("store: list aliases: %w", err)
		}
		aliases = append(aliases, alias)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list aliases: %w", err)
	}
	return aliases, nil
}

// DeleteAlias removes one alias. A missing alias is ErrNotFound; the caller's
// admin_audit row commits in the same transaction when present.
func (s *Store) DeleteAlias(ctx context.Context, eventID, targetType, targetKey, actor string, now int64) error {
	if err := validateEventID("event_id", eventID); err != nil {
		return err
	}
	key, err := validateAliasTarget(targetType, targetKey)
	if err != nil {
		return err
	}
	if _, err := validateBoundedText("actor", actor, b4MaxIdentifierBytes); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin alias delete: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := (&Tx{tx: tx}).EventActiveTx(ctx, eventID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx,
		`DELETE FROM aliases WHERE event_id=? AND target_type=? AND target_key=?`,
		eventID, targetType, key)
	if err != nil {
		return fmt.Errorf("store: delete alias: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: delete alias: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("%w: alias", ErrNotFound)
	}
	if err := appendAuditFromContextTxFields(ctx, tx, "ok", "alias", eventID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit alias delete: %w", err)
	}
	return nil
}

// --- route mapping history --------------------------------------------------

// ListMappingVersions returns the immutable mapping versions of one event/windows
// node, newest version first, with their route entries. Mapping history belongs
// to an existing (active or archived) event; a purged identity is ErrEventPurged.
func (s *Store) ListMappingVersions(ctx context.Context, eventID, windowsNodeID string) ([]MappingVersion, error) {
	if err := validateEventID("event_id", eventID); err != nil {
		return nil, err
	}
	if err := validateNodeID("windows_node_id", windowsNodeID); err != nil {
		return nil, err
	}
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM event_catalog WHERE event_id=?`, eventID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		graveyard, gerr := s.EventGraveyardExists(ctx, eventID)
		if gerr != nil {
			return nil, gerr
		}
		if graveyard {
			return nil, ErrEventPurged
		}
		return nil, ErrEventUnknown
	}
	if err != nil {
		return nil, fmt.Errorf("store: read mapping event: %w", err)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT version, effective_from, COALESCE(created_by,''), COALESCE(created_at,0)
		 FROM route_mapping_versions
		 WHERE event_id=? AND windows_node_id=?
		 ORDER BY version DESC`, eventID, windowsNodeID)
	if err != nil {
		return nil, fmt.Errorf("store: list mapping versions: %w", err)
	}
	versions := make([]MappingVersion, 0)
	index := make(map[int64]int)
	for rows.Next() {
		var version MappingVersion
		if err := rows.Scan(&version.Version, &version.EffectiveFrom, &version.CreatedBy, &version.CreatedAt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: list mapping versions: %w", err)
		}
		version.Entries = make(map[string]string)
		index[version.Version] = len(versions)
		versions = append(versions, version)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("store: list mapping versions: %w", err)
	}
	rows.Close()
	entryRows, err := s.db.QueryContext(ctx,
		`SELECT version, route_token, target_node_id FROM route_mapping_entries
		 WHERE event_id=? AND windows_node_id=?
		 ORDER BY version DESC, route_token ASC`, eventID, windowsNodeID)
	if err != nil {
		return nil, fmt.Errorf("store: list mapping entries: %w", err)
	}
	defer entryRows.Close()
	for entryRows.Next() {
		var version int64
		var token, target string
		if err := entryRows.Scan(&version, &token, &target); err != nil {
			return nil, fmt.Errorf("store: list mapping entries: %w", err)
		}
		if idx, ok := index[version]; ok {
			versions[idx].Entries[token] = target
		}
	}
	if err := entryRows.Err(); err != nil {
		return nil, fmt.Errorf("store: list mapping entries: %w", err)
	}
	return versions, nil
}

// --- purge preview/status and retention runs --------------------------------

// b4PurgePreviewTables is the fixed, closed set of event-scoped tables counted by
// PurgePreview. Table names are compile-time constants, never caller input.
var b4PurgePreviewTables = []string{
	"nodes",
	"snapshots",
	"report_metrics",
	"report_events",
	"report_event_reports",
	"node_latest",
	"node_configs",
	"node_config_history",
	"enroll_tokens",
	"route_mapping_versions",
	"route_mapping_entries",
	"aliases",
}

// PurgePreview returns the bounded inventory the durable purge would delete for
// one event, plus whether the event is already retention-data-purged or has an
// incomplete purge operation. No raw database/schema detail is exposed.
func (s *Store) PurgePreview(ctx context.Context, eventID string) (PurgePreview, error) {
	if err := validateEventID("event_id", eventID); err != nil {
		return PurgePreview{}, err
	}
	rec, err := s.loadEventRecord(ctx, eventID)
	if errors.Is(err, sql.ErrNoRows) {
		graveyard, gerr := s.EventGraveyardExists(ctx, eventID)
		if gerr != nil {
			return PurgePreview{}, gerr
		}
		if graveyard {
			return PurgePreview{}, ErrEventPurged
		}
		return PurgePreview{}, ErrEventUnknown
	}
	if err != nil {
		return PurgePreview{}, fmt.Errorf("store: purge preview event: %w", err)
	}
	preview := PurgePreview{Event: rec, TableCounts: make(map[string]int64, len(b4PurgePreviewTables))}
	for _, table := range b4PurgePreviewTables {
		var count int64
		if err := s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM `+table+` WHERE event_id=?`, eventID).Scan(&count); err != nil {
			return PurgePreview{}, fmt.Errorf("store: purge preview count %s: %w", table, err)
		}
		preview.TableCounts[table] = count
		preview.TotalRows += count
	}
	preview.DataPurged = rec.DataPurgedAt != nil
	var pending int
	err = s.db.QueryRowContext(ctx,
		`SELECT 1 FROM purge_ops WHERE event_id=? AND state<>'completed' LIMIT 1`, eventID).Scan(&pending)
	switch {
	case err == nil:
		preview.Incomplete = true
	case !errors.Is(err, sql.ErrNoRows):
		return PurgePreview{}, fmt.Errorf("store: purge preview state: %w", err)
	}
	return preview, nil
}

// PurgeStatus returns the latest durable purge state, permanent graveyard state
// and tombstone retain-until for one event. An unknown event is ErrEventUnknown;
// a permanently purged identity remains readable here as the graveyard record.
func (s *Store) PurgeStatus(ctx context.Context, eventID string) (PurgeStatus, error) {
	if err := validateEventID("event_id", eventID); err != nil {
		return PurgeStatus{}, err
	}
	status := PurgeStatus{EventID: eventID}
	graveyard, err := s.EventGraveyardExists(ctx, eventID)
	if err != nil {
		return PurgeStatus{}, err
	}
	status.Graveyard = graveyard
	status.Purged = graveyard
	event, eventErr := s.EventState(ctx, eventID)
	eventExists := eventErr == nil
	if eventErr != nil && !errors.Is(eventErr, ErrEventUnknown) {
		return PurgeStatus{}, eventErr
	}
	if !eventExists && !graveyard {
		return PurgeStatus{}, ErrEventUnknown
	}
	if eventExists {
		status.State = event.State
	} else {
		status.State = "purged"
	}
	op, ok, err := s.loadPurgeOp(ctx, eventID)
	if err != nil {
		return PurgeStatus{}, fmt.Errorf("store: purge status: %w", err)
	}
	if ok {
		status.State = op.State
		status.Phase = op.Phase
		status.DeletedRows = op.DeletedRows
		status.Error = op.Error
	}
	var retainUntil sql.NullInt64
	err = s.db.QueryRowContext(ctx,
		`SELECT retain_until FROM purge_tombstones WHERE event_id=?`, eventID).Scan(&retainUntil)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return PurgeStatus{}, fmt.Errorf("store: purge status tombstone: %w", err)
	default:
		status.TombstoneUntil = nullInt64Pointer(retainUntil)
	}
	return status, nil
}

// parseRetentionCounts tolerantly decodes a retention_runs.result_json payload.
func parseRetentionCounts(raw string) map[string]int64 {
	counts := make(map[string]int64)
	var direct map[string]int64
	if err := json.Unmarshal([]byte(raw), &direct); err == nil {
		return direct
	}
	var generic map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &generic); err != nil {
		return counts
	}
	for key, value := range generic {
		var count int64
		if err := json.Unmarshal(value, &count); err == nil {
			counts[key] = count
		}
	}
	return counts
}

// ListRetentionRuns returns the newest bounded page of recorded retention runs.
// The table stores only the run time and the per-table deleted counts; rows are
// written only after a successful sweep, so Status is "completed".
func (s *Store) ListRetentionRuns(ctx context.Context, limit int) ([]RetentionRun, error) {
	limit = b4NormalizeLimit(limit)
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, ran_at, result_json FROM retention_runs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list retention runs: %w", err)
	}
	defer rows.Close()
	runs := make([]RetentionRun, 0)
	for rows.Next() {
		var run RetentionRun
		var ranAt int64
		var resultJSON string
		if err := rows.Scan(&run.ID, &ranAt, &resultJSON); err != nil {
			return nil, fmt.Errorf("store: list retention runs: %w", err)
		}
		run.StartedAt = &ranAt
		run.FinishedAt = nil
		run.Status = "completed"
		run.DeletedCounts = parseRetentionCounts(resultJSON)
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list retention runs: %w", err)
	}
	return runs, nil
}

package management

import "encoding/json"

// API-facing models. They are deliberately separate from store structs so the
// HTTP contract stays stable even if internal query types change, and so no
// private key or DB-only field can accidentally be serialized.

type EventView struct {
	EventID      string `json:"event_id"`
	DisplayName  string `json:"display_name"`
	State        string `json:"state"`
	CreatedAt    int64  `json:"created_at"`
	ArchivedAt   *int64 `json:"archived_at,omitempty"`
	PurgeAfter   *int64 `json:"purge_after,omitempty"`
	DataPurgedAt *int64 `json:"data_purged_at,omitempty"`
	NodeCount    int64  `json:"node_count"`
	ActiveNodes  int64  `json:"active_nodes"`
	LinuxNodes   int64  `json:"linux_nodes"`
	WindowsNodes int64  `json:"windows_nodes"`
}

type EventList struct {
	Events []EventView `json:"events"`
	Total  int64       `json:"total"`
	Limit  int         `json:"limit"`
	Offset int         `json:"offset"`
}

type NodeKeyView struct {
	KeyID       string `json:"key_id"`
	State       string `json:"state"`
	CreatedAt   *int64 `json:"created_at,omitempty"`
	ActivatedAt *int64 `json:"activated_at,omitempty"`
	RevokedAt   *int64 `json:"revoked_at,omitempty"`
}

type RotationView struct {
	OldKeyID  string `json:"old_key_id"`
	NewKeyID  string `json:"new_key_id"`
	State     string `json:"state"`
	ExpiresAt *int64 `json:"expires_at,omitempty"`
	CreatedAt *int64 `json:"created_at,omitempty"`
}

type NodeView struct {
	NodeID           string          `json:"node_id"`
	EventID          string          `json:"event_id"`
	NodeClass        string          `json:"node_class"`
	State            string          `json:"state"`
	DerivedStatus    string          `json:"derived_status"`
	DisplayAlias     string          `json:"display_alias,omitempty"`
	CreatedAt        int64           `json:"created_at"`
	LastSeenAt       *int64          `json:"last_seen_at,omitempty"`
	RetiredAt        *int64          `json:"retired_at,omitempty"`
	ConfigVersion    *int64          `json:"config_version,omitempty"`
	CadenceSeconds   *int64          `json:"cadence_seconds,omitempty"`
	LatestReportID   string          `json:"latest_report_id,omitempty"`
	LatestSnapshotAt *int64          `json:"latest_snapshot_at,omitempty"`
	LatestSnapshot   json.RawMessage `json:"latest_snapshot,omitempty"`
	Keys             []NodeKeyView   `json:"keys,omitempty"`
	Rotation         *RotationView   `json:"rotation,omitempty"`
}

type NodeList struct {
	Nodes  []NodeView `json:"nodes"`
	Total  int64      `json:"total"`
	Limit  int        `json:"limit"`
	Offset int        `json:"offset"`
}

type ConfigHistoryView struct {
	ConfigVersion  int64            `json:"config_version"`
	EffectiveFrom  int64            `json:"effective_from"`
	CadenceSeconds int64            `json:"cadence_seconds"`
	Sources        map[string]bool  `json:"sources"`
	ExpectedTags   []InboundTagView `json:"expected_inbound_tags"`
}

type InboundTagView struct {
	InboundTag string `json:"inbound_tag"`
	Kind       string `json:"kind"`
}

type ConfigView struct {
	NodeID         string           `json:"node_id"`
	EventID        string           `json:"event_id"`
	NodeClass      string           `json:"node_class"`
	ConfigVersion  int64            `json:"config_version"`
	CadenceSeconds int64            `json:"cadence_seconds"`
	Sources        map[string]bool  `json:"sources"`
	ExpectedTags   []InboundTagView `json:"expected_inbound_tags"`
	UpdatedAt      int64            `json:"updated_at"`
}

type EnrollmentTokenView struct {
	TokenID   string `json:"token_id"`
	EventID   string `json:"event_id"`
	NodeClass string `json:"node_class"`
	Status    string `json:"status"`
	CreatedAt *int64 `json:"created_at,omitempty"`
	ExpiresAt *int64 `json:"expires_at,omitempty"`
	UsedAt    *int64 `json:"used_at,omitempty"`
	RevokedAt *int64 `json:"revoked_at,omitempty"`
}

type EnrollmentTokenCreated struct {
	Token     string `json:"token"`
	TokenID   string `json:"token_id"`
	EventID   string `json:"event_id"`
	NodeClass string `json:"node_class"`
	ExpiresAt int64  `json:"expires_at"`
}

type AliasView struct {
	EventID     string `json:"event_id"`
	TargetType  string `json:"target_type"`
	TargetKey   string `json:"target_key"`
	DisplayName string `json:"display_name"`
	Version     int64  `json:"version"`
	UpdatedAt   int64  `json:"updated_at"`
	UpdatedBy   string `json:"updated_by"`
}

type MappingEntryView struct {
	RouteToken   string `json:"route_token"`
	TargetNodeID string `json:"target_node_id"`
}

type MappingVersionView struct {
	Version       int64              `json:"version"`
	EffectiveFrom int64              `json:"effective_from"`
	CreatedBy     string             `json:"created_by"`
	CreatedAt     int64              `json:"created_at"`
	Entries       []MappingEntryView `json:"entries"`
}

type PurgePreviewView struct {
	EventID       string           `json:"event_id"`
	State         string           `json:"state"`
	TableCounts   map[string]int64 `json:"table_counts"`
	TotalRows     int64            `json:"total_rows"`
	DataPurged    bool             `json:"data_purged"`
	Incomplete    bool             `json:"incomplete"`
	Irreversible  bool             `json:"irreversible"`
	ConfirmPhrase string           `json:"confirm_phrase"`
}

type PurgeStatusView struct {
	EventID        string `json:"event_id"`
	State          string `json:"state"`
	Phase          string `json:"phase"`
	DeletedRows    int64  `json:"deleted_rows"`
	Error          string `json:"error,omitempty"`
	Graveyard      bool   `json:"graveyard"`
	DataPurged     bool   `json:"data_purged"`
	TombstoneUntil *int64 `json:"tombstone_until,omitempty"`
}

type RetentionStateView struct {
	Degraded     bool   `json:"degraded"`
	FailureCount int64  `json:"failure_count"`
	LastRunAt    *int64 `json:"last_run_at,omitempty"`
	LastError    string `json:"last_error,omitempty"`
}

type RetentionTimelineView struct {
	ActiveEvents     int64 `json:"active_events"`
	ArchivedEvents   int64 `json:"archived_events"`
	ArchivedRetained int64 `json:"archived_retained"`
	EventsCatalog    int64 `json:"events_catalog"`
}

type CapacityView struct {
	Counts map[string]int64 `json:"counts"`
	// PlanningBasis documents that the byte figures are a planning estimate, not
	// a SQLite disk hard limit.
	PlanningBasis string `json:"planning_basis"`
}

type AuditView struct {
	ID        int64   `json:"id"`
	At        int64   `json:"at"`
	Actor     string  `json:"actor"`
	Role      string  `json:"role"`
	Action    string  `json:"action"`
	Target    string  `json:"target"`
	EventID   *string `json:"event_id,omitempty"`
	Result    string  `json:"result"`
	RequestID *string `json:"request_id,omitempty"`
}

type AuditList struct {
	Entries []AuditView `json:"entries"`
	Total   int64       `json:"total"`
	Limit   int         `json:"limit"`
	Offset  int         `json:"offset"`
}

// ErrorBody is the closed admin-plane error envelope. It never echoes raw
// client input, paths, SQL, tokens or secrets.
type ErrorBody struct {
	V         int       `json:"v"`
	Error     ErrorCode `json:"error"`
	RequestID string    `json:"request_id,omitempty"`
}

type ErrorCode struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// Package management implements the UM-B4 administrative service layer, its
// fail-closed local authentication and the /api/v1 HTTP boundary shared by the
// admin CLI. It is deliberately separate from the agent ingest boundary: the
// admin list never exposes /v1/agent/*, and the ingest listener never imports
// this package.
package management

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Role is the frozen administrative role vocabulary.
type Role string

const (
	RolePlatformAdmin Role = "platform_admin"
	RoleEventAdmin    Role = "event_admin"
	RoleViewer        Role = "viewer"
)

func (r Role) Valid() bool {
	return r == RolePlatformAdmin || r == RoleEventAdmin || r == RoleViewer
}

// Principal is a trusted, locally authenticated administrative identity. It is
// never derived from client-supplied headers, query parameters or bodies.
type Principal struct {
	ID       string
	Role     Role
	EventIDs map[string]bool
}

func (p Principal) HasEvent(eventID string) bool {
	if p.Role == RolePlatformAdmin {
		return true
	}
	return p.EventIDs[eventID]
}

// AllowedEvents returns nil for platform_admin (all events) and the sorted
// scoped set otherwise. The caller must use this in SQL predicates.
func (p Principal) AllowedEvents() []string {
	if p.Role == RolePlatformAdmin {
		return nil
	}
	out := make([]string, 0, len(p.EventIDs))
	for id, ok := range p.EventIDs {
		if ok {
			out = append(out, id)
		}
	}
	// Stable order is not required for correctness but keeps SQL/planning and
	// test output deterministic.
	sortStrings(out)
	return out
}

func sortStrings(v []string) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] < v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}

// Action is a closed administrative action vocabulary used by RBAC and audit.
type Action string

const (
	ActionEventList      Action = "event_list"
	ActionEventRead      Action = "event_read"
	ActionEventCreate    Action = "event_create"
	ActionEventRename    Action = "event_rename"
	ActionEventArchive   Action = "event_archive"
	ActionEventPurgeRead Action = "event_purge_read"
	ActionEventPurge     Action = "event_purge"
	ActionNodeList       Action = "node_list"
	ActionNodeRead       Action = "node_read"
	ActionNodeRevoke     Action = "node_revoke"
	ActionTokenCreate    Action = "enroll_token_create"
	ActionTokenList      Action = "enroll_token_list"
	ActionTokenRead      Action = "enroll_token_read"
	ActionTokenRevoke    Action = "enroll_token_revoke"
	ActionConfigRead     Action = "agent_config_read"
	ActionConfigWrite    Action = "agent_config_write"
	ActionAliasRead      Action = "alias_read"
	ActionAliasWrite     Action = "alias_write"
	ActionMappingRead    Action = "route_mapping_read"
	ActionMappingWrite   Action = "route_mapping_write"
	ActionRetentionRead  Action = "retention_read"
	ActionRetentionRun   Action = "retention_run"
	ActionAuditRead      Action = "audit_read"
	ActionLedgerVerify   Action = "security_ledger_verify"
	ActionAdminHealth    Action = "admin_health"
)

// Authorize implements the frozen permission matrix plus the B4 least-
// privilege decisions for actions the matrix does not name:
//   - route_mapping_write and agent_config_write are platform_admin only;
//   - event create/rename/archive/purge and retention runs are platform_admin;
//   - event_admin may create tokens, revoke nodes and manage aliases only for
//     its resolved event set;
//   - viewers are read-only in scope.
//
// eventID is the already-resolved target event ("" for platform-global
// operations). Denial returns ErrForbidden; the HTTP layer maps event-scope
// misses to 404 without leaking existence.
func Authorize(p Principal, action Action, eventID string) error {
	if !p.Role.Valid() {
		return ErrForbidden
	}
	platformOnly := func() error {
		if p.Role != RolePlatformAdmin {
			return ErrForbidden
		}
		return nil
	}
	eventRead := func() error {
		if !p.HasEvent(eventID) {
			return ErrForbidden
		}
		return nil
	}
	eventWrite := func() error {
		if p.Role != RolePlatformAdmin && p.Role != RoleEventAdmin {
			return ErrForbidden
		}
		return eventRead()
	}
	switch action {
	case ActionEventList, ActionAdminHealth:
		return nil
	case ActionEventRead, ActionNodeList, ActionNodeRead, ActionTokenRead,
		ActionConfigRead, ActionAliasRead, ActionMappingRead, ActionEventPurgeRead:
		return eventRead()
	case ActionEventCreate, ActionEventRename, ActionEventArchive, ActionEventPurge,
		ActionConfigWrite, ActionMappingWrite, ActionRetentionRead, ActionRetentionRun,
		ActionLedgerVerify:
		return platformOnly()
	case ActionNodeRevoke, ActionTokenCreate, ActionTokenList, ActionTokenRevoke, ActionAliasWrite,
		ActionAuditRead:
		return eventWrite()
	default:
		return ErrForbidden
	}
}

// Errors returned by the management service. They are closed and contain no raw
// client input. The HTTP layer maps them to a bounded error vocabulary.
var (
	ErrUnauthenticated  = errors.New("management: authentication required")
	ErrForbidden        = errors.New("management: forbidden")
	ErrNotFound         = errors.New("management: not found")
	ErrConflict         = errors.New("management: conflict")
	ErrInvalid          = errors.New("management: invalid request")
	ErrQuota            = errors.New("management: quota exceeded")
	ErrArchived         = errors.New("management: event archived")
	ErrPurged           = errors.New("management: event purged")
	ErrPurging          = errors.New("management: event purge in progress")
	ErrAuditUnavailable = errors.New("management: audit unavailable")
)

// InvalidError carries a field name (never a value) for client feedback.
type InvalidError struct {
	Field  string
	Detail string
}

func (e *InvalidError) Error() string {
	if e.Field == "" {
		return "management: invalid request"
	}
	return fmt.Sprintf("management: invalid %s", e.Field)
}
func (e *InvalidError) Unwrap() error { return ErrInvalid }

// QuotaError is a bounded quota failure.
type QuotaError struct {
	Kind    string
	Limit   int64
	Current int64
}

func (e *QuotaError) Error() string { return "management: quota " + e.Kind }
func (e *QuotaError) Unwrap() error { return ErrQuota }

var (
	uuidV4Re    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	hex64Re     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	controlRe   = regexp.MustCompile(`[\x00-\x1f\x7f]`)
	aliasSafeRe = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,128}$`)
)

func validUUID(id string) bool { return uuidV4Re.MatchString(id) }

// validDisplayName validates the bounded, control-free display label used for
// event names and aliases. Values are JSON-encoded by the HTTP layer, so HTML
// safety belongs to the future UI; this layer forbids control/log-injection.
func validDisplayName(name string) bool {
	if name == "" || len(name) > 128 || strings.TrimSpace(name) != name {
		return false
	}
	if controlRe.MatchString(name) || !aliasSafeRe.MatchString(name) {
		return false
	}
	return true
}

func validateEventScope(role Role, eventIDs []string) error {
	if role == RolePlatformAdmin {
		if len(eventIDs) != 0 {
			return &InvalidError{Field: "event_ids", Detail: "platform_admin has global scope"}
		}
		return nil
	}
	if !role.Valid() || len(eventIDs) == 0 {
		return &InvalidError{Field: "event_ids", Detail: "scoped role requires at least one event"}
	}
	seen := map[string]bool{}
	for _, id := range eventIDs {
		if !validUUID(id) || seen[id] {
			return &InvalidError{Field: "event_ids", Detail: "must be unique lowercase UUIDv4"}
		}
		seen[id] = true
	}
	return nil
}

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "req-unavailable"
	}
	return hex.EncodeToString(b[:])
}

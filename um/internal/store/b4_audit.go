package store

// UM-B4 structured administrative audit context.
//
// Management operations wrap the request context with AuditMeta. Store methods
// that mutate administrative state append the audit row inside their existing
// transaction using appendAuditFromContextTx, so an audit failure rolls back the
// mutation. Agent-plane calls have no AuditMeta and are unaffected.
//
// The audit table is intentionally separate from the hash-chained security
// ledger: the ledger remains the security-state change log; admin_audit is the
// scoped, queryable administrative audit trail with actor/action/target/result.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type auditContextKey struct{}

// AuditMeta is bounded administrative action metadata. It must never contain
// tokens, private keys, controller secrets, proxy names or raw user data.
type AuditMeta struct {
	Actor     string
	Role      string
	Action    string
	Target    string
	EventID   string
	RequestID string
}

// WithAuditMeta attaches audit metadata to a management request context.
func WithAuditMeta(ctx context.Context, meta AuditMeta) context.Context {
	return context.WithValue(ctx, auditContextKey{}, meta)
}

func auditMetaFromContext(ctx context.Context) (AuditMeta, bool) {
	meta, ok := ctx.Value(auditContextKey{}).(AuditMeta)
	if !ok {
		return AuditMeta{}, false
	}
	if strings.TrimSpace(meta.Actor) == "" || strings.TrimSpace(meta.Action) == "" ||
		strings.TrimSpace(meta.Target) == "" {
		return AuditMeta{}, false
	}
	return meta, true
}

// AppendAuditTx writes one bounded administrative audit row. The caller must be
// inside a transaction so audit and the associated mutation are atomic.
func AppendAuditTx(ctx context.Context, tx *sql.Tx, meta AuditMeta, result string) error {
	if result != "ok" && result != "denied" && result != "error" {
		return errors.New("store: invalid audit result")
	}
	if strings.TrimSpace(meta.Actor) == "" || strings.TrimSpace(meta.Role) == "" ||
		strings.TrimSpace(meta.Action) == "" || strings.TrimSpace(meta.Target) == "" {
		return errors.New("store: incomplete audit metadata")
	}
	eventID := sql.NullString{}
	if meta.EventID != "" {
		eventID = sql.NullString{String: meta.EventID, Valid: true}
	}
	requestID := sql.NullString{}
	if meta.RequestID != "" {
		requestID = sql.NullString{String: meta.RequestID, Valid: true}
	}
	_, err := tx.ExecContext(ctx,
		`INSERT INTO admin_audit(at,actor,role,action,target,event_id,result,detail,request_id)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		nowUnix(), meta.Actor, meta.Role, meta.Action, meta.Target,
		eventID, result, nil, requestID)
	if err != nil {
		return fmt.Errorf("store: append admin audit: %w", err)
	}
	return nil
}

// appendAuditFromContextTx appends audit metadata when present. It is a no-op
// for agent-plane and internal maintenance calls.
func appendAuditFromContextTx(ctx context.Context, tx *sql.Tx, result string) error {
	meta, ok := auditMetaFromContext(ctx)
	if !ok {
		return nil
	}
	return AppendAuditTx(ctx, tx, meta, result)
}

// appendAuditFromContextTxFields appends the caller-supplied audit metadata when
// present and fills only the fields the store can derive unambiguously: the
// closed target type and the event id the mutation already carries. The audit
// action itself is always the caller's. Agent-plane calls have no metadata and
// remain a no-op.
func appendAuditFromContextTxFields(ctx context.Context, tx *sql.Tx, result, defaultTarget, eventID string) error {
	meta, ok := ctx.Value(auditContextKey{}).(AuditMeta)
	if !ok {
		return nil
	}
	if strings.TrimSpace(meta.Target) == "" {
		meta.Target = defaultTarget
	}
	if strings.TrimSpace(meta.EventID) == "" && eventID != "" {
		meta.EventID = eventID
	}
	return AppendAuditTx(ctx, tx, meta, result)
}

// auditActorFromContext returns the authenticated admin actor when the request
// carries audit metadata. Ledger writes that must name an actor (but predate B4)
// use the fallback for agent-plane/internal calls.
func auditActorFromContext(ctx context.Context, fallback string) string {
	if meta, ok := ctx.Value(auditContextKey{}).(AuditMeta); ok {
		if actor := strings.TrimSpace(meta.Actor); actor != "" {
			return actor
		}
	}
	return fallback
}

// RecordAdminAudit writes one audit row without a surrounding mutation. It is
// used for denied/unauthorized management attempts and for long batched
// maintenance runs that are audited separately; successful atomic mutations use
// AppendAuditTx inside their transaction.
func (s *Store) RecordAdminAudit(ctx context.Context, meta AuditMeta, result string) error {
	if result != "ok" && result != "denied" && result != "error" {
		return errors.New("store: invalid standalone audit result")
	}
	if strings.TrimSpace(meta.Actor) == "" || strings.TrimSpace(meta.Role) == "" ||
		strings.TrimSpace(meta.Action) == "" || strings.TrimSpace(meta.Target) == "" {
		return errors.New("store: incomplete audit metadata")
	}
	eventID := sql.NullString{}
	if meta.EventID != "" {
		eventID = sql.NullString{String: meta.EventID, Valid: true}
	}
	requestID := sql.NullString{}
	if meta.RequestID != "" {
		requestID = sql.NullString{String: meta.RequestID, Valid: true}
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO admin_audit(at,actor,role,action,target,event_id,result,detail,request_id)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		nowUnix(), meta.Actor, meta.Role, meta.Action, meta.Target,
		eventID, result, nil, requestID)
	if err != nil {
		return fmt.Errorf("store: append admin audit: %w", err)
	}
	return nil
}

// AdminAuditEntry is one bounded administrative audit record.
type AdminAuditEntry struct {
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

// AdminAuditPage is a bounded audit page plus total count.
type AdminAuditPage struct {
	Entries []AdminAuditEntry `json:"entries"`
	Total   int64             `json:"total"`
	Limit   int               `json:"limit"`
	Offset  int               `json:"offset"`
}

// AuditFilter is intentionally closed and bounded.
type AuditFilter struct {
	EventIDs []string
	Action   string
	Result   string
	Actor    string
	Limit    int
	Offset   int
}

// ListAdminAudit returns audit rows scoped by the already-resolved event set.
// A nil scope means platform-wide (platform_admin); an empty non-nil scope
// returns no rows. The filter values are compared exactly, never interpolated.
func (s *Store) ListAdminAudit(ctx context.Context, filter AuditFilter) (AdminAuditPage, error) {
	if filter.Limit <= 0 {
		filter.Limit = 50
	}
	if filter.Limit > 100 {
		filter.Limit = 100
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	if filter.Offset > 100000 {
		return AdminAuditPage{}, invalidArgument("offset", "too large")
	}
	build := func(selectPart string) (string, []any) {
		var clauses []string
		var args []any
		if filter.EventIDs != nil {
			if len(filter.EventIDs) == 0 {
				return selectPart + " WHERE 1=0", nil
			}
			ph := make([]string, len(filter.EventIDs))
			for i, id := range filter.EventIDs {
				ph[i] = "?"
				args = append(args, id)
			}
			clauses = append(clauses, "event_id IN ("+strings.Join(ph, ",")+")")
		}
		if filter.Action != "" {
			clauses = append(clauses, "action=?")
			args = append(args, filter.Action)
		}
		if filter.Result != "" {
			clauses = append(clauses, "result=?")
			args = append(args, filter.Result)
		}
		if filter.Actor != "" {
			clauses = append(clauses, "actor=?")
			args = append(args, filter.Actor)
		}
		if len(clauses) > 0 {
			selectPart += " WHERE " + strings.Join(clauses, " AND ")
		}
		return selectPart, args
	}
	var total int64
	countSQL, countArgs := build(`SELECT COUNT(*) FROM admin_audit`)
	if err := s.db.QueryRowContext(ctx, countSQL, countArgs...).Scan(&total); err != nil {
		return AdminAuditPage{}, fmt.Errorf("store: count admin audit: %w", err)
	}
	q, args := build(`SELECT id,at,actor,role,action,target,event_id,result,request_id FROM admin_audit`)
	q += " ORDER BY at DESC, id DESC LIMIT ? OFFSET ?"
	args = append(args, filter.Limit, filter.Offset)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return AdminAuditPage{}, fmt.Errorf("store: list admin audit: %w", err)
	}
	defer rows.Close()
	page := AdminAuditPage{Total: total, Limit: filter.Limit, Offset: filter.Offset}
	for rows.Next() {
		var e AdminAuditEntry
		var eventID, requestID sql.NullString
		if err := rows.Scan(&e.ID, &e.At, &e.Actor, &e.Role, &e.Action, &e.Target,
			&eventID, &e.Result, &requestID); err != nil {
			return AdminAuditPage{}, err
		}
		if eventID.Valid {
			v := eventID.String
			e.EventID = &v
		}
		if requestID.Valid {
			v := requestID.String
			e.RequestID = &v
		}
		page.Entries = append(page.Entries, e)
	}
	return page, rows.Err()
}

// AuditJSONHash returns a deterministic helper for callers that need to encode
// bounded details without persisting raw values. Currently unused by the table
// (detail is closed action text only), but exported for management tests.
func AuditJSONHash(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

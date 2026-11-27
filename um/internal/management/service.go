package management

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
)

const (
	defaultPageLimit = 50
	maxPageLimit     = 100
	maxTokenTTL      = 15 * time.Minute
	minTokenTTL      = time.Minute
	defaultStaleSecs = int64(180)
)

// Service is the single administrative business-logic layer. Both the HTTP
// admin API and the management CLI go through it (the CLI via HTTP), so no
// second store/lifecycle/mapping/purge engine exists.
type Service struct {
	st  *store.Store
	Now func() time.Time
}

func NewService(st *store.Store) (*Service, error) {
	if st == nil {
		return nil, errors.New("management: store is required")
	}
	return &Service{st: st, Now: time.Now}, nil
}

func (s *Service) now() int64 { return s.Now().Unix() }

func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

type requestKey struct{}

func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestKey{}, id)
}

func requestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestKey{}).(string)
	return id
}

func auditContext(ctx context.Context, p Principal, action Action, eventID, target string) context.Context {
	return store.WithAuditMeta(ctx, store.AuditMeta{
		Actor:     p.ID,
		Role:      string(p.Role),
		Action:    string(action),
		Target:    target,
		EventID:   eventID,
		RequestID: requestIDFromContext(ctx),
	})
}

func (s *Service) auditDenied(ctx context.Context, p Principal, action Action, eventID, target string) {
	if p.ID == "" {
		p = Principal{ID: "anonymous", Role: ""}
	}
	_ = s.st.RecordAdminAudit(ctx, store.AuditMeta{
		Actor: p.ID, Role: string(p.Role), Action: string(action), Target: target,
		EventID: eventID, RequestID: requestIDFromContext(ctx),
	}, "denied")
}

func clampPage(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = defaultPageLimit
	}
	if limit > maxPageLimit {
		limit = maxPageLimit
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func (s *Service) requireEvent(ctx context.Context, p Principal, action Action, eventID string) error {
	if !p.Role.Valid() {
		s.auditDenied(ctx, p, action, eventID, eventID)
		return ErrForbidden
	}
	// Out-of-scope and unknown events are indistinguishable (404), never a 403
	// that discloses event existence.
	if eventID != "" && !p.HasEvent(eventID) {
		s.auditDenied(ctx, p, action, eventID, eventID)
		return ErrNotFound
	}
	if err := Authorize(p, action, eventID); err != nil {
		s.auditDenied(ctx, p, action, eventID, eventID)
		return err
	}
	if eventID != "" {
		if _, err := s.st.GetEvent(ctx, eventID, p.AllowedEvents()); err != nil {
			return mapStoreError(err)
		}
	}
	return nil
}

func mapStoreError(err error) error {
	if err == nil {
		return nil
	}
	var qe *store.QuotaError
	var inv *store.InvalidArgumentError
	switch {
	case errors.As(err, &qe):
		return &QuotaError{Kind: qe.Kind, Limit: qe.Limit, Current: qe.Current}
	case errors.As(err, &inv):
		return &InvalidError{Field: inv.Field, Detail: "invalid value"}
	case errors.Is(err, store.ErrEventUnknown), errors.Is(err, store.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, store.ErrEventArchived):
		return ErrArchived
	case errors.Is(err, store.ErrEventPurged):
		return ErrPurged
	case errors.Is(err, store.ErrQuotaExceeded), errors.Is(err, store.ErrArchiveQuota):
		return ErrQuota
	case errors.Is(err, store.ErrTokenUsed):
		return &InvalidError{Field: "token", Detail: "already used"}
	case errors.Is(err, store.ErrTokenExpired):
		return &InvalidError{Field: "token", Detail: "expired"}
	case errors.Is(err, store.ErrTokenRevoked):
		return &InvalidError{Field: "token", Detail: "revoked"}
	case errors.Is(err, store.ErrTokenInvalid):
		return ErrNotFound
	case errors.Is(err, store.ErrNodeUnknown), errors.Is(err, store.ErrKeyUnknown):
		return ErrNotFound
	case errors.Is(err, store.ErrAliasConflict):
		return ErrConflict
	default:
		return err
	}
}

// --- Events -------------------------------------------------------------

func (s *Service) ListEvents(ctx context.Context, p Principal, state string, limit, offset int) (EventList, error) {
	limit, offset = clampPage(limit, offset)
	filter := store.EventListFilter{Limit: limit, Offset: offset}
	if state != "" {
		if state != store.EventActive && state != store.EventArchived {
			return EventList{}, &InvalidError{Field: "state", Detail: "must be active or archived"}
		}
		filter.States = []string{state}
	}
	items, total, err := s.st.ListEvents(ctx, p.AllowedEvents(), filter)
	if err != nil {
		return EventList{}, mapStoreError(err)
	}
	out := EventList{Total: total, Limit: limit, Offset: offset}
	for _, e := range items {
		out.Events = append(out.Events, eventView(e))
	}
	return out, nil
}

func eventView(e store.EventRecord) EventView {
	return EventView{
		EventID: e.EventID, DisplayName: e.DisplayName, State: e.State,
		CreatedAt: e.CreatedAt, ArchivedAt: e.ArchivedAt, PurgeAfter: e.PurgeAfter,
		DataPurgedAt: e.DataPurgedAt, NodeCount: e.NodeCount, ActiveNodes: e.ActiveNodes,
		LinuxNodes: e.LinuxNodes, WindowsNodes: e.WindowsNodes,
	}
}

func (s *Service) CreateEvent(ctx context.Context, p Principal, eventID, displayName string) (EventView, error) {
	if err := Authorize(p, ActionEventCreate, ""); err != nil {
		s.auditDenied(ctx, p, ActionEventCreate, "", "event")
		return EventView{}, err
	}
	if !validDisplayName(displayName) {
		return EventView{}, &InvalidError{Field: "display_name"}
	}
	if eventID == "" {
		id, err := newUUIDv4()
		if err != nil {
			return EventView{}, err
		}
		eventID = id
	} else if !validUUID(eventID) {
		return EventView{}, &InvalidError{Field: "event_id"}
	}
	ctx = auditContext(ctx, p, ActionEventCreate, eventID, "event:"+eventID)
	e, err := s.st.CreateEvent(ctx, eventID, displayName, s.now())
	if err != nil {
		return EventView{}, mapStoreError(err)
	}
	return eventView(e), nil
}

func (s *Service) GetEvent(ctx context.Context, p Principal, eventID string) (EventView, error) {
	if err := s.requireEvent(ctx, p, ActionEventRead, eventID); err != nil {
		return EventView{}, err
	}
	e, err := s.st.GetEvent(ctx, eventID, p.AllowedEvents())
	if err != nil {
		return EventView{}, mapStoreError(err)
	}
	return eventView(e), nil
}

func (s *Service) RenameEvent(ctx context.Context, p Principal, eventID, displayName string) (EventView, error) {
	if err := Authorize(p, ActionEventRename, eventID); err != nil {
		s.auditDenied(ctx, p, ActionEventRename, eventID, "event:"+eventID)
		return EventView{}, err
	}
	if !validDisplayName(displayName) {
		return EventView{}, &InvalidError{Field: "display_name"}
	}
	ctx = auditContext(ctx, p, ActionEventRename, eventID, "event:"+eventID)
	if err := s.st.RenameEvent(ctx, eventID, displayName, s.now()); err != nil {
		return EventView{}, mapStoreError(err)
	}
	return s.GetEvent(ctx, p, eventID)
}

func (s *Service) ArchiveEvent(ctx context.Context, p Principal, eventID string) error {
	if err := Authorize(p, ActionEventArchive, eventID); err != nil {
		s.auditDenied(ctx, p, ActionEventArchive, eventID, "event:"+eventID)
		return err
	}
	ctx = auditContext(ctx, p, ActionEventArchive, eventID, "event:"+eventID)
	return mapStoreError(s.st.ArchiveEvent(ctx, eventID, s.now()))
}

func (s *Service) PurgePreview(ctx context.Context, p Principal, eventID string) (PurgePreviewView, error) {
	if err := Authorize(p, ActionEventPurge, eventID); err != nil {
		s.auditDenied(ctx, p, ActionEventPurgeRead, eventID, "event:"+eventID)
		return PurgePreviewView{}, err
	}
	preview, err := s.st.PurgePreview(ctx, eventID)
	if err != nil {
		return PurgePreviewView{}, mapStoreError(err)
	}
	v := PurgePreviewView{
		EventID: eventID, State: preview.Event.State, TableCounts: preview.TableCounts,
		TotalRows: preview.TotalRows, DataPurged: preview.DataPurged,
		Incomplete: preview.Incomplete, Irreversible: true,
		ConfirmPhrase: "purge:" + eventID,
	}
	return v, nil
}

func (s *Service) PurgeConfirm(ctx context.Context, p Principal, eventID, confirmation string) (PurgeStatusView, error) {
	if err := Authorize(p, ActionEventPurge, eventID); err != nil {
		s.auditDenied(ctx, p, ActionEventPurge, eventID, "event:"+eventID)
		return PurgeStatusView{}, err
	}
	if confirmation != "purge:"+eventID {
		return PurgeStatusView{}, &InvalidError{Field: "confirmation", Detail: "must be purge:<event_id>"}
	}
	ctx = auditContext(ctx, p, ActionEventPurge, eventID, "event:"+eventID)
	if err := s.st.PurgeEvent(ctx, eventID, p.ID, true, s.now()); err != nil {
		return PurgeStatusView{}, mapStoreError(err)
	}
	return s.purgeStatus(ctx, eventID)
}

func (s *Service) PurgeStatus(ctx context.Context, p Principal, eventID string) (PurgeStatusView, error) {
	if err := Authorize(p, ActionEventPurge, eventID); err != nil {
		s.auditDenied(ctx, p, ActionEventPurgeRead, eventID, "event:"+eventID)
		return PurgeStatusView{}, err
	}
	return s.purgeStatus(ctx, eventID)
}

func (s *Service) purgeStatus(ctx context.Context, eventID string) (PurgeStatusView, error) {
	st, err := s.st.PurgeStatus(ctx, eventID)
	if err != nil {
		return PurgeStatusView{}, mapStoreError(err)
	}
	return PurgeStatusView{
		EventID: st.EventID, State: st.State, Phase: st.Phase, DeletedRows: st.DeletedRows,
		Error: st.Error, Graveyard: st.Graveyard, DataPurged: st.Purged,
		TombstoneUntil: st.TombstoneUntil,
	}, nil
}

// --- Nodes --------------------------------------------------------------

func (s *Service) ListNodes(ctx context.Context, p Principal, eventID, class, state string, limit, offset int) (NodeList, error) {
	if err := s.requireEvent(ctx, p, ActionNodeList, eventID); err != nil {
		return NodeList{}, err
	}
	if class != "" && class != store.NodeClassLinuxVPS && class != store.NodeClassWindowsTerminal {
		return NodeList{}, &InvalidError{Field: "node_class"}
	}
	if state != "" && state != store.NodeActive && state != store.NodeRevoked && state != "retired" {
		return NodeList{}, &InvalidError{Field: "state"}
	}
	limit, offset = clampPage(limit, offset)
	items, total, err := s.st.ListNodes(ctx, p.AllowedEvents(), eventID, class, state, limit, offset)
	if err != nil {
		return NodeList{}, mapStoreError(err)
	}
	out := NodeList{Total: total, Limit: limit, Offset: offset}
	now := s.now()
	for _, n := range items {
		out.Nodes = append(out.Nodes, s.nodeView(n, nil, now))
	}
	return out, nil
}

func (s *Service) GetNode(ctx context.Context, p Principal, eventID, nodeID string) (NodeView, error) {
	if err := s.requireEvent(ctx, p, ActionNodeRead, eventID); err != nil {
		return NodeView{}, err
	}
	d, err := s.st.GetNodeDetail(ctx, p.AllowedEvents(), eventID, nodeID)
	if err != nil {
		return NodeView{}, mapStoreError(err)
	}
	v := s.nodeView(d.NodeSummary, &d, s.now())
	return v, nil
}

func (s *Service) nodeView(n store.NodeSummary, d *store.NodeDetail, now int64) NodeView {
	v := NodeView{
		NodeID: n.NodeID, EventID: n.EventID, NodeClass: n.NodeClass, State: n.State,
		DisplayAlias: n.Alias, CreatedAt: n.CreatedAt, LastSeenAt: n.LastSeenAt,
		RetiredAt: n.RetiredAt, ConfigVersion: n.ConfigVersion, CadenceSeconds: n.CadenceSeconds,
		LatestReportID: n.LatestReportID, LatestSnapshotAt: n.LatestSnapshotAt,
	}
	v.DerivedStatus = deriveNodeStatus(n, now)
	if d != nil {
		if len(d.LatestSnapshot) > 0 {
			v.LatestSnapshot = json.RawMessage(append([]byte(nil), d.LatestSnapshot...))
		}
		for _, k := range d.Keys {
			v.Keys = append(v.Keys, NodeKeyView{KeyID: k.KeyID, State: k.State,
				CreatedAt: k.CreatedAt, ActivatedAt: k.ActivatedAt, RevokedAt: k.RevokedAt})
		}
		for _, r := range d.Rotations {
			if v.Rotation == nil {
				v.Rotation = &RotationView{OldKeyID: r.OldKeyID, NewKeyID: r.NewKeyID,
					State: r.State, ExpiresAt: r.ExpiresAt, CreatedAt: r.CreatedAt}
			}
		}
	}
	return v
}

func deriveNodeStatus(n store.NodeSummary, now int64) string {
	if n.State == store.NodeRevoked || n.RetiredAt != nil {
		return "revoked"
	}
	if n.LastSeenAt == nil {
		return "never_reported"
	}
	if n.LatestSnapshotAt == nil {
		return "unavailable"
	}
	stale := defaultStaleSecs
	if n.CadenceSeconds != nil && *n.CadenceSeconds*3 > stale {
		stale = *n.CadenceSeconds * 3
	}
	if now-*n.LastSeenAt > stale {
		return "stale"
	}
	return "online"
}

func (s *Service) RevokeNode(ctx context.Context, p Principal, eventID, nodeID string) error {
	if err := s.requireEvent(ctx, p, ActionNodeRevoke, eventID); err != nil {
		return err
	}
	n, err := s.st.GetNode(ctx, nodeID)
	if err != nil {
		return mapStoreError(err)
	}
	if n.EventID != eventID {
		return ErrNotFound
	}
	ctx = auditContext(ctx, p, ActionNodeRevoke, eventID, "node:"+nodeID)
	return mapStoreError(s.st.RevokeNode(ctx, nodeID, s.now()))
}

// --- Enrollment tokens --------------------------------------------------

func (s *Service) CreateToken(ctx context.Context, p Principal, eventID, nodeClass string, ttlSeconds int) (EnrollmentTokenCreated, error) {
	if err := s.requireEvent(ctx, p, ActionTokenCreate, eventID); err != nil {
		return EnrollmentTokenCreated{}, err
	}
	if nodeClass != store.NodeClassLinuxVPS && nodeClass != store.NodeClassWindowsTerminal {
		return EnrollmentTokenCreated{}, &InvalidError{Field: "node_class"}
	}
	ttl := time.Duration(ttlSeconds) * time.Second
	if ttlSeconds == 0 {
		ttl = maxTokenTTL
	}
	if ttl < minTokenTTL || ttl > maxTokenTTL {
		return EnrollmentTokenCreated{}, &InvalidError{Field: "ttl_seconds", Detail: "must be in [60,900]"}
	}
	token, hash, err := store.NewEnrollToken()
	if err != nil {
		return EnrollmentTokenCreated{}, err
	}
	now := s.now()
	expires := now + int64(ttl.Seconds())
	ctx = auditContext(ctx, p, ActionTokenCreate, eventID, "enroll_token")
	if err := s.st.CreateEnrollToken(ctx, hash, eventID, nodeClass, expires, now); err != nil {
		// The plaintext token never reaches an error path or log.
		return EnrollmentTokenCreated{}, mapStoreError(err)
	}
	return EnrollmentTokenCreated{Token: token, TokenID: hash, EventID: eventID,
		NodeClass: nodeClass, ExpiresAt: expires}, nil
}

func (s *Service) ListTokens(ctx context.Context, p Principal, eventID string, limit, offset int) ([]EnrollmentTokenView, int64, error) {
	if err := s.requireEvent(ctx, p, ActionTokenList, eventID); err != nil {
		return nil, 0, err
	}
	limit, offset = clampPage(limit, offset)
	items, total, err := s.st.ListEnrollTokens(ctx, p.AllowedEvents(), eventID, limit, offset)
	if err != nil {
		return nil, 0, mapStoreError(err)
	}
	out := make([]EnrollmentTokenView, 0, len(items))
	for _, t := range items {
		out = append(out, EnrollmentTokenView{TokenID: t.TokenHash, EventID: t.EventID,
			NodeClass: t.NodeClass, Status: t.Status, CreatedAt: t.CreatedAt,
			ExpiresAt: t.ExpiresAt, UsedAt: t.UsedAt, RevokedAt: t.RevokedAt})
	}
	return out, total, nil
}

func (s *Service) GetToken(ctx context.Context, p Principal, eventID, tokenID string) (EnrollmentTokenView, error) {
	if err := s.requireEvent(ctx, p, ActionTokenRead, eventID); err != nil {
		return EnrollmentTokenView{}, err
	}
	if !hex64Re.MatchString(tokenID) {
		return EnrollmentTokenView{}, &InvalidError{Field: "token_id"}
	}
	info, err := s.st.TokenInfo(ctx, tokenID)
	if err != nil {
		return EnrollmentTokenView{}, mapStoreError(err)
	}
	if info.EventID != eventID {
		return EnrollmentTokenView{}, ErrNotFound
	}
	status := "unused"
	if info.RevokedAt != nil {
		status = "revoked"
	} else if info.UsedAt != nil {
		status = "used"
	} else if info.ExpiresAt > 0 && info.ExpiresAt <= s.now() {
		status = "expired"
	}
	createdAt := info.CreatedAt
	createdPtr := &createdAt
	expires := info.ExpiresAt
	return EnrollmentTokenView{TokenID: tokenID, EventID: info.EventID,
		NodeClass: info.NodeClass, Status: status, CreatedAt: createdPtr,
		ExpiresAt: &expires, UsedAt: info.UsedAt, RevokedAt: info.RevokedAt}, nil
}

func (s *Service) RevokeToken(ctx context.Context, p Principal, eventID, tokenID string) error {
	if err := s.requireEvent(ctx, p, ActionTokenRevoke, eventID); err != nil {
		return err
	}
	if !hex64Re.MatchString(tokenID) {
		return &InvalidError{Field: "token_id"}
	}
	ctx = auditContext(ctx, p, ActionTokenRevoke, eventID, "enroll_token")
	return mapStoreError(s.st.RevokeEnrollToken(ctx, eventID, tokenID, s.now()))
}

// --- Agent config -------------------------------------------------------

func (s *Service) GetConfig(ctx context.Context, p Principal, eventID, nodeID string) (ConfigView, error) {
	if err := s.requireEvent(ctx, p, ActionConfigRead, eventID); err != nil {
		return ConfigView{}, err
	}
	n, err := s.st.GetNode(ctx, nodeID)
	if err != nil {
		return ConfigView{}, mapStoreError(err)
	}
	if n.EventID != eventID {
		return ConfigView{}, ErrNotFound
	}
	cfg, err := s.st.GetNodeConfig(ctx, nodeID)
	if err != nil {
		return ConfigView{}, mapStoreError(err)
	}
	view := configView(cfg)
	view.NodeClass = n.NodeClass
	return view, nil
}

func configView(cfg store.NodeConfig) ConfigView {
	tags := make([]InboundTagView, 0, len(cfg.ExpectedInboundTags))
	for _, t := range cfg.ExpectedInboundTags {
		tags = append(tags, InboundTagView{InboundTag: t.InboundTag, Kind: t.Kind})
	}
	return ConfigView{NodeID: cfg.NodeID, EventID: cfg.EventID, NodeClass: "", ConfigVersion: int64(cfg.ConfigVersion),
		CadenceSeconds: int64(cfg.CadenceSeconds), Sources: cloneSources(cfg.Sources),
		ExpectedTags: tags, UpdatedAt: cfg.UpdatedAt}
}

func cloneSources(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (s *Service) ConfigHistory(ctx context.Context, p Principal, eventID, nodeID string) ([]ConfigHistoryView, error) {
	if err := s.requireEvent(ctx, p, ActionConfigRead, eventID); err != nil {
		return nil, err
	}
	n, err := s.st.GetNode(ctx, nodeID)
	if err != nil {
		return nil, mapStoreError(err)
	}
	if n.EventID != eventID {
		return nil, ErrNotFound
	}
	items, err := s.st.ListConfigHistory(ctx, nodeID, maxPageLimit)
	if err != nil {
		return nil, mapStoreError(err)
	}
	out := make([]ConfigHistoryView, 0, len(items))
	for _, h := range items {
		var sources map[string]bool
		var tags []store.InboundTag
		_ = json.Unmarshal([]byte(h.SourcesJSON), &sources)
		_ = json.Unmarshal([]byte(h.ExpectedTagsJSON), &tags)
		view := ConfigHistoryView{ConfigVersion: h.ConfigVersion, EffectiveFrom: h.EffectiveFrom,
			CadenceSeconds: h.CadenceSeconds, Sources: sources}
		for _, tag := range tags {
			view.ExpectedTags = append(view.ExpectedTags, InboundTagView{InboundTag: tag.InboundTag, Kind: tag.Kind})
		}
		out = append(out, view)
	}
	return out, nil
}

func (s *Service) UpdateConfig(ctx context.Context, p Principal, eventID, nodeID string, cadence int, sources map[string]bool, tags []store.InboundTag) (ConfigView, error) {
	if err := s.requireEvent(ctx, p, ActionConfigWrite, eventID); err != nil {
		return ConfigView{}, err
	}
	n, err := s.st.GetNode(ctx, nodeID)
	if err != nil {
		return ConfigView{}, mapStoreError(err)
	}
	if n.EventID != eventID {
		return ConfigView{}, ErrNotFound
	}
	if err := validateAdminSources(n.NodeClass, sources); err != nil {
		return ConfigView{}, err
	}
	if cadence < 30 || cadence > 300 {
		return ConfigView{}, &InvalidError{Field: "cadence_seconds"}
	}
	if len(tags) > 8 {
		return ConfigView{}, &InvalidError{Field: "expected_inbound_tags"}
	}
	ctx = auditContext(ctx, p, ActionConfigWrite, eventID, "node:"+nodeID)
	cfg, err := s.st.UpdateNodeConfig(ctx, nodeID, sources, tags, cadence, s.now())
	if err != nil {
		return ConfigView{}, mapStoreError(err)
	}
	view := configView(cfg)
	view.NodeClass = n.NodeClass
	return view, nil
}

// validateAdminSources enforces B4's conservative source controls: the
// unproven Linux singbox_api source and the Windows R1 controller source may
// not be enabled through the center config at all. The existing store/class
// validator remains the second line of defense.
func validateAdminSources(nodeClass string, sources map[string]bool) error {
	allowed := map[string]bool{"system": true, "services": true, "singbox_api": true,
		"mihomo_api": true, "terminal": true, "events": true}
	for k := range sources {
		if !allowed[k] {
			return &InvalidError{Field: "sources"}
		}
	}
	if sources["singbox_api"] {
		return &InvalidError{Field: "sources", Detail: "singbox_api is not authorizable in this release"}
	}
	if sources["mihomo_api"] {
		return &InvalidError{Field: "sources", Detail: "mihomo_api/R1 is local-bundle-only and cannot be enabled by center config"}
	}
	if nodeClass == store.NodeClassWindowsTerminal {
		if sources["services"] || sources["singbox_api"] {
			return &InvalidError{Field: "sources"}
		}
	} else if sources["terminal"] {
		return &InvalidError{Field: "sources"}
	}
	return nil
}

// --- Aliases ------------------------------------------------------------

func (s *Service) ListAliases(ctx context.Context, p Principal, eventID, targetType string) ([]AliasView, error) {
	if err := s.requireEvent(ctx, p, ActionAliasRead, eventID); err != nil {
		return nil, err
	}
	if targetType != "" && !validAliasType(targetType) {
		return nil, &InvalidError{Field: "target_type"}
	}
	items, err := s.st.ListAliases(ctx, eventID, targetType)
	if err != nil {
		return nil, mapStoreError(err)
	}
	out := make([]AliasView, 0, len(items))
	for _, a := range items {
		out = append(out, aliasView(a))
	}
	return out, nil
}

func aliasView(a store.Alias) AliasView {
	return AliasView{EventID: a.EventID, TargetType: a.TargetType, TargetKey: a.TargetKey,
		DisplayName: a.DisplayName, Version: a.Version, UpdatedAt: a.UpdatedAt, UpdatedBy: a.UpdatedBy}
}

func validAliasType(t string) bool {
	return t == "node" || t == "device_ref" || t == "route"
}

func (s *Service) SetAlias(ctx context.Context, p Principal, eventID, targetType, targetKey, display string, expectedVersion *int64) (AliasView, error) {
	if err := s.requireEvent(ctx, p, ActionAliasWrite, eventID); err != nil {
		return AliasView{}, err
	}
	if !validAliasType(targetType) || !validDisplayName(display) || len(targetKey) == 0 || len(targetKey) > 128 || controlRe.MatchString(targetKey) {
		return AliasView{}, &InvalidError{Field: "alias"}
	}
	if targetType == "node" {
		if !validUUID(targetKey) {
			return AliasView{}, &InvalidError{Field: "target_key"}
		}
		n, err := s.st.GetNode(ctx, targetKey)
		if err != nil || n.EventID != eventID {
			return AliasView{}, ErrNotFound
		}
	}
	if targetType == "route" {
		switch targetKey {
		case "a_reality", "a_hy2", "b_reality", "b_hy2", "direct", "unknown":
		default:
			return AliasView{}, &InvalidError{Field: "target_key"}
		}
	}
	ctx = auditContext(ctx, p, ActionAliasWrite, eventID, targetType+":"+targetKey)
	a, err := s.st.SetAlias(ctx, eventID, targetType, targetKey, display, p.ID, expectedVersion, s.now())
	if err != nil {
		return AliasView{}, mapStoreError(err)
	}
	return aliasView(a), nil
}

func (s *Service) DeleteAlias(ctx context.Context, p Principal, eventID, targetType, targetKey string) error {
	if err := s.requireEvent(ctx, p, ActionAliasWrite, eventID); err != nil {
		return err
	}
	if !validAliasType(targetType) {
		return &InvalidError{Field: "target_type"}
	}
	ctx = auditContext(ctx, p, ActionAliasWrite, eventID, targetType+":"+targetKey)
	return mapStoreError(s.st.DeleteAlias(ctx, eventID, targetType, targetKey, p.ID, s.now()))
}

// --- Versioned route mapping --------------------------------------------

func (s *Service) ListMapping(ctx context.Context, p Principal, eventID, windowsNodeID string) ([]MappingVersionView, error) {
	if err := s.requireEvent(ctx, p, ActionMappingRead, eventID); err != nil {
		return nil, err
	}
	if !validUUID(windowsNodeID) {
		return nil, &InvalidError{Field: "windows_node_id"}
	}
	items, err := s.st.ListMappingVersions(ctx, eventID, windowsNodeID)
	if err != nil {
		return nil, mapStoreError(err)
	}
	out := make([]MappingVersionView, 0, len(items))
	for _, m := range items {
		v := MappingVersionView{Version: m.Version, EffectiveFrom: m.EffectiveFrom,
			CreatedBy: m.CreatedBy, CreatedAt: m.CreatedAt}
		tokens := make([]string, 0, len(m.Entries))
		for token := range m.Entries {
			tokens = append(tokens, token)
		}
		sort.Strings(tokens)
		for _, token := range tokens {
			v.Entries = append(v.Entries, MappingEntryView{RouteToken: token, TargetNodeID: m.Entries[token]})
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *Service) CreateMapping(ctx context.Context, p Principal, eventID, windowsNodeID string, version int, effectiveFrom int64, entries map[string]string) error {
	if err := Authorize(p, ActionMappingWrite, eventID); err != nil {
		s.auditDenied(ctx, p, ActionMappingWrite, eventID, "route_mapping:"+windowsNodeID)
		return err
	}
	if !validUUID(windowsNodeID) || len(entries) > 4 || version < 1 {
		return &InvalidError{Field: "mapping"}
	}
	for token, target := range entries {
		switch token {
		case "a_reality", "a_hy2", "b_reality", "b_hy2":
		default:
			return &InvalidError{Field: "route_token"}
		}
		if !validUUID(target) {
			return &InvalidError{Field: "target_node_id"}
		}
	}
	ctx = auditContext(ctx, p, ActionMappingWrite, eventID, "route_mapping:"+windowsNodeID)
	return mapStoreError(s.st.CreateMappingVersion(ctx, eventID, windowsNodeID, version, effectiveFrom, p.ID, entries))
}

type MappingResolutionView struct {
	WindowsNodeID string            `json:"windows_node_id"`
	At            int64             `json:"at"`
	Version       int64             `json:"version,omitempty"`
	Entries       map[string]string `json:"entries"`
}

func (s *Service) ResolveMapping(ctx context.Context, p Principal, eventID, windowsNodeID string, at int64) (MappingResolutionView, error) {
	if err := s.requireEvent(ctx, p, ActionMappingRead, eventID); err != nil {
		return MappingResolutionView{}, err
	}
	if !validUUID(windowsNodeID) {
		return MappingResolutionView{}, &InvalidError{Field: "windows_node_id"}
	}
	if at <= 0 {
		at = s.now()
	}
	m, version, err := s.st.ResolveMapping(ctx, eventID, windowsNodeID, at)
	if err != nil {
		return MappingResolutionView{}, mapStoreError(err)
	}
	if m == nil {
		m = map[string]string{}
	}
	return MappingResolutionView{WindowsNodeID: windowsNodeID, At: at, Version: int64(version), Entries: m}, nil
}

// --- Retention / capacity -----------------------------------------------

func (s *Service) RetentionState(ctx context.Context, p Principal) (RetentionStateView, error) {
	if err := Authorize(p, ActionRetentionRead, ""); err != nil {
		s.auditDenied(ctx, p, ActionRetentionRead, "", "retention")
		return RetentionStateView{}, err
	}
	st, err := s.st.GetRetentionState(ctx)
	if err != nil {
		return RetentionStateView{}, mapStoreError(err)
	}
	return RetentionStateView{Degraded: st.Degraded, FailureCount: st.FailureCount,
		LastRunAt: st.LastRunAt, LastError: st.LastError}, nil
}

func (s *Service) RetentionTimeline(ctx context.Context, p Principal) (RetentionTimelineView, error) {
	if err := Authorize(p, ActionRetentionRead, ""); err != nil {
		return RetentionTimelineView{}, err
	}
	t, err := s.st.RetentionTimeline(ctx)
	if err != nil {
		return RetentionTimelineView{}, mapStoreError(err)
	}
	return RetentionTimelineView{ActiveEvents: t.ActiveEvents, ArchivedEvents: t.ArchivedEvents,
		ArchivedRetained: t.ArchivedRetained, EventsCatalog: t.EventsCatalog}, nil
}

func (s *Service) Capacity(ctx context.Context, p Principal) (CapacityView, error) {
	if err := Authorize(p, ActionRetentionRead, ""); err != nil {
		return CapacityView{}, err
	}
	base, err := s.st.CapacityStats(ctx)
	if err != nil {
		return CapacityView{}, mapStoreError(err)
	}
	ext, err := s.st.CapacityStatsExtended(ctx)
	if err != nil {
		return CapacityView{}, mapStoreError(err)
	}
	counts := map[string]int64{
		"nodes": base.Nodes, "snapshots": base.Snapshots, "metrics": base.Metrics,
		"events": base.Events, "archive": base.Archive, "seq_dedupe": base.SeqDedupe,
		"boot_registry": base.BootRegistry, "report_dedupe": base.ReportDedupe,
		"nonce_dedupe": base.NonceDedupe, "active_events": ext.ActiveEvents,
		"archived_events": ext.ArchivedEvents, "archived_retained": ext.ArchivedRetained,
		"events_catalog": ext.EventsCatalog,
	}
	quotas := map[string]int64{
		"max_active_nodes_all_events":   store.MaxActiveNodesAllEvents,
		"max_active_nodes_per_event":    store.MaxActiveNodesPerEvent,
		"max_archived_events_with_data": store.MaxArchivedEventsWithData,
		"max_events_catalog":            store.MaxEventsCatalog,
		"active_retention_seconds":      store.PolicyBActiveRetentionSeconds,
		"archive_tail_seconds":          store.PolicyBArchiveTailSeconds,
		"retention_batch_rows":          store.RetentionBatchRows,
		"active_only_planning_bytes":    store.ActiveOnlyPlanningPayloadBytes,
		"overlap_budget_multiplier":     store.OverlapBudgetMultiplier,
	}
	return CapacityView{Counts: counts, Quotas: quotas,
		PlanningBasis: "planning payload estimate; not a SQLite disk hard limit"}, nil
}

func (s *Service) RunRetention(ctx context.Context, p Principal) (map[string]int64, error) {
	if err := Authorize(p, ActionRetentionRun, ""); err != nil {
		s.auditDenied(ctx, p, ActionRetentionRun, "", "retention")
		return nil, err
	}
	ctx = auditContext(ctx, p, ActionRetentionRun, "", "retention")
	counts, err := s.st.RunRetentionB2PolicyB(ctx, s.now())
	if err != nil {
		return nil, mapStoreError(err)
	}
	// Maintenance changes are audited separately; the retention run may be
	// long/batched, so it is not wrapped in one transaction with this row.
	_ = s.st.RecordAdminAudit(ctx, store.AuditMeta{Actor: p.ID, Role: string(p.Role),
		Action: string(ActionRetentionRun), Target: "retention", RequestID: requestIDFromContext(ctx)}, "ok")
	return counts, nil
}

func (s *Service) RetentionRuns(ctx context.Context, p Principal, limit int) ([]map[string]any, error) {
	if err := Authorize(p, ActionRetentionRead, ""); err != nil {
		return nil, err
	}
	limit, _ = clampPage(limit, 0)
	items, err := s.st.ListRetentionRuns(ctx, limit)
	if err != nil {
		return nil, mapStoreError(err)
	}
	out := make([]map[string]any, 0, len(items))
	for _, r := range items {
		out = append(out, map[string]any{"id": r.ID, "started_at": r.StartedAt,
			"finished_at": r.FinishedAt, "status": r.Status, "deleted_counts": r.DeletedCounts})
	}
	return out, nil
}

// --- Audit --------------------------------------------------------------

func (s *Service) ListAudit(ctx context.Context, p Principal, eventID, action, result, actor string, limit, offset int) (AuditList, error) {
	if p.Role == RoleViewer || !p.Role.Valid() {
		s.auditDenied(ctx, p, ActionAuditRead, eventID, "audit")
		return AuditList{}, ErrForbidden
	}
	var scope []string
	if p.Role == RolePlatformAdmin {
		if eventID != "" {
			scope = []string{eventID}
		} else {
			scope = nil
		}
	} else if eventID != "" {
		if !p.HasEvent(eventID) {
			return AuditList{}, ErrNotFound
		}
		scope = []string{eventID}
	} else {
		scope = p.AllowedEvents()
	}
	limit, offset = clampPage(limit, offset)
	page, err := s.st.ListAdminAudit(ctx, store.AuditFilter{EventIDs: scope, Action: action,
		Result: result, Actor: actor, Limit: limit, Offset: offset})
	if err != nil {
		return AuditList{}, mapStoreError(err)
	}
	out := AuditList{Total: page.Total, Limit: page.Limit, Offset: page.Offset}
	for _, e := range page.Entries {
		out.Entries = append(out.Entries, AuditView{ID: e.ID, At: e.At, Actor: e.Actor,
			Role: e.Role, Action: e.Action, Target: e.Target, EventID: e.EventID,
			Result: e.Result, RequestID: e.RequestID})
	}
	return out, nil
}

func (s *Service) VerifyLedger(ctx context.Context, p Principal) error {
	if err := Authorize(p, ActionLedgerVerify, ""); err != nil {
		s.auditDenied(ctx, p, ActionLedgerVerify, "", "security_ledger")
		return err
	}
	return mapStoreError(s.st.VerifyChain(ctx))
}

// --- Node keys/rotation are read through GetNode; no admin rotate API exists.

func (s *Service) Health(ctx context.Context, p Principal) map[string]any {
	return map[string]any{"ok": true, "service": "um-center-management", "actor": p.ID, "role": p.Role}
}

var _ = strings.TrimSpace

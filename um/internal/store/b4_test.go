package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Fixed canonical UUIDv4 fixtures for the UM-B4 management tests.
const (
	testB4EventA = "11111111-1111-4111-8111-111111111111"
	testB4EventB = "22222222-2222-4222-8222-222222222222"
	testB4EventC = "33333333-3333-4333-8333-333333333333"
	testB4EventD = "44444444-4444-4444-8444-444444444444"
)

func b4AuditContext(action string) context.Context {
	return WithAuditMeta(context.Background(), AuditMeta{
		Actor: "admin-1", Role: "platform_admin", Action: action,
		Target: "test", EventID: testB4EventA, RequestID: "req-b4",
	})
}

func mustCreateB4Event(t *testing.T, s *Store, ctx context.Context, eventID, name string, now int64) EventRecord {
	t.Helper()
	record, err := s.CreateEvent(ctx, eventID, name, now)
	if err != nil {
		t.Fatalf("CreateEvent(%q): %v", eventID, err)
	}
	return record
}

func mustEnrollB4Node(t *testing.T, s *Store, eventID, class string, now int64) EnrolledIdentity {
	t.Helper()
	ctx := testContext()
	_, hash, err := NewEnrollToken()
	if err != nil {
		t.Fatalf("NewEnrollToken: %v", err)
	}
	if err := s.CreateEnrollToken(ctx, hash, eventID, class, now+3600, now); err != nil {
		t.Fatalf("CreateEnrollToken: %v", err)
	}
	host := "linux"
	if class == NodeClassWindowsTerminal {
		host = "windows"
	}
	identity, err := s.Enroll(ctx, hash, class, host, testPublicKey(t), now)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	return identity
}

func countLedgerKind(t *testing.T, s *Store, kind string) int64 {
	t.Helper()
	return queryInt(t, s, `SELECT COUNT(*) FROM security_ledger WHERE kind=?`, kind)
}

func TestB4MigrationReopenKeepsManagementState(t *testing.T) {
	path := tempStorePath(t)
	ctx := testContext()
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if version, err := s.SchemaVersion(ctx); err != nil || version != 9 {
		t.Fatalf("schema version = %d (err=%v), want 9", version, err)
	}
	now := int64(1_700_000_000)
	mustCreateB4Event(t, s, b4AuditContext("event_create"), testB4EventA, "Event A", now)
	for _, table := range []string{"admin_audit", "aliases"} {
		var name string
		if err := s.db.QueryRowContext(ctx,
			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name); err != nil {
			t.Fatalf("missing v9 table %q: %v", table, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	if version, err := reopened.SchemaVersion(ctx); err != nil || version != 9 {
		t.Fatalf("reopened schema version = %d (err=%v)", version, err)
	}
	record, err := reopened.GetEvent(ctx, testB4EventA, nil)
	if err != nil {
		t.Fatalf("GetEvent after reopen: %v", err)
	}
	if record.DisplayName != "Event A" || record.State != EventActive {
		t.Fatalf("reopened event = %+v", record)
	}
}

func TestB4EventCreateRenameListAndScope(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)

	a := mustCreateB4Event(t, s, b4AuditContext("event_create"), testB4EventA, "Event A", now)
	mustCreateB4Event(t, s, b4AuditContext("event_create"), testB4EventB, "Event B", now+1)
	if a.State != EventActive || a.NodeCount != 0 || a.CreatedAt != now {
		t.Fatalf("created event A = %+v", a)
	}
	if _, err := s.CreateEvent(ctx, testB4EventA, "Again", now+2); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate CreateEvent error = %v, want ErrAlreadyExists", err)
	}
	for _, badName := range []string{"", "   ", "bad\nname", "bad\x00name", strings.Repeat("a", 129)} {
		if _, err := s.CreateEvent(ctx, testB4EventC, badName, now); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("CreateEvent name %q error = %v, want ErrInvalidArgument", badName, err)
		}
	}
	if _, err := s.CreateEvent(ctx, "not-a-uuid", "Event", now); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("CreateEvent invalid id error = %v", err)
	}

	records, total, err := s.ListEvents(ctx, nil, EventListFilter{})
	if err != nil || total != 2 || len(records) != 2 {
		t.Fatalf("ListEvents = %d/%d err=%v", len(records), total, err)
	}
	if records[0].EventID != testB4EventA || records[1].EventID != testB4EventB {
		t.Fatalf("ListEvents order = %q, %q", records[0].EventID, records[1].EventID)
	}
	if _, total, err := s.ListEvents(ctx, nil, EventListFilter{States: []string{EventArchived}}); err != nil || total != 0 {
		t.Fatalf("archived ListEvents = %d err=%v", total, err)
	}
	if _, _, err := s.ListEvents(ctx, nil, EventListFilter{States: []string{"bogus"}}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("invalid state filter error = %v", err)
	}
	if _, _, err := s.ListEvents(ctx, nil, EventListFilter{Offset: B4MaxOffset + 1}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("oversized offset error = %v", err)
	}

	scoped, total, err := s.ListEvents(ctx, []string{testB4EventA}, EventListFilter{})
	if err != nil || total != 1 || len(scoped) != 1 || scoped[0].EventID != testB4EventA {
		t.Fatalf("scoped ListEvents = %+v total=%d err=%v", scoped, total, err)
	}
	if _, total, err := s.ListEvents(ctx, []string{}, EventListFilter{}); err != nil || total != 0 {
		t.Fatalf("empty scope ListEvents = %d err=%v", total, err)
	}
	if _, err := s.GetEvent(ctx, testB4EventB, []string{testB4EventA}); !errors.Is(err, ErrEventUnknown) {
		t.Fatalf("out-of-scope GetEvent error = %v, want ErrEventUnknown", err)
	}

	if err := s.RenameEvent(b4AuditContext("event_rename"), testB4EventA, "Renamed A", now+3); err != nil {
		t.Fatalf("RenameEvent: %v", err)
	}
	if err := s.RenameEvent(ctx, testB4EventC, "Nope", now); !errors.Is(err, ErrEventUnknown) {
		t.Fatalf("rename unknown event error = %v", err)
	}
	if err := s.RenameEvent(ctx, testB4EventA, "bad\nname", now); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("rename invalid name error = %v", err)
	}
	record, err := s.GetEvent(ctx, testB4EventA, nil)
	if err != nil || record.DisplayName != "Renamed A" {
		t.Fatalf("renamed event = %+v err=%v", record, err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM admin_audit WHERE action='event_create'`); got != 2 {
		t.Fatalf("event_create audit rows = %d, want 2", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM admin_audit WHERE action='event_rename' AND target='test' AND event_id=?`, testB4EventA); got != 1 {
		t.Fatalf("event_rename audit rows = %d, want 1", got)
	}
	if got := countLedgerKind(t, s, "event_created"); got != 2 {
		t.Fatalf("event_created ledger rows = %d, want 2", got)
	}

	// Archive is a normal lifecycle mutation that now also records audit.
	if err := s.ArchiveEvent(b4AuditContext("event_archive"), testB4EventA, now+4); err != nil {
		t.Fatalf("ArchiveEvent: %v", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM admin_audit WHERE action='event_archive'`); got != 1 {
		t.Fatalf("event_archive audit rows = %d, want 1", got)
	}
	if _, total, err := s.ListEvents(ctx, nil, EventListFilter{States: []string{EventArchived}}); err != nil || total != 1 {
		t.Fatalf("archived ListEvents after archive = %d err=%v", total, err)
	}
}

func TestB4EventCreateRejectsGraveyardPurgingAndQuota(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)

	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO event_graveyard(event_id,purged_at,op_id) VALUES(?,?,?)`,
		testB4EventC, now, "purge-deadbeef"); err != nil {
		t.Fatalf("seed graveyard: %v", err)
	}
	if _, err := s.CreateEvent(ctx, testB4EventC, "Graveyard", now); !errors.Is(err, ErrEventPurged) {
		t.Fatalf("graveyard CreateEvent error = %v, want ErrEventPurged", err)
	}

	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO purge_ops(op_id,event_id,actor,started_at,updated_at,state,phase,deleted_rows,error)
		 VALUES('purge-in-progress',?,?,?,?, 'purging','telemetry',0,NULL)`,
		testB4EventD, "admin", now, now); err != nil {
		t.Fatalf("seed purge op: %v", err)
	}
	if _, err := s.CreateEvent(ctx, testB4EventD, "Purging", now); !errors.Is(err, ErrEventPurged) {
		t.Fatalf("purging CreateEvent error = %v, want ErrEventPurged", err)
	}

	// Fill the event catalog to the frozen max with direct rows to keep the test
	// bounded; CreateEvent enforces the quota under the capacity lock.
	for i := 0; i < MaxEventsCatalog; i++ {
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO event_catalog(event_id,state,created_at,archived_at,purge_after,data_purged_at,updated_at)
			 VALUES(?,?,?,NULL,NULL,NULL,?)`,
			fmt.Sprintf("quota-seed-%02d", i), EventActive, now, now); err != nil {
			t.Fatalf("seed catalog %d: %v", i, err)
		}
	}
	if _, err := s.CreateEvent(ctx, testB4EventA, "Over quota", now); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("quota CreateEvent error = %v, want ErrQuotaExceeded", err)
	}
}

func TestB4NodeListDetailConfigHistoryAndRevokeAudit(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	mustCreateB4Event(t, s, ctx, testB4EventA, "Event A", now)

	linuxNode := mustEnrollB4Node(t, s, testB4EventA, NodeClassLinuxVPS, now)
	winNode := mustEnrollB4Node(t, s, testB4EventA, NodeClassWindowsTerminal, now)
	revokedNode := mustEnrollB4Node(t, s, testB4EventA, NodeClassLinuxVPS, now)

	if err := s.RevokeNode(b4AuditContext("node_revoke"), revokedNode.NodeID, now+10); err != nil {
		t.Fatalf("RevokeNode: %v", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM admin_audit WHERE action='node_revoke'`); got != 1 {
		t.Fatalf("node_revoke audit rows = %d, want 1", got)
	}
	// The ledger detail names the authenticated actor, never a hardcoded "admin".
	var detail string
	if err := s.db.QueryRowContext(ctx,
		`SELECT detail_sha256 FROM security_ledger WHERE kind='node_revoked' AND subject=?`,
		revokedNode.NodeID).Scan(&detail); err != nil {
		t.Fatalf("read node_revoked ledger: %v", err)
	}
	if detail != ledgerDetailHash("admin-1") {
		t.Fatalf("node_revoked ledger detail = %q, want actor-scoped hash", detail)
	}

	if nodes, total, err := s.ListNodes(ctx, nil, "", "", "", 0, 0); err != nil || total != 3 || len(nodes) != 3 {
		t.Fatalf("ListNodes all = %d/%d err=%v", len(nodes), total, err)
	}
	if _, total, err := s.ListNodes(ctx, nil, testB4EventA, NodeClassLinuxVPS, "", 0, 0); err != nil || total != 2 {
		t.Fatalf("linux nodes = %d err=%v", total, err)
	}
	if nodes, total, err := s.ListNodes(ctx, nil, "", "", NodeRevoked, 0, 0); err != nil || total != 1 ||
		len(nodes) != 1 || nodes[0].NodeID != revokedNode.NodeID || nodes[0].RetiredAt == nil {
		t.Fatalf("revoked nodes = %+v total=%d err=%v", nodes, total, err)
	}
	if _, _, err := s.ListNodes(ctx, nil, "", "bogus", "", 0, 0); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("invalid class filter error = %v", err)
	}
	if _, _, err := s.ListNodes(ctx, []string{testB4EventB}, testB4EventA, "", "", 0, 0); !errors.Is(err, ErrEventUnknown) {
		t.Fatalf("out-of-scope ListNodes error = %v", err)
	}
	if _, total, err := s.ListNodes(ctx, []string{}, "", "", "", 0, 0); err != nil || total != 0 {
		t.Fatalf("empty scope ListNodes = %d err=%v", total, err)
	}

	// Config update (audited) and effective-dated history.
	cfg, err := s.GetNodeConfig(ctx, linuxNode.NodeID)
	if err != nil {
		t.Fatalf("GetNodeConfig: %v", err)
	}
	if _, err := s.UpdateNodeConfig(b4AuditContext("config_write"), linuxNode.NodeID,
		cfg.Sources, cfg.ExpectedInboundTags, 120, now+5); err != nil {
		t.Fatalf("UpdateNodeConfig: %v", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM admin_audit WHERE action='config_write'`); got != 1 {
		t.Fatalf("config_write audit rows = %d, want 1", got)
	}
	history, err := s.ListConfigHistory(ctx, linuxNode.NodeID, 0)
	if err != nil || len(history) != 2 {
		t.Fatalf("ListConfigHistory = %d err=%v", len(history), err)
	}
	if history[0].ConfigVersion != 2 || history[0].CadenceSeconds != 120 || history[0].EffectiveFrom != now+5 ||
		history[0].SourcesJSON == "" || history[0].DeviceSalt == "" {
		t.Fatalf("newest config history = %+v", history[0])
	}
	if short, err := s.ListConfigHistory(ctx, linuxNode.NodeID, 1); err != nil || len(short) != 1 || short[0].ConfigVersion != 2 {
		t.Fatalf("limited config history = %+v err=%v", short, err)
	}
	if _, err := s.ListConfigHistory(ctx, "99999999-9999-4999-8999-999999999999", 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown node config history error = %v", err)
	}

	// Latest snapshot, node alias and full detail.
	payload := []byte(`{"schema":"um-snapshot/1","bounded":true}`)
	if err := s.WithTx(ctx, func(tx *Tx) error {
		_, err := tx.StoreSnapshotTx(ctx, SnapshotRecord{
			NodeID: linuxNode.NodeID, EventID: testB4EventA, NodeClass: NodeClassLinuxVPS,
			ReportID: "report-b4-1", CollectedAt: now, ReceivedAt: now,
			BodySHA256: "sha-b4-1", Payload: payload,
		})
		return err
	}); err != nil {
		t.Fatalf("seed snapshot: %v", err)
	}
	alias, err := s.SetAlias(b4AuditContext("alias_write"), testB4EventA, AliasTargetNode,
		linuxNode.NodeID, "Linux one", "admin-1", nil, now)
	if err != nil || alias.Version != 1 {
		t.Fatalf("SetAlias node = %+v err=%v", alias, err)
	}
	nodes, _, err := s.ListNodes(ctx, nil, testB4EventA, NodeClassLinuxVPS, NodeActive, 0, 0)
	if err != nil || len(nodes) != 1 {
		t.Fatalf("active linux nodes = %+v err=%v", nodes, err)
	}
	summary := nodes[0]
	if summary.Alias != "Linux one" || summary.ConfigVersion == nil || *summary.ConfigVersion != 2 ||
		summary.CadenceSeconds == nil || *summary.CadenceSeconds != 120 ||
		summary.LatestSnapshotAt == nil || *summary.LatestSnapshotAt != now ||
		summary.LatestReportID != "report-b4-1" || summary.NodeID != linuxNode.NodeID {
		t.Fatalf("node summary = %+v", summary)
	}
	nodeDetail, err := s.GetNodeDetail(ctx, nil, testB4EventA, linuxNode.NodeID)
	if err != nil {
		t.Fatalf("GetNodeDetail: %v", err)
	}
	if len(nodeDetail.Keys) != 1 || nodeDetail.Keys[0].KeyID != linuxNode.KeyID || nodeDetail.Keys[0].State != KeyActive {
		t.Fatalf("node detail keys = %+v", nodeDetail.Keys)
	}
	if len(nodeDetail.Rotations) != 0 {
		t.Fatalf("node detail rotations = %+v", nodeDetail.Rotations)
	}
	if string(nodeDetail.LatestSnapshot) != string(payload) || nodeDetail.Alias != "Linux one" {
		t.Fatalf("node detail snapshot/alias = %q/%q", nodeDetail.LatestSnapshot, nodeDetail.Alias)
	}
	if _, err := s.GetNodeDetail(ctx, []string{testB4EventB}, testB4EventA, linuxNode.NodeID); !errors.Is(err, ErrEventUnknown) {
		t.Fatalf("out-of-scope GetNodeDetail error = %v, want ErrEventUnknown", err)
	}
	if _, err := s.GetNodeDetail(ctx, nil, testB4EventB, linuxNode.NodeID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong-event GetNodeDetail error = %v, want ErrNotFound", err)
	}
	// The windows node is addressable independently of the linux node.
	if detail, err := s.GetNodeDetail(ctx, nil, testB4EventA, winNode.NodeID); err != nil || detail.NodeClass != NodeClassWindowsTerminal {
		t.Fatalf("windows node detail = %+v err=%v", detail, err)
	}
}

func TestB4AliasLifecycleConflictsAndAudit(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	mustCreateB4Event(t, s, ctx, testB4EventA, "Event A", now)
	node := mustEnrollB4Node(t, s, testB4EventA, NodeClassLinuxVPS, now)

	created, err := s.SetAlias(b4AuditContext("alias_write"), testB4EventA, AliasTargetNode,
		node.NodeID, "Node one", "admin-1", nil, now)
	if err != nil || created.Version != 1 || created.DisplayName != "Node one" || created.UpdatedBy != "admin-1" {
		t.Fatalf("create alias = %+v err=%v", created, err)
	}
	if _, err := s.SetAlias(ctx, testB4EventA, AliasTargetNode, node.NodeID, "blind", "admin-1", nil, now); !errors.Is(err, ErrAliasConflict) {
		t.Fatalf("blind upsert error = %v, want ErrAliasConflict", err)
	}
	if _, err := s.SetAlias(ctx, testB4EventA, AliasTargetNode, node.NodeID, "stale", "admin-1", ptrInt64(5), now); !errors.Is(err, ErrAliasConflict) {
		t.Fatalf("stale version error = %v, want ErrAliasConflict", err)
	}
	updated, err := s.SetAlias(b4AuditContext("alias_write"), testB4EventA, AliasTargetNode,
		node.NodeID, "Node one v2", "admin-2", ptrInt64(1), now+1)
	if err != nil || updated.Version != 2 || updated.UpdatedBy != "admin-2" {
		t.Fatalf("update alias = %+v err=%v", updated, err)
	}

	// Route targets: the four A/B protocol tokens plus direct/unknown.
	for _, token := range []string{RouteTokenAReality, RouteTokenAHy2, "b_reality", "b_hy2", RouteTokenDirect, "unknown"} {
		alias, err := s.SetAlias(b4AuditContext("alias_write"), testB4EventA, AliasTargetRoute, token, "route "+token, "admin-1", nil, now)
		if err != nil || alias.Version != 1 {
			t.Fatalf("route alias %q = %+v err=%v", token, alias, err)
		}
	}
	if _, err := s.SetAlias(ctx, testB4EventA, AliasTargetRoute, "bogus", "bad", "admin-1", nil, now); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("invalid route alias error = %v", err)
	}
	if _, err := s.SetAlias(b4AuditContext("alias_write"), testB4EventA, AliasTargetDeviceRef, "device-1", "Device one", "admin-1", nil, now); err != nil {
		t.Fatalf("device alias: %v", err)
	}
	// Locked validation cases.
	if _, err := s.SetAlias(ctx, testB4EventA, AliasTargetNode, "99999999-9999-4999-8999-999999999999", "Ghost", "admin-1", nil, now); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("missing node target error = %v", err)
	}
	if _, err := s.SetAlias(ctx, testB4EventA, AliasTargetNode, node.NodeID, "bad\nname", "admin-1", nil, now); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("control display name error = %v", err)
	}
	if _, err := s.SetAlias(ctx, testB4EventA, AliasTargetNode, node.NodeID, "Blind", "admin-1", ptrInt64(1), now); !errors.Is(err, ErrAliasConflict) {
		t.Fatalf("create with expected version error = %v", err)
	}
	if _, err := s.SetAlias(ctx, testB4EventC, AliasTargetNode, node.NodeID, "Unknown event", "admin-1", nil, now); !errors.Is(err, ErrEventUnknown) {
		t.Fatalf("unknown event alias error = %v", err)
	}
	if _, err := s.SetAlias(ctx, testB4EventA, "bogus", "x", "Name", "admin-1", nil, now); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("invalid target type error = %v", err)
	}
	if _, err := s.SetAlias(ctx, testB4EventA, AliasTargetDeviceRef, strings.Repeat("k", 129), "Name", "admin-1", nil, now); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("oversized target key error = %v", err)
	}
	if _, err := s.SetAlias(ctx, testB4EventA, AliasTargetDeviceRef, "device-2", "Name", "", nil, now); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("empty actor error = %v", err)
	}

	aliases, err := s.ListAliases(ctx, testB4EventA, AliasTargetRoute)
	if err != nil || len(aliases) != 6 {
		t.Fatalf("route aliases = %d err=%v", len(aliases), err)
	}
	if all, err := s.ListAliases(ctx, testB4EventA, ""); err != nil || len(all) != 8 {
		t.Fatalf("all aliases = %d err=%v", len(all), err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM admin_audit WHERE action='alias_write'`); got != 9 {
		t.Fatalf("alias_write audit rows = %d, want 9", got)
	}

	if err := s.DeleteAlias(b4AuditContext("alias_write"), testB4EventA, AliasTargetNode, node.NodeID, "admin-1", now+2); err != nil {
		t.Fatalf("DeleteAlias: %v", err)
	}
	if err := s.DeleteAlias(ctx, testB4EventA, AliasTargetNode, node.NodeID, "admin-1", now+3); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second DeleteAlias error = %v, want ErrNotFound", err)
	}
	if aliases, err := s.ListAliases(ctx, testB4EventA, AliasTargetNode); err != nil || len(aliases) != 0 {
		t.Fatalf("node aliases after delete = %d err=%v", len(aliases), err)
	}
}

func TestB4EnrollTokenRevokeRejectsEnrollmentAndAudits(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	// Token status is derived against the wall clock by ListEnrollTokens, so this
	// test anchors its fixture close to now while keeping deterministic offsets.
	now := nowUnix() - 1000
	mustCreateB4Event(t, s, ctx, testB4EventA, "Event A", now)

	// CreateEnrollToken audit: the caller supplies actor/role/action; the store
	// derives the closed target and the event id.
	_, hash, err := NewEnrollToken()
	if err != nil {
		t.Fatalf("NewEnrollToken: %v", err)
	}
	createCtx := WithAuditMeta(ctx, AuditMeta{
		Actor: "event-admin", Role: "event_admin", Action: "enroll_token_create", RequestID: "req-token-create",
	})
	if err := s.CreateEnrollToken(createCtx, hash, testB4EventA, NodeClassLinuxVPS, now+3600, now); err != nil {
		t.Fatalf("CreateEnrollToken: %v", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM admin_audit WHERE action='enroll_token_create' AND target='enroll_token' AND event_id=?`, testB4EventA); got != 1 {
		t.Fatalf("enroll_token_create audit rows = %d, want 1", got)
	}
	tokens, total, err := s.ListEnrollTokens(ctx, nil, testB4EventA, 0, 0)
	if err != nil || total != 1 || len(tokens) != 1 {
		t.Fatalf("ListEnrollTokens = %d/%d err=%v", len(tokens), total, err)
	}
	if tokens[0].Status != EnrollTokenStatusUnused || tokens[0].RevokedAt != nil || tokens[0].CreatedAt == nil ||
		tokens[0].ExpiresAt == nil || tokens[0].EventID != testB4EventA || tokens[0].TokenHash != hash {
		t.Fatalf("unused token = %+v", tokens[0])
	}
	info, err := s.TokenInfo(ctx, hash)
	if err != nil || info.RevokedAt != nil || info.UsedAt != nil {
		t.Fatalf("TokenInfo before revoke = %+v err=%v", info, err)
	}
	if _, _, err := s.ListEnrollTokens(ctx, []string{testB4EventB}, testB4EventA, 0, 0); !errors.Is(err, ErrEventUnknown) {
		t.Fatalf("out-of-scope ListEnrollTokens error = %v", err)
	}

	revokeCtx := WithAuditMeta(ctx, AuditMeta{
		Actor: "event-admin", Role: "event_admin", Action: "enroll_token_revoke", RequestID: "req-token-revoke",
	})
	if err := s.RevokeEnrollToken(revokeCtx, testB4EventA, hash, now+1); err != nil {
		t.Fatalf("RevokeEnrollToken: %v", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM admin_audit WHERE action='enroll_token_revoke' AND target='enroll_token' AND event_id=?`, testB4EventA); got != 1 {
		t.Fatalf("enroll_token_revoke audit rows = %d, want 1", got)
	}
	if got := countLedgerKind(t, s, "enroll_token_revoked"); got != 1 {
		t.Fatalf("enroll_token_revoked ledger rows = %d, want 1", got)
	}
	info, err = s.TokenInfo(ctx, hash)
	if err != nil || info.RevokedAt == nil || *info.RevokedAt != now+1 {
		t.Fatalf("TokenInfo after revoke = %+v err=%v", info, err)
	}
	if tokens, _, err := s.ListEnrollTokens(ctx, nil, testB4EventA, 0, 0); err != nil || tokens[0].Status != EnrollTokenStatusRevoked {
		t.Fatalf("revoked token status = %+v err=%v", tokens, err)
	}
	// Revoked token can never enroll a node.
	if _, err := s.Enroll(ctx, hash, NodeClassLinuxVPS, "linux", testPublicKey(t), now+2); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("Enroll with revoked token error = %v, want ErrTokenRevoked", err)
	}
	// Idempotent revoke does not duplicate the audit/ledger row.
	if err := s.RevokeEnrollToken(ctx, testB4EventA, hash, now+3); err != nil {
		t.Fatalf("idempotent RevokeEnrollToken: %v", err)
	}
	if got := countLedgerKind(t, s, "enroll_token_revoked"); got != 1 {
		t.Fatalf("idempotent revoke ledger rows = %d, want 1", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM admin_audit WHERE action='enroll_token_revoke'`); got != 1 {
		t.Fatalf("idempotent revoke audit rows = %d, want 1", got)
	}

	// Expired token cannot be revoked.
	_, expiredHash, err := NewEnrollToken()
	if err != nil {
		t.Fatalf("NewEnrollToken: %v", err)
	}
	if err := s.CreateEnrollToken(ctx, expiredHash, testB4EventA, NodeClassLinuxVPS, now+5, now); err != nil {
		t.Fatalf("create expiring token: %v", err)
	}
	if err := s.RevokeEnrollToken(ctx, testB4EventA, expiredHash, now+6); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired revoke error = %v, want ErrTokenExpired", err)
	}
	// Used token cannot be revoked.
	_, usedHash, err := NewEnrollToken()
	if err != nil {
		t.Fatalf("NewEnrollToken: %v", err)
	}
	if err := s.CreateEnrollToken(ctx, usedHash, testB4EventA, NodeClassLinuxVPS, now+3600, now); err != nil {
		t.Fatalf("create used token: %v", err)
	}
	if _, err := s.Enroll(ctx, usedHash, NodeClassLinuxVPS, "linux", testPublicKey(t), now); err != nil {
		t.Fatalf("consume token: %v", err)
	}
	if err := s.RevokeEnrollToken(ctx, testB4EventA, usedHash, now+7); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("used revoke error = %v, want ErrTokenUsed", err)
	}
	// Unknown/wrong-scope hashes are token_invalid; malformed input is rejected.
	if err := s.RevokeEnrollToken(ctx, testB4EventA, TokenHash("missing"), now); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("unknown hash error = %v, want ErrTokenInvalid", err)
	}
	if err := s.RevokeEnrollToken(ctx, testB4EventB, hash, now); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("wrong event hash error = %v, want ErrTokenInvalid", err)
	}
	if err := s.RevokeEnrollToken(ctx, testB4EventA, "short", now); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("malformed hash error = %v", err)
	}
	if err := s.RevokeEnrollToken(ctx, "event-a", hash, now); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("malformed event error = %v", err)
	}
}

func TestB4MappingVersionsAuditAndLedger(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	mustCreateB4Event(t, s, ctx, testB4EventA, "Event A", now)
	winNode := mustEnrollB4Node(t, s, testB4EventA, NodeClassWindowsTerminal, now)
	linuxNode := mustEnrollB4Node(t, s, testB4EventA, NodeClassLinuxVPS, now)

	mappingCtx := WithAuditMeta(ctx, AuditMeta{
		Actor: "admin-1", Role: "platform_admin", Action: "route_mapping_write", RequestID: "req-map",
	})
	entries := map[string]string{RouteTokenAReality: linuxNode.NodeID}
	if err := s.createMappingVersion(mappingCtx, testB4EventA, winNode.NodeID, 1, now+10, "admin-1", entries, now); err != nil {
		t.Fatalf("createMappingVersion: %v", err)
	}
	if got := countLedgerKind(t, s, "route_mapping_created"); got != 1 {
		t.Fatalf("route_mapping_created ledger rows = %d, want 1", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM admin_audit WHERE action='route_mapping_write' AND target='route_mapping' AND event_id=?`, testB4EventA); got != 1 {
		t.Fatalf("route_mapping_write audit rows = %d, want 1", got)
	}
	versions, err := s.ListMappingVersions(ctx, testB4EventA, winNode.NodeID)
	if err != nil || len(versions) != 1 {
		t.Fatalf("ListMappingVersions = %+v err=%v", versions, err)
	}
	if versions[0].Version != 1 || versions[0].EffectiveFrom != now+10 || versions[0].CreatedBy != "admin-1" ||
		versions[0].Entries[RouteTokenAReality] != linuxNode.NodeID || versions[0].CreatedAt == 0 {
		t.Fatalf("mapping version = %+v", versions[0])
	}

	entries2 := map[string]string{
		RouteTokenAReality: linuxNode.NodeID,
		RouteTokenBHy2:     linuxNode.NodeID,
	}
	if err := s.createMappingVersion(ctx, testB4EventA, winNode.NodeID, 2, now+20, "admin-2", entries2, now); err != nil {
		t.Fatalf("createMappingVersion v2: %v", err)
	}
	versions, err = s.ListMappingVersions(ctx, testB4EventA, winNode.NodeID)
	if err != nil || len(versions) != 2 {
		t.Fatalf("ListMappingVersions after v2 = %+v err=%v", versions, err)
	}
	if versions[0].Version != 2 || versions[1].Version != 1 {
		t.Fatalf("mapping version order = %d, %d", versions[0].Version, versions[1].Version)
	}
	if len(versions[0].Entries) != 2 || versions[0].Entries[RouteTokenBHy2] != linuxNode.NodeID {
		t.Fatalf("mapping v2 entries = %+v", versions[0].Entries)
	}
	if _, err := s.ListMappingVersions(ctx, testB4EventB, winNode.NodeID); !errors.Is(err, ErrEventUnknown) {
		t.Fatalf("unknown event mapping list error = %v", err)
	}
	if _, err := s.ListMappingVersions(ctx, "not-a-uuid", winNode.NodeID); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("invalid event mapping list error = %v", err)
	}
}

func TestB4PurgePreviewStatusAndRetentionRuns(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)
	mustCreateB4Event(t, s, ctx, testB4EventA, "Event A", now)
	linuxNode := mustEnrollB4Node(t, s, testB4EventA, NodeClassLinuxVPS, now)
	winNode := mustEnrollB4Node(t, s, testB4EventA, NodeClassWindowsTerminal, now)

	_, extraHash, err := NewEnrollToken()
	if err != nil {
		t.Fatalf("NewEnrollToken: %v", err)
	}
	if err := s.CreateEnrollToken(ctx, extraHash, testB4EventA, NodeClassLinuxVPS, now+3600, now); err != nil {
		t.Fatalf("CreateEnrollToken: %v", err)
	}
	if err := s.WithTx(ctx, func(tx *Tx) error {
		_, err := tx.StoreSnapshotTx(ctx, SnapshotRecord{
			NodeID: linuxNode.NodeID, EventID: testB4EventA, NodeClass: NodeClassLinuxVPS,
			ReportID: "purge-report-1", CollectedAt: now, ReceivedAt: now,
			BodySHA256: "purge-sha-1", Payload: []byte(`{"ok":true}`),
		})
		return err
	}); err != nil {
		t.Fatalf("seed snapshot: %v", err)
	}
	if err := s.createMappingVersion(ctx, testB4EventA, winNode.NodeID, 1, now+10, "admin-1",
		map[string]string{RouteTokenAHy2: linuxNode.NodeID}, now); err != nil {
		t.Fatalf("createMappingVersion: %v", err)
	}
	if _, err := s.SetAlias(ctx, testB4EventA, AliasTargetNode, linuxNode.NodeID, "Linux", "admin-1", nil, now); err != nil {
		t.Fatalf("SetAlias: %v", err)
	}

	preview, err := s.PurgePreview(ctx, testB4EventA)
	if err != nil {
		t.Fatalf("PurgePreview: %v", err)
	}
	if preview.Event.DisplayName != "Event A" || preview.DataPurged || preview.Incomplete {
		t.Fatalf("preview flags = %+v", preview)
	}
	expectedCounts := map[string]int64{
		"nodes": 2, "snapshots": 1, "node_configs": 2, "node_latest": 1,
		"route_mapping_versions": 1, "route_mapping_entries": 1, "aliases": 1,
	}
	for table, want := range expectedCounts {
		if got := preview.TableCounts[table]; got != want {
			t.Fatalf("preview count %s = %d, want %d", table, got, want)
		}
	}
	if preview.TableCounts["enroll_tokens"] < 3 {
		t.Fatalf("preview enroll_tokens = %d, want >= 3", preview.TableCounts["enroll_tokens"])
	}
	var sum int64
	for _, count := range preview.TableCounts {
		sum += count
	}
	if preview.TotalRows != sum {
		t.Fatalf("preview total = %d, want %d", preview.TotalRows, sum)
	}

	if err := s.ArchiveEvent(b4AuditContext("event_archive"), testB4EventA, now+20); err != nil {
		t.Fatalf("ArchiveEvent: %v", err)
	}
	purgeCtx := WithAuditMeta(ctx, AuditMeta{
		Actor: "platform-admin", Role: "platform_admin", Action: "event_purge", RequestID: "req-purge",
	})
	if err := s.PurgeEvent(purgeCtx, testB4EventA, "platform-admin", true, now+100); err != nil {
		t.Fatalf("PurgeEvent: %v", err)
	}
	status, err := s.PurgeStatus(ctx, testB4EventA)
	if err != nil {
		t.Fatalf("PurgeStatus: %v", err)
	}
	wantRetain := now + 100 + PurgeTombstoneSeconds
	if !status.Graveyard || !status.Purged || status.State != "completed" || status.Phase != "completed" ||
		status.DeletedRows < 1 || status.TombstoneUntil == nil || *status.TombstoneUntil != wantRetain {
		t.Fatalf("purge status = %+v", status)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM admin_audit WHERE action='event_purge' AND event_id=?`, testB4EventA); got != 1 {
		t.Fatalf("event_purge audit rows = %d, want 1", got)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM aliases WHERE event_id=?`, testB4EventA); got != 0 {
		t.Fatalf("aliases after purge = %d, want 0", got)
	}
	if _, err := s.PurgePreview(ctx, testB4EventA); !errors.Is(err, ErrEventPurged) {
		t.Fatalf("preview after purge error = %v, want ErrEventPurged", err)
	}
	if _, err := s.GetEvent(ctx, testB4EventA, nil); !errors.Is(err, ErrEventPurged) {
		t.Fatalf("GetEvent after purge error = %v, want ErrEventPurged", err)
	}
	if _, err := s.CreateEvent(ctx, testB4EventA, "Again", now+101); !errors.Is(err, ErrEventPurged) {
		t.Fatalf("re-create purged event error = %v, want ErrEventPurged", err)
	}
	if _, err := s.PurgeStatus(ctx, testB4EventC); !errors.Is(err, ErrEventUnknown) {
		t.Fatalf("unknown purge status error = %v, want ErrEventUnknown", err)
	}
	if _, err := s.PurgePreview(ctx, "bad"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("invalid purge preview error = %v", err)
	}

	// Retention run history is recorded by the existing bounded sweep engine.
	if _, err := s.RunRetentionB2(ctx, now+200); err != nil {
		t.Fatalf("RunRetentionB2: %v", err)
	}
	runs, err := s.ListRetentionRuns(ctx, 0)
	if err != nil || len(runs) == 0 {
		t.Fatalf("ListRetentionRuns = %d err=%v", len(runs), err)
	}
	if runs[0].Status != "completed" || runs[0].StartedAt == nil || *runs[0].StartedAt != now+200 ||
		runs[0].DeletedCounts == nil {
		t.Fatalf("retention run = %+v", runs[0])
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO retention_runs(ran_at,result_json) VALUES(?,?)`, now+201, `{"snapshots":2,"report_metrics":1}`); err != nil {
		t.Fatalf("seed legacy retention run: %v", err)
	}
	runs, err = s.ListRetentionRuns(ctx, 1)
	if err != nil || len(runs) != 1 || runs[0].DeletedCounts["snapshots"] != 2 {
		t.Fatalf("limited retention runs = %+v err=%v", runs, err)
	}
}

func TestB4AuditMissingOrIncompleteMetaIsAtomic(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := testContext()
	now := int64(1_700_000_000)

	// An internal/agent-style call without AuditMeta is allowed and writes no
	// audit row.
	if _, err := s.CreateEvent(ctx, testB4EventA, "No audit", now); err != nil {
		t.Fatalf("CreateEvent without meta: %v", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM admin_audit`); got != 0 {
		t.Fatalf("audit rows after meta-less create = %d, want 0", got)
	}
	// A malformed/incomplete AuditMeta fails the audit append, which rolls back
	// the whole mutation in the same transaction.
	incomplete := WithAuditMeta(ctx, AuditMeta{Actor: "admin-1"})
	if _, err := s.CreateEvent(incomplete, testB4EventB, "Rolled back", now); err == nil {
		t.Fatal("CreateEvent with incomplete audit meta succeeded, want rollback error")
	}
	if _, err := s.GetEvent(ctx, testB4EventB, nil); !errors.Is(err, ErrEventUnknown) {
		t.Fatalf("rolled-back event visible: %v", err)
	}
	if got := countLedgerKind(t, s, "event_created"); got != 1 {
		t.Fatalf("event_created ledger rows = %d, want 1 (rolled-back create must not write)", got)
	}
	// The same no-op guarantee holds for an existing audited mutation.
	_, hash, err := NewEnrollToken()
	if err != nil {
		t.Fatalf("NewEnrollToken: %v", err)
	}
	if err := s.CreateEnrollToken(ctx, hash, testB4EventA, NodeClassLinuxVPS, now+3600, now); err != nil {
		t.Fatalf("CreateEnrollToken without meta: %v", err)
	}
	if got := queryInt(t, s, `SELECT COUNT(*) FROM admin_audit`); got != 0 {
		t.Fatalf("audit rows after meta-less token create = %d, want 0", got)
	}
}

func ptrInt64(v int64) *int64 { return &v }

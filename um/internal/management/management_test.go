package management_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/center"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/management"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/schema"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
)

const (
	contractsDir = "../../../docs/um/contracts/v1"
	eventA       = "11111111-1111-4111-8111-111111111111"
	eventB       = "22222222-2222-4222-8222-222222222222"
)

type b4Center struct {
	st       *store.Store
	srv      *center.Server
	adminURL string
	ingest   string
	tokens   map[string]string
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func writeProtected(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func startB4Center(t *testing.T) *b4Center {
	t.Helper()
	dir := t.TempDir()
	db := filepath.Join(dir, "center.db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	schemas, err := schema.Load(contractsDir)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := center.NewService(center.ServiceConfig{Store: st, Schemas: schemas})
	if err != nil {
		t.Fatal(err)
	}
	mgmt, err := management.NewService(st)
	if err != nil {
		t.Fatal(err)
	}
	raw := map[string]string{
		"platform": "platform-token-0123456789abcdef",
		"admin-a":  "admin-a-token-0123456789abcdef",
		"admin-b":  "admin-b-token-0123456789abcdef",
		"viewer-a": "viewer-a-token-0123456789abcdef",
		"viewer-b": "viewer-b-token-0123456789abcdef",
	}
	authDoc := management.AuthConfig{
		Principals: []management.AuthPrincipal{
			{ID: "platform", Role: management.RolePlatformAdmin},
			{ID: "admin-a", Role: management.RoleEventAdmin, EventIDs: []string{eventA}},
			{ID: "admin-b", Role: management.RoleEventAdmin, EventIDs: []string{eventB}},
			{ID: "viewer-a", Role: management.RoleViewer, EventIDs: []string{eventA}},
			{ID: "viewer-b", Role: management.RoleViewer, EventIDs: []string{eventB}},
		},
	}
	for name, rawToken := range raw {
		authDoc.Tokens = append(authDoc.Tokens, management.AuthToken{SHA256: tokenHash(rawToken), PrincipalID: name})
	}
	authRaw, _ := json.Marshal(authDoc)
	authPath := filepath.Join(dir, "admin-auth.json")
	if err := os.WriteFile(authPath, authRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(authPath, 0o600); err != nil {
		t.Fatal(err)
	}
	auth, err := management.LoadFileAuthenticator(authPath)
	if err != nil {
		t.Fatal(err)
	}
	ip := dir + string(os.PathSeparator)
	_ = ip
	api, err := management.NewHandler(mgmt, auth)
	if err != nil {
		t.Fatal(err)
	}
	cfg := center.Config{IngestAddr: "127.0.0.1:0", AdminAddr: "127.0.0.1:0",
		DBPath: db, ContractDir: contractsDir, RateLimitPerSecond: -1, AdminAPI: api}
	srv, err := center.NewServer(cfg, svc)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close(); _ = st.Close() })
	tokens := map[string]string{}
	for name, rawToken := range raw {
		p := filepath.Join(dir, "token-"+name)
		writeProtected(t, p, []byte(rawToken))
		tokens[name] = p
	}
	return &b4Center{st: st, srv: srv, adminURL: "http://" + srv.AdminAddr(),
		ingest: "http://" + srv.IngestAddr(), tokens: tokens}
}

func clientFor(t *testing.T, c *b4Center, who string) *management.Client {
	t.Helper()
	client, err := management.NewClient(c.adminURL, c.tokens[who])
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func createEvent(t *testing.T, c *management.Client, id, name string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := c.Call(context.Background(), http.MethodPost, "/api/v1/events", nil,
		map[string]any{"event_id": id, "display_name": name}, &out); err != nil {
		t.Fatalf("create event: %v", err)
	}
	return out
}

func TestAuthAndRBAC(t *testing.T) {
	bc := startB4Center(t)
	client := clientFor(t, bc, "platform")
	createEvent(t, client, eventA, "Event A")
	createEvent(t, client, eventB, "Event B")

	// Missing/invalid Authorization is rejected before any service call.
	req, _ := http.NewRequest(http.MethodGet, bc.adminURL+"/api/v1/events", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing auth status=%d, want 401", resp.StatusCode)
	}
	// Admin API is absent from the ingest listener.
	req, _ = http.NewRequest(http.MethodGet, bc.ingest+"/api/v1/health", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("ingest listener served admin API: status=%d", resp.StatusCode)
	}
	// Agent endpoints are absent from the admin listener.
	req, _ = http.NewRequest(http.MethodPost, bc.adminURL+"/v1/agent/enroll", nil)
	req.Header.Set("Authorization", "Bearer "+"platform-token-0123456789abcdef")
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("admin listener served agent endpoint: status=%d", resp.StatusCode)
	}

	// A client-supplied role/event header cannot authorize.
	req, _ = http.NewRequest(http.MethodGet, bc.adminURL+"/api/v1/events", nil)
	req.Header.Set("X-Role", "platform_admin")
	req.Header.Set("X-Event-ID", eventA)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("header-only auth status=%d, want 401", resp.StatusCode)
	}

	eventAdminA := clientFor(t, bc, "admin-a")
	eventAdminB := clientFor(t, bc, "admin-b")
	viewerA := clientFor(t, bc, "viewer-a")

	// event_admin may create tokens and revoke/read nodes only in scope.
	var tok map[string]any
	if err := eventAdminA.Call(context.Background(), http.MethodPost, "/api/v1/events/"+eventA+"/tokens", nil,
		map[string]any{"node_class": "linux_vps", "ttl_seconds": 120}, &tok); err != nil {
		t.Fatalf("event_admin token create: %v", err)
	}
	if tok["token"] == nil || tok["token_id"] == nil {
		t.Fatalf("token create response missing one-time token: %+v", tok)
	}
	errScope := eventAdminA.Call(context.Background(), http.MethodGet, "/api/v1/events/"+eventB, nil, nil, &tok)
	var apiErr *management.APIError
	if !errors.As(errScope, &apiErr) || apiErr.Status != http.StatusNotFound {
		t.Fatalf("event_admin A read event B err=%v, want 404 scope miss", errScope)
	}
	// Viewer mutation is forbidden on a visible event.
	if err := viewerA.Call(context.Background(), http.MethodPost, "/api/v1/events/"+eventA+"/tokens", nil,
		map[string]any{"node_class": "linux_vps", "ttl_seconds": 120}, nil); err == nil {
		t.Fatal("viewer created enrollment token")
	}
	// event_admin cannot create/rename/archive events.
	if err := eventAdminA.Call(context.Background(), http.MethodPost, "/api/v1/events", nil,
		map[string]any{"display_name": "X"}, nil); err == nil {
		t.Fatal("event_admin created an event")
	}
	if err := eventAdminA.Call(context.Background(), http.MethodPatch, "/api/v1/events/"+eventA, nil,
		map[string]any{"display_name": "Renamed"}, nil); err == nil {
		t.Fatal("event_admin renamed an event")
	}
	// event_admin cannot write route mapping or agent config in this release.
	if err := eventAdminA.Call(context.Background(), http.MethodPost, "/api/v1/events/"+eventA+"/mapping/"+
		"33333333-3333-4333-8333-333333333333", nil,
		map[string]any{"version": 1, "effective_from": time.Now().Unix() + 60, "entries": []any{}}, nil); err == nil {
		t.Fatal("event_admin wrote route mapping")
	}
	// viewer cannot read audit.
	errAudit := viewerA.Call(context.Background(), http.MethodGet, "/api/v1/audit", nil, nil, &tok)
	if !errors.As(errAudit, &apiErr) || apiErr.Status != http.StatusForbidden {
		t.Fatalf("viewer read audit err=%v, want 403", errAudit)
	}
	// event_admin B cannot see event A.
	if err := eventAdminB.Call(context.Background(), http.MethodGet, "/api/v1/events/"+eventA, nil, nil, &tok); err == nil {
		t.Fatal("event_admin B read event A")
	}
}

func TestEventLifecycleAndAudit(t *testing.T) {
	bc := startB4Center(t)
	p := clientFor(t, bc, "platform")
	createEvent(t, p, eventA, "A")

	var list struct {
		Events []management.EventView `json:"events"`
	}
	if err := p.Call(context.Background(), http.MethodGet, "/api/v1/events", nil, nil, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Events) != 1 || list.Events[0].DisplayName != "A" {
		t.Fatalf("events=%+v", list.Events)
	}
	var ev management.EventView
	if err := p.Call(context.Background(), http.MethodPatch, "/api/v1/events/"+eventA, nil,
		map[string]any{"display_name": "A renamed"}, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.DisplayName != "A renamed" {
		t.Fatalf("rename=%+v", ev)
	}
	// Archive then ingest token creation must fail.
	if err := p.Call(context.Background(), http.MethodPost, "/api/v1/events/"+eventA+"/archive", nil, nil, &ev); err != nil {
		t.Fatal(err)
	}
	if err := p.Call(context.Background(), http.MethodPost, "/api/v1/events/"+eventA+"/tokens", nil,
		map[string]any{"node_class": "linux_vps", "ttl_seconds": 120}, nil); err == nil {
		t.Fatal("archived event accepted token creation")
	}
	// Audit must be scoped and recorded.
	var audit management.AuditList
	if err := p.Call(context.Background(), http.MethodGet, "/api/v1/audit", nil, nil, &audit); err != nil {
		t.Fatal(err)
	}
	if audit.Total == 0 {
		t.Fatal("no audit entries")
	}
	if err := p.Call(context.Background(), http.MethodGet, "/api/v1/audit/verify", nil, nil, &ev); err != nil {
		t.Fatalf("ledger verify: %v", err)
	}
	// Purge confirmation must be exact and bound to the id.
	var preview management.PurgePreviewView
	if err := p.Call(context.Background(), http.MethodGet, "/api/v1/events/"+eventA+"/purge/preview", nil, nil, &preview); err != nil {
		t.Fatal(err)
	}
	if preview.ConfirmPhrase != "purge:"+eventA {
		t.Fatalf("confirm phrase=%q", preview.ConfirmPhrase)
	}
	if err := p.Call(context.Background(), http.MethodPost, "/api/v1/events/"+eventA+"/purge/confirm", nil,
		map[string]any{"confirmation": "purge:" + eventB}, nil); err == nil {
		t.Fatal("cross-event purge confirmation accepted")
	}
	var status management.PurgeStatusView
	if err := p.Call(context.Background(), http.MethodPost, "/api/v1/events/"+eventA+"/purge/confirm", nil,
		map[string]any{"confirmation": "purge:" + eventA}, &status); err != nil {
		t.Fatalf("purge confirm: %v", err)
	}
	if !status.Graveyard {
		t.Fatalf("purge did not write graveyard: %+v", status)
	}
}

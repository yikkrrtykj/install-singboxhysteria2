package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/center"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/management"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/schema"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
)

func TestAdminCLIUsesManagementAPI(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "center.db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	schemas, err := schema.Load("../../../docs/um/contracts/v1")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := center.NewService(center.ServiceConfig{Store: st, Schemas: schemas})
	if err != nil {
		t.Fatal(err)
	}
	rawToken := "cli-platform-token-0123456789"
	sum := sha256.Sum256([]byte(rawToken))
	authDoc := management.AuthConfig{
		Principals: []management.AuthPrincipal{{ID: "cli-admin", Role: management.RolePlatformAdmin}},
		Tokens:     []management.AuthToken{{SHA256: hex.EncodeToString(sum[:]), PrincipalID: "cli-admin"}},
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
	mgmt, err := management.NewService(st)
	if err != nil {
		t.Fatal(err)
	}
	api, err := management.NewHandler(mgmt, auth)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := center.NewServer(center.Config{
		IngestAddr: "127.0.0.1:0", AdminAddr: "127.0.0.1:0", DBPath: db,
		ContractDir: "../../../docs/um/contracts/v1", RateLimitPerSecond: -1, AdminAPI: api,
	}, svc)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close(); _ = st.Close() })
	tokenPath := filepath.Join(dir, "admin.token")
	if err := os.WriteFile(tokenPath, []byte(rawToken), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tokenPath, 0o600); err != nil {
		t.Fatal(err)
	}
	eventID := "44444444-4444-4444-8444-444444444444"
	rc := runAdminCLI([]string{"--url", "http://" + srv.AdminAddr(),
		"--token-file", tokenPath, "--json",
		"event", "create", "--event-id", eventID, "--name", "CLI event"})
	if rc != 0 {
		t.Fatalf("CLI event create exit=%d", rc)
	}
	// Verify through the same service/API, not by reading SQLite.
	client, err := management.NewClient("http://"+srv.AdminAddr(), tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	var ev management.EventView
	if err := client.Call(context.Background(), "GET", "/api/v1/events/"+eventID, nil, nil, &ev); err != nil {
		t.Fatalf("read created event: %v", err)
	}
	if ev.DisplayName != "CLI event" {
		t.Fatalf("event display=%q", ev.DisplayName)
	}
	for _, args := range [][]string{
		{"--url", "http://" + srv.AdminAddr(), "--token-file", tokenPath, "--json", "event", "list"},
		{"--url", "http://" + srv.AdminAddr(), "--token-file", tokenPath, "--json", "event", "show", eventID},
		{"--url", "http://" + srv.AdminAddr(), "--token-file", tokenPath, "--json", "event", "rename", eventID, "--name", "CLI renamed"},
		{"--url", "http://" + srv.AdminAddr(), "--token-file", tokenPath, "--json", "retention", "state"},
		{"--url", "http://" + srv.AdminAddr(), "--token-file", tokenPath, "--json", "capacity"},
	} {
		if rc := runAdminCLI(args); rc != 0 {
			t.Fatalf("CLI %v exit=%d", args, rc)
		}
	}
	if err := client.Call(context.Background(), "GET", "/api/v1/events/"+eventID, nil, nil, &ev); err != nil || ev.DisplayName != "CLI renamed" {
		t.Fatalf("CLI rename readback display=%q err=%v", ev.DisplayName, err)
	}
	// A CLI failure must use a non-zero exit code and cannot be mistaken for success.
	if rc := runAdminCLI([]string{"--url", "http://" + srv.AdminAddr(),
		"--token-file", tokenPath, "event", "show", "55555555-5555-4555-8555-555555555555"}); rc == 0 {
		t.Fatal("CLI missing event exited 0")
	}
}

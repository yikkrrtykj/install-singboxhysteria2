package management_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/management"
)

func rawRequest(t *testing.T, method, url, token string, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

func TestAdminRequestValidationAndTokenPrivacy(t *testing.T) {
	bc := startB4Center(t)
	platform := clientFor(t, bc, "platform")
	createEvent(t, platform, eventA, "A")
	rawToken := "platform-token-0123456789abcdef"

	// Unknown JSON fields are rejected.
	status, _ := rawRequest(t, http.MethodPost, bc.adminURL+"/api/v1/events", rawToken,
		[]byte(`{"display_name":"x","extra":true}`))
	if status != http.StatusBadRequest {
		t.Fatalf("unknown field status=%d", status)
	}
	// Oversized/invalid page bounds are rejected.
	status, _ = rawRequest(t, http.MethodGet, bc.adminURL+"/api/v1/events?limit=101", rawToken, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("limit=101 status=%d", status)
	}
	status, _ = rawRequest(t, http.MethodGet, bc.adminURL+"/api/v1/events?offset=100001", rawToken, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("offset too large status=%d", status)
	}
	// A body above the documented 1 MiB cap is rejected, not silently truncated.
	oversized := append([]byte(`{"display_name":"x"}`), bytes.Repeat([]byte(" "), 1<<20)...)
	status, _ = rawRequest(t, http.MethodPost, bc.adminURL+"/api/v1/events", rawToken, oversized)
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status=%d, want 413", status)
	}
	// Wrong method is 405, not a silent fallback.
	status, _ = rawRequest(t, http.MethodDelete, bc.adminURL+"/api/v1/events", rawToken, nil)
	if status != http.StatusMethodNotAllowed {
		t.Fatalf("delete events status=%d", status)
	}

	// A duplicate event id is an expected conflict, not a storage 500.
	status, _ = rawRequest(t, http.MethodPost, bc.adminURL+"/api/v1/events", rawToken,
		[]byte(`{"event_id":"`+eventA+`","display_name":"duplicate"}`))
	if status != http.StatusConflict {
		t.Fatalf("duplicate event status=%d, want 409", status)
	}

	// Token plaintext exists only in the creation response.
	var created management.EnrollmentTokenCreated
	if err := platform.Call(context.Background(), http.MethodPost, "/api/v1/events/"+eventA+"/tokens", nil,
		map[string]any{"node_class": "linux_vps", "ttl_seconds": 120}, &created); err != nil {
		t.Fatal(err)
	}
	var list map[string]any
	if err := platform.Call(context.Background(), http.MethodGet, "/api/v1/events/"+eventA+"/tokens", nil, nil, &list); err != nil {
		t.Fatal(err)
	}
	listRaw, _ := json.Marshal(list)
	if strings.Contains(string(listRaw), created.Token) {
		t.Fatal("enrollment token plaintext appeared in token list")
	}
	var audit management.AuditList
	if err := platform.Call(context.Background(), http.MethodGet, "/api/v1/audit", nil, nil, &audit); err != nil {
		t.Fatal(err)
	}
	auditRaw, _ := json.Marshal(audit)
	if strings.Contains(string(auditRaw), created.Token) {
		t.Fatal("enrollment token plaintext appeared in audit")
	}
	if strings.Contains(string(auditRaw), "controller.secret") {
		t.Fatal("secret marker appeared in audit")
	}

	// The auth file itself must be access-protected.
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	if err := os.WriteFile(path, []byte(`{"principals":[],"tokens":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := management.LoadFileAuthenticator(path); err == nil {
		t.Fatal("incomplete/unprotected auth file accepted")
	}
}

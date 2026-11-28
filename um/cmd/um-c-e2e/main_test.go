package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/management"
)

func TestLabClockAdvancesStrictlyForward(t *testing.T) {
	clock := &labClock{}
	base := clock.Now()
	clock.Advance(45)
	advanced := clock.Now()
	if delta := advanced.Sub(base); delta < 45*time.Second || delta > 46*time.Minute {
		t.Fatalf("lab clock delta = %v, want >= 45s", delta)
	}
	clock.Advance(0)
}

func TestLabLocalAuthenticator(t *testing.T) {
	const token = "um-c-e2e-test-local-bearer"
	sum := sha256.Sum256([]byte(token))
	auth := &labLocalAuthenticator{tokenHash: hex.EncodeToString(sum[:])}

	okReq := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	okReq.Header.Set("Authorization", "Bearer "+token)
	p, err := auth.Authenticate(okReq)
	if err != nil {
		t.Fatalf("Authenticate(valid) error = %v", err)
	}
	if p.Role != management.RolePlatformAdmin {
		t.Fatalf("Authenticate(valid) role = %q, want platform_admin", p.Role)
	}

	badCases := []struct{ local, bearer string }{
		{"", ""},
		{"", "um-c-e2e-test-local-bearer-wrong"},
		{"Basic abc", "abc"},
	}
	for _, tc := range badCases {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
		if tc.local != "" {
			req.Header.Set("Authorization", tc.local)
		} else if tc.bearer != "" {
			req.Header.Set("Authorization", "Bearer "+tc.bearer)
		}
		if _, err := auth.Authenticate(req); err == nil {
			t.Fatalf("Authenticate(%q) succeeded, want unauthenticated", tc.local+tc.bearer)
		}
	}
}

func TestLabFixturesStateAndAdvance(t *testing.T) {
	fixtures := &labFixtures{
		clock: &labClock{}, localBearer: "lab-bearer", localAdminURL: "https://localhost:1",
		ownerUsername: "e2e-owner", ownerPassword: "synthetic",
		events: map[string]labEvent{"a": {ID: "a-id", Name: "E2E Event A"}},
	}

	stateRec := httptest.NewRecorder()
	fixtures.ServeHTTP(stateRec, httptest.NewRequest(http.MethodGet, "/__lab/state", nil))
	if stateRec.Code != http.StatusOK {
		t.Fatalf("state status = %d, want 200", stateRec.Code)
	}
	var state struct {
		Now      int64               `json:"now_unix"`
		Bearer   string              `json:"b4_local_bearer"`
		AdminURL string              `json:"b4_local_admin_url"`
		Platform map[string]string   `json:"platform_admin"`
		Events   map[string]labEvent `json:"events"`
	}
	if err := json.Unmarshal(stateRec.Body.Bytes(), &state); err != nil {
		t.Fatalf("state decode: %v", err)
	}
	if state.Bearer != "lab-bearer" || state.AdminURL != "https://localhost:1" {
		t.Fatalf("state bearer/admin url mismatch: %+v", state)
	}
	if state.Platform["username"] != "e2e-owner" || state.Events["a"].ID != "a-id" {
		t.Fatalf("state fixtures mismatch: %+v", state)
	}

	advanceRec := httptest.NewRecorder()
	advanceReq := httptest.NewRequest(http.MethodPost, "/__lab/advance", strings.NewReader(`{"seconds":90}`))
	fixtures.ServeHTTP(advanceRec, advanceReq)
	if advanceRec.Code != http.StatusOK {
		t.Fatalf("advance status = %d, want 200", advanceRec.Code)
	}
	var advanced struct {
		Now int64 `json:"now_unix"`
	}
	if err := json.Unmarshal(advanceRec.Body.Bytes(), &advanced); err != nil {
		t.Fatalf("advance decode: %v", err)
	}
	if advanced.Now < state.Now+90 {
		t.Fatalf("advanced now = %d, want >= %d", advanced.Now, state.Now+90)
	}

	for _, tc := range []struct{ method, path, body string }{
		{http.MethodPost, "/__lab/state", ""},
		{http.MethodGet, "/__lab/advance", ""},
		{http.MethodPost, "/__lab/advance", `{"seconds":-1}`},
		{http.MethodPost, "/__lab/advance", `{"seconds":999999}`},
		{http.MethodPost, "/__lab/advance", `{"unknown":1}`},
		{http.MethodGet, "/__lab/other", ""},
	} {
		rec := httptest.NewRecorder()
		fixtures.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
		if rec.Code == http.StatusOK {
			t.Fatalf("%s %s (%s) unexpectedly returned 200", tc.method, tc.path, tc.body)
		}
	}
}

func TestLoopbackOnlyListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback: %v", err)
	}
	defer ln.Close()
	if err := loopbackOnly(ln); err != nil {
		t.Fatalf("loopbackOnly(loopback) = %v, want nil", err)
	}
}

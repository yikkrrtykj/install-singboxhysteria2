package web_test

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/umcauth"
)

// TestUMCManagementMutationRevocationLinearization proves that a B4 mutation
// that passed the first authentication check cannot race a logout/revocation into
// an unauthorized state: the revocation waits for the in-flight mutation, and a
// new mutation after revocation is rejected. The barrier is deterministic and the
// backend is the real SQLite/B4 service.
func TestUMCManagementMutationRevocationLinearization(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	tw := newTestWebWithHook(t, func() {
		once.Do(func() {
			close(started)
			<-release
		})
	})
	now := time.Now()
	hash, _ := umcauth.HashPassword(tw.password, umcauth.DefaultPasswordParams())
	user, err := tw.store.BootstrapAuthUser(context.Background(), "recovery-admin", hash, now.Unix())
	if err != nil {
		t.Fatal(err)
	}
	eventA := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	if _, err := tw.store.CreateEvent(context.Background(), eventA, "A", now.Unix()); err != nil {
		t.Fatal(err)
	}
	secret, _ := umcauth.NewTOTPSecret()
	sealed, _ := umcauth.Seal(tw.master, []byte(secret), []byte("umc-totp:"+user.UserID+":v1"))
	if err := tw.store.SetAuthUserTOTP(context.Background(), user.UserID, sealed, 1, now.Unix()); err != nil {
		t.Fatal(err)
	}
	pre := tw.startContext(t)
	status, raw := tw.request(t, http.MethodPost, "/auth/login", pre,
		map[string]any{"username": "recovery-admin", "password": tw.password}, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("login status=%d body=%s", status, raw)
	}
	pending, _ := decodeMap(t, raw)["csrf_token"].(string)
	code, _ := umcauth.TOTPCode(secret, *tw.clock)
	status, raw = tw.request(t, http.MethodPost, "/auth/totp", pending, map[string]any{"code": code}, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("TOTP status=%d body=%s", status, raw)
	}
	csrf, _ := decodeMap(t, raw)["csrf_token"].(string)
	if csrf == "" {
		t.Fatal("missing active CSRF token")
	}

	mutationDone := make(chan int, 1)
	go func() {
		status, _ := tw.request(t, http.MethodPost, "/api/v1/events", csrf,
			map[string]any{"event_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "display_name": "B"}, tw.jwt)
		mutationDone <- status
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("B4 mutation did not reach deterministic barrier")
	}
	logoutDone := make(chan int, 1)
	go func() {
		status, _ := tw.request(t, http.MethodPost, "/auth/logout", csrf, nil, tw.jwt)
		logoutDone <- status
	}()
	select {
	case status := <-logoutDone:
		t.Fatalf("logout did not wait for in-flight mutation, status=%d", status)
	case <-time.After(150 * time.Millisecond):
		// Expected: logout is blocked on the account write gate.
	}
	close(release)
	select {
	case status := <-mutationDone:
		if status != http.StatusCreated {
			t.Fatalf("in-flight B4 mutation status=%d, want 201", status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("B4 mutation did not finish after barrier release")
	}
	select {
	case status := <-logoutDone:
		if status != http.StatusNoContent {
			t.Fatalf("logout after in-flight mutation status=%d, want 204", status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("logout did not finish after mutation")
	}
	status, _ = tw.request(t, http.MethodPost, "/api/v1/events", csrf,
		map[string]any{"event_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "display_name": "C"}, tw.jwt)
	if status != http.StatusUnauthorized {
		t.Fatalf("B4 mutation after revocation status=%d, want 401", status)
	}
}

package web_test

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/umcauth"
)

// TestUMCCredentialEpochPasswordResetRace deterministically pauses a login after
// Argon2id verification, commits a concurrent password reset, and proves no
// pending/setup/active session can be created from the stale verification.
func TestUMCCredentialEpochPasswordResetRace(t *testing.T) {
	for _, bound := range []bool{false, true} {
		name := "unbound_totp"
		if bound {
			name = "bound_totp"
		}
		t.Run(name, func(t *testing.T) {
			started := make(chan struct{})
			release := make(chan struct{})
			var once sync.Once
			tw := newTestWebWithPasswordHook(t, func() {
				once.Do(func() {
					close(started)
					<-release
				})
			})
			now := time.Now()
			hash, _ := umcauth.HashPassword(tw.password, umcauth.DefaultPasswordParams())
			user, err := tw.store.BootstrapAuthUser(context.Background(), "race-admin", hash, now.Unix())
			if err != nil {
				t.Fatal(err)
			}
			if bound {
				secret, _ := umcauth.NewTOTPSecret()
				sealed, _ := umcauth.Seal(tw.master, []byte(secret), []byte("umc-totp:"+user.UserID+":v1"))
				if err := tw.store.SetAuthUserTOTP(context.Background(), user.UserID, sealed, 1, now.Unix()); err != nil {
					t.Fatal(err)
				}
			}
			pre := tw.startContext(t)
			type result struct {
				status int
				body   []byte
			}
			done := make(chan result, 1)
			go func() {
				status, raw := tw.request(t, http.MethodPost, "/auth/login", pre,
					map[string]any{"username": "race-admin", "password": tw.password}, tw.jwt)
				done <- result{status: status, body: raw}
			}()
			select {
			case <-started:
			case <-time.After(10 * time.Second):
				t.Fatal("login did not reach after-password-verify barrier")
			}
			// The reset commits while the stale Argon2id result is held at the
			// barrier. It advances the account credential epoch and revokes any
			// existing sessions.
			if err := tw.store.SetAuthUserPassword(context.Background(), user.UserID, hash, time.Now().Unix()+1); err != nil {
				t.Fatal(err)
			}
			close(release)
			var got result
			select {
			case got = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("login did not finish after reset")
			}
			if got.status != http.StatusUnauthorized {
				t.Fatalf("stale login status=%d body=%s, want 401", got.status, got.body)
			}
			sessions, err := tw.store.ListUserSessions(context.Background(), user.UserID)
			if err != nil {
				t.Fatal(err)
			}
			if len(sessions) != 0 {
				t.Fatalf("stale password verification created %d session(s)", len(sessions))
			}
		})
	}
}

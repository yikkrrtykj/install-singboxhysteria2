package web_test

import (
	"context"
	"database/sql"
	"net/http"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/umcauth"
)

// TestUMCLogoutDatabaseFaultIsNotReportedAsSuccess holds a real SQLite write lock
// to force the atomic revoke+audit transaction to fail. Logout must return a bounded
// 503, keep the session valid, and only report 204 after a real retry succeeds.
func TestUMCLogoutDatabaseFaultIsNotReportedAsSuccess(t *testing.T) {
	tw := newTestWeb(t)
	now := time.Now()
	hash, _ := umcauth.HashPassword(tw.password, umcauth.DefaultPasswordParams())
	user, err := tw.store.BootstrapAuthUser(context.Background(), "logout-fault-admin", hash, now.Unix())
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := umcauth.NewTOTPSecret()
	sealed, _ := umcauth.Seal(tw.master, []byte(secret), []byte("umc-totp:"+user.UserID+":v1"))
	if err := tw.store.SetAuthUserTOTP(context.Background(), user.UserID, sealed, 1, now.Unix()); err != nil {
		t.Fatal(err)
	}
	pre := tw.startContext(t)
	status, raw := tw.request(t, http.MethodPost, "/auth/login", pre,
		map[string]any{"username": "logout-fault-admin", "password": tw.password}, tw.jwt)
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

	rawDB, err := sql.Open("sqlite", "file:"+tw.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer rawDB.Close()
	rawDB.SetMaxOpenConns(1)
	lockConn, err := rawDB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockConn.ExecContext(context.Background(), `BEGIN IMMEDIATE`); err != nil {
		t.Fatal(err)
	}
	locked := true
	defer func() {
		if locked {
			_, _ = lockConn.ExecContext(context.Background(), `ROLLBACK`)
		}
		_ = lockConn.Close()
	}()

	// Other authenticated mutations must also distinguish an auth-state outage
	// from a false 401.
	status, raw = tw.request(t, http.MethodPost, "/auth/password", csrf,
		map[string]any{"current_password": tw.password, "new_password": "Another-Password-2026!"}, tw.jwt)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("password under DB fault status=%d body=%s, want 503", status, raw)
	}
	status, raw = tw.request(t, http.MethodPost, "/auth/logout", csrf, nil, tw.jwt)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("logout under DB fault status=%d body=%s, want 503", status, raw)
	}
	status, _ = tw.request(t, http.MethodGet, "/auth/me", "", nil, tw.jwt)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("me under DB fault status=%d, want 503", status)
	}
	if _, err := lockConn.ExecContext(context.Background(), `ROLLBACK`); err != nil {
		t.Fatal(err)
	}
	locked = false
	status, raw = tw.request(t, http.MethodPost, "/auth/logout", csrf, nil, tw.jwt)
	if status != http.StatusNoContent {
		t.Fatalf("logout retry status=%d body=%s, want 204", status, raw)
	}
	status, _ = tw.request(t, http.MethodGet, "/auth/me", "", nil, tw.jwt)
	if status != http.StatusUnauthorized {
		t.Fatalf("session still valid after successful retry status=%d", status)
	}
}

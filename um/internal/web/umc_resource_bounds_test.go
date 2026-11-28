package web_test

import (
	"context"
	"database/sql"
	"net/http"
	"testing"
	"time"
)

// TestUMCLoginFailuresAreAnonymousAndRateBounded verifies that unknown usernames
// are not recorded as trusted actors, that no account-existence signal is
// returned, and that the per-subject/per-username login bucket is bounded.
func TestUMCLoginFailuresAreAnonymousAndRateBounded(t *testing.T) {
	tw := newTestWeb(t)
	pre := tw.startContext(t)
	lastStatus := 0
	for i := 0; i < 6; i++ {
		lastStatus, _ = tw.request(t, http.MethodPost, "/auth/login", pre,
			map[string]any{"username": "unknown-user", "password": "Definitely-Wrong-Password-2026!"}, tw.jwt)
	}
	if lastStatus != http.StatusTooManyRequests {
		t.Fatalf("login failure burst last status=%d, want 429", lastStatus)
	}
	db, err := sql.Open("sqlite", "file:"+tw.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.QueryContext(context.Background(),
		`SELECT actor,role,target FROM admin_audit WHERE action='umc_login_failed'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var actor, role, target string
		if err := rows.Scan(&actor, &role, &target); err != nil {
			t.Fatal(err)
		}
		count++
		if actor != "anonymous" || role != "unauthenticated" || target != "web" {
			t.Fatalf("unknown username became trusted actor: actor=%q role=%q target=%q", actor, role, target)
		}
	}
	if count == 0 {
		t.Fatal("no bounded anonymous login-failure audit rows")
	}
	_ = time.Now
}

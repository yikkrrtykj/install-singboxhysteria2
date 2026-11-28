package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/fileguard"
)

func TestUMCAuthAccountsSessionsTOTPRecovery(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := context.Background()
	now := int64(1_900_000_000)
	hash := "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	admin, err := s.BootstrapAuthUser(ctx, "root-admin", hash, now)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if admin.Role != AuthRolePlatformAdmin || !admin.Enabled {
		t.Fatalf("bootstrap user=%+v", admin)
	}
	if _, err := s.BootstrapAuthUser(ctx, "second-admin", hash, now+1); !errors.Is(err, ErrAuthAlreadyBootstrapped) {
		t.Fatalf("second bootstrap err=%v", err)
	}
	if _, err := s.GetAuthUserByUsername(ctx, "ROOT-ADMIN"); err != nil {
		t.Fatalf("case-insensitive username: %v", err)
	}

	eventA := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	eventB := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	if _, err := s.CreateEvent(ctx, eventA, "A", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateEvent(ctx, eventB, "B", now); err != nil {
		t.Fatal(err)
	}
	ea, err := s.CreateAuthUser(ctx, AuthUserInput{Username: "event-a", PasswordHash: hash,
		Role: AuthRoleEventAdmin, EventIDs: []string{eventA}, Now: now})
	if err != nil {
		t.Fatalf("create event admin: %v", err)
	}
	if len(ea.EventIDs) != 1 || ea.EventIDs[0] != eventA {
		t.Fatalf("scopes=%v", ea.EventIDs)
	}
	if _, err := s.CreateAuthUser(ctx, AuthUserInput{Username: "viewer", PasswordHash: hash,
		Role: AuthRoleViewer, EventIDs: []string{eventB}, Now: now}); err != nil {
		t.Fatal(err)
	}

	// Last-enabled-platform-admin protection applies to disable and role change.
	if err := s.SetAuthUserEnabled(ctx, admin.UserID, false, now+2); !errors.Is(err, ErrAuthLastPlatformAdmin) {
		t.Fatalf("disable last admin err=%v", err)
	}
	if err := s.SetAuthUserRoleAndScopes(ctx, admin.UserID, AuthRoleViewer, []string{eventA}, now+2); !errors.Is(err, ErrAuthLastPlatformAdmin) {
		t.Fatalf("demote last admin err=%v", err)
	}
	admin2, err := s.CreateAuthUser(ctx, AuthUserInput{Username: "second-admin", PasswordHash: hash,
		Role: AuthRolePlatformAdmin, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetAuthUserEnabled(ctx, admin.UserID, false, now+3); err != nil {
		t.Fatalf("disable after second admin: %v", err)
	}
	if err := s.SetAuthUserEnabled(ctx, admin2.UserID, false, now+4); !errors.Is(err, ErrAuthLastPlatformAdmin) {
		t.Fatalf("disable remaining admin err=%v", err)
	}

	// Session + CSRF storage, subject binding, rotation and revocation.
	sess := AuthSession{IDHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", PublicID: "public-session-1",
		UserID: ea.UserID, State: AuthSessionActive, AccessSubject: "subject-1", AccessIssuer: "https://access.example",
		CSRFHash:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now + 1800, AbsoluteExpiresAt: now + 43200}
	if err := s.CreateSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetSession(ctx, sess.IDHash); err != nil || got.AccessSubject != "subject-1" {
		t.Fatalf("get session=%+v err=%v", got, err)
	}
	next := sess
	next.IDHash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	next.PublicID = "public-session-2"
	next.CSRFHash = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	if err := s.RotateSession(ctx, sess.IDHash, next, now+1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, sess.IDHash); err != nil && !errors.Is(err, ErrAuthSessionUnknown) {
		t.Fatal(err)
	}
	if got, err := s.GetSession(ctx, next.IDHash); err != nil || got.RevokedAt != nil {
		t.Fatalf("rotated session=%+v err=%v", got, err)
	}
	// Scope change must revoke all sessions.
	if err := s.SetAuthUserRoleAndScopes(ctx, ea.UserID, AuthRoleEventAdmin, []string{eventB}, now+2); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSession(ctx, next.IDHash)
	if err != nil || got.RevokedAt == nil {
		t.Fatalf("scope change did not revoke session: %+v err=%v", got, err)
	}

	// TOTP counters are persistent and single-use.
	if err := s.SetAuthUserTOTP(ctx, ea.UserID, []byte("sealed-secret"), 1, now+3); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeTOTPCounter(ctx, ea.UserID, 12345, now+4); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeTOTPCounter(ctx, ea.UserID, 12345, now+5); !errors.Is(err, ErrAuthTOTPReplayed) {
		t.Fatalf("TOTP replay err=%v", err)
	}

	// Recovery codes are single-use and re-enrollment required after consumption.
	hashes := []string{
		"1111111111111111111111111111111111111111111111111111111111111111",
		"2222222222222222222222222222222222222222222222222222222222222222",
	}
	if err := s.ReplaceRecoveryCodes(ctx, ea.UserID, hashes, now+6); err != nil {
		t.Fatal(err)
	}
	if total, unused, err := s.CountRecoveryCodes(ctx, ea.UserID); err != nil || total != 2 || unused != 2 {
		t.Fatalf("recovery count=%d/%d err=%v", total, unused, err)
	}
	if err := s.ConsumeRecoveryCode(ctx, ea.UserID, hashes[0], now+7); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeRecoveryCode(ctx, ea.UserID, hashes[0], now+8); !errors.Is(err, ErrAuthRecoveryUsed) {
		t.Fatalf("recovery replay err=%v", err)
	}
	if _, _, err := s.CountRecoveryCodes(ctx, ea.UserID); err != nil {
		t.Fatal(err)
	}

	// Preauth state is separate from real sessions.
	pre := AuthPreauth{TokenHash: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		AccessSubject: "subject-1", AccessIssuer: "https://access.example",
		CSRFHash:  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		CreatedAt: now, ExpiresAt: now + 300}
	if err := s.CreatePreauth(ctx, pre); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetPreauth(ctx, pre.TokenHash); err != nil || got.AccessSubject != "subject-1" {
		t.Fatalf("preauth=%+v err=%v", got, err)
	}
	if err := s.DeletePreauth(ctx, pre.TokenHash); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetPreauth(ctx, pre.TokenHash); !errors.Is(err, ErrAuthSessionUnknown) {
		t.Fatalf("deleted preauth err=%v", err)
	}
}

func TestUMCAuthConcurrentTOTPReplay(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := context.Background()
	now := int64(1_900_100_000)
	hash := "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := s.BootstrapAuthUser(ctx, "concurrent-admin", hash, now); err != nil {
		t.Fatal(err)
	}
	user, err := s.GetAuthUserByUsername(ctx, "concurrent-admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetAuthUserTOTP(ctx, user.UserID, []byte("sealed"), 1, now); err != nil {
		t.Fatal(err)
	}
	const workers = 8
	var wg sync.WaitGroup
	results := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- s.ConsumeTOTPCounter(ctx, user.UserID, 424242, now+1)
		}()
	}
	wg.Wait()
	close(results)
	success, replay := 0, 0
	for err := range results {
		switch {
		case err == nil:
			success++
		case errors.Is(err, ErrAuthTOTPReplayed):
			replay++
		default:
			t.Fatalf("unexpected concurrent TOTP result: %v", err)
		}
	}
	if success != 1 || replay != workers-1 {
		t.Fatalf("concurrent TOTP success=%d replay=%d", success, replay)
	}
}

func TestUMCAuthConcurrentTOTPSetupIsAtomic(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := context.Background()
	now := int64(1_900_200_000)
	hash := "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	user, err := s.BootstrapAuthUser(ctx, "setup-admin", hash, now)
	if err != nil {
		t.Fatal(err)
	}
	old := AuthSession{IDHash: "1111111111111111111111111111111111111111111111111111111111111111",
		PublicID: "setup-old", UserID: user.UserID, State: AuthSessionTOTPSetup,
		AccessSubject: "subject", AccessIssuer: "issuer", CSRFHash: "2222222222222222222222222222222222222222222222222222222222222222",
		CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now + 600, AbsoluteExpiresAt: now + 3600,
		AuthEpoch: user.AuthEpoch}
	if err := s.CreateSession(ctx, old); err != nil {
		t.Fatal(err)
	}
	hashes := []string{"3333333333333333333333333333333333333333333333333333333333333333"}
	const workers = 6
	var wg sync.WaitGroup
	results := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			next := AuthSession{IDHash: fmt.Sprintf("%064d", i+1), PublicID: fmt.Sprintf("setup-next-%d", i),
				UserID: user.UserID, State: AuthSessionActive, AccessSubject: "subject", AccessIssuer: "issuer",
				CSRFHash:  "4444444444444444444444444444444444444444444444444444444444444444",
				CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now + 600, AbsoluteExpiresAt: now + 3600}
			results <- s.CompleteTOTPSetup(ctx, user.UserID, user.AuthEpoch, []byte("sealed"), 1, 777, hashes, old.IDHash, next, now+1)
		}(i)
	}
	wg.Wait()
	close(results)
	success, replay := 0, 0
	for err := range results {
		switch {
		case err == nil:
			success++
		case errors.Is(err, ErrAuthTOTPReplayed), errors.Is(err, ErrAuthSessionUnknown), errors.Is(err, ErrAuthStale):
			replay++
		default:
			t.Fatalf("unexpected setup result: %v", err)
		}
	}
	if success != 1 || replay != workers-1 {
		t.Fatalf("atomic setup success=%d replay=%d", success, replay)
	}
}

func TestUMCAuthCleanupBoundedExpiredState(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := context.Background()
	now := int64(1_900_300_000)
	hash := "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	user, err := s.BootstrapAuthUser(ctx, "cleanup-admin", hash, now)
	if err != nil {
		t.Fatal(err)
	}
	pre := AuthPreauth{TokenHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		AccessSubject: "s", AccessIssuer: "i", CSRFHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		CreatedAt: now - 600, ExpiresAt: now - 1}
	if err := s.CreatePreauth(ctx, pre); err != nil {
		t.Fatal(err)
	}
	sess := AuthSession{IDHash: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		PublicID: "cleanup-session", UserID: user.UserID, State: AuthSessionActive,
		AccessSubject: "s", AccessIssuer: "i", CSRFHash: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		CreatedAt: now - 1000, LastSeenAt: now - 1000, IdleExpiresAt: now - 500, AbsoluteExpiresAt: now - 1}
	if err := s.CreateSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CleanupAuthState(ctx, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetPreauth(ctx, pre.TokenHash); !errors.Is(err, ErrAuthSessionUnknown) {
		t.Fatalf("expired preauth survived cleanup: %v", err)
	}
	if _, err := s.GetSession(ctx, sess.IDHash); !errors.Is(err, ErrAuthSessionUnknown) {
		t.Fatalf("expired session survived cleanup: %v", err)
	}
}

func TestUMCAuthMutationAuditFailureRollsBack(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := context.Background()
	now := int64(1_900_400_000)
	oldHash := "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	newHash := "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err := s.BootstrapAuthUser(ctx, "audit-atomic", oldHash, now); err != nil {
		t.Fatal(err)
	}
	user, err := s.GetAuthUserByUsername(ctx, "audit-atomic")
	if err != nil {
		t.Fatal(err)
	}
	// An incomplete ledger mutation metadata makes the audit/ledger append fail;
	// the password update must roll back atomically instead of committing unaudited.
	badCtx := WithAuthMutation(ctx, AuthMutationMeta{
		Audit:      AuditMeta{Actor: "test", Role: AuthRolePlatformAdmin, Action: "test", Target: "user:" + user.UserID},
		LedgerKind: "test_mutation",
	})
	if err := s.SetAuthUserPassword(badCtx, user.UserID, newHash, now+1); err == nil {
		t.Fatal("SetAuthUserPassword with incomplete ledger metadata unexpectedly succeeded")
	}
	got, err := s.GetAuthUserByID(ctx, user.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if got.PasswordHash != oldHash {
		t.Fatal("password change was not rolled back on audit/ledger failure")
	}
}

func TestUMCAuthCredentialEpochStaleSessionCreate(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := context.Background()
	now := int64(1_900_500_000)
	hash := "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	user, err := s.BootstrapAuthUser(ctx, "epoch-admin", hash, now)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a completed KDF verification against epoch 0, then a concurrent
	// password reset commits before the session is created.
	if user.AuthEpoch != 0 {
		t.Fatalf("fresh account epoch=%d", user.AuthEpoch)
	}
	if err := s.SetAuthUserPassword(ctx, user.UserID, hash+"x", now+1); err != nil {
		t.Fatal(err)
	}
	stale := AuthSession{IDHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PublicID: "stale-pending", UserID: user.UserID, State: AuthSessionTOTPPending,
		AccessSubject: "subject", AccessIssuer: "issuer",
		CSRFHash:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now + 600, AbsoluteExpiresAt: now + 3600,
		AuthEpoch: user.AuthEpoch}
	if err := s.CreateSession(ctx, stale); !errors.Is(err, ErrAuthStale) {
		t.Fatalf("stale session create error=%v, want ErrAuthStale", err)
	}
	got, err := s.GetAuthUserByID(ctx, user.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if got.AuthEpoch != 1 {
		t.Fatalf("password reset epoch=%d, want 1", got.AuthEpoch)
	}
	stale.AuthEpoch = got.AuthEpoch
	stale.PublicID = "fresh-pending"
	stale.IDHash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if err := s.CreateSession(ctx, stale); err != nil {
		t.Fatalf("current-epoch session create: %v", err)
	}
}

func TestUMCAuthSecurityMutationsAdvanceEpoch(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := context.Background()
	now := int64(1_900_600_000)
	hash := "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	user, err := s.BootstrapAuthUser(ctx, "epoch-mutations", hash, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAuthUser(ctx, AuthUserInput{Username: "epoch-admin-2", PasswordHash: hash,
		Role: AuthRolePlatformAdmin, Now: now}); err != nil {
		t.Fatal(err)
	}
	eventID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	if _, err := s.CreateEvent(ctx, eventID, "Epoch", now); err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		name string
		fn   func() error
	}{
		{"role/scope", func() error {
			return s.SetAuthUserRoleAndScopes(ctx, user.UserID, AuthRoleEventAdmin, []string{eventID}, now+1)
		}},
		{"password", func() error { return s.SetAuthUserPassword(ctx, user.UserID, hash, now+2) }},
		{"totp", func() error { return s.SetAuthUserTOTP(ctx, user.UserID, []byte("sealed"), 1, now+3) }},
		{"disable", func() error { return s.SetAuthUserEnabled(ctx, user.UserID, false, now+4) }},
		{"enable", func() error { return s.SetAuthUserEnabled(ctx, user.UserID, true, now+5) }},
	}
	for i, step := range steps {
		if err := step.fn(); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		got, err := s.GetAuthUserByID(ctx, user.UserID)
		if err != nil {
			t.Fatal(err)
		}
		if got.AuthEpoch != int64(i+1) {
			t.Fatalf("%s epoch=%d, want %d", step.name, got.AuthEpoch, i+1)
		}
	}
}

func TestUMCAuthTOTPHighWaterSurvivesCounterCleanupAndRestart(t *testing.T) {
	path := tempStorePath(t)
	s := openTestStore(t, path)
	ctx := context.Background()
	now := int64(1_900_700_000)
	hash := "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	user, err := s.BootstrapAuthUser(ctx, "highwater-admin", hash, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetAuthUserTOTP(ctx, user.UserID, []byte("sealed"), 1, now); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeTOTPCounter(ctx, user.UserID, 100, now+1); err != nil {
		t.Fatal(err)
	}
	// Simulate the bounded cleanup deleting the consumed row. The persistent
	// high-water must still reject an old/replayed counter.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM umc_totp_counters WHERE user_id=?`, user.UserID); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeTOTPCounter(ctx, user.UserID, 50, now+2); !errors.Is(err, ErrAuthTOTPReplayed) {
		t.Fatalf("old counter after cleanup error=%v, want replay", err)
	}
	if err := s.ConsumeTOTPCounter(ctx, user.UserID, 101, now+3); err != nil {
		t.Fatalf("newer counter after cleanup: %v", err)
	}
	_ = s.Close()
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.ConsumeTOTPCounter(ctx, user.UserID, 50, now+4); !errors.Is(err, ErrAuthTOTPReplayed) {
		t.Fatalf("restart replay error=%v, want replay", err)
	}
	if err := reopened.ConsumeTOTPCounter(ctx, user.UserID, 102, now+5); err != nil {
		t.Fatalf("restart newer counter: %v", err)
	}
	// Installing a new secret generation resets the high-water.
	if err := reopened.SetAuthUserTOTP(ctx, user.UserID, []byte("sealed2"), 1, now+6); err != nil {
		t.Fatal(err)
	}
	if err := reopened.ConsumeTOTPCounter(ctx, user.UserID, 50, now+7); err != nil {
		t.Fatalf("new secret generation counter: %v", err)
	}
}

func TestUMCStoreFilesPrivate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "center.db")
	s := openTestStore(t, path)
	defer s.Close()
	if err := fileguard.CheckPrivateDir(filepath.Dir(path)); err != nil {
		t.Fatalf("database parent directory is not private: %v", err)
	}
	if err := fileguard.CheckPrivateFile(path); err != nil {
		t.Fatalf("database file is not private: %v", err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(path + suffix); err == nil {
			if err := fileguard.CheckPrivateFile(path + suffix); err != nil {
				t.Fatalf("database %s is not private: %v", suffix, err)
			}
		}
	}
}

func TestUMCAuthLockoutAdminUnlockPaths(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := context.Background()
	now := int64(1_901_000_000)
	hash := "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	user, err := s.BootstrapAuthUser(ctx, "lockout-unlock", hash, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAuthUser(ctx, AuthUserInput{Username: "lockout-unlock-2", PasswordHash: hash,
		Role: AuthRolePlatformAdmin, Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAuthUserTOTP(ctx, user.UserID, []byte("sealed"), 1, now); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := s.RecordTOTPFailure(ctx, user.UserID, now+int64(i), 5, 900); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := s.GetAuthUserByID(ctx, user.UserID)
	if got.TOTPLockedUntil == nil {
		t.Fatal("account did not lock")
	}
	if err := s.SetAuthUserPassword(ctx, user.UserID, hash, now+10); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetAuthUserByID(ctx, user.UserID)
	if got.TOTPLockedUntil != nil || got.TOTPFailedAttempts != 0 {
		t.Fatalf("password reset did not clear lock: %+v", got)
	}
	// Lock again, then enable clears it.
	for i := 0; i < 5; i++ {
		if _, err := s.RecordTOTPFailure(ctx, user.UserID, now+20+int64(i), 5, 900); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetAuthUserEnabled(ctx, user.UserID, false, now+30); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAuthUserEnabled(ctx, user.UserID, true, now+31); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetAuthUserByID(ctx, user.UserID)
	if got.TOTPLockedUntil != nil || got.TOTPFailedAttempts != 0 {
		t.Fatalf("enable did not clear lock: %+v", got)
	}
}

func TestUMCAuthRecoverySetupFailureRollsBackConsumption(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := context.Background()
	now := int64(1_901_100_000)
	hash := "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	user, err := s.BootstrapAuthUser(ctx, "recovery-rollback", hash, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetAuthUserTOTP(ctx, user.UserID, []byte("old-sealed"), 1, now); err != nil {
		t.Fatal(err)
	}
	hashes := []string{
		"1111111111111111111111111111111111111111111111111111111111111111",
		"2222222222222222222222222222222222222222222222222222222222222222",
	}
	if err := s.ReplaceRecoveryCodes(ctx, user.UserID, hashes, now+1); err != nil {
		t.Fatal(err)
	}
	// A pre-existing session with the public id we deliberately collide on makes
	// the final session insert fail after the code/security updates in the tx.
	user, _ = s.GetAuthUserByID(ctx, user.UserID)
	old := AuthSession{IDHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PublicID: "recovery-collision", UserID: user.UserID, State: AuthSessionActive,
		AccessSubject: "s", AccessIssuer: "i", CSRFHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now + 600, AbsoluteExpiresAt: now + 3600,
		AuthEpoch: user.AuthEpoch}
	if err := s.CreateSession(ctx, old); err != nil {
		t.Fatal(err)
	}
	user, _ = s.GetAuthUserByID(ctx, user.UserID)
	next := AuthSession{IDHash: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		PublicID: "recovery-collision", UserID: user.UserID, State: AuthSessionTOTPSetup,
		AccessSubject: "s", AccessIssuer: "i", CSRFHash: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now + 600, AbsoluteExpiresAt: now + 3600,
		AuthEpoch: user.AuthEpoch + 1}
	err = s.ConsumeRecoveryCodeAndStartSetup(ctx, user.UserID, user.AuthEpoch, hashes[0], []byte("new-sealed"), next, now+2)
	if err == nil {
		t.Fatal("recovery setup collision unexpectedly succeeded")
	}
	reloaded, err := s.GetAuthUserByID(ctx, user.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.TOTPSecret) == 0 || reloaded.AuthEpoch != user.AuthEpoch {
		t.Fatalf("recovery rollback changed account state: %+v", reloaded)
	}
	total, unused, err := s.CountRecoveryCodes(ctx, user.UserID)
	if err != nil || total != 2 || unused != 2 {
		t.Fatalf("recovery rollback codes=%d/%d err=%v", total, unused, err)
	}
}

func TestUMCAuthV12DatabaseUpgradesToEpochSchema(t *testing.T) {
	path := tempStorePath(t)
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, m := range migrations {
		if m.version > 12 {
			break
		}
		for _, stmt := range m.statements {
			if _, err := raw.ExecContext(ctx, stmt); err != nil {
				t.Fatalf("apply v%d: %v", m.version, err)
			}
		}
	}
	if _, err := raw.ExecContext(ctx, `CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES(12, 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, `INSERT INTO umc_users(user_id,username,password_hash,role,enabled,created_at,updated_at)
		VALUES('u-v12','v12-admin','$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','platform_admin',1,1,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, `INSERT INTO umc_sessions(session_id_hash,public_id,user_id,state,access_subject,access_issuer,csrf_hash,created_at,last_seen_at,idle_expires_at,absolute_expires_at)
		VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','v12-session','u-v12','authenticated','s','i','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',1,1,100,200)`); err != nil {
		t.Fatal(err)
	}
	_ = raw.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatalf("v12 upgrade: %v", err)
	}
	defer s.Close()
	user, err := s.GetAuthUserByID(ctx, "u-v12")
	if err != nil || user.AuthEpoch != 0 {
		t.Fatalf("upgraded user epoch=%d err=%v", user.AuthEpoch, err)
	}
	sess, err := s.GetSession(ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil || sess.AuthEpoch != 0 {
		t.Fatalf("upgraded session epoch=%d err=%v", sess.AuthEpoch, err)
	}
	if _, err := s.GetAuthMeta(ctx, "missing"); !errors.Is(err, ErrAuthMetaNotFound) {
		t.Fatalf("upgraded meta table error=%v", err)
	}
}

func TestUMCAuthCompleteLoginChecksHighWater(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := context.Background()
	now := int64(1_901_200_000)
	hash := "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	user, err := s.BootstrapAuthUser(ctx, "login-highwater", hash, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetAuthUserTOTP(ctx, user.UserID, []byte("sealed"), 1, now); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeTOTPCounter(ctx, user.UserID, 100, now+1); err != nil {
		t.Fatal(err)
	}
	user, _ = s.GetAuthUserByID(ctx, user.UserID)
	pending := AuthSession{IDHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PublicID: "pending-highwater", UserID: user.UserID, State: AuthSessionTOTPPending,
		AccessSubject: "s", AccessIssuer: "i", CSRFHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now + 600, AbsoluteExpiresAt: now + 3600,
		AuthEpoch: user.AuthEpoch}
	if err := s.CreateSession(ctx, pending); err != nil {
		t.Fatal(err)
	}
	next := AuthSession{IDHash: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		PublicID: "next-highwater", UserID: user.UserID, State: AuthSessionActive,
		AccessSubject: "s", AccessIssuer: "i", CSRFHash: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now + 600, AbsoluteExpiresAt: now + 3600,
		AuthEpoch: user.AuthEpoch}
	if err := s.CompleteTOTPLogin(ctx, user.UserID, user.AuthEpoch, 50, pending.IDHash, next, now+2); !errors.Is(err, ErrAuthTOTPReplayed) {
		t.Fatalf("lower counter error=%v, want replay", err)
	}
	if err := s.CompleteTOTPLogin(ctx, user.UserID, user.AuthEpoch, 101, pending.IDHash, next, now+3); err != nil {
		t.Fatalf("newer counter: %v", err)
	}
}

func TestUMCAuthPerUserActiveSessionCap(t *testing.T) {
	s := openTestStore(t, tempStorePath(t))
	ctx := context.Background()
	now := int64(1_901_300_000)
	hash := "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	user, err := s.BootstrapAuthUser(ctx, "session-cap", hash, now)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 32; i++ {
		sess := AuthSession{IDHash: fmt.Sprintf("%064d", i+1), PublicID: fmt.Sprintf("cap-%d", i),
			UserID: user.UserID, State: AuthSessionActive, AccessSubject: "s", AccessIssuer: "i",
			CSRFHash:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now + 600, AbsoluteExpiresAt: now + 3600}
		if err := s.CreateSession(ctx, sess); err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
	}
	over := AuthSession{IDHash: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		PublicID: "cap-over", UserID: user.UserID, State: AuthSessionActive, AccessSubject: "s", AccessIssuer: "i",
		CSRFHash:  "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now + 600, AbsoluteExpiresAt: now + 3600}
	if err := s.CreateSession(ctx, over); !errors.Is(err, ErrAuthSessionLimit) {
		t.Fatalf("over-cap session error=%v, want ErrAuthSessionLimit", err)
	}
}

package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
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
		CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now + 600, AbsoluteExpiresAt: now + 3600}
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
			results <- s.CompleteTOTPSetup(ctx, user.UserID, []byte("sealed"), 1, 777, hashes, old.IDHash, next, now+1)
		}(i)
	}
	wg.Wait()
	close(results)
	success, replay := 0, 0
	for err := range results {
		switch {
		case err == nil:
			success++
		case errors.Is(err, ErrAuthTOTPReplayed), errors.Is(err, ErrAuthSessionUnknown):
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

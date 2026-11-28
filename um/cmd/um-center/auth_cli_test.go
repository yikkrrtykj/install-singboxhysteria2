package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/umcauth"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/web"
)

func feedStdin(t *testing.T, value string) func() {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = r
	if _, err := w.WriteString(value); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	return func() { os.Stdin = old; _ = r.Close() }
}

func TestUMCAuthLocalBootstrapAndRecoveryCLI(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "private", "center.db")
	keyPath := filepath.Join(dir, "master.key")
	if err := runAuthCLI([]string{"init-key", "--path", keyPath}); err != nil {
		t.Fatalf("init-key: %v", err)
	}
	restore := feedStdin(t, "Local-Bootstrap-Password-2026!\n")
	err := runAuthCLI([]string{"bootstrap", "--db", dbPath, "--master-key", keyPath, "--username", "cli-admin"})
	restore()
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	user, err := st.GetAuthUserByUsername(context.Background(), "cli-admin")
	_ = st.Close()
	if err != nil {
		t.Fatal(err)
	}
	if user.Role != store.AuthRolePlatformAdmin || !user.Enabled {
		t.Fatalf("bootstrap user=%+v", user)
	}
	// A second bootstrap is atomic once-only and cannot create another account.
	restore = feedStdin(t, "Another-Password-2026!\n")
	err = runAuthCLI([]string{"bootstrap", "--db", dbPath, "--master-key", keyPath, "--username", "cli-admin-2"})
	restore()
	if err == nil {
		t.Fatal("second bootstrap unexpectedly succeeded")
	}
	// Controlled local recovery resets the password and clears TOTP/session state.
	restore = feedStdin(t, "Local-Recovery-Password-2026!\n")
	err = runAuthCLI([]string{"recover", "--db", dbPath, "--master-key", keyPath, "--username", "cli-admin"})
	restore()
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	st, err = store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	user, err = st.GetAuthUserByUsername(context.Background(), "cli-admin")
	if err != nil {
		t.Fatal(err)
	}
	if user.TOTPSecret != nil {
		t.Fatal("local recovery did not clear TOTP state")
	}
}

func TestUMCAuthKeyInitUpgradeVerifiesExistingTOTP(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "private", "center.db")
	keyPath := filepath.Join(dir, "master.key")
	if err := runAuthCLI([]string{"init-key", "--path", keyPath}); err != nil {
		t.Fatal(err)
	}
	key, err := umcauth.LoadMasterKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().Unix()
	hash := "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	user, err := st.BootstrapAuthUser(ctx, "key-init-admin", hash, now)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := umcauth.Seal(key, []byte("totp-secret"), []byte("umc-totp:"+user.UserID+":v1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetAuthUserTOTP(ctx, user.UserID, sealed, 1, now); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	if err := runAuthCLI([]string{"key-init", "--db", dbPath, "--master-key", keyPath}); err != nil {
		t.Fatalf("key-init: %v", err)
	}
	st, err = store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := web.VerifyMasterKey(ctx, st, key); err != nil {
		t.Fatalf("sentinel after key-init: %v", err)
	}
	wrong := make([]byte, len(key))
	for i := range wrong {
		wrong[i] = key[i] ^ 0xff
	}
	if err := web.InitializeMasterKeyForExistingDB(ctx, st, wrong); err == nil {
		t.Fatal("wrong key initialized an existing sentinel database")
	}
}

func TestUMCAuthBootstrapDoesNotCreateUserWhenSentinelMismatch(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "private", "center.db")
	keyA := filepath.Join(dir, "a.key")
	keyB := filepath.Join(dir, "b.key")
	if err := runAuthCLI([]string{"init-key", "--path", keyA}); err != nil {
		t.Fatal(err)
	}
	if err := runAuthCLI([]string{"init-key", "--path", keyB}); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	key, err := umcauth.LoadMasterKey(keyA)
	if err != nil {
		t.Fatal(err)
	}
	if err := web.InitializeMasterKeyForExistingDB(context.Background(), st, key); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	restore := feedStdin(t, "Bootstrap-Mismatch-Password-2026!\n")
	err = runAuthCLI([]string{"bootstrap", "--db", dbPath, "--master-key", keyB, "--username", "cannot-create"})
	restore()
	if err == nil {
		t.Fatal("bootstrap with mismatched sentinel unexpectedly succeeded")
	}
	st, err = store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	n, err := st.CountAuthUsers(context.Background())
	if err != nil || n != 0 {
		t.Fatalf("bootstrap left users after sentinel failure: count=%d err=%v", n, err)
	}
}

func TestUMCAuthBootstrapDoesNotBindSentinelForExistingAccountDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "private", "center.db")
	keyPath := filepath.Join(dir, "master.key")
	if err := runAuthCLI([]string{"init-key", "--path", keyPath}); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	hash := "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := st.BootstrapAuthUser(context.Background(), "existing-no-sentinel", hash, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	restore := feedStdin(t, "Bootstrap-Existing-Password-2026!\n")
	err = runAuthCLI([]string{"bootstrap", "--db", dbPath, "--master-key", keyPath, "--username", "cannot-create"})
	restore()
	if err == nil {
		t.Fatal("bootstrap unexpectedly succeeded for an existing-account database")
	}
	st, err = store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	key, err := umcauth.LoadMasterKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := web.VerifyMasterKey(context.Background(), st, key); !errors.Is(err, web.ErrMasterKeyUninitialized) {
		t.Fatalf("existing-account DB bound a sentinel: %v", err)
	}
}

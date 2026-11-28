package main

import (
	"context"
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
	dbPath := filepath.Join(dir, "center.db")
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
	dbPath := filepath.Join(dir, "center.db")
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

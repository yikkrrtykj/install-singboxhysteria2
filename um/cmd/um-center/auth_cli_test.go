package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
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

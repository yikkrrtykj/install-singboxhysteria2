//go:build windows

package fileguard

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestWindowsPrivateFileAndDACL(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := EnsurePrivateDir(dir); err != nil {
		t.Fatalf("EnsurePrivateDir: %v", err)
	}
	path := filepath.Join(dir, "secret.key")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateFile(path); err != nil {
		t.Fatalf("EnsurePrivateFile: %v", err)
	}
	if err := CheckPrivateFile(path); err != nil {
		t.Fatalf("CheckPrivateFile after hardening: %v", err)
	}
	if err := exec.Command("icacls", path, "/grant", "*S-1-1-0:(F)").Run(); err != nil {
		t.Skipf("icacls unavailable: %v", err)
	}
	if err := CheckPrivateFile(path); !errors.Is(err, ErrUnprotected) {
		t.Fatalf("CheckPrivateFile after Everyone ACE = %v, want ErrUnprotected", err)
	}
	if err := EnsurePrivateFile(path); err != nil {
		t.Fatalf("EnsurePrivateFile restore: %v", err)
	}
	if err := CheckPrivateFile(path); err != nil {
		t.Fatalf("CheckPrivateFile after restore: %v", err)
	}
}

func TestWindowsExistingSharedDirectoryIsRefusedWithoutMutation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("icacls", dir, "/grant", "*S-1-1-0:(OI)(CI)(F)").Run(); err != nil {
		t.Skipf("icacls unavailable: %v", err)
	}
	if err := EnsurePrivateDir(dir); !errors.Is(err, ErrUnprotected) {
		t.Fatalf("EnsurePrivateDir(shared)=%v, want ErrUnprotected", err)
	}
	if err := checkPrivateDir(dir); !errors.Is(err, ErrUnprotected) {
		t.Fatalf("refused directory ACL was mutated to private: %v", err)
	}
}

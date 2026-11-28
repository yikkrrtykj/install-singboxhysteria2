//go:build !windows

package fileguard

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPOSIXPrivateFileAndDir(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "private")
	if err := EnsurePrivateDir(dir); err != nil {
		t.Fatalf("EnsurePrivateDir: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode=%v err=%v", info.Mode().Perm(), err)
	}
	path := filepath.Join(dir, "secret.key")
	if err := os.WriteFile(path, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateFile(path); err != nil {
		t.Fatalf("EnsurePrivateFile: %v", err)
	}
	info, err = os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode=%v err=%v", info.Mode().Perm(), err)
	}
	if err := CheckPrivateFile(path); err != nil {
		t.Fatalf("CheckPrivateFile: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivateFile(path); !errors.Is(err, ErrUnprotected) {
		t.Fatalf("CheckPrivateFile widened mode=%v, want ErrUnprotected", err)
	}
	link := filepath.Join(dir, "link")
	_ = os.Symlink(path, link)
	if err := CheckPrivateFile(link); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("CheckPrivateFile symlink=%v, want ErrUnsafePath", err)
	}
}

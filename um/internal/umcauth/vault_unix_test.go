//go:build unix

package umcauth

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

func writePOSIXMasterKeyFile(t *testing.T, path string, mode os.FileMode) []byte {
	t.Helper()
	key := make([]byte, MasterKeyBytes)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	if err := os.WriteFile(path, key, mode); err != nil {
		t.Fatalf("write test key file: %v", err)
	}
	// Defeat the process umask so the requested mode is exact.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod test key file: %v", err)
	}
	return key
}

func TestLoadMasterKeyPOSIXModes(t *testing.T) {
	dir := t.TempDir()
	for _, mode := range []os.FileMode{0o600, 0o400} {
		path := filepath.Join(dir, "key-"+strconv.FormatUint(uint64(mode), 8))
		key := writePOSIXMasterKeyFile(t, path, mode)
		loaded, err := LoadMasterKey(path)
		if err != nil {
			t.Fatalf("LoadMasterKey(mode %04o): %v", mode, err)
		}
		if !bytes.Equal(loaded, key) {
			t.Fatalf("LoadMasterKey(mode %04o) returned different bytes", mode)
		}
	}
	for _, mode := range []os.FileMode{0o644, 0o640, 0o660, 0o700, 0o777, 0o000} {
		path := filepath.Join(dir, "key-"+strconv.FormatUint(uint64(mode), 8))
		writePOSIXMasterKeyFile(t, path, mode)
		if _, err := LoadMasterKey(path); !errors.Is(err, ErrMasterKeyPermissions) {
			t.Fatalf("LoadMasterKey(mode %04o) error = %v, want ErrMasterKeyPermissions", mode, err)
		}
	}
}

func TestGenerateMasterKeyFilePOSIXMode(t *testing.T) {
	oldUmask := syscall.Umask(0o077)
	defer syscall.Umask(oldUmask)

	path := filepath.Join(t.TempDir(), "master.key")
	if err := GenerateMasterKeyFile(path); err != nil {
		t.Fatalf("GenerateMasterKeyFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("generated master key mode = %04o, want 0600", mode)
	}
	if _, err := LoadMasterKey(path); err != nil {
		t.Fatalf("LoadMasterKey(generated): %v", err)
	}
}

func TestLoadMasterKeyPOSIXRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.key")
	writePOSIXMasterKeyFile(t, target, 0o600)
	link := filepath.Join(dir, "link.key")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not available on this filesystem: %v", err)
	}
	if _, err := LoadMasterKey(link); !errors.Is(err, ErrMasterKeyFile) {
		t.Fatalf("LoadMasterKey(symlink) error = %v, want ErrMasterKeyFile", err)
	}
}

func TestLoadMasterKeyPOSIXOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing ownership requires root")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "owner.key")
	writePOSIXMasterKeyFile(t, path, 0o600)
	foreignUID := 65534
	if os.Geteuid() == foreignUID {
		foreignUID = 1
	}
	if err := os.Chown(path, foreignUID, -1); err != nil {
		t.Fatalf("chown: %v", err)
	}
	if _, err := LoadMasterKey(path); !errors.Is(err, ErrMasterKeyPermissions) {
		t.Fatalf("LoadMasterKey(foreign owner) error = %v, want ErrMasterKeyPermissions", err)
	}
}

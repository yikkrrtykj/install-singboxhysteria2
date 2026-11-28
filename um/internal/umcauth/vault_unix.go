//go:build unix

package umcauth

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// openMasterKeyFile opens the key file without following a symlink, so a path
// swapped to a symlink between Lstat and open still fails closed.
func openMasterKeyFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
}

// checkMasterKeyFilePermissions enforces the POSIX rule: mode 0600 or 0400 and
// ownership by the current effective user. Both checks run on the already
// opened file descriptor, so they cannot be raced by a path replacement.
func checkMasterKeyFilePermissions(_ string, info os.FileInfo, _ *os.File) error {
	mode := info.Mode().Perm()
	if mode != 0o600 && mode != 0o400 {
		return fmt.Errorf("%w: mode must be 0600 or 0400", ErrMasterKeyPermissions)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: owner metadata unavailable", ErrMasterKeyPermissions)
	}
	if int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("%w: file is not owned by the current effective user", ErrMasterKeyPermissions)
	}
	return nil
}

// hardenMasterKeyFile forces the newly created key file to mode 0600,
// overriding a permissive process umask.
func hardenMasterKeyFile(f *os.File, _ string) error {
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("umcauth: set master key file mode: %w", err)
	}
	return nil
}

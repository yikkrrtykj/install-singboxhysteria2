//go:build !unix && !windows

package umcauth

import (
	"fmt"
	"os"
)

// This file covers non-POSIX, non-Windows platforms. UM-C production targets
// Linux and Windows; on other platforms the only portable checks available are
// the regular-file check in LoadMasterKey and conservative permission bits.

func openMasterKeyFile(path string) (*os.File, error) {
	return os.Open(path)
}

func checkMasterKeyFilePermissions(_ string, info os.FileInfo, _ *os.File) error {
	mode := info.Mode().Perm()
	if mode != 0o600 && mode != 0o400 {
		return fmt.Errorf("%w: mode must be 0600 or 0400", ErrMasterKeyPermissions)
	}
	return nil
}

func hardenMasterKeyFile(f *os.File, _ string) error {
	return f.Chmod(0o600)
}

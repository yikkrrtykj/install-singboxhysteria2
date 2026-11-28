//go:build !windows

package management

import (
	"os"
	"syscall"
)

// protectedFileMode reports whether the local auth/token file is readable only
// by its owner and is owned by the current service user. Mode bits alone are not
// sufficient: a privileged center must not trust a 0600 file controlled by a
// different local account.
func protectedFileMode(path string, info os.FileInfo) bool {
	if info.Mode().Perm()&0o077 != 0 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return int(st.Uid) == os.Geteuid()
}

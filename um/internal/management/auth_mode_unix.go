//go:build !windows

package management

import "os"

// protectedFileMode reports whether the local auth/token file is readable only
// by its owner on POSIX systems.
func protectedFileMode(path string, info os.FileInfo) bool {
	return info.Mode().Perm()&0o077 == 0
}

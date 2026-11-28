//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd

package linuxobs

import "os"

// monitorExportPOSIXOwner is unavailable on non-POSIX platforms; callers treat
// ok=false as "cannot verify numeric owner", which only disables the explicit
// owner/group check on those platforms (the deployment target is Linux).
func monitorExportPOSIXOwner(info os.FileInfo) (uid, gid uint32, ok bool) {
	return 0, 0, false
}

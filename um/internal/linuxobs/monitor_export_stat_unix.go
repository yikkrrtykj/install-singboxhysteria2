//go:build linux || darwin || freebsd || netbsd || openbsd

package linuxobs

import (
	"os"
	"syscall"
)

// monitorExportPOSIXOwner returns the numeric owner/group from an already-open
// file's stat information. The agent compares these to the operator-configured
// monitor user/group IDs; it never follows a path to resolve them.
func monitorExportPOSIXOwner(info os.FileInfo) (uid, gid uint32, ok bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return 0, 0, false
	}
	return stat.Uid, stat.Gid, true
}

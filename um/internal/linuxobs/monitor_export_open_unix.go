//go:build unix

package linuxobs

import (
	"os"
	"syscall"
)

// openMonitorExportFile opens the export read-only without following a final
// symlink (O_NOFOLLOW). The caller has already rejected a symlink via Lstat; the
// open flag closes the swap window between the check and the open.
func openMonitorExportFile(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

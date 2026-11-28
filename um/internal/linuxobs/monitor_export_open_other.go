//go:build !unix

package linuxobs

import "os"

// openMonitorExportFile opens the export read-only. Non-unix platforms have no
// O_NOFOLLOW portable equivalent here; the caller's Lstat symlink check is the
// guard. The production agent target is Linux; this file keeps cross-platform
// compilation and unit tests working.
func openMonitorExportFile(path string) (*os.File, error) {
	return os.Open(path)
}

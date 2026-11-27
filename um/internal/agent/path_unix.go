//go:build !windows

package agent

// isReparsePoint is false on non-Windows platforms; symlinks are covered by
// Lstat/FileModeSymlink.
func isReparsePoint(string) bool { return false }

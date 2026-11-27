//go:build windows

package agent

import (
	"errors"

	"golang.org/x/sys/windows"
)

func processAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err == nil {
		_ = windows.CloseHandle(h)
		return true
	}
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) || errors.Is(err, windows.ERROR_NOT_FOUND) {
		return false
	}
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return true
	}
	// Conservative: unknown is alive, so a stale lock is never stolen blindly.
	return true
}

//go:build !windows

package agent

import (
	"errors"
	"syscall"
)

func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true
	}
	if errors.Is(err, syscall.EPERM) {
		return true
	}
	if errors.Is(err, syscall.ESRCH) {
		return false
	}
	// Unknown errors are treated conservatively as alive; never steal a lock
	// from a process we cannot prove is dead.
	return true
}

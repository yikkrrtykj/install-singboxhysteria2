//go:build !windows

package agent

import (
	"errors"
	"os"
	"syscall"
)

// lockFileExclusive acquires a non-blocking OS advisory lock. The lock is tied
// to the open file descriptor, so process death releases it automatically; a
// leftover lock file is harmless and is never removed based on a PID read.
func lockFileExclusive(f *os.File) error {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		return nil
	}
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
		return ErrLocked
	}
	return err
}

func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

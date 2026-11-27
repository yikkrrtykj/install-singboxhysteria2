//go:build windows

package agent

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// lockFileExclusive acquires a non-blocking OS byte-range lock. The lock is
// tied to the open file handle, so process death releases it automatically; a
// leftover lock file is harmless and is never removed based on a PID read.
func lockFileExclusive(f *os.File) error {
	var overlapped windows.Overlapped
	err := windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, &overlapped)
	if err == nil {
		return nil
	}
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) ||
		errors.Is(err, windows.ERROR_IO_PENDING) {
		return ErrLocked
	}
	return err
}

func unlockFile(f *os.File) error {
	var overlapped windows.Overlapped
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &overlapped)
}

//go:build windows

package agent

// Windows does not expose a supported directory-fsync operation through
// os.File.Sync. writeAtomic uses MoveFileEx(MOVEFILE_WRITE_THROUGH) for the
// atomic replacement and file contents are flushed before rename; the residual
// directory-entry durability limitation is documented in the B3 durability
// notes and is not claimed as a full POSIX fsync guarantee.
func syncDir(string) error { return nil }

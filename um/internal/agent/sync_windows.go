//go:build windows

package agent

// Windows does not support FlushFileBuffers on a directory handle through
// os.File.Sync. File contents are flushed before rename; directory-entry
// durability is documented as an OD-P7/Windows storage boundary.
func syncDir(string) error { return nil }

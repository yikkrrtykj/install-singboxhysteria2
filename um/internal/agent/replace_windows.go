//go:build windows

package agent

import "golang.org/x/sys/windows"

// replaceFile uses MoveFileEx with MOVEFILE_WRITE_THROUGH so the replacement
// metadata is flushed as part of the rename. Windows has no directory fsync
// equivalent exposed by Go; this is the strongest available file-replacement
// guarantee and the remaining directory-entry limitation is documented.
func replaceFile(oldPath, newPath string) error {
	oldp, err := windows.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	newp, err := windows.UTF16PtrFromString(newPath)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(oldp, newp,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

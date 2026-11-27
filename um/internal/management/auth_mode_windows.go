//go:build windows

package management

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// protectedFileMode checks the Windows DACL instead of POSIX mode bits (which
// Go cannot represent faithfully on Windows). The file must not grant access to
// Everyone, Authenticated Users or the builtin Users group. The installer/UM-C
// provisioning layer is still responsible for placing this file in a protected
// directory.
func protectedFileMode(path string, info os.FileInfo) bool {
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return false
	}
	dacl, defaulted, err := sd.DACL()
	if err != nil || defaulted || dacl == nil {
		return false
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace == nil {
			return false
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid == nil || !sid.IsValid() {
			return false
		}
		for _, broad := range []windows.WELL_KNOWN_SID_TYPE{
			windows.WinWorldSid, windows.WinAuthenticatedUserSid, windows.WinBuiltinUsersSid,
		} {
			if sid.IsWellKnown(broad) {
				return false
			}
		}
	}
	return true
}

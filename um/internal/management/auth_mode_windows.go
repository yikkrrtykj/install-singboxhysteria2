//go:build windows

package management

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// protectedFileMode checks the Windows DACL instead of POSIX mode bits (which
// Go cannot represent faithfully on Windows). Only the file owner and explicitly
// trusted system principals (LocalSystem and Builtin Administrators) may have
// allow ACEs; arbitrary local/domain users and groups are rejected. The
// installer/UM-C provisioning layer is still responsible for placing this file
// in a protected directory.
func protectedFileMode(path string, info os.FileInfo) bool {
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return false
	}
	dacl, defaulted, err := sd.DACL()
	if err != nil || defaulted || dacl == nil {
		return false
	}
	owner, ownerDefaulted, err := sd.Owner()
	if err != nil || ownerDefaulted || owner == nil {
		return false
	}
	trusted := func(sid *windows.SID) bool {
		return trustedWindowsFileSID(owner, sid)
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
		if !trusted(sid) {
			return false
		}
	}
	return true
}

// trustedWindowsFileSID is the closed allow-list for a protected file DACL:
// the file owner, LocalSystem and Builtin Administrators only.
func trustedWindowsFileSID(owner, sid *windows.SID) bool {
	if sid == nil || !sid.IsValid() {
		return false
	}
	if owner != nil && owner.IsValid() && sid.Equals(owner) {
		return true
	}
	return sid.IsWellKnown(windows.WinLocalSystemSid) ||
		sid.IsWellKnown(windows.WinBuiltinAdministratorsSid)
}

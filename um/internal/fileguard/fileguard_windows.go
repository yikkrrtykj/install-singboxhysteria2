//go:build windows

package fileguard

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func ensurePrivateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("fileguard: create private directory: %w", err)
	}
	return hardenPath(path, true)
}

func ensurePrivateFile(path string) error {
	return hardenPath(path, false)
}

func hardenPath(path string, dir bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("fileguard: stat path: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || isReparsePoint(path) {
		return ErrUnsafePath
	}
	if dir && !info.IsDir() || !dir && !info.Mode().IsRegular() {
		return ErrUnsafePath
	}
	if err := setClosedDACL(path, dir); err != nil {
		return err
	}
	return checkPrivatePath(path, dir)
}

func checkPrivateFile(path string) error {
	return checkPrivatePath(path, false)
}

func checkPrivateDir(path string) error {
	return checkPrivatePath(path, true)
}

func checkPrivatePath(path string, dir bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("fileguard: stat file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || isReparsePoint(path) {
		return ErrUnsafePath
	}
	if dir && !info.IsDir() || !dir && !info.Mode().IsRegular() {
		return ErrUnsafePath
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return ErrUnprotected
	}
	dacl, defaulted, err := sd.DACL()
	if err != nil || defaulted || dacl == nil {
		return ErrUnprotected
	}
	owner, ownerDefaulted, err := sd.Owner()
	if err != nil || ownerDefaulted || owner == nil || !owner.IsValid() {
		return ErrUnprotected
	}
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || tokenUser.User.Sid == nil || !tokenUser.User.Sid.IsValid() {
		return ErrUnprotected
	}
	serviceSID := tokenUser.User.Sid
	trusted := func(sid *windows.SID) bool {
		if sid == nil || !sid.IsValid() {
			return false
		}
		ok := sid.Equals(owner) || sid.Equals(serviceSID) ||
			sid.IsWellKnown(windows.WinLocalSystemSid) ||
			sid.IsWellKnown(windows.WinBuiltinAdministratorsSid)
		return ok
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace == nil {
			return ErrUnprotected
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !trusted(sid) {
			return ErrUnprotected
		}
	}
	return nil
}

func setClosedDACL(path string, dir bool) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return fmt.Errorf("fileguard: read security descriptor: %w", err)
	}
	owner, ownerDefaulted, err := sd.Owner()
	if err != nil || ownerDefaulted || owner == nil || !owner.IsValid() {
		return ErrUnprotected
	}
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || tokenUser.User.Sid == nil || !tokenUser.User.Sid.IsValid() {
		return fmt.Errorf("fileguard: read service SID: %w", err)
	}
	inherit := ""
	if dir {
		inherit = "OICI"
	}
	ownerSID := owner.String()
	serviceSID := tokenUser.User.Sid.String()
	sddl := "D:P(A;" + inherit + ";FA;;;" + ownerSID + ")(A;" + inherit + ";FA;;;SY)(A;" + inherit + ";FA;;;BA)"
	if serviceSID != "" && serviceSID != ownerSID {
		sddl += "(A;" + inherit + ";FA;;;" + serviceSID + ")"
	}
	closed, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("fileguard: build protected SDDL: %w", err)
	}
	dacl, defaulted, err := closed.DACL()
	if err != nil || defaulted || dacl == nil {
		return fmt.Errorf("fileguard: read protected DACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("fileguard: set protected DACL: %w", err)
	}
	return nil
}

func isReparsePoint(path string) bool {
	attrs, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil {
		return true
	}
	return attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

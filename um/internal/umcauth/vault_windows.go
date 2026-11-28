//go:build windows

package umcauth

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// openMasterKeyFile opens the key file. The common loader already rejected a
// symlink with Lstat; the opened handle is additionally checked for a reparse
// point in checkMasterKeyFilePermissions so a path swap cannot redirect the
// open to a junction.
func openMasterKeyFile(path string) (*os.File, error) {
	return os.Open(path)
}

// checkMasterKeyFilePermissions enforces the Windows rule: the file is a
// regular (non-reparse) file whose DACL only grants access to the file owner,
// the current service account, LocalSystem and Builtin Administrators. The
// security descriptor is read from the already opened handle, so path
// replacement cannot race the check.
func checkMasterKeyFilePermissions(_ string, _ os.FileInfo, f *os.File) error {
	handle := windows.Handle(f.Fd())
	var fileInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &fileInfo); err != nil {
		return fmt.Errorf("%w: file metadata unavailable", ErrMasterKeyPermissions)
	}
	if fileInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%w: reparse points and symlinks are not allowed", ErrMasterKeyPermissions)
	}
	if fileInfo.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return fmt.Errorf("%w: must be a regular file", ErrMasterKeyPermissions)
	}

	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return fmt.Errorf("%w: security descriptor unavailable", ErrMasterKeyPermissions)
	}
	dacl, daclDefaulted, err := descriptor.DACL()
	if err != nil || daclDefaulted || dacl == nil {
		return fmt.Errorf("%w: DACL missing or defaulted", ErrMasterKeyPermissions)
	}
	owner, ownerDefaulted, err := descriptor.Owner()
	if err != nil || ownerDefaulted || owner == nil {
		return fmt.Errorf("%w: owner missing or defaulted", ErrMasterKeyPermissions)
	}
	serviceUser, err := currentWindowsUserSID()
	if err != nil {
		return fmt.Errorf("%w: service account SID unavailable", ErrMasterKeyPermissions)
	}

	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil {
			return fmt.Errorf("%w: DACL ACE unavailable", ErrMasterKeyPermissions)
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if !trustedMasterKeySID(owner, serviceUser, sid) {
				return fmt.Errorf("%w: DACL allows an untrusted principal", ErrMasterKeyPermissions)
			}
		case windows.ACCESS_DENIED_ACE_TYPE:
			// A deny ACE never grants access and therefore cannot widen the
			// allow-list. Its SID is irrelevant to this check.
		default:
			// Object/callback/audit ACEs are not expected on a properly
			// protected key file; fail closed rather than skip them.
			return fmt.Errorf("%w: unsupported DACL ACE type", ErrMasterKeyPermissions)
		}
	}
	return nil
}

// trustedMasterKeySID is the closed allow-list for a master-key DACL: the file
// owner, the current service account, LocalSystem and Builtin Administrators.
func trustedMasterKeySID(owner, serviceUser, sid *windows.SID) bool {
	if sid == nil || !sid.IsValid() {
		return false
	}
	if owner != nil && owner.IsValid() && sid.Equals(owner) {
		return true
	}
	if serviceUser != nil && serviceUser.IsValid() && sid.Equals(serviceUser) {
		return true
	}
	return sid.IsWellKnown(windows.WinLocalSystemSid) ||
		sid.IsWellKnown(windows.WinBuiltinAdministratorsSid)
}

func currentWindowsUserSID() (*windows.SID, error) {
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	if tokenUser.User.Sid == nil || !tokenUser.User.Sid.IsValid() {
		return nil, fmt.Errorf("umcauth: invalid service account SID")
	}
	return tokenUser.User.Sid, nil
}

// hardenMasterKeyFile replaces the ACL inherited from the parent directory with
// an explicit protected DACL containing only the current service account,
// LocalSystem and Builtin Administrators. The resulting DACL is re-validated
// through the same check LoadMasterKey uses; a failure removes the file via the
// caller's cleanup path.
func hardenMasterKeyFile(f *os.File, path string) error {
	serviceUser, err := currentWindowsUserSID()
	if err != nil {
		return fmt.Errorf("umcauth: resolve service account SID: %w", err)
	}
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("umcauth: resolve LocalSystem SID: %w", err)
	}
	administratorsSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("umcauth: resolve Administrators SID: %w", err)
	}

	entries := make([]windows.EXPLICIT_ACCESS, 0, 3)
	entries = append(entries, windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(serviceUser),
		},
	})
	if !serviceUser.Equals(systemSID) {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(systemSID),
			},
		})
	}
	if !serviceUser.Equals(administratorsSID) {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(administratorsSID),
			},
		})
	}

	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("umcauth: build master key DACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("umcauth: protect master key file: %w", err)
	}

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("umcauth: stat protected master key file: %w", err)
	}
	if err := checkMasterKeyFilePermissions(path, info, f); err != nil {
		return fmt.Errorf("umcauth: master key file protection verification failed: %w", err)
	}
	return nil
}

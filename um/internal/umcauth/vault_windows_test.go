//go:build windows

package umcauth

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func testCurrentUserSID(t *testing.T) *windows.SID {
	t.Helper()
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("GetTokenUser: %v", err)
	}
	if tokenUser.User.Sid == nil || !tokenUser.User.Sid.IsValid() {
		t.Fatal("current process token has no valid user SID")
	}
	return tokenUser.User.Sid
}

func testWellKnownSID(t *testing.T, kind windows.WELL_KNOWN_SID_TYPE) *windows.SID {
	t.Helper()
	sid, err := windows.CreateWellKnownSid(kind)
	if err != nil {
		t.Fatalf("CreateWellKnownSid(%d): %v", kind, err)
	}
	return sid
}

// testSetExplicitDACL installs a protected DACL containing exactly the trusted
// principals used by production, plus any extra (untrusted) SIDs.
func testSetExplicitDACL(t *testing.T, path string, extraSIDs ...*windows.SID) {
	t.Helper()
	trusted := []*windows.SID{
		testCurrentUserSID(t),
		testWellKnownSID(t, windows.WinLocalSystemSid),
		testWellKnownSID(t, windows.WinBuiltinAdministratorsSid),
	}
	unique := make([]*windows.SID, 0, len(trusted)+len(extraSIDs))
	for _, sid := range append(trusted, extraSIDs...) {
		duplicate := false
		for _, existing := range unique {
			if existing.Equals(sid) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			unique = append(unique, sid)
		}
	}
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(unique))
	for _, sid := range unique {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}
	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatalf("ACLFromEntries: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatalf("SetNamedSecurityInfo: %v", err)
	}
}

func TestGenerateMasterKeyFileWindowsACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	if err := GenerateMasterKeyFile(path); err != nil {
		t.Fatalf("GenerateMasterKeyFile: %v", err)
	}
	key, err := LoadMasterKey(path)
	if err != nil {
		t.Fatalf("LoadMasterKey(generated): %v", err)
	}
	if len(key) != MasterKeyBytes {
		t.Fatalf("loaded key length = %d, want %d", len(key), MasterKeyBytes)
	}

	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo: %v", err)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatalf("Control: %v", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("generated master key DACL is not protected against inheritance")
	}
	dacl, defaulted, err := descriptor.DACL()
	if err != nil || defaulted || dacl == nil {
		t.Fatalf("DACL: dacl=%v defaulted=%v err=%v", dacl, defaulted, err)
	}
	owner, ownerDefaulted, err := descriptor.Owner()
	if err != nil || ownerDefaulted || owner == nil {
		t.Fatalf("Owner: owner=%v defaulted=%v err=%v", owner, ownerDefaulted, err)
	}
	serviceUser := testCurrentUserSID(t)
	allowCount := 0
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil {
			t.Fatalf("GetAce(%d): ace=%v err=%v", index, ace, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !trustedMasterKeySID(owner, serviceUser, sid) {
			t.Fatalf("generated master key DACL allows an untrusted SID: %v", sid)
		}
		allowCount++
	}
	if allowCount == 0 {
		t.Fatal("generated master key DACL has no allow entries")
	}
}

func TestLoadMasterKeyWindowsTrustedExplicitDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	if err := GenerateMasterKeyFile(path); err != nil {
		t.Fatalf("GenerateMasterKeyFile: %v", err)
	}
	testSetExplicitDACL(t, path) // trusted principals only
	if _, err := LoadMasterKey(path); err != nil {
		t.Fatalf("LoadMasterKey(trusted explicit DACL): %v", err)
	}
}

func TestLoadMasterKeyWindowsRejectsUntrustedACE(t *testing.T) {
	for _, untrusted := range []*windows.SID{
		testWellKnownSID(t, windows.WinWorldSid),
		testWellKnownSID(t, windows.WinAuthenticatedUserSid),
	} {
		path := filepath.Join(t.TempDir(), "master.key")
		if err := GenerateMasterKeyFile(path); err != nil {
			t.Fatalf("GenerateMasterKeyFile: %v", err)
		}
		testSetExplicitDACL(t, path, untrusted)
		if _, err := LoadMasterKey(path); !errors.Is(err, ErrMasterKeyPermissions) {
			t.Fatalf("LoadMasterKey(untrusted ACE %v) error = %v, want ErrMasterKeyPermissions", untrusted, err)
		}
	}
}

func TestLoadMasterKeyWindowsWrongSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	if err := GenerateMasterKeyFile(path); err != nil {
		t.Fatalf("GenerateMasterKeyFile: %v", err)
	}
	if err := os.Truncate(path, MasterKeyBytes-1); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	if _, err := LoadMasterKey(path); !errors.Is(err, ErrMasterKeyFile) {
		t.Fatalf("LoadMasterKey(short file) error = %v, want ErrMasterKeyFile", err)
	}
}

func TestLoadMasterKeyWindowsRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.key")
	if err := GenerateMasterKeyFile(target); err != nil {
		t.Fatalf("GenerateMasterKeyFile: %v", err)
	}
	link := filepath.Join(dir, "link.key")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation not permitted: %v", err)
	}
	if _, err := LoadMasterKey(link); !errors.Is(err, ErrMasterKeyFile) {
		t.Fatalf("LoadMasterKey(symlink) error = %v, want ErrMasterKeyFile", err)
	}
}

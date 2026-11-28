//go:build windows

package management_test

import (
	"os/exec"
	"testing"

	"golang.org/x/sys/windows"
)

// protectTestFile makes a temporary credential fixture emulate the documented
// owner-only production ACL. Windows temp directories inherit access for
// sandbox/other local accounts, which the hardened loader correctly rejects.
// Grant the current process token SID explicitly so the fixture does not depend
// on account-name/domain resolution on CI runners.
func protectTestFile(t *testing.T, path string) {
	t.Helper()
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("current token user: %v", err)
	}
	sid := tokenUser.User.Sid
	if sid == nil || !sid.IsValid() {
		t.Fatal("current token user has invalid SID")
	}
	ownerArg := "*" + sid.String()
	cmd := exec.Command("icacls", path, "/inheritance:r",
		"/grant:r", ownerArg+":(F)", "SYSTEM:(F)", "Administrators:(F)")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("protect test file ACL: %v\n%s", err, out)
	}
}

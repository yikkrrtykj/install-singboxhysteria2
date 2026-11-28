//go:build windows

package management_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// protectTestFile makes a temporary credential fixture emulate the documented
// owner-only production ACL. Windows temp directories inherit access for
// sandbox/other local accounts, which the hardened loader correctly rejects.
func protectTestFile(t *testing.T, path string) {
	t.Helper()
	user := os.Getenv("USERNAME")
	if domain := os.Getenv("USERDOMAIN"); domain != "" && user != "" {
		user = domain + `\` + user
	}
	if strings.TrimSpace(user) == "" {
		t.Fatal("cannot determine test owner")
	}
	cmd := exec.Command("icacls", path, "/inheritance:r",
		"/grant:r", user+":(F)", "SYSTEM:(F)", "Administrators:(F)")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("protect test file ACL: %v\n%s", err, out)
	}
}

//go:build windows

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

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

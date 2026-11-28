//go:build windows

package management

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsACLTrustedSID(t *testing.T) {
	owner, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	authUsers, err := windows.CreateWellKnownSid(windows.WinAuthenticatedUserSid)
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		sid  *windows.SID
		want bool
	}{
		{"owner", owner, true},
		{"system", system, true},
		{"administrators", admin, true},
		{"builtin-users", users, false},
		{"everyone", everyone, false},
		{"authenticated-users", authUsers, false},
	} {
		if got := trustedWindowsFileSID(owner, tc.sid); got != tc.want {
			t.Fatalf("%s trusted=%v want=%v", tc.name, got, tc.want)
		}
	}
}

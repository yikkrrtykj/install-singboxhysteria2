//go:build !windows

// Platform-fallback tests. They run on non-Windows hosts only; the Windows host
// cross-compiles them with GOOS=linux go vet, but cannot execute them here.
package secretstore

import (
	"errors"
	"strings"
	"testing"
)

func TestNewDPAPIProtectorUnsupported(t *testing.T) {
	const syntheticEntropy = "synthetic-test-entropy-never-used"
	for _, scope := range []DPAPIScope{DPAPIUserScope, DPAPIMachineScope} {
		protector, err := NewDPAPIProtector(scope, []byte(syntheticEntropy))
		if err == nil {
			t.Fatalf("scope %d unexpectedly produced a protector on this platform", scope)
		}
		if protector != nil {
			t.Fatal("unsupported platform returned a non-nil protector")
		}
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("error does not match ErrUnsupported: %v", err)
		}
		if strings.Contains(err.Error(), syntheticEntropy) {
			t.Fatal("unsupported-platform error echoed the entropy")
		}
	}
}

func TestDPAPIProtectorFailsClosedWithoutWindows(t *testing.T) {
	const syntheticPlaintext = "synthetic-test-credential-never-used"
	// The constructor never yields a usable protector here, but callers may hold
	// a zero value after an error check; the methods must fail closed and must
	// not touch their input.
	var protector DPAPIProtector
	for _, tc := range []struct {
		name string
		call func() ([]byte, error)
	}{
		{"Protect", func() ([]byte, error) { return protector.Protect([]byte(syntheticPlaintext)) }},
		{"Unprotect", func() ([]byte, error) { return protector.Unprotect([]byte(syntheticPlaintext)) }},
	} {
		out, err := tc.call()
		if err == nil {
			t.Fatalf("%s succeeded on an unsupported platform", tc.name)
		}
		if out != nil {
			t.Fatalf("%s returned data on an unsupported platform", tc.name)
		}
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("%s error does not match ErrUnsupported: %v", tc.name, err)
		}
		if strings.Contains(err.Error(), syntheticPlaintext) {
			t.Fatalf("%s error echoed the plaintext", tc.name)
		}
	}
}

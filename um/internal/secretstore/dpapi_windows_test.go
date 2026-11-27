//go:build windows

// MOCK / UNIT only: DPAPI helper tests. No production service account, service
// installation or real credential is involved; all plaintext is synthetic.
package secretstore

import (
	"bytes"
	"strings"
	"testing"
)

// testPlaintext is synthetic test material, never a real credential.
const testPlaintext = "synthetic-test-credential-never-used"

func TestDPAPIUserScopeRoundTrip(t *testing.T) {
	protector, err := NewDPAPIProtector(DPAPIUserScope, []byte("test-entropy"))
	if err != nil {
		t.Fatalf("construct user-scope protector: %v", err)
	}
	// Exercise the shared interface seam, not just the concrete type.
	var seam Protector = protector
	protected, err := seam.Protect([]byte(testPlaintext))
	if err != nil {
		t.Fatalf("DPAPI protect: %v", err)
	}
	if len(protected) == 0 {
		t.Fatal("DPAPI produced an empty protected value")
	}
	if bytes.Equal(protected, []byte(testPlaintext)) {
		t.Fatal("DPAPI protected value is the plaintext")
	}
	if bytes.Contains(protected, []byte(testPlaintext)) {
		t.Fatal("DPAPI protected value contains the plaintext")
	}
	roundTripped, err := seam.Unprotect(protected)
	if err != nil {
		t.Fatalf("DPAPI unprotect: %v", err)
	}
	if string(roundTripped) != testPlaintext {
		t.Fatal("DPAPI round trip changed the plaintext")
	}
}

func TestDPAPIUserScopeRoundTripWithoutEntropy(t *testing.T) {
	protector, err := NewDPAPIProtector(DPAPIUserScope, nil)
	if err != nil {
		t.Fatalf("construct user-scope protector without entropy: %v", err)
	}
	protected, err := protector.Protect([]byte(testPlaintext))
	if err != nil {
		t.Fatalf("DPAPI protect: %v", err)
	}
	roundTripped, err := protector.Unprotect(protected)
	if err != nil {
		t.Fatalf("DPAPI unprotect: %v", err)
	}
	if string(roundTripped) != testPlaintext {
		t.Fatal("DPAPI round trip changed the plaintext")
	}
}

func TestDPAPIProtectorCopiesEntropy(t *testing.T) {
	entropy := []byte("test-entropy")
	protector, err := NewDPAPIProtector(DPAPIUserScope, entropy)
	if err != nil {
		t.Fatalf("construct user-scope protector: %v", err)
	}
	protected, err := protector.Protect([]byte(testPlaintext))
	if err != nil {
		t.Fatalf("DPAPI protect: %v", err)
	}
	// Corrupting the caller's buffer after construction must not change the
	// protector's copied entropy, otherwise Unprotect would silently break.
	for i := range entropy {
		entropy[i] = 0
	}
	roundTripped, err := protector.Unprotect(protected)
	if err != nil {
		t.Fatalf("DPAPI unprotect after caller entropy mutation: %v", err)
	}
	if string(roundTripped) != testPlaintext {
		t.Fatal("DPAPI round trip changed the plaintext")
	}
}

func TestDPAPIWrongEntropyFailsWithoutLeakingPlaintext(t *testing.T) {
	right, err := NewDPAPIProtector(DPAPIUserScope, []byte("right-entropy"))
	if err != nil {
		t.Fatalf("construct right-entropy protector: %v", err)
	}
	protected, err := right.Protect([]byte(testPlaintext))
	if err != nil {
		t.Fatalf("DPAPI protect: %v", err)
	}

	wrong, err := NewDPAPIProtector(DPAPIUserScope, []byte("wrong-entropy"))
	if err != nil {
		t.Fatalf("construct wrong-entropy protector: %v", err)
	}
	out, err := wrong.Unprotect(protected)
	if err == nil {
		t.Fatal("DPAPI unprotect succeeded with the wrong entropy")
	}
	if out != nil {
		t.Fatal("failed DPAPI unprotect returned data")
	}
	if strings.Contains(err.Error(), testPlaintext) || bytes.Contains([]byte(err.Error()), []byte(testPlaintext)) {
		t.Fatal("DPAPI error echoed the plaintext")
	}

	// The reverse direction must fail too: a wrong-entropy protection must not
	// decrypt under the right entropy.
	foreign, err := wrong.Protect([]byte(testPlaintext))
	if err != nil {
		t.Fatalf("DPAPI protect with wrong entropy: %v", err)
	}
	if out, err := right.Unprotect(foreign); err == nil {
		t.Fatal("DPAPI unprotect accepted data protected with different entropy")
	} else if out != nil {
		t.Fatal("failed DPAPI unprotect returned data")
	}
}

func TestDPAPIRejectsEmptyInput(t *testing.T) {
	protector, err := NewDPAPIProtector(DPAPIUserScope, nil)
	if err != nil {
		t.Fatalf("construct user-scope protector: %v", err)
	}
	for _, tc := range []struct {
		name string
		call func() ([]byte, error)
	}{
		{"Protect(nil)", func() ([]byte, error) { return protector.Protect(nil) }},
		{"Protect(empty)", func() ([]byte, error) { return protector.Protect([]byte{}) }},
		{"Unprotect(nil)", func() ([]byte, error) { return protector.Unprotect(nil) }},
		{"Unprotect(empty)", func() ([]byte, error) { return protector.Unprotect([]byte{}) }},
	} {
		out, err := tc.call()
		if err == nil {
			t.Fatalf("%s was accepted", tc.name)
		}
		if out != nil {
			t.Fatalf("%s returned data with an error", tc.name)
		}
	}
}

func TestDPAPIRejectsImpossibleConfiguration(t *testing.T) {
	for _, scope := range []DPAPIScope{DPAPIScope(2), DPAPIScope(100)} {
		if _, err := NewDPAPIProtector(scope, nil); err == nil {
			t.Fatalf("scope %d was accepted", scope)
		}
	}
	if _, err := NewDPAPIProtector(DPAPIUserScope, make([]byte, maxEntropyBytes+1)); err == nil {
		t.Fatal("oversized DPAPI entropy was accepted")
	}
	// Exactly at the documented limit is allowed.
	if _, err := NewDPAPIProtector(DPAPIUserScope, make([]byte, maxEntropyBytes)); err != nil {
		t.Fatalf("entropy at the local limit was rejected: %v", err)
	}
	// Machine scope must be constructible without an elevated token or admin
	// rights; this test deliberately does not Protect/Unprotect with it.
	if _, err := NewDPAPIProtector(DPAPIMachineScope, nil); err != nil {
		t.Fatalf("machine scope helper is not constructible: %v", err)
	}
}

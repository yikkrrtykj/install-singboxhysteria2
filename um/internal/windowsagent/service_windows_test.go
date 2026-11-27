//go:build windows

// MOCK / UNIT only: DPAPI helper tests. No production service account, service
// installation or real credential is involved; the plaintext is synthetic.
package windowsagent

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestDPAPIProtectRoundTrip(t *testing.T) {
	const plaintext = "synthetic-test-credential-never-used"
	protector, err := NewDPAPIProtector(DPAPIUserScope, []byte("test-entropy"))
	if err != nil {
		t.Fatal(err)
	}
	protected, err := protector.Protect([]byte(plaintext))
	if err != nil {
		t.Fatalf("DPAPI protect: %v", err)
	}
	if len(protected) == 0 {
		t.Fatal("DPAPI produced an empty protected value")
	}
	if bytes.Contains(protected, []byte(plaintext)) {
		t.Fatal("DPAPI protected value contains the plaintext")
	}
	roundTripped, err := protector.Unprotect(protected)
	if err != nil {
		t.Fatalf("DPAPI unprotect: %v", err)
	}
	if string(roundTripped) != plaintext {
		t.Fatal("DPAPI round trip changed the plaintext")
	}

	otherEntropy, err := NewDPAPIProtector(DPAPIUserScope, []byte("different-entropy"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otherEntropy.Unprotect(protected); err == nil {
		t.Fatal("DPAPI unprotect succeeded with the wrong entropy")
	} else if strings.Contains(err.Error(), plaintext) {
		t.Fatal("DPAPI error echoed the plaintext")
	}
}

func TestDPAPIRejectsImpossibleInput(t *testing.T) {
	for _, scope := range []DPAPIScope{DPAPIScope(2), DPAPIScope(100)} {
		if _, err := NewDPAPIProtector(scope, nil); err == nil {
			t.Fatalf("scope %d was accepted", scope)
		}
	}
	if _, err := NewDPAPIProtector(DPAPIUserScope, make([]byte, 1025)); err == nil {
		t.Fatal("oversized DPAPI entropy was accepted")
	}
	if _, err := NewDPAPIProtector(DPAPIMachineScope, nil); err != nil {
		t.Fatalf("machine scope helper is not constructible: %v", err)
	}
	protector, err := NewDPAPIProtector(DPAPIUserScope, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protector.Protect(nil); err == nil {
		t.Fatal("empty plaintext was protected")
	}
	if _, err := protector.Unprotect(nil); err == nil {
		t.Fatal("empty protected data was accepted")
	}
}

// TestServiceHostHookIsDeferred documents that only the ADR seam exists: this
// Draft provides no service implementation to instantiate.
func TestServiceHostHookIsDeferred(t *testing.T) {
	var host ServiceHost
	if host != nil {
		t.Fatal("unexpected Windows service implementation")
	}
	_ = context.Background()
}

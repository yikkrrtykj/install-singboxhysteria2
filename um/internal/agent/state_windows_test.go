//go:build windows

package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestWindowsIdentityAndRotationKeysAreDPAPIProtected proves the at-rest state
// never contains the Ed25519/rotation private-key plaintext and that the same
// Windows user can reopen it. This is current-user DPAPI, not a service-account
// lab claim; OD-P7 account provisioning remains separate.
func TestWindowsIdentityAndRotationKeysAreDPAPIProtected(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenState(dir)
	if err != nil {
		t.Fatal(err)
	}
	id := testIdentity(t)
	if err := s.saveIdentity(id); err != nil {
		t.Fatalf("save identity: %v", err)
	}
	if err := s.saveBoot(BootState{Version: stateVersion, Generation: 1, BootID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", NextSeq: 1}); err != nil {
		t.Fatalf("save boot: %v", err)
	}
	rot := RotationState{Version: stateVersion, Nonce: "nonce",
		NewPublicKey: id.PublicKey, NewPrivateKey: id.PrivateKey, State: "awaiting_proof"}
	if err := s.saveRotation(rot); err != nil {
		t.Fatalf("save rotation: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{identityFile, rotationFile} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(id.PrivateKey)) {
			t.Fatalf("%s contains plaintext private key material", name)
		}
	}
	s2, err := OpenState(dir)
	if err != nil {
		t.Fatalf("reopen protected state: %v", err)
	}
	defer s2.Close()
	got, ok := s2.Identity()
	if !ok || got.PrivateKey != id.PrivateKey || got.PublicKey != id.PublicKey {
		t.Fatal("DPAPI identity did not round-trip")
	}
	gotRot, ok := s2.Rotation()
	if !ok || gotRot.NewPrivateKey != id.PrivateKey {
		t.Fatal("DPAPI rotation key did not round-trip")
	}
}

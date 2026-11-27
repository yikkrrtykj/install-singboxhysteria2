//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/linuxobs"
)

func TestSourceAuthorizationRequiresProbe(t *testing.T) {
	t.Setenv("UM_AGENT_SINGBOX_API_SECRET_FILE", "")
	t.Setenv("UM_AGENT_SINGBOX_SOURCE_AUTHORIZED", "1")
	if _, err := platformCollector(commonFlags{}); err == nil {
		t.Fatal("authorization flag without a configured service.api probe was accepted")
	}

	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("synthetic-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(secret, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("UM_AGENT_SINGBOX_API_SECRET_FILE", secret)
	t.Setenv("UM_AGENT_SINGBOX_SOURCE_AUTHORIZED", "1")
	col, err := platformCollector(commonFlags{})
	if err != nil {
		t.Fatalf("authorized source collector: %v", err)
	}
	linuxCol, ok := col.(*linuxobs.Collector)
	if !ok || linuxCol.ServiceAPIProbe == nil || !linuxCol.SingBoxSourceAuthorized {
		t.Fatalf("collector wiring = %#v", col)
	}
}

func TestReadCredentialFilePolicy(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	ok := write("ok", "  synthetic-secret\n", 0o600)
	if got, err := readCredentialFile(ok); err != nil || got != "synthetic-secret" {
		t.Fatalf("0600 credential = %q, %v", got, err)
	}
	// systemd >=254 uses ACLs whose mask appears in the group read bit.
	aclMask := write("acl-mask", "synthetic-secret\n", 0o440)
	if got, err := readCredentialFile(aclMask); err != nil || got != "synthetic-secret" {
		t.Fatalf("0440 ACL-mask credential = %q, %v", got, err)
	}
	world := write("world", "synthetic-secret\n", 0o604)
	if _, err := readCredentialFile(world); err == nil {
		t.Fatal("world-readable credential accepted")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(ok, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := readCredentialFile(link); err == nil {
		t.Fatal("symlink credential accepted")
	}
	empty := write("empty", "\n", 0o600)
	if _, err := readCredentialFile(empty); err == nil {
		t.Fatal("empty credential accepted")
	}
	oversize := write("oversize", string(make([]byte, 5000)), 0o600)
	if _, err := readCredentialFile(oversize); err == nil {
		t.Fatal("oversized credential accepted")
	}
}

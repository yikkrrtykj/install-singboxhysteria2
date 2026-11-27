//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/linuxobs"
)

// The B3 release has no supported enablement path for the unproven sing-box
// service.api source. Environment values that used to be an operator assertion
// must not wire a probe or authorize the source.
func TestSourceAuthorizationEnvIsNotAProductionGate(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("synthetic-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("UM_AGENT_SINGBOX_API_SECRET_FILE", secret)
	t.Setenv("UM_AGENT_SINGBOX_SOURCE_AUTHORIZED", "1")
	col, err := platformCollector(commonFlags{})
	if err != nil {
		t.Fatalf("ignored env values must not fail startup: %v", err)
	}
	linuxCol, ok := col.(*linuxobs.Collector)
	if !ok {
		t.Fatalf("collector wiring = %#v", col)
	}
	if linuxCol.ServiceAPIProbe != nil || linuxCol.SingBoxSourceAuthorized {
		t.Fatalf("environment values authorized service.api: %#v", linuxCol)
	}
}

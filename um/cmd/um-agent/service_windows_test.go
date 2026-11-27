//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMergeServiceArgsKeepsImagePathFlags(t *testing.T) {
	configured := []string{"--state-dir", `C:\ProgramData\UM Agent`, "--center", "https://center.example", "--node-class", "windows_terminal"}
	got := mergeServiceArgs([]string{"um-agent"}, configured)
	if len(got) != len(configured) {
		t.Fatalf("mergeServiceArgs = %#v, want configured flags %#v", got, configured)
	}
	for i := range configured {
		if got[i] != configured[i] {
			t.Fatalf("arg[%d]=%q, want %q", i, got[i], configured[i])
		}
	}
	withExtra := mergeServiceArgs([]string{"um-agent", "--extra"}, configured)
	if len(withExtra) != len(configured)+1 || withExtra[len(withExtra)-1] != "--extra" {
		t.Fatalf("extra SCM args = %#v", withExtra)
	}
}

func TestWindowsR1ProvisioningAndActivation(t *testing.T) {
	inputDir := t.TempDir()
	stateDir := t.TempDir()
	profile := writeTestFile(t, inputDir, "profile.json",
		`{"controller":"http://127.0.0.1:1","group":"G","routes":{"a_reality":"A"}}`)
	secret := writeTestFile(t, inputDir, "secret", "synthetic-secret\n")

	if _, enabled, err := loadWindowsR1Observer(stateDir); err != nil || enabled {
		t.Fatalf("default R1 state = enabled=%v err=%v, want disabled", enabled, err)
	}
	// Legacy environment switches cannot enable R1 without the protected bundle.
	t.Setenv("UM_AGENT_WINDOWS_OBSERVE_PROFILE", profile)
	t.Setenv("UM_AGENT_WINDOWS_OBSERVE_SECRET_FILE", secret)
	t.Setenv("UM_AGENT_WINDOWS_SOURCE_AUTHORIZED", "1")
	if _, enabled, err := loadWindowsR1Observer(stateDir); err != nil || enabled {
		t.Fatalf("environment-only R1 state = enabled=%v err=%v, want disabled", enabled, err)
	}

	if err := provisionWindowsR1(stateDir, profile, secret, "OD-P3-R1/isolated-lab/2026-11-27"); err != nil {
		t.Fatalf("provisionWindowsR1: %v", err)
	}
	observer, enabled, err := loadWindowsR1Observer(stateDir)
	if err != nil || !enabled || observer == nil {
		t.Fatalf("provisioned R1 = observer=%v enabled=%v err=%v", observer, enabled, err)
	}
	col, err := platformCollector(commonFlags{stateDir: stateDir})
	if err != nil || col == nil {
		t.Fatalf("platformCollector with R1: %v", err)
	}

	// Any accepted file mutation is a hash mismatch and must fail closed.
	profilePath := filepath.Join(r1Dir(stateDir), r1ProfileFile)
	if err := os.WriteFile(profilePath, []byte(`{"controller":"http://127.0.0.1:1","group":"G","routes":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadWindowsR1Observer(stateDir); err == nil {
		t.Fatal("tampered R1 profile accepted")
	}
}

func TestWindowsR1ScopeMustBeIsolatedLab(t *testing.T) {
	inputDir := t.TempDir()
	stateDir := t.TempDir()
	profile := writeTestFile(t, inputDir, "profile.json",
		`{"controller":"http://127.0.0.1:1","group":"G","routes":{"a_reality":"A"}}`)
	secret := writeTestFile(t, inputDir, "secret", "synthetic-secret\n")
	if err := provisionWindowsR1(stateDir, profile, secret, "OD-P3-R1/test"); err != nil {
		t.Fatal(err)
	}
	acceptPath := filepath.Join(r1Dir(stateDir), r1AcceptanceFile)
	raw, err := os.ReadFile(acceptPath)
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), `"scope": "isolated_lab"`, `"scope": "production"`, 1))
	if err := os.WriteFile(acceptPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadWindowsR1Observer(stateDir); err == nil {
		t.Fatal("production-scope R1 bundle accepted without separate authorization")
	}
}

func TestWindowsSourceFilesRejectInvalidInput(t *testing.T) {
	dir := t.TempDir()
	empty := writeTestFile(t, dir, "empty", "")
	if _, err := readWindowsSecret(empty); err == nil {
		t.Fatal("empty secret accepted")
	}
	tooLarge := writeTestFile(t, dir, "large", string(make([]byte, 5000)))
	if _, err := readWindowsSecret(tooLarge); err == nil {
		t.Fatal("oversized secret accepted")
	}
	badProfile := writeTestFile(t, dir, "bad-profile", `{"unknown":true}`)
	if _, err := readWindowsProfile(badProfile); err == nil {
		t.Fatal("unknown profile field accepted")
	}
}

//go:build windows

package main

import (
	"os"
	"path/filepath"
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

func TestWindowsSourceAuthorizationGate(t *testing.T) {
	dir := t.TempDir()
	profile := writeTestFile(t, dir, "profile.json",
		`{"controller":"http://127.0.0.1:1","group":"G","routes":{"a_reality":"A"}}`)
	secret := writeTestFile(t, dir, "secret", "synthetic-secret\n")

	t.Setenv("UM_AGENT_WINDOWS_OBSERVE_PROFILE", "")
	t.Setenv("UM_AGENT_WINDOWS_OBSERVE_SECRET_FILE", "")
	t.Setenv("UM_AGENT_WINDOWS_SOURCE_AUTHORIZED", "")
	if _, err := platformCollector(commonFlags{}); err != nil {
		t.Fatalf("default collector should be available: %v", err)
	}

	t.Setenv("UM_AGENT_WINDOWS_OBSERVE_PROFILE", profile)
	t.Setenv("UM_AGENT_WINDOWS_OBSERVE_SECRET_FILE", secret)
	t.Setenv("UM_AGENT_WINDOWS_SOURCE_AUTHORIZED", "")
	if _, err := platformCollector(commonFlags{}); err == nil {
		t.Fatal("R1 source was accepted without an authorization gate")
	}

	t.Setenv("UM_AGENT_WINDOWS_SOURCE_AUTHORIZED", "true")
	col, err := platformCollector(commonFlags{})
	if err != nil {
		t.Fatalf("authorized synthetic observer rejected: %v", err)
	}
	if col == nil {
		t.Fatal("nil collector")
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

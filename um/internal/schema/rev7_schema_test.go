package schema

import (
	"path/filepath"
	"testing"
)

// TestRev7OverlayCompilesAndValidatesFixtures exercises the additive rev-7
// contract package in its own directory. Keeping the overlay in a subdirectory
// means the frozen rev-5 top-level schema set (and every rev-5 consumer) remains
// byte- and count-compatible; rev-7-aware centers load this overlay explicitly.
func TestRev7OverlayCompilesAndValidatesFixtures(t *testing.T) {
	dir := filepath.Join(contractsDir, "rev7")
	set, err := Load(dir)
	if err != nil {
		t.Fatalf("Load(%q): %v", dir, err)
	}
	if !set.Has("report-snapshot.schema.json") || !set.Has("agent-config.schema.json") {
		t.Fatalf("rev-7 overlay schemas missing: %v", set.Names())
	}
	cases := []struct {
		schema string
		file   string
	}{
		{"report-snapshot.schema.json", "examples/report-snapshot.json"},
		{"agent-config.schema.json", "examples/agent-config.json"},
	}
	for _, tc := range cases {
		body := readFile(t, filepath.Join(dir, filepath.FromSlash(tc.file)))
		if err := set.Validate(tc.schema, body); err != nil {
			t.Fatalf("valid rev-7 fixture %s rejected by %s: %v", tc.file, tc.schema, err)
		}
	}
}

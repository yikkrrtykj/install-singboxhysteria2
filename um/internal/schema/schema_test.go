package schema

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// contractsDir is the frozen rev-5 contract directory, package-relative:
// um/internal/schema + ../../../ = worktree root; then docs/um/contracts/v1.
const contractsDir = "../../../docs/um/contracts/v1"

// allSchemas is the frozen rev-5 schema set plus the additive rev-7 overlay
// schemas. The rev-5 files remain byte-frozen; rev-7 adds two standalone files.
var allSchemas = []string{
	"ack.schema.json",
	"agent-config.schema.json",
	"enroll-request.schema.json",
	"enroll-response.schema.json",
	"error.schema.json",
	"report-events.schema.json",
	"report-metrics.schema.json",
	"report-snapshot.schema.json",
	"rotate-request.schema.json",
	"rotate-response.schema.json",
	"agent-config.rev7.schema.json",
	"report-snapshot.rev7.schema.json",
}

func loadSet(t *testing.T) *Set {
	t.Helper()
	set, err := Load(contractsDir)
	if err != nil {
		t.Fatalf("Load(%q): %v", contractsDir, err)
	}
	return set
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	return body
}

func TestLoadCompilesAllTenSchemas(t *testing.T) {
	set := loadSet(t)

	names := set.Names()
	if len(names) != len(allSchemas) {
		t.Fatalf("compiled %d schemas, want %d: %v", len(names), len(allSchemas), names)
	}
	if !sort.StringsAreSorted(names) {
		t.Errorf("Names() is not sorted: %v", names)
	}
	for _, want := range allSchemas {
		if !set.Has(want) {
			t.Errorf("schema %q was not compiled; loaded: %v", want, names)
		}
		if set.schemas[want] == nil {
			t.Errorf("schema %q compiled to nil", want)
		}
	}
	if set.Dir() != contractsDir {
		t.Errorf("Dir() = %q, want %q", set.Dir(), contractsDir)
	}

	// Names() must be a defensive copy.
	names[0] = "mutated.schema.json"
	if got := set.Names()[0]; got == "mutated.schema.json" {
		t.Error("Names() exposes internal slice")
	}
}

func TestLoadRejectsMissingDirectory(t *testing.T) {
	if _, err := Load(filepath.Join(contractsDir, "does-not-exist")); err == nil {
		t.Fatal("Load() of a missing directory returned nil error")
	}
}

func TestValidateRejectsUnknownSchemaName(t *testing.T) {
	set := loadSet(t)
	if err := set.Validate("nope.schema.json", []byte(`{}`)); err == nil {
		t.Fatal("Validate() with an unknown schema name returned nil error")
	} else if !strings.Contains(err.Error(), "not loaded") {
		t.Errorf("unknown schema error = %v, want mention of not loaded", err)
	}
}

func TestValidatePositiveExamples(t *testing.T) {
	set := loadSet(t)
	cases := []struct {
		schema string
		file   string
	}{
		{"enroll-request.schema.json", "examples/enroll-request.v1.json"},
		{"enroll-response.schema.json", "examples/enroll-response.v1.json"},
		{"report-snapshot.schema.json", "examples/report-snapshot.v1.json"},
		{"report-snapshot.schema.json", "examples/terminal-snapshot.v1.json"},
		{"report-events.schema.json", "examples/report-events.v1.json"},
		{"report-metrics.schema.json", "examples/report-metrics.v1.json"},
		{"ack.schema.json", "examples/ack.v1.json"},
		{"agent-config.schema.json", "examples/agent-config.v1.json"},
		{"rotate-request.schema.json", "examples/rotate-request.v1.json"},
		{"rotate-response.schema.json", "examples/rotate-response.v1.json"},
		{"agent-config.rev7.schema.json", "examples/agent-config.rev7.json"},
		{"report-snapshot.rev7.schema.json", "examples/report-snapshot.rev7.json"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.schema+"/"+filepath.Base(tc.file), func(t *testing.T) {
			body := readFile(t, filepath.Join(contractsDir, filepath.FromSlash(tc.file)))
			if err := set.Validate(tc.schema, body); err != nil {
				t.Fatalf("valid example rejected by %s: %v", tc.schema, err)
			}
		})
	}

	// error.schema.json has no committed positive example file; exercise it with
	// a synthetic closed error body so all 10 schemas are positively validated.
	errorBody := []byte(`{"v":1,"error":"invalid_request","retryable":false,"server_time":1795622400}`)
	if err := set.Validate("error.schema.json", errorBody); err != nil {
		t.Fatalf("valid synthetic error body rejected: %v", err)
	}
}

func TestValidateRejectsSchemaNegativeExamples(t *testing.T) {
	set := loadSet(t)
	cases := []struct {
		schema string
		file   string
	}{
		{"enroll-request.schema.json", "examples/negative/enroll-request-signature-in-body.v1.json"},
		{"error.schema.json", "examples/negative/error-unknown-code.v1.json"},
		{"report-events.schema.json", "examples/negative/report-events-arbitrary-detail.v1.json"},
		{"report-events.schema.json", "examples/negative/report-events-free-text-detail.v1.json"},
		{"report-snapshot.schema.json", "examples/negative/report-snapshot-impossible-units.v1.json"},
		{"report-snapshot.schema.json", "examples/negative/terminal-raw-proxy-name.v1.json"},
		{"report-snapshot.schema.json", "examples/negative/terminal-unknown-route-token.v1.json"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(filepath.Base(tc.file), func(t *testing.T) {
			body := readFile(t, filepath.Join(contractsDir, filepath.FromSlash(tc.file)))
			if err := set.Validate(tc.schema, body); err == nil {
				t.Fatalf("negative example %q was accepted by %s", tc.file, tc.schema)
			}
		})
	}
}

// TestSchemaValidButRuntimeInvalidVectors pins the split of responsibility: the
// tampered rev-4 snapshot and the Windows by-route sum mismatch are structurally
// schema-valid; only runtime rules (signature/recovery and aggregate coherence)
// reject them elsewhere.
func TestSchemaValidButRuntimeInvalidVectors(t *testing.T) {
	set := loadSet(t)
	for _, file := range []string{
		"examples/negative/report-snapshot-tampered.v1.json",
		"examples/negative/terminal-by-route-sum-mismatch.v1.json",
	} {
		body := readFile(t, filepath.Join(contractsDir, filepath.FromSlash(file)))
		if err := set.Validate("report-snapshot.schema.json", body); err != nil {
			t.Fatalf("%s must be schema-valid (runtime-only rule), got: %v", file, err)
		}
	}
}

// TestValidationIsReal is the negative control proving this package performs
// actual JSON Schema validation: take a valid committed body, mutate required
// fields, and require rejection at every step.
func TestValidationIsReal(t *testing.T) {
	set := loadSet(t)
	valid := readFile(t, filepath.Join(contractsDir, "examples", "report-snapshot.v1.json"))
	if err := set.Validate("report-snapshot.schema.json", valid); err != nil {
		t.Fatalf("baseline valid body rejected: %v", err)
	}

	mutate := func(t *testing.T, fn func(map[string]any)) []byte {
		t.Helper()
		dec := json.NewDecoder(strings.NewReader(string(valid)))
		dec.UseNumber()
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			t.Fatalf("decode baseline: %v", err)
		}
		fn(doc)
		out, err := json.Marshal(doc)
		if err != nil {
			t.Fatalf("encode mutated body: %v", err)
		}
		return out
	}

	t.Run("missing required field collected_at", func(t *testing.T) {
		body := mutate(t, func(doc map[string]any) { delete(doc, "collected_at") })
		if err := set.Validate("report-snapshot.schema.json", body); err == nil {
			t.Fatal("missing required collected_at was accepted")
		}
	})
	t.Run("required field wrong type", func(t *testing.T) {
		body := mutate(t, func(doc map[string]any) { doc["collected_at"] = "1795622400" })
		if err := set.Validate("report-snapshot.schema.json", body); err == nil {
			t.Fatal("string collected_at was accepted")
		}
	})
	t.Run("wrong const discriminator", func(t *testing.T) {
		body := mutate(t, func(doc map[string]any) { doc["type"] = "metrics" })
		if err := set.Validate("report-snapshot.schema.json", body); err == nil {
			t.Fatal("type=metrics was accepted by the snapshot schema")
		}
	})
	t.Run("additional property", func(t *testing.T) {
		body := mutate(t, func(doc map[string]any) { doc["rogue"] = true })
		if err := set.Validate("report-snapshot.schema.json", body); err == nil {
			t.Fatal("additional top-level property was accepted")
		}
	})
	t.Run("pattern violation", func(t *testing.T) {
		body := mutate(t, func(doc map[string]any) { doc["report_id"] = "not-a-uuid" })
		if err := set.Validate("report-snapshot.schema.json", body); err == nil {
			t.Fatal("invalid report_id pattern was accepted")
		}
	})
	t.Run("impossible units negative baseline", func(t *testing.T) {
		body := mutate(t, func(doc map[string]any) {
			doc["system"].(map[string]any)["cpu_pct"] = json.Number("-1")
		})
		if err := set.Validate("report-snapshot.schema.json", body); err == nil {
			t.Fatal("negative cpu_pct was accepted")
		}
	})

	// Malformed JSON must be rejected as a parse failure, not accepted.
	if err := set.Validate("report-snapshot.schema.json", []byte(`{"v":1,`)); err == nil {
		t.Fatal("malformed JSON was accepted")
	}
}

func TestValidateFile(t *testing.T) {
	set := loadSet(t)
	path := filepath.Join(contractsDir, "examples", "ack.v1.json")
	if err := set.ValidateFile("ack.schema.json", path); err != nil {
		t.Fatalf("ValidateFile(valid): %v", err)
	}
	if err := set.ValidateFile("ack.schema.json", filepath.Join(contractsDir, "missing.json")); err == nil {
		t.Fatal("ValidateFile(missing) returned nil error")
	}
}

// TestValidateRejectsDuplicateJSONObjectKeys pins the strict-JSON grammar the
// wire contract requires. Duplicate member names are textually valid RFC 8259
// JSON that encoding/json silently overlays (last value wins), so two consumers
// could disagree about the same body; the frozen UM v1 contract forbids them.
func TestValidateRejectsDuplicateJSONObjectKeys(t *testing.T) {
	set := loadSet(t)

	t.Run("top-level duplicate", func(t *testing.T) {
		body := []byte(`{"v":1,"v":1,"error":"invalid_request","retryable":false,"server_time":1795622400}`)
		if err := set.Validate("error.schema.json", body); err == nil {
			t.Fatal("top-level duplicate member name was accepted")
		}
	})

	t.Run("nested duplicate", func(t *testing.T) {
		valid := string(readFile(t, filepath.Join(contractsDir, "examples", "report-snapshot.v1.json")))
		const anchor = `"host":{"os":"linux",`
		mutated := strings.Replace(valid, anchor, `"host":{"os":"linux","os":"windows",`, 1)
		if mutated == valid {
			t.Fatalf("test setup: nested anchor %q not found", anchor)
		}
		if err := set.Validate("report-snapshot.schema.json", []byte(mutated)); err == nil {
			t.Fatal("nested duplicate member name was accepted")
		}
	})
}

// TestValidateRejectsTrailingDataButAllowsTrailingWhitespace pins the
// single-top-level-value rule: whitespace around the value is fine, any further
// bytes are not.
func TestValidateRejectsTrailingDataButAllowsTrailingWhitespace(t *testing.T) {
	set := loadSet(t)
	valid := []byte(`{"v":1,"error":"invalid_request","retryable":false,"server_time":1795622400}`)
	if err := set.Validate("error.schema.json", valid); err != nil {
		t.Fatalf("baseline valid error body rejected: %v", err)
	}

	withWhitespace := append(append([]byte{}, valid...), []byte("\n\t  \r\n")...)
	if err := set.Validate("error.schema.json", withWhitespace); err != nil {
		t.Fatalf("trailing whitespace was rejected: %v", err)
	}

	for _, trailing := range []string{" {}", "{}", "x", " 0", "null"} {
		body := append(append([]byte{}, valid...), []byte(trailing)...)
		if err := set.Validate("error.schema.json", body); err == nil {
			t.Fatalf("trailing data %q was accepted", trailing)
		}
	}
}

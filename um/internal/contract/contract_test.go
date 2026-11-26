package contract

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/schema"
)

// testContractsDir is the frozen rev-5 contract directory, package-relative:
// um/internal/contract + ../../../ = worktree root; then docs/um/contracts/v1.
const testContractsDir = "../../../docs/um/contracts/v1"

const (
	terminalSnapshotExample = "examples/terminal-snapshot.v1.json"
	linuxSnapshotExample    = "examples/report-snapshot.v1.json"
	linuxMetricsExample     = "examples/report-metrics.v1.json"
	linuxEventsExample      = "examples/report-events.v1.json"
)

func readExample(t *testing.T, rel string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(testContractsDir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read example %q: %v", rel, err)
	}
	return body
}

func decodeJSONObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var doc map[string]any
	if err := decoder.Decode(&doc); err != nil {
		t.Fatalf("decode object: %v", err)
	}
	return doc
}

func encodeJSONObject(t *testing.T, doc map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("encode object: %v", err)
	}
	return raw
}

// mutateExample reads a committed example, mutates the decoded object and
// re-encodes it.
func mutateExample(t *testing.T, rel string, mutate func(doc map[string]any)) []byte {
	t.Helper()
	doc := decodeJSONObject(t, readExample(t, rel))
	mutate(doc)
	return encodeJSONObject(t, doc)
}

// objectAt walks nested objects and fails the test when the path is not an
// object.
func objectAt(t *testing.T, doc map[string]any, keys ...string) map[string]any {
	t.Helper()
	current := doc
	for _, key := range keys {
		next, ok := current[key].(map[string]any)
		if !ok {
			t.Fatalf("path %v: %q is %T, want object", keys, key, current[key])
		}
		current = next
	}
	return current
}

func requireInvalidRequest(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a validation error, got nil")
	}
	if !IsInvalidRequest(err) {
		t.Fatalf("expected invalid_request, got %v", err)
	}
}

func requirePlatformMismatch(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a validation error, got nil")
	}
	if !IsPlatformMismatch(err) {
		t.Fatalf("expected platform_mismatch, got %v", err)
	}
}

// requireField checks the stable error field so tests pin which rule fired.
func requireField(t *testing.T, err error, want string) {
	t.Helper()
	var contractErr *Error
	if !errors.As(err, &contractErr) {
		t.Fatalf("expected *contract.Error, got %T %v", err, err)
	}
	if contractErr.Field != want {
		t.Fatalf("error field = %q, want %q (error: %v)", contractErr.Field, want, err)
	}
}

func TestErrorFormattingAndHelpers(t *testing.T) {
	err := &Error{Code: CodeInvalidRequest, Field: "terminal.selection.route", Detail: "boom"}
	if got, want := err.Error(), "invalid_request (terminal.selection.route): boom"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if !IsInvalidRequest(err) {
		t.Error("IsInvalidRequest() = false for invalid_request")
	}
	if IsPlatformMismatch(err) {
		t.Error("IsPlatformMismatch() = true for invalid_request")
	}

	mismatchErr := &Error{Code: CodePlatformMismatch, Field: "terminal", Detail: "no"}
	if !IsPlatformMismatch(mismatchErr) {
		t.Error("IsPlatformMismatch() = false for platform_mismatch")
	}
	if IsInvalidRequest(mismatchErr) {
		t.Error("IsInvalidRequest() = true for platform_mismatch")
	}

	// Helpers must unwrap wrapped errors.
	wrapped := fmt.Errorf("ingest: %w", mismatchErr)
	if !IsPlatformMismatch(wrapped) {
		t.Error("IsPlatformMismatch() = false for wrapped platform_mismatch")
	}
	if IsPlatformMismatch(nil) || IsInvalidRequest(nil) {
		t.Error("helpers must return false for nil error")
	}
	if IsInvalidRequest(errors.New("other")) {
		t.Error("IsInvalidRequest() = true for unrelated error")
	}
}

func TestValidateReportBodySnapshotDispatch(t *testing.T) {
	if err := ValidateReportBody(NodeClassLinuxVPS, ReportTypeSnapshot, readExample(t, linuxSnapshotExample)); err != nil {
		t.Fatalf("linux snapshot rejected via ValidateReportBody: %v", err)
	}
	if err := ValidateReportBody(NodeClassWindowsTerminal, ReportTypeSnapshot, readExample(t, terminalSnapshotExample)); err != nil {
		t.Fatalf("windows terminal snapshot rejected via ValidateReportBody: %v", err)
	}
	// Body/type mismatch is caught by the schema's const discriminator.
	requireInvalidRequest(t, ValidateReportBody(NodeClassLinuxVPS, ReportTypeSnapshot, readExample(t, linuxMetricsExample)))
}

func TestValidateReportBodyMetrics(t *testing.T) {
	if err := ValidateReportBody(NodeClassLinuxVPS, ReportTypeMetrics, readExample(t, linuxMetricsExample)); err != nil {
		t.Fatalf("linux metrics rejected: %v", err)
	}
	// Windows terminal metrics are deferred in v1 -> platform_mismatch.
	requirePlatformMismatch(t, ValidateReportBody(NodeClassWindowsTerminal, ReportTypeMetrics, readExample(t, linuxMetricsExample)))
	// Unknown class -> invalid_request.
	requireInvalidRequest(t, ValidateReportBody("macos", ReportTypeMetrics, readExample(t, linuxMetricsExample)))
	// Malformed metrics body for a valid class -> invalid_request.
	requireInvalidRequest(t, ValidateReportBody(NodeClassLinuxVPS, ReportTypeMetrics, []byte(`{"v":1}`)))
}

func TestValidateReportBodyEvents(t *testing.T) {
	if err := ValidateReportBody(NodeClassLinuxVPS, ReportTypeEvents, readExample(t, linuxEventsExample)); err != nil {
		t.Fatalf("linux events rejected: %v", err)
	}

	// Generic agent kind is allowed for windows_terminal.
	generic := []byte(`{"v":1,"type":"events","report_id":"3c8f5d7b-0e2a-4b4c-9d6f-1a3e5b7c9d02","collected_at":1795622400,"events":[{"event_id":"6d1a9b3e-7c2f-4e8a-a5b0-9c3d1e7f2a64","at":1795622300,"kind":"agent_started","severity":"info","detail":{"agent_version":"1.0.0"}}]}`)
	if err := ValidateReportBody(NodeClassWindowsTerminal, ReportTypeEvents, generic); err != nil {
		t.Fatalf("windows generic event rejected: %v", err)
	}

	// Windows-only terminal kind is allowed for windows_terminal.
	terminalEvent := []byte(`{"v":1,"type":"events","report_id":"3c8f5d7b-0e2a-4b4c-9d6f-1a3e5b7c9d02","collected_at":1795622400,"events":[{"event_id":"6d1a9b3e-7c2f-4e8a-a5b0-9c3d1e7f2a64","at":1795622300,"kind":"terminal_route_changed","severity":"info","detail":{"previous_route":"unknown","current_route":"a_reality","sampled_at":1795622290}}]}`)
	if err := ValidateReportBody(NodeClassWindowsTerminal, ReportTypeEvents, terminalEvent); err != nil {
		t.Fatalf("windows terminal event rejected: %v", err)
	}

	// Linux-only server kinds are a platform mismatch for windows_terminal.
	requirePlatformMismatch(t, ValidateReportBody(NodeClassWindowsTerminal, ReportTypeEvents, readExample(t, linuxEventsExample)))

	// Terminal kinds are a platform mismatch for linux_vps.
	linuxWithTerminalKind := mutateExample(t, linuxEventsExample, func(doc map[string]any) {
		events := doc["events"].([]any)
		event := events[0].(map[string]any)
		event["kind"] = "terminal_source_unavailable"
		event["detail"] = map[string]any{"source": "mihomo_api", "reason_code": "controller_unreachable"}
	})
	requirePlatformMismatch(t, ValidateReportBody(NodeClassLinuxVPS, ReportTypeEvents, linuxWithTerminalKind))

	// Unknown class and malformed body.
	requireInvalidRequest(t, ValidateReportBody("", ReportTypeEvents, terminalEvent))
	requireInvalidRequest(t, ValidateReportBody(NodeClassLinuxVPS, ReportTypeEvents, []byte(`{"v":1}`)))
}

func TestValidateReportBodyUnknownType(t *testing.T) {
	requireInvalidRequest(t, ValidateReportBody(NodeClassLinuxVPS, "ack", []byte(`{"v":1}`)))
	requireInvalidRequest(t, ValidateReportBody(NodeClassLinuxVPS, "", []byte(`{}`)))
}

// TestSchemaStageRejectsTerminalShapeViolations proves that the two committed
// negative examples are rejected by JSON Schema itself (the first stage), and
// that ValidateSnapshot surfaces them as invalid_request.
func TestSchemaStageRejectsTerminalShapeViolations(t *testing.T) {
	set, err := schema.Load(testContractsDir)
	if err != nil {
		t.Fatalf("schema.Load(%q): %v", testContractsDir, err)
	}

	cases := []string{
		"examples/negative/terminal-unknown-route-token.v1.json",
		"examples/negative/terminal-raw-proxy-name.v1.json",
	}
	for _, file := range cases {
		file := file
		t.Run(filepath.Base(file), func(t *testing.T) {
			raw := readExample(t, file)
			if err := set.Validate("report-snapshot.schema.json", raw); err == nil {
				t.Fatalf("%s was accepted by the JSON Schema", file)
			}
			requireInvalidRequest(t, ValidateSnapshot(NodeClassWindowsTerminal, raw))
		})
	}
}

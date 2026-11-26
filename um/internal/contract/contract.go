// Package contract enforces the runtime semantics of the frozen Unified
// Monitor v1 node protocol (revision 5) that JSON Schema cannot express:
// platform isolation between linux_vps and windows_terminal nodes, the Windows
// terminal route/connection coherence and sampling-window rules, the report-body
// allowlists per node class, and the privacy sentinel boundary.
//
// Structural validation is delegated to internal/schema, which compiles the
// committed docs/um/contracts/v1/*.schema.json files from disk at runtime.
package contract

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/schema"
)

// Error codes produced by this package. They are members of the frozen
// error.schema.json enum.
const (
	CodeInvalidRequest   = "invalid_request"
	CodePlatformMismatch = "platform_mismatch"
)

// Node classes bound at enrollment.
const (
	NodeClassLinuxVPS        = "linux_vps"
	NodeClassWindowsTerminal = "windows_terminal"
)

// Report body types accepted by the frozen report schemas.
const (
	ReportTypeSnapshot = "snapshot"
	ReportTypeMetrics  = "metrics"
	ReportTypeEvents   = "events"
)

// Frozen contract schema file names.
const (
	snapshotSchemaFile = "report-snapshot.schema.json"
	metricsSchemaFile  = "report-metrics.schema.json"
	eventsSchemaFile   = "report-events.schema.json"
)

// Error is a runtime contract violation.
//
// Field is a stable, non-secret location such as "terminal.selection.route" or
// "availability.system"; Detail never contains the offending value, so privacy
// sentinels are neither logged nor echoed to the peer.
type Error struct {
	Code   string
	Field  string
	Detail string
}

// Error implements the error interface as "code (field): detail".
func (e *Error) Error() string {
	return fmt.Sprintf("%s (%s): %s", e.Code, e.Field, e.Detail)
}

// IsPlatformMismatch reports whether err is a platform-isolation violation
// (error code platform_mismatch). It unwraps wrapped errors.
func IsPlatformMismatch(err error) bool { return errorCode(err) == CodePlatformMismatch }

// IsInvalidRequest reports whether err is a runtime invalid_request violation.
// It unwraps wrapped errors.
func IsInvalidRequest(err error) bool { return errorCode(err) == CodeInvalidRequest }

func errorCode(err error) string {
	var contractErr *Error
	if errors.As(err, &contractErr) {
		return contractErr.Code
	}
	return ""
}

func invalid(field, detail string) error {
	return &Error{Code: CodeInvalidRequest, Field: field, Detail: detail}
}

func mismatch(field, detail string) error {
	return &Error{Code: CodePlatformMismatch, Field: field, Detail: detail}
}

var (
	schemaOnce   sync.Once
	schemaSet    *schema.Set
	schemaSetErr error
)

// validateSchema runs the frozen JSON Schema name against raw. The underlying
// validator text is intentionally discarded: jsonschema quotes offending
// instance values in some errors, and terminal payloads must never echo privacy
// sentinels.
func validateSchema(name string, raw []byte) error {
	set, err := loadSchemas()
	if err != nil {
		return err
	}
	if err := set.Validate(name, raw); err != nil {
		return invalid("body", "body does not conform to "+name)
	}
	return nil
}

func loadSchemas() (*schema.Set, error) {
	schemaOnce.Do(func() {
		schemaSet, schemaSetErr = schema.Load(contractsDir())
	})
	if schemaSetErr != nil {
		return nil, fmt.Errorf("contract: load frozen schemas: %w", schemaSetErr)
	}
	return schemaSet, nil
}

// contractsDir resolves the frozen contract directory relative to this source
// file, so validation works regardless of the process working directory. The
// directory is read from disk at runtime; no schemas are embedded.
//
// It is um/internal/contract + ../../../docs/um/contracts/v1. UM_CONTRACTS_DIR
// overrides the location for deployment layouts that move the schema files.
func contractsDir() string {
	if dir := os.Getenv("UM_CONTRACTS_DIR"); dir != "" {
		return dir
	}
	if _, file, _, ok := runtime.Caller(0); ok {
		dir := filepath.Join(filepath.Dir(file), "..", "..", "..", "docs", "um", "contracts", "v1")
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			return dir
		}
	}
	return filepath.Join("..", "..", "..", "docs", "um", "contracts", "v1")
}

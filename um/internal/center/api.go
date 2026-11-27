// Package center implements the UM v1 center machine-ingress HTTP boundary:
// the four frozen node endpoints on an isolated ingest listener, the isolated
// admin listener, strict raw-header cardinality, content-encoding consistency,
// bounded body decoding and the closed error/success JSON contract of
// docs/um/um-a/04-node-protocol-v1.md §1–§8.
//
// The HTTP boundary is deliberately free of database, replay, nonce, boot and
// signature-verification state: it validates the wire envelope and delegates
// all authenticated identity decisions to a Service implementation (the parent
// UM-B2 service wires the real SQLite store and Ed25519 verification). It never
// echoes a decoder, validator or service error string, because those can carry
// payload bytes, paths or secrets.
package center

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/schema"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/wire"
)

// Frozen body and response caps from docs/um/um-a/04-node-protocol-v1.md §1:
// compressed ≤256 KiB, decoded ≤128 KiB, enrollment ≤8 KiB, config response
// ≤16 KiB. They are the defaults used when Config leaves a cap at zero.
const (
	DefaultMaxCompressedBody int64 = 256 << 10
	DefaultMaxDecodedBody    int64 = 128 << 10
	DefaultMaxEnrollBody     int64 = 8 << 10
	DefaultMaxConfigResponse int64 = 16 << 10
	// DefaultMaxResponseBody bounds every JSON response the boundary itself
	// serializes; the frozen schemas bound the fields well below this, so the
	// cap is defense in depth against a misbehaving Service.
	DefaultMaxResponseBody int64 = 64 << 10
)

// Per-IP ingest rate limiting defaults. The contract lists 429 rate_limited for
// unauthenticated floods; the boundary applies a bounded token bucket before any
// expensive parsing. Config.RateLimitPerSecond / RateLimitBurst override them.
const (
	DefaultRateLimitPerSecond    = 100
	DefaultRateLimitBurst        = 200
	maxRateLimitBuckets          = 4096
	minRetryAfterSeconds         = 1
	DefaultMaxConcurrentRequests = 256
)

// ContractSchemaNames is the frozen rev-5 schema set the center insists on at
// startup: exactly the ten files under docs/um/contracts/v1 (and any deployment
// copy of it). LoadContracts fails if one is missing, because a center that
// silently accepts a partial contract set could never validate a request or
// response body.
var ContractSchemaNames = []string{
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
}

// Config configures one center instance. Addresses, DBPath and ContractDir are
// required; the caps and clock fall back to the frozen defaults.
type Config struct {
	// IngestAddr is the machine-ingress listener address, for example
	// "127.0.0.1:0". The ingest plane serves only /v1/agent/*.
	IngestAddr string
	// AdminAddr is the separate admin listener address, for example
	// "127.0.0.1:0". It never serves /v1/agent/*.
	AdminAddr string
	// DBPath is the center database path. The HTTP boundary does not open it;
	// the Service owns persistence. It is required so a misconfigured center
	// fails at startup instead of running without durable state.
	DBPath string
	// ContractDir is the explicit trusted deployment path of the frozen
	// docs/um/contracts/v1 schema files. There is no cwd or package-relative
	// fallback: an empty value is a configuration error.
	ContractDir string

	// MaxCompressedBody caps the on-the-wire request body (default 256 KiB).
	MaxCompressedBody int64
	// MaxDecodedBody caps the decoded request body (default 128 KiB).
	MaxDecodedBody int64
	// MaxEnrollBody caps the decoded enrollment body (default 8 KiB).
	MaxEnrollBody int64

	// Now is the optional test clock. nil means time.Now. It is also the source
	// of the server_time carried by every boundary-generated error body.
	Now func() time.Time

	// RateLimitPerSecond is the per-IP ingest token refill rate. Zero uses
	// DefaultRateLimitPerSecond; a negative value disables rate limiting
	// (intended for tests only).
	RateLimitPerSecond float64
	// RateLimitBurst is the per-IP token bucket depth. Zero uses
	// DefaultRateLimitBurst.
	RateLimitBurst int

	// MaxConcurrentRequests bounds in-flight ingest handlers. Zero uses
	// DefaultMaxConcurrentRequests; a negative value disables the bound for tests.
	MaxConcurrentRequests int

	// AdminAPI is the optional B4 management handler mounted on the isolated
	// admin listener under /api/v1/*. It is nil for the B2 health-only center;
	// when non-nil it owns authentication and RBAC. The ingest handler never
	// receives this field and the admin listener never serves /v1/agent/*.
	AdminAPI http.Handler
}

// withDefaults returns a copy with every unset optional field filled in. It does
// not validate the required fields.
func (c Config) withDefaults() Config {
	if c.MaxCompressedBody == 0 {
		c.MaxCompressedBody = DefaultMaxCompressedBody
	}
	if c.MaxDecodedBody == 0 {
		c.MaxDecodedBody = DefaultMaxDecodedBody
	}
	if c.MaxEnrollBody == 0 {
		c.MaxEnrollBody = DefaultMaxEnrollBody
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.RateLimitPerSecond == 0 {
		c.RateLimitPerSecond = DefaultRateLimitPerSecond
	}
	if c.RateLimitBurst == 0 {
		c.RateLimitBurst = DefaultRateLimitBurst
	}
	if c.MaxConcurrentRequests == 0 {
		c.MaxConcurrentRequests = DefaultMaxConcurrentRequests
	}
	return c
}

// Validate checks required fields and rejects nonsensical caps. A zero optional
// cap means "use the frozen default", not an error. Contract contents are
// checked by LoadContracts (and therefore NewServer), not here.
func (c Config) Validate() error {
	if strings.TrimSpace(c.IngestAddr) == "" {
		return errors.New("center: IngestAddr is required")
	}
	if _, _, err := net.SplitHostPort(c.IngestAddr); err != nil {
		return fmt.Errorf("center: IngestAddr is not host:port: %w", err)
	}
	if strings.TrimSpace(c.AdminAddr) == "" {
		return errors.New("center: AdminAddr is required")
	}
	if _, _, err := net.SplitHostPort(c.AdminAddr); err != nil {
		return fmt.Errorf("center: AdminAddr is not host:port: %w", err)
	}
	if strings.TrimSpace(c.DBPath) == "" {
		return errors.New("center: DBPath is required")
	}
	if strings.TrimSpace(c.ContractDir) == "" {
		return errors.New("center: ContractDir is required (explicit trusted path, no cwd fallback)")
	}
	if c.MaxCompressedBody < 0 {
		return errors.New("center: MaxCompressedBody must not be negative")
	}
	if c.MaxDecodedBody < 0 {
		return errors.New("center: MaxDecodedBody must not be negative")
	}
	if c.MaxEnrollBody < 0 {
		return errors.New("center: MaxEnrollBody must not be negative")
	}
	if c.MaxEnrollBody > 0 && c.MaxDecodedBody > 0 && c.MaxEnrollBody > c.MaxDecodedBody {
		return errors.New("center: MaxEnrollBody must not exceed MaxDecodedBody")
	}
	if c.RateLimitBurst < 0 {
		return errors.New("center: RateLimitBurst must not be negative")
	}
	return nil
}

// LoadContracts loads and compiles the frozen contract schemas from the
// explicit ContractDir and verifies that all ten rev-5 schemas are present.
// schema.Load already compiles each file (draft 2020-12), so a returned Set is
// prevalidated; a deployment with a missing or uncompilable schema fails here.
func (c Config) LoadContracts() (*schema.Set, error) {
	dir := strings.TrimSpace(c.ContractDir)
	if dir == "" {
		return nil, errors.New("center: ContractDir is required")
	}
	set, err := schema.Load(dir)
	if err != nil {
		return nil, fmt.Errorf("center: load contracts: %w", err)
	}
	var missing []string
	for _, name := range ContractSchemaNames {
		if !set.Has(name) {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("center: contract dir %q is missing required rev-5 schemas: %s",
			dir, strings.Join(missing, ", "))
	}
	return set, nil
}

// APIError is a Service-originated failure already expressed in the frozen
// contract vocabulary (error.schema.json). The boundary maps it to the given
// HTTP status and retryable flag; it never adds the Go error text to the body.
type APIError struct {
	Status    int
	Code      string
	Retryable bool
}

// NewAPIError constructs an APIError. Callers are expected to pass one of the
// status/error pairs frozen in docs/um/um-a/04-node-protocol-v1.md §8.
func NewAPIError(status int, code string, retryable bool) *APIError {
	return &APIError{Status: status, Code: code, Retryable: retryable}
}

// Error implements error without echoing anything user- or peer-controlled.
func (e *APIError) Error() string {
	if e == nil {
		return "center: nil APIError"
	}
	return fmt.Sprintf("center: api error status=%d code=%s retryable=%t", e.Status, e.Code, e.Retryable)
}

// errorCodeSet is the closed rev-5 error vocabulary (error.schema.json enum).
var errorCodeSet = map[string]struct{}{
	"invalid_request": {}, "method_not_allowed": {}, "endpoint_not_found": {},
	"missing_header": {}, "duplicate_header": {}, "invalid_header": {},
	"unsupported_encoding": {}, "unauthorized": {}, "unknown_node": {},
	"revoked_key": {}, "bad_signature": {}, "stale_timestamp": {},
	"replay": {}, "nonce_reuse": {}, "sequence_conflict": {},
	"identity_mismatch": {}, "report_conflict": {}, "token_invalid": {},
	"token_expired": {}, "token_used": {}, "token_scope_mismatch": {},
	"rate_limited": {}, "payload_too_large": {}, "unsupported_version": {},
	"upgrade_required": {}, "storage_unavailable": {}, "rotation_in_progress": {},
	"rotation_expired": {}, "stale_boot_generation": {}, "boot_identity_conflict": {},
	"platform_mismatch": {},
}

// IsClosedErrorCode reports whether code is a member of the frozen error enum.
func IsClosedErrorCode(code string) bool {
	_, ok := errorCodeSet[code]
	return ok
}

// errorBody is the frozen error.schema.json shape. Field order is cosmetic but
// kept stable for deterministic tests.
type errorBody struct {
	V          int    `json:"v"`
	Error      string `json:"error"`
	Retryable  bool   `json:"retryable"`
	ServerTime int64  `json:"server_time"`
}

// ErrorResponse maps any error to the frozen error body and HTTP status. It
// never includes err.Error(): service, decoder and validator text is untrusted
// and could contain payload bytes, paths or secrets.
//
//   - *APIError (also wrapped) with a closed-vocabulary code and a 4xx/5xx
//     status is used verbatim.
//   - context cancellation/deadline expiry is 503 storage_unavailable retryable.
//   - anything else (including a malformed *APIError) is 503 storage_unavailable
//     retryable.
//
// The returned body is always valid error.schema.json.
func ErrorResponse(err error, now int64) (status int, body []byte) {
	status = 503
	code := "storage_unavailable"
	retryable := true

	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr != nil &&
		apiErr.Status >= 400 && apiErr.Status <= 599 &&
		IsClosedErrorCode(apiErr.Code) {
		status = apiErr.Status
		code = apiErr.Code
		retryable = apiErr.Retryable
	} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		// context cancellation is transient storage/service unavailability from
		// the peer's point of view; never a 500 with internal text.
		status = 503
		code = "storage_unavailable"
		retryable = true
	}
	if now < 0 {
		now = 0
	}
	body, _ = json.Marshal(errorBody{V: 1, Error: code, Retryable: retryable, ServerTime: now})
	return status, body
}

// Request/result types shared by the HTTP boundary and the Service.
//
// Every request carries the exact signed header values (wire.Fields), the
// decoded body bytes (the bytes the signature covers), their SHA-256 in
// lowercase hex, the raw X-UM-Signature tag and the boundary's request-time
// clock. The Service owns signature verification (enroll against
// Fields.PublicKey, the other endpoints against the key named by Fields.KeyID),
// freshness, nonce/seq/boot/replay state and all store transactions.
//
// The Signature field is an additive extension to the frozen boundary slice
// requested for this package: without it a Service could not verify the Ed25519
// signature because wire.Fields deliberately excludes the signature tag.
type EnrollRequest struct {
	Fields     wire.Fields
	Token      string
	Body       []byte
	BodySHA256 string
	Signature  string
	Now        int64
}

// EnrollResult is the service result for one committed enrollment.
type EnrollResult struct {
	NodeID           string
	EventID          string
	NodeClass        string
	KeyID            string
	DeviceSalt       string
	ConfigVersion    int
	CadenceSeconds   int
	ServerTime       int64
	CenterSPKISHA256 string
}

// ReportRequest is one authenticated report attempt.
type ReportRequest struct {
	Fields      wire.Fields
	Body        []byte
	BodySHA256  string
	Signature   string
	ReportType  string
	ReportID    string
	CollectedAt int64
	Now         int64
	Fingerprint string
}

// ReportResult is the service decision for one report attempt.
//
// RetryAfterS is optional: nil means JSON null (ack.schema.json's
// retry_after_s accepts only null or 1..3600). A non-positive value is also
// written as null; a value above 3600 fails ACK schema validation and becomes
// 503 storage_unavailable (a Service bug, never a malformed 200).
type ReportResult struct {
	ReportID      string
	Result        string
	NextSeq       *uint64
	ConfigVersion int
	ServerTime    int64
	RetryAfterS   *int
}

// RotateRequest is one rotation attempt signed with the old key.
type RotateRequest struct {
	Fields      wire.Fields
	Body        []byte
	BodySHA256  string
	Signature   string
	Now         int64
	Fingerprint string
}

// RotateResult is the persisted rotation response replayed or created by the
// Service. The response's node_id is the authenticated request node id.
//
// Response is the optional exact persisted rotate-response bytes for idempotent
// replay: when non-empty the boundary schema-validates and writes those bytes
// verbatim (so a replay is byte-identical), and the fields below are ignored.
// When empty the boundary builds the documented JSON from the fields.
type RotateResult struct {
	PreviousKeyID string
	NewKeyID      string
	ConfigVersion int
	ServerTime    int64
	Response      []byte
}

// ConfigRequest is one config pull. The request body is exactly the two bytes
// "{}"; the boundary enforces that before calling the Service.
type ConfigRequest struct {
	Fields      wire.Fields
	Body        []byte
	BodySHA256  string
	Signature   string
	Now         int64
	Fingerprint string
}

// ConfigResult carries the complete agent-config response body. The Service
// must return the full frozen agent-config.schema.json document including its
// own v/config_version/server_time; the boundary validates it and writes the
// bytes verbatim (it never re-serializes or injects fields), so a persisted
// config response is byte-stable across retries.
type ConfigResult struct {
	ConfigVersion int
	Body          []byte
	ServerTime    int64
}

// Service is the center business interface implemented by the real UM-B2
// service with the SQLite store. The boundary guarantees: exactly one request
// body, decoded bytes capped, strict JSON grammar, schema-valid request body,
// canonical envelope fields for reports, and the frozen endpoint path. The
// Service owns authentication (signature verification, freshness), enrollment
// token scope, replay/sequence/boot state, rotation state, store transactions
// and decides every frozen contract error returned as *APIError.
type Service interface {
	Enroll(ctx context.Context, req EnrollRequest) (EnrollResult, error)
	Report(ctx context.Context, req ReportRequest) (ReportResult, error)
	Rotate(ctx context.Context, req RotateRequest) (RotateResult, error)
	Config(ctx context.Context, req ConfigRequest) (ConfigResult, error)
}

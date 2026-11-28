package center

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/contract"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/schema"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/wire"
)

// Frozen contract schema file names used by the boundary. The Set is loaded and
// prevalidated once in NewServer; these constants are the only names the
// handlers reference.
const (
	schemaAck             = "ack.schema.json"
	schemaAgentConfig     = "agent-config.schema.json"
	schemaEnrollRequest   = "enroll-request.schema.json"
	schemaEnrollResponse  = "enroll-response.schema.json"
	schemaError           = "error.schema.json"
	schemaRotateRequest   = "rotate-request.schema.json"
	schemaRotateResponse  = "rotate-response.schema.json"
	schemaReportSnapshot  = "report-snapshot.schema.json"
	schemaReportMetrics   = "report-metrics.schema.json"
	schemaReportEvents    = "report-events.schema.json"
	configRequestBody     = "{}"
	maxConfigRequestBytes = 2
)

// ingestRoutes is the complete ingest surface: exactly four POST paths. There
// is no /api/* route, no revoke, no HTML, no redirect and no catch-all.
var ingestRoutes = map[string]wire.Endpoint{
	"/v1/agent/enroll": wire.Enroll,
	"/v1/agent/report": wire.Report,
	"/v1/agent/rotate": wire.Rotate,
	"/v1/agent/config": wire.Config,
}

// ingestResult is one successful boundary result ready for writeSuccess.
type ingestResult struct {
	body       []byte
	schemaName string
	maxBody    int64
}

// serveIngest applies the frozen boundary in order: path/method, rate limit,
// raw-header cardinality, Content-Type, signed-header grammar, encoding
// consistency, bounded decoding, config body shape, strict JSON, per-endpoint
// envelope/schema checks, Service call and finally the schema-validated
// success body.
func (s *Server) serveIngest(w http.ResponseWriter, r *http.Request) {
	endpoint, known := ingestRoutes[r.URL.Path]
	if !known {
		s.writeError(w, NewAPIError(http.StatusNotFound, "endpoint_not_found", false), 0)
		return
	}
	if r.Method != http.MethodPost {
		s.writeError(w, NewAPIError(http.StatusMethodNotAllowed, "method_not_allowed", false), 0)
		return
	}
	if allowed, retryAfter := s.limiter.allow(remoteIP(r)); !allowed {
		s.writeError(w, NewAPIError(http.StatusTooManyRequests, "rate_limited", true), retryAfter)
		return
	}
	idx, apiErr := indexHeaders(r.Header)
	if apiErr != nil {
		s.writeError(w, apiErr, 0)
		return
	}
	if apiErr := checkContentType(idx); apiErr != nil {
		s.writeError(w, apiErr, 0)
		return
	}
	fields, signature, apiErr := parseSignedFields(idx, endpoint)
	if apiErr != nil {
		s.writeError(w, apiErr, 0)
		return
	}
	if apiErr := checkEncodingConsistency(idx, fields); apiErr != nil {
		s.writeError(w, apiErr, 0)
		return
	}
	body, apiErr := s.readDecodedBody(r, fields.Encoding, endpoint)
	if apiErr != nil {
		s.writeError(w, apiErr, 0)
		return
	}
	if endpoint == wire.Config && !bytes.Equal(body, []byte(configRequestBody)) {
		s.writeError(w, invalidRequestError(), 0)
		return
	}
	if err := schema.CheckStrictJSON(body); err != nil {
		s.writeError(w, invalidRequestError(), 0)
		return
	}

	now := s.nowUnix()
	var result ingestResult
	switch endpoint {
	case wire.Enroll:
		result, apiErr = s.handleEnroll(r.Context(), idx, fields, signature, body, now)
	case wire.Report:
		result, apiErr = s.handleReport(r.Context(), fields, signature, body, now)
	case wire.Rotate:
		result, apiErr = s.handleRotate(r.Context(), fields, signature, body, now)
	case wire.Config:
		result, apiErr = s.handleConfig(r.Context(), fields, signature, body, now)
	}
	if apiErr != nil {
		// During shutdown the connection is going away; do not pretend the
		// request was answered by writing into a closing response.
		if s.shuttingDown.Load() && r.Context().Err() != nil {
			return
		}
		s.writeError(w, apiErr, 0)
		return
	}
	s.writeSuccess(w, result.body, result.schemaName, result.maxBody)
}

// handleEnroll validates the enrollment body schema, parses the one-time
// bootstrap token and calls the Service. Cryptography (the self-signed
// enrollment proof), token scope/expiry and the atomic commit are Service-owned.
func (s *Server) handleEnroll(ctx context.Context, idx *headerIndex, fields wire.Fields, signature string, body []byte, now int64) (ingestResult, *APIError) {
	if err := s.schemas.Validate(schemaEnrollRequest, body); err != nil {
		return ingestResult{}, invalidRequestError()
	}
	token, apiErr := parseBearerToken(idx)
	if apiErr != nil {
		return ingestResult{}, apiErr
	}
	result, err := s.svc.Enroll(ctx, EnrollRequest{
		Fields:     fields,
		Token:      token,
		Body:       body,
		BodySHA256: bodySHA256(body),
		Signature:  signature,
		Now:        now,
	})
	if err != nil {
		return ingestResult{}, serviceError(err)
	}
	responseBody, err := enrollResponseJSON(result)
	if err != nil {
		return ingestResult{}, storageUnavailableError()
	}
	return ingestResult{
		body:       responseBody,
		schemaName: schemaEnrollResponse,
		maxBody:    DefaultMaxResponseBody,
	}, nil
}

// handleReport extracts and validates the report discriminator, validates the
// body against the per-type schema, computes the frozen request fingerprint and
// calls the Service. Replay/sequence/boot/platform/privacy decisions and the
// ACK result are Service-owned.
func (s *Server) handleReport(ctx context.Context, fields wire.Fields, signature string, body []byte, now int64) (ingestResult, *APIError) {
	envelope, apiErr := extractReportEnvelope(body)
	if apiErr != nil {
		return ingestResult{}, apiErr
	}
	schemaName := schemaForReportType(envelope.Type)
	// Revision-7 snapshots select the rev-7 schema at the boundary; a deployment
	// without the additive rev-7 contract fails closed rather than validating the
	// rev-7 body against the rev-5 schema (which would reject it for the new
	// members with a misleading error).
	if envelope.Type == reportTypeSnapshot && envelope.ContractRevision == contract.ContractRevision7 {
		schemaName = contract.SnapshotRev7SchemaFile
	}
	if !s.schemas.Has(schemaName) {
		return ingestResult{}, invalidRequestError()
	}
	if err := s.schemas.Validate(schemaName, body); err != nil {
		return ingestResult{}, invalidRequestError()
	}
	fingerprint, err := wire.Fingerprint(fields, body)
	if err != nil {
		return ingestResult{}, invalidHeaderError()
	}
	result, err := s.svc.Report(ctx, ReportRequest{
		Fields:      fields,
		Body:        body,
		BodySHA256:  bodySHA256(body),
		Signature:   signature,
		ReportType:  envelope.Type,
		ReportID:    envelope.ReportID,
		CollectedAt: envelope.CollectedAt,
		Now:         now,
		Fingerprint: fingerprint,
	})
	if err != nil {
		return ingestResult{}, serviceError(err)
	}
	responseBody, err := reportAckJSON(envelope.ReportID, result)
	if err != nil {
		return ingestResult{}, storageUnavailableError()
	}
	return ingestResult{
		body:       responseBody,
		schemaName: schemaAck,
		maxBody:    DefaultMaxResponseBody,
	}, nil
}

// handleRotate validates the rotate-request body schema, computes the request
// fingerprint and calls the Service. Rotation intent, key state and idempotent
// replay are Service-owned.
func (s *Server) handleRotate(ctx context.Context, fields wire.Fields, signature string, body []byte, now int64) (ingestResult, *APIError) {
	if err := s.schemas.Validate(schemaRotateRequest, body); err != nil {
		return ingestResult{}, invalidRequestError()
	}
	fingerprint, err := wire.Fingerprint(fields, body)
	if err != nil {
		return ingestResult{}, invalidHeaderError()
	}
	result, err := s.svc.Rotate(ctx, RotateRequest{
		Fields:      fields,
		Body:        body,
		BodySHA256:  bodySHA256(body),
		Signature:   signature,
		Now:         now,
		Fingerprint: fingerprint,
	})
	if err != nil {
		return ingestResult{}, serviceError(err)
	}
	// Idempotent rotate replay: the Service returns the exact persisted
	// rotate-response bytes and the boundary writes them verbatim (after the
	// frozen schema check in writeSuccess), so retries are byte-identical.
	responseBody := result.Response
	if len(responseBody) == 0 {
		responseBody, err = rotateResponseJSON(fields.NodeID, result)
		if err != nil {
			return ingestResult{}, storageUnavailableError()
		}
	}
	return ingestResult{
		body:       responseBody,
		schemaName: schemaRotateResponse,
		maxBody:    DefaultMaxResponseBody,
	}, nil
}

// handleConfig calls the Service and returns the complete persisted
// agent-config body verbatim. The boundary never re-serializes it, so a replayed
// config response stays byte-stable; it does validate the frozen schema and the
// 16 KiB response cap before writing.
func (s *Server) handleConfig(ctx context.Context, fields wire.Fields, signature string, body []byte, now int64) (ingestResult, *APIError) {
	fingerprint, err := wire.Fingerprint(fields, body)
	if err != nil {
		return ingestResult{}, invalidHeaderError()
	}
	result, err := s.svc.Config(ctx, ConfigRequest{
		Fields:      fields,
		Body:        body,
		BodySHA256:  bodySHA256(body),
		Signature:   signature,
		Now:         now,
		Fingerprint: fingerprint,
	})
	if err != nil {
		return ingestResult{}, serviceError(err)
	}
	if int64(len(result.Body)) > DefaultMaxConfigResponse {
		return ingestResult{}, storageUnavailableError()
	}
	return ingestResult{
		body:       result.Body,
		schemaName: s.agentConfigSchemaForBody(result.Body),
		maxBody:    DefaultMaxConfigResponse,
	}, nil
}

// agentConfigSchemaForBody selects the schema the boundary revalidates a config
// response against. The revision-7 response is identified by the optional
// collect.monitor_export member; a body carrying it is validated only against the
// rev-7 schema (which must be loaded and is selected by the Service only then).
// This is a response-shape check, not an authorization decision.
func (s *Server) agentConfigSchemaForBody(body []byte) string {
	var doc struct {
		Collect map[string]json.RawMessage `json:"collect"`
	}
	if err := json.Unmarshal(body, &doc); err == nil {
		if _, ok := doc.Collect["monitor_export"]; ok && s.schemas.Has(contract.AgentConfigRev7SchemaFile) {
			return contract.AgentConfigRev7SchemaFile
		}
	}
	return schemaAgentConfig
}

// schemaForReportType maps the validated report discriminator to its frozen
// schema file. extractReportEnvelope has already restricted the type.
func schemaForReportType(reportType string) string {
	switch reportType {
	case reportTypeSnapshot:
		return schemaReportSnapshot
	case reportTypeMetrics:
		return schemaReportMetrics
	default:
		return schemaReportEvents
	}
}

// remoteIP is the rate-limit key: the transport peer address only. Forwarding
// headers are untrusted at the ingestion boundary and never parsed here.
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		return r.RemoteAddr
	}
	return host
}

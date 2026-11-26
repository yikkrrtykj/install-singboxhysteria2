package center

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"regexp"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/wire"
)

// bodySHA256 returns the lowercase hex SHA-256 of the decoded body bytes: the
// exact value bound by the signing string and the request fingerprint.
func bodySHA256(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// readDecodedBody reads the request body under the frozen caps, decodes it
// according to the signed content coding, and enforces the decoded cap:
//
//  1. the compressed bytes are read with a hard limit of MaxCompressedBody+1
//     (413 payload_too_large if exceeded);
//  2. identity bodies are directly checked against the decoded cap;
//  3. gzip bodies must be exactly one member with no trailing bytes and are
//     decoded with a hard limit of decodedCap+1 (413 on overflow, 400
//     unsupported_encoding on malformed/trailing/stacked input).
//
// Enrollment uses MaxEnrollBody as its decoded cap; every other endpoint uses
// MaxDecodedBody. The cap is enforced before any JSON or schema parsing.
func (s *Server) readDecodedBody(r *http.Request, encoding string, ep wire.Endpoint) ([]byte, *APIError) {
	maxCompressed := s.cfg.MaxCompressedBody
	if r.ContentLength > 0 && r.ContentLength > maxCompressed {
		return nil, payloadTooLargeError()
	}
	compressed, err := io.ReadAll(io.LimitReader(r.Body, maxCompressed+1))
	if err != nil {
		return nil, invalidRequestError()
	}
	if int64(len(compressed)) > maxCompressed {
		return nil, payloadTooLargeError()
	}
	decodedMax := s.cfg.MaxDecodedBody
	if ep == wire.Enroll {
		decodedMax = s.cfg.MaxEnrollBody
	}
	if encoding == "identity" {
		if int64(len(compressed)) > decodedMax {
			return nil, payloadTooLargeError()
		}
		return compressed, nil
	}
	return gunzipSingleMember(compressed, decodedMax)
}

// gunzipSingleMember decodes exactly one gzip member and rejects concatenated
// members, trailing data, truncation, checksum failures and cap overflows. The
// frozen contract allows one coding token and a single-member gzip stream only.
func gunzipSingleMember(compressed []byte, decodedMax int64) ([]byte, *APIError) {
	reader := bytes.NewReader(compressed)
	zr, err := gzip.NewReader(reader)
	if err != nil {
		return nil, unsupportedEncodingError()
	}
	defer func() { _ = zr.Close() }()
	// Multistream(false) stops at the end of the first member so a second
	// concatenated member is not silently decoded.
	zr.Multistream(false)
	decoded, err := io.ReadAll(io.LimitReader(zr, decodedMax+1))
	if err != nil {
		return nil, unsupportedEncodingError()
	}
	if int64(len(decoded)) > decodedMax {
		return nil, payloadTooLargeError()
	}
	// The gzip reader consumes exactly the member (header, deflate stream,
	// CRC32/ISIZE trailer). Any unread compressed byte is trailing data, which
	// the frozen contract rejects as unsupported_encoding.
	if reader.Len() != 0 {
		return nil, unsupportedEncodingError()
	}
	return decoded, nil
}

// Report body types accepted by the frozen report schemas.
const (
	reportTypeSnapshot = "snapshot"
	reportTypeMetrics  = "metrics"
	reportTypeEvents   = "events"
)

// maxCollectedAt is the frozen upper bound of report collected_at
// (report-*.schema.json: maximum 1000000000000).
const maxCollectedAt uint64 = 1000000000000

// uuidV4Pattern is the frozen lowercase UUIDv4 grammar used by report_id and
// node_id/event_id fields.
var uuidV4Pattern = regexp.MustCompile(
	`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
)

// reportEnvelope is the small discrimination struct the boundary extracts from
// a report body before choosing the per-type schema and calling the Service.
// Pointers distinguish absent members from JSON zero values.
type reportEnvelope struct {
	V           *json.Number `json:"v"`
	Type        *string      `json:"type"`
	ReportID    *string      `json:"report_id"`
	CollectedAt *json.Number `json:"collected_at"`
}

// reportEnvelopeInfo is the validated report discriminator.
type reportEnvelopeInfo struct {
	Type        string
	ReportID    string
	CollectedAt int64
}

// extractReportEnvelope validates the frozen report discriminator:
// v == 1, type in {snapshot,metrics,events}, report_id a lowercase UUIDv4 and
// collected_at a canonical decimal in [0, 1000000000000]. Any violation is
// 400 invalid_request. The full body is still validated against the per-type
// schema and by the Service's platform/privacy checks.
func extractReportEnvelope(body []byte) (reportEnvelopeInfo, *APIError) {
	var envelope reportEnvelope
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&envelope); err != nil {
		return reportEnvelopeInfo{}, invalidRequestError()
	}
	if envelope.V == nil || envelope.V.String() != "1" {
		return reportEnvelopeInfo{}, invalidRequestError()
	}
	if envelope.Type == nil {
		return reportEnvelopeInfo{}, invalidRequestError()
	}
	reportType := *envelope.Type
	if reportType != reportTypeSnapshot && reportType != reportTypeMetrics && reportType != reportTypeEvents {
		return reportEnvelopeInfo{}, invalidRequestError()
	}
	if envelope.ReportID == nil || !uuidV4Pattern.MatchString(*envelope.ReportID) {
		return reportEnvelopeInfo{}, invalidRequestError()
	}
	if envelope.CollectedAt == nil {
		return reportEnvelopeInfo{}, invalidRequestError()
	}
	collectedAt, err := wire.ParseCanonicalDecimal(
		"collected_at", envelope.CollectedAt.String(), 0, maxCollectedAt,
	)
	if err != nil {
		return reportEnvelopeInfo{}, invalidRequestError()
	}
	return reportEnvelopeInfo{
		Type:        reportType,
		ReportID:    *envelope.ReportID,
		CollectedAt: int64(collectedAt),
	}, nil
}

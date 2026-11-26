package center

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
)

// Frozen boundary error constructors. They return fresh values so a Service
// mapping helper can never mutate a package-level singleton.
func missingHeaderError() *APIError {
	return NewAPIError(http.StatusBadRequest, "missing_header", false)
}
func invalidHeaderError() *APIError {
	return NewAPIError(http.StatusBadRequest, "invalid_header", false)
}
func duplicateHeaderError() *APIError {
	return NewAPIError(http.StatusBadRequest, "duplicate_header", false)
}
func invalidRequestError() *APIError {
	return NewAPIError(http.StatusBadRequest, "invalid_request", false)
}
func unsupportedEncodingError() *APIError {
	return NewAPIError(http.StatusBadRequest, "unsupported_encoding", false)
}
func unauthorizedError() *APIError {
	return NewAPIError(http.StatusUnauthorized, "unauthorized", false)
}
func payloadTooLargeError() *APIError {
	return NewAPIError(http.StatusRequestEntityTooLarge, "payload_too_large", false)
}
func storageUnavailableError() *APIError {
	return NewAPIError(http.StatusServiceUnavailable, "storage_unavailable", true)
}

// writeError writes the frozen error.schema.json body. The status/code/
// retryable mapping is ErrorResponse's; a 429 additionally carries Retry-After
// as the contract requires.
func (s *Server) writeError(w http.ResponseWriter, err error, retryAfterSeconds int) {
	status, body := ErrorResponse(err, s.nowUnix())
	if status == http.StatusTooManyRequests {
		if retryAfterSeconds < minRetryAfterSeconds {
			retryAfterSeconds = minRetryAfterSeconds
		}
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// writeSuccess validates a success body against its frozen response schema and
// the response cap, then writes it with Content-Type: application/json and no
// other headers. A Service that produced a contract-invalid body is a center
// fault: the peer gets 503 storage_unavailable retryable, never internal text
// or a malformed 200.
func (s *Server) writeSuccess(w http.ResponseWriter, body []byte, schemaName string, maxBody int64) {
	if maxBody > 0 && int64(len(body)) > maxBody {
		s.writeError(w, storageUnavailableError(), 0)
		return
	}
	if schemaName != "" {
		if err := s.schemas.Validate(schemaName, body); err != nil {
			s.writeError(w, storageUnavailableError(), 0)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// serviceError maps a Service error to the frozen vocabulary. Only a valid
// *APIError is passed through; context cancellation/deadline and every unknown
// or malformed error become 503 storage_unavailable retryable. The Go error
// text is never propagated into the response.
func serviceError(err error) *APIError {
	if err == nil {
		return nil
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr != nil &&
		apiErr.Status >= 400 && apiErr.Status <= 599 &&
		IsClosedErrorCode(apiErr.Code) {
		return apiErr
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return storageUnavailableError()
	}
	return storageUnavailableError()
}

// Success response bodies. They mirror the frozen response schemas exactly;
// every body is schema-validated by writeSuccess before it is sent.

type enrollResponseBody struct {
	V                int     `json:"v"`
	NodeID           string  `json:"node_id"`
	EventID          string  `json:"event_id"`
	NodeClass        string  `json:"node_class"`
	KeyID            string  `json:"key_id"`
	ConfigVersion    int     `json:"config_version"`
	DeviceSalt       string  `json:"device_salt"`
	CadenceSeconds   int     `json:"cadence_seconds"`
	ServerTime       int64   `json:"server_time"`
	CenterSPKISHA256 *string `json:"center_spki_sha256"`
}

func enrollResponseJSON(result EnrollResult) ([]byte, error) {
	body := enrollResponseBody{
		V:              1,
		NodeID:         result.NodeID,
		EventID:        result.EventID,
		NodeClass:      result.NodeClass,
		KeyID:          result.KeyID,
		ConfigVersion:  result.ConfigVersion,
		DeviceSalt:     result.DeviceSalt,
		CadenceSeconds: result.CadenceSeconds,
		ServerTime:     result.ServerTime,
	}
	if result.CenterSPKISHA256 != "" {
		spki := result.CenterSPKISHA256
		body.CenterSPKISHA256 = &spki
	}
	return json.Marshal(body)
}

type reportAckBody struct {
	V             int     `json:"v"`
	ReportID      string  `json:"report_id"`
	Result        string  `json:"result"`
	ServerTime    int64   `json:"server_time"`
	NextSeq       *uint64 `json:"next_seq"`
	ConfigVersion int     `json:"config_version"`
	RetryAfterS   *int    `json:"retry_after_s"`
}

// reportAckJSON builds the ACK. report_id falls back to the request report_id
// when the Service leaves it empty (the ACK must always echo the request id).
// next_seq is an explicit JSON null when nil (generation exhausted), and
// retry_after_s is null when RetryAfterS is nil or non-positive (the frozen ACK
// schema accepts only null or 1..3600).
func reportAckJSON(requestReportID string, result ReportResult) ([]byte, error) {
	reportID := result.ReportID
	if reportID == "" {
		reportID = requestReportID
	}
	var retryAfter *int
	if result.RetryAfterS != nil && *result.RetryAfterS > 0 {
		value := *result.RetryAfterS
		retryAfter = &value
	}
	return json.Marshal(reportAckBody{
		V:             1,
		ReportID:      reportID,
		Result:        result.Result,
		ServerTime:    result.ServerTime,
		NextSeq:       result.NextSeq,
		ConfigVersion: result.ConfigVersion,
		RetryAfterS:   retryAfter,
	})
}

type rotateResponseBody struct {
	V             int    `json:"v"`
	NodeID        string `json:"node_id"`
	PreviousKeyID string `json:"previous_key_id"`
	NewKeyID      string `json:"new_key_id"`
	ConfigVersion int    `json:"config_version"`
	ServerTime    int64  `json:"server_time"`
}

// rotateResponseJSON builds the rotate response. node_id is the authenticated
// request node id; the Service only supplies the key ids and version.
func rotateResponseJSON(nodeID string, result RotateResult) ([]byte, error) {
	return json.Marshal(rotateResponseBody{
		V:             1,
		NodeID:        nodeID,
		PreviousKeyID: result.PreviousKeyID,
		NewKeyID:      result.NewKeyID,
		ConfigVersion: result.ConfigVersion,
		ServerTime:    result.ServerTime,
	})
}

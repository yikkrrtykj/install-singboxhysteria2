package agent

import (
	"errors"
	"fmt"
)

// Sentinel errors are intentionally non-echoing: callers may log them without
// exposing payloads, credentials or local paths.
var (
	ErrLocked              = errors.New("agent: state directory is already in use")
	ErrNoIdentity          = errors.New("agent: no persisted identity")
	ErrAlreadyEnrolled     = errors.New("agent: already enrolled")
	ErrBootStateCorrupt    = errors.New("agent: boot_state_corrupt")
	ErrIdentityCorrupt     = errors.New("agent: identity_corrupt")
	ErrNotEnrolled         = errors.New("agent: not enrolled")
	ErrStopped             = errors.New("agent: stopped")
	ErrRevoked             = errors.New("agent: revoked")
	ErrGenerationExhausted = errors.New("agent: sequence generation exhausted")
	ErrStaleGeneration     = errors.New("agent: stale boot generation; operator recovery required")
	ErrSequenceConflict    = errors.New("agent: sequence conflict; operator recovery required")
	ErrRotationMismatch    = errors.New("agent: rotation state mismatch")
	ErrSpoolFull           = errors.New("agent: spool capacity exhausted")
	ErrPayloadRejected     = errors.New("agent: payload rejected by center")
	ErrFailClosed          = errors.New("agent: fail_closed marker present; operator recovery required")
)

// CenterError is a frozen-vocabulary error returned by the center. The exact
// body is not retained; only the stable code/status/retryability are exposed.
type CenterError struct {
	Status      int
	Code        string
	Retryable   bool
	ServerTime  int64
	RetryAfterS *int
}

func (e *CenterError) Error() string {
	return fmt.Sprintf("agent: center error status=%d code=%s retryable=%v", e.Status, e.Code, e.Retryable)
}

// TransportError means the request did not produce a usable center response
// (network, timeout, malformed/over-limit response). It is retryable.
type TransportError struct{ Cause string }

func (e *TransportError) Error() string { return "agent: transport failure: " + e.Cause }

// IsRetryable reports whether err is a transient transport/center condition.
func IsRetryable(err error) bool {
	var ce *CenterError
	if errors.As(err, &ce) {
		return ce.Retryable || ce.Status == 429 || ce.Status >= 500
	}
	var te *TransportError
	return errors.As(err, &te)
}

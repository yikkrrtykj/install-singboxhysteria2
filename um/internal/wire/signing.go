// Package wire implements the canonical UM wire v1 revision-5 primitives:
// field grammar, signed byte strings, Ed25519 sign/verify, request
// fingerprints and typed validation errors. The HTTP layer owns header
// cardinality, decoding, freshness windows and replay state.
package wire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// Frozen revision-5 constants.
const (
	ProtocolVersion = "1"
	// MaxNumeric is the largest accepted X-UM-Boot-Gen / X-UM-Seq value:
	// 2^63-2. It fits a signed SQLite INTEGER and leaves the next value
	// representable (next_seq = last_seq + 1).
	MaxNumeric uint64 = 9223372036854775806
	// MaxBootGap is the largest accepted generation forward jump.
	MaxBootGap uint64 = 65535

	maxSigned64 = uint64(9223372036854775807)
)

// Header names are part of the frozen contract; keep them in one place.
const (
	HeaderProtocol      = "X-UM-Protocol"
	HeaderPubkey        = "X-UM-Pubkey"
	HeaderNodeID        = "X-UM-Node-Id"
	HeaderKeyID         = "X-UM-Key-Id"
	HeaderBootGen       = "X-UM-Boot-Gen"
	HeaderBootID        = "X-UM-Boot-Id"
	HeaderSeq           = "X-UM-Seq"
	HeaderSentAt        = "X-UM-Sent-At"
	HeaderNonce         = "X-UM-Nonce"
	HeaderContentEnc    = "X-UM-Content-Encoding"
	HeaderSignature     = "X-UM-Signature"
	HeaderContentType   = "Content-Type"
	HeaderAuthorization = "Authorization"
)

// Endpoint is one of the four frozen node endpoints.
type Endpoint string

const (
	Enroll Endpoint = "enroll"
	Report Endpoint = "report"
	Rotate Endpoint = "rotate"
	Config Endpoint = "config"
)

// ErrorCode is the closed subset of contract errors produced by this package.
// The HTTP receiver maps these to the frozen error body. Only field/grammar
// failures are produced here; replays, nonces and boot high-water live in the
// protocol/store layers.
type ErrorCode string

const (
	CodeMissingHeader ErrorCode = "missing_header"
	CodeInvalidHeader ErrorCode = "invalid_header"
	CodeBadSignature  ErrorCode = "bad_signature"
	CodeInvalidFields ErrorCode = "invalid_request"
)

// FieldError is a typed, non-echoing validation error. It never contains the
// offending value, so callers may log it safely.
type FieldError struct {
	Code   ErrorCode
	Field  string
	Detail string
}

func (e *FieldError) Error() string {
	if e.Field == "" {
		return string(e.Code) + ": " + e.Detail
	}
	return string(e.Code) + " (" + e.Field + "): " + e.Detail
}

// IsCode reports whether err is (or wraps) a FieldError with code.
func IsCode(err error, code ErrorCode) bool {
	var fe *FieldError
	if errors.As(err, &fe) {
		return fe.Code == code
	}
	return false
}

var (
	nodeIDRe  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	keyIDRe   = regexp.MustCompile(`^key-[0-9a-f]{8}$`)
	bootIDRe  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	decimalRe = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
)

// Fields are the exact signed header values of one routed request.
type Fields struct {
	Endpoint                        Endpoint
	Protocol, Encoding, SentAt      string
	Nonce, PublicKey                string
	NodeID, KeyID, BootID, Sequence string
	BootGen                         string
}

func invalid(field, detail string) error {
	return &FieldError{Code: CodeInvalidHeader, Field: field, Detail: detail}
}

// ParseCanonicalDecimal validates a canonical decimal (no leading zero, no
// sign, no whitespace) within [min, max]. It is the only numeric parser used
// for signed header fields.
func ParseCanonicalDecimal(field, value string, min, max uint64) (uint64, error) {
	if !decimalRe.MatchString(value) {
		return 0, invalid(field, "must be a canonical decimal")
	}
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, invalid(field, "decimal overflow")
	}
	if n < min || n > max {
		return 0, invalid(field, "out of range")
	}
	return n, nil
}

// Validate checks the frozen per-endpoint field grammar.
func (f Fields) Validate() error {
	if f.Protocol != ProtocolVersion {
		return invalid(HeaderProtocol, "unsupported protocol")
	}
	if f.Encoding != "identity" && f.Encoding != "gzip" {
		return invalid(HeaderContentEnc, "unsupported encoding")
	}
	if !decimalRe.MatchString(f.SentAt) {
		return invalid(HeaderSentAt, "must be a canonical decimal")
	}
	sentAt, err := strconv.ParseUint(f.SentAt, 10, 64)
	if err != nil || sentAt > maxSigned64 {
		return invalid(HeaderSentAt, "out of range")
	}
	if decodeRawURL(f.Nonce, 16) == nil {
		return invalid(HeaderNonce, "must be base64url 16 bytes")
	}
	switch f.Endpoint {
	case Enroll:
		if decodeRawURL(f.PublicKey, ed25519.PublicKeySize) == nil {
			return invalid(HeaderPubkey, "must be base64url 32 bytes")
		}
		if f.NodeID != "" || f.KeyID != "" || f.BootGen != "" || f.BootID != "" || f.Sequence != "" {
			return invalid("", "enrollment must not carry node-auth fields")
		}
	case Report, Rotate, Config:
		if !nodeIDRe.MatchString(f.NodeID) {
			return invalid(HeaderNodeID, "must be lowercase UUIDv4")
		}
		if !keyIDRe.MatchString(f.KeyID) {
			return invalid(HeaderKeyID, "must match key-[0-9a-f]{8}")
		}
		if _, err := ParseCanonicalDecimal(HeaderBootGen, f.BootGen, 1, MaxNumeric); err != nil {
			return err
		}
		if !bootIDRe.MatchString(f.BootID) {
			return invalid(HeaderBootID, "must be 32 lowercase hex")
		}
		if _, err := ParseCanonicalDecimal(HeaderSeq, f.Sequence, 1, MaxNumeric); err != nil {
			return err
		}
		if f.PublicKey != "" {
			return invalid(HeaderPubkey, "must be empty for node-auth endpoints")
		}
	default:
		return invalid("", "unknown endpoint")
	}
	return nil
}

func (f Fields) path() string { return "/v1/agent/" + string(f.Endpoint) }

// SigningInput returns the exact UTF-8 bytes frozen in the rev-5 contract.
// decodedBody must be the decoded (post-gzip) body bytes.
func SigningInput(fields Fields, decodedBody []byte) ([]byte, error) {
	if err := fields.Validate(); err != nil {
		return nil, err
	}
	bodyHash := hashHex(decodedBody)
	if fields.Endpoint == Enroll {
		return join("um-enroll-v1", "POST", fields.path(), fields.Protocol,
			fields.Encoding, fields.PublicKey, fields.SentAt, fields.Nonce, bodyHash), nil
	}
	if fields.Endpoint == Config && !bytes.Equal(decodedBody, []byte("{}")) {
		return nil, invalid("body", "config body must be exactly two bytes {}")
	}
	return join("um-v1", string(fields.Endpoint), "POST", fields.path(), fields.Protocol,
		fields.NodeID, fields.KeyID, fields.BootGen, fields.BootID, fields.Sequence,
		fields.SentAt, fields.Nonce, fields.Encoding, bodyHash), nil
}

// Sign produces the canonical base64url Ed25519 signature for one request.
func Sign(priv ed25519.PrivateKey, fields Fields, decodedBody []byte) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", &FieldError{Code: CodeBadSignature, Detail: "invalid private key"}
	}
	msg, err := SigningInput(fields, decodedBody)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, msg)), nil
}

// VerifyWithError verifies a signature and distinguishes malformed fields
// (invalid_header) from a cryptographically bad signature (bad_signature).
func VerifyWithError(fields Fields, decodedBody []byte, tag string, publicKey ed25519.PublicKey) error {
	msg, err := SigningInput(fields, decodedBody)
	if err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return &FieldError{Code: CodeBadSignature, Detail: "invalid public key length"}
	}
	if fields.Endpoint == Enroll {
		declared := decodeRawURL(fields.PublicKey, ed25519.PublicKeySize)
		if declared == nil || !bytes.Equal(declared, publicKey) {
			return &FieldError{Code: CodeBadSignature, Field: HeaderPubkey, Detail: "declared key mismatch"}
		}
	}
	sig := decodeRawURL(tag, ed25519.SignatureSize)
	if sig == nil {
		return &FieldError{Code: CodeBadSignature, Field: HeaderSignature, Detail: "must be base64url 64 bytes"}
	}
	if !ed25519.Verify(publicKey, msg, sig) {
		return &FieldError{Code: CodeBadSignature, Detail: "signature verification failed"}
	}
	return nil
}

// Verify is the boolean convenience wrapper.
func Verify(fields Fields, decodedBody []byte, tag string, publicKey ed25519.PublicKey) bool {
	return VerifyWithError(fields, decodedBody, tag, publicKey) == nil
}

// Fingerprint returns the frozen rev-5 request fingerprint:
// sha256(endpoint|method|path|key_id|boot_gen|boot_id|seq|sent_at|encoding|body_sha256)
// with LF separators and no trailing newline. Enrollment is not fingerprinted
// by this helper (the bootstrap token is the enrollment identity input).
func Fingerprint(fields Fields, decodedBody []byte) (string, error) {
	if _, err := SigningInput(fields, decodedBody); err != nil {
		return "", err
	}
	return hashHex(join(string(fields.Endpoint), "POST", fields.path(), fields.KeyID,
		fields.BootGen, fields.BootID, fields.Sequence, fields.SentAt, fields.Encoding,
		hashHex(decodedBody))), nil
}

func hashHex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func join(fields ...string) []byte { return []byte(strings.Join(fields, "\n")) }

func decodeRawURL(value string, size int) []byte {
	b, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(b) != size || base64.RawURLEncoding.EncodeToString(b) != value {
		return nil
	}
	return b
}

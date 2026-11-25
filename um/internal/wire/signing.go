// Package wire implements the cryptographic primitives of the UM v1 wire contract.
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

type Endpoint string

const (
	Enroll Endpoint = "enroll"
	Report Endpoint = "report"
	Rotate Endpoint = "rotate"
	Config Endpoint = "config"
)

var (
	nodeID    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	keyID     = regexp.MustCompile(`^key-[0-9a-f]{8}$`)
	bootID    = regexp.MustCompile(`^[0-9a-f]{32}$`)
	decimal   = regexp.MustCompile(`^[0-9]+$`)
	errFields = errors.New("invalid UM v1 signing fields")
)

// Fields are the exact signed header values from a single routed request.
// The HTTP layer owns header cardinality, route matching, decoding and replay checks.
type Fields struct {
	Endpoint                        Endpoint
	Protocol, Encoding, SentAt      string
	Nonce, PublicKey                string
	NodeID, KeyID, BootID, Sequence string
}

// SigningInput returns the UTF-8 bytes defined in the UM v1 contract.
// Use the exact decoded body bytes received or sent on the wire.
func SigningInput(fields Fields, decodedBody []byte) ([]byte, error) {
	if fields.Protocol != "1" || (fields.Encoding != "identity" && fields.Encoding != "gzip") {
		return nil, errFields
	}
	if _, err := strconv.ParseInt(fields.SentAt, 10, 64); err != nil || !decimal.MatchString(fields.SentAt) {
		return nil, errFields
	}
	if decodeBase64(fields.Nonce, 16) == nil {
		return nil, errFields
	}
	digest := sha256.Sum256(decodedBody)
	bodyHash := hex.EncodeToString(digest[:])

	switch fields.Endpoint {
	case Enroll:
		if decodeBase64(fields.PublicKey, ed25519.PublicKeySize) == nil ||
			fields.NodeID != "" || fields.KeyID != "" || fields.BootID != "" || fields.Sequence != "" {
			return nil, errFields
		}
		return join("um-enroll-v1", "POST", "/v1/agent/enroll", fields.Protocol,
			fields.Encoding, fields.PublicKey, fields.SentAt, fields.Nonce, bodyHash), nil
	case Report, Rotate, Config:
		sequence, err := strconv.ParseUint(fields.Sequence, 10, 64)
		if err != nil || sequence == 0 || !decimal.MatchString(fields.Sequence) ||
			!nodeID.MatchString(fields.NodeID) || !keyID.MatchString(fields.KeyID) ||
			!bootID.MatchString(fields.BootID) || fields.PublicKey != "" {
			return nil, errFields
		}
		if fields.Endpoint == Config && string(decodedBody) != "{}" {
			return nil, errFields
		}
		endpoint := string(fields.Endpoint)
		return join("um-v1", endpoint, "POST", "/v1/agent/"+endpoint, fields.Protocol,
			fields.NodeID, fields.KeyID, fields.BootID, fields.Sequence, fields.SentAt,
			fields.Nonce, fields.Encoding, bodyHash), nil
	default:
		return nil, errFields
	}
}

// Verify checks a signature with the request's registered public key. Enrollment
// uses the public key declared in the enrollment fields.
func Verify(fields Fields, decodedBody []byte, tag string, publicKey ed25519.PublicKey) bool {
	message, err := SigningInput(fields, decodedBody)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	if fields.Endpoint == Enroll && !bytes.Equal(publicKey, decodeBase64(fields.PublicKey, ed25519.PublicKeySize)) {
		return false
	}
	signature := decodeBase64(tag, ed25519.SignatureSize)
	return signature != nil && ed25519.Verify(publicKey, message, signature)
}

func join(fields ...string) []byte {
	return []byte(strings.Join(fields, "\n"))
}

func decodeBase64(value string, size int) []byte {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != size || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil
	}
	return decoded
}

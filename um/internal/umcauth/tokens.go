package umcauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

// Opaque bearer tokens.
//
// Session tokens and CSRF tokens are 256-bit random values encoded as unpadded
// base64url. Only their SHA-256 hex digest is ever persisted: the plaintext
// token is returned to the caller once and must never be logged. Comparing
// digests with ConstantTimeEqual keeps equality checks independent of the
// compared lengths.
const tokenRandomBytes = 32

// NewToken returns a fresh 256-bit session bearer token encoded with unpadded
// base64url (43 characters).
func NewToken() (string, error) {
	return newRandomToken()
}

// NewCSRFToken returns a fresh 256-bit CSRF token encoded with unpadded
// base64url. It uses the same primitive as NewToken and is domain-separated by
// the caller binding it to one session, never by its format.
func NewCSRFToken() (string, error) {
	return newRandomToken()
}

// HashToken returns the lowercase hex SHA-256 digest of token. The digest is
// suitable for persistence; the input token must not be stored or logged.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ConstantTimeEqual compares two strings in time independent of their contents
// by comparing fixed-size SHA-256 digests. It is intended for tokens, CSRF
// values and cookie values; do not use it for password hashes (VerifyPassword
// already compares Argon2id output).
func ConstantTimeEqual(a, b string) bool {
	sumA := sha256.Sum256([]byte(a))
	sumB := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(sumA[:], sumB[:]) == 1
}

func newRandomToken() (string, error) {
	buf := make([]byte, tokenRandomBytes)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", fmt.Errorf("umcauth: generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

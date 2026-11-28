package umcauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
)

// One-time recovery codes.
//
// Each generated code carries 120 bits of entropy (15 random bytes rendered as
// 24 base32 symbols in six dash-separated groups of four). Codes are intended
// to be shown once and stored only as HashRecoveryCode output; this package
// deliberately provides no plaintext persistence helper.
const (
	recoveryCodeEntropyBytes = 15
	recoveryCodeGroupSize    = 4
	recoveryCodeGroups       = 6
	recoveryCodeMinCount     = 1
	recoveryCodeMaxCount     = 64
)

// ErrInvalidRecoveryCodeCount reports a requested recovery-code count outside
// the supported bound.
var ErrInvalidRecoveryCodeCount = errors.New("umcauth: invalid recovery code count")

// GenerateRecoveryCodes returns count fresh, unique, human-readable recovery
// codes in the form XXXX-XXXX-XXXX-XXXX-XXXX-XXXX. Code generation fails closed
// if the system random source fails.
func GenerateRecoveryCodes(count int) ([]string, error) {
	if count < recoveryCodeMinCount || count > recoveryCodeMaxCount {
		return nil, fmt.Errorf("%w: must be in [%d, %d]", ErrInvalidRecoveryCodeCount, recoveryCodeMinCount, recoveryCodeMaxCount)
	}
	codes := make([]string, 0, count)
	seen := make(map[string]struct{}, count)
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	for len(codes) < count {
		raw := make([]byte, recoveryCodeEntropyBytes)
		if _, err := io.ReadFull(rand.Reader, raw); err != nil {
			return nil, fmt.Errorf("umcauth: generate recovery code: %w", err)
		}
		encoded := encoding.EncodeToString(raw)
		grouped := groupRecoveryCode(encoded)
		if _, duplicate := seen[grouped]; duplicate {
			// A 120-bit collision is not expected to happen; regenerate
			// rather than emitting a duplicate code.
			continue
		}
		seen[grouped] = struct{}{}
		codes = append(codes, grouped)
	}
	return codes, nil
}

// NormalizeRecoveryCode returns the canonical comparison form of a recovery
// code: trimmed, upper-cased, and with dashes, underscores and whitespace
// removed so a user may type the code with or without grouping.
func NormalizeRecoveryCode(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	var b strings.Builder
	b.Grow(len(code))
	for _, r := range code {
		if r == '-' || r == '_' || unicode.IsSpace(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// HashRecoveryCode returns the lowercase hex SHA-256 digest of the normalized
// code. Only this digest should be persisted; the plaintext code must be
// discarded after it is shown to the user once and compared with
// ConstantTimeEqual after hashing.
func HashRecoveryCode(code string) string {
	normalized := NormalizeRecoveryCode(code)
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func groupRecoveryCode(encoded string) string {
	var b strings.Builder
	b.Grow(len(encoded) + recoveryCodeGroups - 1)
	for offset := 0; offset < len(encoded); offset += recoveryCodeGroupSize {
		if offset > 0 {
			b.WriteByte('-')
		}
		b.WriteString(encoded[offset : offset+recoveryCodeGroupSize])
	}
	return b.String()
}

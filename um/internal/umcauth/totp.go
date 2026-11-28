package umcauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238/4226 fixes SHA-1 for TOTP interoperability.
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// RFC 6238 TOTP (SHA-1, six digits, 30-second period).
//
// The algorithm is fixed on purpose: Cloudflare Access and standard
// authenticator applications interoperate on SHA-1/6/30, and the package does
// not accept a caller-selected algorithm that could silently weaken the
// verifier. Secrets are 20 random bytes encoded as unpadded base32 when
// generated; verification accepts case-insensitive base32 with or without
// padding for imported secrets.
const (
	// TOTPDigits is the number of decimal digits in a TOTP code.
	TOTPDigits = 6
	// TOTPPeriod is the TOTP time step.
	TOTPPeriod = 30 * time.Second
	// TOTPSecretBytes is the size of a generated TOTP secret in bytes.
	TOTPSecretBytes = 20
	// MaxTOTPSkewSteps bounds the accepted +/- clock-skew steps. Callers that
	// need a tighter window should pass a smaller value.
	MaxTOTPSkewSteps = 10

	totpMinSecretBytes     = 10  // 80 bits is the smallest secret this verifier accepts.
	totpMaxSecretBytes     = 128 // Bound decoded imported secrets.
	totpMaxEncodedSecret   = 256
	otpauthMaxIssuerBytes  = 128
	otpauthMaxAccountBytes = 256
	otpauthMaxURIBytes     = 2048
)

// TOTP errors. They never contain the secret or the submitted code.
var (
	// ErrInvalidTOTPSecret reports a missing, malformed, too short or too long
	// base32 TOTP secret.
	ErrInvalidTOTPSecret = errors.New("umcauth: invalid TOTP secret")
	// ErrInvalidTOTPCode reports a code that is not exactly six ASCII digits.
	ErrInvalidTOTPCode = errors.New("umcauth: invalid TOTP code")
	// ErrInvalidTOTPSkew reports an allowed-skew value outside [0, MaxTOTPSkewSteps].
	ErrInvalidTOTPSkew = errors.New("umcauth: invalid TOTP skew")
	// ErrInvalidTOTPTime reports a time that cannot be represented as a TOTP
	// counter (before the Unix epoch).
	ErrInvalidTOTPTime = errors.New("umcauth: invalid TOTP time")
	// ErrInvalidOTPAuthURI reports invalid issuer/account labels or secret for
	// OtpauthURI.
	ErrInvalidOTPAuthURI = errors.New("umcauth: invalid otpauth URI parameters")
)

// NewTOTPSecret returns a fresh 20-byte TOTP secret encoded as unpadded
// uppercase base32.
func NewTOTPSecret() (string, error) {
	buf := make([]byte, TOTPSecretBytes)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", fmt.Errorf("umcauth: generate TOTP secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

// TOTPCode returns the six-digit TOTP code for secret at time t.
func TOTPCode(secret string, t time.Time) (string, error) {
	raw, err := decodeTOTPSecret(secret)
	if err != nil {
		return "", err
	}
	counter, err := totpCounter(t)
	if err != nil {
		return "", err
	}
	return formatTOTPCode(hotpValue(raw, counter)), nil
}

// VerifyTOTP checks code against secret in the time step of now expanded by
// allowedSkewSteps steps in both directions. It returns the counter value that
// matched (for single-use replay storage), whether a match was found, and an
// error only for malformed inputs. A well-formed code outside the accepted
// window returns (0, false, nil); callers must treat that as an authentication
// failure.
func VerifyTOTP(secret, code string, now time.Time, allowedSkewSteps int) (uint64, bool, error) {
	raw, err := decodeTOTPSecret(secret)
	if err != nil {
		return 0, false, err
	}
	if allowedSkewSteps < 0 || allowedSkewSteps > MaxTOTPSkewSteps {
		return 0, false, fmt.Errorf("%w: must be in [0, %d]", ErrInvalidTOTPSkew, MaxTOTPSkewSteps)
	}
	code = strings.TrimSpace(code)
	if err := validateTOTPCode(code); err != nil {
		return 0, false, err
	}
	base, err := totpCounter(now)
	if err != nil {
		return 0, false, err
	}

	var matched uint64
	found := false
	// Evaluate the whole window so the result does not depend on where in the
	// window a match occurred.
	for delta := -allowedSkewSteps; delta <= allowedSkewSteps; delta++ {
		var counter uint64
		switch {
		case delta < 0:
			steps := uint64(-delta)
			if base < steps {
				continue
			}
			counter = base - steps
		case delta > 0:
			steps := uint64(delta)
			if steps > ^uint64(0)-base {
				continue
			}
			counter = base + steps
		default:
			counter = base
		}
		expected := formatTOTPCode(hotpValue(raw, counter))
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 && !found {
			matched = counter
			found = true
		}
	}
	return matched, found, nil
}

// OtpauthURI returns a Google-Authenticator-compatible otpauth:// URI for
// issuer/account/secret. The issuer and account are percent-encoded as label
// components; the issuer is also included as a query parameter as required by
// the Key URI format. The returned URI contains the secret, so callers must
// deliver it over a protected channel and must not log it.
func OtpauthURI(issuer, account, secret string) (string, error) {
	issuer = strings.TrimSpace(issuer)
	account = strings.TrimSpace(account)
	if err := validateOTPAuthLabel("issuer", issuer, otpauthMaxIssuerBytes); err != nil {
		return "", err
	}
	if err := validateOTPAuthLabel("account", account, otpauthMaxAccountBytes); err != nil {
		return "", err
	}
	raw, err := decodeTOTPSecret(secret)
	if err != nil {
		return "", err
	}
	canonicalSecret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)

	query := url.Values{}
	query.Set("secret", canonicalSecret)
	query.Set("issuer", issuer)
	query.Set("algorithm", "SHA1")
	query.Set("digits", strconv.Itoa(TOTPDigits))
	query.Set("period", strconv.Itoa(int(TOTPPeriod/time.Second)))

	uri := "otpauth://totp/" + escapeOTPAuthLabel(issuer) + ":" + escapeOTPAuthLabel(account) + "?" +
		strings.ReplaceAll(query.Encode(), "+", "%20")
	if len(uri) > otpauthMaxURIBytes {
		return "", fmt.Errorf("%w: URI exceeds %d bytes", ErrInvalidOTPAuthURI, otpauthMaxURIBytes)
	}
	return uri, nil
}

// decodeTOTPSecret accepts case-insensitive padded or unpadded base32 for
// imported secrets and enforces the supported size bounds.
func decodeTOTPSecret(secret string) ([]byte, error) {
	normalized := strings.TrimSpace(secret)
	if normalized == "" {
		return nil, fmt.Errorf("%w: empty", ErrInvalidTOTPSecret)
	}
	if len(normalized) > totpMaxEncodedSecret {
		return nil, fmt.Errorf("%w: encoded length out of range", ErrInvalidTOTPSecret)
	}
	normalized = strings.ToUpper(normalized)
	normalized = strings.TrimRight(normalized, "=")
	if normalized == "" {
		return nil, fmt.Errorf("%w: empty", ErrInvalidTOTPSecret)
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(normalized)
	if err != nil {
		return nil, fmt.Errorf("%w: not valid base32", ErrInvalidTOTPSecret)
	}
	if len(raw) < totpMinSecretBytes || len(raw) > totpMaxSecretBytes {
		return nil, fmt.Errorf("%w: decoded length out of range", ErrInvalidTOTPSecret)
	}
	return raw, nil
}

func totpCounter(t time.Time) (uint64, error) {
	seconds := t.Unix()
	if seconds < 0 {
		return 0, fmt.Errorf("%w: before the Unix epoch", ErrInvalidTOTPTime)
	}
	return uint64(seconds) / uint64(TOTPPeriod/time.Second), nil
}

func validateTOTPCode(code string) error {
	if len(code) != TOTPDigits {
		return fmt.Errorf("%w: must be exactly %d digits", ErrInvalidTOTPCode, TOTPDigits)
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return fmt.Errorf("%w: must contain only ASCII digits", ErrInvalidTOTPCode)
		}
	}
	return nil
}

func formatTOTPCode(value uint32) string {
	return fmt.Sprintf("%0*d", TOTPDigits, value)
}

// hotpValue implements the RFC 4226 dynamic-truncation step.
func hotpValue(secret []byte, counter uint64) uint32 {
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(message[:])
	sum := mac.Sum(nil)
	offset := int(sum[len(sum)-1] & 0x0f)
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return value % 1_000_000
}

func validateOTPAuthLabel(name, value string, maxBytes int) error {
	if value == "" {
		return fmt.Errorf("%w: %s must not be empty", ErrInvalidOTPAuthURI, name)
	}
	if len(value) > maxBytes {
		return fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalidOTPAuthURI, name, maxBytes)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%w: %s must be valid UTF-8", ErrInvalidOTPAuthURI, name)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: %s must not contain control characters", ErrInvalidOTPAuthURI, name)
		}
	}
	return nil
}

// escapeOTPAuthLabel percent-encodes every byte outside RFC 3986 unreserved
// characters. A literal ':' between issuer and account stays the label
// separator; colons inside either component are escaped.
func escapeOTPAuthLabel(value string) string {
	const upperHex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(value))
	for i := 0; i < len(value); i++ {
		c := value[i]
		if isOTPAuthUnreserved(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(upperHex[c>>4])
		b.WriteByte(upperHex[c&0x0f])
	}
	return b.String()
}

func isOTPAuthUnreserved(c byte) bool {
	switch {
	case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9':
		return true
	case c == '-', c == '.', c == '_', c == '~':
		return true
	default:
		return false
	}
}

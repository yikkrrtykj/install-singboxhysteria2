package umcauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2id password hashing.
//
// The encoded form is fixed and strict:
//
//	$argon2id$v=19$m=<KiB>,t=<iterations>,p=<parallelism>$<salt>$<hash>
//
// where <salt> is the 16-byte salt and <hash> is the 32-byte derived key, both
// encoded with canonical unpadded standard base64. Parsing accepts nothing
// else: another algorithm, another version, reordered/missing/extra parameters,
// non-canonical decimal values, padded base64, or wrong salt/key lengths are
// rejected. Parameter values are bounded so a crafted encoded hash cannot
// trigger an unbounded Argon2 memory/CPU allocation.
const (
	passwordAlgorithm   = "argon2id"
	passwordVersion     = argon2.Version
	passwordSaltLength  = 16
	passwordKeyLength   = 32
	passwordMinBytes    = 12
	passwordMaxBytes    = 1024
	passwordMaxEncoded  = 512
	passwordMinMemory   = 8 * 1024    // 8 MiB, KiB units as in the format
	passwordMaxMemory   = 1024 * 1024 // 1 GiB
	passwordMinTime     = 1           // iterations
	passwordMaxTime     = 10          // iterations
	passwordMinParallel = 1           // lanes
	passwordMaxParallel = 16          // lanes
)

// Password hashing errors. They never contain the password or the encoded hash;
// callers may safely log them.
var (
	// ErrInvalidPasswordHash reports an encoded password hash that does not
	// conform to the fixed Argon2id format above.
	ErrInvalidPasswordHash = errors.New("umcauth: invalid password hash")
	// ErrInvalidPasswordParams reports Argon2id cost parameters outside the
	// supported, bounded range.
	ErrInvalidPasswordParams = errors.New("umcauth: invalid argon2id parameters")
	// ErrPasswordPolicy reports a password that violates the login policy.
	ErrPasswordPolicy = errors.New("umcauth: password does not meet policy")
)

// PasswordParams are the Argon2id cost parameters. Memory is expressed in KiB,
// Time is the number of passes and Parallelism is the number of lanes.
type PasswordParams struct {
	Memory      uint32
	Time        uint32
	Parallelism uint8
}

// DefaultPasswordParams returns the production Argon2id parameters: 64 MiB,
// three passes, two lanes.
func DefaultPasswordParams() PasswordParams {
	return PasswordParams{
		Memory:      64 * 1024,
		Time:        3,
		Parallelism: 2,
	}
}

// Validate reports whether the parameters are inside the supported bounds. The
// bounds are deliberately tighter than Argon2's own limits so that parsing an
// attacker-supplied encoded hash cannot request an unbounded allocation.
func (p PasswordParams) Validate() error {
	if p.Memory < passwordMinMemory || p.Memory > passwordMaxMemory {
		return fmt.Errorf("%w: memory must be in [%d, %d] KiB", ErrInvalidPasswordParams, passwordMinMemory, passwordMaxMemory)
	}
	if p.Time < passwordMinTime || p.Time > passwordMaxTime {
		return fmt.Errorf("%w: time must be in [%d, %d]", ErrInvalidPasswordParams, passwordMinTime, passwordMaxTime)
	}
	if p.Parallelism < passwordMinParallel || p.Parallelism > passwordMaxParallel {
		return fmt.Errorf("%w: parallelism must be in [%d, %d]", ErrInvalidPasswordParams, passwordMinParallel, passwordMaxParallel)
	}
	if p.Memory < 8*uint32(p.Parallelism) {
		return fmt.Errorf("%w: memory must be at least 8 KiB per lane", ErrInvalidPasswordParams)
	}
	return nil
}

// HashPassword derives a fresh Argon2id hash of password with a random 16-byte
// salt and encodes it in the fixed format documented above.
//
// Password strength is not assessed here; callers must run
// ValidatePasswordPolicy before hashing a user-chosen password.
func HashPassword(password string, params PasswordParams) (string, error) {
	if err := params.Validate(); err != nil {
		return "", err
	}
	salt := make([]byte, passwordSaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("umcauth: generate password salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, params.Time, params.Memory, params.Parallelism, passwordKeyLength)
	return encodePasswordHash(params, salt, key), nil
}

// VerifyPassword checks password against an encoded Argon2id hash. It returns
// (false, nil) for a well-formed hash that does not match, and an error only
// when the encoded hash is malformed or uses unsupported parameters. The
// comparison is constant time.
func VerifyPassword(encoded, password string) (bool, error) {
	parsed, err := parsePasswordHash(encoded)
	if err != nil {
		return false, err
	}
	key := argon2.IDKey([]byte(password), parsed.salt, parsed.params.Time, parsed.params.Memory, parsed.params.Parallelism, passwordKeyLength)
	return subtle.ConstantTimeCompare(key, parsed.key) == 1, nil
}

// ParsePasswordParams strictly parses an encoded Argon2id hash and returns its
// cost parameters. It is useful for re-hashing on login or for periodic
// parameter upgrades.
func ParsePasswordParams(encoded string) (PasswordParams, error) {
	parsed, err := parsePasswordHash(encoded)
	if err != nil {
		return PasswordParams{}, err
	}
	return parsed.params, nil
}

// ValidatePasswordPolicy reports whether password satisfies the UM-C login
// policy: 12..1024 bytes, valid UTF-8, no NUL byte, and at least one character
// that is neither whitespace nor a control character. It deliberately does not
// echo the password in the returned error.
func ValidatePasswordPolicy(password string) error {
	if n := len(password); n < passwordMinBytes {
		return fmt.Errorf("%w: at least %d bytes required", ErrPasswordPolicy, passwordMinBytes)
	} else if n > passwordMaxBytes {
		return fmt.Errorf("%w: at most %d bytes allowed", ErrPasswordPolicy, passwordMaxBytes)
	}
	if !utf8.ValidString(password) {
		return fmt.Errorf("%w: must be valid UTF-8", ErrPasswordPolicy)
	}
	if strings.IndexByte(password, 0) >= 0 {
		return fmt.Errorf("%w: must not contain a NUL byte", ErrPasswordPolicy)
	}
	for _, r := range password {
		if !unicode.IsSpace(r) && !unicode.IsControl(r) {
			return nil
		}
	}
	return fmt.Errorf("%w: must contain a non-space, non-control character", ErrPasswordPolicy)
}

// passwordHash is the parsed form of an encoded Argon2id hash.
type passwordHash struct {
	params PasswordParams
	salt   []byte
	key    []byte
}

func encodePasswordHash(params PasswordParams, salt, key []byte) string {
	return fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		passwordAlgorithm,
		passwordVersion,
		params.Memory,
		params.Time,
		params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
}

func parsePasswordHash(encoded string) (passwordHash, error) {
	if len(encoded) == 0 || len(encoded) > passwordMaxEncoded {
		return passwordHash{}, fmt.Errorf("%w: encoded length out of range", ErrInvalidPasswordHash)
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" {
		return passwordHash{}, fmt.Errorf("%w: expected $argon2id$v=...$m=...,t=...,p=...$salt$hash", ErrInvalidPasswordHash)
	}
	if parts[1] != passwordAlgorithm {
		return passwordHash{}, fmt.Errorf("%w: unsupported algorithm identifier", ErrInvalidPasswordHash)
	}

	version, err := parseCanonicalUint(parts[2], "v=")
	if err != nil {
		return passwordHash{}, err
	}
	if version != uint64(passwordVersion) {
		return passwordHash{}, fmt.Errorf("%w: unsupported version", ErrInvalidPasswordHash)
	}

	params, err := parsePasswordParamsField(parts[3])
	if err != nil {
		return passwordHash{}, err
	}

	salt, err := decodePasswordBase64(parts[4], "salt")
	if err != nil {
		return passwordHash{}, err
	}
	if len(salt) != passwordSaltLength {
		return passwordHash{}, fmt.Errorf("%w: salt must be %d bytes", ErrInvalidPasswordHash, passwordSaltLength)
	}
	key, err := decodePasswordBase64(parts[5], "hash")
	if err != nil {
		return passwordHash{}, err
	}
	if len(key) != passwordKeyLength {
		return passwordHash{}, fmt.Errorf("%w: hash must be %d bytes", ErrInvalidPasswordHash, passwordKeyLength)
	}
	return passwordHash{params: params, salt: salt, key: key}, nil
}

// parsePasswordParamsField strictly parses the "m=<KiB>,t=<passes>,p=<lanes>"
// field. Order, canonical decimal spelling and bounds are enforced.
func parsePasswordParamsField(field string) (PasswordParams, error) {
	parts := strings.Split(field, ",")
	if len(parts) != 3 {
		return PasswordParams{}, fmt.Errorf("%w: expected exactly m=...,t=...,p=...", ErrInvalidPasswordHash)
	}
	memory, err := parseCanonicalUint(parts[0], "m=")
	if err != nil {
		return PasswordParams{}, err
	}
	iterations, err := parseCanonicalUint(parts[1], "t=")
	if err != nil {
		return PasswordParams{}, err
	}
	lanes, err := parseCanonicalUint(parts[2], "p=")
	if err != nil {
		return PasswordParams{}, err
	}
	if memory > uint64(^uint32(0)) || iterations > uint64(^uint32(0)) || lanes > uint64(^uint8(0)) {
		return PasswordParams{}, fmt.Errorf("%w: parameter value out of range", ErrInvalidPasswordParams)
	}
	params := PasswordParams{
		Memory:      uint32(memory),
		Time:        uint32(iterations),
		Parallelism: uint8(lanes),
	}
	if err := params.Validate(); err != nil {
		return PasswordParams{}, err
	}
	return params, nil
}

// parseCanonicalUint parses an unsigned canonical decimal field with the given
// prefix: ASCII digits only, no sign, no leading zero (except the single digit
// zero), bounded length to avoid pathological conversions.
func parseCanonicalUint(field, prefix string) (uint64, error) {
	if !strings.HasPrefix(field, prefix) {
		return 0, fmt.Errorf("%w: missing %q field", ErrInvalidPasswordHash, prefix)
	}
	digits := field[len(prefix):]
	if digits == "" || len(digits) > 10 {
		return 0, fmt.Errorf("%w: invalid %q field", ErrInvalidPasswordHash, prefix)
	}
	if len(digits) > 1 && digits[0] == '0' {
		return 0, fmt.Errorf("%w: non-canonical %q field", ErrInvalidPasswordHash, prefix)
	}
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return 0, fmt.Errorf("%w: invalid %q field", ErrInvalidPasswordHash, prefix)
		}
	}
	value, err := strconv.ParseUint(digits, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid %q field", ErrInvalidPasswordHash, prefix)
	}
	return value, nil
}

// decodePasswordBase64 decodes canonical unpadded standard base64. Padding,
// URL-safe characters and non-zero trailing bits are rejected.
func decodePasswordBase64(field, name string) ([]byte, error) {
	if field == "" {
		return nil, fmt.Errorf("%w: missing %s", ErrInvalidPasswordHash, name)
	}
	decoded, err := base64.RawStdEncoding.Strict().DecodeString(field)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid %s encoding", ErrInvalidPasswordHash, name)
	}
	if base64.RawStdEncoding.EncodeToString(decoded) != field {
		return nil, fmt.Errorf("%w: non-canonical %s encoding", ErrInvalidPasswordHash, name)
	}
	return decoded, nil
}

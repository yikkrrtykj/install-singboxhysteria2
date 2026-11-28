package umcauth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// Cryptographic Cloudflare Access JWT verification.
//
// Verify parses and validates a compact JWT before touching the network: the
// token must have exactly three unpadded base64url segments below the size
// limit, its header and payload must be JSON objects without duplicate member
// names, the algorithm must be RS256 or ES256, forbidden key-discovery headers
// (jku, x5u, jwk, x5c, crit) must be absent, and all claims (iss, aud, sub, exp
// and optionally nbf/iat) must be valid before a JWKS request is even
// considered. The signature is then verified against keys fetched from the
// configured JWKS URL, which must be HTTPS unless AllowInsecureHTTPForTests is
// set; redirects are disabled, the response is size-capped, and fetched keys
// are cached until CacheTTL expires. Unknown key ids trigger at most one forced
// refresh per unknownKeyIDRefreshCooldown so a flood of tokens with invented
// kids cannot become a JWKS refresh storm. Any JWKS failure fails closed.
//
// Nothing in this file logs. Errors never contain the raw token, header or
// claim values, and Verify only returns the small safe structs declared below.
const (
	defaultAccessJWTCacheTTL     = 5 * time.Minute
	defaultAccessJWTFetchTimeout = 5 * time.Second
	defaultMaxAccessJWTBytes     = 8 * 1024
	defaultMaxAccessJWKSBytes    = 64 * 1024
	minAccessJWTBytes            = 512
	maxAccessJWTBytesLimit       = 64 * 1024
	minAccessJWKSBytes           = 512
	maxAccessJWKSBytesLimit      = 1024 * 1024
	maxAccessJWTHeaderBytes      = 4 * 1024
	maxAccessJWTSignatureBytes   = 1024 // 8192-bit RSA
	maxAccessJWTHeaderMembers    = 32
	maxAccessJWTClaimMembers     = 128
	maxAccessJWKSKeys            = 64
	maxAccessJWKSTopLevelMembers = 16
	maxAccessJWKKeyMembers       = 32
	maxAccessJWTJSONDepth        = 16
	maxAccessJWTKeyIDBytes       = 256
	maxAccessJWTSubjectBytes     = 1024
	maxAccessJWTAudienceBytes    = 512
	maxAccessJWTAudiences        = 32
	maxAccessJWTIssuerBytes      = 2048
	maxAccessJWTNumericDate      = 253402300799 // 9999-12-31T23:59:59Z
	maxAccessJWTLeeway           = 5 * time.Minute
	maxAccessJWTCacheTTL         = time.Hour
	unknownKeyIDRefreshCooldown  = 30 * time.Second
	minAccessJWTRSABits          = 2048
	maxAccessJWTRSABits          = 8192
)

// Access JWT verifier errors. They identify the failed check without echoing
// token contents, claim values or key material, so they are safe to log.
var (
	// ErrInvalidConfig reports an unusable verifier configuration.
	ErrInvalidConfig = errors.New("umcauth: invalid access JWT verifier configuration")
	// ErrMalformedToken reports a token that does not have the strict compact
	// JWT structure or well-formed JSON header/payload.
	ErrMalformedToken = errors.New("umcauth: malformed access JWT")
	// ErrTokenTooLarge reports a token above MaxJWTBytes.
	ErrTokenTooLarge = errors.New("umcauth: access JWT exceeds the size limit")
	// ErrUnsupportedAlgorithm reports an alg outside the RS256/ES256 allowlist.
	ErrUnsupportedAlgorithm = errors.New("umcauth: unsupported access JWT algorithm")
	// ErrUnsupportedHeader reports a forbidden or unsupported JOSE header.
	ErrUnsupportedHeader = errors.New("umcauth: unsupported access JWT header")
	// ErrMalformedClaims reports a claims payload that is not a valid object or
	// has invalid claim types/bounds.
	ErrMalformedClaims = errors.New("umcauth: access JWT claims are invalid")
	// ErrIssuerMismatch reports an iss claim that is not exactly the configured
	// issuer.
	ErrIssuerMismatch = errors.New("umcauth: access JWT issuer mismatch")
	// ErrAudienceMismatch reports that aud does not contain the configured
	// audience.
	ErrAudienceMismatch = errors.New("umcauth: access JWT audience mismatch")
	// ErrInvalidSubject reports a missing, empty or oversized sub claim.
	ErrInvalidSubject = errors.New("umcauth: access JWT subject is invalid")
	// ErrTokenExpired reports an exp claim in the past beyond Leeway.
	ErrTokenExpired = errors.New("umcauth: access JWT expired")
	// ErrTokenNotYetValid reports an nbf claim in the future beyond Leeway.
	ErrTokenNotYetValid = errors.New("umcauth: access JWT is not yet valid")
	// ErrIssuedInFuture reports an iat claim in the future beyond Leeway.
	ErrIssuedInFuture = errors.New("umcauth: access JWT was issued in the future")
	// ErrInvalidSignature reports a signature that does not verify with the
	// trusted key for the token's key id.
	ErrInvalidSignature = errors.New("umcauth: access JWT signature invalid")
	// ErrKeyAlgorithmMismatch reports an RS256/ES256 algorithm that does not
	// match the trusted key material for the token's key id.
	ErrKeyAlgorithmMismatch = errors.New("umcauth: access JWT algorithm does not match the signing key")
	// ErrUnknownKeyID reports a kid absent from a successfully fetched JWKS,
	// including after the single allowed rotation refresh.
	ErrUnknownKeyID = errors.New("umcauth: access JWT key id is not in the trusted JWKS")
	// ErrJWKSUnavailable reports a failed, timed-out, oversized, malformed or
	// otherwise untrusted JWKS fetch.
	ErrJWKSUnavailable = errors.New("umcauth: access JWKS unavailable or invalid")
)

// Config configures a Verifier. Issuer, Audience and JWKSURL are required and
// are trusted configuration, never derived from a request.
type Config struct {
	// Issuer is the exact expected "iss" claim (for Cloudflare Access, the
	// team's access domain).
	Issuer string
	// Audience is the Access application audience (AUD) tag that must appear
	// in "aud", either as a string or in an array of strings.
	Audience string
	// JWKSURL is the trusted HTTPS URL of the Access JWKS document.
	JWKSURL string
	// HTTPClient optionally supplies the HTTP client used for JWKS fetches. A
	// private copy is used; redirects are always disabled and the fetch is
	// context/timeout-bounded. Nil uses a bounded default client.
	HTTPClient *http.Client
	// Now optionally supplies the clock. Nil uses time.Now.
	Now func() time.Time
	// CacheTTL is how long a successfully fetched JWKS is trusted. Zero uses
	// the 5-minute default.
	CacheTTL time.Duration
	// Leeway is the accepted clock skew for exp, nbf and iat. Zero means no
	// leeway; it must not exceed 5 minutes.
	Leeway time.Duration
	// MaxJWTBytes bounds the raw compact token size. Zero uses 8 KiB.
	MaxJWTBytes int
	// MaxJWKSBytes bounds the raw JWKS response size. Zero uses 64 KiB.
	MaxJWKSBytes int
	// AllowInsecureHTTPForTests permits an http:// JWKS URL. It exists only
	// for hermetic tests and must never be set in production.
	AllowInsecureHTTPForTests bool
}

// VerifiedHeader is the safe subset of a verified token's JOSE header returned
// to callers.
type VerifiedHeader struct {
	// Algorithm is the verified "alg" value: RS256 or ES256.
	Algorithm string
	// KeyID is the verified "kid" value used to select the trusted key.
	KeyID string
	// Type is the "typ" value, if present. Only "JWT" is accepted.
	Type string
}

// VerifiedClaims is the safe subset of a verified token's claims returned to
// callers. It intentionally does not expose the raw token or its JSON payload.
type VerifiedClaims struct {
	Issuer       string
	Audience     []string
	Subject      string
	ExpiresAt    time.Time
	IssuedAt     time.Time
	HasIssuedAt  bool
	NotBefore    time.Time
	HasNotBefore bool
}

// VerifiedToken is the result of a successful Verify call.
type VerifiedToken struct {
	Header VerifiedHeader
	Claims VerifiedClaims
}

// Verifier verifies Cloudflare Access JWTs against a cached, trusted JWKS.
// A Verifier is safe for concurrent use. Keys are fetched lazily on the first
// verification (or after cache expiry), never at construction time.
type Verifier struct {
	issuer   string
	audience string
	jwksURL  string
	client   *http.Client
	now      func() time.Time
	cacheTTL time.Duration
	leeway   time.Duration
	maxJWT   int
	maxJWKS  int

	mu                    sync.RWMutex
	keys                  map[string]*jwkKey
	cacheExpiry           time.Time
	lastUnknownKeyRefresh time.Time

	refreshMu sync.Mutex
}

// NewVerifier validates cfg and returns a verifier. It performs no network I/O.
func NewVerifier(cfg Config) (*Verifier, error) {
	maxJWT, maxJWKS, cacheTTL, err := validateAccessJWTConfig(cfg)
	if err != nil {
		return nil, err
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultAccessJWTFetchTimeout}
	} else {
		// Copy so the caller's client is not mutated; redirects are always
		// refused and the fetch still carries a context deadline.
		copied := *client
		client = &copied
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if client.Timeout <= 0 {
		client.Timeout = defaultAccessJWTFetchTimeout
	}
	return &Verifier{
		issuer:   cfg.Issuer,
		audience: cfg.Audience,
		jwksURL:  cfg.JWKSURL,
		client:   client,
		now:      now,
		cacheTTL: cacheTTL,
		leeway:   cfg.Leeway,
		maxJWT:   maxJWT,
		maxJWKS:  maxJWKS,
	}, nil
}

// Verify validates a compact Access JWT and returns only its safe header and
// claim subset. It performs JWKS I/O only after the token structure, header,
// claims and time bounds have all been validated.
func (v *Verifier) Verify(ctx context.Context, rawToken string) (*VerifiedToken, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	now := v.now()
	parsed, err := v.parseToken(rawToken, now)
	if err != nil {
		return nil, err
	}
	key, err := v.resolveKey(ctx, parsed.keyID, parsed.algorithm, now)
	if err != nil {
		return nil, err
	}
	if err := verifyAccessJWTSignature(parsed.algorithm, key, parsed.signingInput, parsed.signature); err != nil {
		return nil, err
	}
	return &VerifiedToken{
		Header: VerifiedHeader{
			Algorithm: parsed.algorithm,
			KeyID:     parsed.keyID,
			Type:      parsed.typ,
		},
		Claims: parsed.claims,
	}, nil
}

// parsedAccessJWT is the internal, pre-signature parse of a compact token. It
// is never exported, so raw header/payload bytes do not escape the verifier.
type parsedAccessJWT struct {
	algorithm    string
	keyID        string
	typ          string
	claims       VerifiedClaims
	signingInput []byte
	signature    []byte
}

func (v *Verifier) parseToken(rawToken string, now time.Time) (*parsedAccessJWT, error) {
	if rawToken == "" {
		return nil, fmt.Errorf("%w: empty token", ErrMalformedToken)
	}
	if len(rawToken) > v.maxJWT {
		return nil, fmt.Errorf("%w: token exceeds %d bytes", ErrTokenTooLarge, v.maxJWT)
	}
	segments := strings.Split(rawToken, ".")
	if len(segments) != 3 {
		return nil, fmt.Errorf("%w: compact JWT must have exactly three segments", ErrMalformedToken)
	}
	for _, segment := range segments {
		if segment == "" {
			return nil, fmt.Errorf("%w: empty token segment", ErrMalformedToken)
		}
	}

	headerJSON, err := decodeJWTBase64URL(segments[0])
	if err != nil {
		return nil, err
	}
	if len(headerJSON) > maxAccessJWTHeaderBytes {
		return nil, fmt.Errorf("%w: header exceeds %d bytes", ErrMalformedToken, maxAccessJWTHeaderBytes)
	}
	payloadJSON, err := decodeJWTBase64URL(segments[1])
	if err != nil {
		return nil, err
	}
	signature, err := decodeJWTBase64URL(segments[2])
	if err != nil {
		return nil, err
	}
	if len(signature) > maxAccessJWTSignatureBytes {
		return nil, fmt.Errorf("%w: signature exceeds %d bytes", ErrMalformedToken, maxAccessJWTSignatureBytes)
	}

	algorithm, keyID, typ, err := parseAccessJWTHeader(headerJSON)
	if err != nil {
		return nil, err
	}
	// ES256 signatures have a fixed 64-byte R||S encoding. Rejecting a wrong
	// length here keeps obviously malformed tokens from reaching the JWKS
	// fetch; RSA signatures are length-checked against the trusted modulus
	// after key resolution.
	if algorithm == "ES256" && len(signature) != 64 {
		return nil, ErrInvalidSignature
	}
	claims, err := v.parseAccessJWTClaims(payloadJSON, now)
	if err != nil {
		return nil, err
	}

	signingInput := make([]byte, 0, len(segments[0])+1+len(segments[1]))
	signingInput = append(signingInput, segments[0]...)
	signingInput = append(signingInput, '.')
	signingInput = append(signingInput, segments[1]...)
	return &parsedAccessJWT{
		algorithm:    algorithm,
		keyID:        keyID,
		typ:          typ,
		claims:       claims,
		signingInput: signingInput,
		signature:    signature,
	}, nil
}

func decodeJWTBase64URL(segment string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(segment)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid unpadded base64url segment", ErrMalformedToken)
	}
	if len(decoded) == 0 {
		return nil, fmt.Errorf("%w: empty decoded segment", ErrMalformedToken)
	}
	if base64.RawURLEncoding.EncodeToString(decoded) != segment {
		return nil, fmt.Errorf("%w: non-canonical base64url segment", ErrMalformedToken)
	}
	return decoded, nil
}

func parseAccessJWTHeader(data []byte) (algorithm, keyID, typ string, err error) {
	header, err := decodeStrictJSONObject(data, maxAccessJWTHeaderMembers)
	if err != nil {
		return "", "", "", fmt.Errorf("%w: header: %v", ErrMalformedToken, err)
	}
	for _, forbidden := range []string{"jku", "x5u", "jwk", "x5c", "crit"} {
		if _, present := header[forbidden]; present {
			return "", "", "", fmt.Errorf("%w: %q is not accepted", ErrUnsupportedHeader, forbidden)
		}
	}
	algorithm, err = requiredJSONString(header, "alg")
	if err != nil {
		return "", "", "", fmt.Errorf("%w: header: %v", ErrMalformedToken, err)
	}
	switch algorithm {
	case "RS256", "ES256":
	default:
		return "", "", "", fmt.Errorf("%w: only RS256 and ES256 are accepted", ErrUnsupportedAlgorithm)
	}
	keyID, err = requiredJSONString(header, "kid")
	if err != nil {
		return "", "", "", fmt.Errorf("%w: header: %v", ErrMalformedToken, err)
	}
	if err := validateAccessJWTText("kid", keyID, maxAccessJWTKeyIDBytes); err != nil {
		return "", "", "", fmt.Errorf("%w: %v", ErrMalformedToken, err)
	}
	if rawType, present := header["typ"]; present {
		if isJSONNull(rawType) {
			return "", "", "", fmt.Errorf("%w: typ must not be null", ErrMalformedToken)
		}
		if err := json.Unmarshal(rawType, &typ); err != nil {
			return "", "", "", fmt.Errorf("%w: typ must be a string", ErrMalformedToken)
		}
		if !strings.EqualFold(typ, "JWT") {
			return "", "", "", fmt.Errorf("%w: typ must be JWT", ErrUnsupportedHeader)
		}
	}
	return algorithm, keyID, typ, nil
}

func (v *Verifier) parseAccessJWTClaims(data []byte, now time.Time) (VerifiedClaims, error) {
	claims, err := decodeStrictJSONObject(data, maxAccessJWTClaimMembers)
	if err != nil {
		return VerifiedClaims{}, fmt.Errorf("%w: payload: %v", ErrMalformedClaims, err)
	}

	issuer, err := requiredJSONString(claims, "iss")
	if err != nil {
		return VerifiedClaims{}, fmt.Errorf("%w: payload: %v", ErrMalformedClaims, err)
	}
	if issuer != v.issuer {
		return VerifiedClaims{}, ErrIssuerMismatch
	}

	audienceRaw, present := claims["aud"]
	if !present {
		return VerifiedClaims{}, fmt.Errorf("%w: aud is required", ErrMalformedClaims)
	}
	audiences, err := parseAccessJWTAudience(audienceRaw)
	if err != nil {
		return VerifiedClaims{}, err
	}
	audienceMatches := false
	for _, audience := range audiences {
		if audience == v.audience {
			audienceMatches = true
			break
		}
	}
	if !audienceMatches {
		return VerifiedClaims{}, ErrAudienceMismatch
	}

	subject, err := requiredJSONString(claims, "sub")
	if err != nil {
		return VerifiedClaims{}, fmt.Errorf("%w: payload: %v", ErrMalformedClaims, err)
	}
	if strings.TrimSpace(subject) == "" {
		return VerifiedClaims{}, fmt.Errorf("%w: sub must not be blank", ErrInvalidSubject)
	}
	if err := validateAccessJWTText("sub", subject, maxAccessJWTSubjectBytes); err != nil {
		return VerifiedClaims{}, fmt.Errorf("%w: %v", ErrInvalidSubject, err)
	}

	expiresAt, err := requiredJSONNumericDate(claims, "exp")
	if err != nil {
		return VerifiedClaims{}, err
	}
	expiresTime := time.Unix(expiresAt, 0).UTC()
	if !now.Before(expiresTime.Add(v.leeway)) {
		return VerifiedClaims{}, ErrTokenExpired
	}

	verified := VerifiedClaims{
		Issuer:    issuer,
		Audience:  audiences,
		Subject:   subject,
		ExpiresAt: expiresTime,
	}
	if notBefore, present, err := optionalJSONNumericDate(claims, "nbf"); err != nil {
		return VerifiedClaims{}, err
	} else if present {
		if notBefore > expiresAt {
			return VerifiedClaims{}, fmt.Errorf("%w: nbf is after exp", ErrMalformedClaims)
		}
		notBeforeTime := time.Unix(notBefore, 0).UTC()
		if now.Add(v.leeway).Before(notBeforeTime) {
			return VerifiedClaims{}, ErrTokenNotYetValid
		}
		verified.NotBefore = notBeforeTime
		verified.HasNotBefore = true
	}
	if issuedAt, present, err := optionalJSONNumericDate(claims, "iat"); err != nil {
		return VerifiedClaims{}, err
	} else if present {
		if issuedAt > expiresAt {
			return VerifiedClaims{}, fmt.Errorf("%w: iat is after exp", ErrMalformedClaims)
		}
		issuedTime := time.Unix(issuedAt, 0).UTC()
		if now.Add(v.leeway).Before(issuedTime) {
			return VerifiedClaims{}, ErrIssuedInFuture
		}
		verified.IssuedAt = issuedTime
		verified.HasIssuedAt = true
	}
	return verified, nil
}

func parseAccessJWTAudience(raw json.RawMessage) ([]string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || isJSONNull(trimmed) {
		return nil, fmt.Errorf("%w: aud is required", ErrMalformedClaims)
	}
	switch trimmed[0] {
	case '"':
		var single string
		if err := json.Unmarshal(raw, &single); err != nil {
			return nil, fmt.Errorf("%w: aud must be a string or an array of strings", ErrMalformedClaims)
		}
		if err := validateAccessJWTText("aud", single, maxAccessJWTAudienceBytes); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformedClaims, err)
		}
		return []string{single}, nil
	case '[':
		var multiple []string
		if err := json.Unmarshal(raw, &multiple); err != nil {
			return nil, fmt.Errorf("%w: aud must be a string or an array of strings", ErrMalformedClaims)
		}
		if len(multiple) == 0 || len(multiple) > maxAccessJWTAudiences {
			return nil, fmt.Errorf("%w: aud array length out of range", ErrMalformedClaims)
		}
		for _, audience := range multiple {
			if err := validateAccessJWTText("aud", audience, maxAccessJWTAudienceBytes); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedClaims, err)
			}
		}
		return multiple, nil
	default:
		return nil, fmt.Errorf("%w: aud must be a string or an array of strings", ErrMalformedClaims)
	}
}

// requiredJSONNumericDate parses a required NumericDate claim.
func requiredJSONNumericDate(object map[string]json.RawMessage, name string) (int64, error) {
	raw, present := object[name]
	if !present {
		return 0, fmt.Errorf("%w: %s is required", ErrMalformedClaims, name)
	}
	return parseJSONNumericDate(raw, name)
}

func optionalJSONNumericDate(object map[string]json.RawMessage, name string) (int64, bool, error) {
	raw, present := object[name]
	if !present {
		return 0, false, nil
	}
	value, err := parseJSONNumericDate(raw, name)
	if err != nil {
		return 0, false, err
	}
	return value, true, nil
}

// parseJSONNumericDate accepts only a canonical JSON integer in
// [0, maxAccessJWTNumericDate]; strings, fractions, exponents, negative values
// and out-of-range values are rejected so exp/nbf/iat are always bounded.
func parseJSONNumericDate(raw json.RawMessage, name string) (int64, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || isJSONNull(trimmed) {
		return 0, fmt.Errorf("%w: %s must be a NumericDate", ErrMalformedClaims, name)
	}
	if trimmed[0] != '-' && (trimmed[0] < '0' || trimmed[0] > '9') {
		return 0, fmt.Errorf("%w: %s must be a NumericDate", ErrMalformedClaims, name)
	}
	for _, c := range trimmed {
		if c == '.' || c == 'e' || c == 'E' || c == '+' {
			return 0, fmt.Errorf("%w: %s must be an integer NumericDate", ErrMalformedClaims, name)
		}
	}
	var number json.Number
	if err := json.Unmarshal(raw, &number); err != nil {
		return 0, fmt.Errorf("%w: %s must be a NumericDate", ErrMalformedClaims, name)
	}
	value, err := strconv.ParseInt(number.String(), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %s is out of range", ErrMalformedClaims, name)
	}
	if value < 0 || value > maxAccessJWTNumericDate {
		return 0, fmt.Errorf("%w: %s is out of range", ErrMalformedClaims, name)
	}
	return value, nil
}

func requiredJSONString(object map[string]json.RawMessage, name string) (string, error) {
	raw, present := object[name]
	if !present {
		return "", fmt.Errorf("%s is required", name)
	}
	if isJSONNull(raw) {
		return "", fmt.Errorf("%s must not be null", name)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("%s must be a string", name)
	}
	return value, nil
}

func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// validateAccessJWTText enforces non-empty, valid UTF-8, bounded and
// control-character-free claim/key-id values.
func validateAccessJWTText(name, value string, maxBytes int) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", name)
	}
	if len(value) > maxBytes {
		return fmt.Errorf("%s exceeds %d bytes", name, maxBytes)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s must be valid UTF-8", name)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s must not contain control characters", name)
		}
	}
	return nil
}

// key resolution and JWKS cache management.

func (v *Verifier) resolveKey(ctx context.Context, keyID, algorithm string, now time.Time) (*jwkKey, error) {
	if key, _ := v.cachedKey(keyID, now); key != nil {
		if !key.supports(algorithm) {
			return nil, ErrKeyAlgorithmMismatch
		}
		return key, nil
	}
	// Cache miss: either no cache yet, an expired cache, or a fresh cache that
	// does not know this kid (possible Access key rotation). The refresh is
	// serialized and unknown-kid refreshes are rate-limited.
	return v.resolveUnknownKey(ctx, keyID, algorithm, now)
}

func (v *Verifier) resolveUnknownKey(ctx context.Context, keyID, algorithm string, now time.Time) (*jwkKey, error) {
	v.refreshMu.Lock()
	defer v.refreshMu.Unlock()

	// Another goroutine may have refreshed the cache while we waited.
	key, cacheValid := v.cachedKey(keyID, now)
	if key != nil {
		if !key.supports(algorithm) {
			return nil, ErrKeyAlgorithmMismatch
		}
		return key, nil
	}
	if cacheValid {
		if !v.unknownKeyRefreshAllowed(now) {
			return nil, fmt.Errorf("%w: key id not found", ErrUnknownKeyID)
		}
		v.markUnknownKeyRefresh(now)
		if err := v.fetchAndCache(ctx, now); err != nil {
			return nil, err
		}
		key, _ = v.cachedKey(keyID, now)
		if key == nil {
			return nil, fmt.Errorf("%w: key id not found", ErrUnknownKeyID)
		}
		if !key.supports(algorithm) {
			return nil, ErrKeyAlgorithmMismatch
		}
		return key, nil
	}

	// No usable cache: ordinary first load or TTL refresh. A failure here fails
	// closed instead of falling back to stale keys.
	if err := v.fetchAndCache(ctx, now); err != nil {
		return nil, err
	}
	key, _ = v.cachedKey(keyID, now)
	if key == nil {
		// The freshly fetched trusted set does not contain the kid. Record the
		// attempt so repeated unknown-kid tokens cannot force another
		// immediate fetch, then fail closed.
		v.markUnknownKeyRefresh(now)
		return nil, fmt.Errorf("%w: key id not found", ErrUnknownKeyID)
	}
	if !key.supports(algorithm) {
		return nil, ErrKeyAlgorithmMismatch
	}
	return key, nil
}

func (v *Verifier) cachedKey(keyID string, now time.Time) (*jwkKey, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.keys == nil || !now.Before(v.cacheExpiry) {
		return nil, false
	}
	return v.keys[keyID], true
}

func (v *Verifier) unknownKeyRefreshAllowed(now time.Time) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.lastUnknownKeyRefresh.IsZero() ||
		now.Sub(v.lastUnknownKeyRefresh) >= unknownKeyIDRefreshCooldown
}

func (v *Verifier) markUnknownKeyRefresh(now time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.lastUnknownKeyRefresh = now
}

func (v *Verifier) fetchAndCache(ctx context.Context, now time.Time) error {
	keys, err := v.fetchJWKS(ctx)
	if err != nil {
		return err
	}
	v.mu.Lock()
	v.keys = keys
	v.cacheExpiry = now.Add(v.cacheTTL)
	v.mu.Unlock()
	return nil
}

func (v *Verifier) fetchJWKS(ctx context.Context) (map[string]*jwkKey, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, defaultAccessJWTFetchTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: could not build request", ErrJWKSUnavailable)
	}
	request.Header.Set("Accept", "application/json")
	response, err := v.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed", ErrJWKSUnavailable)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: unexpected status %d", ErrJWKSUnavailable, response.StatusCode)
	}
	if response.ContentLength > int64(v.maxJWKS) {
		return nil, fmt.Errorf("%w: response exceeds %d bytes", ErrJWKSUnavailable, v.maxJWKS)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(v.maxJWKS)+1))
	if err != nil {
		return nil, fmt.Errorf("%w: could not read response", ErrJWKSUnavailable)
	}
	if len(body) > v.maxJWKS {
		return nil, fmt.Errorf("%w: response exceeds %d bytes", ErrJWKSUnavailable, v.maxJWKS)
	}
	keys, err := parseJWKS(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWKSUnavailable, err)
	}
	return keys, nil
}

// jwkKey is one parsed, allowlisted signing key from the trusted JWKS.
type jwkKey struct {
	keyID string
	rsa   *rsa.PublicKey
	ecdsa *ecdsa.PublicKey
}

func (k *jwkKey) supports(algorithm string) bool {
	switch algorithm {
	case "RS256":
		return k != nil && k.rsa != nil
	case "ES256":
		return k != nil && k.ecdsa != nil
	default:
		return false
	}
}

func parseJWKS(data []byte) (map[string]*jwkKey, error) {
	topLevel, err := decodeStrictJSONObject(data, maxAccessJWKSTopLevelMembers)
	if err != nil {
		return nil, fmt.Errorf("invalid JWKS JSON: %w", err)
	}
	rawKeys, present := topLevel["keys"]
	if !present {
		return nil, errors.New("JWKS has no keys member")
	}
	trimmed := bytes.TrimSpace(rawKeys)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, errors.New("JWKS keys member must be an array")
	}
	var documents []json.RawMessage
	if err := json.Unmarshal(rawKeys, &documents); err != nil {
		return nil, errors.New("JWKS keys member must be an array of objects")
	}
	if len(documents) == 0 {
		return nil, errors.New("JWKS contains no keys")
	}
	if len(documents) > maxAccessJWKSKeys {
		return nil, fmt.Errorf("JWKS contains more than %d keys", maxAccessJWKSKeys)
	}
	keys := make(map[string]*jwkKey, len(documents))
	for index, document := range documents {
		key, err := parseJWK(document)
		if err != nil {
			return nil, fmt.Errorf("JWKS key %d: %w", index, err)
		}
		if key == nil {
			// Not usable for the fixed RS256/ES256 allowlist (unsupported
			// kty/use/alg/key_ops); ignoring it cannot widen trust.
			continue
		}
		if _, duplicate := keys[key.keyID]; duplicate {
			return nil, fmt.Errorf("JWKS key %d: duplicate key id", index)
		}
		keys[key.keyID] = key
	}
	if len(keys) == 0 {
		return nil, errors.New("JWKS contains no usable signing keys")
	}
	return keys, nil
}

// parseJWK returns (nil, nil) for a syntactically valid key that the fixed
// allowlist cannot use, and an error for a malformed supported key.
func parseJWK(document json.RawMessage) (*jwkKey, error) {
	trimmed := bytes.TrimSpace(document)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, errors.New("key must be a JSON object")
	}
	object, err := decodeStrictJSONObject(document, maxAccessJWKKeyMembers)
	if err != nil {
		return nil, err
	}
	kid, present, err := optionalJSONString(object, "kid")
	if err != nil {
		return nil, err
	}
	if !present || validateAccessJWTText("kid", kid, maxAccessJWTKeyIDBytes) != nil {
		// A key without a usable kid can never be selected by a token.
		return nil, nil
	}
	keyType, err := requiredJSONString(object, "kty")
	if err != nil {
		return nil, err
	}
	use, present, err := optionalJSONString(object, "use")
	if err != nil {
		return nil, err
	}
	if present && use != "sig" {
		return nil, nil
	}
	algorithm, present, err := optionalJSONString(object, "alg")
	if err != nil {
		return nil, err
	}
	keyOps, err := parseJWKKeyOps(object)
	if err != nil {
		return nil, err
	}
	if keyOps != nil && !containsString(keyOps, "verify") {
		return nil, nil
	}

	switch keyType {
	case "RSA":
		if present && algorithm != "RS256" {
			return nil, nil
		}
		publicKey, err := parseRSAJWK(object)
		if err != nil {
			return nil, err
		}
		return &jwkKey{keyID: kid, rsa: publicKey}, nil
	case "EC":
		if present && algorithm != "ES256" {
			return nil, nil
		}
		publicKey, err := parseECJWK(object)
		if errors.Is(err, errUnusableJWK) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return &jwkKey{keyID: kid, ecdsa: publicKey}, nil
	default:
		// Unknown key types (for example oct/OKP) are never usable for the
		// fixed RS256/ES256 allowlist.
		return nil, nil
	}
}

func optionalJSONString(object map[string]json.RawMessage, name string) (string, bool, error) {
	raw, present := object[name]
	if !present {
		return "", false, nil
	}
	if isJSONNull(raw) {
		return "", false, fmt.Errorf("%s must not be null", name)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false, fmt.Errorf("%s must be a string", name)
	}
	return value, true, nil
}

func parseJWKKeyOps(object map[string]json.RawMessage) ([]string, error) {
	raw, present := object["key_ops"]
	if !present || isJSONNull(raw) {
		return nil, nil
	}
	var operations []string
	if err := json.Unmarshal(raw, &operations); err != nil {
		return nil, errors.New("key_ops must be an array of strings")
	}
	if len(operations) > 16 {
		return nil, errors.New("key_ops is too long")
	}
	return operations, nil
}

func parseRSAJWK(object map[string]json.RawMessage) (*rsa.PublicKey, error) {
	encodedModulus, err := requiredJSONString(object, "n")
	if err != nil {
		return nil, err
	}
	encodedExponent, err := requiredJSONString(object, "e")
	if err != nil {
		return nil, err
	}
	modulusBytes, err := decodeJWKBase64URL(encodedModulus)
	if err != nil {
		return nil, err
	}
	exponentBytes, err := decodeJWKBase64URL(encodedExponent)
	if err != nil {
		return nil, err
	}
	modulus := new(big.Int).SetBytes(modulusBytes)
	if modulus.Sign() <= 0 || modulus.BitLen() < minAccessJWTRSABits || modulus.BitLen() > maxAccessJWTRSABits {
		return nil, fmt.Errorf("RSA modulus must be %d..%d bits", minAccessJWTRSABits, maxAccessJWTRSABits)
	}
	if modulus.Bit(0) == 0 {
		return nil, errors.New("RSA modulus must be odd")
	}
	if len(exponentBytes) == 0 || len(exponentBytes) > 4 {
		return nil, errors.New("RSA exponent length out of range")
	}
	exponent := new(big.Int).SetBytes(exponentBytes)
	// RFC 7518 requires a public exponent >= 3; bound it to 2^31-1 so the
	// verifier never performs an unexpectedly expensive modular exponentiation.
	if exponent.Cmp(big.NewInt(3)) < 0 || exponent.BitLen() > 31 || exponent.Bit(0) == 0 {
		return nil, errors.New("RSA exponent out of range")
	}
	return &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}, nil
}

func parseECJWK(object map[string]json.RawMessage) (*ecdsa.PublicKey, error) {
	curve, err := requiredJSONString(object, "crv")
	if err != nil {
		return nil, err
	}
	if curve != "P-256" {
		// Non-P-256 curves are not usable for ES256.
		return nil, errUnusableJWK
	}
	encodedX, err := requiredJSONString(object, "x")
	if err != nil {
		return nil, err
	}
	encodedY, err := requiredJSONString(object, "y")
	if err != nil {
		return nil, err
	}
	xBytes, err := decodeJWKBase64URL(encodedX)
	if err != nil {
		return nil, err
	}
	yBytes, err := decodeJWKBase64URL(encodedY)
	if err != nil {
		return nil, err
	}
	if len(xBytes) != 32 || len(yBytes) != 32 {
		return nil, errors.New("P-256 coordinates must be 32 bytes")
	}
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	p256 := elliptic.P256()
	if !p256.IsOnCurve(x, y) {
		return nil, errors.New("EC public key is not on P-256")
	}
	return &ecdsa.PublicKey{Curve: p256, X: x, Y: y}, nil
}

// errUnusableJWK marks a supported key type that the fixed allowlist cannot
// use; it is converted to a skip rather than a JWKS parse failure.
var errUnusableJWK = errors.New("umcauth: JWK is not usable for RS256/ES256")

func decodeJWKBase64URL(value string) ([]byte, error) {
	if value == "" {
		return nil, errors.New("empty base64url key field")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		return nil, errors.New("invalid base64url key field")
	}
	return decoded, nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func verifyAccessJWTSignature(algorithm string, key *jwkKey, signingInput, signature []byte) error {
	if key == nil {
		return ErrUnknownKeyID
	}
	digest := sha256.Sum256(signingInput)
	switch algorithm {
	case "RS256":
		if key.rsa == nil {
			return ErrKeyAlgorithmMismatch
		}
		if err := rsa.VerifyPKCS1v15(key.rsa, crypto.SHA256, digest[:], signature); err != nil {
			return ErrInvalidSignature
		}
		return nil
	case "ES256":
		if key.ecdsa == nil {
			return ErrKeyAlgorithmMismatch
		}
		if len(signature) != 64 {
			return ErrInvalidSignature
		}
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		if r.Sign() == 0 || s.Sign() == 0 {
			return ErrInvalidSignature
		}
		if !ecdsa.Verify(key.ecdsa, digest[:], r, s) {
			return ErrInvalidSignature
		}
		return nil
	default:
		return ErrUnsupportedAlgorithm
	}
}

// validateAccessJWTConfig validates cfg and returns the effective size/TTL
// values (applying defaults for zero fields).
func validateAccessJWTConfig(cfg Config) (maxJWT, maxJWKS int, cacheTTL time.Duration, err error) {
	if err := validateAccessJWTText("issuer", cfg.Issuer, maxAccessJWTIssuerBytes); err != nil {
		return 0, 0, 0, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	if strings.TrimSpace(cfg.Issuer) != cfg.Issuer {
		return 0, 0, 0, fmt.Errorf("%w: issuer must not have surrounding whitespace", ErrInvalidConfig)
	}
	if err := validateAccessJWTText("audience", cfg.Audience, maxAccessJWTAudienceBytes); err != nil {
		return 0, 0, 0, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	if strings.TrimSpace(cfg.Audience) != cfg.Audience {
		return 0, 0, 0, fmt.Errorf("%w: audience must not have surrounding whitespace", ErrInvalidConfig)
	}
	if len(cfg.JWKSURL) == 0 || len(cfg.JWKSURL) > 2048 {
		return 0, 0, 0, fmt.Errorf("%w: JWKS URL length out of range", ErrInvalidConfig)
	}
	parsedURL, err := url.Parse(cfg.JWKSURL)
	if err != nil || parsedURL.Host == "" || parsedURL.User != nil || parsedURL.Fragment != "" || parsedURL.Opaque != "" {
		return 0, 0, 0, fmt.Errorf("%w: JWKS URL is not an absolute URL without userinfo or fragment", ErrInvalidConfig)
	}
	switch parsedURL.Scheme {
	case "https":
	case "http":
		if !cfg.AllowInsecureHTTPForTests {
			return 0, 0, 0, fmt.Errorf("%w: JWKS URL must use HTTPS", ErrInvalidConfig)
		}
	default:
		return 0, 0, 0, fmt.Errorf("%w: JWKS URL must use HTTPS", ErrInvalidConfig)
	}
	if cfg.Leeway < 0 || cfg.Leeway > maxAccessJWTLeeway {
		return 0, 0, 0, fmt.Errorf("%w: leeway must be in [0, %s]", ErrInvalidConfig, maxAccessJWTLeeway)
	}
	if cfg.CacheTTL < 0 || cfg.CacheTTL > maxAccessJWTCacheTTL {
		return 0, 0, 0, fmt.Errorf("%w: cache TTL must be in [0, %s]", ErrInvalidConfig, maxAccessJWTCacheTTL)
	}
	cacheTTL = cfg.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = defaultAccessJWTCacheTTL
	}
	maxJWT = cfg.MaxJWTBytes
	if maxJWT == 0 {
		maxJWT = defaultMaxAccessJWTBytes
	}
	if maxJWT < minAccessJWTBytes || maxJWT > maxAccessJWTBytesLimit {
		return 0, 0, 0, fmt.Errorf("%w: MaxJWTBytes must be in [%d, %d]", ErrInvalidConfig, minAccessJWTBytes, maxAccessJWTBytesLimit)
	}
	maxJWKS = cfg.MaxJWKSBytes
	if maxJWKS == 0 {
		maxJWKS = defaultMaxAccessJWKSBytes
	}
	if maxJWKS < minAccessJWKSBytes || maxJWKS > maxAccessJWKSBytesLimit {
		return 0, 0, 0, fmt.Errorf("%w: MaxJWKSBytes must be in [%d, %d]", ErrInvalidConfig, minAccessJWKSBytes, maxAccessJWKSBytesLimit)
	}
	return maxJWT, maxJWKS, cacheTTL, nil
}

// decodeStrictJSONObject parses one JSON object, rejecting duplicate member
// names at any depth, excessive nesting, non-object top levels and trailing
// data. It is the single JSON gate for JWT headers, JWT claims and JWKS
// documents.
func decodeStrictJSONObject(data []byte, maxMembers int) (map[string]json.RawMessage, error) {
	if len(data) == 0 {
		return nil, errors.New("empty JSON")
	}
	if err := validateStrictJSON(data); err != nil {
		return nil, err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, fmt.Errorf("not a JSON object: %w", err)
	}
	if object == nil {
		return nil, errors.New("top-level JSON value is not an object")
	}
	if len(object) > maxMembers {
		return nil, fmt.Errorf("JSON object has more than %d members", maxMembers)
	}
	return object, nil
}

// validateStrictJSON walks data with json.Decoder tokens and fails on
// duplicate object member names, non-object top levels, nesting above
// maxAccessJWTJSONDepth and trailing data.
func validateStrictJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return errors.New("top-level JSON value is not an object")
	}
	if err := scanJSONObject(decoder, 1); err != nil {
		return err
	}
	token, err = decoder.Token()
	if !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return errors.New("trailing data after JSON object")
	}
	return nil
}

func scanJSONObject(decoder *json.Decoder, depth int) error {
	if depth > maxAccessJWTJSONDepth {
		return errors.New("JSON nesting is too deep")
	}
	seen := make(map[string]struct{})
	for {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		if delimiter, ok := token.(json.Delim); ok {
			if delimiter == '}' {
				return nil
			}
			return errors.New("unexpected JSON delimiter in object")
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("invalid JSON object member name")
		}
		if _, duplicate := seen[key]; duplicate {
			return errors.New("duplicate JSON object member name")
		}
		seen[key] = struct{}{}
		if err := scanJSONValue(decoder, depth); err != nil {
			return err
		}
	}
}

func scanJSONValue(decoder *json.Decoder, containingDepth int) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil // scalar
	}
	switch delimiter {
	case '{':
		return scanJSONObject(decoder, containingDepth+1)
	case '[':
		return scanJSONArray(decoder, containingDepth+1)
	default:
		return errors.New("unexpected JSON delimiter in value")
	}
}

func scanJSONArray(decoder *json.Decoder, depth int) error {
	if depth > maxAccessJWTJSONDepth {
		return errors.New("JSON nesting is too deep")
	}
	for {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			continue // scalar element
		}
		switch delimiter {
		case ']':
			return nil
		case '{':
			if err := scanJSONObject(decoder, depth+1); err != nil {
				return err
			}
		case '[':
			if err := scanJSONArray(decoder, depth+1); err != nil {
				return err
			}
		default:
			return errors.New("unexpected JSON delimiter in array")
		}
	}
}

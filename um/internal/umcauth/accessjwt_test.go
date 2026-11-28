package umcauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	accessTestIssuer   = "https://team.cloudflareaccess.com"
	accessTestAudience = "access-audience-tag"
)

func newAccessTestClock() *fakeClock {
	return &fakeClock{current: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
}

type fakeClock struct {
	mu      sync.Mutex
	current time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.current
}

func (c *fakeClock) Advance(delta time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.current = c.current.Add(delta)
}

// Shared test keys: RSA key generation is expensive, so reuse it across tests.
var (
	sharedRSATestKeyOnce sync.Once
	sharedRSATestKey     *rsa.PrivateKey
	sharedRSATestKeyErr  error

	sharedRSAOtherKeyOnce sync.Once
	sharedRSAOtherKey     *rsa.PrivateKey
	sharedRSAOtherKeyErr  error

	sharedECTestKeyOnce sync.Once
	sharedECTestKey     *ecdsa.PrivateKey
	sharedECTestKeyErr  error
)

func sharedRSATestSigningKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	sharedRSATestKeyOnce.Do(func() {
		sharedRSATestKey, sharedRSATestKeyErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	if sharedRSATestKeyErr != nil {
		t.Fatalf("generate RSA test key: %v", sharedRSATestKeyErr)
	}
	return sharedRSATestKey
}

func sharedRSAOtherSigningKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	sharedRSAOtherKeyOnce.Do(func() {
		sharedRSAOtherKey, sharedRSAOtherKeyErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	if sharedRSAOtherKeyErr != nil {
		t.Fatalf("generate second RSA test key: %v", sharedRSAOtherKeyErr)
	}
	return sharedRSAOtherKey
}

func sharedECTestSigningKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	sharedECTestKeyOnce.Do(func() {
		sharedECTestKey, sharedECTestKeyErr = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	})
	if sharedECTestKeyErr != nil {
		t.Fatalf("generate EC test key: %v", sharedECTestKeyErr)
	}
	return sharedECTestKey
}

type testSigner struct {
	algorithm string
	keyID     string
	rsaKey    *rsa.PrivateKey
	ecKey     *ecdsa.PrivateKey
}

func rsaTestSigner(t *testing.T, keyID string) *testSigner {
	t.Helper()
	return &testSigner{algorithm: "RS256", keyID: keyID, rsaKey: sharedRSATestSigningKey(t)}
}

func ecTestSigner(t *testing.T, keyID string) *testSigner {
	t.Helper()
	return &testSigner{algorithm: "ES256", keyID: keyID, ecKey: sharedECTestSigningKey(t)}
}

func (s *testSigner) jwk(t *testing.T) map[string]any {
	t.Helper()
	if s.algorithm == "RS256" {
		return rsaPublicJWK(t, s.keyID, &s.rsaKey.PublicKey, nil)
	}
	return ecPublicJWK(t, s.keyID, &s.ecKey.PublicKey, nil)
}

func rsaPublicJWK(t *testing.T, keyID string, publicKey *rsa.PublicKey, overrides map[string]any) map[string]any {
	t.Helper()
	jwk := map[string]any{
		"kty": "RSA",
		"kid": keyID,
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
	}
	applyJWKOverrides(jwk, overrides)
	return jwk
}

func ecPublicJWK(t *testing.T, keyID string, publicKey *ecdsa.PublicKey, overrides map[string]any) map[string]any {
	t.Helper()
	byteLen := (publicKey.Curve.Params().BitSize + 7) / 8
	jwk := map[string]any{
		"kty": "EC",
		"kid": keyID,
		"use": "sig",
		"alg": "ES256",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(padBigInt(publicKey.X, byteLen)),
		"y":   base64.RawURLEncoding.EncodeToString(padBigInt(publicKey.Y, byteLen)),
	}
	applyJWKOverrides(jwk, overrides)
	return jwk
}

func applyJWKOverrides(jwk map[string]any, overrides map[string]any) {
	for key, value := range overrides {
		if value == nil {
			delete(jwk, key)
			continue
		}
		jwk[key] = value
	}
}

func padBigInt(value *big.Int, length int) []byte {
	raw := value.Bytes()
	if len(raw) >= length {
		return raw
	}
	padded := make([]byte, length)
	copy(padded[length-len(raw):], raw)
	return padded
}

func marshalTestJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return data
}

func testJWKSBody(t *testing.T, keys ...map[string]any) []byte {
	t.Helper()
	documents := make([]any, 0, len(keys))
	for _, key := range keys {
		documents = append(documents, key)
	}
	return marshalTestJSON(t, map[string]any{"keys": documents})
}

func testJWTHeader(t *testing.T, algorithm, keyID string) []byte {
	t.Helper()
	return marshalTestJSON(t, map[string]any{"alg": algorithm, "kid": keyID, "typ": "JWT"})
}

func testJWTHeaderWith(t *testing.T, overrides map[string]any) []byte {
	t.Helper()
	header := map[string]any{"alg": "RS256", "kid": "test-key", "typ": "JWT"}
	for key, value := range overrides {
		if value == nil {
			delete(header, key)
			continue
		}
		header[key] = value
	}
	return marshalTestJSON(t, header)
}

// testJSONNull marks an explicit JSON null value in test claim overrides; a
// nil override deletes the claim instead.
type testJSONNull struct{}

// testJWTClaims builds a claims object with sensible defaults. A nil override
// value deletes the claim; a testJSONNull value emits an explicit null.
func testJWTClaims(t *testing.T, clock *fakeClock, overrides map[string]any) []byte {
	t.Helper()
	now := clock.Now().Unix()
	claims := map[string]any{
		"iss": accessTestIssuer,
		"aud": []string{accessTestAudience},
		"sub": "user-123",
		"exp": now + 300,
		"iat": now,
		"nbf": now - 30,
	}
	for key, value := range overrides {
		if value == nil {
			delete(claims, key)
			continue
		}
		if _, isNull := value.(testJSONNull); isNull {
			claims[key] = nil
			continue
		}
		claims[key] = value
	}
	return marshalTestJSON(t, claims)
}

func signTestJWT(t *testing.T, signer *testSigner, headerJSON, payloadJSON []byte) string {
	t.Helper()
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payloadJSON)
	digest := sha256.Sum256([]byte(signingInput))
	var signature []byte
	switch signer.algorithm {
	case "RS256":
		signed, err := rsa.SignPKCS1v15(rand.Reader, signer.rsaKey, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatalf("rsa.SignPKCS1v15: %v", err)
		}
		signature = signed
	case "ES256":
		r, s, err := ecdsa.Sign(rand.Reader, signer.ecKey, digest[:])
		if err != nil {
			t.Fatalf("ecdsa.Sign: %v", err)
		}
		signature = make([]byte, 64)
		r.FillBytes(signature[:32])
		s.FillBytes(signature[32:])
	default:
		t.Fatalf("unsupported test signer algorithm %q", signer.algorithm)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func signedTestJWT(t *testing.T, signer *testSigner, clock *fakeClock, claimOverrides map[string]any) string {
	t.Helper()
	return signTestJWT(t, signer,
		testJWTHeader(t, signer.algorithm, signer.keyID),
		testJWTClaims(t, clock, claimOverrides))
}

// jwksTestServer is a controllable JWKS endpoint: it can change bodies, status
// codes, delays and counts requests.
type jwksTestServer struct {
	server *httptest.Server

	mu     sync.Mutex
	body   []byte
	status int
	delay  time.Duration
	hits   int
}

func newJWKSTestServer(t *testing.T) *jwksTestServer {
	t.Helper()
	server := &jwksTestServer{status: http.StatusOK}
	server.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		server.mu.Lock()
		server.hits++
		body := append([]byte(nil), server.body...)
		status := server.status
		delay := server.delay
		server.mu.Unlock()
		if delay > 0 {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-request.Context().Done():
				return
			}
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(status)
		_, _ = writer.Write(body)
	}))
	t.Cleanup(server.server.Close)
	return server
}

func (s *jwksTestServer) URL() string { return s.server.URL }

func (s *jwksTestServer) SetBody(body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body = body
}

func (s *jwksTestServer) SetStatus(status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = status
}

func (s *jwksTestServer) SetDelay(delay time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.delay = delay
}

func (s *jwksTestServer) Hits() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits
}

func newTestAccessVerifier(t *testing.T, jwksURL string, clock *fakeClock, mutate func(*Config)) *Verifier {
	t.Helper()
	cfg := Config{
		Issuer:                    accessTestIssuer,
		Audience:                  accessTestAudience,
		JWKSURL:                   jwksURL,
		AllowInsecureHTTPForTests: true,
		Now:                       clock.Now,
		CacheTTL:                  time.Minute,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	verifier, err := NewVerifier(cfg)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return verifier
}

func requireAccessJWTError(t *testing.T, verifier *Verifier, token string, target error) {
	t.Helper()
	verified, err := verifier.Verify(context.Background(), token)
	if err == nil {
		t.Fatalf("Verify returned token %+v, want error %v", verified, target)
	}
	if !errors.Is(err, target) {
		t.Fatalf("Verify error = %v, want %v", err, target)
	}
}

func requireAccessJWTOK(t *testing.T, verifier *Verifier, token string) *VerifiedToken {
	t.Helper()
	verified, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return verified
}

func TestAccessJWTValidRS256(t *testing.T) {
	clock := newAccessTestClock()
	signer := rsaTestSigner(t, "rsa-key-1")
	server := newJWKSTestServer(t)
	server.SetBody(testJWKSBody(t, signer.jwk(t)))
	verifier := newTestAccessVerifier(t, server.URL(), clock, nil)

	token := signedTestJWT(t, signer, clock, nil)
	verified := requireAccessJWTOK(t, verifier, token)
	if verified.Header.Algorithm != "RS256" || verified.Header.KeyID != "rsa-key-1" || verified.Header.Type != "JWT" {
		t.Fatalf("header = %+v", verified.Header)
	}
	if verified.Claims.Subject != "user-123" {
		t.Fatalf("subject = %q, want user-123", verified.Claims.Subject)
	}
	if verified.Claims.Issuer != accessTestIssuer {
		t.Fatalf("issuer = %q, want %q", verified.Claims.Issuer, accessTestIssuer)
	}
	if len(verified.Claims.Audience) != 1 || verified.Claims.Audience[0] != accessTestAudience {
		t.Fatalf("audience = %v, want [%q]", verified.Claims.Audience, accessTestAudience)
	}
	now := clock.Now()
	if want := time.Unix(now.Unix()+300, 0).UTC(); !verified.Claims.ExpiresAt.Equal(want) {
		t.Fatalf("exp = %v, want %v", verified.Claims.ExpiresAt, want)
	}
	if !verified.Claims.HasIssuedAt || !verified.Claims.HasNotBefore {
		t.Fatalf("optional claim presence not reported: %+v", verified.Claims)
	}
	if got, hits := server.Hits(), 1; got != hits {
		t.Fatalf("first verify hits = %d, want %d", got, hits)
	}

	// A warm cache must not refetch.
	requireAccessJWTOK(t, verifier, token)
	if hits := server.Hits(); hits != 1 {
		t.Fatalf("second verify hits = %d, want 1 (cached)", hits)
	}

	// Audience as a bare string is also accepted.
	stringAudienceToken := signTestJWT(t, signer,
		testJWTHeader(t, "RS256", signer.keyID),
		testJWTClaims(t, clock, map[string]any{"aud": accessTestAudience}))
	requireAccessJWTOK(t, verifier, stringAudienceToken)

	// Audience array with the expected value among others is accepted.
	multiAudienceToken := signTestJWT(t, signer,
		testJWTHeader(t, "RS256", signer.keyID),
		testJWTClaims(t, clock, map[string]any{"aud": []string{"other", accessTestAudience}}))
	requireAccessJWTOK(t, verifier, multiAudienceToken)
	if hits := server.Hits(); hits != 1 {
		t.Fatalf("extra verifies hits = %d, want 1", hits)
	}
}

func TestAccessJWTValidES256(t *testing.T) {
	clock := newAccessTestClock()
	rsaSigner := rsaTestSigner(t, "rsa-key-1")
	ecSigner := ecTestSigner(t, "ec-key-1")
	server := newJWKSTestServer(t)
	server.SetBody(testJWKSBody(t, rsaSigner.jwk(t), ecSigner.jwk(t)))
	verifier := newTestAccessVerifier(t, server.URL(), clock, nil)

	token := signedTestJWT(t, ecSigner, clock, nil)
	verified := requireAccessJWTOK(t, verifier, token)
	if verified.Header.Algorithm != "ES256" || verified.Header.KeyID != "ec-key-1" {
		t.Fatalf("header = %+v", verified.Header)
	}
	if verified.Claims.Subject != "user-123" {
		t.Fatalf("subject = %q", verified.Claims.Subject)
	}
}

func TestAccessJWTClaimsValidation(t *testing.T) {
	clock := newAccessTestClock()
	signer := rsaTestSigner(t, "rsa-key-1")
	server := newJWKSTestServer(t)
	server.SetBody(testJWKSBody(t, signer.jwk(t)))
	verifier := newTestAccessVerifier(t, server.URL(), clock, nil)
	now := clock.Now().Unix()

	cases := []struct {
		name      string
		overrides map[string]any
		want      error
	}{
		{"wrong issuer", map[string]any{"iss": "https://evil.example.com"}, ErrIssuerMismatch},
		{"missing issuer", map[string]any{"iss": nil}, ErrMalformedClaims},
		{"null issuer", map[string]any{"iss": testJSONNull{}}, ErrMalformedClaims},
		{"non-string issuer", map[string]any{"iss": 42}, ErrMalformedClaims},
		{"missing audience", map[string]any{"aud": nil}, ErrMalformedClaims},
		{"null audience", map[string]any{"aud": testJSONNull{}}, ErrMalformedClaims},
		{"wrong audience", map[string]any{"aud": "other-audience"}, ErrAudienceMismatch},
		{"audience array without expected", map[string]any{"aud": []string{"a", "b"}}, ErrAudienceMismatch},
		{"empty audience array", map[string]any{"aud": []string{}}, ErrMalformedClaims},
		{"numeric audience", map[string]any{"aud": 1234}, ErrMalformedClaims},
		{"mixed audience array", map[string]any{"aud": []any{accessTestAudience, 42}}, ErrMalformedClaims},
		{"empty subject", map[string]any{"sub": ""}, ErrInvalidSubject},
		{"blank subject", map[string]any{"sub": "   "}, ErrInvalidSubject},
		{"missing subject", map[string]any{"sub": nil}, ErrMalformedClaims},
		{"non-string subject", map[string]any{"sub": true}, ErrMalformedClaims},
		{"oversized subject", map[string]any{"sub": strings.Repeat("s", maxAccessJWTSubjectBytes+1)}, ErrInvalidSubject},
		{"subject control chars", map[string]any{"sub": "user\x00id"}, ErrInvalidSubject},
		{"missing exp", map[string]any{"exp": nil}, ErrMalformedClaims},
		{"null exp", map[string]any{"exp": testJSONNull{}}, ErrMalformedClaims},
		{"string exp", map[string]any{"exp": "9999999999"}, ErrMalformedClaims},
		{"fractional exp", map[string]any{"exp": float64(now) + 1.5}, ErrMalformedClaims},
		{"negative exp", map[string]any{"exp": int64(-1)}, ErrMalformedClaims},
		{"huge exp", map[string]any{"exp": int64(1) << 62}, ErrMalformedClaims},
		{"expired", map[string]any{"exp": now - 1}, ErrTokenExpired},
		{"expired at now", map[string]any{"exp": now}, ErrTokenExpired},
		{"nbf in future", map[string]any{"nbf": now + 120}, ErrTokenNotYetValid},
		{"nbf after exp", map[string]any{"nbf": now + 600, "exp": now + 300}, ErrMalformedClaims},
		{"string nbf", map[string]any{"nbf": "now"}, ErrMalformedClaims},
		{"null nbf", map[string]any{"nbf": testJSONNull{}}, ErrMalformedClaims},
		{"iat in future", map[string]any{"iat": now + 120}, ErrIssuedInFuture},
		{"iat after exp", map[string]any{"iat": now + 600, "exp": now + 300}, ErrMalformedClaims},
		{"string iat", map[string]any{"iat": "now"}, ErrMalformedClaims},
		{"null iat", map[string]any{"iat": testJSONNull{}}, ErrMalformedClaims},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			token := signTestJWT(t, signer,
				testJWTHeader(t, "RS256", signer.keyID),
				testJWTClaims(t, clock, testCase.overrides))
			requireAccessJWTError(t, verifier, token, testCase.want)
		})
	}
	if hits := server.Hits(); hits != 0 {
		t.Fatalf("malformed-claims verification hit the network %d times, want 0", hits)
	}
}

func TestAccessJWTClaimsStructure(t *testing.T) {
	clock := newAccessTestClock()
	signer := rsaTestSigner(t, "rsa-key-1")
	server := newJWKSTestServer(t)
	server.SetBody(testJWKSBody(t, signer.jwk(t)))
	verifier := newTestAccessVerifier(t, server.URL(), clock, nil)
	now := clock.Now().Unix()
	validClaims := testJWTClaims(t, clock, nil)

	payloadCases := []struct {
		name    string
		payload []byte
	}{
		{"array payload", []byte(`[1,2,3]`)},
		{"string payload", []byte(`"claims"`)},
		{"null payload", []byte(`null`)},
		{"duplicate claim", []byte(`{"iss":"` + accessTestIssuer + `","aud":"` + accessTestAudience + `","sub":"a","sub":"b","exp":` + jsonInt(now+300) + `}`)},
		{"trailing data", append(append([]byte{}, validClaims...), []byte(`{}`)...)},
		{"truncated JSON", append([]byte{}, validClaims[:len(validClaims)-1]...)},
	}
	for _, testCase := range payloadCases {
		t.Run(testCase.name, func(t *testing.T) {
			token := signTestJWT(t, signer, testJWTHeader(t, "RS256", signer.keyID), testCase.payload)
			requireAccessJWTError(t, verifier, token, ErrMalformedClaims)
		})
	}
	if hits := server.Hits(); hits != 0 {
		t.Fatalf("malformed payload verification hit the network %d times, want 0", hits)
	}
}

func TestAccessJWTLeeway(t *testing.T) {
	now := newAccessTestClock().Now().Unix()
	cases := []struct {
		name      string
		leeway    time.Duration
		overrides map[string]any
		want      error // nil means success
	}{
		{"expired within leeway", 60 * time.Second, map[string]any{"exp": now - 30, "iat": nil}, nil},
		{"expired beyond leeway", 60 * time.Second, map[string]any{"exp": now - 90, "iat": nil}, ErrTokenExpired},
		{"nbf within leeway", 60 * time.Second, map[string]any{"nbf": now + 30}, nil},
		{"nbf beyond leeway", 60 * time.Second, map[string]any{"nbf": now + 90}, ErrTokenNotYetValid},
		{"iat within leeway", 60 * time.Second, map[string]any{"iat": now + 30}, nil},
		{"iat beyond leeway", 60 * time.Second, map[string]any{"iat": now + 90}, ErrIssuedInFuture},
		{"exp equal now with zero leeway", 0, map[string]any{"exp": now, "iat": nil}, ErrTokenExpired},
		{"nbf equals now plus leeway", time.Second, map[string]any{"nbf": now + 1}, nil},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			clock := newAccessTestClock()
			signer := rsaTestSigner(t, "rsa-key-1")
			server := newJWKSTestServer(t)
			server.SetBody(testJWKSBody(t, signer.jwk(t)))
			verifier := newTestAccessVerifier(t, server.URL(), clock, func(cfg *Config) {
				cfg.Leeway = testCase.leeway
			})
			token := signTestJWT(t, signer,
				testJWTHeader(t, "RS256", signer.keyID),
				testJWTClaims(t, clock, testCase.overrides))
			if testCase.want == nil {
				requireAccessJWTOK(t, verifier, token)
			} else {
				requireAccessJWTError(t, verifier, token, testCase.want)
			}
		})
	}
}

func TestAccessJWTHeaderValidation(t *testing.T) {
	clock := newAccessTestClock()
	signer := rsaTestSigner(t, "rsa-key-1")
	server := newJWKSTestServer(t)
	server.SetBody(testJWKSBody(t, signer.jwk(t)))
	verifier := newTestAccessVerifier(t, server.URL(), clock, nil)
	payload := testJWTClaims(t, clock, nil)

	cases := []struct {
		name   string
		header []byte
		want   error
	}{
		{"alg none", testJWTHeader(t, "none", signer.keyID), ErrUnsupportedAlgorithm},
		{"alg HS256", testJWTHeader(t, "HS256", signer.keyID), ErrUnsupportedAlgorithm},
		{"alg RS384", testJWTHeader(t, "RS384", signer.keyID), ErrUnsupportedAlgorithm},
		{"alg ES384", testJWTHeader(t, "ES384", signer.keyID), ErrUnsupportedAlgorithm},
		{"alg lowercase", testJWTHeader(t, "rs256", signer.keyID), ErrUnsupportedAlgorithm},
		{"missing alg", testJWTHeaderWith(t, map[string]any{"alg": nil}), ErrMalformedToken},
		{"null alg", testJWTHeaderWith(t, map[string]any{"alg": nil}), ErrMalformedToken},
		{"numeric alg", testJWTHeaderWith(t, map[string]any{"alg": 256}), ErrMalformedToken},
		{"missing kid", testJWTHeaderWith(t, map[string]any{"kid": nil}), ErrMalformedToken},
		{"empty kid", testJWTHeaderWith(t, map[string]any{"kid": ""}), ErrMalformedToken},
		{"numeric kid", testJWTHeaderWith(t, map[string]any{"kid": 7}), ErrMalformedToken},
		{"oversized kid", testJWTHeaderWith(t, map[string]any{"kid": strings.Repeat("k", maxAccessJWTKeyIDBytes+1)}), ErrMalformedToken},
		{"kid control chars", testJWTHeaderWith(t, map[string]any{"kid": "key\x01id"}), ErrMalformedToken},
		{"unexpected typ", testJWTHeaderWith(t, map[string]any{"typ": "token"}), ErrUnsupportedHeader},
		{"jku header", testJWTHeaderWith(t, map[string]any{"jku": "https://evil.example/jwks"}), ErrUnsupportedHeader},
		{"x5u header", testJWTHeaderWith(t, map[string]any{"x5u": "https://evil.example/cert"}), ErrUnsupportedHeader},
		{"jwk header", testJWTHeaderWith(t, map[string]any{"jwk": signer.jwk(t)}), ErrUnsupportedHeader},
		{"x5c header", testJWTHeaderWith(t, map[string]any{"x5c": []string{"AAAA"}}), ErrUnsupportedHeader},
		{"crit header", testJWTHeaderWith(t, map[string]any{"crit": []string{"exp"}}), ErrUnsupportedHeader},
		{"array header", []byte(`[1,2,3]`), ErrMalformedToken},
		{"duplicate header member", []byte(`{"alg":"RS256","alg":"RS256","kid":"` + signer.keyID + `"}`), ErrMalformedToken},
		{"missing kid and forbidden jku", testJWTHeaderWith(t, map[string]any{"kid": nil, "jku": "https://evil.example"}), ErrUnsupportedHeader},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			token := signTestJWT(t, signer, testCase.header, payload)
			requireAccessJWTError(t, verifier, token, testCase.want)
		})
	}

	// A header larger than the decoded-size bound is rejected.
	bigHeader := testJWTHeaderWith(t, map[string]any{"pad": strings.Repeat("a", maxAccessJWTHeaderBytes+100)})
	requireAccessJWTError(t, verifier, signTestJWT(t, signer, bigHeader, payload), ErrMalformedToken)

	if hits := server.Hits(); hits != 0 {
		t.Fatalf("header validation hit the network %d times, want 0", hits)
	}
}

func TestAccessJWTStructureAndSize(t *testing.T) {
	clock := newAccessTestClock()
	signer := rsaTestSigner(t, "rsa-key-1")
	server := newJWKSTestServer(t)
	server.SetBody(testJWKSBody(t, signer.jwk(t)))
	verifier := newTestAccessVerifier(t, server.URL(), clock, nil)
	header := testJWTHeader(t, "RS256", signer.keyID)
	payload := testJWTClaims(t, clock, nil)
	headerSegment := base64.RawURLEncoding.EncodeToString(header)
	payloadSegment := base64.RawURLEncoding.EncodeToString(payload)
	validSignature := "AAAA"

	malformed := []string{
		"",
		"abc",
		"a.b",
		"a.b.c.d",
		".a.b",
		"a..b",
		"a.b.",
		headerSegment + "." + payloadSegment + ".",
		"!!!." + payloadSegment + "." + validSignature,
		headerSegment + "!!!." + validSignature,
		headerSegment + "." + payloadSegment + "." + validSignature + "=",
		headerSegment + "=." + payloadSegment + "." + validSignature,
	}
	for _, token := range malformed {
		if _, err := verifier.Verify(context.Background(), token); !errors.Is(err, ErrMalformedToken) {
			t.Fatalf("Verify(%q) error = %v, want ErrMalformedToken", token, err)
		}
	}

	// Oversized raw JWT.
	smallLimitVerifier := newTestAccessVerifier(t, server.URL(), clock, func(cfg *Config) {
		cfg.MaxJWTBytes = minAccessJWTBytes
	})
	validToken := signedTestJWT(t, signer, clock, nil)
	if len(validToken) <= minAccessJWTBytes {
		t.Fatalf("test token is unexpectedly small (%d bytes)", len(validToken))
	}
	if _, err := smallLimitVerifier.Verify(context.Background(), validToken); !errors.Is(err, ErrTokenTooLarge) {
		t.Fatalf("Verify(oversized) error = %v, want ErrTokenTooLarge", err)
	}

	// Oversized signature segment.
	oversizedSignature := base64.RawURLEncoding.EncodeToString(make([]byte, maxAccessJWTSignatureBytes+1))
	token := headerSegment + "." + payloadSegment + "." + oversizedSignature
	if _, err := verifier.Verify(context.Background(), token); !errors.Is(err, ErrMalformedToken) {
		t.Fatalf("Verify(oversized signature) error = %v, want ErrMalformedToken", err)
	}

	if hits := server.Hits(); hits != 0 {
		t.Fatalf("structure validation hit the network %d times, want 0", hits)
	}
}

func TestAccessJWTInvalidSignature(t *testing.T) {
	clock := newAccessTestClock()
	signer := rsaTestSigner(t, "rsa-key-1")
	server := newJWKSTestServer(t)
	server.SetBody(testJWKSBody(t, signer.jwk(t)))
	verifier := newTestAccessVerifier(t, server.URL(), clock, nil)

	token := signedTestJWT(t, signer, clock, nil)
	requireAccessJWTOK(t, verifier, token)
	hitsAfterWarm := server.Hits()

	segments := strings.Split(token, ".")
	signature, err := base64.RawURLEncoding.DecodeString(segments[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	tamperedSignature := append([]byte{}, signature...)
	tamperedSignature[len(tamperedSignature)-1] ^= 0x01
	tamperedToken := segments[0] + "." + segments[1] + "." + base64.RawURLEncoding.EncodeToString(tamperedSignature)
	requireAccessJWTError(t, verifier, tamperedToken, ErrInvalidSignature)
	if hits := server.Hits(); hits != hitsAfterWarm {
		t.Fatalf("invalid signature triggered a JWKS refetch: %d -> %d", hitsAfterWarm, hits)
	}

	// A token signed by another key but claiming the trusted kid is rejected.
	otherSigner := &testSigner{algorithm: "RS256", keyID: signer.keyID, rsaKey: sharedRSAOtherSigningKey(t)}
	requireAccessJWTError(t, verifier, signedTestJWT(t, otherSigner, clock, nil), ErrInvalidSignature)

	// ES256 signature tampering.
	ecSigner := ecTestSigner(t, "ec-key-1")
	ecServer := newJWKSTestServer(t)
	ecServer.SetBody(testJWKSBody(t, ecSigner.jwk(t)))
	ecVerifier := newTestAccessVerifier(t, ecServer.URL(), clock, nil)
	ecToken := signedTestJWT(t, ecSigner, clock, nil)
	requireAccessJWTOK(t, ecVerifier, ecToken)
	ecSegments := strings.Split(ecToken, ".")
	ecSignature, err := base64.RawURLEncoding.DecodeString(ecSegments[2])
	if err != nil {
		t.Fatalf("decode ES256 signature: %v", err)
	}
	ecSignature[len(ecSignature)-1] ^= 0x80
	tamperedEC := ecSegments[0] + "." + ecSegments[1] + "." + base64.RawURLEncoding.EncodeToString(ecSignature)
	requireAccessJWTError(t, ecVerifier, tamperedEC, ErrInvalidSignature)

	// A short/invalid-length ES256 signature is rejected before using the key.
	shortEC := ecSegments[0] + "." + ecSegments[1] + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 63))
	requireAccessJWTError(t, ecVerifier, shortEC, ErrInvalidSignature)
}

func TestAccessJWTAlgorithmKeyMismatch(t *testing.T) {
	clock := newAccessTestClock()
	rsaSigner := rsaTestSigner(t, "rsa-key-1")
	server := newJWKSTestServer(t)
	server.SetBody(testJWKSBody(t, rsaSigner.jwk(t)))
	verifier := newTestAccessVerifier(t, server.URL(), clock, nil)

	// ES256 token with an RSA kid: key resolution succeeds but the key type is
	// wrong, and no signature check may be attempted.
	token := signTestJWT(t, ecTestSigner(t, rsaSigner.keyID),
		testJWTHeader(t, "ES256", rsaSigner.keyID),
		testJWTClaims(t, clock, nil))
	requireAccessJWTError(t, verifier, token, ErrKeyAlgorithmMismatch)

	ecSigner := ecTestSigner(t, "ec-key-1")
	ecServer := newJWKSTestServer(t)
	ecServer.SetBody(testJWKSBody(t, ecSigner.jwk(t)))
	ecVerifier := newTestAccessVerifier(t, ecServer.URL(), clock, nil)
	rsaTokenWithECKid := signTestJWT(t, rsaTestSigner(t, ecSigner.keyID),
		testJWTHeader(t, "RS256", ecSigner.keyID),
		testJWTClaims(t, clock, nil))
	requireAccessJWTError(t, ecVerifier, rsaTokenWithECKid, ErrKeyAlgorithmMismatch)
}

func TestAccessJWTUnknownKidRotation(t *testing.T) {
	clock := newAccessTestClock()
	firstSigner := rsaTestSigner(t, "rotation-key-1")
	secondSigner := rsaTestSigner(t, "rotation-key-2")
	server := newJWKSTestServer(t)
	server.SetBody(testJWKSBody(t, firstSigner.jwk(t)))
	verifier := newTestAccessVerifier(t, server.URL(), clock, nil)

	firstToken := signedTestJWT(t, firstSigner, clock, nil)
	requireAccessJWTOK(t, verifier, firstToken)
	if hits := server.Hits(); hits != 1 {
		t.Fatalf("initial load hits = %d, want 1", hits)
	}

	// Access rotates the signing key. A token with the new kid forces exactly
	// one refresh and then verifies.
	server.SetBody(testJWKSBody(t, secondSigner.jwk(t)))
	secondToken := signedTestJWT(t, secondSigner, clock, nil)
	requireAccessJWTOK(t, verifier, secondToken)
	if hits := server.Hits(); hits != 2 {
		t.Fatalf("rotation refresh hits = %d, want 2", hits)
	}

	// The retired kid now fails, and the refresh cooldown prevents a storm.
	requireAccessJWTError(t, verifier, firstToken, ErrUnknownKeyID)
	if hits := server.Hits(); hits != 2 {
		t.Fatalf("cooldown hits = %d, want 2 (no refresh storm)", hits)
	}

	// After the cooldown another attempt is allowed, still fails closed, and
	// exposes the rotated-away key as unknown.
	clock.Advance(unknownKeyIDRefreshCooldown + time.Second)
	requireAccessJWTError(t, verifier, firstToken, ErrUnknownKeyID)
	if hits := server.Hits(); hits != 3 {
		t.Fatalf("post-cooldown refresh hits = %d, want 3", hits)
	}
}

func TestAccessJWTUnknownKidConcurrentNoRefreshStorm(t *testing.T) {
	clock := newAccessTestClock()
	signer := rsaTestSigner(t, "rsa-key-1")
	server := newJWKSTestServer(t)
	server.SetBody(testJWKSBody(t, signer.jwk(t)))
	verifier := newTestAccessVerifier(t, server.URL(), clock, nil)

	requireAccessJWTOK(t, verifier, signedTestJWT(t, signer, clock, nil))
	warmHits := server.Hits()

	unknownSigner := &testSigner{algorithm: "RS256", keyID: "unknown-key", rsaKey: signer.rsaKey}
	unknownToken := signedTestJWT(t, unknownSigner, clock, nil)
	const goroutines = 12
	var waitGroup sync.WaitGroup
	errs := make(chan error, goroutines)
	waitGroup.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer waitGroup.Done()
			_, err := verifier.Verify(context.Background(), unknownToken)
			errs <- err
		}()
	}
	waitGroup.Wait()
	close(errs)
	for err := range errs {
		if !errors.Is(err, ErrUnknownKeyID) {
			t.Fatalf("concurrent unknown kid error = %v, want ErrUnknownKeyID", err)
		}
	}
	if hits := server.Hits(); hits != warmHits+1 {
		t.Fatalf("unknown-kid storm fetched %d times, want exactly one rotation refresh", hits-warmHits)
	}
}

func TestAccessJWTColdCacheConcurrentSingleFetch(t *testing.T) {
	clock := newAccessTestClock()
	signer := rsaTestSigner(t, "rsa-key-1")
	server := newJWKSTestServer(t)
	server.SetBody(testJWKSBody(t, signer.jwk(t)))
	server.SetDelay(20 * time.Millisecond)
	verifier := newTestAccessVerifier(t, server.URL(), clock, nil)
	token := signedTestJWT(t, signer, clock, nil)

	const goroutines = 10
	var waitGroup sync.WaitGroup
	errs := make(chan error, goroutines)
	waitGroup.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer waitGroup.Done()
			_, err := verifier.Verify(context.Background(), token)
			errs <- err
		}()
	}
	waitGroup.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent cold-cache Verify: %v", err)
		}
	}
	if hits := server.Hits(); hits != 1 {
		t.Fatalf("cold-cache concurrency fetched %d times, want 1", hits)
	}
}

func TestAccessJWKSCacheExpiry(t *testing.T) {
	clock := newAccessTestClock()
	signer := rsaTestSigner(t, "rsa-key-1")
	server := newJWKSTestServer(t)
	server.SetBody(testJWKSBody(t, signer.jwk(t)))
	verifier := newTestAccessVerifier(t, server.URL(), clock, func(cfg *Config) {
		cfg.CacheTTL = time.Minute
	})

	token := signTestJWT(t, signer,
		testJWTHeader(t, "RS256", signer.keyID),
		testJWTClaims(t, clock, map[string]any{"exp": clock.Now().Unix() + 3600}))
	requireAccessJWTOK(t, verifier, token)
	requireAccessJWTOK(t, verifier, token)
	if hits := server.Hits(); hits != 1 {
		t.Fatalf("cache hits = %d, want 1", hits)
	}

	clock.Advance(30 * time.Second)
	requireAccessJWTOK(t, verifier, token)
	if hits := server.Hits(); hits != 1 {
		t.Fatalf("within-TTL hits = %d, want 1", hits)
	}

	clock.Advance(31 * time.Second) // total 61s > 1m TTL
	requireAccessJWTOK(t, verifier, token)
	if hits := server.Hits(); hits != 2 {
		t.Fatalf("expired-cache hits = %d, want 2", hits)
	}
}

func TestAccessJWKSUnavailableFailsClosed(t *testing.T) {
	clock := newAccessTestClock()
	signer := rsaTestSigner(t, "rsa-key-1")
	server := newJWKSTestServer(t)
	server.SetStatus(http.StatusInternalServerError)
	verifier := newTestAccessVerifier(t, server.URL(), clock, nil)
	token := signedTestJWT(t, signer, clock, nil)

	requireAccessJWTError(t, verifier, token, ErrJWKSUnavailable)
	if hits := server.Hits(); hits != 1 {
		t.Fatalf("JWKS outage hits = %d, want 1", hits)
	}

	server.SetStatus(http.StatusOK)
	server.SetBody(testJWKSBody(t, signer.jwk(t)))
	requireAccessJWTOK(t, verifier, token)

	// Expired cache with an unreachable JWKS must fail closed rather than use
	// stale keys.
	server.SetStatus(http.StatusInternalServerError)
	clock.Advance(2 * time.Minute)
	requireAccessJWTError(t, verifier, token, ErrJWKSUnavailable)

	// Unknown kid against an unavailable JWKS fails closed once, then the
	// cooldown prevents a retry storm.
	server.SetStatus(http.StatusOK)
	requireAccessJWTOK(t, verifier, token) // repopulate the cache
	server.SetStatus(http.StatusInternalServerError)
	unknownSigner := &testSigner{algorithm: "RS256", keyID: "unknown-key", rsaKey: signer.rsaKey}
	unknownToken := signedTestJWT(t, unknownSigner, clock, nil)
	hitsBefore := server.Hits()
	requireAccessJWTError(t, verifier, unknownToken, ErrJWKSUnavailable)
	if hits := server.Hits(); hits != hitsBefore+1 {
		t.Fatalf("unknown-kid outage hits = %d, want %d", hits, hitsBefore+1)
	}
	requireAccessJWTError(t, verifier, unknownToken, ErrUnknownKeyID)
	if hits := server.Hits(); hits != hitsBefore+1 {
		t.Fatalf("post-outage cooldown refetched JWKS: %d -> %d", hitsBefore+1, hits)
	}
}

func TestAccessJWKSRedirectsDisabled(t *testing.T) {
	clock := newAccessTestClock()
	signer := rsaTestSigner(t, "rsa-key-1")
	target := newJWKSTestServer(t)
	target.SetBody(testJWKSBody(t, signer.jwk(t)))
	redirector := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL(), http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	verifier := newTestAccessVerifier(t, redirector.URL, clock, nil)
	requireAccessJWTError(t, verifier, signedTestJWT(t, signer, clock, nil), ErrJWKSUnavailable)
	if hits := target.Hits(); hits != 0 {
		t.Fatalf("redirect target was fetched %d times, want 0", hits)
	}
}

func TestAccessJWKSHttpsAndCustomClient(t *testing.T) {
	clock := newAccessTestClock()
	signer := rsaTestSigner(t, "rsa-key-1")
	body := testJWKSBody(t, signer.jwk(t))
	var hits atomic.Int32
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		hits.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(body)
	}))
	t.Cleanup(tlsServer.Close)

	verifier := newTestAccessVerifier(t, tlsServer.URL, clock, func(cfg *Config) {
		cfg.AllowInsecureHTTPForTests = false
		cfg.HTTPClient = tlsServer.Client()
	})
	requireAccessJWTOK(t, verifier, signedTestJWT(t, signer, clock, nil))
	if got := hits.Load(); got != 1 {
		t.Fatalf("HTTPS JWKS fetch count = %d, want 1", got)
	}

	// Plain HTTP is refused unless the test-only flag is set.
	if _, err := NewVerifier(Config{
		Issuer:   accessTestIssuer,
		Audience: accessTestAudience,
		JWKSURL:  strings.Replace(tlsServer.URL, "https://", "http://", 1),
	}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewVerifier(http URL) error = %v, want ErrInvalidConfig", err)
	}
}

func TestAccessJWKSFetchBounded(t *testing.T) {
	clock := newAccessTestClock()
	signer := rsaTestSigner(t, "rsa-key-1")
	token := signedTestJWT(t, signer, clock, nil)

	t.Run("oversized body", func(t *testing.T) {
		server := newJWKSTestServer(t)
		server.SetBody([]byte(strings.Repeat("x", 1024)))
		verifier := newTestAccessVerifier(t, server.URL(), clock, func(cfg *Config) {
			cfg.MaxJWKSBytes = 512
		})
		requireAccessJWTError(t, verifier, token, ErrJWKSUnavailable)
	})

	t.Run("malformed JSON", func(t *testing.T) {
		server := newJWKSTestServer(t)
		server.SetBody([]byte(`{"keys": [`))
		verifier := newTestAccessVerifier(t, server.URL(), clock, nil)
		requireAccessJWTError(t, verifier, token, ErrJWKSUnavailable)
	})

	t.Run("empty keys", func(t *testing.T) {
		server := newJWKSTestServer(t)
		server.SetBody([]byte(`{"keys":[]}`))
		verifier := newTestAccessVerifier(t, server.URL(), clock, nil)
		requireAccessJWTError(t, verifier, token, ErrJWKSUnavailable)
	})

	t.Run("no usable keys", func(t *testing.T) {
		server := newJWKSTestServer(t)
		server.SetBody(marshalTestJSON(t, map[string]any{"keys": []any{
			map[string]any{"kty": "oct", "kid": "symmetric", "k": "AAAA"},
		}}))
		verifier := newTestAccessVerifier(t, server.URL(), clock, nil)
		requireAccessJWTError(t, verifier, token, ErrJWKSUnavailable)
	})

	t.Run("too many keys", func(t *testing.T) {
		keys := make([]map[string]any, 0, maxAccessJWKSKeys+1)
		for i := 0; i < maxAccessJWKSKeys+1; i++ {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("generate EC key: %v", err)
			}
			keys = append(keys, ecPublicJWK(t, "key-"+itoa(i), &key.PublicKey, nil))
		}
		server := newJWKSTestServer(t)
		server.SetBody(testJWKSBody(t, keys...))
		verifier := newTestAccessVerifier(t, server.URL(), clock, nil)
		requireAccessJWTError(t, verifier, token, ErrJWKSUnavailable)
	})

	t.Run("duplicate kid", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate EC key: %v", err)
		}
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate EC key: %v", err)
		}
		server := newJWKSTestServer(t)
		server.SetBody(testJWKSBody(t,
			ecPublicJWK(t, "same-kid", &key.PublicKey, nil),
			ecPublicJWK(t, "same-kid", &other.PublicKey, nil)))
		verifier := newTestAccessVerifier(t, server.URL(), clock, nil)
		requireAccessJWTError(t, verifier, token, ErrJWKSUnavailable)
	})

	t.Run("rsa modulus too small", func(t *testing.T) {
		smallKey, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatalf("generate 1024-bit RSA key: %v", err)
		}
		server := newJWKSTestServer(t)
		server.SetBody(testJWKSBody(t, rsaPublicJWK(t, "small-rsa", &smallKey.PublicKey, nil)))
		verifier := newTestAccessVerifier(t, server.URL(), clock, nil)
		requireAccessJWTError(t, verifier, token, ErrJWKSUnavailable)
	})

	t.Run("timeout", func(t *testing.T) {
		server := newJWKSTestServer(t)
		server.SetBody(testJWKSBody(t, signer.jwk(t)))
		server.SetDelay(250 * time.Millisecond)
		verifier := newTestAccessVerifier(t, server.URL(), clock, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		started := time.Now()
		if _, err := verifier.Verify(ctx, token); !errors.Is(err, ErrJWKSUnavailable) {
			t.Fatalf("Verify(timeout) error = %v, want ErrJWKSUnavailable", err)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("timed-out fetch took %s, want well under the 5s bound", elapsed)
		}
	})
}

func TestAccessJWKSKeyFiltering(t *testing.T) {
	clock := newAccessTestClock()
	signer := rsaTestSigner(t, "rsa-key-1")
	ecSigner := ecTestSigner(t, "ec-key-1")
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}
	server := newJWKSTestServer(t)
	server.SetBody(testJWKSBody(t,
		rsaPublicJWK(t, "rsa-key-1", &signer.rsaKey.PublicKey, nil),
		ecPublicJWK(t, "ec-key-1", &ecSigner.ecKey.PublicKey, nil),
		rsaPublicJWK(t, "enc-key", &signer.rsaKey.PublicKey, map[string]any{"use": "enc"}),
		rsaPublicJWK(t, "sign-only-key", &signer.rsaKey.PublicKey, map[string]any{"key_ops": []string{"sign"}}),
		rsaPublicJWK(t, "rs512-key", &signer.rsaKey.PublicKey, map[string]any{"alg": "RS512"}),
		map[string]any{"kty": "oct", "kid": "oct-key", "k": "AAAA"},
		ecPublicJWK(t, "p384-key", &p384Key.PublicKey, map[string]any{"crv": "P-384", "x": base64.RawURLEncoding.EncodeToString(padBigInt(p384Key.X, 48)), "y": base64.RawURLEncoding.EncodeToString(padBigInt(p384Key.Y, 48))}),
	))
	verifier := newTestAccessVerifier(t, server.URL(), clock, nil)

	// The usable keys work.
	requireAccessJWTOK(t, verifier, signedTestJWT(t, signer, clock, nil))
	requireAccessJWTOK(t, verifier, signedTestJWT(t, ecSigner, clock, nil))
	warmHits := server.Hits()

	for _, keyID := range []string{"enc-key", "sign-only-key", "rs512-key", "oct-key", "p384-key", "not-in-jwks"} {
		unknownSigner := &testSigner{algorithm: "RS256", keyID: keyID, rsaKey: signer.rsaKey}
		requireAccessJWTError(t, verifier, signedTestJWT(t, unknownSigner, clock, nil), ErrUnknownKeyID)
	}
	// At most one rotation refresh is permitted during the cooldown.
	if hits := server.Hits(); hits > warmHits+1 {
		t.Fatalf("filtered-key verification fetched JWKS %d times, want at most one refresh", hits-warmHits)
	}
}

func TestAccessJWKSOptionalMetadataAccepted(t *testing.T) {
	clock := newAccessTestClock()
	rsaSigner := rsaTestSigner(t, "rsa-no-metadata")
	ecSigner := ecTestSigner(t, "ec-no-metadata")
	rsaJWK := rsaPublicJWK(t, rsaSigner.keyID, &rsaSigner.rsaKey.PublicKey,
		map[string]any{"use": nil, "alg": nil})
	rsaJWK["key_ops"] = []string{"verify"}
	ecJWK := ecPublicJWK(t, ecSigner.keyID, &ecSigner.ecKey.PublicKey,
		map[string]any{"use": nil, "alg": nil})
	server := newJWKSTestServer(t)
	server.SetBody(testJWKSBody(t, rsaJWK, ecJWK))
	verifier := newTestAccessVerifier(t, server.URL(), clock, nil)

	requireAccessJWTOK(t, verifier, signedTestJWT(t, rsaSigner, clock, nil))
	requireAccessJWTOK(t, verifier, signedTestJWT(t, ecSigner, clock, nil))
}

func TestAccessJWTConfigValidation(t *testing.T) {
	valid := Config{
		Issuer:   accessTestIssuer,
		Audience: accessTestAudience,
		JWKSURL:  "https://team.cloudflareaccess.com/cdn-cgi/access/certs",
	}
	if _, err := NewVerifier(valid); err != nil {
		t.Fatalf("NewVerifier(valid): %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"empty issuer", func(cfg *Config) { cfg.Issuer = "" }},
		{"issuer whitespace", func(cfg *Config) { cfg.Issuer = " " + accessTestIssuer }},
		{"issuer control", func(cfg *Config) { cfg.Issuer = "https://x\x00" }},
		{"oversized issuer", func(cfg *Config) { cfg.Issuer = strings.Repeat("i", maxAccessJWTIssuerBytes+1) }},
		{"empty audience", func(cfg *Config) { cfg.Audience = "" }},
		{"audience whitespace", func(cfg *Config) { cfg.Audience = accessTestAudience + " " }},
		{"empty JWKS URL", func(cfg *Config) { cfg.JWKSURL = "" }},
		{"relative JWKS URL", func(cfg *Config) { cfg.JWKSURL = "/jwks" }},
		{"no host JWKS URL", func(cfg *Config) { cfg.JWKSURL = "https:///jwks" }},
		{"ftp JWKS URL", func(cfg *Config) { cfg.JWKSURL = "ftp://example.com/jwks" }},
		{"JWKS userinfo", func(cfg *Config) { cfg.JWKSURL = "https://user:pass@example.com/jwks" }},
		{"JWKS fragment", func(cfg *Config) { cfg.JWKSURL = "https://example.com/jwks#fragment" }},
		{"http without test flag", func(cfg *Config) {
			cfg.JWKSURL = "http://example.com/jwks"
			cfg.AllowInsecureHTTPForTests = false
		}},
		{"negative leeway", func(cfg *Config) { cfg.Leeway = -time.Second }},
		{"excessive leeway", func(cfg *Config) { cfg.Leeway = maxAccessJWTLeeway + time.Second }},
		{"negative cache TTL", func(cfg *Config) { cfg.CacheTTL = -time.Second }},
		{"excessive cache TTL", func(cfg *Config) { cfg.CacheTTL = maxAccessJWTCacheTTL + time.Second }},
		{"tiny MaxJWTBytes", func(cfg *Config) { cfg.MaxJWTBytes = 1 }},
		{"huge MaxJWTBytes", func(cfg *Config) { cfg.MaxJWTBytes = maxAccessJWTBytesLimit + 1 }},
		{"tiny MaxJWKSBytes", func(cfg *Config) { cfg.MaxJWKSBytes = 1 }},
		{"huge MaxJWKSBytes", func(cfg *Config) { cfg.MaxJWKSBytes = maxAccessJWKSBytesLimit + 1 }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := valid
			testCase.mutate(&cfg)
			if _, err := NewVerifier(cfg); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("NewVerifier error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

// jsonInt formats an int64 for inclusion in hand-built JSON payloads.
func jsonInt(value int64) string {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func itoa(value int) string {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(data)
}

package umcauth

import (
	"encoding/base32"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

// rfc6238Secret is the RFC 6238 SHA-1 test secret ("12345678901234567890")
// encoded as unpadded base32.
const rfc6238Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestNewTOTPSecret(t *testing.T) {
	seen := make(map[string]struct{})
	for i := 0; i < 20; i++ {
		secret, err := NewTOTPSecret()
		if err != nil {
			t.Fatalf("NewTOTPSecret: %v", err)
		}
		if strings.Contains(secret, "=") {
			t.Fatalf("secret %q contains padding", secret)
		}
		if len(secret) != 32 {
			t.Fatalf("secret %q length = %d, want 32 base32 chars for 20 bytes", secret, len(secret))
		}
		decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
		if err != nil || len(decoded) != TOTPSecretBytes {
			t.Fatalf("secret %q decodes to %d bytes, %v; want %d bytes", secret, len(decoded), err, TOTPSecretBytes)
		}
		if _, duplicate := seen[secret]; duplicate {
			t.Fatalf("NewTOTPSecret returned duplicate secret %q", secret)
		}
		seen[secret] = struct{}{}
	}
}

func TestTOTPRFC6238SHA1Vectors(t *testing.T) {
	// RFC 6238 SHA-1 vectors, reduced to the six-digit codes this package emits.
	vectors := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}
	for _, vector := range vectors {
		code, err := TOTPCode(rfc6238Secret, time.Unix(vector.unix, 0))
		if err != nil {
			t.Fatalf("TOTPCode(%d): %v", vector.unix, err)
		}
		if code != vector.want {
			t.Fatalf("TOTPCode(%d) = %q, want %q", vector.unix, code, vector.want)
		}
	}
}

func TestTOTPTimeStep(t *testing.T) {
	first, err := TOTPCode(rfc6238Secret, time.Unix(0, 0))
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}
	sameStep, err := TOTPCode(rfc6238Secret, time.Unix(29, 0))
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}
	nextStep, err := TOTPCode(rfc6238Secret, time.Unix(30, 0))
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}
	if first != sameStep {
		t.Fatalf("code changed inside a 30s step: %q vs %q", first, sameStep)
	}
	if first == nextStep {
		t.Fatalf("code did not change across a step boundary: %q", first)
	}
}

func TestVerifyTOTPAcceptsCurrentAndSkew(t *testing.T) {
	now := time.Unix(59, 0) // counter 1
	current, err := TOTPCode(rfc6238Secret, now)
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}
	previousCounter, err := TOTPCode(rfc6238Secret, time.Unix(29, 0)) // counter 0
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}
	nextCounter, err := TOTPCode(rfc6238Secret, time.Unix(89, 0)) // counter 2
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}
	twoStepsAhead, err := TOTPCode(rfc6238Secret, time.Unix(119, 0)) // counter 3
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}

	cases := []struct {
		name      string
		secret    string
		code      string
		now       time.Time
		skew      int
		wantOK    bool
		wantCount uint64
	}{
		{"current skew zero", rfc6238Secret, current, now, 0, true, 1},
		{"current with skew", rfc6238Secret, current, now, 2, true, 1},
		{"previous within skew one", rfc6238Secret, previousCounter, now, 1, true, 0},
		{"previous outside skew zero", rfc6238Secret, previousCounter, now, 0, false, 0},
		{"next within skew one", rfc6238Secret, nextCounter, now, 1, true, 2},
		{"next outside skew zero", rfc6238Secret, nextCounter, now, 0, false, 0},
		{"two steps ahead inside skew two", rfc6238Secret, twoStepsAhead, now, 2, true, 3},
		{"two steps ahead outside skew one", rfc6238Secret, twoStepsAhead, now, 1, false, 0},
		{"maximum skew", rfc6238Secret, current, now, MaxTOTPSkewSteps, true, 1},
		{"padded code input", rfc6238Secret, " " + current + " ", now, 0, true, 1},
		{"wrong code", rfc6238Secret, "000000", now, 1, false, 0},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			counter, ok, err := VerifyTOTP(testCase.secret, testCase.code, testCase.now, testCase.skew)
			if err != nil {
				t.Fatalf("VerifyTOTP: %v", err)
			}
			if ok != testCase.wantOK {
				t.Fatalf("VerifyTOTP ok = %v, want %v", ok, testCase.wantOK)
			}
			if ok && counter != testCase.wantCount {
				t.Fatalf("VerifyTOTP counter = %d, want %d", counter, testCase.wantCount)
			}
			if !ok && counter != 0 {
				t.Fatalf("VerifyTOTP returned nonzero counter %d on failure", counter)
			}
		})
	}
}

func TestVerifyTOTPRejectsMalformed(t *testing.T) {
	now := time.Unix(59, 0)
	code, err := TOTPCode(rfc6238Secret, now)
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}
	for _, malformed := range []string{"", "12345", "1234567", "abcdef", "12 456", "12345a", "１２３４５６", "-12345"} {
		if _, _, err := VerifyTOTP(rfc6238Secret, malformed, now, 1); !errors.Is(err, ErrInvalidTOTPCode) {
			t.Fatalf("VerifyTOTP(code=%q) error = %v, want ErrInvalidTOTPCode", malformed, err)
		}
	}
	for _, skew := range []int{-1, MaxTOTPSkewSteps + 1, 1000} {
		if _, _, err := VerifyTOTP(rfc6238Secret, code, now, skew); !errors.Is(err, ErrInvalidTOTPSkew) {
			t.Fatalf("VerifyTOTP(skew=%d) error = %v, want ErrInvalidTOTPSkew", skew, err)
		}
	}
}

func TestTOTPSecretParsing(t *testing.T) {
	code, err := TOTPCode(rfc6238Secret, time.Unix(59, 0))
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}
	// Case-insensitive and padded imported secrets are accepted.
	lower := strings.ToLower(rfc6238Secret)
	padded := rfc6238Secret + "===="
	for _, secret := range []string{rfc6238Secret, lower, padded, " " + rfc6238Secret + " "} {
		got, err := TOTPCode(secret, time.Unix(59, 0))
		if err != nil {
			t.Fatalf("TOTPCode(%q): %v", secret, err)
		}
		if got != code {
			t.Fatalf("TOTPCode(%q) = %q, want %q", secret, got, code)
		}
	}

	invalidSecrets := []string{
		"",
		"   ",
		"ABC",
		"!",
		base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345")), // too short (5 bytes)
		strings.Repeat("A", 300), // encoded length out of range
		"JBSW Y3DP EHPK 3PXP",    // internal spaces
	}
	for _, secret := range invalidSecrets {
		if _, err := TOTPCode(secret, time.Unix(59, 0)); !errors.Is(err, ErrInvalidTOTPSecret) {
			t.Fatalf("TOTPCode(secret=%q) error = %v, want ErrInvalidTOTPSecret", secret, err)
		}
	}
}

func TestTOTPCodeRejectsPreEpochTime(t *testing.T) {
	for _, timestamp := range []int64{-1, -30, -1234567890} {
		if _, err := TOTPCode(rfc6238Secret, time.Unix(timestamp, 0)); !errors.Is(err, ErrInvalidTOTPTime) {
			t.Fatalf("TOTPCode(unix=%d) error = %v, want ErrInvalidTOTPTime", timestamp, err)
		}
	}
}

func TestOtpauthURI(t *testing.T) {
	uri, err := OtpauthURI("ACME Co", "alice@example.com:prod", rfc6238Secret)
	if err != nil {
		t.Fatalf("OtpauthURI: %v", err)
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", uri, err)
	}
	if parsed.Scheme != "otpauth" || parsed.Host != "totp" {
		t.Fatalf("URI %q has scheme/host %q/%q, want otpauth/totp", uri, parsed.Scheme, parsed.Host)
	}
	if wantPath := "ACME Co:alice@example.com:prod"; parsed.Path != "/"+wantPath {
		t.Fatalf("URI path = %q, want %q", parsed.Path, "/"+wantPath)
	}
	if !strings.Contains(uri, "ACME%20Co:alice%40example.com%3Aprod") {
		t.Fatalf("URI %q does not percent-encode the label components", uri)
	}
	query := parsed.Query()
	if query.Get("secret") != rfc6238Secret {
		t.Fatalf("secret parameter = %q, want %q", query.Get("secret"), rfc6238Secret)
	}
	if query.Get("issuer") != "ACME Co" {
		t.Fatalf("issuer parameter = %q, want %q", query.Get("issuer"), "ACME Co")
	}
	if query.Get("algorithm") != "SHA1" {
		t.Fatalf("algorithm = %q, want SHA1", query.Get("algorithm"))
	}
	if query.Get("digits") != "6" {
		t.Fatalf("digits = %q, want 6", query.Get("digits"))
	}
	if query.Get("period") != "30" {
		t.Fatalf("period = %q, want 30", query.Get("period"))
	}

	// Padded/lowercase secrets and non-ASCII labels must normalize and escape.
	uri, err = OtpauthURI("服务", "用户", " "+strings.ToLower(rfc6238Secret)+"== ")
	if err != nil {
		t.Fatalf("OtpauthURI(non-ASCII): %v", err)
	}
	parsed, err = url.Parse(uri)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	if parsed.Query().Get("issuer") != "服务" || parsed.Query().Get("secret") != rfc6238Secret {
		t.Fatalf("non-ASCII URI did not round-trip: %q", uri)
	}
	if !strings.Contains(uri, "%E6%9C%8D%E5%8A%A1") {
		t.Fatalf("URI %q does not percent-encode UTF-8 label bytes", uri)
	}

	invalid := []struct {
		issuer  string
		account string
		secret  string
	}{
		{"", "alice", rfc6238Secret},
		{"   ", "alice", rfc6238Secret},
		{"ACME Co", "", rfc6238Secret},
		{"ACME Co", "   ", rfc6238Secret},
		{"bad\x00issuer", "alice", rfc6238Secret},
		{"ACME Co", "bad\naccount", rfc6238Secret},
		{strings.Repeat("i", 129), "alice", rfc6238Secret},
		{"ACME Co", strings.Repeat("a", 257), rfc6238Secret},
		{"ACME Co", "alice", "not base32!"},
	}
	for _, testCase := range invalid {
		if _, err := OtpauthURI(testCase.issuer, testCase.account, testCase.secret); err == nil {
			t.Fatalf("OtpauthURI(%q, %q, secret) = nil error, want error", testCase.issuer, testCase.account)
		}
	}
}

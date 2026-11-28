package umcauth

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"testing"
)

var recoveryCodeFormatRE = regexp.MustCompile(`^[A-Z2-7]{4}(-[A-Z2-7]{4}){5}$`)

func TestGenerateRecoveryCodes(t *testing.T) {
	codes, err := GenerateRecoveryCodes(10)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	if len(codes) != 10 {
		t.Fatalf("len(codes) = %d, want 10", len(codes))
	}
	seen := make(map[string]struct{}, len(codes))
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	for _, code := range codes {
		if !recoveryCodeFormatRE.MatchString(code) {
			t.Fatalf("code %q does not match human-readable format", code)
		}
		if _, duplicate := seen[code]; duplicate {
			t.Fatalf("duplicate recovery code %q", code)
		}
		seen[code] = struct{}{}
		raw, err := encoding.DecodeString(strings.ReplaceAll(code, "-", ""))
		if err != nil {
			t.Fatalf("decode code %q: %v", code, err)
		}
		if len(raw) < 10 {
			t.Fatalf("code %q carries %d bytes, want at least 10", code, len(raw))
		}
	}
}

func TestGenerateRecoveryCodesBounds(t *testing.T) {
	for _, count := range []int{-1, 0, recoveryCodeMaxCount + 1} {
		if _, err := GenerateRecoveryCodes(count); !errors.Is(err, ErrInvalidRecoveryCodeCount) {
			t.Fatalf("GenerateRecoveryCodes(%d) error = %v, want ErrInvalidRecoveryCodeCount", count, err)
		}
	}
	for _, count := range []int{1, 2, recoveryCodeMaxCount} {
		codes, err := GenerateRecoveryCodes(count)
		if err != nil {
			t.Fatalf("GenerateRecoveryCodes(%d): %v", count, err)
		}
		if len(codes) != count {
			t.Fatalf("GenerateRecoveryCodes(%d) returned %d codes", count, len(codes))
		}
	}
}

func TestNormalizeRecoveryCode(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"ABCD-EFGH-IJKL-MNOP-QRST-UVWX", "ABCDEFGHIJKLMNOPQRSTUVWX"},
		{"abcd-efgh-ijkl-mnop-qrst-uvwx", "ABCDEFGHIJKLMNOPQRSTUVWX"},
		{"  abcd efgh ijkl mnop qrst uvwx  ", "ABCDEFGHIJKLMNOPQRSTUVWX"},
		{"ABCD_EFGH\tIJKL\nMNOP QRST UVWX", "ABCDEFGHIJKLMNOPQRSTUVWX"},
		{"", ""},
	}
	for _, testCase := range cases {
		if got := NormalizeRecoveryCode(testCase.input); got != testCase.want {
			t.Fatalf("NormalizeRecoveryCode(%q) = %q, want %q", testCase.input, got, testCase.want)
		}
	}
}

func TestHashRecoveryCode(t *testing.T) {
	codes, err := GenerateRecoveryCodes(2)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	first, second := codes[0], codes[1]

	hash := HashRecoveryCode(first)
	if len(hash) != 64 {
		t.Fatalf("HashRecoveryCode length = %d, want 64 hex chars", len(hash))
	}
	if _, err := hex.DecodeString(hash); err != nil {
		t.Fatalf("HashRecoveryCode output %q is not hex: %v", hash, err)
	}
	if strings.ToLower(hash) != hash {
		t.Fatalf("HashRecoveryCode output %q is not lowercase", hash)
	}

	normalized := NormalizeRecoveryCode(first)
	wantSum := sha256.Sum256([]byte(normalized))
	if want := hex.EncodeToString(wantSum[:]); hash != want {
		t.Fatalf("HashRecoveryCode = %q, want SHA-256(normalized) = %q", hash, want)
	}

	// Punctuation, case and whitespace variants normalize to the same hash.
	for _, variant := range []string{
		strings.ToLower(first),
		strings.ReplaceAll(first, "-", ""),
		" " + strings.ReplaceAll(strings.ToLower(first), "-", " ") + " ",
		strings.ReplaceAll(first, "-", "_"),
	} {
		if got := HashRecoveryCode(variant); got != hash {
			t.Fatalf("HashRecoveryCode(%q) = %q, want %q", variant, got, hash)
		}
	}
	if HashRecoveryCode(second) == hash {
		t.Fatal("different recovery codes hash to the same value")
	}
	if strings.Contains(hash, strings.ReplaceAll(first, "-", "")) {
		t.Fatal("hash output contains the plaintext code")
	}
}

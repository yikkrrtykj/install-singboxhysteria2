package umcauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestNewToken(t *testing.T) {
	seen := make(map[string]struct{})
	for i := 0; i < 50; i++ {
		token, err := NewToken()
		if err != nil {
			t.Fatalf("NewToken: %v", err)
		}
		if len(token) != 43 {
			t.Fatalf("token %q length = %d, want 43 chars (32 raw bytes, base64url)", token, len(token))
		}
		if strings.Contains(token, "=") {
			t.Fatalf("token %q contains base64 padding", token)
		}
		raw, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil {
			t.Fatalf("token %q is not unpadded base64url: %v", token, err)
		}
		if len(raw) != 32 {
			t.Fatalf("token decodes to %d bytes, want 32", len(raw))
		}
		if _, duplicate := seen[token]; duplicate {
			t.Fatalf("NewToken returned duplicate token %q", token)
		}
		seen[token] = struct{}{}
	}
}

func TestNewCSRFToken(t *testing.T) {
	for i := 0; i < 20; i++ {
		token, err := NewCSRFToken()
		if err != nil {
			t.Fatalf("NewCSRFToken: %v", err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil || len(raw) != 32 {
			t.Fatalf("CSRF token %q: decoded %d bytes, %v; want 32", token, len(raw), err)
		}
	}
	first, err := NewCSRFToken()
	if err != nil {
		t.Fatalf("NewCSRFToken: %v", err)
	}
	second, err := NewCSRFToken()
	if err != nil {
		t.Fatalf("NewCSRFToken: %v", err)
	}
	if first == second {
		t.Fatal("NewCSRFToken returned the same token twice")
	}
}

func TestHashToken(t *testing.T) {
	token, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	hash := HashToken(token)
	if len(hash) != 64 {
		t.Fatalf("HashToken length = %d, want 64 hex chars", len(hash))
	}
	if _, err := hex.DecodeString(hash); err != nil {
		t.Fatalf("HashToken output is not hex: %v", err)
	}
	if hash != strings.ToLower(hash) {
		t.Fatalf("HashToken output %q is not lowercase", hash)
	}
	sum := sha256.Sum256([]byte(token))
	if want := hex.EncodeToString(sum[:]); hash != want {
		t.Fatalf("HashToken = %q, want %q", hash, want)
	}
	if HashToken(token+"x") == hash {
		t.Fatal("HashToken collided for different tokens")
	}
	if strings.Contains(hash, token) {
		t.Fatal("token hash contains the plaintext token")
	}
}

func TestConstantTimeEqual(t *testing.T) {
	token, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if !ConstantTimeEqual(token, token) {
		t.Fatal("ConstantTimeEqual(token, token) = false")
	}
	if ConstantTimeEqual(token, token+"x") {
		t.Fatal("ConstantTimeEqual accepted different strings")
	}
	if ConstantTimeEqual("", "x") {
		t.Fatal("ConstantTimeEqual accepted different strings of different lengths")
	}
	if !ConstantTimeEqual("", "") {
		t.Fatal("ConstantTimeEqual(\"\", \"\") = false")
	}
	other, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if ConstantTimeEqual(token, other) {
		t.Fatal("ConstantTimeEqual accepted two different tokens")
	}
	if ConstantTimeEqual(HashToken(token), token) {
		t.Fatal("ConstantTimeEqual accepted a token and its hash")
	}
}

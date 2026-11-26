package wire

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const vectorsDir = "../../../docs/um/contracts/v1"

type vectorSig struct {
	PublicKey string `json:"public_key_b64url"`
	Signature string `json:"signature_b64url"`
}

type vector struct {
	Headers        map[string]string `json:"headers"`
	BodyFile       string            `json:"body_file"`
	Body           string            `json:"body"`
	SigningString  string            `json:"signing_string"`
	Signature      vectorSig         `json:"signature"`
	DecodedSHA256  string            `json:"decoded_body_sha256_hex"`
	ExpectedResult string            `json:"-"`
}

type vectorsFile struct {
	Revision  int              `json:"revision"`
	Report    vector           `json:"report_vector"`
	Windows   vector           `json:"windows_terminal_report_vector"`
	Enroll    vector           `json:"enroll_vector"`
	Rotate    vector           `json:"rotate_vector"`
	Config    vector           `json:"config_vector"`
	Negatives []negativeVector `json:"negative_crypto_vectors"`
}

type negativeVector struct {
	ID            string            `json:"id"`
	Headers       map[string]string `json:"headers"`
	BodyFile      string            `json:"body_file"`
	SigningString string            `json:"signing_string"`
	Signature     vectorSig         `json:"signature"`
	SignatureFrom string            `json:"signature_from"`
}

func loadVectors(t *testing.T) vectorsFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorsDir, "test-vectors.v1.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vectorsFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if v.Revision != 5 {
		t.Fatalf("want revision 5, got %d", v.Revision)
	}
	return v
}

func fieldsFromHeaders(t *testing.T, headers map[string]string, endpoint Endpoint) Fields {
	t.Helper()
	return Fields{
		Endpoint:  endpoint,
		Protocol:  headers[HeaderProtocol],
		Encoding:  headers[HeaderContentEnc],
		SentAt:    headers[HeaderSentAt],
		Nonce:     headers[HeaderNonce],
		PublicKey: headers[HeaderPubkey],
		NodeID:    headers[HeaderNodeID],
		KeyID:     headers[HeaderKeyID],
		BootGen:   headers[HeaderBootGen],
		BootID:    headers[HeaderBootID],
		Sequence:  headers[HeaderSeq],
	}
}

func bodyOf(t *testing.T, v vector) []byte {
	t.Helper()
	if v.BodyFile != "" {
		b, err := os.ReadFile(filepath.Join(vectorsDir, v.BodyFile))
		if err != nil {
			t.Fatalf("read body %s: %v", v.BodyFile, err)
		}
		return b
	}
	return []byte(v.Body)
}

func checkVector(t *testing.T, name string, v vector, endpoint Endpoint, pubkey string) {
	t.Helper()
	body := bodyOf(t, v)
	fields := fieldsFromHeaders(t, v.Headers, endpoint)
	msg, err := SigningInput(fields, body)
	if err != nil {
		t.Fatalf("%s: signing input: %v", name, err)
	}
	if string(msg) != v.SigningString {
		t.Fatalf("%s: signing string mismatch\n got: %q\nwant: %q", name, msg, v.SigningString)
	}
	pub, err := base64.RawURLEncoding.DecodeString(pubkey)
	if err != nil {
		t.Fatalf("%s: pubkey decode: %v", name, err)
	}
	if err := VerifyWithError(fields, body, v.Signature.Signature, ed25519.PublicKey(pub)); err != nil {
		t.Fatalf("%s: verify: %v", name, err)
	}
}

func TestRevision5PositiveVectors(t *testing.T) {
	v := loadVectors(t)
	checkVector(t, "report", v.Report, Report, v.Report.Signature.PublicKey)
	checkVector(t, "windows-terminal", v.Windows, Report, v.Windows.Signature.PublicKey)
	checkVector(t, "enroll", v.Enroll, Enroll, v.Enroll.Signature.PublicKey)
	checkVector(t, "rotate", v.Rotate, Rotate, v.Rotate.Signature.PublicKey)
	checkVector(t, "config", v.Config, Config, v.Config.Signature.PublicKey)
}

func TestRevision5CryptoNegatives(t *testing.T) {
	v := loadVectors(t)
	byID := map[string]negativeVector{}
	for _, n := range v.Negatives {
		byID[n.ID] = n
	}

	t.Run("report-boot-gen-tamper", func(t *testing.T) {
		fields := fieldsFromHeaders(t, v.Report.Headers, Report)
		fields.BootGen = "2"
		pub := mustKey(t, v.Report.Signature.PublicKey)
		if Verify(fields, bodyOf(t, v.Report), v.Report.Signature.Signature, pub) {
			t.Fatal("tampered boot generation must not verify")
		}
	})

	t.Run("report-tampered-body", func(t *testing.T) {
		n := byID["report-tampered-body"]
		fields := fieldsFromHeaders(t, v.Report.Headers, Report)
		pub := mustKey(t, v.Report.Signature.PublicKey)
		if Verify(fields, bodyOf(t, vector{BodyFile: n.BodyFile}), v.Report.Signature.Signature, pub) {
			t.Fatal("tampered body must not verify")
		}
	})

	t.Run("report-wrong-key", func(t *testing.T) {
		n := byID["report-wrong-key"]
		fields := fieldsFromHeaders(t, v.Report.Headers, Report)
		msg, err := SigningInput(fields, bodyOf(t, v.Report))
		if err != nil {
			t.Fatal(err)
		}
		sig, err := base64.RawURLEncoding.DecodeString(n.Signature.Signature)
		if err != nil {
			t.Fatal(err)
		}
		if ed25519.Verify(mustKey(t, v.Report.Signature.PublicKey), msg, sig) {
			t.Fatal("wrong-key signature must not verify under report key")
		}
	})

	t.Run("report-signature-reused-on-rotate", func(t *testing.T) {
		fields := fieldsFromHeaders(t, v.Report.Headers, Rotate)
		pub := mustKey(t, v.Report.Signature.PublicKey)
		if Verify(fields, bodyOf(t, v.Report), v.Report.Signature.Signature, pub) {
			t.Fatal("report signature must not verify on rotate endpoint")
		}
	})

	t.Run("windows-terminal-tampered-body", func(t *testing.T) {
		n := byID["windows-terminal-tampered-body"]
		fields := fieldsFromHeaders(t, v.Windows.Headers, Report)
		pub := mustKey(t, v.Windows.Signature.PublicKey)
		if Verify(fields, bodyOf(t, vector{BodyFile: n.BodyFile}), v.Windows.Signature.Signature, pub) {
			t.Fatal("tampered windows body must not verify")
		}
	})

	t.Run("windows-terminal-boot-gen-tamper", func(t *testing.T) {
		fields := fieldsFromHeaders(t, v.Windows.Headers, Report)
		fields.BootGen = "6"
		pub := mustKey(t, v.Windows.Signature.PublicKey)
		if Verify(fields, bodyOf(t, v.Windows), v.Windows.Signature.Signature, pub) {
			t.Fatal("tampered windows boot generation must not verify")
		}
	})

	t.Run("rotate-new-pubkey-tampered", func(t *testing.T) {
		n := byID["rotate-new-pubkey-tampered"]
		fields := fieldsFromHeaders(t, v.Rotate.Headers, Rotate)
		pub := mustKey(t, v.Rotate.Signature.PublicKey)
		if Verify(fields, bodyOf(t, vector{BodyFile: n.BodyFile}), v.Rotate.Signature.Signature, pub) {
			t.Fatal("tampered rotate body must not verify")
		}
	})
}

func mustKey(t *testing.T, b64 string) ed25519.PublicKey {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil || len(b) != ed25519.PublicKeySize {
		t.Fatalf("bad public key %q: %v", b64, err)
	}
	return ed25519.PublicKey(b)
}

func validReportFields() Fields {
	return Fields{
		Endpoint: Report, Protocol: "1", Encoding: "identity",
		SentAt: "1795622410", Nonce: "AAECAwQFBgcICQoLDA0ODw",
		NodeID: "0f3d7c2a-8b41-4a6e-9c55-2d7e1b9a4c60",
		KeyID:  "key-4f2a9c1b", BootGen: "1",
		BootID:   "9c1f5a7e2b6d48c3a0e4f812d36b7c95",
		Sequence: "7",
	}
}

func TestCanonicalDecimalBounds(t *testing.T) {
	cases := []struct {
		name  string
		value string
		min   uint64
		max   uint64
		ok    bool
	}{
		{"max-numeric", "9223372036854775806", 1, MaxNumeric, true},
		{"above-max", "9223372036854775807", 1, MaxNumeric, false},
		{"leading-zero", "07", 1, MaxNumeric, false},
		{"plus", "+7", 1, MaxNumeric, false},
		{"space", " 7", 1, MaxNumeric, false},
		{"zero-when-min-one", "0", 1, MaxNumeric, false},
		{"sent-at-zero", "0", 0, maxSigned64, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseCanonicalDecimal("field", c.value, c.min, c.max)
			if (err == nil) != c.ok {
				t.Fatalf("ok=%v err=%v", c.ok, err)
			}
		})
	}
	if MaxNumeric != 9223372036854775806 || MaxBootGap != 65535 {
		t.Fatalf("frozen constants changed: max=%d gap=%d", MaxNumeric, MaxBootGap)
	}
}

func TestFieldsValidateRejects(t *testing.T) {
	base := validReportFields()
	bad := []struct {
		name string
		edit func(*Fields)
		code ErrorCode
	}{
		{"leading-zero-boot-gen", func(f *Fields) { f.BootGen = "01" }, CodeInvalidHeader},
		{"boot-gen-over-max", func(f *Fields) { f.BootGen = "9223372036854775807" }, CodeInvalidHeader},
		{"leading-zero-seq", func(f *Fields) { f.Sequence = "07" }, CodeInvalidHeader},
		{"seq-zero", func(f *Fields) { f.Sequence = "0" }, CodeInvalidHeader},
		{"bad-node-id", func(f *Fields) { f.NodeID = "not-a-uuid" }, CodeInvalidHeader},
		{"bad-key-id", func(f *Fields) { f.KeyID = "key-XYZ" }, CodeInvalidHeader},
		{"bad-boot-id", func(f *Fields) { f.BootID = "xyz" }, CodeInvalidHeader},
		{"bad-encoding", func(f *Fields) { f.Encoding = "deflate" }, CodeInvalidHeader},
		{"bad-sent-at", func(f *Fields) { f.SentAt = "1795622410.5" }, CodeInvalidHeader},
		{"public-key-on-report", func(f *Fields) { f.PublicKey = "abc" }, CodeInvalidHeader},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			f := base
			c.edit(&f)
			err := f.Validate()
			if err == nil || !IsCode(err, c.code) {
				t.Fatalf("want %s, got %v", c.code, err)
			}
		})
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fields := validReportFields()
	body := []byte(`{"v":1}`)
	sig, err := Sign(priv, fields, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyWithError(fields, body, sig, pub); err != nil {
		t.Fatalf("round-trip verify: %v", err)
	}
	if Verify(fields, []byte(`{"v":2}`), sig, pub) {
		t.Fatal("modified body must not verify")
	}
	if err := VerifyWithError(fields, body, "not-base64", pub); !IsCode(err, CodeBadSignature) {
		t.Fatalf("want bad_signature, got %v", err)
	}
}

func TestConfigBodyStrictlyTwoBytes(t *testing.T) {
	fields := validReportFields()
	fields.Endpoint = Config
	fields.Sequence = "9"
	for _, body := range []string{"", "{} ", "{ }", "{\n}", `{}`} {
		_, err := SigningInput(fields, []byte(body))
		if body == "{}" {
			if err != nil {
				t.Fatalf("valid config body rejected: %v", err)
			}
			continue
		}
		if !IsCode(err, CodeInvalidHeader) && !IsCode(err, CodeInvalidFields) {
			t.Fatalf("body %q: expected field error, got %v", body, err)
		}
	}
}

func TestFingerprint(t *testing.T) {
	fields := validReportFields()
	body := []byte(`{"v":1}`)
	fp1, err := Fingerprint(fields, body)
	if err != nil {
		t.Fatal(err)
	}
	fp2, err := Fingerprint(fields, body)
	if err != nil || fp1 != fp2 {
		t.Fatalf("fingerprint not deterministic: %v %q %q", err, fp1, fp2)
	}
	if len(fp1) != 64 {
		t.Fatalf("want sha256 hex, got %q", fp1)
	}
	changed := fields
	changed.SentAt = "1795622411"
	fp3, err := Fingerprint(changed, body)
	if err != nil || fp3 == fp1 {
		t.Fatalf("fingerprint must bind sent_at: %v", err)
	}
	if _, err := Fingerprint(fields, []byte("{}")); err != nil {
		t.Fatalf("wire fingerprint must not perform payload-schema validation: %v", err)
	}
}

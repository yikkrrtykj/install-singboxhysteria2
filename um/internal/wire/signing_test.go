package wire

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const fixtureDir = "../../../docs/um/contracts/v1"

type signedVector struct {
	Headers       map[string]string `json:"headers"`
	BodyFile      string            `json:"body_file"`
	SigningString string            `json:"signing_string"`
	Signature     struct {
		Key string `json:"public_key_b64url"`
		Tag string `json:"signature_b64url"`
	} `json:"signature"`
}

func (v signedVector) fields(endpoint Endpoint) Fields {
	return Fields{
		Endpoint: endpoint, Protocol: v.Headers["X-UM-Protocol"],
		Encoding: v.Headers["X-UM-Content-Encoding"], SentAt: v.Headers["X-UM-Sent-At"],
		Nonce: v.Headers["X-UM-Nonce"], PublicKey: v.Headers["X-UM-Pubkey"],
		NodeID: v.Headers["X-UM-Node-Id"], KeyID: v.Headers["X-UM-Key-Id"],
		BootID: v.Headers["X-UM-Boot-Id"], Sequence: v.Headers["X-UM-Seq"],
	}
}

func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(fixtureDir, path))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestFrozenSignedVectors(t *testing.T) {
	var vectors struct {
		Report   signedVector `json:"report_vector"`
		Enroll   signedVector `json:"enroll_vector"`
		Negative []struct {
			ID            string `json:"id"`
			BodyFile      string `json:"body_file"`
			SigningString string `json:"signing_string"`
			Tag           string `json:"signature_b64url"`
		} `json:"negative_crypto_vectors"`
	}
	if err := json.Unmarshal(readFixture(t, "test-vectors.v1.json"), &vectors); err != nil {
		t.Fatal(err)
	}
	positives := map[Endpoint]signedVector{Report: vectors.Report, Enroll: vectors.Enroll}
	for endpoint, vector := range positives {
		t.Run(string(endpoint), func(t *testing.T) {
			fields := vector.fields(endpoint)
			body := readFixture(t, vector.BodyFile)
			publicKey := ed25519.PublicKey(decodeBase64(vector.Signature.Key, ed25519.PublicKeySize))
			got, err := SigningInput(fields, body)
			if err != nil || string(got) != vector.SigningString {
				t.Fatalf("frozen signing bytes differ, err = %v", err)
			}
			if !Verify(fields, body, vector.Signature.Tag, publicKey) {
				t.Fatal("frozen valid signature did not verify")
			}
			if Verify(fields, body, vector.Signature.Tag+"\n", publicKey) {
				t.Fatal("noncanonical signature encoding was accepted")
			}
		})
	}

	vector := vectors.Report
	publicKey := ed25519.PublicKey(decodeBase64(vector.Signature.Key, ed25519.PublicKeySize))
	for _, negative := range vectors.Negative {
		t.Run(negative.ID, func(t *testing.T) {
			fields := vector.fields(Report)
			body := readFixture(t, vector.BodyFile)
			tag := vector.Signature.Tag
			switch negative.ID {
			case "report-tampered-body":
				body = readFixture(t, negative.BodyFile)
			case "report-wrong-key":
				tag = negative.Tag
			case "report-signature-reused-on-rotate":
				fields.Endpoint = Rotate
				got, err := SigningInput(fields, body)
				if err != nil || string(got) != negative.SigningString {
					t.Fatalf("frozen rotate signing bytes differ, err = %v", err)
				}
			default:
				t.Fatal("unhandled negative fixture")
			}
			if Verify(fields, body, tag, publicKey) {
				t.Fatal("frozen invalid signature verified")
			}
		})
	}
	fields := vector.fields(Config)
	if _, err := SigningInput(fields, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{"", "{}\n", "{ }"} {
		if _, err := SigningInput(fields, []byte(body)); err == nil {
			t.Errorf("accepted invalid config body %q", body)
		}
	}
}

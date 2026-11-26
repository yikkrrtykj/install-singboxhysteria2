package center

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/wire"
)

// knownXUMHeaders is the exact closed set of X-UM-* request headers (lowercase,
// case-insensitive match). Anything else with the X-UM- prefix is rejected
// before routing; there is no extension header namespace in rev 5.
var knownXUMHeaders = map[string]struct{}{
	"x-um-protocol":         {},
	"x-um-pubkey":           {},
	"x-um-node-id":          {},
	"x-um-key-id":           {},
	"x-um-boot-gen":         {},
	"x-um-boot-id":          {},
	"x-um-seq":              {},
	"x-um-sent-at":          {},
	"x-um-nonce":            {},
	"x-um-content-encoding": {},
	"x-um-signature":        {},
}

// headerIndex holds every raw header value grouped by case-insensitive name.
// Duplicate detection must look at the raw slices, not at Header.Get (which
// silently joins or discards repeated values).
type headerIndex struct {
	values map[string][]string
}

// indexHeaders enforces the frozen raw-header rules before any header value is
// parsed:
//
//   - any repeated X-UM-* / Content-Encoding / Authorization header value is
//     400 duplicate_header;
//   - any unknown X-UM-* header name is 400 invalid_header.
//
// Detection is deterministic: duplicate names are checked in sorted order, then
// unknown names in sorted order, so a request carrying both always yields the
// same frozen error.
func indexHeaders(h http.Header) (*headerIndex, *APIError) {
	idx := &headerIndex{values: make(map[string][]string, len(h))}
	for name, vals := range h {
		lower := strings.ToLower(name)
		idx.values[lower] = append(idx.values[lower], vals...)
	}
	names := make([]string, 0, len(idx.values))
	for name := range idx.values {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if len(idx.values[name]) <= 1 {
			continue
		}
		if strings.HasPrefix(name, "x-um-") || name == "content-encoding" || name == "authorization" {
			return nil, duplicateHeaderError()
		}
	}
	for _, name := range names {
		if !strings.HasPrefix(name, "x-um-") {
			continue
		}
		if _, known := knownXUMHeaders[name]; !known {
			return nil, invalidHeaderError()
		}
	}
	return idx, nil
}

// single returns the unique value of a header and whether it was present. An
// empty header value is "present" and is then rejected by grammar validation,
// which is distinct from a missing header.
func (h *headerIndex) single(name string) (string, bool) {
	vals := h.values[strings.ToLower(name)]
	if len(vals) == 0 {
		return "", false
	}
	return vals[0], true
}

// present reports whether the header appeared at least once.
func (h *headerIndex) present(name string) bool {
	_, ok := h.single(name)
	return ok
}

// Signed headers required per endpoint. Content-Type and Authorization are
// validated separately because they are not part of the signing string.
var (
	enrollSignedHeaders = []string{
		wire.HeaderProtocol, wire.HeaderPubkey, wire.HeaderSentAt,
		wire.HeaderNonce, wire.HeaderContentEnc, wire.HeaderSignature,
	}
	nodeSignedHeaders = []string{
		wire.HeaderProtocol, wire.HeaderNodeID, wire.HeaderKeyID,
		wire.HeaderBootGen, wire.HeaderBootID, wire.HeaderSeq,
		wire.HeaderSentAt, wire.HeaderNonce, wire.HeaderContentEnc,
		wire.HeaderSignature,
	}
)

// parseSignedFields validates header cardinality and grammar for one endpoint
// and copies the exact raw values into wire.Fields. It returns the raw
// X-UM-Signature tag unchanged: only its syntactic base64url-64B grammar is
// checked here, the Service owns cryptographic verification.
//
// Cross-endpoint headers are rejected (enroll cannot carry node-auth headers;
// node endpoints cannot carry X-UM-Pubkey or Authorization), matching the
// per-endpoint header table in docs/um/um-a/04-node-protocol-v1.md §2.
func parseSignedFields(idx *headerIndex, ep wire.Endpoint) (wire.Fields, string, *APIError) {
	required := nodeSignedHeaders
	if ep == wire.Enroll {
		required = enrollSignedHeaders
	}
	for _, name := range required {
		if !idx.present(name) {
			return wire.Fields{}, "", missingHeaderError()
		}
	}
	signature, _ := idx.single(wire.HeaderSignature)
	if !validSignatureTag(signature) {
		return wire.Fields{}, "", invalidHeaderError()
	}
	if ep == wire.Enroll {
		for _, name := range []string{
			wire.HeaderNodeID, wire.HeaderKeyID, wire.HeaderBootGen,
			wire.HeaderBootID, wire.HeaderSeq,
		} {
			if idx.present(name) {
				return wire.Fields{}, "", invalidHeaderError()
			}
		}
	} else {
		if idx.present(wire.HeaderPubkey) {
			return wire.Fields{}, "", invalidHeaderError()
		}
		if idx.present(wire.HeaderAuthorization) {
			return wire.Fields{}, "", invalidHeaderError()
		}
	}

	fields := wire.Fields{
		Endpoint: ep,
		Protocol: headerValue(idx, wire.HeaderProtocol),
		Encoding: headerValue(idx, wire.HeaderContentEnc),
		SentAt:   headerValue(idx, wire.HeaderSentAt),
		Nonce:    headerValue(idx, wire.HeaderNonce),
	}
	if ep == wire.Enroll {
		fields.PublicKey = headerValue(idx, wire.HeaderPubkey)
	} else {
		fields.NodeID = headerValue(idx, wire.HeaderNodeID)
		fields.KeyID = headerValue(idx, wire.HeaderKeyID)
		fields.BootGen = headerValue(idx, wire.HeaderBootGen)
		fields.BootID = headerValue(idx, wire.HeaderBootID)
		fields.Sequence = headerValue(idx, wire.HeaderSeq)
	}
	// The vector NEG-ENROLL-10 expects unsupported_encoding (not invalid_header)
	// for a stacked or non-gzip Content-Encoding token, so screen the signed
	// coding before wire.Validate and map its encoding field accordingly.
	if fields.Encoding != "identity" && fields.Encoding != "gzip" {
		return wire.Fields{}, "", unsupportedEncodingError()
	}
	if err := fields.Validate(); err != nil {
		var fieldErr *wire.FieldError
		if errors.As(err, &fieldErr) {
			if fieldErr.Field == wire.HeaderContentEnc {
				return wire.Fields{}, "", unsupportedEncodingError()
			}
			if fieldErr.Code == wire.CodeMissingHeader {
				return wire.Fields{}, "", missingHeaderError()
			}
		}
		return wire.Fields{}, "", invalidHeaderError()
	}
	return fields, signature, nil
}

// headerValue reads a header that the caller has already verified as present.
func headerValue(idx *headerIndex, name string) string {
	value, _ := idx.single(name)
	return value
}

// checkContentType enforces the frozen Content-Type: exactly application/json,
// no parameters and no alternative case spelling.
func checkContentType(idx *headerIndex) *APIError {
	value, ok := idx.single(wire.HeaderContentType)
	if !ok {
		return missingHeaderError()
	}
	if strings.TrimSpace(value) != "application/json" {
		return invalidHeaderError()
	}
	return nil
}

// checkEncodingConsistency enforces the frozen Content-Encoding/§1 rule: both
// headers are explicit, the HTTP header may be absent only when the signed
// coding is identity, and when present it must be byte-identical to the signed
// value. Every violation is 400 unsupported_encoding (repeated headers were
// already rejected as duplicate_header).
func checkEncodingConsistency(idx *headerIndex, fields wire.Fields) *APIError {
	httpEncoding, present := idx.single("Content-Encoding")
	if !present {
		if fields.Encoding != "identity" {
			return unsupportedEncodingError()
		}
		return nil
	}
	if httpEncoding != fields.Encoding {
		return unsupportedEncodingError()
	}
	return nil
}

// parseBearerToken parses the enroll-only Authorization header as
// "Bearer <bootstrap-token>". A missing or malformed value is 401 unauthorized,
// never invalid_header, because the token is an authentication credential and
// the contract confirms only the generic auth failure.
func parseBearerToken(idx *headerIndex) (string, *APIError) {
	raw, ok := idx.single(wire.HeaderAuthorization)
	if !ok {
		return "", unauthorizedError()
	}
	const prefix = "bearer "
	if len(raw) <= len(prefix) || !strings.EqualFold(raw[:len(prefix)], prefix) {
		return "", unauthorizedError()
	}
	token := strings.TrimSpace(raw[len(prefix):])
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", unauthorizedError()
	}
	return token, nil
}

// validSignatureTag checks the frozen base64url 64-byte grammar of
// X-UM-Signature. A syntactically malformed tag is 400 invalid_header; a
// well-formed tag that does not verify is the Service's 401 bad_signature.
func validSignatureTag(tag string) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(tag)
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return false
	}
	return base64.RawURLEncoding.EncodeToString(decoded) == tag
}

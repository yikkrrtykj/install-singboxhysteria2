package contract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// Privacy sentinel detection.
//
// This scanner is best-effort defense in depth, not a proof of absence: no
// finite scanner can prove that an arbitrary string contains no secret. The
// frozen schemas already close every report object to enums, patterns and
// bounded integers; the scan exists to catch a future schema revision or a bug
// above this layer that lets free-form or credential-shaped text through.
//
// Scanning is by field path, not by a global regex. The frozen contract defines
// legitimate machine identities — UUID `report_id`/`event_id` (and `node_id`
// where the envelope carries one), the 43-char base64url `device_ref` client
// pseudonym, and the 32-hex `counter_epoch` rotation epoch — so identifier-shape
// heuristics are skipped exactly at those paths while the unambiguous
// credential/material markers still apply everywhere. A report_id/event_id UUID
// or a device_ref pseudonym is not a credential and must never be rejected as
// one.
var (
	// uuidSentinelRE matches UUID-shaped identifiers.
	uuidSentinelRE = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	// ipv4SentinelRE matches dotted-quad IPv4-shaped values.
	ipv4SentinelRE = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	// ipv6SentinelRE matches IPv6-shaped values (including compressed forms).
	ipv6SentinelRE = regexp.MustCompile(`(?i)(?:[0-9a-f]{1,4}:){2,}[0-9a-f]{0,4}|::`)
	// urlSentinelRE matches scheme-qualified URLs.
	urlSentinelRE = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://`)
	// hexIDSentinelRE matches long hex blobs used as connection/request ids.
	hexIDSentinelRE = regexp.MustCompile(`(?i)\b[0-9a-f]{16,}\b`)
	// opaqueTokenSentinelRE matches long base64url-like tokens (device salts,
	// session/connection tokens) that contain at least one digit.
	opaqueTokenSentinelRE = regexp.MustCompile(`^[A-Za-z0-9_-]{24,}$`)
	// connIDPrefixSentinelRE matches explicit conn/conntrack/connection ids.
	connIDPrefixSentinelRE = regexp.MustCompile(`(?i)\b(?:conn|conntrack|connection|cid)[-_:=][a-z0-9][a-z0-9_-]{3,}\b`)
)

// privateYAMLMarkers are lowercase fragments that identify private YAML,
// credentials, tokens or PEM material. They are unambiguous: none can appear in
// a legitimate contract identifier or enum token.
var privateYAMLMarkers = []string{
	"proxies:",
	"mixed-port:",
	"external-controller:",
	"password:",
	"password=",
	"secret:",
	"secret=",
	"token=",
	"begin ",
}

// contractUUIDFields are member names whose frozen schema type is a UUID machine
// identity. A UUID at one of those paths is legitimate identity, not a secret.
var contractUUIDFields = []string{"report_id", "event_id", "node_id"}

// contractOpaqueIdentifierFields are further contract-defined identifiers whose
// shape would otherwise look credential-like: the 43-char base64url device_ref
// pseudonym and the 32-hex counter_epoch rotation epoch.
var contractOpaqueIdentifierFields = []string{"device_ref", "counter_epoch", "source_epoch"}

// matchesFieldPath reports whether path is the member named field, or a nested
// member path ending in ".field" (for example "events[0].event_id").
func matchesFieldPath(path, field string) bool {
	return path == field || strings.HasSuffix(path, "."+field)
}

// isContractIdentifierField reports whether path is one of the frozen contract's
// legitimate identifier fields, where identifier-shape heuristics must not fire.
func isContractIdentifierField(path string) bool {
	for _, field := range contractUUIDFields {
		if matchesFieldPath(path, field) {
			return true
		}
	}
	for _, field := range contractOpaqueIdentifierFields {
		if matchesFieldPath(path, field) {
			return true
		}
	}
	return false
}

// joinJSONPath builds a stable, non-secret field path used in errors.
func joinJSONPath(path, member string) string {
	if path == "" {
		return member
	}
	return path + "." + member
}

// privacyMaterialKind returns a non-secret category when value contains an
// unambiguous credential/private-material marker, and "" otherwise.
func privacyMaterialKind(value string) string {
	lower := strings.ToLower(value)
	for _, marker := range privateYAMLMarkers {
		if strings.Contains(lower, marker) {
			return "private-yaml/credential marker"
		}
	}
	return ""
}

// privacySentinelKind returns a non-secret category when value alone looks like
// a forbidden privacy sentinel, and "" otherwise. It has no path context and is
// used for map member names; report values must go through
// privacySentinelKindAt so contract identifiers are not false-positives. The
// value itself is never included in the returned category.
func privacySentinelKind(value string) string {
	if value == "" {
		return ""
	}
	if kind := privacyMaterialKind(value); kind != "" {
		return kind
	}
	if uuidSentinelRE.MatchString(value) {
		return "uuid-like value"
	}
	if ipv4SentinelRE.MatchString(value) {
		return "ip-address-like value"
	}
	if ipv6SentinelRE.MatchString(value) {
		return "ip-address-like value"
	}
	if urlSentinelRE.MatchString(value) {
		return "url-like value"
	}
	if hexIDSentinelRE.MatchString(value) {
		return "connection-id-like value"
	}
	if opaqueTokenSentinelRE.MatchString(value) && hasDigit(value) {
		return "connection-id-like value"
	}
	if connIDPrefixSentinelRE.MatchString(value) {
		return "connection-id-like value"
	}
	return ""
}

// privacySentinelKindAt is the path-aware sentinel classifier used for report
// values. Contract-defined identifiers (report_id/event_id/node_id/device_ref/
// counter_epoch) are exempt from UUID/hex/base64url shape heuristics because
// they are legitimate identities, but the unambiguous material markers still
// apply to every value: no legitimate identifier contains a PEM/credential/YAML
// marker.
func privacySentinelKindAt(path, value string) string {
	if value == "" {
		return ""
	}
	if kind := privacyMaterialKind(value); kind != "" {
		return kind
	}
	if isContractIdentifierField(path) {
		return ""
	}
	return privacySentinelKind(value)
}

func hasDigit(value string) bool {
	return strings.IndexFunc(value, unicode.IsDigit) >= 0
}

// scanReportPrivacy scans every string reachable from a decoded report body of
// any type (snapshot, metrics or events — not only terminal telemetry), by
// field path. Map member names are checked too, in sorted order for
// deterministic errors. This is best-effort: it cannot prove absence of every
// possible secret. The offending key/value is never echoed: Detail carries only
// the sentinel category.
func scanReportPrivacy(reportType string, raw []byte) error {
	document, err := decodeAny(raw)
	if err != nil {
		return invalid("body", "malformed "+reportType+" body")
	}
	return scanPrivacy(document, "")
}

// scanPrivacy walks a decoded JSON value and rejects the first string that looks
// like a privacy sentinel. path is the current field path used for the
// identifier allowlist and stable error locations.
func scanPrivacy(value any, path string) error {
	switch node := value.(type) {
	case string:
		if kind := privacySentinelKindAt(path, node); kind != "" {
			return invalid(path, "privacy sentinel detected: "+kind)
		}
	case map[string]any:
		keys := make([]string, 0, len(node))
		for key := range node {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if kind := privacySentinelKind(key); kind != "" {
				return invalid(path, "privacy sentinel detected in field name: "+kind)
			}
			if err := scanPrivacy(node[key], joinJSONPath(path, key)); err != nil {
				return err
			}
		}
	case []any:
		for index, item := range node {
			if err := scanPrivacy(item, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
	}
	return nil
}

// decodeAny decodes JSON preserving integer precision (json.Number) so the
// privacy scanner never coerces counts.
func decodeAny(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	return document, nil
}

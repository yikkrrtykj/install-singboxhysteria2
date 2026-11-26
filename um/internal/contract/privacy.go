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

// Privacy sentinel detection. The frozen protocol forbids UUIDs, IP addresses,
// URLs, YAML/credential material, raw proxy names and connection ids in agent
// payloads. JSON Schema already closes the terminal object to enums and fixed
// keys; this scanner is the defense-in-depth boundary for free-form string
// values that a future schema revision (or a bug above this layer) might let
// through.
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
// credentials or PEM material.
var privateYAMLMarkers = []string{"proxies:", "password:", "secret:", "begin "}

// privacySentinelKind returns a non-secret category when value looks like a
// forbidden privacy sentinel, and "" otherwise. The value itself is never
// included in the returned category.
func privacySentinelKind(value string) string {
	if value == "" {
		return ""
	}
	lower := strings.ToLower(value)
	for _, marker := range privateYAMLMarkers {
		if strings.Contains(lower, marker) {
			return "private-yaml/credential marker"
		}
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

func hasDigit(value string) bool {
	return strings.IndexFunc(value, unicode.IsDigit) >= 0
}

// scanPrivacy walks a decoded JSON value and rejects the first string that looks
// like a privacy sentinel. Map keys are checked too, in sorted order for
// deterministic errors. The offending key/value is never echoed: Detail carries
// only the sentinel category.
func scanPrivacy(value any, path string) error {
	switch node := value.(type) {
	case string:
		if kind := privacySentinelKind(node); kind != "" {
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
			if err := scanPrivacy(node[key], path+"."+key); err != nil {
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

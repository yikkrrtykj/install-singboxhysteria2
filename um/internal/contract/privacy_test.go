package contract

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPrivacySentinelKindCleanValues(t *testing.T) {
	// Every legal terminal value (availability enums, six route tokens, closed
	// reason codes, event source/kind tokens) must pass the sentinel scanner.
	clean := []string{
		"", "ok", "partial", "unavailable",
		"a_reality", "a_hy2", "b_reality", "b_hy2", "direct", "unknown",
		"controller_unreachable", "controller_auth", "malformed_response",
		"route_unbound", "source_authorization_unproven",
		"mihomo_api", "local_readonly", "sing-box",
		"agent_started", "terminal_route_changed", "terminal_source_unavailable",
	}
	for _, value := range clean {
		if kind := privacySentinelKind(value); kind != "" {
			t.Errorf("privacySentinelKind(%q) = %q, want no sentinel", value, kind)
		}
	}
}

func TestPrivacySentinelKindSentinels(t *testing.T) {
	cases := []struct {
		value string
		want  string
	}{
		{"550e8400-e29b-41d4-a716-446655440000", "uuid-like"},
		{"10.0.0.1", "ip-address-like"},
		{"192.168.10.20", "ip-address-like"},
		{"2001:db8::1", "ip-address-like"},
		{"fe80::1", "ip-address-like"},
		{"proxies:\n  - name: vps-a", "private-yaml"},
		{"password: hunter2", "private-yaml"},
		{"secret: s3cr3t", "private-yaml"},
		{"-----BEGIN OPENSSH PRIVATE KEY-----", "private-yaml"},
		{"https://controller.example/api", "url-like"},
		{"wss://relay.example/ws", "url-like"},
		{"conn-9f2a1b3c4d", "connection-id-like"},
		{"conntrack:abcdef123456", "connection-id-like"},
		{"9f2a1b3c4d5e6f708192a3b4c5d6e7f8", "connection-id-like"},
		{"AbCdEf0123456789AbCdEf0123456789", "connection-id-like"},
	}
	for _, tc := range cases {
		got := privacySentinelKind(tc.value)
		if !strings.Contains(got, tc.want) {
			t.Errorf("privacySentinelKind(%q) = %q, want category containing %q", tc.value, got, tc.want)
		}
		if strings.Contains(got, tc.value) {
			t.Errorf("sentinel category %q echoes the offending value", got)
		}
	}
}

func TestScanPrivacy(t *testing.T) {
	t.Run("clean terminal object", func(t *testing.T) {
		doc := decodeJSONObject(t, readExample(t, terminalSnapshotExample))
		terminal := doc["terminal"]
		if err := scanPrivacy(terminal, "terminal"); err != nil {
			t.Fatalf("clean terminal object rejected: %v", err)
		}
	})

	t.Run("nested uuid in terminal field", func(t *testing.T) {
		const sentinel = "550e8400-e29b-41d4-a716-446655440000"
		terminal := map[string]any{
			"selection": map[string]any{"route": sentinel, "reason_code": nil},
		}
		err := scanPrivacy(terminal, "terminal")
		requireInvalidRequest(t, err)
		requireField(t, err, "terminal.selection.route")
		if strings.Contains(err.Error(), sentinel) {
			t.Fatalf("error echoes the sentinel: %v", err)
		}
		if !strings.Contains(err.Error(), "uuid-like") {
			t.Fatalf("error = %v, want uuid-like category", err)
		}
	})

	t.Run("ip in sliced value", func(t *testing.T) {
		const sentinel = "10.1.2.3"
		terminal := map[string]any{
			"active_connections": map[string]any{
				"by_route": []any{"a_reality", sentinel},
			},
		}
		err := scanPrivacy(terminal, "terminal")
		requireInvalidRequest(t, err)
		requireField(t, err, "terminal.active_connections.by_route[1]")
		if strings.Contains(err.Error(), sentinel) {
			t.Fatalf("error echoes the sentinel: %v", err)
		}
	})

	t.Run("yaml marker in map key", func(t *testing.T) {
		const sentinelMarker = "password:"
		terminal := map[string]any{
			sentinelMarker + " hunter2": json.Number("1"),
		}
		err := scanPrivacy(terminal, "terminal")
		requireInvalidRequest(t, err)
		requireField(t, err, "terminal")
		if strings.Contains(err.Error(), "hunter2") {
			t.Fatalf("error echoes the sentinel: %v", err)
		}
		if !strings.Contains(err.Error(), "field name") {
			t.Fatalf("error = %v, want field-name category", err)
		}
	})
}

// TestTerminalSentinelRuntimeWiring proves the privacy scan is wired into the
// terminal runtime validation, not just unit-tested in isolation. The schema is
// bypassed here because the frozen terminal object is closed; this guards future
// schema revisions that might admit a free-form string field.
func TestTerminalSentinelRuntimeWiring(t *testing.T) {
	const sentinel = "550e8400-e29b-41d4-a716-446655440000"
	terminal := []byte(`{"selection":{"availability":"ok","sampled_at":1795622398,"route":"` + sentinel + `","reason_code":null},` +
		`"active_connections":{"availability":"ok","sampled_at":1795622399,"total":42,"by_route":{"a_reality":20,"a_hy2":5,"b_reality":10,"b_hy2":2,"direct":3,"unknown":2}}}`)
	err := validateTerminalTelemetry(1795622400, terminal)
	requireInvalidRequest(t, err)
	requireField(t, err, "terminal.selection.route")
	if strings.Contains(err.Error(), sentinel) {
		t.Fatalf("runtime validation echoes the sentinel: %v", err)
	}
}

// TestSentinelRejectedAtSnapshotBoundary plants UUID/IP/YAML sentinels in the
// terminal payload and requires ValidateSnapshot to reject the report without
// echoing the value. This is the SEC-14/NEG-PLAT-09 boundary check.
func TestSentinelRejectedAtSnapshotBoundary(t *testing.T) {
	cases := []struct {
		name     string
		sentinel string
		mutate   func(doc map[string]any)
	}{
		{
			name:     "raw proxy name extra field",
			sentinel: "vps-a-reality",
			mutate: func(doc map[string]any) {
				objectAt(t, doc, "terminal", "selection")["proxy_name"] = "vps-a-reality"
			},
		},
		{
			name:     "uuid in reason_code",
			sentinel: "550e8400-e29b-41d4-a716-446655440000",
			mutate: func(doc map[string]any) {
				objectAt(t, doc, "terminal", "selection")["reason_code"] = "550e8400-e29b-41d4-a716-446655440000"
			},
		},
		{
			name:     "ipv4 in route",
			sentinel: "10.0.0.1",
			mutate: func(doc map[string]any) {
				objectAt(t, doc, "terminal", "selection")["route"] = "10.0.0.1"
			},
		},
		{
			name:     "yaml marker in nested extra field",
			sentinel: "password: hunter2",
			mutate: func(doc map[string]any) {
				objectAt(t, doc, "terminal")["notes"] = map[string]any{"config": "password: hunter2"}
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			raw := mutateExample(t, terminalSnapshotExample, tc.mutate)
			err := ValidateSnapshot(NodeClassWindowsTerminal, raw)
			requireInvalidRequest(t, err)
			if strings.Contains(err.Error(), tc.sentinel) {
				t.Fatalf("boundary error echoes the sentinel: %v", err)
			}
		})
	}

	// The committed raw-proxy-name negative example must be rejected without
	// echoing its synthetic proxy name.
	raw := readExample(t, "examples/negative/terminal-raw-proxy-name.v1.json")
	err := ValidateSnapshot(NodeClassWindowsTerminal, raw)
	requireInvalidRequest(t, err)
	if strings.Contains(err.Error(), "vps-a-reality") {
		t.Fatalf("committed negative example echoed its proxy name: %v", err)
	}
}

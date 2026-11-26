package contract

import (
	"encoding/json"
	"strings"
	"testing"
)

// windowsTerminalTokens is used to null out all six route counts.
var windowsTerminalTokens = []string{"a_reality", "a_hy2", "b_reality", "b_hy2", "direct", "unknown"}

func TestValidateSnapshotPositiveExamples(t *testing.T) {
	if err := ValidateSnapshot(NodeClassWindowsTerminal, readExample(t, terminalSnapshotExample)); err != nil {
		t.Fatalf("valid windows terminal snapshot rejected: %v", err)
	}
	if err := ValidateSnapshot(NodeClassLinuxVPS, readExample(t, linuxSnapshotExample)); err != nil {
		t.Fatalf("valid linux_vps snapshot rejected: %v", err)
	}
}

// TestValidateSnapshotUnavailableAndPartialTerminal pins the honest-degradation
// paths: an unconfigured/unavailable source still sends the terminal object with
// availability=unavailable and every count null.
func TestValidateSnapshotUnavailableAndPartialTerminal(t *testing.T) {
	t.Run("unavailable", func(t *testing.T) {
		raw := mutateExample(t, terminalSnapshotExample, func(doc map[string]any) {
			selection := objectAt(t, doc, "terminal", "selection")
			selection["availability"] = "unavailable"
			selection["route"] = nil
			selection["reason_code"] = "source_authorization_unproven"
			selection["sampled_at"] = json.Number("1795622400")

			connections := objectAt(t, doc, "terminal", "active_connections")
			connections["availability"] = "unavailable"
			connections["total"] = nil
			connections["sampled_at"] = json.Number("1795622400")
			byRoute := objectAt(t, doc, "terminal", "active_connections", "by_route")
			for _, token := range windowsTerminalTokens {
				byRoute[token] = nil
			}
		})
		if err := ValidateSnapshot(NodeClassWindowsTerminal, raw); err != nil {
			t.Fatalf("unavailable terminal snapshot rejected: %v", err)
		}
	})

	t.Run("partial", func(t *testing.T) {
		raw := mutateExample(t, terminalSnapshotExample, func(doc map[string]any) {
			selection := objectAt(t, doc, "terminal", "selection")
			selection["availability"] = "partial"
			selection["route"] = nil
			selection["reason_code"] = "controller_unreachable"

			connections := objectAt(t, doc, "terminal", "active_connections")
			connections["availability"] = "partial"
			connections["total"] = nil // at least one null is required for partial
		})
		if err := ValidateSnapshot(NodeClassWindowsTerminal, raw); err != nil {
			t.Fatalf("partial terminal snapshot rejected: %v", err)
		}
	})
}

func TestValidateSnapshotPlatformIsolation(t *testing.T) {
	t.Run("terminal on linux_vps", func(t *testing.T) {
		// host.os=linux keeps the class/host binding honest; the terminal
		// object alone must be the platform mismatch.
		raw := mutateExample(t, terminalSnapshotExample, func(doc map[string]any) {
			objectAt(t, doc, "host")["os"] = "linux"
		})
		err := ValidateSnapshot(NodeClassLinuxVPS, raw)
		requirePlatformMismatch(t, err)
		requireField(t, err, "terminal")
	})

	t.Run("linux_os_with_terminal_host_windows", func(t *testing.T) {
		requirePlatformMismatch(t, ValidateSnapshot(NodeClassLinuxVPS, readExample(t, terminalSnapshotExample)))
	})

	t.Run("missing terminal on windows_terminal", func(t *testing.T) {
		raw := mutateExample(t, terminalSnapshotExample, func(doc map[string]any) {
			delete(doc, "terminal")
		})
		err := ValidateSnapshot(NodeClassWindowsTerminal, raw)
		requirePlatformMismatch(t, err)
		requireField(t, err, "terminal")
	})

	t.Run("windows base data without terminal", func(t *testing.T) {
		// The rev-4 linux snapshot carries real base data, so a
		// windows_terminal node must be rejected even though the schema is
		// happy with the body shape.
		raw := mutateExample(t, linuxSnapshotExample, func(doc map[string]any) {
			objectAt(t, doc, "host")["os"] = "windows"
		})
		requirePlatformMismatch(t, ValidateSnapshot(NodeClassWindowsTerminal, raw))
	})

	t.Run("host os disagreement", func(t *testing.T) {
		raw := mutateExample(t, terminalSnapshotExample, func(doc map[string]any) {
			objectAt(t, doc, "host")["os"] = "linux"
		})
		err := ValidateSnapshot(NodeClassWindowsTerminal, raw)
		requirePlatformMismatch(t, err)
		requireField(t, err, "host.os")
	})

	t.Run("unknown node class", func(t *testing.T) {
		requireInvalidRequest(t, ValidateSnapshot("macos", readExample(t, terminalSnapshotExample)))
		requireInvalidRequest(t, ValidateSnapshot("", readExample(t, linuxSnapshotExample)))
	})
}

func TestValidateSnapshotWindowsBaseHonesty(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(doc map[string]any)
		field  string
	}{
		{
			name: "availability not unavailable",
			mutate: func(doc map[string]any) {
				objectAt(t, doc, "availability")["system"] = "ok"
			},
			field: "availability.system",
		},
		{
			name: "system field not null",
			mutate: func(doc map[string]any) {
				objectAt(t, doc, "system")["cpu_pct"] = json.Number("12.5")
			},
			field: "system.cpu_pct",
		},
		{
			name: "services not empty",
			mutate: func(doc map[string]any) {
				doc["services"] = []any{map[string]any{"name": "sing-box", "state": "active"}}
			},
			field: "services",
		},
		{
			name: "protocols not empty",
			mutate: func(doc map[string]any) {
				doc["protocols"] = []any{map[string]any{
					"kind": "reality", "inbound_tag": "vless-in", "state": "up",
					"reason": "ok", "observed_at": json.Number("1795622398"),
				}}
			},
			field: "protocols",
		},
		{
			name: "traffic not empty",
			mutate: func(doc map[string]any) {
				doc["traffic"] = []any{map[string]any{
					"scope": "protocol", "inbound_tag": "vless-in",
					"uplink_total_bytes": json.Number("1"), "downlink_total_bytes": json.Number("2"),
				}}
			},
			field: "traffic",
		},
		{
			name: "clients active not null",
			mutate: func(doc map[string]any) {
				objectAt(t, doc, "clients")["active"] = json.Number("0")
			},
			field: "clients.active",
		},
		{
			name: "clients tracked not null",
			mutate: func(doc map[string]any) {
				objectAt(t, doc, "clients")["tracked"] = json.Number("3")
			},
			field: "clients.tracked",
		},
		{
			name: "clients summaries not empty",
			mutate: func(doc map[string]any) {
				objectAt(t, doc, "clients")["summaries"] = []any{map[string]any{
					"device_ref":     strings.Repeat("A", 43),
					"active":         json.Number("1"),
					"uplink_bytes":   json.Number("10"),
					"downlink_bytes": json.Number("20"),
					"last_seen":      json.Number("1795622390"),
				}}
			},
			field: "clients.summaries",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			raw := mutateExample(t, terminalSnapshotExample, tc.mutate)
			err := ValidateSnapshot(NodeClassWindowsTerminal, raw)
			requirePlatformMismatch(t, err)
			requireField(t, err, tc.field)
		})
	}
}

func TestValidateSnapshotTerminalSemantics(t *testing.T) {
	t.Run("by-route sum mismatch", func(t *testing.T) {
		raw := readExample(t, "examples/negative/terminal-by-route-sum-mismatch.v1.json")
		err := ValidateSnapshot(NodeClassWindowsTerminal, raw)
		requireInvalidRequest(t, err)
		requireField(t, err, "terminal.active_connections.total")
	})

	t.Run("ok with null total", func(t *testing.T) {
		raw := mutateExample(t, terminalSnapshotExample, func(doc map[string]any) {
			objectAt(t, doc, "terminal", "active_connections")["total"] = nil
		})
		err := ValidateSnapshot(NodeClassWindowsTerminal, raw)
		requireInvalidRequest(t, err)
		requireField(t, err, "terminal.active_connections.total")
	})

	t.Run("ok with null route count", func(t *testing.T) {
		raw := mutateExample(t, terminalSnapshotExample, func(doc map[string]any) {
			objectAt(t, doc, "terminal", "active_connections", "by_route")["direct"] = nil
		})
		requireInvalidRequest(t, ValidateSnapshot(NodeClassWindowsTerminal, raw))
	})

	t.Run("selection ok with null route", func(t *testing.T) {
		raw := mutateExample(t, terminalSnapshotExample, func(doc map[string]any) {
			objectAt(t, doc, "terminal", "selection")["route"] = nil
		})
		err := ValidateSnapshot(NodeClassWindowsTerminal, raw)
		requireInvalidRequest(t, err)
		requireField(t, err, "terminal.selection.route")
	})

	t.Run("selection unavailable with non-null route", func(t *testing.T) {
		raw := mutateExample(t, terminalSnapshotExample, func(doc map[string]any) {
			selection := objectAt(t, doc, "terminal", "selection")
			selection["availability"] = "unavailable"
			selection["reason_code"] = "controller_unreachable"
		})
		requireInvalidRequest(t, ValidateSnapshot(NodeClassWindowsTerminal, raw))
	})

	t.Run("selection unavailable without reason_code", func(t *testing.T) {
		raw := mutateExample(t, terminalSnapshotExample, func(doc map[string]any) {
			selection := objectAt(t, doc, "terminal", "selection")
			selection["availability"] = "unavailable"
			selection["route"] = nil
			selection["reason_code"] = nil
		})
		requireInvalidRequest(t, ValidateSnapshot(NodeClassWindowsTerminal, raw))
	})

	t.Run("selection partial with both fields non-null", func(t *testing.T) {
		raw := mutateExample(t, terminalSnapshotExample, func(doc map[string]any) {
			selection := objectAt(t, doc, "terminal", "selection")
			selection["availability"] = "partial"
			selection["reason_code"] = "controller_unreachable"
		})
		requireInvalidRequest(t, ValidateSnapshot(NodeClassWindowsTerminal, raw))
	})

	t.Run("connections unavailable with non-null total", func(t *testing.T) {
		raw := mutateExample(t, terminalSnapshotExample, func(doc map[string]any) {
			objectAt(t, doc, "terminal", "active_connections")["availability"] = "unavailable"
		})
		requireInvalidRequest(t, ValidateSnapshot(NodeClassWindowsTerminal, raw))
	})

	t.Run("connections unavailable with non-null counts", func(t *testing.T) {
		raw := mutateExample(t, terminalSnapshotExample, func(doc map[string]any) {
			connections := objectAt(t, doc, "terminal", "active_connections")
			connections["availability"] = "unavailable"
			connections["total"] = nil
		})
		requireInvalidRequest(t, ValidateSnapshot(NodeClassWindowsTerminal, raw))
	})

	t.Run("connections partial with no null", func(t *testing.T) {
		raw := mutateExample(t, terminalSnapshotExample, func(doc map[string]any) {
			objectAt(t, doc, "terminal", "active_connections")["availability"] = "partial"
		})
		requireInvalidRequest(t, ValidateSnapshot(NodeClassWindowsTerminal, raw))
	})
}

func TestValidateSnapshotSamplingBounds(t *testing.T) {
	const collectedAt = 1795622400
	valid := []struct {
		name   string
		sample string
		value  int64
	}{
		{"selection at past bound", "selection", collectedAt - 300},
		{"selection at future bound", "selection", collectedAt + 60},
		{"connections at past bound", "active_connections", collectedAt - 300},
		{"connections at future bound", "active_connections", collectedAt + 60},
	}
	for _, tc := range valid {
		tc := tc
		t.Run("accepted/"+tc.name, func(t *testing.T) {
			raw := mutateExample(t, terminalSnapshotExample, func(doc map[string]any) {
				objectAt(t, doc, "terminal", tc.sample)["sampled_at"] = json.Number(jsonInt(tc.value))
			})
			if err := ValidateSnapshot(NodeClassWindowsTerminal, raw); err != nil {
				t.Fatalf("inclusive bound rejected: %v", err)
			}
		})
	}

	invalid := []struct {
		name   string
		sample string
		value  int64
	}{
		{"selection too old", "selection", collectedAt - 301},
		{"selection in future", "selection", collectedAt + 61},
		{"connections too old", "active_connections", collectedAt - 301},
		{"connections in future", "active_connections", collectedAt + 61},
	}
	for _, tc := range invalid {
		tc := tc
		t.Run("rejected/"+tc.name, func(t *testing.T) {
			raw := mutateExample(t, terminalSnapshotExample, func(doc map[string]any) {
				objectAt(t, doc, "terminal", tc.sample)["sampled_at"] = json.Number(jsonInt(tc.value))
			})
			err := ValidateSnapshot(NodeClassWindowsTerminal, raw)
			requireInvalidRequest(t, err)
			requireField(t, err, "terminal."+tc.sample+".sampled_at")
		})
	}
}

// jsonInt renders an int64 as a json.Number without exponent notation.
func jsonInt(value int64) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}

package contract

// Red-first regression tests for UM-B1 review item P1-06: runtime semantics that
// JSON Schema cannot express (strict JSON grammar, Linux availability ↔
// null/empty coherence, protocol state/reason coherence, metrics/events temporal
// bounds and event-id uniqueness, Windows system telemetry, terminal-source
// configuration, and path-aware privacy scanning).
//
// No test below prints a sentinel value: privacy assertions only inspect whether
// the error text echoes the planted value.

import (
	"encoding/json"
	"strings"
	"testing"
)

// -----------------------------------------------------------------------------
// Strict JSON grammar: duplicate object keys and trailing data.
// -----------------------------------------------------------------------------

func TestStrictJSONRejectsDuplicateObjectKeys(t *testing.T) {
	snapshotDuplicateTop := strings.Replace(
		string(readExample(t, linuxSnapshotExample)),
		`{"v":1,`, `{"v":1,"v":1,`, 1)
	snapshotDuplicateNested := strings.Replace(
		string(readExample(t, linuxSnapshotExample)),
		`"host":{"os":"linux",`, `"host":{"os":"linux","os":"linux",`, 1)
	metricsDuplicate := strings.Replace(
		string(readExample(t, linuxMetricsExample)),
		`{"v":1,`, `{"v":1,"v":1,`, 1)
	eventsDuplicate := strings.Replace(
		string(readExample(t, linuxEventsExample)),
		`{"v":1,`, `{"v":1,"v":1,`, 1)

	cases := []struct {
		name       string
		nodeClass  string
		reportType string
		body       []byte
	}{
		{"snapshot duplicate top-level key", NodeClassLinuxVPS, ReportTypeSnapshot, []byte(snapshotDuplicateTop)},
		{"snapshot duplicate nested key", NodeClassLinuxVPS, ReportTypeSnapshot, []byte(snapshotDuplicateNested)},
		{"metrics duplicate top-level key", NodeClassLinuxVPS, ReportTypeMetrics, []byte(metricsDuplicate)},
		{"events duplicate top-level key", NodeClassLinuxVPS, ReportTypeEvents, []byte(eventsDuplicate)},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateReportBody(tc.nodeClass, tc.reportType, tc.body)
			requireInvalidRequest(t, err)
			requireField(t, err, "body")
		})
	}

	// The same body through the direct snapshot entry point must be rejected.
	t.Run("snapshot direct validation", func(t *testing.T) {
		requireInvalidRequest(t, ValidateSnapshot(NodeClassLinuxVPS, []byte(snapshotDuplicateNested)))
	})
}

func TestStrictJSONRejectsTrailingData(t *testing.T) {
	linuxSnapshot := readExample(t, linuxSnapshotExample)
	cases := []struct {
		name       string
		nodeClass  string
		reportType string
		base       []byte
		trailing   string
	}{
		{"snapshot second JSON value", NodeClassLinuxVPS, ReportTypeSnapshot, linuxSnapshot, ` {}`},
		{"metrics garbage byte", NodeClassLinuxVPS, ReportTypeMetrics, readExample(t, linuxMetricsExample), `x`},
		{"events second JSON value", NodeClassLinuxVPS, ReportTypeEvents, readExample(t, linuxEventsExample), ` 0`},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			body := append(append([]byte{}, tc.base...), []byte(tc.trailing)...)
			err := ValidateReportBody(tc.nodeClass, tc.reportType, body)
			requireInvalidRequest(t, err)
			requireField(t, err, "body")
		})
	}
}

func TestStrictJSONAllowsTrailingWhitespace(t *testing.T) {
	cases := []struct {
		nodeClass  string
		reportType string
		rel        string
	}{
		{NodeClassLinuxVPS, ReportTypeSnapshot, linuxSnapshotExample},
		{NodeClassLinuxVPS, ReportTypeMetrics, linuxMetricsExample},
		{NodeClassLinuxVPS, ReportTypeEvents, linuxEventsExample},
	}
	for _, tc := range cases {
		body := append(append([]byte{}, readExample(t, tc.rel)...), []byte("\n\t  ")...)
		if err := ValidateReportBody(tc.nodeClass, tc.reportType, body); err != nil {
			t.Fatalf("%s with trailing whitespace rejected: %v", tc.reportType, err)
		}
	}
}

// -----------------------------------------------------------------------------
// Linux snapshot availability coherence.
// -----------------------------------------------------------------------------

func TestLinuxSnapshotAvailabilityCoherence(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(doc map[string]any)
		wantField string
	}{
		{
			name: "system ok with null field",
			mutate: func(doc map[string]any) {
				objectAt(t, doc, "system")["cpu_pct"] = nil
			},
			wantField: "system.cpu_pct",
		},
		{
			name: "system unavailable with non-null field",
			mutate: func(doc map[string]any) {
				objectAt(t, doc, "availability")["system"] = "unavailable"
			},
			wantField: "system.cpu_pct",
		},
		{
			name: "system partial without null field",
			mutate: func(doc map[string]any) {
				objectAt(t, doc, "availability")["system"] = "partial"
			},
			wantField: "system",
		},
		{
			name: "services ok with empty array",
			mutate: func(doc map[string]any) {
				doc["services"] = []any{}
			},
			wantField: "services",
		},
		{
			name: "services unavailable with non-empty array",
			mutate: func(doc map[string]any) {
				objectAt(t, doc, "availability")["services"] = "unavailable"
			},
			wantField: "services",
		},
		{
			name: "services partial without unknown state",
			mutate: func(doc map[string]any) {
				objectAt(t, doc, "availability")["services"] = "partial"
			},
			wantField: "services",
		},
		{
			name: "protocols ok with empty array",
			mutate: func(doc map[string]any) {
				objectAt(t, doc, "availability")["protocols"] = "ok"
				doc["protocols"] = []any{}
			},
			wantField: "protocols",
		},
		{
			name: "protocols unavailable with non-empty array",
			mutate: func(doc map[string]any) {
				objectAt(t, doc, "availability")["protocols"] = "unavailable"
			},
			wantField: "protocols",
		},
		{
			name: "protocols partial without unknown state",
			mutate: func(doc map[string]any) {
				protocols := doc["protocols"].([]any)
				second := protocols[1].(map[string]any)
				second["state"] = "down"
				second["reason"] = "timeout"
			},
			wantField: "protocols",
		},
		{
			name: "traffic ok with empty array",
			mutate: func(doc map[string]any) {
				doc["traffic"] = []any{}
			},
			wantField: "traffic",
		},
		{
			name: "traffic unavailable with non-empty array",
			mutate: func(doc map[string]any) {
				objectAt(t, doc, "availability")["traffic"] = "unavailable"
			},
			wantField: "traffic",
		},
		{
			name: "traffic partial without null counter",
			mutate: func(doc map[string]any) {
				objectAt(t, doc, "availability")["traffic"] = "partial"
			},
			wantField: "traffic",
		},
		{
			name: "traffic ok with null counter",
			mutate: func(doc map[string]any) {
				traffic := doc["traffic"].([]any)
				traffic[0].(map[string]any)["uplink_total_bytes"] = nil
			},
			wantField: "traffic[0].uplink_total_bytes",
		},
		{
			name: "clients ok with null active",
			mutate: func(doc map[string]any) {
				objectAt(t, doc, "availability")["clients"] = "ok"
			},
			wantField: "clients.active",
		},
		{
			name: "clients unavailable with non-null active",
			mutate: func(doc map[string]any) {
				objectAt(t, doc, "clients")["active"] = json.Number("0")
			},
			wantField: "clients.active",
		},
		{
			name: "clients partial with both counters non-null",
			mutate: func(doc map[string]any) {
				objectAt(t, doc, "availability")["clients"] = "partial"
				clients := objectAt(t, doc, "clients")
				clients["active"] = json.Number("0")
				clients["tracked"] = json.Number("0")
			},
			wantField: "clients",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			raw := mutateExample(t, linuxSnapshotExample, tc.mutate)
			err := ValidateSnapshot(NodeClassLinuxVPS, raw)
			requireInvalidRequest(t, err)
			requireField(t, err, tc.wantField)
		})
	}
}

func TestLinuxSnapshotAvailabilityCoherenceAcceptsHonestValues(t *testing.T) {
	t.Run("all unavailable with null and empty", func(t *testing.T) {
		raw := mutateExample(t, linuxSnapshotExample, func(doc map[string]any) {
			availability := objectAt(t, doc, "availability")
			availability["system"] = "unavailable"
			availability["services"] = "unavailable"
			availability["protocols"] = "unavailable"
			availability["traffic"] = "unavailable"
			availability["clients"] = "unavailable"
			for _, field := range systemFieldNames {
				objectAt(t, doc, "system")[field] = nil
			}
			doc["services"] = []any{}
			doc["protocols"] = []any{}
			doc["traffic"] = []any{}
			clients := objectAt(t, doc, "clients")
			clients["active"] = nil
			clients["tracked"] = nil
			clients["summaries"] = []any{}
		})
		if err := ValidateSnapshot(NodeClassLinuxVPS, raw); err != nil {
			t.Fatalf("honest unavailable snapshot rejected: %v", err)
		}
	})

	t.Run("system partial with one null", func(t *testing.T) {
		raw := mutateExample(t, linuxSnapshotExample, func(doc map[string]any) {
			objectAt(t, doc, "availability")["system"] = "partial"
			objectAt(t, doc, "system")["disk_used_bytes"] = nil
		})
		if err := ValidateSnapshot(NodeClassLinuxVPS, raw); err != nil {
			t.Fatalf("honest partial system rejected: %v", err)
		}
	})

	t.Run("services partial with unknown state", func(t *testing.T) {
		raw := mutateExample(t, linuxSnapshotExample, func(doc map[string]any) {
			objectAt(t, doc, "availability")["services"] = "partial"
			services := doc["services"].([]any)
			services[0].(map[string]any)["state"] = "unknown"
		})
		if err := ValidateSnapshot(NodeClassLinuxVPS, raw); err != nil {
			t.Fatalf("honest partial services rejected: %v", err)
		}
	})

	t.Run("traffic partial with null counter", func(t *testing.T) {
		raw := mutateExample(t, linuxSnapshotExample, func(doc map[string]any) {
			objectAt(t, doc, "availability")["traffic"] = "partial"
			traffic := doc["traffic"].([]any)
			traffic[0].(map[string]any)["downlink_total_bytes"] = nil
		})
		if err := ValidateSnapshot(NodeClassLinuxVPS, raw); err != nil {
			t.Fatalf("honest partial traffic rejected: %v", err)
		}
	})

	t.Run("clients partial with one null counter", func(t *testing.T) {
		raw := mutateExample(t, linuxSnapshotExample, func(doc map[string]any) {
			objectAt(t, doc, "availability")["clients"] = "partial"
			objectAt(t, doc, "clients")["tracked"] = json.Number("3")
		})
		if err := ValidateSnapshot(NodeClassLinuxVPS, raw); err != nil {
			t.Fatalf("honest partial clients rejected: %v", err)
		}
	})
}

func TestLinuxProtocolStateReasonCoherence(t *testing.T) {
	firstProtocol := func(doc map[string]any) map[string]any {
		return doc["protocols"].([]any)[0].(map[string]any)
	}
	cases := []struct {
		name       string
		mutate     func(doc map[string]any)
		wantField  string
		wantReject bool
	}{
		{
			name: "up requires ok reason",
			mutate: func(doc map[string]any) {
				firstProtocol(doc)["reason"] = "timeout"
			},
			wantReject: true,
			wantField:  "protocols[0].reason",
		},
		{
			name: "unknown requires source_unavailable or unknown reason",
			mutate: func(doc map[string]any) {
				protocol := firstProtocol(doc)
				protocol["state"] = "unknown"
				protocol["reason"] = "ok"
			},
			wantReject: true,
			wantField:  "protocols[0].reason",
		},
		{
			name: "down requires non-ok reason",
			mutate: func(doc map[string]any) {
				protocol := firstProtocol(doc)
				protocol["state"] = "down"
				protocol["reason"] = "ok"
			},
			wantReject: true,
			wantField:  "protocols[0].reason",
		},
		{
			name: "down with timeout reason is accepted",
			mutate: func(doc map[string]any) {
				protocol := firstProtocol(doc)
				protocol["state"] = "down"
				protocol["reason"] = "timeout"
			},
		},
		{
			name: "unknown with source_unavailable reason is accepted",
			mutate: func(doc map[string]any) {
				protocol := firstProtocol(doc)
				protocol["state"] = "unknown"
				protocol["reason"] = "source_unavailable"
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			raw := mutateExample(t, linuxSnapshotExample, tc.mutate)
			err := ValidateSnapshot(NodeClassLinuxVPS, raw)
			if !tc.wantReject {
				if err != nil {
					t.Fatalf("valid protocol state rejected: %v", err)
				}
				return
			}
			requireInvalidRequest(t, err)
			requireField(t, err, tc.wantField)
		})
	}
}

func TestLinuxProtocolObservedAtBounds(t *testing.T) {
	const collectedAt = 1795622400
	firstProtocolAt := func(doc map[string]any, at int64) {
		doc["protocols"].([]any)[0].(map[string]any)["observed_at"] = json.Number(jsonInt(at))
	}
	accepted := []int64{collectedAt - 900, collectedAt + 60}
	for _, at := range accepted {
		at := at
		t.Run("accepted/"+jsonInt(at), func(t *testing.T) {
			raw := mutateExample(t, linuxSnapshotExample, func(doc map[string]any) { firstProtocolAt(doc, at) })
			if err := ValidateSnapshot(NodeClassLinuxVPS, raw); err != nil {
				t.Fatalf("observed_at at inclusive bound rejected: %v", err)
			}
		})
	}
	rejected := []int64{collectedAt - 901, collectedAt + 61}
	for _, at := range rejected {
		at := at
		t.Run("rejected/"+jsonInt(at), func(t *testing.T) {
			raw := mutateExample(t, linuxSnapshotExample, func(doc map[string]any) { firstProtocolAt(doc, at) })
			err := ValidateSnapshot(NodeClassLinuxVPS, raw)
			requireInvalidRequest(t, err)
			requireField(t, err, "protocols[0].observed_at")
		})
	}
}

// -----------------------------------------------------------------------------
// Metrics/events temporal checks.
// -----------------------------------------------------------------------------

func TestMetricsTemporalSemantics(t *testing.T) {
	const collectedAt = 1795622400
	setSampleAt := func(index int, at int64) func(doc map[string]any) {
		return func(doc map[string]any) {
			doc["samples"].([]any)[index].(map[string]any)["at"] = json.Number(jsonInt(at))
		}
	}

	t.Run("sample not minute aligned", func(t *testing.T) {
		raw := mutateExample(t, linuxMetricsExample, setSampleAt(0, collectedAt-59))
		err := ValidateReportBody(NodeClassLinuxVPS, ReportTypeMetrics, raw)
		requireInvalidRequest(t, err)
		requireField(t, err, "samples[0].at")
	})

	t.Run("samples not strictly increasing", func(t *testing.T) {
		raw := mutateExample(t, linuxMetricsExample, setSampleAt(1, collectedAt-60))
		err := ValidateReportBody(NodeClassLinuxVPS, ReportTypeMetrics, raw)
		requireInvalidRequest(t, err)
		requireField(t, err, "samples[1].at")
	})

	t.Run("duplicate sample times", func(t *testing.T) {
		raw := mutateExample(t, linuxMetricsExample, setSampleAt(1, collectedAt-60))
		err := ValidateReportBody(NodeClassLinuxVPS, ReportTypeMetrics, raw)
		requireInvalidRequest(t, err)
		requireField(t, err, "samples[1].at")
	})

	t.Run("sample before window", func(t *testing.T) {
		raw := mutateExample(t, linuxMetricsExample, setSampleAt(0, collectedAt-660))
		err := ValidateReportBody(NodeClassLinuxVPS, ReportTypeMetrics, raw)
		requireInvalidRequest(t, err)
		requireField(t, err, "samples[0].at")
	})

	t.Run("sample after window", func(t *testing.T) {
		raw := mutateExample(t, linuxMetricsExample, setSampleAt(1, collectedAt+120))
		err := ValidateReportBody(NodeClassLinuxVPS, ReportTypeMetrics, raw)
		requireInvalidRequest(t, err)
		requireField(t, err, "samples[1].at")
	})

	t.Run("inclusive window bounds accepted", func(t *testing.T) {
		raw := mutateExample(t, linuxMetricsExample, func(doc map[string]any) {
			samples := doc["samples"].([]any)
			samples[0].(map[string]any)["at"] = json.Number(jsonInt(collectedAt - 600))
			samples[1].(map[string]any)["at"] = json.Number(jsonInt(collectedAt + 60))
		})
		if err := ValidateReportBody(NodeClassLinuxVPS, ReportTypeMetrics, raw); err != nil {
			t.Fatalf("inclusive sample bounds rejected: %v", err)
		}
	})
}

func TestEventsTemporalAndDuplicateIDs(t *testing.T) {
	const collectedAt = 1795622400
	setEventAt := func(index int, at int64) func(doc map[string]any) {
		return func(doc map[string]any) {
			doc["events"].([]any)[index].(map[string]any)["at"] = json.Number(jsonInt(at))
		}
	}

	t.Run("event before window", func(t *testing.T) {
		raw := mutateExample(t, linuxEventsExample, setEventAt(0, collectedAt-3601))
		err := ValidateReportBody(NodeClassLinuxVPS, ReportTypeEvents, raw)
		requireInvalidRequest(t, err)
		requireField(t, err, "events[0].at")
	})

	t.Run("event after window", func(t *testing.T) {
		raw := mutateExample(t, linuxEventsExample, setEventAt(0, collectedAt+61))
		err := ValidateReportBody(NodeClassLinuxVPS, ReportTypeEvents, raw)
		requireInvalidRequest(t, err)
		requireField(t, err, "events[0].at")
	})

	t.Run("inclusive event bounds accepted", func(t *testing.T) {
		raw := mutateExample(t, linuxEventsExample, func(doc map[string]any) {
			events := doc["events"].([]any)
			events[0].(map[string]any)["at"] = json.Number(jsonInt(collectedAt - 3600))
			events[1].(map[string]any)["at"] = json.Number(jsonInt(collectedAt + 60))
		})
		if err := ValidateReportBody(NodeClassLinuxVPS, ReportTypeEvents, raw); err != nil {
			t.Fatalf("inclusive event bounds rejected: %v", err)
		}
	})

	t.Run("duplicate event id within one body", func(t *testing.T) {
		raw := mutateExample(t, linuxEventsExample, func(doc map[string]any) {
			events := doc["events"].([]any)
			first := events[0].(map[string]any)["event_id"]
			events[1].(map[string]any)["event_id"] = first
		})
		err := ValidateReportBody(NodeClassLinuxVPS, ReportTypeEvents, raw)
		requireInvalidRequest(t, err)
		requireField(t, err, "events[1].event_id")
		if strings.Contains(err.Error(), "6d1a9b3e-7c2f-4e8a-a5b0-9c3d1e7f2a64") {
			t.Fatalf("duplicate event id error echoes the identifier: %v", err)
		}
	})
}

// -----------------------------------------------------------------------------
// Windows system telemetry and terminal-source configuration.
// -----------------------------------------------------------------------------

func windowsWithoutTerminal(t *testing.T) []byte {
	t.Helper()
	return mutateExample(t, terminalSnapshotExample, func(doc map[string]any) {
		delete(doc, "terminal")
	})
}

func windowsSystemValues(system map[string]any) {
	system["cpu_pct"] = 12.5
	system["load1"] = 0.42
	system["mem_total_bytes"] = json.Number("4294967296")
	system["mem_used_bytes"] = json.Number("1610612736")
	system["disk_total_bytes"] = json.Number("42949672960")
	system["disk_used_bytes"] = json.Number("10737418240")
	system["net_rx_bytes"] = json.Number("123456789")
	system["net_tx_bytes"] = json.Number("987654321")
}

func TestWindowsSystemTelemetrySemantics(t *testing.T) {
	unconfigured := ValidateOptions{TerminalConfigured: false}

	t.Run("system ok with full values accepted", func(t *testing.T) {
		raw := mutateExample(t, terminalSnapshotExample, func(doc map[string]any) {
			delete(doc, "terminal")
			objectAt(t, doc, "availability")["system"] = "ok"
			windowsSystemValues(objectAt(t, doc, "system"))
		})
		if err := ValidateSnapshotWithOptions(NodeClassWindowsTerminal, raw, unconfigured); err != nil {
			t.Fatalf("windows system ok rejected: %v", err)
		}
	})

	t.Run("system partial with one null accepted", func(t *testing.T) {
		raw := mutateExample(t, terminalSnapshotExample, func(doc map[string]any) {
			delete(doc, "terminal")
			objectAt(t, doc, "availability")["system"] = "partial"
			system := objectAt(t, doc, "system")
			windowsSystemValues(system)
			system["disk_used_bytes"] = nil
		})
		if err := ValidateSnapshotWithOptions(NodeClassWindowsTerminal, raw, unconfigured); err != nil {
			t.Fatalf("windows system partial rejected: %v", err)
		}
	})

	t.Run("system ok with null field rejected", func(t *testing.T) {
		raw := mutateExample(t, terminalSnapshotExample, func(doc map[string]any) {
			delete(doc, "terminal")
			objectAt(t, doc, "availability")["system"] = "ok"
		})
		err := ValidateSnapshotWithOptions(NodeClassWindowsTerminal, raw, unconfigured)
		requireInvalidRequest(t, err)
		requireField(t, err, "system.cpu_pct")
	})

	t.Run("system unavailable with value rejected", func(t *testing.T) {
		raw := mutateExample(t, terminalSnapshotExample, func(doc map[string]any) {
			delete(doc, "terminal")
			objectAt(t, doc, "system")["cpu_pct"] = 12.5
		})
		err := ValidateSnapshotWithOptions(NodeClassWindowsTerminal, raw, unconfigured)
		requireInvalidRequest(t, err)
		requireField(t, err, "system.cpu_pct")
	})

	t.Run("system partial without null rejected", func(t *testing.T) {
		raw := mutateExample(t, terminalSnapshotExample, func(doc map[string]any) {
			delete(doc, "terminal")
			objectAt(t, doc, "availability")["system"] = "partial"
			windowsSystemValues(objectAt(t, doc, "system"))
		})
		err := ValidateSnapshotWithOptions(NodeClassWindowsTerminal, raw, unconfigured)
		requireInvalidRequest(t, err)
		requireField(t, err, "system")
	})

	t.Run("system ok with terminal telemetry accepted by default", func(t *testing.T) {
		raw := mutateExample(t, terminalSnapshotExample, func(doc map[string]any) {
			objectAt(t, doc, "availability")["system"] = "ok"
			windowsSystemValues(objectAt(t, doc, "system"))
		})
		if err := ValidateSnapshot(NodeClassWindowsTerminal, raw); err != nil {
			t.Fatalf("windows system ok with terminal rejected: %v", err)
		}
	})

	t.Run("services availability must stay unavailable", func(t *testing.T) {
		raw := mutateExample(t, terminalSnapshotExample, func(doc map[string]any) {
			delete(doc, "terminal")
			objectAt(t, doc, "availability")["services"] = "ok"
		})
		err := ValidateSnapshotWithOptions(NodeClassWindowsTerminal, raw, unconfigured)
		requirePlatformMismatch(t, err)
		requireField(t, err, "availability.services")
	})

	t.Run("clients counters must stay null", func(t *testing.T) {
		raw := mutateExample(t, terminalSnapshotExample, func(doc map[string]any) {
			delete(doc, "terminal")
			objectAt(t, doc, "clients")["active"] = json.Number("0")
		})
		err := ValidateSnapshotWithOptions(NodeClassWindowsTerminal, raw, unconfigured)
		requirePlatformMismatch(t, err)
		requireField(t, err, "clients.active")
	})
}

func TestTerminalConfiguredOption(t *testing.T) {
	withTerminal := readExample(t, terminalSnapshotExample)
	withoutTerminal := windowsWithoutTerminal(t)

	t.Run("default requires terminal", func(t *testing.T) {
		requirePlatformMismatch(t, ValidateSnapshot(NodeClassWindowsTerminal, withoutTerminal))
		if err := ValidateSnapshot(NodeClassWindowsTerminal, withTerminal); err != nil {
			t.Fatalf("default wrapper rejected a configured terminal snapshot: %v", err)
		}
	})

	t.Run("configured false rejects terminal object", func(t *testing.T) {
		err := ValidateSnapshotWithOptions(NodeClassWindowsTerminal, withTerminal,
			ValidateOptions{TerminalConfigured: false})
		requirePlatformMismatch(t, err)
		requireField(t, err, "terminal")
	})

	t.Run("configured false accepts absent terminal", func(t *testing.T) {
		if err := ValidateSnapshotWithOptions(NodeClassWindowsTerminal, withoutTerminal,
			ValidateOptions{TerminalConfigured: false}); err != nil {
			t.Fatalf("configured=false rejected a valid terminal-free snapshot: %v", err)
		}
	})

	t.Run("configured true equals default", func(t *testing.T) {
		if err := ValidateSnapshotWithOptions(NodeClassWindowsTerminal, withTerminal,
			ValidateOptions{TerminalConfigured: true}); err != nil {
			t.Fatalf("configured=true rejected a valid terminal snapshot: %v", err)
		}
		requirePlatformMismatch(t, ValidateSnapshotWithOptions(NodeClassWindowsTerminal,
			withoutTerminal, ValidateOptions{TerminalConfigured: true}))
	})

	t.Run("linux forbids terminal regardless of option", func(t *testing.T) {
		linuxWithTerminal := mutateExample(t, terminalSnapshotExample, func(doc map[string]any) {
			objectAt(t, doc, "host")["os"] = "linux"
		})
		requirePlatformMismatch(t, ValidateSnapshotWithOptions(NodeClassLinuxVPS,
			linuxWithTerminal, ValidateOptions{TerminalConfigured: false}))
		requirePlatformMismatch(t, ValidateSnapshot(NodeClassLinuxVPS, linuxWithTerminal))
	})

	t.Run("report body options threading", func(t *testing.T) {
		if err := ValidateReportBodyWithOptions(NodeClassWindowsTerminal, ReportTypeSnapshot,
			withoutTerminal, ValidateOptions{TerminalConfigured: false}); err != nil {
			t.Fatalf("ValidateReportBodyWithOptions rejected terminal-free snapshot: %v", err)
		}
		requirePlatformMismatch(t, ValidateReportBodyWithOptions(NodeClassWindowsTerminal,
			ReportTypeSnapshot, withTerminal, ValidateOptions{TerminalConfigured: false}))
		if err := ValidateReportBodyWithOptions(NodeClassLinuxVPS, ReportTypeSnapshot,
			readExample(t, linuxSnapshotExample), ValidateOptions{TerminalConfigured: true}); err != nil {
			t.Fatalf("ValidateReportBodyWithOptions rejected the linux snapshot: %v", err)
		}
	})
}

// -----------------------------------------------------------------------------
// Path-aware privacy scanning.
// -----------------------------------------------------------------------------

func TestPrivacyPathAllowlistKeepsLegalIdentifiers(t *testing.T) {
	t.Run("full report documents scan clean", func(t *testing.T) {
		// report_id and event_id UUIDs are contract-defined identities, not
		// privacy sentinels; counter_epoch is a contract-defined 32-hex value.
		for _, rel := range []string{
			linuxSnapshotExample,
			terminalSnapshotExample,
			linuxMetricsExample,
			linuxEventsExample,
		} {
			doc := decodeJSONObject(t, readExample(t, rel))
			if err := scanPrivacy(doc, ""); err != nil {
				t.Fatalf("%s rejected by the privacy scanner: %v", rel, err)
			}
		}
	})

	t.Run("legal identifiers accepted through validation", func(t *testing.T) {
		for _, tc := range []struct {
			reportType string
			rel        string
		}{
			{ReportTypeSnapshot, linuxSnapshotExample},
			{ReportTypeMetrics, linuxMetricsExample},
			{ReportTypeEvents, linuxEventsExample},
		} {
			if err := ValidateReportBody(NodeClassLinuxVPS, tc.reportType,
				readExample(t, tc.rel)); err != nil {
				t.Fatalf("%s with legal UUID identities rejected: %v", tc.reportType, err)
			}
		}
	})

	t.Run("device_ref is not a credential", func(t *testing.T) {
		deviceRef := strings.Repeat("Ab3", 14) + "Z" // 43 base64url chars incl. digits
		if len(deviceRef) != 43 {
			t.Fatalf("test setup: device_ref length %d", len(deviceRef))
		}
		raw := mutateExample(t, linuxSnapshotExample, func(doc map[string]any) {
			objectAt(t, doc, "availability")["clients"] = "ok"
			clients := objectAt(t, doc, "clients")
			clients["active"] = json.Number("1")
			clients["tracked"] = json.Number("1")
			clients["summaries"] = []any{map[string]any{
				"device_ref":     deviceRef,
				"active":         json.Number("1"),
				"uplink_bytes":   json.Number("10"),
				"downlink_bytes": json.Number("20"),
				"last_seen":      json.Number("1795622390"),
			}}
		})
		if err := ValidateSnapshot(NodeClassLinuxVPS, raw); err != nil {
			t.Fatalf("legal device_ref rejected: %v", err)
		}
	})
}

func TestPrivacyRejectsCredentialsInNonTerminalReportFields(t *testing.T) {
	const ipSentinel = "10.0.0.1"
	const uuidSentinel = "550e8400-e29b-41d4-a716-446655440000"

	t.Run("snapshot host kernel ipv4", func(t *testing.T) {
		raw := mutateExample(t, linuxSnapshotExample, func(doc map[string]any) {
			objectAt(t, doc, "host")["kernel"] = ipSentinel
		})
		err := ValidateSnapshot(NodeClassLinuxVPS, raw)
		requireInvalidRequest(t, err)
		requireField(t, err, "host.kernel")
		if strings.Contains(err.Error(), ipSentinel) {
			t.Fatalf("privacy error echoes the sentinel: %v", err)
		}
	})

	t.Run("snapshot host kernel uuid", func(t *testing.T) {
		raw := mutateExample(t, linuxSnapshotExample, func(doc map[string]any) {
			objectAt(t, doc, "host")["kernel"] = uuidSentinel
		})
		err := ValidateSnapshot(NodeClassLinuxVPS, raw)
		requireInvalidRequest(t, err)
		requireField(t, err, "host.kernel")
		if strings.Contains(err.Error(), uuidSentinel) {
			t.Fatalf("privacy error echoes the sentinel: %v", err)
		}
	})

	t.Run("events detail inbound tag ipv4", func(t *testing.T) {
		raw := mutateExample(t, linuxEventsExample, func(doc map[string]any) {
			event := doc["events"].([]any)[0].(map[string]any)
			event["detail"].(map[string]any)["inbound_tag"] = ipSentinel
		})
		err := ValidateReportBody(NodeClassLinuxVPS, ReportTypeEvents, raw)
		requireInvalidRequest(t, err)
		requireField(t, err, "events[0].detail.inbound_tag")
		if strings.Contains(err.Error(), ipSentinel) {
			t.Fatalf("privacy error echoes the sentinel: %v", err)
		}
	})
}

func TestPrivacyMarkerCoverage(t *testing.T) {
	markers := []string{
		"proxies:\n  - name: vps-a",
		"mixed-port: 7890",
		"external-controller: loopback",
		"password: hunter2",
		"password=hunter2",
		"secret: s3cr3t",
		"secret=s3cr3t",
		"token=abcdef",
		"-----BEGIN OPENSSH PRIVATE KEY-----",
	}
	for _, value := range markers {
		if kind := privacySentinelKind(value); kind == "" {
			t.Errorf("privacySentinelKind(%q) = \"\", want a sentinel category", value)
		}
	}
}

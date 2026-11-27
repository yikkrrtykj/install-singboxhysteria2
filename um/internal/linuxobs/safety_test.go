package linuxobs

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoExecRootOrWriteSurface is the static least-privilege proof for this
// package: the non-test sources contain no os/exec, no privilege-changing
// syscall, no write/create/remove API and no listening socket. Combined with
// TestDefaultProbesReportUnavailable this pins the "never exec, never write,
// never root" requirement at the source level.
func TestNoExecRootOrWriteSurface(t *testing.T) {
	forbidden := []string{
		// Process execution.
		"os/exec", "exec.Command", "exec.CommandContext",
		"syscall.Exec", "syscall.ForkExec", "syscall.StartProcess",
		// Privilege changes.
		"syscall.Setuid", "syscall.Setgid", "syscall.Seteuid", "syscall.Setegid",
		"Setuid(", "Setgid(", "Geteuid", "Getegid",
		// File writes / mutations.
		"os.WriteFile", "os.Create", "os.OpenFile", "os.Mkdir", "os.Remove",
		"os.Rename", "os.Chmod", "os.Chown", "os.Truncate", "ioutil.WriteFile",
		// Listening sockets.
		"net.Listen", "ListenAndServe",
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	scanned := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		scanned++
		for _, token := range forbidden {
			if bytes.Contains(source, []byte(token)) {
				t.Errorf("%s contains forbidden least-privilege token %q", name, token)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("static least-privilege scan found no package sources")
	}
}

// TestPrivacySentinelsNeverLeak plants credential/IP/secret sentinels in file
// content the collector is allowed to read but must never project, then
// asserts the frozen contract's own privacy scan accepts the bodies and the
// sentinels are absent from every report kind.
func TestPrivacySentinelsNeverLeak(t *testing.T) {
	requireSupportedArch(t)
	const (
		secretSentinel = "SECRET-SENTINEL-hunter2"
		ipSentinel     = "203.0.113.9"
		hostSentinel   = "private.example"
		saltSentinel   = "SALT-SENTINEL-AAAAAAAAAAAAAAAAAAAAAAAAAAA"
	)

	files := fakeProcFiles()
	// The comm field is parsed only for the starttime field; its text must
	// never be emitted.
	files["self/stat"] = "1234 (um-agent token=" + secretSentinel + ") S 1 1234 1234 0 -1 4194560 100 0 0 0 5 6 0 0 20 0 1 0 500 0 0 0 0 0 0 0 0 0 0 0\n"
	// Interface names and unrelated meminfo keys are ignored by the parsers.
	files["net/dev"] = "Inter-|   Receive |  Transmit\n" +
		" face |bytes ...\n" +
		" " + hostSentinel + ": " + ipSentinel + " 0 0 0 0 0 0 0 7 0 0 0 0 0 0 0\n" +
		"  eth0: 123456789 0 0 0 0 0 0 0 987654321 0 0 0 0 0 0 0\n"
	files["meminfo"] = fakeProcMemInfo + "Password: " + ipSentinel + " kB\n"

	service := &fakeServiceProbe{observation: ServiceObservation{SingBox: ServiceActive}}
	singbox := &fakeSingBoxProbe{observation: SingBoxObservation{Inbounds: map[string]InboundEvidence{
		"vless-in": {ActiveConnections: 1, UplinkBytes: 10, DownlinkBytes: 20},
		// A rogue observed tag is not in the center allowlist and must not be
		// projected even when it looks like an address.
		ipSentinel: {ActiveConnections: 1, UplinkBytes: 1, DownlinkBytes: 1},
	}}}
	collector := &Collector{
		ProcRoot:                writeTree(t, files),
		AgentVersion:            "1.2.3",
		DiskProbe:               &fakeDiskProbe{total: 42949672960, used: 10737418240},
		ServiceProbe:            service,
		SingBoxProbe:            singbox,
		SingBoxSourceAuthorized: true,
	}
	rc := reportContext([]string{"system", "services", "singbox_api", "events"}, testExpectedTags())
	rc.Config.DeviceSalt = saltSentinel

	bodies := map[string][]byte{}
	snapshotRaw, err := collector.Snapshot(context.Background(), rc)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	validateSnapshotBody(t, snapshotRaw)
	bodies["snapshot"] = snapshotRaw
	metricsRaw, err := collector.Metrics(context.Background(), rc)
	if err != nil {
		t.Fatalf("Metrics: %v", err)
	}
	validateMetricsBody(t, metricsRaw)
	bodies["metrics"] = metricsRaw
	eventsRaw, err := collector.Events(context.Background(), rc)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	validateEventsBody(t, eventsRaw)
	bodies["events"] = eventsRaw

	for name, raw := range bodies {
		text := string(raw)
		for _, sentinel := range []string{secretSentinel, ipSentinel, hostSentinel, saltSentinel, "Password:", "password: "} {
			if strings.Contains(text, sentinel) {
				t.Fatalf("%s leaked privacy sentinel %q", name, sentinel)
			}
		}
		if strings.Contains(text, filepath.ToSlash(collector.ProcRoot)) {
			t.Fatalf("%s leaked the local procfs path", name)
		}
	}
}

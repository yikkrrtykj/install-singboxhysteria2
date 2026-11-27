package linuxobs

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// The synthetic unit path PID 1 is expected to return for sing-box.service:
// systemd escapes the '-' and '.' as _2d/_2e and places unit objects below
// /org/freedesktop/systemd1/unit/.
const fakeSingBoxUnitPath = systemdUnitPathPrefix + "sing_2dbox_2eservice"

// Compile-time assertions for the closed surfaces this file pins.
var (
	_ DBusProbe      = (*SystemdDBusProbe)(nil)
	_ io.Closer      = (*SystemdDBusProbe)(nil)
	_ dbusUnitReader = (*fakeDBusUnitReader)(nil)
)

// dbusReadCall is one wire-level read observation recorded by the fake reader.
// It records the D-Bus interface, member, object path and string arguments so a
// test can assert the complete call tuple, not just that "something" was called.
type dbusReadCall struct {
	Interface string
	Member    string
	Path      string
	Args      []string
}

// fakeDBusUnitReader is the synthetic dbusUnitReader behind the probe. It has
// exactly the three seam methods and records every read call; there is no write
// or lifecycle method to call.
type fakeDBusUnitReader struct {
	mu       sync.Mutex
	calls    []dbusReadCall
	closes   int
	unitPath string
	state    string
	unitErr  error
	stateErr error
	closeErr error
	block    bool
}

func (reader *fakeDBusUnitReader) record(call dbusReadCall) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	reader.calls = append(reader.calls, call)
}

// Calls returns a copy of the recorded read calls.
func (reader *fakeDBusUnitReader) Calls() []dbusReadCall {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return append([]dbusReadCall(nil), reader.calls...)
}

// Closes returns how many times Close was called.
func (reader *fakeDBusUnitReader) Closes() int {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return reader.closes
}

func (reader *fakeDBusUnitReader) GetUnit(ctx context.Context, unit string) (string, error) {
	reader.record(dbusReadCall{
		Interface: systemdManagerInterface,
		Member:    getUnitMember,
		Path:      systemdManagerPath,
		Args:      []string{unit},
	})
	if reader.block {
		<-ctx.Done()
		return "", ctx.Err()
	}
	if reader.unitErr != nil {
		return "", reader.unitErr
	}
	return reader.unitPath, nil
}

func (reader *fakeDBusUnitReader) GetActiveState(ctx context.Context, unitPath string) (string, error) {
	reader.record(dbusReadCall{
		Interface: propertiesInterface,
		Member:    propertiesGetMember,
		Path:      unitPath,
		Args:      []string{systemdUnitInterface, activeStateProperty},
	})
	if reader.block {
		<-ctx.Done()
		return "", ctx.Err()
	}
	if reader.stateErr != nil {
		return "", reader.stateErr
	}
	return reader.state, nil
}

func (reader *fakeDBusUnitReader) Close() error {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	reader.closes++
	return reader.closeErr
}

// newFakeSingBoxReader returns a fake reader that resolves sing-box.service to
// the synthetic unit path and reports state.
func newFakeSingBoxReader(state string) *fakeDBusUnitReader {
	return &fakeDBusUnitReader{unitPath: fakeSingBoxUnitPath, state: state}
}

// TestSystemdDBusProbeIssuesExactlyTheTwoReadOnlyCalls is the wire-level proof
// for the frozen contract: one Manager.GetUnit on the fixed Manager path for the
// allowlisted unit, then one Properties.Get on the returned unit path for
// org.freedesktop.systemd1.Unit.ActiveState, and nothing else.
func TestSystemdDBusProbeIssuesExactlyTheTwoReadOnlyCalls(t *testing.T) {
	reader := newFakeSingBoxReader("active")
	probe := newSystemdDBusProbe(reader)

	state, err := probe.ActiveState(context.Background(), singBoxUnitName)
	if err != nil {
		t.Fatalf("ActiveState: %v", err)
	}
	if state != "active" {
		t.Fatalf("ActiveState = %q, want %q", state, "active")
	}

	wantCalls := []dbusReadCall{
		{
			Interface: systemdManagerInterface,
			Member:    getUnitMember,
			Path:      systemdManagerPath,
			Args:      []string{singBoxUnitName},
		},
		{
			Interface: propertiesInterface,
			Member:    propertiesGetMember,
			Path:      fakeSingBoxUnitPath,
			Args:      []string{systemdUnitInterface, activeStateProperty},
		},
	}
	if gotCalls := reader.Calls(); !reflect.DeepEqual(gotCalls, wantCalls) {
		t.Fatalf("D-Bus calls = %#v, want exactly %#v", gotCalls, wantCalls)
	}
}

// TestSystemdDBusProbeRejectsEveryOtherUnitWithoutEchoing pins the allowlist at
// the probe boundary: no other unit name may reach the bus, and the rejected
// name must not be echoed in the error.
func TestSystemdDBusProbeRejectsEveryOtherUnitWithoutEchoing(t *testing.T) {
	units := []string{
		"",
		"sing-box",
		"sshd.service",
		"sing-box.service ",
		"SING-BOX.SERVICE",
		"sing-box.service@instance",
	}
	for _, unit := range units {
		reader := newFakeSingBoxReader("active")
		probe := newSystemdDBusProbe(reader)
		_, err := probe.ActiveState(context.Background(), unit)
		if !errors.Is(err, ErrProbeUnavailable) {
			t.Fatalf("unit %q: error = %v, want ErrProbeUnavailable", unit, err)
		}
		var probeErr *systemdProbeError
		if !errors.As(err, &probeErr) || probeErr.stage != systemdStageUnitNotAllowed {
			t.Fatalf("unit %q: stage = %v, want %q", unit, probeErr, systemdStageUnitNotAllowed)
		}
		if calls := reader.Calls(); len(calls) != 0 {
			t.Fatalf("unit %q reached the bus: %#v", unit, calls)
		}
		if unit != "" && strings.Contains(err.Error(), unit) {
			t.Fatalf("error echoes rejected unit %q: %v", unit, err)
		}
	}
}

// TestSystemdDBusProbeMapsFailuresToClosedUnavailable pins every failure path on
// the closed, non-echoing ErrProbeUnavailable error. A failed observation must
// never degrade into a fabricated state, and remote error text must never leak.
func TestSystemdDBusProbeMapsFailuresToClosedUnavailable(t *testing.T) {
	const remoteSentinel = "DBUS-REMOTE-ERROR-SENTINEL"
	cases := []struct {
		name      string
		reader    *fakeDBusUnitReader
		wantStage string
		wantCalls int
	}{
		{
			name:      "get_unit_error",
			reader:    &fakeDBusUnitReader{unitErr: errors.New(remoteSentinel)},
			wantStage: systemdStageGetUnit,
			wantCalls: 1,
		},
		{
			name:      "get_active_state_error",
			reader:    &fakeDBusUnitReader{unitPath: fakeSingBoxUnitPath, stateErr: errors.New(remoteSentinel)},
			wantStage: systemdStageActiveState,
			wantCalls: 2,
		},
		{
			name:      "unit_path_outside_systemd_unit_tree",
			reader:    &fakeDBusUnitReader{unitPath: "/org/freedesktop/UDISKS2"},
			wantStage: systemdStageInvalidUnitPath,
			wantCalls: 1,
		},
		{
			name:      "unit_path_not_absolute",
			reader:    &fakeDBusUnitReader{unitPath: "org/freedesktop/systemd1/unit/foo"},
			wantStage: systemdStageInvalidUnitPath,
			wantCalls: 1,
		},
		{
			name:      "unit_path_with_illegal_characters",
			reader:    &fakeDBusUnitReader{unitPath: fakeSingBoxUnitPath + "not a path"},
			wantStage: systemdStageInvalidUnitPath,
			wantCalls: 1,
		},
		{
			name:      "unit_path_is_the_bare_prefix",
			reader:    &fakeDBusUnitReader{unitPath: systemdUnitPathPrefix},
			wantStage: systemdStageInvalidUnitPath,
			wantCalls: 1,
		},
		{
			name:      "unit_path_empty",
			reader:    &fakeDBusUnitReader{},
			wantStage: systemdStageInvalidUnitPath,
			wantCalls: 1,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			probe := newSystemdDBusProbe(testCase.reader)
			_, err := probe.ActiveState(context.Background(), singBoxUnitName)
			if !errors.Is(err, ErrProbeUnavailable) {
				t.Fatalf("error = %v, want ErrProbeUnavailable", err)
			}
			var probeErr *systemdProbeError
			if !errors.As(err, &probeErr) {
				t.Fatalf("error %v is not a *systemdProbeError", err)
			}
			if probeErr.stage != testCase.wantStage {
				t.Fatalf("stage = %q, want %q", probeErr.stage, testCase.wantStage)
			}
			if strings.Contains(err.Error(), remoteSentinel) {
				t.Fatalf("error echoes the remote D-Bus text: %v", err)
			}
			if calls := testCase.reader.Calls(); len(calls) != testCase.wantCalls {
				t.Fatalf("recorded %d calls, want %d: %#v", len(calls), testCase.wantCalls, calls)
			}
		})
	}

	t.Run("zero_value_probe", func(t *testing.T) {
		var probe SystemdDBusProbe
		_, err := probe.ActiveState(context.Background(), singBoxUnitName)
		if !errors.Is(err, ErrProbeUnavailable) {
			t.Fatalf("zero-value probe error = %v, want ErrProbeUnavailable", err)
		}
		var probeErr *systemdProbeError
		if !errors.As(err, &probeErr) || probeErr.stage != systemdStageNotConnected {
			t.Fatalf("zero-value probe stage = %v, want %q", probeErr, systemdStageNotConnected)
		}
	})

	t.Run("nil_probe", func(t *testing.T) {
		var probe *SystemdDBusProbe
		_, err := probe.ActiveState(context.Background(), singBoxUnitName)
		if !errors.Is(err, ErrProbeUnavailable) {
			t.Fatalf("nil probe error = %v, want ErrProbeUnavailable", err)
		}
	})

	t.Run("nil_context", func(t *testing.T) {
		reader := newFakeSingBoxReader("active")
		probe := newSystemdDBusProbe(reader)
		_, err := probe.ActiveState(nil, singBoxUnitName)
		if !errors.Is(err, ErrProbeUnavailable) {
			t.Fatalf("nil context error = %v, want ErrProbeUnavailable", err)
		}
		var probeErr *systemdProbeError
		if !errors.As(err, &probeErr) || probeErr.stage != systemdStageContext {
			t.Fatalf("nil context stage = %v, want %q", probeErr, systemdStageContext)
		}
		if calls := reader.Calls(); len(calls) != 0 {
			t.Fatalf("nil context reached the bus: %#v", calls)
		}
	})
}

// TestSystemdDBusProbeHonoursContextTimeoutAndCancellation proves a wedged call
// cannot stall collection: the caller's cancellation and the probe's own
// no-deadline cap both return promptly and honestly as unavailable.
func TestSystemdDBusProbeHonoursContextTimeoutAndCancellation(t *testing.T) {
	t.Run("internal_timeout_without_caller_deadline", func(t *testing.T) {
		reader := &fakeDBusUnitReader{block: true}
		probe := newSystemdDBusProbe(reader)
		probe.timeout = 25 * time.Millisecond
		started := time.Now()
		_, err := probe.ActiveState(context.Background(), singBoxUnitName)
		elapsed := time.Since(started)
		if !errors.Is(err, ErrProbeUnavailable) {
			t.Fatalf("error = %v, want ErrProbeUnavailable", err)
		}
		if elapsed > time.Second {
			t.Fatalf("probe ignored its own timeout: took %v", elapsed)
		}
		var probeErr *systemdProbeError
		if !errors.As(err, &probeErr) || probeErr.stage != systemdStageGetUnit {
			t.Fatalf("stage = %v, want %q", probeErr, systemdStageGetUnit)
		}
		if calls := reader.Calls(); len(calls) != 1 {
			t.Fatalf("recorded %d calls, want the one GetUnit attempt", len(calls))
		}
	})

	t.Run("caller_cancellation", func(t *testing.T) {
		reader := &fakeDBusUnitReader{block: true}
		probe := newSystemdDBusProbe(reader)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		started := time.Now()
		_, err := probe.ActiveState(ctx, singBoxUnitName)
		elapsed := time.Since(started)
		if !errors.Is(err, ErrProbeUnavailable) {
			t.Fatalf("error = %v, want ErrProbeUnavailable", err)
		}
		if elapsed > time.Second {
			t.Fatalf("probe ignored caller cancellation: took %v", elapsed)
		}
	})
}

// TestSystemdDBusProbeClose pins lifecycle: Close is idempotent, the connection
// is closed exactly once, and a closed probe reports unavailable without adding
// any bus traffic.
func TestSystemdDBusProbeClose(t *testing.T) {
	reader := newFakeSingBoxReader("active")
	probe := newSystemdDBusProbe(reader)
	if err := probe.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := probe.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if closes := reader.Closes(); closes != 1 {
		t.Fatalf("reader Close called %d times, want 1", closes)
	}
	_, err := probe.ActiveState(context.Background(), singBoxUnitName)
	if !errors.Is(err, ErrProbeUnavailable) {
		t.Fatalf("closed probe error = %v, want ErrProbeUnavailable", err)
	}
	var probeErr *systemdProbeError
	if !errors.As(err, &probeErr) || probeErr.stage != systemdStageClosed {
		t.Fatalf("closed probe stage = %v, want %q", probeErr, systemdStageClosed)
	}
	if calls := reader.Calls(); len(calls) != 0 {
		t.Fatalf("closed probe reached the bus: %#v", calls)
	}

	closeErr := errors.New("fixture: close failed")
	failingReader := &fakeDBusUnitReader{closeErr: closeErr}
	failingProbe := newSystemdDBusProbe(failingReader)
	if err := failingProbe.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("Close error = %v, want the reader's close error", err)
	}
	if err := failingProbe.Close(); err != nil {
		t.Fatalf("second Close after a close error = %v, want nil", err)
	}
}

// TestSystemdDBusProbeMapsThroughServiceAdapter chains the real probe type into
// the collector adapter and pins the frozen state mapping: only the three contract
// states survive; every other ActiveState value becomes "unknown", and a probe
// failure stays unavailable rather than being guessed.
func TestSystemdDBusProbeMapsThroughServiceAdapter(t *testing.T) {
	cases := []struct {
		activeState string
		want        ServiceState
	}{
		{"active", ServiceActive},
		{"inactive", ServiceInactive},
		{"failed", ServiceFailed},
		{"activating", ServiceUnknown},
		{"deactivating", ServiceUnknown},
		{"reloading", ServiceUnknown},
		{"maintenance", ServiceUnknown},
		{"", ServiceUnknown},
	}
	for _, testCase := range cases {
		probe := newSystemdDBusProbe(newFakeSingBoxReader(testCase.activeState))
		observation, err := (DBusServiceProbe{DBus: probe}).ObserveServices(context.Background())
		if err != nil {
			t.Fatalf("ObserveServices(%q): %v", testCase.activeState, err)
		}
		if observation.SingBox != testCase.want {
			t.Fatalf("ActiveState %q mapped to %q, want %q", testCase.activeState, observation.SingBox, testCase.want)
		}
	}

	failingProbe := newSystemdDBusProbe(&fakeDBusUnitReader{unitErr: errors.New("fixture: dbus denied")})
	if _, err := (DBusServiceProbe{DBus: failingProbe}).ObserveServices(context.Background()); !errors.Is(err, ErrProbeUnavailable) {
		t.Fatalf("failing probe through adapter: error = %v, want ErrProbeUnavailable", err)
	}
}

// TestDBusUnitReaderExposesNoWriteSurface proves the injectable seam itself has
// no method that could mutate a unit. Adding a generic Call or a lifecycle
// method to dbusUnitReader must fail this test, not silently widen the probe.
func TestDBusUnitReaderExposesNoWriteSurface(t *testing.T) {
	readerType := reflect.TypeOf((*dbusUnitReader)(nil)).Elem()
	methods := make([]string, 0, readerType.NumMethod())
	for index := 0; index < readerType.NumMethod(); index++ {
		methods = append(methods, readerType.Method(index).Name)
	}
	wantMethods := []string{"Close", "GetActiveState", "GetUnit"}
	if !reflect.DeepEqual(methods, wantMethods) {
		t.Fatalf("dbusUnitReader methods = %v, want exactly %v", methods, wantMethods)
	}
	forbiddenTokens := []string{
		"Start", "Stop", "Restart", "Reload", "Enable", "Disable", "Mask",
		"Kill", "Set", "Write", "Call", "Invoke", "Exec", "Signal",
	}
	for _, method := range methods {
		for _, token := range forbiddenTokens {
			if strings.Contains(method, token) {
				t.Fatalf("dbusUnitReader method %q contains forbidden token %q", method, token)
			}
		}
	}
}

// TestSystemdDBusImplementationSourcesHaveNoWriteOrExecSurface is the static
// companion of the seam test: the new non-test sources contain no systemd
// lifecycle method name, no systemctl and no exec/file-write surface, and the
// Linux reader contains exactly the two fixed CallWithContext wire sites.
func TestSystemdDBusImplementationSourcesHaveNoWriteOrExecSurface(t *testing.T) {
	forbiddenTokens := []string{
		"StartUnit", "StopUnit", "RestartUnit", "TryRestartUnit",
		"ReloadUnit", "ReloadOrRestartUnit", "EnqueueUnitJob", "KillUnit",
		"EnableUnitFiles", "DisableUnitFiles", "MaskUnitFiles",
		"SetUnitProperties", "SetProperties",
		"systemctl", "os/exec", "exec.Command", "exec.CommandContext",
		"os.WriteFile", "os.OpenFile",
	}
	sources := map[string]string{}
	for _, name := range []string{"dbus.go", "dbus_linux.go", "dbus_other.go"} {
		content, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if len(content) == 0 {
			t.Fatalf("%s is empty", name)
		}
		sources[name] = string(content)
		for _, token := range forbiddenTokens {
			if strings.Contains(sources[name], token) {
				t.Errorf("%s contains forbidden write/exec token %q", name, token)
			}
		}
	}

	linuxSource := sources["dbus_linux.go"]
	if count := strings.Count(linuxSource, "CallWithContext("); count != 2 {
		t.Fatalf("dbus_linux.go has %d CallWithContext sites, want exactly the two fixed reads", count)
	}
	if count := strings.Count(linuxSource, "dbus.FlagNoAutoStart"); count != 2 {
		t.Fatalf("dbus_linux.go has %d FlagNoAutoStart sites, want 2 (no bus activation side effects)", count)
	}
	for _, coordinate := range []string{
		`dbus.SystemBusPrivate()`,
		`systemdManagerInterface+"."+getUnitMember`,
		`propertiesInterface+"."+propertiesGetMember`,
		`systemdUnitInterface, activeStateProperty`,
	} {
		if !strings.Contains(linuxSource, coordinate) {
			t.Fatalf("dbus_linux.go does not contain the frozen wire coordinate %q", coordinate)
		}
	}
	if strings.Contains(linuxSource, "dbus.SystemBus()") {
		t.Fatal("dbus_linux.go uses the shared dbus.SystemBus; the probe must own a private connection")
	}
}

// TestSystemdDBusProbeDefaultTimeoutFallback pins that a probe constructed
// without newSystemdDBusProbe's default still gets the bounded 3s observation
// budget instead of an instantly-cancelled context.
func TestSystemdDBusProbeDefaultTimeoutFallback(t *testing.T) {
	probe := &SystemdDBusProbe{reader: newFakeSingBoxReader("inactive")}
	state, err := probe.ActiveState(context.Background(), singBoxUnitName)
	if err != nil {
		t.Fatalf("ActiveState with zero-value timeout: %v", err)
	}
	if state != "inactive" {
		t.Fatalf("ActiveState = %q, want %q", state, "inactive")
	}
}

// TestValidSystemdUnitPath pins the object-path validation used before the
// property read: only well-formed D-Bus paths below PID 1's unit tree pass.
func TestValidSystemdUnitPath(t *testing.T) {
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"synthetic sing-box unit", fakeSingBoxUnitPath, true},
		{"digits in unit element", systemdUnitPathPrefix + "getty_40tty1_2eservice", true},
		{"uppercase in unit element", systemdUnitPathPrefix + "Foo_2eservice", true},
		{"nested but well-formed inside the tree", systemdUnitPathPrefix + "foo/bar", true},
		{"bare prefix", systemdUnitPathPrefix, false},
		{"empty element", systemdUnitPathPrefix + "foo//bar", false},
		{"illegal hyphen", systemdUnitPathPrefix + "foo-bar", false},
		{"prefix mismatch", "/org/freedesktop/systemd1/unit_x", false},
		{"root path", "/", false},
		{"empty", "", false},
	}
	for _, testCase := range cases {
		if got := validSystemdUnitPath(testCase.path); got != testCase.want {
			t.Errorf("validSystemdUnitPath(%q) = %v, want %v (%s)", testCase.path, got, testCase.want, testCase.name)
		}
	}
	if !validDBusObjectPath("/") {
		t.Error(`validDBusObjectPath("/") = false, want true`)
	}
	if validDBusObjectPath("") {
		t.Error(`validDBusObjectPath("") = true, want false`)
	}
}

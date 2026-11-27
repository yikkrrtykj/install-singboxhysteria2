package linuxobs

import (
	"context"
	"strings"
	"sync/atomic"
	"time"
)

// The read-only systemd D-Bus contract (UM-A "04-node-protocol-v1" §11) allows
// exactly one observation: org.freedesktop.systemd1.Unit.ActiveState, read via
// two fixed D-Bus calls:
//
//  1. org.freedesktop.systemd1.Manager.GetUnit on /org/freedesktop/systemd1 to
//     resolve the allowlisted unit name to its object path;
//  2. org.freedesktop.DBus.Properties.Get on that returned unit path for
//     interface org.freedesktop.systemd1.Unit, property ActiveState.
//
// Every wire coordinate is frozen in this file so the probe, its tests and its
// reviewer all point at the same two calls. The probe MUST NOT call any other
// D-Bus method, MUST NOT execute an external command, MUST NOT write a file and
// MUST NOT require root.
const (
	// systemdBusName is PID 1's well-known system bus name.
	systemdBusName = "org.freedesktop.systemd1"
	// systemdManagerPath is the fixed Manager object path.
	systemdManagerPath = "/org/freedesktop/systemd1"
	// systemdManagerInterface hosts the only Manager method used.
	systemdManagerInterface = "org.freedesktop.systemd1.Manager"
	// getUnitMember resolves a unit name to its object path. It does not start,
	// stop, reload or enable anything.
	getUnitMember = "GetUnit"
	// systemdUnitInterface hosts the only property read.
	systemdUnitInterface = "org.freedesktop.systemd1.Unit"
	// activeStateProperty is the only property the v1 contract reads.
	activeStateProperty = "ActiveState"
	// propertiesInterface is the standard D-Bus property interface.
	propertiesInterface = "org.freedesktop.DBus.Properties"
	// propertiesGetMember is the standard single-property read.
	propertiesGetMember = "Get"
	// systemdUnitPathPrefix is where PID 1 exports unit objects. The path
	// returned by GetUnit is validated against this prefix before any property
	// read, so this probe can never ask PID 1 for a property of a non-unit
	// object even if the returned path is unexpected.
	systemdUnitPathPrefix = "/org/freedesktop/systemd1/unit/"
	// systemdProbeTimeout bounds one ActiveState observation even when the
	// caller's context carries no deadline. Local D-Bus calls complete in
	// milliseconds; the cap only exists so a wedged bus can never stall a
	// report collection indefinitely.
	systemdProbeTimeout = 3 * time.Second
)

// Closed, non-echoing failure stages for the systemd D-Bus probe.
const (
	systemdStageUnsupportedPlatform = "unsupported_platform"
	systemdStageConnect             = "connect_failed"
	systemdStageAuth                = "authenticate_failed"
	systemdStageHello               = "hello_failed"
	systemdStageNotConnected        = "no_connection"
	systemdStageClosed              = "closed"
	systemdStageContext             = "invalid_context"
	systemdStageUnitNotAllowed      = "unit_not_allowlisted"
	systemdStageGetUnit             = "get_unit_failed"
	systemdStageInvalidUnitPath     = "invalid_unit_path"
	systemdStageActiveState         = "active_state_failed"
)

// systemdProbeError is the closed error type of every SystemdDBusProbe failure.
//
// It deliberately carries only one of the fixed stage tokens above. The
// underlying D-Bus error text, the unit name and the object path are never
// echoed: a failed observation must not leak local systemd state into report
// bodies, agent logs or operator-facing errors, and the reported error string
// must not depend on remote input. errors.Is(err, ErrProbeUnavailable) is true
// for every probe failure, so the collector keeps rendering services as
// unavailable/unknown and never as "active".
type systemdProbeError struct {
	stage string
}

// Error implements error with a stable, non-echoing message.
func (probeError *systemdProbeError) Error() string {
	return "linuxobs: systemd D-Bus probe unavailable (" + probeError.stage + ")"
}

// Unwrap makes every probe failure match ErrProbeUnavailable.
func (probeError *systemdProbeError) Unwrap() error {
	return ErrProbeUnavailable
}

// newSystemdProbeError returns the closed probe error for one fixed stage.
func newSystemdProbeError(stage string) *systemdProbeError {
	return &systemdProbeError{stage: stage}
}

// dbusUnitReader is the complete D-Bus surface a SystemdDBusProbe can reach.
//
// It is intentionally much narrower than a D-Bus connection: two fixed read
// operations and Close. There is no generic Call/Invoke method, no property
// write and no unit lifecycle method in this interface, so code built on it
// cannot start, stop, restart, reload, enable, mask or otherwise mutate a unit
// even if it were asked to. The real implementation on Linux hard-wires the
// interface names, member names and property name above.
type dbusUnitReader interface {
	// GetUnit performs org.freedesktop.systemd1.Manager.GetUnit for unit and
	// returns the unit object path. It must honour ctx and must not mutate unit
	// state.
	GetUnit(ctx context.Context, unit string) (string, error)
	// GetActiveState performs org.freedesktop.DBus.Properties.Get on unitPath
	// for interface org.freedesktop.systemd1.Unit, property ActiveState. It must
	// honour ctx and must not mutate unit state.
	GetActiveState(ctx context.Context, unitPath string) (string, error)
	// Close releases the underlying connection.
	Close() error
}

// SystemdDBusProbe is the reviewed read-only systemd observer. It implements
// DBusProbe and is meant to be injected through DBusServiceProbe:
//
//	probe, err := NewSystemdDBusProbe()
//	if err == nil {
//	    collector.ServiceProbe = DBusServiceProbe{DBus: probe}
//	}
//
// The probe answers exactly one question: the ActiveState of the single frozen
// v1 unit sing-box.service. It reports ErrProbeUnavailable (via a closed
// systemdProbeError) for every connection, permission, timeout, malformed-path
// or transport failure. It never returns a fabricated "active": the only
// values it can return are the strings PID 1 actually reported in ActiveState.
//
// A SystemdDBusProbe is safe for concurrent use; the injected reader must be
// too (the Linux reader wraps a concurrency-safe *dbus.Conn).
type SystemdDBusProbe struct {
	reader  dbusUnitReader
	timeout time.Duration
	closed  atomic.Bool
}

// newSystemdDBusProbe wraps one reader. The seam is unexported on purpose: only
// the real Linux connection (NewSystemdDBusProbe) and this package's tests can
// construct a probe, so no other package can inject a wider D-Bus surface.
func newSystemdDBusProbe(reader dbusUnitReader) *SystemdDBusProbe {
	return &SystemdDBusProbe{reader: reader, timeout: systemdProbeTimeout}
}

// ActiveState implements DBusProbe for the single allowlisted unit.
//
// The unit argument is checked against the frozen v1 allowlist before any D-Bus
// call, the returned object path is validated against the systemd unit tree
// before the property read, and every failure is collapsed into a closed
// ErrProbeUnavailable error. A nil context, a closed probe and a zero-value
// probe are honest unavailable results, never panics.
func (probe *SystemdDBusProbe) ActiveState(ctx context.Context, unit string) (string, error) {
	if probe == nil || probe.reader == nil {
		return "", newSystemdProbeError(systemdStageNotConnected)
	}
	if probe.closed.Load() {
		return "", newSystemdProbeError(systemdStageClosed)
	}
	if ctx == nil {
		return "", newSystemdProbeError(systemdStageContext)
	}
	if unit != singBoxUnitName {
		return "", newSystemdProbeError(systemdStageUnitNotAllowed)
	}
	timeout := probe.timeout
	if timeout <= 0 {
		timeout = systemdProbeTimeout
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	unitPath, err := probe.reader.GetUnit(callCtx, unit)
	if err != nil {
		return "", newSystemdProbeError(systemdStageGetUnit)
	}
	if !validSystemdUnitPath(unitPath) {
		return "", newSystemdProbeError(systemdStageInvalidUnitPath)
	}
	state, err := probe.reader.GetActiveState(callCtx, unitPath)
	if err != nil {
		return "", newSystemdProbeError(systemdStageActiveState)
	}
	return state, nil
}

// Close releases the private system bus connection. It is idempotent and
// returns nil for a nil or zero-value probe. After Close, ActiveState reports
// the closed stage as unavailable without touching the bus again.
func (probe *SystemdDBusProbe) Close() error {
	if probe == nil || probe.reader == nil || probe.closed.Swap(true) {
		return nil
	}
	return probe.reader.Close()
}

// validSystemdUnitPath reports whether path is a well-formed D-Bus object path
// inside PID 1's unit tree. It is defence in depth: GetUnit is expected to
// return such a path, and nothing outside it is ever asked for a property.
func validSystemdUnitPath(path string) bool {
	if !strings.HasPrefix(path, systemdUnitPathPrefix) || len(path) == len(systemdUnitPathPrefix) {
		return false
	}
	return validDBusObjectPath(path)
}

// validDBusObjectPath implements the D-Bus object-path grammar: a leading '/'
// followed by non-empty elements of [A-Za-z0-9_], with '/' as separator.
func validDBusObjectPath(path string) bool {
	if path == "" || path[0] != '/' {
		return false
	}
	if path == "/" {
		return true
	}
	for _, element := range strings.Split(path[1:], "/") {
		if element == "" {
			return false
		}
		for index := 0; index < len(element); index++ {
			character := element[index]
			switch {
			case character >= 'a' && character <= 'z':
			case character >= 'A' && character <= 'Z':
			case character >= '0' && character <= '9':
			case character == '_':
			default:
				return false
			}
		}
	}
	return true
}

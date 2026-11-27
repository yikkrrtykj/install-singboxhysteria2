package linuxobs

import (
	"context"
	"errors"
	"strings"
)

// ErrProbeUnavailable is the honest result of every optional probe this
// package ships by default: the observation surface exists, but the read-only
// evidence source is not implemented or not reachable.
var ErrProbeUnavailable = errors.New("linuxobs: read-only probe unavailable")

// ServiceState is the frozen v1 service state vocabulary
// (report-snapshot.schema.json services[].state).
type ServiceState string

// Frozen service states.
const (
	ServiceActive   ServiceState = "active"
	ServiceInactive ServiceState = "inactive"
	ServiceFailed   ServiceState = "failed"
	ServiceUnknown  ServiceState = "unknown"
)

// The v1 runtime service allowlist is exactly one unit.
const singBoxUnitName = "sing-box.service"

// ServiceObservation is the result of one read-only unit-state observation.
type ServiceObservation struct {
	// SingBox is the observed state of the v1 allowlisted sing-box unit. The
	// zero value is mapped to ServiceUnknown, never to "active".
	SingBox ServiceState
}

// ServiceProbe observes local systemd unit state with read-only property
// reads. Implementations MUST NOT execute systemctl (or any other program),
// MUST NOT mutate a unit, and MUST NOT require root. This package ships only
// an unavailable default; a future reviewed implementation may implement this
// interface without changing the collector.
type ServiceProbe interface {
	ObserveServices(ctx context.Context) (ServiceObservation, error)
}

// unavailableServiceProbe is the shipped default: it performs no I/O and
// reports unavailable.
type unavailableServiceProbe struct{}

// ObserveServices implements ServiceProbe as an honest unavailable result.
func (unavailableServiceProbe) ObserveServices(context.Context) (ServiceObservation, error) {
	return ServiceObservation{}, ErrProbeUnavailable
}

// DBusProbe is the minimal bounded read-only D-Bus property surface a reviewed
// systemd observer would need. It exposes exactly one read operation
// (org.freedesktop.systemd1.Unit.ActiveState for one unit name); there is no
// generic call, no method invocation and no write method in the interface, so
// no D-Bus client built on it can start/stop/enable a unit.
//
// The Linux build ships SystemdDBusProbe (see dbus_linux.go), a real
// unprivileged system-bus client with exactly the two fixed read calls above.
// Non-Linux builds return the honest unavailable default. The seam remains
// injectable for tests and for an operator that wants to supply a reviewed
// alternative.
type DBusProbe interface {
	// ActiveState reads the systemd unit ActiveState property. It must not
	// mutate state, must not require root and must honour ctx.
	ActiveState(ctx context.Context, unit string) (string, error)
}

// UnavailableDBusProbe is the shipped DBusProbe: it performs no D-Bus I/O and
// reports unavailable.
type UnavailableDBusProbe struct{}

// ActiveState implements DBusProbe as an honest unavailable result. The unit
// argument is deliberately ignored: no path, name or value is logged.
func (UnavailableDBusProbe) ActiveState(context.Context, string) (string, error) {
	return "", ErrProbeUnavailable
}

// DBusServiceProbe adapts a DBusProbe to the collector's ServiceProbe. It is
// hard-wired to the single frozen v1 service allowlist entry, so even a
// compromised/naive DBusProbe is only ever asked for sing-box.service.
type DBusServiceProbe struct {
	DBus DBusProbe
}

// ObserveServices implements ServiceProbe for the single allowed unit.
func (probe DBusServiceProbe) ObserveServices(ctx context.Context) (ServiceObservation, error) {
	if probe.DBus == nil {
		return ServiceObservation{}, ErrProbeUnavailable
	}
	state, err := probe.DBus.ActiveState(ctx, singBoxUnitName)
	if err != nil {
		return ServiceObservation{}, err
	}
	return ServiceObservation{SingBox: normalizeServiceState(ServiceState(strings.TrimSpace(state)))}, nil
}

// Close releases the underlying read-only D-Bus probe when it owns a
// persistent connection.
func (probe DBusServiceProbe) Close() error {
	if closer, ok := probe.DBus.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

// normalizeServiceState maps a systemd ActiveState value onto the frozen enum.
// States the contract cannot express (activating, deactivating, reloading,
// maintenance, empty, ...) become "unknown" rather than a guess.
func normalizeServiceState(raw ServiceState) ServiceState {
	switch raw {
	case ServiceActive, ServiceInactive, ServiceFailed:
		return raw
	default:
		return ServiceUnknown
	}
}

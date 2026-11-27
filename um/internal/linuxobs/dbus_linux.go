//go:build linux

package linuxobs

import (
	"context"
	"errors"

	"github.com/godbus/dbus/v5"
)

// NewSystemdDBusProbe opens a private, unprivileged connection to the system bus
// and returns the reviewed read-only systemd observer.
//
// The connection is created with dbus.SystemBusPrivate (not the shared
// dbus.SystemBus), authenticated with the caller's own uid through the default
// EXTERNAL mechanism, greeted with Hello, and owned by the returned probe so
// Close can release the file descriptor. No privileged credentials, no root and
// no external command path are involved; the bus address comes from the
// standard client rules (DBUS_SYSTEM_BUS_ADDRESS, else
// /run/dbus/system_bus_socket).
//
// A construction failure is a closed ErrProbeUnavailable error: callers should
// fall back to the honest unavailable default (leave Collector.ServiceProbe
// nil) instead of retrying in a loop or treating the unit as active.
func NewSystemdDBusProbe() (*SystemdDBusProbe, error) {
	connection, err := dbus.SystemBusPrivate()
	if err != nil {
		return nil, newSystemdProbeError(systemdStageConnect)
	}
	if err := connection.Auth(nil); err != nil {
		_ = connection.Close()
		return nil, newSystemdProbeError(systemdStageAuth)
	}
	if err := connection.Hello(); err != nil {
		_ = connection.Close()
		return nil, newSystemdProbeError(systemdStageHello)
	}
	return newSystemdDBusProbe(&systemdDBusConn{connection: connection}), nil
}

// systemdDBusConn is the one real dbusUnitReader. It wraps a private system bus
// connection and issues exactly two fixed read-only calls; there is no generic
// call helper, no property write and no unit lifecycle invocation in this file.
type systemdDBusConn struct {
	connection *dbus.Conn
}

// GetUnit performs org.freedesktop.systemd1.Manager.GetUnit on the fixed
// Manager object path for the one allowlisted unit.
func (connection *systemdDBusConn) GetUnit(ctx context.Context, unit string) (string, error) {
	var unitPath dbus.ObjectPath
	call := connection.connection.Object(systemdBusName, dbus.ObjectPath(systemdManagerPath)).
		CallWithContext(ctx, systemdManagerInterface+"."+getUnitMember, dbus.FlagNoAutoStart, unit)
	if call.Err != nil {
		return "", call.Err
	}
	if err := call.Store(&unitPath); err != nil {
		return "", err
	}
	return string(unitPath), nil
}

// GetActiveState performs org.freedesktop.DBus.Properties.Get on the unit path
// returned by GetUnit for interface org.freedesktop.systemd1.Unit, property
// ActiveState.
func (connection *systemdDBusConn) GetActiveState(ctx context.Context, unitPath string) (string, error) {
	var property dbus.Variant
	call := connection.connection.Object(systemdBusName, dbus.ObjectPath(unitPath)).
		CallWithContext(ctx, propertiesInterface+"."+propertiesGetMember, dbus.FlagNoAutoStart,
			systemdUnitInterface, activeStateProperty)
	if call.Err != nil {
		return "", call.Err
	}
	if err := call.Store(&property); err != nil {
		return "", err
	}
	state, ok := property.Value().(string)
	if !ok {
		return "", errors.New("linuxobs: systemd ActiveState is not a string")
	}
	return state, nil
}

// Close closes the private system bus connection.
func (connection *systemdDBusConn) Close() error {
	return connection.connection.Close()
}

// Compile-time proof that the real Linux reader is exactly the closed seam.
var _ dbusUnitReader = (*systemdDBusConn)(nil)

// Compile-time proof that the probe implements the collector-facing interface.
var _ DBusProbe = (*SystemdDBusProbe)(nil)

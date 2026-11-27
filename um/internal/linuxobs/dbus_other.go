//go:build !linux

package linuxobs

// NewSystemdDBusProbe reports that the real read-only systemd D-Bus probe is not
// supported on this platform. It compiles everywhere so cross-platform builds
// and tests of this package stay green; the returned error is a closed
// ErrProbeUnavailable error (errors.Is(err, ErrProbeUnavailable) is true), so a
// caller can fall back to the honest unavailable default.
//
// The Linux implementation lives in dbus_linux.go and talks only to the system
// bus; this stub performs no I/O at all.
func NewSystemdDBusProbe() (*SystemdDBusProbe, error) {
	return nil, newSystemdProbeError(systemdStageUnsupportedPlatform)
}

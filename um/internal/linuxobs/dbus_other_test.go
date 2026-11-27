//go:build !linux

package linuxobs

import (
	"errors"
	"testing"
)

// TestNewSystemdDBusProbeUnsupportedOnNonLinux pins the cross-platform stub: it
// compiles and reports a closed unavailable error, so a Windows/other-platform
// build of this package stays green and can never accidentally claim systemd
// observation support.
func TestNewSystemdDBusProbeUnsupportedOnNonLinux(t *testing.T) {
	probe, err := NewSystemdDBusProbe()
	if probe != nil {
		t.Fatalf("NewSystemdDBusProbe() = %#v, want a nil probe", probe)
	}
	if !errors.Is(err, ErrProbeUnavailable) {
		t.Fatalf("NewSystemdDBusProbe() error = %v, want ErrProbeUnavailable", err)
	}
	var probeErr *systemdProbeError
	if !errors.As(err, &probeErr) {
		t.Fatalf("NewSystemdDBusProbe() error %v is not a *systemdProbeError", err)
	}
	if probeErr.stage != systemdStageUnsupportedPlatform {
		t.Fatalf("stage = %q, want %q", probeErr.stage, systemdStageUnsupportedPlatform)
	}
}

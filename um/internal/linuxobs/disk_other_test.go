//go:build !linux

package linuxobs

import (
	"errors"
	"testing"
)

// TestDefaultDiskProbeUnavailableOutsideLinux proves the non-Linux build never
// fabricates disk numbers: collection must report null fields instead.
func TestDefaultDiskProbeUnavailableOutsideLinux(t *testing.T) {
	if _, _, err := newDefaultDiskProbe(".").Usage(); !errors.Is(err, ErrProbeUnavailable) {
		t.Fatalf("Usage error = %v, want ErrProbeUnavailable", err)
	}
}

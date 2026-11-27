//go:build linux

package linuxobs

import (
	"errors"
	"path/filepath"
	"testing"
)

// TestDefaultDiskProbeLinux exercises the real syscall.Statfs probe on a temp
// directory. It reads only; nothing is created inside the observed path.
func TestDefaultDiskProbeLinux(t *testing.T) {
	probe := newDefaultDiskProbe(t.TempDir())
	total, used, err := probe.Usage()
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	if total == 0 {
		t.Fatal("statfs reported a zero-size filesystem")
	}
	if used > total {
		t.Fatalf("used (%d) exceeds total (%d)", used, total)
	}

	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if _, _, err := newDefaultDiskProbe(missing).Usage(); err == nil {
		t.Fatal("statfs accepted a missing mount path")
	}
	if errors.Is(err, ErrProbeUnavailable) {
		t.Fatalf("real statfs failure wrapped ErrProbeUnavailable unexpectedly: %v", err)
	}
}

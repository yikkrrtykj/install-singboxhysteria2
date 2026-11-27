//go:build !linux

package linuxobs

import "fmt"

// defaultDiskProbe is unavailable outside Linux: the frozen contract targets
// Linux VPS hosts, and this package must never fabricate disk numbers on a
// platform where the read-only statfs evidence does not exist.
type defaultDiskProbe struct {
	path string
}

func newDefaultDiskProbe(path string) DiskProbe {
	return defaultDiskProbe{path: path}
}

// Usage implements DiskProbe as an honest unavailable result.
func (probe defaultDiskProbe) Usage() (uint64, uint64, error) {
	return 0, 0, fmt.Errorf("%w: filesystem stat is unsupported on this platform", ErrProbeUnavailable)
}

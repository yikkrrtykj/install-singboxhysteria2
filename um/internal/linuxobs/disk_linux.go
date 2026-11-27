//go:build linux

package linuxobs

import (
	"errors"
	"syscall"
)

// defaultDiskProbe is the read-only statfs observer used on Linux.
type defaultDiskProbe struct {
	path string
}

func newDefaultDiskProbe(path string) DiskProbe {
	return defaultDiskProbe{path: path}
}

// Usage implements DiskProbe with syscall.Statfs. It opens no descriptor and
// writes nothing.
func (probe defaultDiskProbe) Usage() (uint64, uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(probe.path, &stat); err != nil {
		return 0, 0, err
	}
	if stat.Bsize <= 0 {
		return 0, 0, errors.New("linuxobs: invalid statfs block size")
	}
	blockSize := uint64(stat.Bsize)
	if stat.Bfree > stat.Blocks {
		return 0, 0, errors.New("linuxobs: invalid statfs free block count")
	}
	if stat.Blocks > maxUint64Value/blockSize {
		return 0, 0, errors.New("linuxobs: filesystem size overflows byte counters")
	}
	total := stat.Blocks * blockSize
	used := (stat.Blocks - stat.Bfree) * blockSize
	return total, used, nil
}

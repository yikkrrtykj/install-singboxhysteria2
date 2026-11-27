package linuxobs

// DiskProbe observes filesystem usage of the configured mount point without
// writing to it. The shipped default uses syscall.Statfs on Linux; on other
// platforms (this package must also build and test on Windows) the default is
// unavailable and the disk fields are reported null.
type DiskProbe interface {
	// Usage reports total and used bytes for the observed filesystem. An error
	// means the filesystem could not be observed; the caller must render null
	// disk fields rather than a zero.
	Usage() (totalBytes, usedBytes uint64, err error)
}

// diskProbe resolves the configured disk observer.
func (c *Collector) diskProbe() DiskProbe {
	if c.DiskProbe != nil {
		return c.DiskProbe
	}
	return newDefaultDiskProbe(c.diskMountPath())
}

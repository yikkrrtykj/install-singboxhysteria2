//go:build !windows

package agent

import (
	"os"
	"runtime"
	"strings"
)

func platformHost() HostInfo {
	kernel := "unknown"
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		if v := strings.TrimSpace(string(b)); v != "" {
			kernel = v
		}
	}
	return HostInfo{OS: "linux", Kernel: kernel, Arch: runtime.GOARCH}
}

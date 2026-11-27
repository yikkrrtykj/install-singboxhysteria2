//go:build windows

package agent

import "runtime"

func platformHost() HostInfo {
	// The exact Windows version is obtained by the service/installer ADR; the
	// frozen snapshot schema requires a non-empty kernel-form string.
	return HostInfo{OS: "windows", Kernel: "10.0.0", Arch: runtime.GOARCH}
}

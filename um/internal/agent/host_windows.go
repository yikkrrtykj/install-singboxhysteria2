//go:build windows

package agent

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/windows"
)

func platformHost() HostInfo {
	version := windows.RtlGetVersion()
	return HostInfo{OS: "windows", Kernel: fmt.Sprintf("%d.%d.%d",
		version.MajorVersion, version.MinorVersion, version.BuildNumber), Arch: runtime.GOARCH}
}

//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/agent"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/linuxobs"
)

func platformCollector(c commonFlags) (agent.Collector, error) {
	col := &linuxobs.Collector{AgentVersion: version}
	// The monitor-v2 traffic export path is operator-local only. It is never
	// accepted from center config, a URL or a command; an invalid fixed path is a
	// startup configuration error instead of a silently ignored one.
	if err := linuxobs.ValidateMonitorExportPath(c.monitorExportFile); err != nil {
		return nil, err
	}
	col.MonitorExportFile = c.monitorExportFile
	mode, err := c.monitorExportMode()
	if err != nil {
		return nil, err
	}
	col.MonitorExportOwnerUID = c.monitorExportOwnerUID
	col.MonitorExportGroupGID = c.monitorExportGroupGID
	col.MonitorExportMode = mode
	// The systemd probe is read-only and non-root. If the system bus is
	// unavailable, keep the honest unavailable default rather than failing the
	// whole agent; services are source-gated by center config.
	if probe, err := linuxobs.NewSystemdDBusProbe(); err == nil {
		col.ServiceProbe = linuxobs.DBusServiceProbe{DBus: probe}
	}
	// No environment variable, center switch or local secret path authorizes
	// the sing-box service.api source in this release. The v1.14.5 P1-10 audit
	// FAILED because the single service.api credential is write-capable; until a
	// separately approved versioned authorization exists, the collector remains
	// source-unauthorized and honestly unavailable. Lab tests construct a probe
	// directly in-process only.
	return col, nil
}

func platformService([]string) error {
	return errors.New("Windows Service is not supported on this platform; use the Linux systemd unit")
}

func runR1Provision([]string) int {
	fmt.Fprintln(os.Stderr, "um-agent: R1 provisioning is Windows-terminal-only")
	return 1
}

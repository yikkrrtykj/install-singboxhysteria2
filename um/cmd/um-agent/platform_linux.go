//go:build !windows

package main

import (
	"errors"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/agent"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/linuxobs"
)

func platformCollector(commonFlags) (agent.Collector, error) {
	return &linuxobs.Collector{AgentVersion: version}, nil
}

func platformService([]string) error {
	return errors.New("Windows Service is not supported on this platform; use the Linux systemd unit")
}

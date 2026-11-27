//go:build !windows

package main

import (
	"errors"
	"os"
	"strings"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/agent"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/linuxobs"
)

func platformCollector(commonFlags) (agent.Collector, error) {
	col := &linuxobs.Collector{AgentVersion: version}
	// The systemd probe is read-only and non-root. If the system bus is
	// unavailable, keep the honest unavailable default rather than failing the
	// whole agent; services are source-gated by center config.
	if probe, err := linuxobs.NewSystemdDBusProbe(); err == nil {
		col.ServiceProbe = linuxobs.DBusServiceProbe{DBus: probe}
	}
	authorized := os.Getenv("UM_AGENT_SINGBOX_SOURCE_AUTHORIZED")
	sourceAuthorized := authorized == "1" || strings.EqualFold(authorized, "true")
	secretFile := os.Getenv("UM_AGENT_SINGBOX_API_SECRET_FILE")
	if sourceAuthorized && secretFile == "" {
		return nil, errors.New("um-agent: sing-box source authorization requires a configured service.api probe")
	}
	// The secret is only read when the operator explicitly configured the
	// credential path (normally a systemd LoadCredential directory entry). No
	// source is enabled by this wiring; the center source switch remains false
	// until the versioned P1-10 authorization audit and Owner enablement.
	if secretFile != "" {
		raw, err := os.ReadFile(secretFile)
		if err != nil {
			return nil, errors.New("um-agent: cannot read configured sing-box API secret")
		}
		secret := strings.TrimSpace(string(raw))
		if secret == "" {
			return nil, errors.New("um-agent: configured sing-box API secret is empty")
		}
		apiURL := envOr("UM_AGENT_SINGBOX_API_URL", linuxobs.DefaultServiceAPIURL)
		probe, err := linuxobs.NewServiceAPIProbe(linuxobs.ServiceAPIConfig{
			URL: apiURL, Secret: secret,
		})
		if err != nil {
			return nil, errors.New("um-agent: invalid sing-box service.api configuration")
		}
		col.ServiceAPIProbe = probe
	}
	if sourceAuthorized {
		if col.ServiceAPIProbe == nil {
			return nil, errors.New("um-agent: sing-box source authorization requires a configured service.api probe")
		}
		col.SingBoxSourceAuthorized = true
	}
	return col, nil
}

func platformService([]string) error {
	return errors.New("Windows Service is not supported on this platform; use the Linux systemd unit")
}

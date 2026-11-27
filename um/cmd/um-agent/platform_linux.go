//go:build !windows

package main

import (
	"errors"
	"fmt"
	"io"
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
		secret, err := readCredentialFile(secretFile)
		if err != nil {
			return nil, errors.New("um-agent: cannot read configured sing-box API secret")
		}
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

// readCredentialFile reads a root/systemd-provided service.api secret. It
// rejects symlinks, non-regular files, oversized input and group/world-readable
// modes so a misconfigured credential path fails closed instead of following an
// attacker-controlled link.
func readCredentialFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("credential is not a regular non-symlink file")
	}
	if info.Size() > 4096 {
		return "", errors.New("credential exceeds size limit")
	}
	// systemd >=254 provisions LoadCredential files with POSIX ACLs. The ACL
	// mask is reflected in st_mode's group bits, so a stat that reports 0440
	// can still be a correctly scoped 0400 credential. Reject world access and
	// group write/execute, but allow the ACL-mask group read bit; the source
	// path itself is root-controlled and the credential is delivered in the
	// unit's private credentials mount.
	if info.Mode().Perm()&0o007 != 0 || info.Mode().Perm()&0o030 != 0 {
		return "", errors.New("credential grants world access or group write/execute")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return "", err
	}
	if len(raw) > 4096 {
		return "", errors.New("credential exceeds size limit")
	}
	secret := strings.TrimSpace(string(raw))
	if secret == "" {
		return "", errors.New("credential is empty")
	}
	return secret, nil
}

func platformService([]string) error {
	return errors.New("Windows Service is not supported on this platform; use the Linux systemd unit")
}

func runR1Provision([]string) int {
	fmt.Fprintln(os.Stderr, "um-agent: R1 provisioning is Windows-terminal-only")
	return 1
}

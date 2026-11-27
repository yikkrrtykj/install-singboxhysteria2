//go:build !windows

package agent

import "errors"

// On non-Windows platforms the state directory and its files are protected by
// 0700/0600 permissions; there is no DPAPI equivalent in this build.
func sealPrivateKey(string) (string, error) { return "", nil }

func unsealPrivateKey(protected string) (string, error) {
	if protected != "" {
		return "", errors.New("agent: state is DPAPI-protected and cannot be used on this platform")
	}
	return "", nil
}

func privateKeyProtectionAvailable() bool { return false }

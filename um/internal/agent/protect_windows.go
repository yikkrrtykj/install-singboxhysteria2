//go:build windows

package agent

import (
	"encoding/base64"
	"errors"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/secretstore"
)

// sealPrivateKey protects private key material at rest with DPAPI CurrentUser.
// The service/agent must run under the same account at enrollment and at every
// restart; changing the runtime account makes the state unreadable (fail
// closed), which is documented in the OD-P7 ADR.
func sealPrivateKey(plaintext string) (string, error) {
	if plaintext == "" {
		return "", errors.New("agent: refusing to seal an empty private key")
	}
	protector, err := secretstore.NewDPAPIProtector(secretstore.DPAPIUserScope, nil)
	if err != nil {
		return "", err
	}
	protected, err := protector.Protect([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(protected), nil
}

func unsealPrivateKey(protected string) (string, error) {
	if protected == "" {
		return "", errors.New("agent: missing protected private key")
	}
	raw, err := base64.RawURLEncoding.DecodeString(protected)
	if err != nil || len(raw) == 0 {
		return "", errors.New("agent: invalid protected private key")
	}
	protector, err := secretstore.NewDPAPIProtector(secretstore.DPAPIUserScope, nil)
	if err != nil {
		return "", err
	}
	plaintext, err := protector.Unprotect(raw)
	if err != nil {
		return "", errors.New("agent: DPAPI unprotect failed")
	}
	return string(plaintext), nil
}

func privateKeyProtectionAvailable() bool { return true }

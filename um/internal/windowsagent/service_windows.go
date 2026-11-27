//go:build windows

// Windows credential-protection helper and service-lifecycle ADR hooks.
//
// STATUS: DPAPI protection is now backed by the shared internal/secretstore
// package so the agent runtime and this ADR hook use one implementation. The
// Windows runtime account, ACL, DPAPI scope and enrollment provisioning remain
// OD-P7 PENDING; this file does not install or approve a service account and is
// not a production-service claim.
package windowsagent

import (
	"context"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/secretstore"
)

// SecretProtector protects an explicitly injected local credential at rest.
type SecretProtector = secretstore.Protector

// DPAPIScope selects the Windows DPAPI protection scope.
type DPAPIScope = secretstore.DPAPIScope

const (
	// DPAPIUserScope ties the protected value to the current user profile.
	DPAPIUserScope = secretstore.DPAPIUserScope
	// DPAPIMachineScope ties the protected value to the local machine. It is
	// OD-P7-gated and not the default.
	DPAPIMachineScope = secretstore.DPAPIMachineScope
)

// DPAPIProtector is the shared dependency-free Windows DPAPI implementation.
type DPAPIProtector = secretstore.DPAPIProtector

// NewDPAPIProtector creates a DPAPI protector for the given scope.
func NewDPAPIProtector(scope DPAPIScope, entropy []byte) (*DPAPIProtector, error) {
	return secretstore.NewDPAPIProtector(scope, entropy)
}

// ServiceHost is the ADR hook for a future reviewed Windows service wrapper
// around agent.Runtime. Account/session/ACL, event-log source, DPAPI scope and
// installer behavior remain OD-P7 decisions and are PENDING.
type ServiceHost interface {
	// Run blocks until the service is asked to stop or fails closed.
	Run(ctx context.Context) error
}

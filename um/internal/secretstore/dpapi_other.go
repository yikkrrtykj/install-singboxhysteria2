//go:build !windows

package secretstore

import (
	"fmt"
	"runtime"
)

// NewDPAPIProtector reports that Windows DPAPI is unavailable on the current
// platform. It never inspects, copies or retains entropy and returns no
// protector; the returned error matches ErrUnsupported with errors.Is.
func NewDPAPIProtector(scope DPAPIScope, entropy []byte) (*DPAPIProtector, error) {
	return nil, unsupportedDPAPIError("protector")
}

// Protect fails closed on platforms without DPAPI. It never reads, copies or
// logs plaintext.
func (p *DPAPIProtector) Protect(plaintext []byte) ([]byte, error) {
	return nil, unsupportedDPAPIError("protect")
}

// Unprotect fails closed on platforms without DPAPI. It never reads, copies or
// logs protected data.
func (p *DPAPIProtector) Unprotect(protected []byte) ([]byte, error) {
	return nil, unsupportedDPAPIError("unprotect")
}

// unsupportedDPAPIError builds a typed platform error: the GOOS name is safe to
// report and the cause matches ErrUnsupported.
func unsupportedDPAPIError(operation string) error {
	return fmt.Errorf("secretstore: DPAPI %s is unavailable on %s: %w", operation, runtime.GOOS, ErrUnsupported)
}

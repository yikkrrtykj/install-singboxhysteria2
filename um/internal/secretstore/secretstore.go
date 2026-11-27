// Package secretstore provides at-rest protection for small local secrets such
// as an agent's Ed25519 private key.
//
// It is a mechanism seam, not a credential store or an authorization boundary:
// it performs no file, registry or network I/O, does not enumerate, provision or
// persist keys, and never logs, echoes or includes the plaintext or the
// protected bytes in an error. Protecting a key at rest complements, but never
// replaces, owner-only file permissions and the enrollment decision that
// authorizes the key.
//
// The only implemented mechanism is Windows DPAPI (dpapi_windows.go), which
// calls CryptProtectData/CryptUnprotectData with UI prompts forbidden and frees
// every Win32-owned buffer with LocalFree. The default DPAPIUserScope needs no
// service account. DPAPIMachineScope is opt-in and Owner/OD-P7-gated: do not use
// it for a production credential until the service-account/ACL decision is
// recorded. On other platforms the same API compiles; NewDPAPIProtector there
// returns an error matching ErrUnsupported, so callers must decide explicitly
// whether to fall back instead of silently writing plaintext.
package secretstore

import "errors"

// Protector protects a small local secret at rest.
//
// Implementations must never log, echo, upload or include in an error the
// plaintext or the protected bytes. Empty input is refused: Protect rejects
// empty plaintext and Unprotect rejects empty protected data.
type Protector interface {
	Protect(plaintext []byte) ([]byte, error)
	Unprotect(protected []byte) ([]byte, error)
}

// DPAPIScope selects the Windows DPAPI protection scope.
type DPAPIScope uint32

const (
	// DPAPIUserScope ties the protected value to the current user profile. It is
	// the default and requires no production service account.
	DPAPIUserScope DPAPIScope = iota
	// DPAPIMachineScope ties the protected value to the local machine. It is
	// OD-P7-gated: do not use it for production credentials until the service
	// account/ACL decision is approved.
	DPAPIMachineScope
)

// maxEntropyBytes bounds caller-supplied DPAPI entropy. Entropy is an optional
// second, non-secret local binding factor rather than a cryptographic key, and
// the same value must be supplied to both Protect and Unprotect. The limit keeps
// a misconfigured caller from passing an unreasonably large buffer to Win32.
const maxEntropyBytes = 1024

// ErrUnsupported reports that the running platform has no implementation of the
// requested protection mechanism. Match it with errors.Is. The non-Windows
// fallback wraps it with the GOOS name; it is not used for configuration
// errors, which every platform rejects the same way.
var ErrUnsupported = errors.New("secretstore: protection mechanism is unsupported on this platform")

// DPAPIProtector is the Windows DPAPI implementation of Protector
// (CryptProtectData/CryptUnprotectData with UI prompts forbidden, and
// CRYPTPROTECT_LOCAL_MACHINE selected only for DPAPIMachineScope). It performs
// no I/O of its own, copies caller-supplied entropy at construction, and is safe
// for concurrent use once constructed.
//
// Construct it with NewDPAPIProtector; the zero value is not a supported
// configuration. On non-Windows platforms the type and its methods exist so
// that cross-platform callers compile, but the constructor always returns
// ErrUnsupported and the methods fail closed without touching their input.
type DPAPIProtector struct {
	scope   DPAPIScope
	entropy []byte
}

// Compile-time interface assertion; the platform files define the methods.
var _ Protector = (*DPAPIProtector)(nil)

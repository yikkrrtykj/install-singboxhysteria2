//go:build windows

// Windows credential-protection helper and service-lifecycle ADR hooks.
//
// STATUS: ADR scaffolding only. OD-P7 ("Windows Agent 运行账户与 secret 存储
// (DPAPI/服务账户/用户会话)", docs/um/um-127/05-owner-decisions.md) is PENDING.
// This file therefore:
//
//   - does not install, start, configure or query a Windows service;
//   - does not create or require a service account, ACL, scheduled task or
//     production host;
//   - does not read a secret store, an environment variable or the registry;
//   - is not wired into cmd/um-agent (its `service` subcommand stays deferred);
//   - never provisions an R1 controller credential. R1 remains unauthorized.
//
// The DPAPI protector exists so that a future reviewed service host can protect
// an explicitly injected local credential at rest instead of writing plaintext.
// It is dependency-free (stdlib syscall + crypt32.dll) and is exercised only by
// Windows unit tests. The default user scope needs no service account; the
// machine scope is documented as Owner/OD-P7-gated.
//
// The service host seam is represented by the ServiceHost interface below and
// intentionally has no implementation in this Draft: the account/session/ACL
// decision must be recorded in the ADR before any service wiring is added.

package windowsagent

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

// SecretProtector protects an explicitly injected local credential at rest.
// The interface is the ADR hook so a future reviewed service can swap a DPAPI
// scope (or another Owner-approved mechanism) without touching collectors.
//
// Implementations must never log, echo or upload the plaintext or the
// protected bytes; errors must not contain secret material.
type SecretProtector interface {
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

// DPAPIProtector is a dependency-free Windows DPAPI implementation of
// SecretProtector (CryptProtectData/CryptUnprotectData with UI prompts
// forbidden). It performs no I/O of its own.
type DPAPIProtector struct {
	scope   DPAPIScope
	entropy []byte
}

// Compile-time interface assertion.
var _ SecretProtector = (*DPAPIProtector)(nil)

// Windows constants used by the DPAPI calls.
const (
	cryptProtectUIForbidden  = 0x1
	cryptProtectLocalMachine = 0x4
	maxEntropyBytes          = 1024
)

var (
	crypt32DLL             = syscall.NewLazyDLL("crypt32.dll")
	kernel32DLL            = syscall.NewLazyDLL("kernel32.dll")
	procCryptProtectData   = crypt32DLL.NewProc("CryptProtectData")
	procCryptUnprotectData = crypt32DLL.NewProc("CryptUnprotectData")
	procLocalFree          = kernel32DLL.NewProc("LocalFree")
)

// dataBlob mirrors the Win32 DATA_BLOB layout.
type dataBlob struct {
	cbData uint32
	pbData *byte
}

// NewDPAPIProtector creates a DPAPI protector for the given scope with optional
// caller-supplied entropy (a second, non-secret local binding factor). An empty
// entropy is allowed; oversized entropy is rejected.
func NewDPAPIProtector(scope DPAPIScope, entropy []byte) (*DPAPIProtector, error) {
	switch scope {
	case DPAPIUserScope, DPAPIMachineScope:
	default:
		return nil, errors.New("windowsagent: unsupported DPAPI scope")
	}
	if len(entropy) > maxEntropyBytes {
		return nil, errors.New("windowsagent: DPAPI entropy is larger than the local limit")
	}
	return &DPAPIProtector{scope: scope, entropy: append([]byte(nil), entropy...)}, nil
}

// Protect returns DPAPI-protected bytes for plaintext. Empty input is refused
// rather than silently protected.
func (p *DPAPIProtector) Protect(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("windowsagent: refusing to protect empty data")
	}
	var entropy dataBlob
	var entropyPtr *dataBlob
	if len(p.entropy) > 0 {
		entropy = blobOf(p.entropy)
		entropyPtr = &entropy
	}
	var output dataBlob
	flags := uint32(cryptProtectUIForbidden)
	if p.scope == DPAPIMachineScope {
		flags |= cryptProtectLocalMachine
	}
	input := blobOf(plaintext)
	ret, _, callErr := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&input)),
		0, // ppszDataDescr is not requested
		uintptr(unsafe.Pointer(entropyPtr)),
		0, // pvReserved is reserved
		0, // pPromptStruct: UI is forbidden
		uintptr(flags),
		uintptr(unsafe.Pointer(&output)),
	)
	if ret == 0 {
		return nil, dpapiError("protect", callErr)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(output.pbData)))
	return copyBlob(output), nil
}

// Unprotect decrypts bytes previously returned by Protect with the same scope
// and entropy.
func (p *DPAPIProtector) Unprotect(protected []byte) ([]byte, error) {
	if len(protected) == 0 {
		return nil, errors.New("windowsagent: refusing to unprotect empty data")
	}
	var entropy dataBlob
	var entropyPtr *dataBlob
	if len(p.entropy) > 0 {
		entropy = blobOf(p.entropy)
		entropyPtr = &entropy
	}
	var description *uint16
	var output dataBlob
	flags := uint32(cryptProtectUIForbidden)
	if p.scope == DPAPIMachineScope {
		flags |= cryptProtectLocalMachine
	}
	input := blobOf(protected)
	ret, _, callErr := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&input)),
		uintptr(unsafe.Pointer(&description)),
		uintptr(unsafe.Pointer(entropyPtr)),
		0, // pvReserved is reserved
		0, // pPromptStruct: UI is forbidden
		uintptr(flags),
		uintptr(unsafe.Pointer(&output)),
	)
	if ret == 0 {
		return nil, dpapiError("unprotect", callErr)
	}
	if description != nil {
		procLocalFree.Call(uintptr(unsafe.Pointer(description)))
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(output.pbData)))
	return copyBlob(output), nil
}

// ServiceHost is the ADR hook for a future reviewed Windows service wrapper
// around agent.Runtime. This Draft intentionally provides no implementation:
// account/session/ACL, event-log source, DPAPI scope and installer behavior are
// OD-P7 decisions and remain PENDING. cmd/um-agent reports the deferred state.
type ServiceHost interface {
	// Run blocks until the service is asked to stop or fails closed.
	Run(ctx context.Context) error
}

// blobOf returns a Win32 DATA_BLOB pointing at data. The caller must keep data
// alive for the duration of the Win32 call.
func blobOf(data []byte) dataBlob {
	return dataBlob{cbData: uint32(len(data)), pbData: &data[0]}
}

// copyBlob copies a Win32 output buffer into Go memory before LocalFree.
func copyBlob(blob dataBlob) []byte {
	if blob.cbData == 0 || blob.pbData == nil {
		return []byte{}
	}
	out := make([]byte, int(blob.cbData))
	copy(out, unsafe.Slice(blob.pbData, int(blob.cbData)))
	return out
}

// dpapiError maps a failed Win32 call to an error that carries no secret or
// protected payload content.
func dpapiError(operation string, callErr error) error {
	if callErr != nil && !errors.Is(callErr, syscall.Errno(0)) {
		return fmt.Errorf("windowsagent: DPAPI %s failed (%v)", operation, callErr)
	}
	return fmt.Errorf("windowsagent: DPAPI %s failed", operation)
}

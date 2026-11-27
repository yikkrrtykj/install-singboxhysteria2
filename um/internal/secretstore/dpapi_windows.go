//go:build windows

// Windows DPAPI implementation of the shared secretstore.Protector seam.
//
// STATUS: ADR scaffolding only. OD-P7 ("Windows Agent 运行账户与 secret 存储
// (DPAPI/服务账户/用户会话)", docs/um/um-127/05-owner-decisions.md) is PENDING.
// This file only provides an injected in-process protector: it does not create a
// service account, install or query a service, read an environment variable or
// registry secret, or provision an R1 controller credential. The default user
// scope needs no service account; the machine scope is Owner/OD-P7-gated.
//
// It is dependency-free (stdlib syscall + crypt32.dll/kernel32.dll) and is
// exercised only by Windows unit tests using synthetic plaintext.

package secretstore

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

// Windows constants used by the DPAPI calls.
const (
	cryptProtectUIForbidden  = 0x1
	cryptProtectLocalMachine = 0x4
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

// NewDPAPIProtector creates a Windows DPAPI protector for the given scope with
// optional caller-supplied entropy (a second, non-secret local binding factor).
// An empty entropy is allowed; oversized entropy and unknown scopes are
// rejected. DPAPIUserScope is the default; DPAPIMachineScope must be requested
// explicitly and is OD-P7-gated for production credentials. Construction does
// not call Win32, so it never prompts the user or needs an elevated token.
func NewDPAPIProtector(scope DPAPIScope, entropy []byte) (*DPAPIProtector, error) {
	switch scope {
	case DPAPIUserScope, DPAPIMachineScope:
	default:
		return nil, errors.New("secretstore: unsupported DPAPI scope")
	}
	if len(entropy) > maxEntropyBytes {
		return nil, errors.New("secretstore: DPAPI entropy is larger than the local limit")
	}
	return &DPAPIProtector{scope: scope, entropy: append([]byte(nil), entropy...)}, nil
}

// Protect returns DPAPI-protected bytes for plaintext. Empty input is refused
// rather than silently protected. The returned protected bytes are a fresh copy
// owned by the caller.
func (p *DPAPIProtector) Protect(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("secretstore: refusing to protect empty data")
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
// and entropy. Empty input is refused. The returned plaintext is a fresh copy
// owned by the caller; callers must not log it.
func (p *DPAPIProtector) Unprotect(protected []byte) ([]byte, error) {
	if len(protected) == 0 {
		return nil, errors.New("secretstore: refusing to unprotect empty data")
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
		return fmt.Errorf("secretstore: DPAPI %s failed (%v)", operation, callErr)
	}
	return fmt.Errorf("secretstore: DPAPI %s failed", operation)
}

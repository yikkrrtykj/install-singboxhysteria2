package umcauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
)

// AES-256-GCM master-key vault.
//
// The master key is 32 raw random bytes stored in a dedicated file that must be
// protected by the platform's file-permission model: on POSIX the mode must be
// 0600 or 0400 and the owner must be the current effective user; on Windows the
// DACL may only allow the file owner, the current service account, LocalSystem
// and Builtin Administrators. Symlinks and other non-regular files are
// rejected.
//
// Sealed blobs are versioned:
//
//	v1 | 12-byte random nonce | AES-256-GCM ciphertext and tag
//
// The format version and a fixed domain-separation prefix are bound into the
// GCM associated data, so a wrong key, a modified nonce/ciphertext, a modified
// caller AAD or a modified version byte all fail authentication. No key
// material, plaintext or AAD is included in error values.
const (
	// MasterKeyBytes is the required master-key size in bytes (AES-256).
	MasterKeyBytes = 32

	vaultVersion1  = byte(1)
	vaultAADPrefix = "umcauth:vault:"
)

// Vault errors. They never contain key material, plaintext or associated data.
var (
	// ErrMasterKeyFile reports a missing, non-regular, symlinked or wrongly
	// sized master-key file.
	ErrMasterKeyFile = errors.New("umcauth: invalid master key file")
	// ErrMasterKeyPermissions reports a master-key file whose POSIX mode/owner
	// or Windows DACL does not protect it.
	ErrMasterKeyPermissions = errors.New("umcauth: master key file permissions are not protected")
	// ErrMasterKeyExists reports GenerateMasterKeyFile refusing to overwrite an
	// existing path.
	ErrMasterKeyExists = errors.New("umcauth: master key file already exists")
	// ErrInvalidMasterKey reports a master key that is not exactly 32 bytes.
	ErrInvalidMasterKey = errors.New("umcauth: invalid master key")
	// ErrSealedData reports a sealed blob that is truncated, has been tampered
	// with, was sealed with another key or was opened with the wrong AAD.
	ErrSealedData = errors.New("umcauth: sealed data is invalid")
	// ErrUnsupportedVaultVersion reports a sealed blob with an unknown format
	// version.
	ErrUnsupportedVaultVersion = errors.New("umcauth: unsupported vault format version")
)

// LoadMasterKey reads a 32-byte master key from path after validating that it
// is a regular, non-symlink file protected by the platform permission model.
// The returned slice is the key material: callers must keep it in memory only,
// should clear it when done, and must never log or persist it in plaintext.
func LoadMasterKey(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("%w: empty path", ErrMasterKeyFile)
	}
	lstat, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMasterKeyFile, err)
	}
	if lstat.Mode()&os.ModeSymlink != 0 || !lstat.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: must be a regular file, not a symlink", ErrMasterKeyFile)
	}

	f, err := openMasterKeyFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMasterKeyFile, err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMasterKeyFile, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: must be a regular file", ErrMasterKeyFile)
	}
	if err := checkMasterKeyFilePermissions(path, info, f); err != nil {
		return nil, err
	}
	if info.Size() != MasterKeyBytes {
		return nil, fmt.Errorf("%w: must contain exactly %d bytes", ErrMasterKeyFile, MasterKeyBytes)
	}

	key := make([]byte, MasterKeyBytes)
	if _, err := io.ReadFull(f, key); err != nil {
		clear(key)
		return nil, fmt.Errorf("%w: could not read %d bytes", ErrMasterKeyFile, MasterKeyBytes)
	}
	// The file must end exactly after the key: an oversized file is not the
	// protected 32-byte key file we expect, even if the size raced since Stat.
	var extra [1]byte
	if n, err := f.Read(extra[:]); n != 0 || !errors.Is(err, io.EOF) {
		clear(key)
		return nil, fmt.Errorf("%w: unexpected trailing data", ErrMasterKeyFile)
	}
	return key, nil
}

// GenerateMasterKeyFile atomically creates path with exactly 32 random bytes,
// mode 0600 and a platform-protected ACL, refusing to overwrite an existing
// file. After success the key is loaded with LoadMasterKey.
func GenerateMasterKeyFile(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%w: empty path", ErrMasterKeyFile)
	}

	key := make([]byte, MasterKeyBytes)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return fmt.Errorf("umcauth: generate master key: %w", err)
	}
	defer clear(key)

	// O_EXCL makes the existence check and creation atomic: exactly one caller
	// can win, and an existing key file is never truncated or replaced.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) || os.IsExist(err) {
			return fmt.Errorf("%w: refusing to overwrite", ErrMasterKeyExists)
		}
		return fmt.Errorf("umcauth: create master key file: %w", err)
	}
	removeOnFailure := true
	closed := false
	defer func() {
		if !closed {
			_ = f.Close()
		}
		if removeOnFailure {
			_ = os.Remove(path)
		}
	}()

	if err := hardenMasterKeyFile(f, path); err != nil {
		return err
	}
	written, err := f.Write(key)
	if err != nil {
		return fmt.Errorf("umcauth: write master key file: %w", err)
	}
	if written != len(key) {
		return fmt.Errorf("umcauth: short write to master key file")
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("umcauth: sync master key file: %w", err)
	}
	if err := f.Close(); err != nil {
		closed = true
		return fmt.Errorf("umcauth: close master key file: %w", err)
	}
	closed = true
	removeOnFailure = false
	return nil
}

// Seal encrypts plaintext with key (exactly 32 bytes) using AES-256-GCM and a
// fresh random nonce, returning the versioned blob described in the package
// documentation. aad is authenticated but not encrypted and may be nil.
func Seal(key, plaintext, aad []byte) ([]byte, error) {
	aead, err := newVaultAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("umcauth: generate vault nonce: %w", err)
	}
	blob := make([]byte, 0, 1+len(nonce)+len(plaintext)+aead.Overhead())
	blob = append(blob, vaultVersion1)
	blob = append(blob, nonce...)
	blob = aead.Seal(blob, nonce, plaintext, vaultAssociatedData(vaultVersion1, aad))
	return blob, nil
}

// Open authenticates and decrypts a blob produced by Seal with the same key and
// AAD. It fails closed on wrong key, wrong AAD, truncation, tampering or an
// unsupported format version; the returned error never contains plaintext or
// key material.
func Open(key, blob, aad []byte) ([]byte, error) {
	aead, err := newVaultAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < 1+aead.NonceSize()+aead.Overhead() {
		return nil, fmt.Errorf("%w: ciphertext is truncated", ErrSealedData)
	}
	version := blob[0]
	if version != vaultVersion1 {
		return nil, fmt.Errorf("%w: version %d", ErrUnsupportedVaultVersion, version)
	}
	nonce := blob[1 : 1+aead.NonceSize()]
	ciphertext := blob[1+aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, vaultAssociatedData(version, aad))
	if err != nil {
		return nil, fmt.Errorf("%w: authentication failed", ErrSealedData)
	}
	return plaintext, nil
}

func newVaultAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != MasterKeyBytes {
		return nil, fmt.Errorf("%w: must be exactly %d bytes", ErrInvalidMasterKey, MasterKeyBytes)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidMasterKey, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidMasterKey, err)
	}
	return aead, nil
}

// vaultAssociatedData binds the format version and domain-separation prefix
// into the GCM tag together with the caller's AAD.
func vaultAssociatedData(version byte, aad []byte) []byte {
	out := make([]byte, 0, len(vaultAADPrefix)+1+len(aad))
	out = append(out, vaultAADPrefix...)
	out = append(out, version)
	out = append(out, aad...)
	return out
}

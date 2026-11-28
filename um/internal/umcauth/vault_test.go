package umcauth

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func newMasterKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, MasterKeyBytes)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("generate test master key: %v", err)
	}
	return key
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := newMasterKey(t)
	plaintext := []byte("totp-secret-and-other-protected-state")
	aad := []byte("admin-user:42")

	blob, err := Seal(key, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(blob) != 1+12+len(plaintext)+16 {
		t.Fatalf("sealed blob length = %d, want %d", len(blob), 1+12+len(plaintext)+16)
	}
	if blob[0] != vaultVersion1 {
		t.Fatalf("sealed blob version = %d, want %d", blob[0], vaultVersion1)
	}
	if bytes.Contains(blob, plaintext) {
		t.Fatal("sealed blob contains the plaintext")
	}

	opened, err := Open(key, blob, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("Open = %q, want %q", opened, plaintext)
	}

	secondBlob, err := Seal(key, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal (second): %v", err)
	}
	if bytes.Equal(blob, secondBlob) {
		t.Fatal("two seals of the same plaintext are identical; nonce is not random")
	}

	// Empty plaintext and nil AAD are supported.
	emptyBlob, err := Seal(key, nil, nil)
	if err != nil {
		t.Fatalf("Seal(empty): %v", err)
	}
	empty, err := Open(key, emptyBlob, nil)
	if err != nil {
		t.Fatalf("Open(empty): %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("Open(empty) returned %d bytes, want 0", len(empty))
	}
}

func TestOpenRejectsWrongKeyAndAAD(t *testing.T) {
	key := newMasterKey(t)
	plaintext := []byte("protected payload")
	blob, err := Seal(key, plaintext, []byte("aad-one"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := Open(newMasterKey(t), blob, []byte("aad-one")); !errors.Is(err, ErrSealedData) {
		t.Fatalf("Open(wrong key) error = %v, want ErrSealedData", err)
	}
	if _, err := Open(key, blob, []byte("aad-two")); !errors.Is(err, ErrSealedData) {
		t.Fatalf("Open(wrong AAD) error = %v, want ErrSealedData", err)
	}
	if _, err := Open(key, blob, nil); !errors.Is(err, ErrSealedData) {
		t.Fatalf("Open(missing AAD) error = %v, want ErrSealedData", err)
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	key := newMasterKey(t)
	plaintext := []byte("protected payload")
	aad := []byte("aad")
	blob, err := Seal(key, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	tamperedVersion := append([]byte{}, blob...)
	tamperedVersion[0] = 2
	if _, err := Open(key, tamperedVersion, aad); !errors.Is(err, ErrUnsupportedVaultVersion) {
		t.Fatalf("Open(version 2) error = %v, want ErrUnsupportedVaultVersion", err)
	}

	tamperedNonce := append([]byte{}, blob...)
	tamperedNonce[1] ^= 0xff
	if _, err := Open(key, tamperedNonce, aad); !errors.Is(err, ErrSealedData) {
		t.Fatalf("Open(tampered nonce) error = %v, want ErrSealedData", err)
	}

	tamperedCiphertext := append([]byte{}, blob...)
	tamperedCiphertext[len(tamperedCiphertext)-1] ^= 0x80
	if _, err := Open(key, tamperedCiphertext, aad); !errors.Is(err, ErrSealedData) {
		t.Fatalf("Open(tampered ciphertext) error = %v, want ErrSealedData", err)
	}

	tamperedAAD := append([]byte{}, aad...)
	tamperedAAD[0] ^= 0x01
	if _, err := Open(key, blob, tamperedAAD); !errors.Is(err, ErrSealedData) {
		t.Fatalf("Open(tampered AAD) error = %v, want ErrSealedData", err)
	}
}

func TestSealOpenRejectInvalidMasterKey(t *testing.T) {
	for _, size := range []int{0, 1, 16, 31, 33, 64} {
		key := make([]byte, size)
		if _, err := Seal(key, []byte("data"), nil); !errors.Is(err, ErrInvalidMasterKey) {
			t.Fatalf("Seal(key len %d) error = %v, want ErrInvalidMasterKey", size, err)
		}
		if _, err := Open(key, make([]byte, 1+12+16), nil); !errors.Is(err, ErrInvalidMasterKey) {
			t.Fatalf("Open(key len %d) error = %v, want ErrInvalidMasterKey", size, err)
		}
	}
}

func TestOpenRejectsTruncatedBlob(t *testing.T) {
	key := newMasterKey(t)
	for _, length := range []int{0, 1, 12, 28} {
		if _, err := Open(key, make([]byte, length), nil); !errors.Is(err, ErrSealedData) {
			t.Fatalf("Open(blob len %d) error = %v, want ErrSealedData", length, err)
		}
	}
}

func TestVaultErrorsDoNotContainSecrets(t *testing.T) {
	key := newMasterKey(t)
	plaintext := []byte("super-secret-totp-key-material")
	blob, err := Seal(key, plaintext, nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	_, err = Open(newMasterKey(t), blob, nil)
	if err == nil {
		t.Fatal("Open(wrong key) returned nil error")
	}
	if strings.Contains(err.Error(), string(plaintext)) {
		t.Fatalf("error contains plaintext: %v", err)
	}
	if strings.Contains(err.Error(), string(key)) {
		t.Fatalf("error contains master key: %v", err)
	}
}

func TestLoadAndGenerateMasterKeyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "master.key")

	if err := GenerateMasterKeyFile(path); err != nil {
		t.Fatalf("GenerateMasterKeyFile: %v", err)
	}
	firstKey, err := LoadMasterKey(path)
	if err != nil {
		t.Fatalf("LoadMasterKey: %v", err)
	}
	if len(firstKey) != MasterKeyBytes {
		t.Fatalf("loaded key length = %d, want %d", len(firstKey), MasterKeyBytes)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Size() != MasterKeyBytes {
		t.Fatalf("master key file size = %d, want %d", info.Size(), MasterKeyBytes)
	}

	// A second generation must refuse to overwrite and leave the key intact.
	if err := GenerateMasterKeyFile(path); !errors.Is(err, ErrMasterKeyExists) {
		t.Fatalf("second GenerateMasterKeyFile error = %v, want ErrMasterKeyExists", err)
	}
	secondLoad, err := LoadMasterKey(path)
	if err != nil {
		t.Fatalf("LoadMasterKey after refused overwrite: %v", err)
	}
	if !bytes.Equal(firstKey, secondLoad) {
		t.Fatal("refused overwrite changed the master key")
	}

	// A fresh path gets a different random key.
	otherPath := filepath.Join(dir, "other.key")
	if err := GenerateMasterKeyFile(otherPath); err != nil {
		t.Fatalf("GenerateMasterKeyFile(other): %v", err)
	}
	otherKey, err := LoadMasterKey(otherPath)
	if err != nil {
		t.Fatalf("LoadMasterKey(other): %v", err)
	}
	if bytes.Equal(firstKey, otherKey) {
		t.Fatal("two generated master keys are identical")
	}

	// Round-trip a sealed value through the generated key file.
	blob, err := Seal(firstKey, []byte("protected"), []byte("aad"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	opened, err := Open(secondLoad, blob, []byte("aad"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(opened) != "protected" {
		t.Fatalf("Open = %q, want %q", opened, "protected")
	}
}

func TestLoadMasterKeyRejectsMissingAndWrongSize(t *testing.T) {
	dir := t.TempDir()

	if _, err := LoadMasterKey(""); !errors.Is(err, ErrMasterKeyFile) {
		t.Fatalf("LoadMasterKey(empty) error = %v, want ErrMasterKeyFile", err)
	}
	if _, err := LoadMasterKey(filepath.Join(dir, "missing.key")); !errors.Is(err, ErrMasterKeyFile) {
		t.Fatalf("LoadMasterKey(missing) error = %v, want ErrMasterKeyFile", err)
	}
	if _, err := LoadMasterKey(dir); !errors.Is(err, ErrMasterKeyFile) {
		t.Fatalf("LoadMasterKey(directory) error = %v, want ErrMasterKeyFile", err)
	}

	for _, size := range []int{0, 31, 33, 64} {
		path := filepath.Join(dir, "wrong-size-"+strconv.Itoa(size)+".key")
		if err := GenerateMasterKeyFile(path); err != nil {
			t.Fatalf("GenerateMasterKeyFile: %v", err)
		}
		if err := os.WriteFile(path, make([]byte, size), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := LoadMasterKey(path); !errors.Is(err, ErrMasterKeyFile) {
			t.Fatalf("LoadMasterKey(size %d) error = %v, want ErrMasterKeyFile", size, err)
		}
	}
}

func TestGenerateMasterKeyFileRejectsInvalidPath(t *testing.T) {
	if err := GenerateMasterKeyFile(""); !errors.Is(err, ErrMasterKeyFile) {
		t.Fatalf("GenerateMasterKeyFile(empty) error = %v, want ErrMasterKeyFile", err)
	}
	missingParent := filepath.Join(t.TempDir(), "does", "not", "exist", "master.key")
	if err := GenerateMasterKeyFile(missingParent); err == nil {
		t.Fatal("GenerateMasterKeyFile with a missing parent directory returned nil error")
	}
}

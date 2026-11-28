// Package fileguard enforces the local protection model for center-owned
// security files: a private directory plus regular files readable only by the
// service owner. POSIX uses mode/owner checks; Windows uses a closed DACL.
// It is used for the SQLite database/WAL/SHM and TLS private keys. Master-key
// and B4 auth/token files have their own existing validators.
package fileguard

import "errors"

var (
	// ErrUnprotected reports a path whose mode/DACL/owner is not private.
	ErrUnprotected = errors.New("fileguard: path is not privately protected")
	// ErrUnsafePath reports a symlink, reparse point or non-regular path.
	ErrUnsafePath = errors.New("fileguard: path is a symlink/reparse point or wrong type")
)

// EnsurePrivateDir creates (if needed) and hardens a private service directory.
func EnsurePrivateDir(path string) error { return ensurePrivateDir(path) }

// EnsurePrivateFile hardens an existing regular security file.
func EnsurePrivateFile(path string) error { return ensurePrivateFile(path) }

// CheckPrivateFile rejects symlinks/reparse points and verifies that only the
// service owner (and trusted OS principals on Windows) can read the file.
func CheckPrivateFile(path string) error { return checkPrivateFile(path) }

// CheckPrivateDir verifies the directory has no symlink/reparse traversal and
// only the service owner (plus trusted OS principals on Windows) can access it.
func CheckPrivateDir(path string) error { return checkPrivateDir(path) }

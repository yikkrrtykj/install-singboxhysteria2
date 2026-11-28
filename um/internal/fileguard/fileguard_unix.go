//go:build !windows

package fileguard

import (
	"fmt"
	"os"
	"syscall"
)

func ensurePrivateDir(path string) error {
	if info, err := os.Lstat(path); err == nil {
		// Never rewrite the mode of an operator-supplied existing directory. It
		// must already be private; otherwise fail closed and let the operator fix
		// its ownership/permissions explicitly.
		return checkInfo(path, info, true)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("fileguard: stat directory: %w", err)
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("fileguard: create private directory: %w", err)
	}
	return hardenPath(path, true)
}

func ensurePrivateFile(path string) error {
	return hardenPath(path, false)
}

func hardenPath(path string, dir bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("fileguard: stat path: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return ErrUnsafePath
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return ErrUnprotected
	}
	if dir {
		if !info.IsDir() {
			return ErrUnsafePath
		}
		if err := os.Chmod(path, 0o700); err != nil {
			return fmt.Errorf("fileguard: chmod directory: %w", err)
		}
	} else {
		if !info.Mode().IsRegular() {
			return ErrUnsafePath
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("fileguard: chmod file: %w", err)
		}
	}
	info, err = os.Lstat(path)
	if err != nil {
		return fmt.Errorf("fileguard: restat path: %w", err)
	}
	if err := checkInfo(path, info, dir); err != nil {
		return err
	}
	return nil
}

func checkPrivateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("fileguard: stat file: %w", err)
	}
	return checkInfo(path, info, false)
}

func checkPrivateDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("fileguard: stat directory: %w", err)
	}
	return checkInfo(path, info, true)
}

func checkInfo(path string, info os.FileInfo, dir bool) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return ErrUnsafePath
	}
	if dir {
		if !info.IsDir() {
			return ErrUnsafePath
		}
		if info.Mode().Perm()&0o077 != 0 {
			return ErrUnprotected
		}
	} else {
		if !info.Mode().IsRegular() {
			return ErrUnsafePath
		}
		if info.Mode().Perm()&0o077 != 0 {
			return ErrUnprotected
		}
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return ErrUnprotected
	}
	return nil
}

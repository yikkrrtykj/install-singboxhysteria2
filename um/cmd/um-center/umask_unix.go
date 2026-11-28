//go:build !windows

package main

import "syscall"

// hardenProcessUmask ensures SQLite/WAL/SHM and other service-created files are
// private from creation even if the caller's inherited umask was permissive.
func hardenProcessUmask() { _ = syscall.Umask(0o077) }

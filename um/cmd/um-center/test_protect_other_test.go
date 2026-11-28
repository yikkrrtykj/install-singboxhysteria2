//go:build !windows

package main

import "testing"

func protectTestFile(t *testing.T, path string) {
	t.Helper()
	_ = path
}

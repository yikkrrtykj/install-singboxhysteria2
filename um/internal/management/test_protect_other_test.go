//go:build !windows

package management_test

import "testing"

func protectTestFile(t *testing.T, path string) {
	t.Helper()
	_ = path
}

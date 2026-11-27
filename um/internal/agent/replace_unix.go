//go:build !windows

package agent

import "os"

func replaceFile(oldPath, newPath string) error { return os.Rename(oldPath, newPath) }

//go:build !windows

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "um-lab-service: Windows-only lab helper")
	os.Exit(1)
}

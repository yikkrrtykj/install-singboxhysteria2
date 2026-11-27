package windowsagent

import (
	"crypto/rand"
	"fmt"
)

// newUUIDv4 returns a canonical lowercase UUIDv4 for contract event ids. It
// uses crypto/rand only (no external dependency); failures are reported to the
// caller instead of emitting a non-contract id.
func newUUIDv4() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40 // version 4
	raw[8] = (raw[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16]), nil
}

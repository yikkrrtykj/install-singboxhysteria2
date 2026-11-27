package linuxobs

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Limits used to detect overflow while summing kernel counters without
// importing platform-specific integer aliases.
const (
	maxUint64Value = ^uint64(0)
	maxInt64Value  = int64(^uint64(0) >> 1)
)

// errMalformedProc is returned when a local kernel file does not have the
// documented shape. The offending bytes are never echoed.
var errMalformedProc = errors.New("linuxobs: malformed proc data")

// firstLine returns the first line of data without the trailing newline.
func firstLine(data []byte) string {
	text := string(data)
	if index := strings.IndexByte(text, '\n'); index >= 0 {
		return text[:index]
	}
	return text
}

// parseCPUPercent parses the aggregate "cpu" line of /proc/stat and returns
// the busy ratio since boot as a percentage. user/nice/system/irq/softirq/steal
// count as busy; idle and iowait do not. The guest and guest_nice columns are
// already included in user/nice and are ignored to avoid double counting.
func parseCPUPercent(data []byte) (float64, error) {
	fields := strings.Fields(firstLine(data))
	if len(fields) < 9 || fields[0] != "cpu" {
		return 0, errMalformedProc
	}
	var values [8]uint64
	for index := 0; index < len(values); index++ {
		value, err := strconv.ParseUint(fields[index+1], 10, 64)
		if err != nil {
			return 0, errMalformedProc
		}
		values[index] = value
	}
	var total uint64
	for _, value := range values {
		sum, ok := safeAddUint64(total, value)
		if !ok {
			return 0, errMalformedProc
		}
		total = sum
	}
	idle, ok := safeAddUint64(values[3], values[4]) // idle + iowait
	if !ok || total == 0 || idle > total {
		return 0, errMalformedProc
	}
	percent := float64(total-idle) / float64(total) * 100
	if math.IsNaN(percent) || math.IsInf(percent, 0) || percent < 0 || percent >= 10000 {
		return 0, errMalformedProc
	}
	return percent, nil
}

// parseLoadAverage parses the 1-minute load average from /proc/loadavg.
func parseLoadAverage(data []byte) (float64, error) {
	fields := strings.Fields(firstLine(data))
	if len(fields) == 0 {
		return 0, errMalformedProc
	}
	value, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value >= 100000 {
		return 0, errMalformedProc
	}
	return value, nil
}

// memInfoValues is the partial result of parsing /proc/meminfo. A nil field is
// unavailable, never zero.
type memInfoValues struct {
	total *int64
	used  *int64
}

// parseMemInfo parses MemTotal/MemAvailable from /proc/meminfo. "used" is
// MemTotal - MemAvailable (the conventional available-memory definition); when
// MemAvailable is absent it stays nil instead of falling back to a different
// semantic.
func parseMemInfo(data []byte) memInfoValues {
	kilobytes := make(map[string]uint64)
	for _, line := range strings.Split(string(data), "\n") {
		key, raw, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		fields := strings.Fields(raw)
		if len(fields) == 0 {
			continue
		}
		if len(fields) >= 2 && fields[1] != "kB" {
			continue
		}
		value, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		kilobytes[key] = value
	}

	var result memInfoValues
	totalKB, hasTotal := kilobytes["MemTotal"]
	if hasTotal {
		if bytes, ok := kilobytesToBytes(totalKB); ok {
			value := bytes
			result.total = &value
		}
	}
	availableKB, hasAvailable := kilobytes["MemAvailable"]
	if hasTotal && hasAvailable && availableKB <= totalKB {
		if bytes, ok := kilobytesToBytes(totalKB - availableKB); ok {
			value := bytes
			result.used = &value
		}
	}
	return result
}

// parseNetDevCounters parses /proc/net/dev and sums receive/transmit bytes
// across non-loopback interfaces. Loopback traffic is not external host
// traffic, so it is excluded. At least one non-loopback interface must be
// observed for the result to be considered available.
func parseNetDevCounters(data []byte) (uint64, uint64, error) {
	var rxTotal, txTotal uint64
	interfaces := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, raw, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		fields := strings.Fields(raw)
		if len(fields) < 9 {
			return 0, 0, errMalformedProc
		}
		rx, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return 0, 0, errMalformedProc
		}
		tx, err := strconv.ParseUint(fields[8], 10, 64)
		if err != nil {
			return 0, 0, errMalformedProc
		}
		if name == "lo" {
			continue
		}
		if rxTotal, ok = safeAddUint64(rxTotal, rx); !ok {
			return 0, 0, errMalformedProc
		}
		if txTotal, ok = safeAddUint64(txTotal, tx); !ok {
			return 0, 0, errMalformedProc
		}
		interfaces++
	}
	if interfaces == 0 {
		return 0, 0, errMalformedProc
	}
	return rxTotal, txTotal, nil
}

// parseUptimeSeconds parses the first field of /proc/uptime.
func parseUptimeSeconds(data []byte) (float64, error) {
	fields := strings.Fields(firstLine(data))
	if len(fields) == 0 {
		return 0, errMalformedProc
	}
	value, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
		return 0, errMalformedProc
	}
	return value, nil
}

// parseProcessStartTicks parses field 22 (starttime, in clock ticks since
// boot) of a /proc/<pid>/stat document. The comm field may contain spaces and
// parentheses, so parsing starts after the last ')'.
func parseProcessStartTicks(data []byte) (uint64, error) {
	text := strings.TrimSpace(string(data))
	closeIndex := strings.LastIndexByte(text, ')')
	if closeIndex < 0 {
		return 0, errMalformedProc
	}
	fields := strings.Fields(text[closeIndex+1:])
	const startTimeField = 22
	const firstFieldAfterComm = 3
	index := startTimeField - firstFieldAfterComm
	if len(fields) <= index {
		return 0, errMalformedProc
	}
	value, err := strconv.ParseUint(fields[index], 10, 64)
	if err != nil {
		return 0, errMalformedProc
	}
	return value, nil
}

// normalizeBootID converts a canonical boot id (32 hex or UUID-shaped) to the
// frozen 32-lowercase-hex counter-epoch grammar. Anything else returns "".
func normalizeBootID(data []byte) string {
	value := strings.ToLower(strings.TrimSpace(string(data)))
	if isLowerHex32(value) {
		return value
	}
	if len(value) == 36 && value[8] == '-' && value[13] == '-' &&
		value[18] == '-' && value[23] == '-' {
		candidate := value[:8] + value[9:13] + value[14:18] + value[19:23] + value[24:]
		if isLowerHex32(candidate) {
			return candidate
		}
	}
	return ""
}

// isLowerHex32 reports whether value is exactly 32 lowercase hex characters.
func isLowerHex32(value string) bool {
	if len(value) != 32 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

// validKernelRelease enforces the frozen host.kernel grammar and 64-byte cap.
func validKernelRelease(kernel string) bool {
	if len(kernel) == 0 || len(kernel) > 64 {
		return false
	}
	for index := 0; index < len(kernel); index++ {
		character := kernel[index]
		switch {
		case character >= '0' && character <= '9',
			character >= 'A' && character <= 'Z',
			character >= 'a' && character <= 'z',
			character == '.', character == '+', character == '-':
		default:
			return false
		}
	}
	return true
}

// safeAddUint64 adds two kernel counters, reporting overflow instead of
// wrapping.
func safeAddUint64(left, right uint64) (uint64, bool) {
	if right > maxUint64Value-left {
		return 0, false
	}
	return left + right, true
}

// kilobytesToBytes converts a /proc/meminfo kB value to bytes when the result
// fits the contract's integer range.
func kilobytesToBytes(kilobytes uint64) (int64, bool) {
	if kilobytes > uint64(maxInt64Value/1024) {
		return 0, false
	}
	return int64(kilobytes * 1024), true
}

// readKernelRelease reads the kernel release string from procfs.
func readKernelRelease(procRoot string) (string, error) {
	data, err := os.ReadFile(filepath.Join(procRoot, "sys", "kernel", "osrelease"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// readCounterEpoch derives the counter epoch from the procfs boot id. The
// all-zero epoch means "boot id unavailable"; it is a documented contract
// placeholder, not fabricated host identity.
func readCounterEpoch(procRoot string) string {
	data, err := os.ReadFile(filepath.Join(procRoot, "sys", "kernel", "random", "boot_id"))
	if err != nil {
		return zeroCounterEpoch
	}
	if epoch := normalizeBootID(data); epoch != "" {
		return epoch
	}
	return zeroCounterEpoch
}

// readUint64File reads one decimal kernel counter file.
func readUint64File(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, errMalformedProc
	}
	return value, nil
}

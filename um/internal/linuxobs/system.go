package linuxobs

import (
	"fmt"
	"os"
	"path/filepath"
)

// systemValues is the frozen snapshot system object. Nil fields are
// unavailable values (rendered as JSON null), never zero.
type systemValues struct {
	CPUPercent     *float64 `json:"cpu_pct"`
	Load1          *float64 `json:"load1"`
	MemTotalBytes  *int64   `json:"mem_total_bytes"`
	MemUsedBytes   *int64   `json:"mem_used_bytes"`
	DiskTotalBytes *int64   `json:"disk_total_bytes"`
	DiskUsedBytes  *int64   `json:"disk_used_bytes"`
	NetRxBytes     *int64   `json:"net_rx_bytes"`
	NetTxBytes     *int64   `json:"net_tx_bytes"`
}

// observedFields counts the eight frozen system fields that were actually
// observed.
func (values systemValues) observedFields() int {
	count := 0
	if values.CPUPercent != nil {
		count++
	}
	if values.Load1 != nil {
		count++
	}
	if values.MemTotalBytes != nil {
		count++
	}
	if values.MemUsedBytes != nil {
		count++
	}
	if values.DiskTotalBytes != nil {
		count++
	}
	if values.DiskUsedBytes != nil {
		count++
	}
	if values.NetRxBytes != nil {
		count++
	}
	if values.NetTxBytes != nil {
		count++
	}
	return count
}

// availability projects the frozen availability.system coherence rule:
// ok => all fields present, partial => at least one present and one missing,
// unavailable => no field present.
func (values systemValues) availability() string {
	switch values.observedFields() {
	case 0:
		return availabilityUnavailable
	case 8:
		return availabilityOK
	default:
		return availabilityPartial
	}
}

// readSystemValues reads every system field independently. A failed source
// only nulls its own fields; it never fake-zeros another one.
func (c *Collector) readSystemValues() systemValues {
	var values systemValues
	procRoot := c.procRoot()

	if data, err := os.ReadFile(filepath.Join(procRoot, "stat")); err == nil {
		if percent, err := parseCPUPercent(data); err == nil {
			value := percent
			values.CPUPercent = &value
		}
	}

	if data, err := os.ReadFile(filepath.Join(procRoot, "loadavg")); err == nil {
		if load, err := parseLoadAverage(data); err == nil {
			value := load
			values.Load1 = &value
		}
	}

	if data, err := os.ReadFile(filepath.Join(procRoot, "meminfo")); err == nil {
		memory := parseMemInfo(data)
		if memory.total != nil && *memory.total >= 1 && *memory.total <= maxContractSizeBytes {
			value := *memory.total
			values.MemTotalBytes = &value
		}
		if memory.used != nil && *memory.used >= 0 && *memory.used <= maxContractSizeBytes {
			value := *memory.used
			values.MemUsedBytes = &value
		}
	}

	if total, used, err := c.diskProbe().Usage(); err == nil &&
		total >= 1 && total <= uint64(maxContractSizeBytes) && used <= total {
		value := int64(total)
		values.DiskTotalBytes = &value
		usedValue := int64(used)
		values.DiskUsedBytes = &usedValue
	}

	if rx, tx, err := c.netCounters(); err == nil {
		if rx <= uint64(maxContractCounter) {
			value := int64(rx)
			values.NetRxBytes = &value
		}
		if tx <= uint64(maxContractCounter) {
			value := int64(tx)
			values.NetTxBytes = &value
		}
	}

	return values
}

// netCounters prefers /proc/net/dev and falls back to sysfs interface
// statistics only when the procfs document is unreadable. It never runs a
// subprocess and never opens a socket.
func (c *Collector) netCounters() (uint64, uint64, error) {
	if data, err := os.ReadFile(filepath.Join(c.procRoot(), "net", "dev")); err == nil {
		return parseNetDevCounters(data)
	}
	return readSysfsNetCounters(c.sysRoot())
}

// readSysfsNetCounters sums rx_bytes/tx_bytes across non-loopback interfaces
// exposed by sysfs. A candidate is considered only when its statistics
// directory exists; any unreadable interface counter fails the whole
// observation rather than under-reporting a partial sum.
func readSysfsNetCounters(sysRoot string) (uint64, uint64, error) {
	classDir := filepath.Join(sysRoot, "class", "net")
	entries, err := os.ReadDir(classDir)
	if err != nil {
		return 0, 0, err
	}
	var rxTotal, txTotal uint64
	interfaces := 0
	for _, entry := range entries {
		name := entry.Name()
		if name == "lo" {
			continue
		}
		statisticsDir := filepath.Join(classDir, name, "statistics")
		info, err := os.Stat(statisticsDir)
		if err != nil || !info.IsDir() {
			continue
		}
		rx, err := readUint64File(filepath.Join(statisticsDir, "rx_bytes"))
		if err != nil {
			return 0, 0, err
		}
		tx, err := readUint64File(filepath.Join(statisticsDir, "tx_bytes"))
		if err != nil {
			return 0, 0, err
		}
		if rxTotal, err = addChecked(rxTotal, rx); err != nil {
			return 0, 0, err
		}
		if txTotal, err = addChecked(txTotal, tx); err != nil {
			return 0, 0, err
		}
		interfaces++
	}
	if interfaces == 0 {
		return 0, 0, fmt.Errorf("linuxobs: no non-loopback network interface observed in sysfs")
	}
	return rxTotal, txTotal, nil
}

// addChecked adds two interface counters without wrapping.
func addChecked(left, right uint64) (uint64, error) {
	sum, ok := safeAddUint64(left, right)
	if !ok {
		return 0, errMalformedProc
	}
	return sum, nil
}

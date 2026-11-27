package linuxobs

import (
	"math"
	"strings"
	"testing"
)

func TestParseCPUPercent(t *testing.T) {
	percent, err := parseCPUPercent([]byte(fakeProcStat))
	if err != nil {
		t.Fatalf("parseCPUPercent: %v", err)
	}
	if math.Abs(percent-2000.0/11000.0*100) > 1e-9 {
		t.Fatalf("parseCPUPercent = %v, want %v", percent, 2000.0/11000.0*100)
	}

	idle, err := parseCPUPercent([]byte("cpu 0 0 0 100 0 0 0 0 0 0\n"))
	if err != nil || idle != 0 {
		t.Fatalf("all-idle cpu = %v, %v; want 0", idle, err)
	}

	for _, malformed := range []string{
		"",
		"notcpu 1 2 3 4 5 6 7 8 9\n",
		"cpu 1 2 3\n",
		"cpu -1 2 3 4 5 6 7 8\n",
		"cpu 0 0 0 0 0 0 0 0 0 0\n",
	} {
		if _, err := parseCPUPercent([]byte(malformed)); err == nil {
			t.Fatalf("parseCPUPercent accepted %q", malformed)
		}
	}

	// Guest/guest_nice columns are already part of user/nice and must be
	// ignored rather than double counted.
	withGuests, err := parseCPUPercent([]byte("cpu 100 0 0 100 0 0 0 0 900 900\n"))
	if err != nil {
		t.Fatalf("parseCPUPercent with guests: %v", err)
	}
	if math.Abs(withGuests-50) > 1e-9 {
		t.Fatalf("guest double counting produced %v, want 50", withGuests)
	}
}

func TestParseLoadAverage(t *testing.T) {
	load, err := parseLoadAverage([]byte(fakeProcLoadAvg))
	if err != nil || math.Abs(load-0.42) > 1e-9 {
		t.Fatalf("parseLoadAverage = %v, %v; want 0.42", load, err)
	}
	for _, malformed := range []string{"", "nan 0.1 0.1", "-1 0 0", "100000 0 0", "not-a-number"} {
		if _, err := parseLoadAverage([]byte(malformed)); err == nil {
			t.Fatalf("parseLoadAverage accepted %q", malformed)
		}
	}
}

func TestParseMemInfo(t *testing.T) {
	values := parseMemInfo([]byte(fakeProcMemInfo))
	if values.total == nil || *values.total != 4294967296 {
		t.Fatalf("MemTotal = %v, want 4294967296", values.total)
	}
	if values.used == nil || *values.used != 2147483648 {
		t.Fatalf("MemUsed = %v, want 2147483648", values.used)
	}

	noAvailable := parseMemInfo([]byte("MemTotal: 1024 kB\nMemFree: 512 kB\n"))
	if noAvailable.total == nil || *noAvailable.total != 1048576 {
		t.Fatalf("MemTotal without MemAvailable = %v", noAvailable.total)
	}
	if noAvailable.used != nil {
		t.Fatalf("MemUsed without MemAvailable = %v, want nil", *noAvailable.used)
	}

	availableAboveTotal := parseMemInfo([]byte("MemTotal: 1024 kB\nMemAvailable: 2048 kB\n"))
	if availableAboveTotal.used != nil {
		t.Fatalf("impossible MemAvailable produced used=%v", *availableAboveTotal.used)
	}

	wrongUnit := parseMemInfo([]byte("MemTotal: 1024 MB\n"))
	if wrongUnit.total != nil {
		t.Fatalf("non-kB unit produced total=%v", *wrongUnit.total)
	}

	garbage := parseMemInfo([]byte("MemTotal: not-a-number kB\nMemAvailable: 1 kB\n"))
	if garbage.total != nil || garbage.used != nil {
		t.Fatalf("garbage meminfo produced values: %+v", garbage)
	}
}

func TestParseNetDevCounters(t *testing.T) {
	rx, tx, err := parseNetDevCounters([]byte(fakeProcNetDev))
	if err != nil || rx != 123456789 || tx != 987654321 {
		t.Fatalf("parseNetDevCounters = %d/%d, %v; want 123456789/987654321", rx, tx, err)
	}

	onlyLoopback := "Inter-|   Receive |  Transmit\n face |bytes ...\n  lo: 100 0 0 0 0 0 0 0 200 0 0 0 0 0 0 0\n"
	if _, _, err := parseNetDevCounters([]byte(onlyLoopback)); err == nil {
		t.Fatal("parseNetDevCounters accepted a loopback-only observation")
	}
	if _, _, err := parseNetDevCounters([]byte("eth0: 1 2 3\n")); err == nil {
		t.Fatal("parseNetDevCounters accepted a truncated interface row")
	}
	if _, _, err := parseNetDevCounters([]byte("eth0: -1 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0\n")); err == nil {
		t.Fatal("parseNetDevCounters accepted a negative counter")
	}
}

func TestParseUptimeSeconds(t *testing.T) {
	value, err := parseUptimeSeconds([]byte(fakeProcUptime))
	if err != nil || value != 10000 {
		t.Fatalf("parseUptimeSeconds = %v, %v; want 10000", value, err)
	}
	for _, malformed := range []string{"", "nan 1", "-5 1", "abc"} {
		if _, err := parseUptimeSeconds([]byte(malformed)); err == nil {
			t.Fatalf("parseUptimeSeconds accepted %q", malformed)
		}
	}
}

func TestParseProcessStartTicks(t *testing.T) {
	ticks, err := parseProcessStartTicks([]byte(fakeProcSelfStat))
	if err != nil || ticks != 500 {
		t.Fatalf("parseProcessStartTicks = %d, %v; want 500", ticks, err)
	}

	// A comm field containing spaces and parentheses must not shift the field
	// index: parsing starts after the last ')'.
	weird := "12 ((a) b) S 1 12 12 0 -1 4194560 100 0 0 0 5 6 0 0 20 0 1 0 777 0 0 0 0 0 0 0 0 0 0 0\n"
	ticks, err = parseProcessStartTicks([]byte(weird))
	if err != nil || ticks != 777 {
		t.Fatalf("parseProcessStartTicks(weird comm) = %d, %v; want 777", ticks, err)
	}

	for _, malformed := range []string{"", "1234 no-comm-close", "1234 (comm) S 1"} {
		if _, err := parseProcessStartTicks([]byte(malformed)); err == nil {
			t.Fatalf("parseProcessStartTicks accepted %q", malformed)
		}
	}
}

func TestNormalizeBootID(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{testBootID + "\n", testCounterEpoch},
		{"5F0C2D7A-91B4-46C8-A3D1-F9052B7E4C6A\n", testCounterEpoch},
		{"5f0c2d7a91b4e6c8a3d1f9052b7e4c6a\n", "5f0c2d7a91b4e6c8a3d1f9052b7e4c6a"},
		{"", ""},
		{"not-a-boot-id", ""},
		{"5f0c2d7a-91b4-46c8-a3d1-f9052b7e4c", ""},
	}
	for _, tc := range cases {
		if got := normalizeBootID([]byte(tc.raw)); got != tc.want {
			t.Fatalf("normalizeBootID(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestValidKernelRelease(t *testing.T) {
	for _, valid := range []string{"6.8.0-45-generic", "5.15.0+", "6.1.0-rc1", "10.0.26100"} {
		if !validKernelRelease(valid) {
			t.Fatalf("validKernelRelease(%q) = false", valid)
		}
	}
	for _, invalid := range []string{"", "kernel with spaces", "6.8.0_45", strings.Repeat("1", 65)} {
		if validKernelRelease(invalid) {
			t.Fatalf("validKernelRelease(%q) = true", invalid)
		}
	}
}

func TestReadCounterEpochFromFixture(t *testing.T) {
	root := writeTree(t, map[string]string{
		"sys/kernel/random/boot_id": testBootID + "\n",
	})
	if got := readCounterEpoch(root); got != testCounterEpoch {
		t.Fatalf("readCounterEpoch = %q, want %q", got, testCounterEpoch)
	}
	empty := writeTree(t, map[string]string{})
	if got := readCounterEpoch(empty); got != zeroCounterEpoch {
		t.Fatalf("readCounterEpoch(empty) = %q, want %q", got, zeroCounterEpoch)
	}
	weird := writeTree(t, map[string]string{"sys/kernel/random/boot_id": "garbage\n"})
	if got := readCounterEpoch(weird); got != zeroCounterEpoch {
		t.Fatalf("readCounterEpoch(garbage) = %q, want %q", got, zeroCounterEpoch)
	}
}

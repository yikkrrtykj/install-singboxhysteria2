package center

import "testing"

func TestAgentVersionAtLeast(t *testing.T) {
	minimum := MinMonitorExportAgentVersion
	cases := []struct {
		version string
		want    bool
	}{
		{"", false},
		{"garbage", false},
		{"1.0.0", false},
		{"1.0.99", false},
		{"1.1.0", true},
		{"1.1.0+build.7", true},
		{"1.2.0", true},
		{"2.0.0", true},
		{"10.0.0", true},
		// Semver ordering: a prerelease of the minimum release is older.
		{"1.1.0-rc.1", false},
		{"1.1.0-1", false},
		// A prerelease of a higher core remains newer than the minimum release.
		{"1.2.0-rc.1", true},
		{"1.1", false},
	}
	for _, tcCase := range cases {
		if got := agentVersionAtLeast(tcCase.version, minimum); got != tcCase.want {
			t.Fatalf("agentVersionAtLeast(%q, %q) = %v, want %v", tcCase.version, minimum, got, tcCase.want)
		}
	}
}

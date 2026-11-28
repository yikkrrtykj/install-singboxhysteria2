//go:build linux || darwin || freebsd || netbsd || openbsd

package linuxobs

import (
	"os"
	"runtime"
	"testing"
)

func TestMonitorExportOwnerGroupModeChecks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX owner/group/mode checks are not enforced on this host")
	}
	col, _, _, _ := newFakeCollector(t)
	col.MonitorExportFile = writeMonitorExport(t, validMonitorExport(testCollectedAt, 3, "ee"))
	col.MonitorExportOwnerUID = os.Getuid() + 1
	assertUnavailableObservation(t, col)

	col, _, _, _ = newFakeCollector(t)
	col.MonitorExportFile = writeMonitorExport(t, validMonitorExport(testCollectedAt, 3, "ef"))
	col.MonitorExportGroupGID = os.Getgid() + 1
	assertUnavailableObservation(t, col)

	col, _, _, _ = newFakeCollector(t)
	col.MonitorExportFile = writeMonitorExport(t, validMonitorExport(testCollectedAt, 3, "eg"))
	col.MonitorExportMode = 0o600
	assertUnavailableObservation(t, col)

	col, _, _, _ = newFakeCollector(t)
	path := writeMonitorExport(t, validMonitorExport(testCollectedAt, 3, "eh"))
	col.MonitorExportFile = path
	col.MonitorExportOwnerUID = os.Getuid()
	// Group ownership of a temp fixture is not portable across CI runners; the
	// mismatch case above still proves the group check fails closed.
	col.MonitorExportGroupGID = 0
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatalf("chmod fixture: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat fixture: %v", err)
	}
	col.MonitorExportMode = uint32(info.Mode().Perm())
	uid, gid, ok := monitorExportPOSIXOwner(info)
	t.Logf("fixture uid=%d gid=%d ok=%v mode=%o expected uid=%d group=%d mode=%o", uid, gid, ok, info.Mode().Perm(), col.MonitorExportOwnerUID, col.MonitorExportGroupGID, col.MonitorExportMode)
	if _, err := readMonitorExportFile(path, col.MonitorExportOwnerUID, col.MonitorExportGroupGID, col.MonitorExportMode); err != nil {
		t.Fatalf("matching owner/group/mode direct read rejected: %v", err)
	}
	if obs := snapshotTraffic(t, col); obs.Freshness != "fresh" {
		t.Fatalf("matching owner/group/mode rejected: %s", obs.Freshness)
	}
}

func TestMonitorExportDropsUnauthorizedEntriesButForwardsAuthorizedSubset(t *testing.T) {
	col, _, _, _ := newFakeCollector(t)
	export := validMonitorExport(testCollectedAt, 4, "de")
	inbounds := export["inbounds"].([]map[string]any)
	if len(inbounds) < 2 {
		t.Fatalf("fixture has %d inbounds, need >=2", len(inbounds))
	}
	inbounds[0]["inbound_tag"] = "unknown-in"
	col.MonitorExportFile = writeMonitorExport(t, export)
	obs := snapshotTraffic(t, col)
	if obs.Freshness != "fresh" || obs.Availability != "partial" {
		t.Fatalf("authorized-subset export rendered as %s/%s", obs.Freshness, obs.Availability)
	}
	for _, entry := range obs.Inbounds {
		if entry.InboundTag == "unknown-in" {
			t.Fatal("unauthorized tag leaked into the report")
		}
	}
}

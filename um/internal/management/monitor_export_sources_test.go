package management

import "testing"

func monitorExportSources(monitorExport bool) map[string]bool {
	return map[string]bool{"system": false, "services": false, "singbox_api": false,
		"mihomo_api": false, "terminal": false, "events": false, "monitor_export": monitorExport}
}

func TestValidateAdminSourcesSupportsOptionalMonitorExport(t *testing.T) {
	if err := validateAdminSources("linux_vps", monitorExportSources(false)); err != nil {
		t.Fatalf("linux six/seven-key config rejected: %v", err)
	}
	if err := validateAdminSources("linux_vps", monitorExportSources(true)); err != nil {
		t.Fatalf("linux monitor_export enable rejected: %v", err)
	}
	if err := validateAdminSources("windows_terminal", monitorExportSources(true)); err == nil {
		t.Fatal("windows monitor_export enable accepted")
	}
	unknown := monitorExportSources(false)
	unknown["bogus"] = true
	if err := validateAdminSources("linux_vps", unknown); err == nil {
		t.Fatal("unknown source switch accepted")
	}
	// The unproven singbox_api / local-only mihomo_api gates are unchanged.
	singbox := monitorExportSources(false)
	singbox["singbox_api"] = true
	if err := validateAdminSources("linux_vps", singbox); err == nil {
		t.Fatal("singbox_api enable accepted")
	}
}

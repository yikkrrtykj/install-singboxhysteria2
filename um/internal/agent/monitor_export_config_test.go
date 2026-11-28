package agent

import "testing"

func validTestConfig(class string) Config {
	sources := map[string]bool{
		"system": false, "services": false, "singbox_api": false,
		"mihomo_api": false, "terminal": false, "events": false,
	}
	cfg := Config{V: 1, NodeClass: class, ConfigVersion: 1, Cadence: 60, Collect: sources,
		DeviceSalt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	if class == "linux_vps" {
		cfg.Tags = []InboundTag{{InboundTag: "vless-in", Kind: "reality"}}
	}
	return cfg
}

func TestValidateConfigAcceptsOptionalMonitorExportSource(t *testing.T) {
	// A rev-6 center sends exactly the six frozen keys; a rev-7 center may add the
	// optional monitor_export switch. Both must remain valid for linux_vps.
	six := validTestConfig("linux_vps")
	if err := validateConfigForClass("linux_vps", six); err != nil {
		t.Fatalf("six-key config rejected: %v", err)
	}
	for _, enabled := range []bool{false, true} {
		seven := validTestConfig("linux_vps")
		seven.Collect["monitor_export"] = enabled
		if len(seven.Collect) != 7 {
			t.Fatalf("test config source count = %d", len(seven.Collect))
		}
		if err := validateConfigForClass("linux_vps", seven); err != nil {
			t.Fatalf("seven-key linux config (monitor_export=%t) rejected: %v", enabled, err)
		}
	}
}

func TestValidateConfigRejectsBadCollectSourceSets(t *testing.T) {
	five := validTestConfig("linux_vps")
	delete(five.Collect, "events")
	if err := validateConfigForClass("linux_vps", five); err == nil {
		t.Fatal("five-key config accepted")
	}
	unknown := validTestConfig("linux_vps")
	unknown.Collect["monitor_export"] = true
	unknown.Collect["bogus"] = true
	if err := validateConfigForClass("linux_vps", unknown); err == nil {
		t.Fatal("unknown source switch accepted")
	}
	eight := validTestConfig("linux_vps")
	eight.Collect["monitor_export"] = false
	eight.Collect["another_optional"] = false
	if err := validateConfigForClass("linux_vps", eight); err == nil {
		t.Fatal("eight-key config accepted")
	}
}

func TestValidateConfigRejectsWindowsMonitorExport(t *testing.T) {
	windows := validTestConfig("windows_terminal")
	windows.Collect["monitor_export"] = false
	if err := validateConfigForClass("windows_terminal", windows); err != nil {
		t.Fatalf("windows seven-key config with monitor_export=false rejected: %v", err)
	}
	windows.Collect["monitor_export"] = true
	if err := validateConfigForClass("windows_terminal", windows); err == nil {
		t.Fatal("windows config enabling the linux-only monitor_export source accepted")
	}
}

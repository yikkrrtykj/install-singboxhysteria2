package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testSigningIdentity(t *testing.T) Identity {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return Identity{Version: stateVersion, CenterURL: "http://127.0.0.1:1",
		NodeID:  "11111111-1111-4111-8111-111111111111",
		EventID: "22222222-2222-4222-8222-222222222222", NodeClass: "linux_vps",
		KeyID: "key-1234abcd", PublicKey: base64.RawURLEncoding.EncodeToString(pub),
		PrivateKey: base64.RawURLEncoding.EncodeToString(priv)}
}

func testAttempt() Attempt {
	return Attempt{Generation: 1, BootID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Seq: 1, SentAt: 1795622400, Nonce: "AAAAAAAAAAAAAAAAAAAAAA"}
}

func TestReportRejectsMissingRequiredACKFields(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"missing-next-seq", `{"v":1,"report_id":"11111111-1111-4111-8111-111111111111","result":"accepted","server_time":1795622400,"config_version":1,"retry_after_s":null}`},
		{"missing-retry-after", `{"v":1,"report_id":"11111111-1111-4111-8111-111111111111","result":"accepted","server_time":1795622400,"config_version":1,"next_seq":2}`},
		{"bad-report-id", `{"v":1,"report_id":"not-a-uuid","result":"accepted","server_time":1795622400,"config_version":1,"next_seq":2,"retry_after_s":null}`},
		{"zero-next-seq", `{"v":1,"report_id":"11111111-1111-4111-8111-111111111111","result":"accepted","server_time":1795622400,"config_version":1,"next_seq":0,"retry_after_s":null}`},
		{"bad-retry-after", `{"v":1,"report_id":"11111111-1111-4111-8111-111111111111","result":"accepted","server_time":1795622400,"config_version":1,"next_seq":2,"retry_after_s":3601}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()
			c, err := NewClient(srv.URL, nil, func() time.Time { return time.Unix(1795622400, 0) })
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Report(context.Background(), testSigningIdentity(t), testAttempt(), "snapshot", []byte(`{"v":1}`)); err == nil {
				t.Fatal("malformed ACK was accepted")
			}
		})
	}
}

func TestReportAcceptsExplicitNullExhaustion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"v":1,"report_id":"11111111-1111-4111-8111-111111111111","result":"accepted","server_time":1795622400,"config_version":1,"next_seq":null,"retry_after_s":null}`)
	}))
	defer srv.Close()
	c, err := NewClient(srv.URL, nil, func() time.Time { return time.Unix(1795622400, 0) })
	if err != nil {
		t.Fatal(err)
	}
	ack, err := c.Report(context.Background(), testSigningIdentity(t), testAttempt(), "snapshot", []byte(`{"v":1}`))
	if err != nil {
		t.Fatalf("explicit null ACK rejected: %v", err)
	}
	if ack.NextSeq != nil {
		t.Fatalf("explicit null next_seq parsed as %v", *ack.NextSeq)
	}
}

func TestConfigClassAllowlist(t *testing.T) {
	base := Config{V: 1, NodeID: "11111111-1111-4111-8111-111111111111",
		EventID: "22222222-2222-4222-8222-222222222222", NodeClass: "linux_vps",
		ConfigVersion: 1, Cadence: 60,
		Collect: map[string]bool{"system": true, "services": true, "singbox_api": true,
			"mihomo_api": false, "terminal": false, "events": true},
		DeviceSalt: strings.Repeat("a", 43), Tags: []InboundTag{
			{InboundTag: "vless-in", Kind: "reality"},
			{InboundTag: "hy2-in", Kind: "hysteria2"},
		}}
	if err := validateConfigForClass("linux_vps", base); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	forbidden := base
	forbidden.Collect = cloneBoolMap(base.Collect)
	forbidden.Collect["terminal"] = true
	if err := validateConfigForClass("linux_vps", forbidden); err == nil {
		t.Fatal("linux config enabling terminal was accepted")
	}
	noTags := base
	noTags.Tags = nil
	if err := validateConfigForClass("linux_vps", noTags); err == nil {
		t.Fatal("linux config without expected tags was accepted")
	}
	win := base
	win.NodeClass = "windows_terminal"
	win.Collect = map[string]bool{"system": false, "services": false, "singbox_api": false,
		"mihomo_api": true, "terminal": true, "events": true}
	win.Tags = nil
	if err := validateConfigForClass("windows_terminal", win); err != nil {
		t.Fatalf("valid windows config rejected: %v", err)
	}
	win.Collect["services"] = true
	if err := validateConfigForClass("windows_terminal", win); err == nil {
		t.Fatal("windows config enabling services was accepted")
	}
}

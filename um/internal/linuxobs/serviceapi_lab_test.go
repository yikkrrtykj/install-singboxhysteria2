package linuxobs

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// TestServiceAPIOptInLab is executed only by the isolated sing-box lab workflow
// (and can be run manually on an isolated host). It deliberately requires an
// explicit env gate; normal CI must skip it. The lab script starts a real
// sing-box 1.14.5 with a synthetic mixed inbound and service.api listener.
func TestServiceAPIOptInLab(t *testing.T) {
	if os.Getenv("UM_SINGBOX_SERVICEAPI_LAB") != "1" {
		t.Skip("opt-in real sing-box service.api lab")
	}
	url := os.Getenv("UM_SINGBOX_SERVICEAPI_URL")
	secret := os.Getenv("UM_SINGBOX_SERVICEAPI_SECRET")
	mixed := os.Getenv("UM_SINGBOX_SERVICEAPI_MIXED")
	if url == "" || secret == "" || mixed == "" {
		t.Fatal("lab URL/secret/mixed address missing")
	}
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = conn.Write([]byte("ok"))
			}()
		}
	}()
	proxy, err := net.DialTimeout("tcp", mixed, 3*time.Second)
	if err != nil {
		t.Fatalf("dial mixed inbound: %v", err)
	}
	defer proxy.Close()
	_, err = fmt.Fprintf(proxy, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echo.Addr().String(), echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = proxy.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := bufio.NewReader(proxy).ReadString('\n')
	if err != nil || !strings.Contains(line, "200") {
		t.Fatalf("CONNECT through real mixed inbound: %q err=%v", line, err)
	}
	probe, err := NewServiceAPIProbe(ServiceAPIConfig{URL: url, Secret: secret, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	obs, err := probe.ObserveServiceAPI(context.Background())
	if err != nil {
		t.Fatalf("real service.api observation: %v", err)
	}
	evidence, ok := obs.Inbounds["test-in"]
	if !ok || evidence.ActiveConnections < 1 {
		t.Fatalf("real active connection not observed: connected=%v inbounds=%+v", obs.Connected, obs.Inbounds)
	}
	if evidence.TotalsExact {
		t.Fatal("lab claims exact lifetime totals from a per-connection API")
	}
	// The frozen traffic projection must remain unavailable: the accumulator's
	// observed cumulative total is a lower bound, not a schema-representable
	// lifetime total.
	if evidence.TotalsAvailable && evidence.UplinkTotalBytes >= 0 {
		t.Logf("observed lower-bound totals: uplink=%d downlink=%d (not reported as exact totals)",
			evidence.UplinkTotalBytes, evidence.DownlinkTotalBytes)
	}
}

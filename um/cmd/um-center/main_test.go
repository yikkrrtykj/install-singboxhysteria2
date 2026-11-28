package main

import "testing"

func TestRequireLoopbackAdmin(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8090", "127.0.0.1:0", "[::1]:8090", "localhost:8090"} {
		if err := requireLoopbackAdmin(addr); err != nil {
			t.Fatalf("requireLoopbackAdmin(%q) = %v, want nil", addr, err)
		}
	}
	for _, addr := range []string{"0.0.0.0:8090", ":8090", "192.0.2.1:8090", "[::]:8090", "example.com:8090"} {
		if err := requireLoopbackAdmin(addr); err == nil {
			t.Fatalf("requireLoopbackAdmin(%q) = nil, want rejection", addr)
		}
	}
}

func TestUMCPlainIngestMustBeLoopback(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8443": true, "[::1]:8443": true, "localhost:8443": true,
		"0.0.0.0:8443": false, "[::]:8443": false, ":8443": false,
		"192.0.2.1:8443": false, "bad": false,
	}
	for addr, want := range cases {
		if got := isLoopbackHostPort(addr); got != want {
			t.Fatalf("isLoopbackHostPort(%q)=%v, want %v", addr, got, want)
		}
	}
}

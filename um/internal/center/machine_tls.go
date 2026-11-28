package center

import "crypto/tls"

// MachineTLSConfig returns the production machine-plane TLS configuration.
// The machine listener must never fall back to TLS 1.2 or below; agent identity
// remains the frozen Ed25519 protocol at the application layer.
func MachineTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}
}

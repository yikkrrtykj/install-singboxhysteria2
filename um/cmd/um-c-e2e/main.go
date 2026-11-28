// Command um-c-e2e is an isolated browser/HTTP laboratory harness for UM-C. It
// runs the real center store, management service and Web handler with synthetic
// Cloudflare Access JWKS/JWT keys and a self-signed loopback TLS certificate. It
// is not a production command and never contacts Cloudflare or real DNS.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/management"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/umcauth"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/web"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "loopback browser listener")
	staticDir := flag.String("static", "web/dist", "built Vue frontend directory")
	flag.Parse()
	dir, err := os.MkdirTemp("", "um-c-e2e-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)
	st, err := store.Open(filepath.Join(dir, "center.db"))
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()
	keyPath := filepath.Join(dir, "master.key")
	if err := umcauth.GenerateMasterKeyFile(keyPath); err != nil {
		log.Fatal(err)
	}
	master, err := umcauth.LoadMasterKey(keyPath)
	if err != nil {
		log.Fatal(err)
	}
	password := "E2E-UM-C-Password-2026!"
	hash, err := umcauth.HashPassword(password, umcauth.DefaultPasswordParams())
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	if _, err := st.BootstrapAuthUser(ctx, "e2e-admin", hash, time.Now().Unix()); err != nil {
		log.Fatal(err)
	}
	eventA := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	eventB := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	for _, e := range []string{eventA, eventB} {
		if _, err := st.CreateEvent(ctx, e, "E2E "+e, time.Now().Unix()); err != nil {
			log.Fatal(err)
		}
	}
	msvc, err := management.NewService(st)
	if err != nil {
		log.Fatal(err)
	}

	// Synthetic Cloudflare Access JWKS and a signed assertion. The browser test
	// injects only this synthetic header via Playwright routing.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	const kid = "um-c-e2e-key"
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(rsaKey.PublicKey.N.Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": n, "e": "AQAB",
		}}})
	}))
	defer jwks.Close()
	verifier, err := umcauth.NewVerifier(umcauth.Config{
		Issuer: "https://e2e.cloudflareaccess.test", Audience: "um-c-e2e-audience",
		JWKSURL: jwks.URL, AllowInsecureHTTPForTests: true,
	})
	if err != nil {
		log.Fatal(err)
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	origin := fmt.Sprintf("https://localhost:%d", port)
	h, err := web.NewHandler(web.Config{
		Store: st, ManagementService: msvc, Access: verifier, MasterKey: master,
		StaticDir: *staticDir, AllowedOrigins: []string{origin},
	})
	if err != nil {
		log.Fatal(err)
	}
	cert, err := selfSignedCert()
	if err != nil {
		log.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}})
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second}
	go func() { _ = srv.Serve(tlsLn) }()

	token := signAccessToken(rsaKey, kid, "e2e-browser-subject", time.Now())
	ready := map[string]string{
		"url": "https://localhost:" + fmt.Sprint(port), "token": token,
		"username": "e2e-admin", "password": password, "event_a": eventA, "event_b": eventB,
		"static": *staticDir,
	}
	raw, _ := json.Marshal(ready)
	fmt.Println("E2E_READY " + string(raw))
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
}

func signAccessToken(key *rsa.PrivateKey, kid, subject string, now time.Time) string {
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iss": "https://e2e.cloudflareaccess.test", "aud": "um-c-e2e-audience", "sub": subject,
		"exp": now.Add(time.Hour).Unix(), "nbf": now.Add(-10 * time.Second).Unix(),
		"iat": now.Add(-10 * time.Second).Unix(),
	})
	enc := base64.RawURLEncoding.EncodeToString
	signing := enc(header) + "." + enc(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, 5, sum[:])
	return signing + "." + enc(sig)
}

func selfSignedCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

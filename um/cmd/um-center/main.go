// Command um-center runs the UM-B2 center: an isolated machine-ingest listener,
// an isolated admin boundary, and the SQLite store. It only listens on the
// explicitly configured addresses and loads contracts from the explicitly
// configured trusted deployment path; there is no cwd fallback.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/center"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/management"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/umcauth"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/web"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "admin" {
		os.Exit(runAdminCLI(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "auth" {
		if err := runAuthCLI(os.Args[2:]); err != nil {
			log.Printf("um-center auth: %v", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
	}
	if err := run(); err != nil {
		log.Printf("um-center: %v", err)
		os.Exit(1)
	}
}

func envOr(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

func run() error {
	var (
		ingestAddr          = flag.String("ingest", envOr("UM_CENTER_INGEST_ADDR", ""), "machine-ingest listen address (required; loopback preferred)")
		adminAddr           = flag.String("admin", envOr("UM_CENTER_ADMIN_ADDR", ""), "isolated admin listen address (required)")
		dbPath              = flag.String("db", envOr("UM_CENTER_DB", ""), "SQLite database path (required)")
		contractDir         = flag.String("contracts", envOr("UM_CENTER_CONTRACTS", ""), "explicit trusted path to docs/um/contracts/v1 (required)")
		adminAuthFile       = flag.String("admin-auth-file", envOr("UM_CENTER_ADMIN_AUTH_FILE", ""), "protected 0600 local admin auth JSON; enables /api/v1 management API")
		webAddr             = flag.String("web", envOr("UM_CENTER_WEB_ADDR", ""), "UM-C web listener (loopback only; Access + local session)")
		webStatic           = flag.String("web-static", envOr("UM_CENTER_WEB_STATIC", ""), "built UM-C frontend static directory")
		webTLSFlag          = flag.Bool("web-tls", false, "serve Web listener with TLS 1.3 (requires -web-tls-cert/-web-tls-key)")
		webTLSCert          = flag.String("web-tls-cert", envOr("UM_CENTER_WEB_TLS_CERT", ""), "Web TLS certificate")
		webTLSKey           = flag.String("web-tls-key", envOr("UM_CENTER_WEB_TLS_KEY", ""), "Web TLS private key")
		webOrigin           = flag.String("web-origin", envOr("UM_CENTER_WEB_ORIGIN", ""), "comma-separated allowed https Web origins")
		masterKeyFile       = flag.String("master-key", envOr("UM_CENTER_MASTER_KEY", ""), "protected UM-C master-key file")
		accessIssuer        = flag.String("access-issuer", envOr("UM_CENTER_ACCESS_ISSUER", ""), "Cloudflare Access issuer")
		accessAudienceience = flag.String("access-audience", envOr("UM_CENTER_ACCESS_AUDIENCE", ""), "Cloudflare Access audience")
		accessJWKS          = flag.String("access-jwks", envOr("UM_CENTER_ACCESS_JWKS", ""), "trusted Cloudflare Access JWKS URL")
		accessHTTP          = flag.Bool("access-jwks-insecure-http-for-tests", false, "allow http JWKS only for hermetic tests")
		machineTLS          = flag.String("machine-tls", envOr("UM_CENTER_MACHINE_TLS_ADDR", ""), "optional independent machine TLS listener")
		machineCert         = flag.String("machine-tls-cert", envOr("UM_CENTER_MACHINE_TLS_CERT", ""), "machine listener TLS certificate")
		machineKey          = flag.String("machine-tls-key", envOr("UM_CENTER_MACHINE_TLS_KEY", ""), "machine listener TLS private key")
	)
	flag.Parse()

	if *dbPath == "" || *contractDir == "" {
		return errors.New("-db and -contracts are required (or UM_CENTER_DB / UM_CENTER_CONTRACTS)")
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()
	if *ingestAddr == "" || *adminAddr == "" {
		return errors.New("-ingest and -admin are required (or UM_CENTER_INGEST_ADDR / UM_CENTER_ADMIN_ADDR)")
	}
	var mgmtSvc *management.Service
	if *adminAuthFile != "" || *webAddr != "" {
		mgmtSvc, err = management.NewService(st)
		if err != nil {
			return err
		}
	}
	cfg := center.Config{
		IngestAddr: *ingestAddr, AdminAddr: *adminAddr,
		DBPath: *dbPath, ContractDir: *contractDir,
	}
	if *adminAuthFile != "" {
		if err := requireLoopbackAdmin(*adminAddr); err != nil {
			return err
		}
		auth, err := management.LoadFileAuthenticator(*adminAuthFile)
		if err != nil {
			return fmt.Errorf("admin auth: %w", err)
		}
		adminAPI, err := management.NewHandler(mgmtSvc, auth)
		if err != nil {
			return err
		}
		cfg.AdminAPI = adminAPI
	}
	var webHandler *web.Handler
	if *webAddr != "" {
		if err := requireLoopbackAdmin(*webAddr); err != nil {
			return fmt.Errorf("web listener: %w", err)
		}
		if *masterKeyFile == "" || *accessIssuer == "" || *accessAudienceience == "" || *accessJWKS == "" || *webOrigin == "" {
			return errors.New("-web requires -master-key, -access-issuer, -access-audience, -access-jwks and -web-origin")
		}
		masterKey, err := umcauth.LoadMasterKey(*masterKeyFile)
		if err != nil {
			return fmt.Errorf("web master key: %w", err)
		}
		access, err := umcauth.NewVerifier(umcauth.Config{Issuer: *accessIssuer, Audience: *accessAudienceience,
			JWKSURL: *accessJWKS, AllowInsecureHTTPForTests: *accessHTTP})
		if err != nil {
			return fmt.Errorf("access verifier: %w", err)
		}
		webHandler, err = web.NewHandler(web.Config{Store: st, ManagementService: mgmtSvc, Access: access,
			MasterKey: masterKey, StaticDir: *webStatic, AllowedOrigins: strings.Split(*webOrigin, ",")})
		if err != nil {
			return fmt.Errorf("web handler: %w", err)
		}
	}
	if *machineTLS != "" {
		if *machineCert == "" || *machineKey == "" {
			return errors.New("-machine-tls requires -machine-tls-cert and -machine-tls-key")
		}
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	schemas, err := cfg.LoadContracts()
	if err != nil {
		return err
	}
	svc, err := center.NewService(center.ServiceConfig{Store: st, Schemas: schemas})
	if err != nil {
		return err
	}
	srv, err := center.NewServer(cfg, svc)
	if err != nil {
		return err
	}
	if err := srv.Start(); err != nil {
		return fmt.Errorf("start center: %w", err)
	}
	log.Printf("um-center ingest listening on %s (machine plane)", srv.IngestAddr())
	if cfg.AdminAPI != nil {
		log.Printf("um-center admin listening on %s (admin plane; authenticated /api/v1 management API)", srv.AdminAddr())
	} else {
		log.Printf("um-center admin listening on %s (admin plane; health only, management API disabled)", srv.AdminAddr())
	}
	log.Printf("um-center contract set loaded from %s", *contractDir)

	var webSrv, machineSrv *http.Server
	var webLn, machineLn net.Listener
	if webHandler != nil {
		webLn, err = net.Listen("tcp", *webAddr)
		if err != nil {
			return fmt.Errorf("web listen: %w", err)
		}
		if *webTLSFlag {
			cert, err := tls.LoadX509KeyPair(*webTLSCert, *webTLSKey)
			if err != nil {
				_ = webLn.Close()
				return fmt.Errorf("web TLS certificate: %w", err)
			}
			webLn = tls.NewListener(webLn, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}})
		}
		webSrv = &http.Server{Handler: webHandler, ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
		go func() { _ = webSrv.Serve(webLn) }()
		scheme := "http"
		if *webTLSFlag {
			scheme = "https"
		}
		log.Printf("um-center web listening on %s (%s; Cloudflare Access + local session)", webLn.Addr(), scheme)
	}
	if *machineTLS != "" {
		cert, err := tls.LoadX509KeyPair(*machineCert, *machineKey)
		if err != nil {
			return fmt.Errorf("machine TLS certificate: %w", err)
		}
		machineLn, err = tls.Listen("tcp", *machineTLS, &tls.Config{MinVersion: tls.VersionTLS13,
			Certificates: []tls.Certificate{cert}})
		if err != nil {
			return fmt.Errorf("machine TLS listen: %w", err)
		}
		machineSrv = &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
		go func() { _ = machineSrv.Serve(machineLn) }()
		log.Printf("um-center machine TLS listening on %s (independent machine plane, TLS 1.3)", machineLn.Addr())
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Bounded maintenance: rotate expirations and policy-B retention. The sweep
	// itself is repeatable, bounded and never deletes node_boot.
	maintCtx, cancelMaint := context.WithCancel(context.Background())
	defer cancelMaint()
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-maintCtx.Done():
				return
			case <-ticker.C:
				if _, err := st.AbortExpiredRotations(maintCtx, time.Now().Unix()); err != nil {
					log.Printf("um-center maintenance: abort rotations: %v", err)
				}
				if _, err := st.RunRetentionB2(maintCtx, time.Now().Unix()); err != nil {
					log.Printf("um-center maintenance: retention: %v", err)
				}
				if _, err := st.CleanupAuthState(maintCtx, time.Now().Unix()); err != nil {
					log.Printf("um-center maintenance: auth cleanup: %v", err)
				}
			}
		}
	}()
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if webSrv != nil {
		_ = webSrv.Shutdown(shutdownCtx)
	}
	if machineSrv != nil {
		_ = machineSrv.Shutdown(shutdownCtx)
	}
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	log.Printf("um-center stopped")
	return nil
}

// requireLoopbackAdmin refuses to expose the management API on a non-loopback
// listener. UM-C (Cloudflare Tunnel/TLS/login/session) is not implemented in
// B4; an unauthenticated public admin listener is never acceptable.
func requireLoopbackAdmin(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return errors.New("admin address must be host:port")
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("management API requires a loopback admin address in B4")
	}
	return nil
}

// Command um-center runs the UM-B2 center: an isolated machine-ingest listener,
// an isolated admin boundary, and the SQLite store. It only listens on the
// explicitly configured addresses and loads contracts from the explicitly
// configured trusted deployment path; there is no cwd fallback.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/center"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/management"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "admin" {
		os.Exit(runAdminCLI(os.Args[2:]))
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
		ingestAddr    = flag.String("ingest", envOr("UM_CENTER_INGEST_ADDR", ""), "machine-ingest listen address (required; loopback preferred)")
		adminAddr     = flag.String("admin", envOr("UM_CENTER_ADMIN_ADDR", ""), "isolated admin listen address (required)")
		dbPath        = flag.String("db", envOr("UM_CENTER_DB", ""), "SQLite database path (required)")
		contractDir   = flag.String("contracts", envOr("UM_CENTER_CONTRACTS", ""), "explicit trusted path to docs/um/contracts/v1 (required)")
		adminAuthFile = flag.String("admin-auth-file", envOr("UM_CENTER_ADMIN_AUTH_FILE", ""), "protected 0600 local admin auth JSON; enables /api/v1 management API")
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
		mgmt, err := management.NewService(st)
		if err != nil {
			return err
		}
		adminAPI, err := management.NewHandler(mgmt, auth)
		if err != nil {
			return err
		}
		cfg.AdminAPI = adminAPI
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
			}
		}
	}()
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
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

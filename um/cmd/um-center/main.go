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
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/center"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
)

func main() {
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
		ingestAddr  = flag.String("ingest", envOr("UM_CENTER_INGEST_ADDR", ""), "machine-ingest listen address (required; loopback preferred)")
		adminAddr   = flag.String("admin", envOr("UM_CENTER_ADMIN_ADDR", ""), "isolated admin listen address (required)")
		dbPath      = flag.String("db", envOr("UM_CENTER_DB", ""), "SQLite database path (required)")
		contractDir = flag.String("contracts", envOr("UM_CENTER_CONTRACTS", ""), "explicit trusted path to docs/um/contracts/v1 (required)")
		issueToken  = flag.Bool("issue-enroll-token", false, "create one enrollment token and exit (admin action)")
		tokenEvent  = flag.String("token-event", "", "event_id scope for -issue-enroll-token")
		tokenClass  = flag.String("token-class", "", "node_class scope for -issue-enroll-token (linux_vps|windows_terminal)")
		tokenTTL    = flag.Duration("token-ttl", 30*time.Minute, "enrollment token lifetime")
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
	now := time.Now().Unix()

	if *issueToken {
		if *tokenEvent == "" || *tokenClass == "" {
			return errors.New("-issue-enroll-token requires -token-event and -token-class")
		}
		token, hash, err := store.NewEnrollToken()
		if err != nil {
			return err
		}
		if err := st.CreateEnrollToken(context.Background(), hash, *tokenEvent, *tokenClass, now+int64(tokenTTL.Seconds()), now); err != nil {
			return fmt.Errorf("create enrollment token: %w", err)
		}
		fmt.Println(token)
		return nil
	}

	if *ingestAddr == "" || *adminAddr == "" {
		return errors.New("-ingest and -admin are required (or UM_CENTER_INGEST_ADDR / UM_CENTER_ADMIN_ADDR)")
	}
	cfg := center.Config{
		IngestAddr: *ingestAddr, AdminAddr: *adminAddr,
		DBPath: *dbPath, ContractDir: *contractDir,
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
	log.Printf("um-center admin listening on %s (admin plane, health only)", srv.AdminAddr())
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

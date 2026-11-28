package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/umcauth"
	"golang.org/x/term"
)

// runAuthCLI implements the OS-local UM-C bootstrap/recovery operations. These
// commands never listen on a network socket, never accept passwords via argv or
// environment variables, and do not bypass Cloudflare/local authentication for
// later browser login.
func runAuthCLI(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: um-center auth init-key|bootstrap|recover [flags]")
	}
	switch args[0] {
	case "init-key":
		return runAuthInitKey(args[1:])
	case "bootstrap":
		return runAuthBootstrap(args[1:])
	case "recover":
		return runAuthRecover(args[1:])
	default:
		return fmt.Errorf("unknown auth command %q", args[0])
	}
}

func runAuthInitKey(args []string) error {
	fs := flag.NewFlagSet("auth init-key", flag.ContinueOnError)
	path := fs.String("path", "", "protected master-key file path (must not exist)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*path) == "" {
		return errors.New("--path is required")
	}
	if err := umcauth.GenerateMasterKeyFile(*path); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "master key created at %s (keep this file protected; never commit it)\n", *path)
	return nil
}

func runAuthBootstrap(args []string) error {
	fs := flag.NewFlagSet("auth bootstrap", flag.ContinueOnError)
	dbPath := fs.String("db", "", "center SQLite path")
	keyPath := fs.String("master-key", "", "protected master-key file")
	username := fs.String("username", "", "initial platform_admin username")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dbPath == "" || *keyPath == "" || strings.TrimSpace(*username) == "" {
		return errors.New("--db, --master-key and --username are required")
	}
	if _, err := umcauth.LoadMasterKey(*keyPath); err != nil {
		return fmt.Errorf("master key: %w", err)
	}
	password, err := readPasswordLocal("New initial platform_admin password: ")
	if err != nil {
		return err
	}
	if err := umcauth.ValidatePasswordPolicy(password); err != nil {
		return errors.New("password does not meet policy")
	}
	hash, err := umcauth.HashPassword(password, umcauth.DefaultPasswordParams())
	if err != nil {
		return errors.New("password hashing unavailable")
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()
	user, err := st.BootstrapAuthUser(context.Background(), *username, hash, nowUnix())
	if err != nil {
		return err
	}
	_ = st.RecordAuthAudit(context.Background(), "local-bootstrap", "platform_admin", "umc_bootstrap_cli", "user:"+user.UserID, "ok", nowUnix())
	fmt.Fprintf(os.Stdout, "initial platform_admin %q created; TOTP setup is required at first Web login\n", user.Username)
	return nil
}

func runAuthRecover(args []string) error {
	fs := flag.NewFlagSet("auth recover", flag.ContinueOnError)
	dbPath := fs.String("db", "", "center SQLite path")
	keyPath := fs.String("master-key", "", "protected master-key file")
	username := fs.String("username", "", "account username")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dbPath == "" || *keyPath == "" || strings.TrimSpace(*username) == "" {
		return errors.New("--db, --master-key and --username are required")
	}
	if _, err := umcauth.LoadMasterKey(*keyPath); err != nil {
		return fmt.Errorf("master key: %w", err)
	}
	password, err := readPasswordLocal("New password for controlled local recovery: ")
	if err != nil {
		return err
	}
	if err := umcauth.ValidatePasswordPolicy(password); err != nil {
		return errors.New("password does not meet policy")
	}
	hash, err := umcauth.HashPassword(password, umcauth.DefaultPasswordParams())
	if err != nil {
		return errors.New("password hashing unavailable")
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()
	user, err := st.GetAuthUserByUsername(context.Background(), *username)
	if err != nil {
		return errors.New("account recovery target is unavailable")
	}
	if err := st.ResetAuthUserForLocalRecovery(context.Background(), user.UserID, hash, nowUnix()); err != nil {
		return err
	}
	_ = st.RecordAuthAudit(context.Background(), "local-recovery", "platform_admin", "umc_local_recovery", "user:"+user.UserID, "ok", nowUnix())
	_ = st.RecordAuthLedger(context.Background(), "umc_local_recovery", user.UserID, ledgerHash("local-recovery"), nowUnix())
	log.Printf("um-center: controlled local recovery completed for %q; all sessions revoked and TOTP re-enrollment required", user.Username)
	return nil
}

func readPasswordLocal(prompt string) (string, error) {
	if strings.TrimSpace(prompt) != "" {
		fmt.Fprint(os.Stderr, prompt)
	}
	fd := int(os.Stdin.Fd())
	var raw []byte
	var err error
	if term.IsTerminal(fd) {
		raw, err = term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
	} else {
		reader := bufio.NewReader(os.Stdin)
		line, rerr := reader.ReadString('\n')
		raw = []byte(strings.TrimRight(line, "\r\n"))
		err = rerr
		if len(raw) == 0 && err != nil {
			return "", errors.New("password input unavailable")
		}
		err = nil
	}
	if err != nil {
		return "", errors.New("password input unavailable")
	}
	return string(raw), nil
}

func nowUnix() int64 { return time.Now().Unix() }

func ledgerHash(value string) string {
	// Reuse a SHA-256 hash hex string; details never contain the password.
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

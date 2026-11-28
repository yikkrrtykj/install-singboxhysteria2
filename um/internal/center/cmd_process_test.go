package center_test

import (
	"bufio"
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestCenterCommandProcessStartStop runs the real cmd/um-center binary with
// real listeners and SQLite, checks the admin health endpoint, and terminates
// the process. This is a process-level lifecycle test, not only an in-process
// http.Handler test.
func TestCenterCommandProcessStartStop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping process build/run in -short mode")
	}
	bin := filepath.Join(t.TempDir(), "um-center")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-o", bin, "../../cmd/um-center")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build cmd/um-center: %v\n%s", err, out)
	}
	db := filepath.Join(t.TempDir(), "private", "center.db")
	contracts, err := filepath.Abs(contractsDir)
	if err != nil {
		t.Fatalf("contracts abs: %v", err)
	}
	cmd := exec.Command(bin,
		"-ingest", "127.0.0.1:0",
		"-admin", "127.0.0.1:0",
		"-db", db,
		"-contracts", contracts,
	)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start center: %v", err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	}()
	adminAddr := ""
	ingestAddr := ""
	scanner := bufio.NewScanner(stderr)
	deadline := time.Now().Add(20 * time.Second)
	for (adminAddr == "" || ingestAddr == "") && time.Now().Before(deadline) {
		if !scanner.Scan() {
			break
		}
		line := scanner.Text()
		if idx := strings.Index(line, "ingest listening on "); idx >= 0 {
			ingestAddr = strings.TrimSpace(line[idx+len("ingest listening on "):])
			if sp := strings.Index(ingestAddr, " "); sp >= 0 {
				ingestAddr = ingestAddr[:sp]
			}
		}
		if idx := strings.Index(line, "admin listening on "); idx >= 0 {
			adminAddr = strings.TrimSpace(line[idx+len("admin listening on "):])
			if sp := strings.Index(adminAddr, " "); sp >= 0 {
				adminAddr = adminAddr[:sp]
			}
		}
	}
	if adminAddr == "" || ingestAddr == "" {
		t.Fatalf("did not observe listener addresses (admin=%q ingest=%q)", adminAddr, ingestAddr)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + adminAddr + "/api/health")
	if err != nil {
		t.Fatalf("admin health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin health status=%d", resp.StatusCode)
	}
	// Machine plane must not serve admin health.
	resp2, err := client.Get("http://" + ingestAddr + "/api/health")
	if err != nil {
		t.Fatalf("ingest health request: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("ingest plane served admin path: %d", resp2.StatusCode)
	}
	// Graceful stop request.
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		// Windows cannot deliver os.Interrupt; kill is an acceptable test stop.
		_ = cmd.Process.Kill()
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-stopCtx.Done():
		_ = cmd.Process.Kill()
	case <-done:
	}
}

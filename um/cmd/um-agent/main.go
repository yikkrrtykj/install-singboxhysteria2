// Command um-agent runs the UM-B3 node agent for Linux VPS and Windows
// terminal nodes. It is a thin CLI over the shared internal/agent runtime; the
// platform build selects the read-only collector.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/agent"
)

// version is the reported agent.version. 1.1.0 is the first revision that
// understands the optional rev-7 collect.monitor_export switch; the center only
// emits that switch to agents reporting >= center.MinMonitorExportAgentVersion
// (OD-LT-14), so this constant and the minimum must move together.
const version = "1.1.0"

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

type commonFlags struct {
	stateDir  string
	centerURL string
	nodeClass string
	// monitorExportFile is the operator-local fixed absolute path of the optional
	// monitor-v2 read-only traffic export. It is never accepted from center
	// config; empty disables the local read path even when the center source is
	// enabled (the report then carries an honest unavailable observation).
	monitorExportFile string
	// The expected POSIX owner/group/mode of the export are local operator
	// flags, never center-supplied; non-zero values are enforced by the reader.
	monitorExportOwnerUID int
	monitorExportGroupGID int
	monitorExportModeText string
}

func addCommon(fs *flag.FlagSet, c *commonFlags) {
	fs.StringVar(&c.stateDir, "state-dir", envOr("UM_AGENT_STATE_DIR", ""), "owner-only agent state directory")
	fs.StringVar(&c.centerURL, "center", envOr("UM_AGENT_CENTER_URL", ""), "center ingest base URL")
	fs.StringVar(&c.nodeClass, "node-class", envOr("UM_AGENT_NODE_CLASS", ""), "linux_vps or windows_terminal")
	fs.StringVar(&c.monitorExportFile, "monitor-export-file", envOr("UM_AGENT_MONITOR_EXPORT_FILE", ""),
		"optional fixed absolute path of the monitor-v2 read-only traffic export (linux_vps only; empty disables)")
	fs.IntVar(&c.monitorExportOwnerUID, "monitor-export-owner-uid", envIntOr("UM_AGENT_MONITOR_EXPORT_OWNER_UID", 0),
		"expected numeric owner uid of the export (0 disables the owner check)")
	fs.IntVar(&c.monitorExportGroupGID, "monitor-export-group-gid", envIntOr("UM_AGENT_MONITOR_EXPORT_GROUP_GID", 0),
		"expected numeric group gid of the export (0 disables the group check)")
	fs.StringVar(&c.monitorExportModeText, "monitor-export-mode", envOr("UM_AGENT_MONITOR_EXPORT_MODE", ""),
		"expected exact octal POSIX mode of the export (e.g. 0640; empty disables the mode check)")
}

func (c commonFlags) validate() error {
	if strings.TrimSpace(c.stateDir) == "" {
		return errors.New("--state-dir is required")
	}
	if strings.TrimSpace(c.centerURL) == "" {
		return errors.New("--center is required")
	}
	if c.nodeClass != "linux_vps" && c.nodeClass != "windows_terminal" {
		return errors.New("--node-class must be linux_vps or windows_terminal")
	}
	if _, err := c.monitorExportMode(); err != nil {
		return err
	}
	return nil
}

func (c commonFlags) monitorExportMode() (uint32, error) {
	if strings.TrimSpace(c.monitorExportModeText) == "" {
		return 0, nil
	}
	value, err := strconv.ParseUint(c.monitorExportModeText, 0, 32)
	if err != nil || value > 0o777 {
		return 0, errors.New("--monitor-export-mode must be an octal POSIX mode in [0,0777]")
	}
	return uint32(value), nil
}

func envIntOr(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func newRuntime(c commonFlags, once bool) (*agent.Runtime, error) {
	col, err := platformCollector(c)
	if err != nil {
		return nil, err
	}
	return agent.NewRuntime(agent.Options{
		StateDir: c.stateDir, CenterURL: c.centerURL, NodeClass: c.nodeClass,
		AgentVersion: version, Collector: col,
	})
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	switch cmd {
	case "enroll":
		os.Exit(runEnroll(os.Args[2:]))
	case "run":
		os.Exit(runAgent(os.Args[2:]))
	case "rotate":
		os.Exit(runRotate(os.Args[2:]))
	case "status":
		os.Exit(runStatus(os.Args[2:]))
	case "service":
		os.Exit(runService(os.Args[2:]))
	case "r1-provision":
		os.Exit(runR1Provision(os.Args[2:]))
	case "version":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: um-agent <enroll|run|rotate|status|service|r1-provision|version> [flags]")
}

func runEnroll(args []string) int {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	var c commonFlags
	var tokenFile string
	var tokenStdin bool
	addCommon(fs, &c)
	fs.StringVar(&tokenFile, "token-file", envOr("UM_AGENT_TOKEN_FILE", ""), "single-use enrollment token file (0600 recommended)")
	fs.BoolVar(&tokenStdin, "token-stdin", false, "read the single-use enrollment token from stdin (recommended root-opened pipe)")
	_ = fs.Parse(args)
	if err := c.validate(); err != nil {
		fmt.Fprintln(os.Stderr, "um-agent:", err)
		return 2
	}
	if tokenFile == "" && !tokenStdin {
		fmt.Fprintln(os.Stderr, "um-agent: --token-file or --token-stdin is required")
		return 2
	}
	if tokenFile != "" && tokenStdin {
		fmt.Fprintln(os.Stderr, "um-agent: choose exactly one of --token-file/--token-stdin")
		return 2
	}
	var raw []byte
	var err error
	if tokenStdin {
		raw, err = io.ReadAll(io.LimitReader(os.Stdin, 4096))
	} else {
		raw, err = os.ReadFile(filepath.Clean(tokenFile))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "um-agent: cannot read enrollment token")
		return 1
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		fmt.Fprintln(os.Stderr, "um-agent: empty enrollment token")
		return 1
	}
	r, err := newRuntime(c, false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "um-agent:", err)
		return 1
	}
	defer r.Close()
	ctx, stop := signalContext()
	defer stop()
	if err := r.Enroll(ctx, token); err != nil {
		fmt.Fprintln(os.Stderr, "um-agent: enrollment failed:", err)
		return 1
	}
	if err := r.PullConfig(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "um-agent: enrollment succeeded but config pull failed:", err)
		return 1
	}
	fmt.Println("enrolled")
	return 0
}

func runAgent(args []string) int {
	ctx, stop := signalContext()
	defer stop()
	if err := runAgentContext(ctx, args); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "um-agent:", err)
		return 1
	}
	return 0
}

// runAgentContext is shared by the console CLI and the Windows service host.
func runAgentContext(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var c commonFlags
	var once bool
	addCommon(fs, &c)
	fs.BoolVar(&once, "once", false, "collect and send one snapshot, then exit")
	_ = fs.Parse(args)
	if err := c.validate(); err != nil {
		return err
	}
	r, err := newRuntime(c, once)
	if err != nil {
		return err
	}
	defer r.Close()
	if once {
		// A committed rotation proof may have lost its ACK; recover it before
		// pulling config, otherwise the center has already revoked the old key
		// and this one-shot path would write fail_closed. Flush also drains any
		// fsynced spool records, which is safe before the single snapshot.
		if err := r.Flush(ctx); err != nil {
			return err
		}
		if err := r.PullConfig(ctx); err != nil {
			return err
		}
		if _, err := r.QueueReport(ctx, "snapshot"); err != nil {
			return err
		}
		return r.Flush(ctx)
	}
	return r.Run(ctx)
}

func runRotate(args []string) int {
	fs := flag.NewFlagSet("rotate", flag.ExitOnError)
	var c commonFlags
	addCommon(fs, &c)
	_ = fs.Parse(args)
	if err := c.validate(); err != nil {
		fmt.Fprintln(os.Stderr, "um-agent:", err)
		return 2
	}
	r, err := newRuntime(c, false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "um-agent:", err)
		return 1
	}
	defer r.Close()
	ctx, stop := signalContext()
	defer stop()
	if err := r.Rotate(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "um-agent:", err)
		return 1
	}
	if err := r.Flush(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "um-agent:", err)
		return 1
	}
	fmt.Println("rotation complete")
	return 0
}

func runStatus(args []string) int {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	var stateDir string
	fs.StringVar(&stateDir, "state-dir", envOr("UM_AGENT_STATE_DIR", ""), "state directory")
	_ = fs.Parse(args)
	if stateDir == "" {
		fmt.Fprintln(os.Stderr, "um-agent: --state-dir is required")
		return 2
	}
	s, err := agent.InspectState(stateDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "um-agent:", err)
		return 1
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s); err != nil {
		return 1
	}
	return 0
}

func runService(args []string) int {
	if err := platformService(args); err != nil {
		fmt.Fprintln(os.Stderr, "um-agent:", err)
		return 1
	}
	return 0
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-ch:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

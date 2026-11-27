//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/agent"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/windowsagent"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/windowsobs"
)

var windowsAgentStartedAt = time.Now()

func platformCollector(commonFlags) (agent.Collector, error) {
	opts := windowsagent.Options{
		AgentVersion: version,
		Uptime: func() int64 {
			return int64(time.Since(windowsAgentStartedAt) / time.Second)
		},
	}
	profilePath := os.Getenv("UM_AGENT_WINDOWS_OBSERVE_PROFILE")
	secretPath := os.Getenv("UM_AGENT_WINDOWS_OBSERVE_SECRET_FILE")
	if profilePath != "" || secretPath != "" {
		if profilePath == "" || secretPath == "" {
			return nil, errors.New("um-agent: Windows observation requires both profile and secret file")
		}
		authorized := os.Getenv("UM_AGENT_WINDOWS_SOURCE_AUTHORIZED")
		if authorized != "1" && !strings.EqualFold(authorized, "true") {
			return nil, errors.New("um-agent: Windows R1 observation is not authorized by OD-P3")
		}
		profile, err := readWindowsProfile(profilePath)
		if err != nil {
			return nil, errors.New("um-agent: invalid Windows observation profile")
		}
		secret, err := readWindowsSecret(secretPath)
		if err != nil {
			return nil, errors.New("um-agent: invalid Windows controller secret")
		}
		observer, err := windowsobs.New(profile, secret)
		if err != nil {
			return nil, errors.New("um-agent: cannot construct Windows route observer")
		}
		opts.Observer = observer
	}
	// The default binary has no terminal route source configured. R1 is
	// write-capable and only reachable through the explicit OD-P3/OD-P7 gate
	// above; R2 has no proven local read-only surface in the tested builds.
	return windowsagent.New(opts)
}

func readWindowsProfile(path string) (windowsobs.Profile, error) {
	raw, err := readRegularBounded(path, 16384)
	if err != nil {
		return windowsobs.Profile{}, err
	}
	var profile windowsobs.Profile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return windowsobs.Profile{}, err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return windowsobs.Profile{}, errors.New("trailing profile data")
	}
	return profile, nil
}

func readWindowsSecret(path string) (string, error) {
	raw, err := readRegularBounded(path, 4096)
	if err != nil {
		return "", err
	}
	secret := strings.TrimSpace(string(raw))
	if secret == "" {
		return "", errors.New("empty controller secret")
	}
	return secret, nil
}

// readRegularBounded refuses symlinks/reparse points, non-regular files and
// over-limit inputs. The secret is never logged or included in an error.
func readRegularBounded(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("expected regular non-symlink file")
	}
	if info.Size() > limit {
		return nil, errors.New("file exceeds configured limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("file exceeds configured limit")
	}
	return raw, nil
}

func platformService(args []string) error {
	// Only the SCM lifecycle wrapper lives here. The final service account, ACL,
	// DPAPI scope and credential rotation remain OD-P7-gated (see ADR); this
	// wrapper does not install, configure, or approve an account.
	err := svc.Run("um-agent", &agentService{args: args})
	if err != nil {
		logServiceEvent(1, "service failed: "+err.Error())
	}
	return err
}

// logServiceEvent writes a closed-code service failure to the Application log.
// Callers must pass errors that contain no token, key, payload or secret.
func logServiceEvent(id uint32, message string) {
	log, err := eventlog.Open("um-agent")
	if err != nil {
		return
	}
	defer log.Close()
	_ = log.Error(id, message)
}

type agentService struct{ args []string }

func (s *agentService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	runArgs := args
	if len(runArgs) == 0 {
		runArgs = s.args
	}
	if len(runArgs) > 0 && runArgs[0] == "service" {
		runArgs = runArgs[1:]
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- runAgentContext(ctx, runArgs) }()

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case cr := <-r:
			switch cr.Cmd {
			case svc.Interrogate:
				changes <- cr.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case err := <-errCh:
					if err != nil && !errors.Is(err, context.Canceled) &&
						!strings.Contains(strings.ToLower(err.Error()), "stopped") {
						logServiceEvent(2, "agent stopped with error: "+err.Error())
						return false, 1
					}
					return false, 0
				case <-time.After(10 * time.Second):
					logServiceEvent(3, "agent stop timed out")
					return false, 0
				}
			}
		case err := <-errCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				logServiceEvent(4, "agent exited with error: "+err.Error())
				return false, 1
			}
			return false, 0
		}
	}
}

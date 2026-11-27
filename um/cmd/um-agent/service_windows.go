//go:build windows

package main

import (
	"context"
	"errors"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/agent"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/windowsagent"
)

func platformCollector(commonFlags) (agent.Collector, error) {
	// The default Windows binary has no terminal route source configured:
	// windowsobs/R1 requires explicit Owner authorization and R2 is not yet
	// validated. The collector therefore emits honest unavailable data.
	return windowsagent.New(windowsagent.Options{AgentVersion: version})
}

func platformService(args []string) error {
	// Only the SCM lifecycle wrapper lives here. The final service account, ACL,
	// DPAPI scope and credential rotation remain OD-P7-gated (see ADR); this
	// wrapper does not install, configure, or approve an account.
	return svc.Run("um-agent", &agentService{args: args})
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
						return false, 1
					}
					return false, 0
				case <-time.After(10 * time.Second):
					return false, 0
				}
			}
		case err := <-errCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				return false, 1
			}
			return false, 0
		}
	}
}

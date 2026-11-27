//go:build windows

// Command um-lab-service is an isolated-lab-only SCM host used to run a
// one-shot console action (enrollment or R1 provisioning) under the exact
// Windows service account before the real `um-agent service` wrapper is
// installed. It is not part of the production agent and is only built/run by
// the Windows lab workflow.
//
// The service ImagePath is:
//   um-lab-service.exe <target.exe> <arg>...
// The helper reports SCM running/stopped correctly and waits for the child.
package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"time"

	"golang.org/x/sys/windows/svc"
)

type labService struct {
	target string
	args   []string
}

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	target := os.Args[1]
	if err := svc.Run("um-agent", &labService{target: target, args: os.Args[2:]}); err != nil {
		os.Exit(1)
	}
}

func (s *labService) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	child := exec.CommandContext(ctx, s.target, s.args...)
	child.Env = os.Environ()
	if err := child.Start(); err != nil {
		return false, 1
	}
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				return false, 1
			}
			return false, 0
		case req := <-requests:
			switch req.Cmd {
			case svc.Interrogate:
				status <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
					return false, 0
				case <-time.After(10 * time.Second):
					return false, 1
				}
			}
		}
	}
}

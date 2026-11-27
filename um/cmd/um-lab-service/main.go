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
	"fmt"
	"os"
	"os/exec"
	"time"

	"golang.org/x/sys/windows/svc"
)

type labService struct {
	target  string
	args    []string
	logPath string
}

func main() {
	args := os.Args[1:]
	logPath := ""
	if len(args) >= 2 && args[0] == "--log" {
		logPath = args[1]
		args = args[2:]
	}
	if len(args) < 1 {
		os.Exit(2)
	}
	target := args[0]
	if err := svc.Run("um-agent", &labService{target: target, args: args[1:], logPath: logPath}); err != nil {
		os.Exit(1)
	}
}

func (s *labService) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	child := exec.CommandContext(ctx, s.target, s.args...)
	child.Env = os.Environ()
	var logFile *os.File
	if s.logPath != "" {
		logFile, _ = os.OpenFile(s.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if logFile != nil {
			defer logFile.Close()
			fmt.Fprintf(logFile, "um-lab-service: start %s %v\n", s.target, s.args)
			child.Stdout = logFile
			child.Stderr = logFile
		}
	}
	if err := child.Start(); err != nil {
		if logFile != nil {
			fmt.Fprintf(logFile, "start error: %v\n", err)
		}
		return false, 1
	}
	done := make(chan error, 1)
	go func() {
		err := child.Wait()
		if logFile != nil {
			fmt.Fprintf(logFile, "child exit: %v\n", err)
			_ = logFile.Sync()
		}
		done <- err
	}()
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

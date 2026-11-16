package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const preparationCommandTimeout = 15 * time.Minute

// Start this clock at command dispatch, after resource and tool-lease waiting.
func preparationCommandContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, preparationCommandTimeout)
}

const (
	processPipeWait               = time.Second
	processGroupSettlementTimeout = 5 * time.Second
	processGroupPollInterval      = 10 * time.Millisecond
	processObservationInterval    = 100 * time.Millisecond
)

type processResult struct {
	diagnostic error
	Status     string
	Started    bool
	Joined     bool
	Cause      error
}

// Protected-file fixtures need a non-writable ancestor chain. Their scratch
// parent belongs to the current workflow or suite, not the general TMPDIR.
type protectedFixtureContextKey struct{}

const protectedFixtureEnvironment = "ENKV_TEST_PROTECTED_FIXTURES"

func runProcess(parent context.Context, binary, directory string, args, environment []string, timeout time.Duration) processResult {
	return runProcessOutput(parent, binary, directory, args, environment, timeout, nil, nil)
}

func runProcessOutput(parent context.Context, binary, directory string, args, environment []string, timeout time.Duration, stdout, stderr io.Writer) processResult {
	if timeout <= 0 {
		return processResult{Status: "timed_out", Joined: true, Cause: context.DeadlineExceeded}
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	command := exec.Command(binary, args...)
	command.Dir, command.Env = directory, environment
	command.Stdout, command.Stderr = stdout, stderr
	return superviseProcess(ctx, command)
}

func superviseProcess(ctx context.Context, command *exec.Cmd) processResult {
	return superviseCommand(ctx, command, nil, false)
}

// The native owner supplies the signal horizon. Normal signals reach only the
// runner PID, so its independent cleanup remains under aggregate observation.
// It takes ownership of ExtraFiles; common callers retain their own files.
func superviseNativeProcess(ctx context.Context, command *exec.Cmd, signals <-chan os.Signal) processResult {
	return superviseCommand(ctx, command, signals, true)
}

func superviseCommand(ctx context.Context, command *exec.Cmd, signals <-chan os.Signal, ownExtraFiles bool) (result processResult) {
	filesClosed := false
	closeExtraFiles := func() error {
		if !ownExtraFiles || filesClosed {
			return nil
		}
		filesClosed = true
		seen := make(map[*os.File]struct{}, len(command.ExtraFiles))
		var failure error
		for _, file := range command.ExtraFiles {
			if file == nil {
				continue
			}
			if _, duplicate := seen[file]; duplicate {
				continue
			}
			seen[file] = struct{}{}
			failure = errors.Join(failure, file.Close())
		}
		if failure != nil {
			return fmt.Errorf("close native process files: %w", failure)
		}
		return nil
	}
	defer func() {
		if err := closeExtraFiles(); err != nil {
			result.Status = "process_failed"
			result.Cause = errors.Join(result.Cause, err)
		}
	}()
	if err := ctx.Err(); err != nil {
		return processResult{Status: processContextStatus(err), Joined: true, Cause: err}
	}
	if command.Env == nil {
		command.Env = raceEnvironment(os.Environ(), raceEnabled(ctx))
	} else {
		command.Env = raceEnvironment(command.Env, raceEnabled(ctx))
	}
	if directory, ok := ctx.Value(protectedFixtureContextKey{}).(string); ok {
		command.Env = environment(command.Env, map[string]string{protectedFixtureEnvironment: directory})
	}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.WaitDelay = processPipeWait
	if err := ctx.Err(); err != nil {
		return processResult{Status: processContextStatus(err), Joined: true, Cause: err}
	}
	startErr := command.Start()
	closeErr := closeExtraFiles()
	if startErr != nil {
		return processResult{Status: "process_failed", Joined: true, Cause: errors.Join(startErr, closeErr)}
	}
	watcher := newProcessIdentityWatcher(command.Process.Pid, false)
	observationErr := watcher.sample()
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	result = processResult{Status: "passed", Started: true}
	defer func() {
		if err := ctx.Err(); err != nil {
			if result.Status == "passed" || result.Status == "interrupted" {
				result.Status = processContextStatus(err)
			}
			result.Cause = errors.Join(result.Cause, err)
		}
	}()
	if observationErr != nil || closeErr != nil {
		result.Status, result.Cause = "process_failed", closeErr
		if observationErr != nil {
			result.Cause = errors.Join(result.Cause, fmt.Errorf("process identity observation: %w", observationErr))
		}
		return stopSupervisedProcess(command.Process.Pid, wait, watcher, result)
	}
	ticker := time.NewTicker(processObservationInterval)
	defer ticker.Stop()
	for {
		select {
		case waitErr := <-wait:
			if waitErr != nil {
				if result.Status == "passed" {
					result.Status = "process_failed"
				}
				result.Cause = errors.Join(result.Cause, waitErr)
			}
			return stopSupervisedProcess(command.Process.Pid, nil, watcher, result)
		case received, open := <-signals:
			if !open {
				signals = nil
				continue
			}
			result.Status = "interrupted"
			result.Cause = errors.Join(result.Cause, context.Canceled)
			for _, forwarded := range []os.Signal{syscall.SIGCONT, received} {
				if err := command.Process.Signal(forwarded); err != nil && !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, syscall.ESRCH) {
					result.Status = "process_failed"
					result.Cause = errors.Join(result.Cause, fmt.Errorf("forward process signal: %w", err))
					return stopSupervisedProcess(command.Process.Pid, wait, watcher, result)
				}
			}
		case <-ctx.Done():
			result.Status = processContextStatus(ctx.Err())
			result.Cause = errors.Join(result.Cause, ctx.Err())
			return stopSupervisedProcess(command.Process.Pid, wait, watcher, result)
		case <-ticker.C:
			if err := watcher.sample(); err != nil {
				result.Status = "process_failed"
				result.Cause = errors.Join(result.Cause, fmt.Errorf("process identity observation: %w", err))
				return stopSupervisedProcess(command.Process.Pid, wait, watcher, result)
			}
		}
	}
}

func stopSupervisedProcess(pid int, wait <-chan error, watcher *processIdentityWatcher, result processResult) processResult {
	stopErr := stopGroup(pid)
	if watcher != nil {
		stopErr = errors.Join(stopErr, watcher.stopEscaped())
	}
	joined, joinErr := groupStopped(pid, wait)
	result.Joined = joined
	result.Cause = errors.Join(result.Cause, stopErr, joinErr)
	if watcher != nil {
		deadline := time.Now().Add(processGroupSettlementTimeout)
		for {
			stopped, err := watcher.escapedStopped()
			if err != nil {
				result.Cause = errors.Join(result.Cause, err)
				result.Joined = false
				break
			}
			if stopped {
				break
			}
			if !time.Now().Before(deadline) {
				result.Cause = errors.Join(result.Cause, errors.New("escaped descendant is not settled"))
				result.Joined = false
				break
			}
			escapedStopErr := watcher.stopEscaped()
			stopErr = errors.Join(stopErr, escapedStopErr)
			result.Cause = errors.Join(result.Cause, escapedStopErr)
			time.Sleep(processGroupPollInterval)
		}
	}
	if !result.Joined || stopErr != nil {
		result.Status = "group_stop_failed"
	}
	return result
}

func processContextStatus(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timed_out"
	}
	return "interrupted"
}

func stopGroup(pid int) error {
	err := syscall.Kill(-pid, syscall.SIGKILL)
	// Darwin returns EPERM when the group contains only unreaped zombies.
	// groupStopped still waits for the group to disappear after this call.
	if errors.Is(err, syscall.ESRCH) || errors.Is(err, syscall.EPERM) {
		return nil
	}
	return err
}

func groupStopped(pid int, wait <-chan error) (bool, error) {
	deadline := time.Now().Add(processGroupSettlementTimeout)
	var waitErr error
	if wait != nil {
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		select {
		case waitErr = <-wait:
		case <-timer.C:
			return false, errors.New("writer did not stop within the settlement allowance")
		}
	}
	for {
		err := syscall.Kill(-pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return true, waitErr
		}
		if err != nil && !errors.Is(err, syscall.EPERM) {
			return false, errors.Join(waitErr, err)
		}
		if !time.Now().Before(deadline) {
			return false, errors.Join(waitErr, err, errors.New("worker group is not settled"))
		}
		time.Sleep(processGroupPollInterval)
	}
}

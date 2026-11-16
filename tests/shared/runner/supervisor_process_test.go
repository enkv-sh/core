package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// full_only: false
func TestProcessIdentityWatcherAcceptsConfirmedShortExit(t *testing.T) {
	command := exec.Command("/bin/sh", "-c", "exit 0")
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
	watcher := newProcessIdentityWatcher(command.Process.Pid, false)
	if err := watcher.sample(); err != nil || !watcher.rootGone || watcher.rootIdentity.start != 0 || len(watcher.owned) != 0 {
		t.Fatal("confirmed short exit fabricated an identity or failed", watcher, err)
	}
	if joined, err := groupStopped(command.Process.Pid, nil); !joined || err != nil || command.ProcessState == nil {
		t.Fatal("confirmed short exit lacks actual Wait/group absence", err)
	}
}

// full_only: false
func TestProcessIdentityObservationRefusesLiveUncertainty(t *testing.T) {
	for _, observationErr := range []error{syscall.ESRCH, errors.New("controlled denied identity observation")} {
		t.Run(observationErr.Error(), func(t *testing.T) {
			command := exec.Command("/bin/sleep", "30")
			command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				stopErr := stopGroup(command.Process.Pid)
				waitErr := command.Wait()
				var exit *exec.ExitError
				if stopErr != nil || waitErr != nil && !errors.As(waitErr, &exit) {
					t.Error("identity fixture did not stop/wait", stopErr, waitErr)
				}
				if joined, err := groupStopped(command.Process.Pid, nil); !joined || err != nil || command.ProcessState == nil {
					t.Error("identity fixture did not positively join", err)
				}
			})
			watcher := newProcessIdentityWatcher(command.Process.Pid, false)
			_, err := watcher.observe(func(int) (processMemoryInfo, error) {
				return processMemoryInfo{}, observationErr
			})
			if err == nil || watcher.rootGone || watcher.rootIdentity.start != 0 || len(watcher.owned) != 0 {
				t.Fatal("live observation uncertainty was accepted or fabricated a generation", watcher, err)
			}
			if !errors.Is(observationErr, syscall.ESRCH) && !errors.Is(err, observationErr) {
				t.Fatal("native identity failure cause was lost", err)
			}
		})
	}
}

// full_only: false
func TestProcessIdentityWatcherDoesNotSignalAnotherGeneration(t *testing.T) {
	command := exec.Command("/bin/sleep", "30")
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopErr := stopGroup(command.Process.Pid)
		waitErr := command.Wait()
		var exit *exec.ExitError
		if stopErr != nil || waitErr != nil && !errors.As(waitErr, &exit) {
			t.Error("foreign-generation fixture did not stop/wait", stopErr, waitErr)
		}
		if joined, err := groupStopped(command.Process.Pid, nil); !joined || err != nil || command.ProcessState == nil {
			t.Error("foreign-generation fixture did not positively join", err)
		}
	})
	identity, err := nativeProcessIdentity(command.Process.Pid)
	if err != nil || identity.identity.start == 0 {
		t.Fatal("foreign native generation unavailable", err)
	}
	watcher := newProcessIdentityWatcher(os.Getpid(), false)
	watcher.owned[processIdentity{pid: command.Process.Pid, start: identity.identity.start + 1}] = struct{}{}
	if err := watcher.stopEscaped(); err != nil {
		t.Fatal(err)
	}
	if stopped, err := watcher.escapedStopped(); !stopped || err != nil {
		t.Fatal("old generation was adopted", err)
	}
	after, err := nativeProcessIdentity(command.Process.Pid)
	if err != nil || after.identity != identity.identity || after.state == 'Z' {
		t.Fatal("old-generation cleanup killed a live foreign generation", after, err)
	}
}

// full_only: false
func TestNativeProcessClosesTransferredFilesBeforeWait(t *testing.T) {
	for _, mode := range []string{"native_owner", "common_caller_owner"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			input, release, err := os.Pipe()
			if err != nil {
				reader.Close()
				writer.Close()
				t.Fatal(err)
			}
			command := exec.Command("/bin/sh", "-c", `printf '%s\n' "$$" >&3; exec 3>&- 4>&-; read value`)
			command.Stdin = input
			// One file may supply two child descriptors. Ownership closes the
			// file object once, after both descriptors have been inherited.
			command.ExtraFiles = []*os.File{writer, writer}
			done := make(chan processResult, 1)
			go func() {
				if mode == "native_owner" {
					done <- superviseNativeProcess(ctx, command, nil)
				} else {
					done <- superviseProcess(ctx, command)
				}
			}()
			finished := false
			readerDone := make(chan struct{})
			callerFileClosed := mode == "native_owner"
			t.Cleanup(func() {
				cancel()
				if !finished {
					<-done
				}
				if !callerFileClosed {
					if err := writer.Close(); err != nil {
						t.Error("caller file cleanup failed", err)
					}
				}
				if err := errors.Join(reader.Close(), input.Close(), release.Close()); err != nil {
					t.Error("pipe fixture cleanup failed", err)
				}
				<-readerDone
			})
			type pipeResult struct {
				text string
				err  error
			}
			ready := make(chan pipeResult, 1)
			eof := make(chan pipeResult, 1)
			go func() {
				defer close(readerDone)
				buffer := bufio.NewReader(reader)
				line, err := buffer.ReadString('\n')
				ready <- pipeResult{line, err}
				if err != nil {
					eof <- pipeResult{err: err}
					return
				}
				body, err := io.ReadAll(buffer)
				eof <- pipeResult{string(body), err}
			}()
			var first pipeResult
			select {
			case first = <-ready:
			case <-ctx.Done():
				t.Fatal("child did not write its inherited descriptor", ctx.Err())
			}
			pid, parseErr := strconv.Atoi(strings.TrimSpace(first.text))
			if first.err != nil || parseErr != nil || pid <= 0 {
				t.Fatal("inherited descriptor has no child PID", first, parseErr)
			}
			if mode == "common_caller_owner" {
				if _, err := writer.WriteString("caller-owned\n"); err != nil {
					t.Fatal("common process took caller file ownership", err)
				}
			}
			if mode == "native_owner" {
				select {
				case terminal := <-eof:
					if terminal.err != nil || terminal.text != "" {
						t.Fatal("native descriptor EOF differs", terminal)
					}
				case <-ctx.Done():
					t.Fatal("parent retained a transferred descriptor while waiting", ctx.Err())
				}
				if _, err := writer.WriteString("unexpected"); !errors.Is(err, os.ErrClosed) {
					t.Fatal("native parent did not close the transferred file", err)
				}
			}
			identity, err := nativeProcessIdentity(pid)
			if err != nil || identity.identity.pid != pid || identity.state == 'Z' {
				t.Fatal("inherited-descriptor child is not alive before cancellation", identity, err)
			}
			select {
			case result := <-done:
				finished = true
				t.Fatal("process owner returned before child release", result)
			default:
			}
			cancel()
			result := <-done
			finished = true
			if !result.Started || !result.Joined || command.ProcessState == nil || result.Status != "interrupted" ||
				!errors.Is(result.Cause, context.Canceled) || errors.Is(result.Cause, os.ErrClosed) {
				t.Fatal("transferred descriptor process lost actual Wait or closed twice", result)
			}
			if !errors.Is(syscall.Kill(-pid, 0), syscall.ESRCH) {
				t.Fatal("transferred descriptor child group remains")
			}
			if mode == "common_caller_owner" {
				// Child readiness proves inheritance. Receiving the supervision
				// result orders Close after Start's File.Fd read.
				closeErr := writer.Close()
				callerFileClosed = true
				if closeErr != nil {
					t.Fatal("caller could not close its file", closeErr)
				}
				select {
				case terminal := <-eof:
					if terminal.err != nil || terminal.text != "caller-owned\n" {
						t.Fatal("caller descriptor EOF differs", terminal)
					}
				case <-time.After(processPipeWait):
					t.Fatal("caller descriptor did not reach EOF")
				}
			}
		})
	}
}

// full_only: false
func TestNativeProcessClosesTransferredFilesWithoutStart(t *testing.T) {
	for _, mode := range []string{"already_canceled", "start_failed", "close_failed"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			readerDone := make(chan struct{})
			reading := false
			t.Cleanup(func() {
				if err := reader.Close(); err != nil {
					t.Error(err)
				}
				if reading {
					<-readerDone
				}
			})
			command := exec.Command(filepath.Join(t.TempDir(), "missing"))
			command.ExtraFiles = []*os.File{writer}
			if mode != "start_failed" {
				cancel()
			}
			if mode == "close_failed" {
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
			}
			result := superviseNativeProcess(ctx, command, nil)
			if result.Started || !result.Joined || command.Process != nil || command.ProcessState != nil {
				t.Fatal("non-started native process fabricated a physical result", result)
			}
			if mode == "already_canceled" && (result.Status != "interrupted" || !errors.Is(result.Cause, context.Canceled)) ||
				mode == "start_failed" && (result.Status != "process_failed" || !errors.Is(result.Cause, os.ErrNotExist)) ||
				mode == "close_failed" && (result.Status != "process_failed" || !errors.Is(result.Cause, os.ErrClosed) || !errors.Is(result.Cause, context.Canceled)) {
				t.Fatal("native file closure lost its original or close cause", result)
			}
			eof := make(chan error, 1)
			reading = true
			go func() {
				defer close(readerDone)
				body, err := io.ReadAll(reader)
				if len(body) != 0 {
					err = errors.Join(err, errors.New("non-started native process wrote pipe data"))
				}
				eof <- err
			}()
			select {
			case err := <-eof:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("non-started native process retained transferred file")
			}
		})
	}
}

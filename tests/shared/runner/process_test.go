package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// full_only: false
func TestProcessHelper(t *testing.T) {
	mode := os.Getenv("ENKV_PROCESS_HELPER")
	if mode == "" {
		return
	}
	if mode == "failed" {
		t.Fatal("expected worker failure")
	}
	if mode == "exited" {
		return
	}
	directory := os.Getenv("ENKV_PROCESS_FIXTURE")
	if mode == "existing_cleanup_child" {
		terms := make(chan os.Signal, 1)
		signal.Notify(terms, syscall.SIGTERM)
		defer signal.Stop(terms)
		if err := os.WriteFile(filepath.Join(directory, "existing.pid"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			t.Fatal(err)
		}
		deadline := time.NewTimer(10 * time.Second)
		defer deadline.Stop()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		recordTerm := func() {
			if err := os.WriteFile(filepath.Join(directory, "existing.term"), nil, 0600); err != nil {
				t.Fatal(err)
			}
		}
		for {
			select {
			case <-terms:
				recordTerm()
			case <-ticker.C:
				if _, err := os.Stat(filepath.Join(directory, "existing.release")); err == nil {
					select {
					case <-terms:
						recordTerm()
					default:
					}
					return
				} else if !os.IsNotExist(err) {
					t.Fatal(err)
				}
			case <-deadline.C:
				t.Fatal("owner did not release the existing child")
			}
		}
	}
	if mode == "cleanup_child" {
		if err := os.WriteFile(filepath.Join(directory, "cleanup.pid"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(10 * time.Second)
		for {
			if _, err := os.Stat(filepath.Join(directory, "cleanup.release")); err == nil {
				return
			} else if !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if !time.Now().Before(deadline) {
				t.Fatal("cleanup monitor did not release the child")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if mode == "cleanup_owner" || mode == "stopped_owner_with_existing_child" {
		ctx, stop := signal.NotifyContext(t.Context(), syscall.SIGTERM)
		defer stop()
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		var existing *exec.Cmd
		if mode == "stopped_owner_with_existing_child" {
			existing = exec.Command(executable, "-test.run=^TestProcessHelper$", "-test.parallel=1")
			existing.Env = environment(os.Environ(), map[string]string{"ENKV_PROCESS_HELPER": "existing_cleanup_child"})
			if err := existing.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if existing != nil {
					releaseErr := os.WriteFile(filepath.Join(directory, "existing.release"), nil, 0600)
					if err := errors.Join(releaseErr, existing.Wait()); err != nil {
						t.Error("existing child cleanup did not join", err)
					}
				}
			}()
			deadline := time.Now().Add(10 * time.Second)
			for {
				body, err := os.ReadFile(filepath.Join(directory, "existing.pid"))
				if err == nil {
					pid, parseErr := strconv.Atoi(string(body))
					if parseErr != nil || pid != existing.Process.Pid {
						t.Fatal("existing child readiness has the wrong PID", parseErr)
					}
					break
				} else if !os.IsNotExist(err) {
					t.Fatal(err)
				}
				if !time.Now().Before(deadline) {
					t.Fatal("existing child readiness was not observed")
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		if err := os.WriteFile(filepath.Join(directory, "writer.pid"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			t.Fatal(err)
		}
		<-ctx.Done()
		child := exec.Command(executable, "-test.run=^TestProcessHelper$", "-test.parallel=1")
		child.Env = environment(os.Environ(), map[string]string{"ENKV_PROCESS_HELPER": "cleanup_child"})
		if err := child.Run(); err != nil {
			t.Fatal("independent cleanup did not join", err)
		}
		if existing != nil {
			if err := os.WriteFile(filepath.Join(directory, "existing.release"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			waitErr := existing.Wait()
			existing = nil
			if waitErr != nil {
				t.Fatal("existing child did not join", waitErr)
			}
		}
		if err := os.WriteFile(filepath.Join(directory, "cleanup.complete"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	if mode == "child" {
		if os.Getenv("ENKV_PROCESS_ESCAPE_GROUP") == "1" {
			if err := syscall.Setpgid(0, 0); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(directory, "child.pid"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Minute)
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestProcessHelper$")
	child.Env = environment(os.Environ(), map[string]string{"ENKV_PROCESS_HELPER": "child"})
	if mode == "escaped" {
		child.Env = environment(child.Env, map[string]string{"ENKV_PROCESS_ESCAPE_GROUP": "1"})
	}
	if strings.HasPrefix(mode, "captured_") {
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "writer.pid"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}
	if strings.TrimPrefix(mode, "captured_") == "orphan" {
		deadline := time.Now().Add(10 * time.Second)
		for {
			body, _ := os.ReadFile(filepath.Join(directory, "child.pid"))
			pid, _ := strconv.Atoi(string(body))
			if pid == child.Process.Pid {
				break
			}
			if !time.Now().Before(deadline) {
				t.Fatal("child readiness was not observed")
			}
			time.Sleep(10 * time.Millisecond)
		}
		return
	}
	time.Sleep(time.Minute)
}

// full_only: false
func TestProcessSupervisionStopsAndJoinsBeforeReturning(t *testing.T) {
	for _, mode := range []string{"interrupted", "timed_out", "orphan", "captured_interrupted", "captured_timed_out", "captured_orphan"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			var result processResult
			timeout := 15 * time.Second
			operation := strings.TrimPrefix(mode, "captured_")
			if operation == "timed_out" {
				timeout = 3 * time.Second
			}
			go func() {
				env := environment(os.Environ(), map[string]string{"ENKV_PROCESS_HELPER": mode, "ENKV_PROCESS_FIXTURE": directory})
				args := []string{"-test.run=^TestProcessHelper$"}
				if strings.HasPrefix(mode, "captured_") {
					deadline, stop := context.WithTimeout(ctx, timeout)
					defer stop()
					command := exec.Command(executable, args...)
					command.Dir, command.Env = directory, env
					var stdout, stderr limitedOutput
					command.Stdout, command.Stderr = &stdout, &stderr
					result = superviseProcess(deadline, command)
				} else {
					result = runProcess(ctx, executable, directory, args, env, timeout)
				}
				close(done)
			}()
			t.Cleanup(func() { cancel(); <-done })
			var writer, child int
			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) {
				writerBytes, _ := os.ReadFile(filepath.Join(directory, "writer.pid"))
				childBytes, _ := os.ReadFile(filepath.Join(directory, "child.pid"))
				writer, _ = strconv.Atoi(string(writerBytes))
				child, _ = strconv.Atoi(string(childBytes))
				if writer > 0 && child > 0 {
					break
				}
				select {
				case <-done:
					t.Fatalf("worker finished before registering its child: %+v", result)
				default:
				}
				time.Sleep(10 * time.Millisecond)
			}
			if writer == 0 || child == 0 {
				t.Fatal("worker did not register its child")
			}
			if operation == "interrupted" {
				cancel()
			}
			select {
			case <-done:
			case <-time.After(8 * time.Second):
				t.Fatal("worker did not stop within its deadline and settlement allowance")
			}
			want := operation
			if operation == "orphan" {
				want = "passed"
				if mode == "captured_orphan" {
					want = "process_failed"
					if !errors.Is(result.Cause, exec.ErrWaitDelay) {
						t.Fatalf("held capture pipe did not retain its wait failure: %+v", result)
					}
				}
			}
			if result.Status != want || !result.Started || !result.Joined {
				t.Fatalf("worker supervision: %+v", result)
			}
			if operation == "interrupted" && !errors.Is(result.Cause, context.Canceled) || operation == "timed_out" && !errors.Is(result.Cause, context.DeadlineExceeded) {
				t.Fatalf("worker context cause was lost: %+v", result)
			}
			for _, pid := range []int{writer, child} {
				if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
					t.Errorf("worker %d remains after join: %v", pid, err)
				}
			}
		})
	}
}

// full_only: false
func TestProcessExpiredBudgetDoesNotStartAWorker(t *testing.T) {
	result := runProcess(context.Background(), "unavailable", t.TempDir(), nil, nil, 0)
	if result.Status != "timed_out" || result.Started || !result.Joined {
		t.Fatal("expired workload started a worker")
	}
}

// full_only: false
func TestProcessCanceledContextDoesNotStartAWorker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := runProcess(ctx, "unavailable", t.TempDir(), nil, nil, time.Minute)
	if result.Status != "interrupted" || result.Started || !result.Joined || !errors.Is(result.Cause, context.Canceled) {
		t.Fatalf("canceled workload started a worker or lost its cause: %+v", result)
	}
}

// full_only: false
func TestProcessUsesCurrentProtectedFixtureOwner(t *testing.T) {
	directory := t.TempDir()
	ctx := context.WithValue(t.Context(), protectedFixtureContextKey{}, directory)
	command := exec.Command("/bin/sh", "-c", `printf '%s' "$ENKV_TEST_PROTECTED_FIXTURES" > "$ENKV_TEST_PROTECTED_FIXTURES/child"`)
	command.Env = environment(os.Environ(), map[string]string{protectedFixtureEnvironment: filepath.Join(directory, "stale-owner")})
	result := superviseProcess(ctx, command)
	if result.Status != "passed" || !result.Started || !result.Joined {
		t.Fatalf("protected fixture process did not settle: %+v", result)
	}
	body, err := os.ReadFile(filepath.Join(directory, "child"))
	if err != nil || string(body) != directory {
		t.Fatal("child did not use the current owned fixture parent", err)
	}
}

// full_only: false
func TestProcessFailureRetainsExitErrorAfterJoining(t *testing.T) {
	t.Run("launch_failure", func(t *testing.T) {
		root := t.TempDir()
		ctx := t.Context()
		result := runProcess(ctx, filepath.Join(root, "absent"), root, nil, nil, time.Minute)
		if result.Status != "process_failed" || result.Started || !result.Joined || !errors.Is(result.Cause, os.ErrNotExist) {
			t.Fatalf("launch failure lost its physical result: %+v", result)
		}
	})
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	result := runProcess(context.Background(), executable, t.TempDir(), []string{"-test.run=^TestProcessHelper$"}, environment(os.Environ(), map[string]string{"ENKV_PROCESS_HELPER": "failed"}), 15*time.Second)
	var exitError *exec.ExitError
	if result.Status != "process_failed" || !result.Joined || !errors.As(result.Cause, &exitError) {
		t.Fatalf("worker failure was lost during settlement: %+v", result)
	}
}

// full_only: false
func TestProcessSettlementBoundsAnUnfinishedWriterWait(t *testing.T) {
	if joined, err := groupStopped(os.Getpid(), make(chan error)); joined || err == nil {
		t.Fatal("unsettled writer was reported as joined")
	}
}

// full_only: false
func TestProcessSettlementWaitsForAnUnreapedGroup(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestProcessHelper$")
	command.Env = environment(os.Environ(), map[string]string{"ENKV_PROCESS_HELPER": "exited"})
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	reaped := false
	t.Cleanup(func() {
		if !reaped {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	// EOF observes exit without reaping the leader. On macOS a group with
	// only zombie members reports EPERM until Wait removes the last member.
	if _, err := io.Copy(io.Discard, stdout); err != nil {
		t.Fatal(err)
	}
	done := make(chan processResult, 1)
	go func() {
		joined, err := groupStopped(command.Process.Pid, nil)
		done <- processResult{Joined: joined, Cause: err}
	}()
	select {
	case result := <-done:
		t.Errorf("settlement returned before the group was reaped: %+v", result)
	case <-time.After(100 * time.Millisecond):
	}
	err = command.Wait()
	reaped = true
	if err != nil {
		t.Fatal(err)
	}
	if t.Failed() {
		return
	}
	select {
	case result := <-done:
		if !result.Joined || result.Cause != nil {
			t.Fatalf("reaped group did not settle: %+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("settlement did not observe the reaped group")
	}
}

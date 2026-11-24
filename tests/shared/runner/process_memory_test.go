package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func waitProcessMarker(t *testing.T, ctx context.Context, path string) int {
	t.Helper()
	ticker := time.NewTicker(processGroupPollInterval)
	defer ticker.Stop()
	for {
		body, err := os.ReadFile(path)
		if err == nil && len(bytes.TrimSpace(body)) != 0 {
			pid, err := strconv.Atoi(string(bytes.TrimSpace(body)))
			if err != nil || pid <= 0 {
				t.Fatal("process marker has no valid PID", path, err)
			}
			return pid
		}
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("process marker was not observed", path, ctx.Err())
		case <-ticker.C:
		}
	}
}

func aggregateObservedPID(g *invocationMemoryGuard, pid int) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for id := range g.watcher.owned {
		if id.pid == pid {
			return true
		}
	}
	return false
}

func waitAggregateProcess(t *testing.T, ctx context.Context, g *invocationMemoryGuard, pid int) {
	t.Helper()
	ticker := time.NewTicker(processGroupPollInterval)
	defer ticker.Stop()
	for !aggregateObservedPID(g, pid) {
		select {
		case <-ctx.Done():
			t.Fatal("native aggregate did not observe process", pid, ctx.Err())
		case <-g.failure():
			_, err := g.result()
			t.Fatal("native aggregate failed before process observation", err)
		case <-ticker.C:
		}
	}
}

func startTestAggregate(t *testing.T) *invocationMemoryGuard {
	t.Helper()
	g, sample, err := startInvocationMemoryGuard(processMemoryMaximum)
	if err != nil {
		t.Fatal("native aggregate did not start", sample, err)
	}
	t.Cleanup(func() {
		if _, err := g.stop(); err != nil {
			t.Error("native aggregate failed", err)
		}
	})
	return g
}

// full_only: false
func TestProcessForwardedSignalKeepsCleanupMonitored(t *testing.T) {
	for _, mode := range []string{"cleanup_passed", "stopped_owner_with_existing_child"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
			defer cancel()
			g := startTestAggregate(t)
			command := exec.Command(executable, "-test.run=^TestProcessHelper$", "-test.parallel=1")
			helperMode := "cleanup_owner"
			if mode == "stopped_owner_with_existing_child" {
				helperMode = mode
			}
			command.Env = environment(os.Environ(), map[string]string{"ENKV_PROCESS_HELPER": helperMode, "ENKV_PROCESS_FIXTURE": directory})
			signals := make(chan os.Signal, 1)
			done := make(chan processResult, 1)
			go func() { done <- superviseNativeProcess(ctx, command, signals) }()
			finished := false
			t.Cleanup(func() {
				cancel()
				if !finished {
					<-done
				}
				if stopped, err := g.stopDescendants(); err != nil || !stopped {
					t.Error("cleanup fixture descendants remain", err)
				}
			})
			writer := waitProcessMarker(t, ctx, filepath.Join(directory, "writer.pid"))
			waitAggregateProcess(t, ctx, g, writer)
			if mode == "stopped_owner_with_existing_child" {
				existing := waitProcessMarker(t, ctx, filepath.Join(directory, "existing.pid"))
				waitAggregateProcess(t, ctx, g, existing)
				if err := syscall.Kill(writer, syscall.SIGSTOP); err != nil {
					t.Fatal(err)
				}
				for {
					owner, err := nativeProcessIdentity(writer)
					if err != nil {
						t.Fatal(err)
					}
					if owner.state == 'T' {
						break
					}
					select {
					case <-ctx.Done():
						t.Fatal("owner did not stop", ctx.Err())
					case <-time.After(processGroupPollInterval):
					}
				}
			}
			signals <- syscall.SIGTERM
			cleanup := waitProcessMarker(t, ctx, filepath.Join(directory, "cleanup.pid"))
			waitAggregateProcess(t, ctx, g, cleanup)
			if err := os.WriteFile(filepath.Join(directory, "cleanup.release"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			var result processResult
			select {
			case result = <-done:
				finished = true
			case <-ctx.Done():
				t.Fatal("cleanup owner did not join", ctx.Err())
			}
			if result.Status != "interrupted" || !result.Started || !result.Joined || command.ProcessState == nil ||
				!errors.Is(result.Cause, context.Canceled) {
				t.Fatal("forwarded signal lost physical cleanup result", result)
			}
			if _, err := os.Stat(filepath.Join(directory, "cleanup.complete")); err != nil {
				t.Fatal("independent cleanup did not complete", err)
			}
			if _, err := os.Stat(filepath.Join(directory, "existing.term")); !os.IsNotExist(err) {
				t.Fatal("forwarded signal reached an existing worker", err)
			}
			for _, pid := range []int{writer, cleanup} {
				if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
					t.Fatal("joined cleanup process remains", pid, err)
				}
			}
		})
	}
}

// full_only: false
func TestProcessResourceLimitStopsAndJoinsWithoutLargeAllocation(t *testing.T) {
	runSupervisorMemoryWitness(t, "^TestMemoryWitness$/^(below_limit|at_limit|above_limit|partial_failure|unavailable|earlier_peak)$")
}

// full_only: false
func TestProcessMemorySamplerSeesSmallNativeProcess(t *testing.T) {
	identity, err := nativeProcessIdentity(os.Getpid())
	if err != nil || identity.identity.pid != os.Getpid() || identity.identity.start == 0 || identity.group == 0 {
		t.Fatal("native process identity is incomplete", identity, err)
	}
	g := startTestAggregate(t)
	sample, err := g.stop()
	if err != nil || sample.count < 1 || sample.bytes == 0 || sample.peak < sample.bytes || sample.limit != 25_769_803_776 {
		t.Fatal("native aggregate sample is incomplete", sample, err)
	}
	t.Run("exited_child_keeps_identity_until_wait", func(t *testing.T) {
		child := exec.Command("true")
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if child.ProcessState == nil {
				if err := child.Wait(); err != nil {
					t.Error(err)
				}
			}
		}()
		pid := child.Process.Pid
		ctx, cancel := context.WithTimeout(t.Context(), processGroupSettlementTimeout)
		defer cancel()
		var observed processIdentity
		for {
			info, err := nativeProcessIdentity(pid)
			if err != nil || info.identity.pid != pid || info.identity.start == 0 || info.parent != os.Getpid() {
				t.Fatal("child identity unavailable before Wait", info, err)
			}
			if info.state == 'Z' {
				observed = info.identity
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal("child exit was not observed", ctx.Err())
			case <-time.After(processGroupPollInterval):
			}
		}
		usage, err := nativeProcessMemory(pid)
		if err != nil || usage.identity != observed {
			t.Fatal("exited child lost its memory observation before Wait", usage, err)
		}
		if err := child.Wait(); err != nil {
			t.Fatal(err)
		}
		if info, err := nativeProcessIdentity(pid); !errors.Is(err, syscall.ESRCH) && (err != nil || info.identity == observed) {
			t.Fatal("could not establish that Wait removed the child", info, err)
		}
	})
}

// full_only: false
func TestProcessMemoryNativeChildCensusSeesMoreThanTen(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatal(err)
	}
	type started struct {
		command *exec.Cmd
		err     error
	}
	starts := make(chan started, 12)
	release := make(chan struct{})
	threadsJoined := make(chan struct{}, 12)
	children := make([]*exec.Cmd, 0, 12)
	t.Cleanup(func() {
		close(release)
		for _, child := range children {
			if err := child.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Errorf("stop child %d: %v", child.Process.Pid, err)
			}
		}
		for _, child := range children {
			var exit *exec.ExitError
			if err := child.Wait(); err != nil && !errors.As(err, &exit) {
				t.Errorf("join child %d: %v", child.Process.Pid, err)
			}
		}
		for range 12 {
			<-threadsJoined
		}
	})
	for range 12 {
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			defer func() { threadsJoined <- struct{}{} }()
			child := exec.Command(sleep, "30")
			starts <- started{command: child, err: child.Start()}
			<-release
		}()
	}
	var startErr error
	for range 12 {
		result := <-starts
		if result.err != nil {
			startErr = errors.Join(startErr, result.err)
		} else {
			children = append(children, result.command)
		}
	}
	if startErr != nil {
		t.Fatal(startErr)
	}
	seen, err := nativeProcessChildren(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	for _, child := range children {
		found := false
		for _, pid := range seen {
			if pid == child.Process.Pid {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("native child census omitted %d from %d children on locked threads", child.Process.Pid, len(seen))
		}
	}
}

// full_only: false
func TestProcessResourceEvidenceRetainsPeakAndLimit(t *testing.T) {
	inv, _, _ := telemetryImportFixture(t)
	for _, status := range []string{"resource_limit", "passed"} {
		t.Run(status, func(t *testing.T) {
			state := &runState{record: runRecord{Suite: "hermetic"}}
			evidence, _, err := state.importWorker(inv, inv.Scenario, processResult{
				Status: status, Started: true, Joined: true,
			}, nil)
			if err == nil || evidence.Process != status || evidence.MemoryPeakBytes != 0 || evidence.MemoryLimitBytes != 0 {
				t.Fatalf("worker import invented a new child memory observation: %+v, %v", evidence, err)
			}
			body, err := json.Marshal(evidence)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(body, []byte("memory_peak_bytes")) || bytes.Contains(body, []byte("memory_limit_bytes")) {
				t.Fatal("new worker record emitted unavailable child memory fields", string(body))
			}
			var decoded workerEvidence
			if err := json.Unmarshal(body, &decoded); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(`{"memory_peak_bytes":7,"memory_limit_bytes":5}`), &decoded); err != nil ||
				decoded.MemoryPeakBytes != 7 || decoded.MemoryLimitBytes != 5 {
				t.Fatalf("historical worker memory fields are no longer readable: %+v, %v", decoded, err)
			}
			if status == "resource_limit" {
				decoded.Role = "cleanup"
				if !validAttemptWorker(decoded) {
					t.Fatal("report reader refused a historical joined resource-limited worker")
				}
			}
		})
	}
}

// full_only: false
func TestProcessNativeResourceLimitStopsAndJoins(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	defer cancel()
	g, initial, err := startInvocationMemoryGuard(processMemoryMaximum)
	if err != nil {
		t.Fatal("native aggregate did not start", initial, err)
	}
	t.Cleanup(func() { g.stop() })
	directory := t.TempDir()
	command := exec.Command("/bin/sh", "-c", `echo $$ > "$1"; sleep 30`, "aggregate-fixture", filepath.Join(directory, "writer.pid"))
	done := make(chan processResult, 1)
	go func() { done <- superviseProcess(ctx, command) }()
	finished := false
	t.Cleanup(func() {
		cancel()
		if !finished {
			<-done
		}
		if stopped, err := g.stopDescendants(); err != nil || !stopped {
			t.Error("native aggregate fixture remains", err)
		}
	})
	pid := waitProcessMarker(t, ctx, filepath.Join(directory, "writer.pid"))
	waitAggregateProcess(t, ctx, g, pid)
	if err := g.setLimit(1); err == nil {
		t.Fatal("one-byte aggregate allowance accepted a live native process")
	}
	select {
	case <-g.failure():
	default:
		t.Fatal("aggregate failure was not latched")
	}
	cancel()
	result := <-done
	finished = true
	stopped, stopErr := g.stopDescendants()
	sample, guardErr := g.stop()
	if !result.Started || !result.Joined || command.ProcessState == nil || !stopped || stopErr != nil ||
		guardErr == nil || sample.limit != 1 || sample.peak <= 1 {
		t.Fatal("native aggregate failure lost actual process joins", result, sample, guardErr, stopErr)
	}
	if !errors.Is(syscall.Kill(-pid, 0), syscall.ESRCH) {
		t.Fatal("native aggregate failure retained the original group")
	}
}

// full_only: false
func TestProcessMemoryWatcherStopsEscapedChildGroup(t *testing.T) {
	directory := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	defer cancel()
	g := startTestAggregate(t)
	command := exec.Command(executable, "-test.run=^TestProcessHelper$")
	command.Dir = directory
	command.Env = environment(os.Environ(), map[string]string{"ENKV_PROCESS_HELPER": "escaped", "ENKV_PROCESS_FIXTURE": directory})
	done := make(chan processResult, 1)
	go func() { done <- superviseProcess(ctx, command) }()
	finished := false
	t.Cleanup(func() {
		cancel()
		if !finished {
			<-done
		}
		if stopped, err := g.stopDescendants(); err != nil || !stopped {
			t.Error("escaped fixture remains", err)
		}
	})
	child := waitProcessMarker(t, ctx, filepath.Join(directory, "child.pid"))
	waitAggregateProcess(t, ctx, g, child)
	cancel()
	result := <-done
	finished = true
	stopped, err := g.stopDescendants()
	if result.Status != "interrupted" || !result.Started || !result.Joined || command.ProcessState == nil || !stopped || err != nil {
		t.Fatal("observed escaped group did not settle", result, err)
	}
	if err := syscall.Kill(child, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatal("observed escaped child remains", err)
	}
}

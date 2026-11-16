package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The copied stop owner gets a held first escape signal and one later identity
// fault. Native ownership, the final signal, Wait and disappearance stay real.
// full_only: false
func TestProcessEscapedStopFailureKeepsPhysicalJoin(t *testing.T) {
	root := t.TempDir()
	module := filepath.Join(root, "core")
	if err := os.Mkdir(module, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(module, "go.mod"), []byte("module enkv.sh/core\n\ngo 1.27.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	source := filepath.Clean(filepath.Join(filepath.Dir(savedWorkflowPath(t, "dev")), "../.."))
	for _, path := range supervisorFixturePaths {
		name := filepath.Base(path)
		if !strings.HasPrefix(path, "tests/shared/runner/") || !strings.HasSuffix(name, ".go") || name == "supervisor_driver.go" {
			continue
		}
		body, err := os.ReadFile(filepath.Join(source, path))
		if err != nil {
			t.Fatal(err)
		}
		if name == "process_memory.go" {
			const anchor = "func (w *processIdentityWatcher) stopEscaped() error {"
			if strings.Count(string(body), anchor) != 1 {
				t.Fatal("copied escaped stop entry changed")
			}
			body = []byte(strings.Replace(string(body), anchor, anchor+"\n if err, held := escapedFailureFixtureStop(w); held { return err }\n", 1))
		}
		if err := os.WriteFile(filepath.Join(module, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(module, "internal/testrecords"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"io.go", "layout.go", "source.go", "live_limits.go"} {
		body, err := os.ReadFile(filepath.Join(source, "tests/shared/records", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(module, "internal/testrecords", name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(module, "escape_test.go"), []byte(escapedStopFailureWitness), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(cacheOnlyGoContext(withExecutionParallel(t.Context(), 1)), time.Minute)
	defer cancel()
	output, err := runGo(ctx, root, "core", "test", "-mod=readonly", "-race", "-json", "-count=1", "-parallel=1", "-timeout=30s", "-run=^TestEscapedStopFailureWitness$", ".")
	if err != nil {
		t.Fatalf("escaped stop failure lost physical/failure facts: %v\n%s", err, output)
	}
	terminals, err := validateOrdinaryEvents(output, map[string][]string{"enkv.sh/core": {"TestEscapedStopFailureWitness"}}, nil)
	if err != nil || len(terminals) != 3 {
		t.Fatal("escaped-stop witness terminal inventory differs", terminals, err)
	}
	want := map[string]bool{"TestEscapedStopFailureWitness": true, "TestEscapedStopFailureWitness/initial_observation_failure": true, "TestEscapedStopFailureWitness/later_observation_failure": true}
	for _, terminal := range terminals {
		if !want[terminal.Name] || terminal.Outcome != "pass" {
			t.Fatal("escaped-stop witness did not execute its exact passing nodes", terminal)
		}
		delete(want, terminal.Name)
	}
	if len(want) != 0 {
		t.Fatal("escaped-stop witness nodes missing", want)
	}
}

const escapedStopFailureWitness = `package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

var escapedProbeFailure = errors.New("controlled later escaped identity observation failure")
var escapedFailureRoot int
var escapedFailureID processIdentity
var escapedFailureCalls int
var escapedFailureAt int

func escapedFailureFixtureStop(w *processIdentityWatcher) (error, bool) {
	if w.root != escapedFailureRoot || escapedFailureRoot == 0 {
		return nil, false
	}
	escapedFailureCalls++
	if escapedFailureCalls > escapedFailureAt {
		return nil, false
	}
	actual, err := nativeProcessIdentity(escapedFailureID.pid)
	if err != nil {
		return err, true
	}
	if actual.identity != escapedFailureID || actual.group == w.root {
		return errors.New("escaped fixture generation changed"), true
	}
	if escapedFailureCalls < escapedFailureAt {
		// Hold this signal only in the copy so a real retry is required. No join
		// fact is substituted; the unchanged later attempt sends actual SIGKILL.
		return nil, true
	}
	return escapedProbeFailure, true
}

func escapedFixturePID(t *testing.T, ctx context.Context, path string) int {
	t.Helper()
	for {
		body, err := os.ReadFile(path)
		if err == nil && strings.TrimSpace(string(body)) != "" {
			pid, err := strconv.Atoi(strings.TrimSpace(string(body)))
			if err != nil || pid <= 0 {
				t.Fatal("escaped fixture PID marker invalid", err)
			}
			return pid
		}
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("escaped fixture readiness missing", ctx.Err())
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// full_only: false
func TestEscapedStopFailureHelper(t *testing.T) {
	role := os.Getenv("ENKV_ESCAPED_FAILURE_ROLE")
	if role == "" {
		return
	}
	directory := os.Getenv("ENKV_ESCAPED_FAILURE_DIRECTORY")
	if role == "child" {
		if err := os.WriteFile(filepath.Join(directory, "child.pid"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			t.Fatal(err)
		}
		for {
			if _, err := os.Stat(filepath.Join(directory, "child.escape")); err == nil {
				break
			} else if !os.IsNotExist(err) {
				t.Fatal(err)
			}
			time.Sleep(5 * time.Millisecond)
		}
		if err := syscall.Setpgid(0, 0); err != nil {
			t.Fatal(err)
		}
		time.Sleep(30 * time.Second)
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestEscapedStopFailureHelper$", "-test.parallel=1")
	child.Env = environment(os.Environ(), map[string]string{"ENKV_ESCAPED_FAILURE_ROLE": "child"})
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "parent.release")); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// full_only: false
func TestEscapedStopFailureWitness(t *testing.T) {
	for _, row := range []struct {
		name   string
		failAt int
	}{{"initial_observation_failure", 1}, {"later_observation_failure", 2}} {
		t.Run(row.name, func(t *testing.T) { escapedStopFailureCase(t, row.failAt) })
	}
}

func escapedStopFailureCase(t *testing.T, failAt int) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	directory := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	parent := exec.Command(executable, "-test.run=^TestEscapedStopFailureHelper$", "-test.parallel=1")
	parent.Env = environment(os.Environ(), map[string]string{"ENKV_ESCAPED_FAILURE_ROLE": "parent", "ENKV_ESCAPED_FAILURE_DIRECTORY": directory})
	parent.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stdout, stderr bytes.Buffer
	parent.Stdout, parent.Stderr = &stdout, &stderr
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}
	wait := make(chan error, 1)
	go func() { wait <- parent.Wait() }()
	watcher := newProcessIdentityWatcher(parent.Process.Pid, false)
	waited := false
	t.Cleanup(func() {
		if !waited {
			stopErr := stopGroup(parent.Process.Pid)
			escapeErr := watcher.stopEscaped()
			if err := errors.Join(stopErr, escapeErr); err != nil {
				t.Error("parent/escaped cleanup stop failed", err)
			}
			select {
			case waitErr := <-wait:
				waited = true
				var exit *exec.ExitError
				if waitErr != nil && !errors.As(waitErr, &exit) {
					t.Error("parent cleanup Wait failed", waitErr)
				}
			case <-time.After(processGroupSettlementTimeout):
				t.Error("parent cleanup did not complete its one Wait")
			}
		}
		if !waited {
			t.Error("parent cleanup Wait remains uncertain")
		}
		if joined, err := groupStopped(parent.Process.Pid, nil); !joined || err != nil {
			t.Error("parent cleanup group remains uncertain", err)
		}
		deadline := time.Now().Add(processGroupSettlementTimeout)
		for {
			if err := watcher.stopEscaped(); err != nil {
				t.Error("escaped cleanup stop failed", err)
			}
			stopped, err := watcher.escapedStopped()
			if err != nil {
				t.Error("escaped cleanup observation failed", err)
				break
			}
			if stopped {
				break
			}
			if !time.Now().Before(deadline) {
				t.Error("escaped cleanup remains uncertain")
				break
			}
			time.Sleep(processGroupPollInterval)
		}
	})
	pid := escapedFixturePID(t, ctx, filepath.Join(directory, "child.pid"))
	info, err := nativeProcessIdentity(pid)
	if err != nil || info.identity.start == 0 || info.group != parent.Process.Pid {
		t.Fatal("native child is not yet protected by its parent group", info, err)
	}
	child := info.identity
	if err := watcher.sample(); err != nil {
		t.Fatal(err)
	}
	if _, observed := watcher.owned[child]; !observed {
		t.Fatal("actual descendant generation was never observed")
	}
	// Before this gate the parent group owns cleanup. Afterward the already
	// observed PID/start generation also owns escape cleanup on every failure.
	if err := os.WriteFile(filepath.Join(directory, "child.escape"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	for {
		actual, err := nativeProcessIdentity(child.pid)
		if err != nil || actual.identity != child {
			t.Fatal("owned child generation changed before escape", actual, err)
		}
		if actual.group == child.pid {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("owned child did not escape", ctx.Err())
		case <-time.After(processGroupPollInterval):
		}
	}
	if err := os.WriteFile(filepath.Join(directory, "parent.release"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case waitErr := <-wait:
		waited = true
		if waitErr != nil {
			t.Fatal("normal parent Wait failed", waitErr, stdout.String(), stderr.String())
		}
	case <-ctx.Done():
		t.Fatal("normal parent Wait exceeded its context", ctx.Err())
	}
	if parent.ProcessState == nil || !parent.ProcessState.Success() {
		t.Fatal("normal parent exit was not positively waited")
	}
	if joined, err := groupStopped(parent.Process.Pid, nil); !joined || err != nil {
		t.Fatal("normal parent group is not absent", err)
	}
	escapedFailureRoot, escapedFailureID = parent.Process.Pid, child
	escapedFailureCalls, escapedFailureAt = 0, failAt
	result := stopSupervisedProcess(parent.Process.Pid, nil, watcher, processResult{Status: "passed", Started: true})
	if !errors.Is(syscall.Kill(parent.Process.Pid, 0), syscall.ESRCH) || !errors.Is(syscall.Kill(-parent.Process.Pid, 0), syscall.ESRCH) {
		t.Fatal("positively waited parent remains")
	}
	if !errors.Is(syscall.Kill(child.pid, 0), syscall.ESRCH) || !errors.Is(syscall.Kill(-child.pid, 0), syscall.ESRCH) {
		t.Fatal("escaped generation remains after actual final SIGKILL")
	}
	if escapedFailureCalls < failAt+1 || !errors.Is(result.Cause, escapedProbeFailure) || !result.Joined || result.Status != "group_stop_failed" {
		t.Fatalf("later stop observation loss became success or erased physical join: calls=%d result=%+v", escapedFailureCalls, result)
	}
}
`

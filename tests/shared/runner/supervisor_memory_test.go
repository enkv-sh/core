package main

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Only native byte readings are substituted. Identity, descendant discovery,
// process groups and each command's actual Wait remain the production owners.
// full_only: false
func TestSupervisorAggregateMemoryAndStageRetention(t *testing.T) {
	runSupervisorMemoryWitness(t, "^TestMemoryWitness$/^(two_branches_share_one_guard|stage_gap_retains_escaped_identity_and_peak|stop_retains_in_flight_failure|stop_excludes_native_owner)$")
}

func runSupervisorMemoryWitness(t *testing.T, selection string) {
	t.Helper()
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
		if name == "process_memory_darwin.go" || name == "process_memory_linux.go" {
			body = supervisorMemoryByteFixture(t, name, body)
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
	if err := os.WriteFile(filepath.Join(module, "memory_test.go"), []byte(supervisorMemoryWitness), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(cacheOnlyGoContext(t.Context()), time.Minute)
	defer cancel()
	output, err := runGo(ctx, root, "core", "test", "-mod=readonly", "-json", "-race", "-count=1", "-parallel=1", "-timeout=45s", "-run="+selection, ".")
	if err != nil {
		t.Fatalf("aggregate memory witness failed: %v\n%s", err, output)
	}
	terminals, err := validateOrdinaryEvents(output, map[string][]string{"enkv.sh/core": {"TestMemoryWitness"}}, nil)
	if err != nil {
		t.Fatal("memory witness terminal inventory differs", err)
	}
	modes := []string{"below_limit", "at_limit", "above_limit", "partial_failure", "unavailable", "earlier_peak"}
	if strings.Contains(selection, "two_branches_share_one_guard") {
		modes = []string{"two_branches_share_one_guard", "stage_gap_retains_escaped_identity_and_peak", "stop_retains_in_flight_failure", "stop_excludes_native_owner"}
	}
	want := map[string]bool{"TestMemoryWitness": true}
	for _, mode := range modes {
		want["TestMemoryWitness/"+mode] = true
	}
	for _, terminal := range terminals {
		if !want[terminal.Name] || terminal.Outcome != "pass" {
			t.Fatal("unexpected memory witness terminal", terminal)
		}
		delete(want, terminal.Name)
	}
	if len(want) != 0 {
		t.Fatal("memory witness did not execute every selected node", want)
	}
}

func supervisorMemoryByteFixture(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	positions := token.NewFileSet()
	file, err := parser.ParseFile(positions, name, body, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "nativeProcessMemory" {
			continue
		}
		start := positions.Position(function.Body.Pos()).Offset
		end := positions.Position(function.Body.End()).Offset
		result := append([]byte(nil), body[:start]...)
		result = append(result, []byte("{ return witnessMemoryBytes(pid) }")...)
		return append(result, body[end:]...)
	}
	t.Fatal("native byte reader absent", name)
	return nil
}

const supervisorMemoryWitness = `package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

var witnessFailure = errors.New("controlled native byte observation failure")
var witnessBytes = struct {
	sync.Mutex
	values        map[int]uint64
	failedPID     int
	blockedPID    int
	entered       chan struct{}
	release       chan struct{}
	active        int
	maximumActive int
}{values: make(map[int]uint64)}

func witnessMemoryBytes(pid int) (processMemoryInfo, error) {
	identity, err := nativeProcessIdentity(pid)
	if err != nil {
		return processMemoryInfo{}, err
	}
	witnessBytes.Lock()
	witnessBytes.active++
	witnessBytes.maximumActive = max(witnessBytes.maximumActive, witnessBytes.active)
	amount, failed := witnessBytes.values[pid], witnessBytes.failedPID == pid
	var release <-chan struct{}
	if witnessBytes.blockedPID == pid {
		close(witnessBytes.entered)
		release = witnessBytes.release
		witnessBytes.blockedPID = 0
	}
	witnessBytes.Unlock()
	defer func() { witnessBytes.Lock(); witnessBytes.active--; witnessBytes.Unlock() }()
	if release != nil {
		<-release
	}
	if failed {
		return processMemoryInfo{}, witnessFailure
	}
	after, err := nativeProcessIdentity(pid)
	if err != nil {
		return processMemoryInfo{}, err
	}
	if after.identity != identity.identity {
		return processMemoryInfo{}, syscall.ESRCH
	}
	return processMemoryInfo{processIdentityInfo: identity, bytes: amount}, nil
}

func witnessMetric(pid int, amount uint64) {
	witnessBytes.Lock()
	witnessBytes.values[pid] = amount
	witnessBytes.Unlock()
}

func witnessPID(t *testing.T, ctx context.Context, path string) int {
	t.Helper()
	for {
		body, err := os.ReadFile(path)
		if err == nil && strings.TrimSpace(string(body)) != "" {
			pid, err := strconv.Atoi(strings.TrimSpace(string(body)))
			if err != nil || pid <= 0 {
				t.Fatal("invalid PID marker", err)
			}
			return pid
		}
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("PID marker missing", ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func witnessObserved(t *testing.T, ctx context.Context, g *invocationMemoryGuard, pid int) {
	t.Helper()
	for {
		found := false
		g.mu.Lock()
		for id := range g.watcher.owned {
			if id.pid == pid {
				found = true
			}
		}
		g.mu.Unlock()
		if found {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("native process unobserved", ctx.Err())
		case <-g.failure():
			_, err := g.result()
			t.Fatal(err)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

type witnessBranch struct {
	command *exec.Cmd
	cancel  context.CancelFunc
	done    chan processResult
	pid     int
	joined  bool
}

func witnessStartBranch(t *testing.T, ctx context.Context) *witnessBranch {
	t.Helper()
	directory := t.TempDir()
	marker := filepath.Join(directory, "pid")
	ctx, cancel := context.WithCancel(ctx)
	command := exec.Command("/bin/sh", "-c", "echo $$ > \"$1\"; read value", "memory-fixture", marker)
	input, release, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stdin = input
	b := &witnessBranch{command: command, cancel: cancel, done: make(chan processResult, 1)}
	go func() { b.done <- superviseProcess(ctx, command) }()
	t.Cleanup(func() {
		cancel()
		if !b.joined {
			witnessJoinBranch(t, b)
		}
		if err := errors.Join(input.Close(), release.Close()); err != nil {
			t.Error(err)
		}
	})
	b.pid = witnessPID(t, ctx, marker)
	return b
}

func witnessJoinBranch(t *testing.T, b *witnessBranch) {
	t.Helper()
	b.cancel()
	result := <-b.done
	b.joined = true
	if !result.Started || !result.Joined || b.command.Process == nil || b.command.ProcessState == nil {
		t.Fatal("actual branch Wait/group join missing", result)
	}
	if err := syscall.Kill(-b.command.Process.Pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatal("joined native group remains", err)
	}
}

func witnessGuard(t *testing.T) *invocationMemoryGuard {
	t.Helper()
	g, sample, err := startInvocationMemoryGuard(100)
	if err != nil || sample.bytes != 10 || sample.peak != 10 || sample.count != 1 {
		t.Fatal("initial aggregate differs", sample, err)
	}
	t.Cleanup(func() { g.stop() })
	return g
}

// full_only: false
func TestMemoryWitnessHelper(t *testing.T) {
	mode := os.Getenv("ENKV_MEMORY_WITNESS_MODE")
	if mode == "" {
		return
	}
	directory := os.Getenv("ENKV_MEMORY_WITNESS_DIRECTORY")
	if mode == "escape_child" {
		if err := os.WriteFile(filepath.Join(directory, "child.pid"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(30 * time.Second)
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestMemoryWitnessHelper$", "-test.parallel=1")
	child.Env = append(os.Environ(), "ENKV_MEMORY_WITNESS_MODE=escape_child")
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "parent.release")); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func witnessStageGap(t *testing.T, ctx context.Context, g *invocationMemoryGuard) {
	directory := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	parent := exec.Command(executable, "-test.run=^TestMemoryWitnessHelper$", "-test.parallel=1")
	parent.Env = append(os.Environ(), "ENKV_MEMORY_WITNESS_MODE=escape_parent", "ENKV_MEMORY_WITNESS_DIRECTORY="+directory)
	parent.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	child := 0
	t.Cleanup(func() {
		if !waited {
			stopErr := stopGroup(parent.Process.Pid)
			waitErr := parent.Wait()
			var exit *exec.ExitError
			if stopErr != nil || waitErr != nil && !errors.As(waitErr, &exit) {
				t.Error("first-stage fixture did not stop/wait", stopErr, waitErr)
			}
		}
		if child != 0 {
			if err := syscall.Kill(child, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
				t.Error("escaped fixture stop failed", err)
			}
		}
		if stopped, err := g.stopDescendants(); !stopped || err != nil {
			t.Error("stage fixture descendants remain", err)
		}
	})
	child = witnessPID(t, ctx, filepath.Join(directory, "child.pid"))
	witnessObserved(t, ctx, g, child)
	witnessMetric(child, 40)
	if err := g.setLimit(100); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "parent.release"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := parent.Wait(); err != nil {
		t.Fatal("actual first-stage Wait failed", err)
	}
	waited = true
	if joined, err := groupStopped(parent.Process.Pid, nil); !joined || err != nil {
		t.Fatal("first-stage group remains", err)
	}
	if err := g.setLimit(100); err != nil {
		t.Fatal(err)
	}
	sample, err := g.result()
	if err != nil || sample.bytes != 50 || sample.peak != 50 || sample.count != 2 {
		t.Fatal("phase gap lost orphan", sample, err)
	}
	witnessMetric(child, 5)
	next := witnessStartBranch(t, ctx)
	witnessObserved(t, ctx, g, next.pid)
	witnessMetric(next.pid, 5)
	if err := g.setLimit(80); err != nil {
		t.Fatal(err)
	}
	sample, err = g.result()
	if err != nil || sample.bytes != 20 || sample.peak != 50 || sample.limit != 80 {
		t.Fatal("next phase lost peak/history/limit", sample, err)
	}
	witnessJoinBranch(t, next)
	if stopped, err := g.stopDescendants(); !stopped || err != nil {
		t.Fatal("remembered escaped generation remains", err)
	}
	sample, err = g.stop()
	if err != nil || sample.bytes != 10 || sample.peak != 50 {
		t.Fatal("final stage lost observation", sample, err)
	}
	if err := g.setLimit(100); err == nil {
		t.Fatal("stopped aggregate accepted limit update")
	}
}

// full_only: false
func TestMemoryWitness(t *testing.T) {
	for _, mode := range []string{"below_limit", "at_limit", "above_limit", "partial_failure", "unavailable", "earlier_peak", "two_branches_share_one_guard", "stage_gap_retains_escaped_identity_and_peak", "stop_retains_in_flight_failure", "stop_excludes_native_owner"} {
		t.Run(mode, func(t *testing.T) {
			witnessBytes.Lock()
			witnessBytes.values = map[int]uint64{os.Getpid(): 10}
			witnessBytes.failedPID, witnessBytes.blockedPID = 0, 0
			witnessBytes.maximumActive = 0
			witnessBytes.Unlock()
			ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
			defer cancel()
			g := witnessGuard(t)
			switch mode {
			case "stage_gap_retains_escaped_identity_and_peak":
				witnessStageGap(t, ctx, g)
			case "stop_excludes_native_owner":
				before, err := nativeProcessIdentity(os.Getpid())
				if err != nil {
					t.Fatal(err)
				}
				if stopped, err := g.stopDescendants(); !stopped || err != nil {
					t.Fatal("native-only tree did not settle", err)
				}
				if _, err := g.stop(); err != nil {
					t.Fatal(err)
				}
				after, err := nativeProcessIdentity(os.Getpid())
				if err != nil || before.identity != after.identity {
					t.Fatal("aggregate stop changed native owner", err)
				}
			case "two_branches_share_one_guard":
				first, second := witnessStartBranch(t, ctx), witnessStartBranch(t, ctx)
				witnessObserved(t, ctx, g, first.pid)
				witnessObserved(t, ctx, g, second.pid)
				witnessMetric(first.pid, 40)
				witnessMetric(second.pid, 40)
				if err := g.setLimit(100); err != nil {
					t.Fatal(err)
				}
				sample, err := g.result()
				if err != nil || sample.bytes != 90 || sample.count != 3 || sample.peak != 90 {
					t.Fatal("one guard lost two branches", sample, err)
				}
				if err := g.setLimit(90); err == nil {
					t.Fatal("aggregate equality did not fail")
				}
				witnessJoinBranch(t, first)
				witnessJoinBranch(t, second)
				if stopped, err := g.stopDescendants(); !stopped || err != nil {
					t.Fatal("aggregate failure left descendants", err)
				}
				sample, err = g.stop()
				if err == nil || sample.peak != 90 || sample.limit != 90 {
					t.Fatal("terminal aggregate failure changed", sample, err)
				}
			case "stop_retains_in_flight_failure":
				branch := witnessStartBranch(t, ctx)
				witnessObserved(t, ctx, g, branch.pid)
				entered, release := make(chan struct{}), make(chan struct{})
				var releaseOnce sync.Once
				t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
				witnessBytes.Lock()
				witnessBytes.failedPID, witnessBytes.blockedPID = branch.pid, branch.pid
				witnessBytes.entered, witnessBytes.release = entered, release
				witnessBytes.Unlock()
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal("sample did not enter byte barrier", ctx.Err())
				}
				stopped := make(chan struct {
					sample processMemorySample
					err    error
				}, 1)
				go func() {
					sample, err := g.stop()
					stopped <- struct {
						sample processMemorySample
						err    error
					}{sample, err}
				}()
				select {
				case result := <-stopped:
					t.Fatal("Stop returned before in-flight sample", result)
				case <-time.After(30 * time.Millisecond):
				}
				releaseOnce.Do(func() { close(release) })
				result := <-stopped
				if !errors.Is(result.err, witnessFailure) || result.sample.bytes != 10 || result.sample.peak != 10 {
					t.Fatal("Stop lost in-flight partial failure", result)
				}
				select {
				case <-g.failure():
				default:
					t.Fatal("in-flight failure was not latched")
				}
				witnessJoinBranch(t, branch)
			default:
				branch := witnessStartBranch(t, ctx)
				witnessObserved(t, ctx, g, branch.pid)
				witnessBytes.Lock()
				witnessBytes.values[branch.pid] = 40
				if mode == "partial_failure" {
					witnessBytes.failedPID = branch.pid
				}
				if mode == "unavailable" {
					witnessBytes.values[branch.pid] = 0
					witnessBytes.failedPID = os.Getpid()
				}
				witnessBytes.Unlock()
				limit := uint64(51)
				wantBytes, wantPeak := uint64(50), uint64(50)
				wantFailure := false
				switch mode {
				case "at_limit":
					limit, wantFailure = 50, true
				case "above_limit":
					limit, wantFailure = 49, true
				case "partial_failure":
					limit = 100
					wantBytes, wantPeak, wantFailure = 10, 10, true
				case "unavailable":
					limit = 100
					wantBytes, wantPeak, wantFailure = 0, 10, true
				case "earlier_peak":
					if err := g.setLimit(100); err != nil {
						t.Fatal(err)
					}
					witnessMetric(branch.pid, 5)
					wantBytes, wantPeak = 15, 50
				}
				err := g.setLimit(limit)
				sample, terminalErr := g.result()
				if (err != nil) != wantFailure || (terminalErr != nil) != wantFailure || sample.bytes != wantBytes || sample.peak != wantPeak || sample.limit != limit {
					t.Fatal("aggregate threshold/partial result differs", sample, err, terminalErr)
				}
				if (mode == "partial_failure" || mode == "unavailable") && !errors.Is(err, witnessFailure) {
					t.Fatal("native observation cause lost", err)
				}
				witnessJoinBranch(t, branch)
				final, finalErr := g.stop()
				if (finalErr != nil) != wantFailure || final.peak != wantPeak {
					t.Fatal("terminal aggregate result differs", final, finalErr)
				}
			}
			witnessBytes.Lock()
			active, maximum := witnessBytes.active, witnessBytes.maximumActive
			witnessBytes.Unlock()
			if active != 0 || maximum != 1 {
				t.Fatal("aggregate byte census overlapped or did not join", active, maximum)
			}
		})
	}
}
`

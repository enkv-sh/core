package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	records "enkv.sh/core/internal/testrecords"
)

// These controls use the actual installed native entry, root pipes and locks.
// The small runner supplies prepared metadata. It performs no Product scenario,
// provider preflight, grant consumption or recovery mutation.
type supervisorResourceFixture struct {
	root, controls, stages, supervisor, runner string
	locks                                      *resourceLocks
	settled                                    bool
}

type supervisorResourceInvocation struct {
	fixture            *supervisorResourceFixture
	control, operation string
	done               chan processResult
	cancel             context.CancelFunc
	finished           bool
	result             processResult
	output             *setupScriptOutput
}

func newSupervisorResourceFixture(t *testing.T) *supervisorResourceFixture {
	t.Helper()
	return newConfiguredSupervisorResourceFixture(t, nil)
}

// configure changes only copied fixture sources before native setup binds them.
func newConfiguredSupervisorResourceFixture(t *testing.T, configure func(*testing.T, *supervisorResourceFixture)) *supervisorResourceFixture {
	t.Helper()
	initial, previousResources, previousControls, _ := copiedSupervisorSetupFixture(t)
	directory, err := os.MkdirTemp("", "enkv-resource-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	root, resources, controls := filepath.Join(directory, "checkout"), filepath.Join(directory, "resources"), filepath.Join(directory, "controls")
	fixture := &supervisorResourceFixture{root: root, controls: controls, settled: true}
	t.Cleanup(func() {
		if t.Failed() || !fixture.settled {
			t.Log("retained resource fixture:", directory)
			return
		}
		current, err := os.Lstat(directory)
		if err != nil || !current.IsDir() || !records.SameLocalFile(identity, current) {
			t.Error("resource fixture directory changed", err)
			return
		}
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	for _, name := range supervisorFixturePaths {
		body, err := os.ReadFile(filepath.Join(initial, name))
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, body, 0700); err != nil {
			t.Fatal(err)
		}
	}
	copyModuleInventoryFixture(t, root)
	rewriteSupervisorFixtureResources(t, root, previousResources, resources)
	if err := os.Mkdir(controls, 0700); err != nil {
		t.Fatal(err)
	}
	ps, err := os.ReadFile(filepath.Join(previousControls, "ps"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(controls, "ps"), ps, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := os.Stat(filepath.Join(controls, "ps.called")); !errors.Is(err, os.ErrNotExist) {
			t.Error("resource fixture invoked ps", err)
		}
	})
	script := filepath.Join(root, "tests/scripts/setup-supervisor")
	fixture.stages = supervisorFixtureStageParent(t, root, &fixture.settled)
	if configure != nil {
		configure(t, fixture)
	}
	ctx, cancel := context.WithTimeout(withExecutionParallel(t.Context(), supervisorFixtureParallel(t)), 3*time.Minute)
	defer cancel()
	command := exec.Command("/bin/bash", script)
	command.Dir = root
	command.Env = environment(goEnvironment(), map[string]string{"PATH": controls + string(os.PathListSeparator) + os.Getenv("PATH")})
	output := new(setupScriptOutput)
	command.Stdout, command.Stderr = output, output
	result := superviseProcess(ctx, command)
	fixture.settled = result.Joined
	if result.Status != "passed" || !result.Started || !result.Joined || output.Overflow() {
		t.Fatalf("resource fixture native setup failed: %+v %s", result, output.String())
	}
	fixture.supervisor = filepath.Join(root, "tests/.supervisor/supervisor")
	source := filepath.Join(controls, "resource-runner.go")
	if err := os.WriteFile(source, []byte(supervisorResourceRunnerSource), 0600); err != nil {
		t.Fatal(err)
	}
	fixture.runner = filepath.Join(controls, "resource-runner")
	if body, err := runGo(ctx, root, "core", "build", "-mod=readonly", "-o", fixture.runner, source); err != nil {
		fixture.settled = fixture.settled && toolCommandsJoined(err)
		t.Fatalf("resource fixture runner build: %v %s", err, body)
	}
	tools := filepath.Join(controls, "tools")
	if err := os.Mkdir(tools, 0700); err != nil {
		t.Fatal(err)
	}
	compiler := `#!/bin/bash
set -euo pipefail
output=
while [ "$#" -gt 0 ]; do
 if [ "$1" = -o ]; then shift; output=$1; fi
 shift
done
if [ -z "$output" ] || [ "${output##*/}" != bootstrap ]; then exit 91; fi
printf '%s\n' "$$" > "$ENKV_RESOURCE_FIXTURE_CONTROL/compiler"
cp "$ENKV_RESOURCE_FIXTURE_BOOTSTRAP" "$output"
chmod 700 "$output"
`
	bootstrap := `#!/bin/bash
set -euo pipefail
directory=$(mktemp -d "$TMPDIR/enkv-test-resource.XXXXXXXX")
cp "$ENKV_RESOURCE_FIXTURE_RUNNER" "$directory/runner"
chmod 700 "$directory/runner"
printf '%s\n' "$directory/runner"
`
	if err := os.WriteFile(filepath.Join(tools, "go"), []byte(compiler), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(controls, "bootstrap"), []byte(bootstrap), 0700); err != nil {
		t.Fatal(err)
	}
	fixture.locks, err = openResourceLocks(resources)
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture *supervisorResourceFixture) initializeEvidence(t *testing.T) {
	t.Helper()
	// Fixture Git must not use an operator's real index, redirects or hooks.
	for _, entry := range os.Environ() {
		name, value, ok := strings.Cut(entry, "=")
		if ok && strings.HasPrefix(name, "GIT_") {
			t.Setenv(name, value)
			if err := os.Unsetenv(name); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	initializeWorkflowExecutionFixture(t, fixture.root)
}

func (fixture *supervisorResourceFixture) checkout(t *testing.T, name string) string {
	t.Helper()
	root := filepath.Join(filepath.Dir(fixture.root), name)
	for _, name := range supervisorFixturePaths {
		body, err := os.ReadFile(filepath.Join(fixture.root, name))
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, body, 0700); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func (fixture *supervisorResourceFixture) start(t *testing.T, root, id, operation string, big, live, paused bool, mode string) *supervisorResourceInvocation {
	t.Helper()
	control := filepath.Join(fixture.controls, id)
	if err := os.Mkdir(control, 0700); err != nil {
		t.Fatal(err)
	}
	if !paused {
		if err := os.WriteFile(filepath.Join(control, "prepare"), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	workflow := filepath.Join(control, "workflow.json")
	// Native parsing reads this file; the fixture owns the prepared selection.
	if err := os.WriteFile(workflow, []byte(`{"schema_version":1,"name":"resource-fixture","profile":"full","steps":[{"id":"operation","kind":"runner-tests"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	limits := filepath.Join(control, "limits.json")
	saveSelection(t, limits, testLimits())
	const runID = "20261027T000000Z-resource-fixture"
	args := []string{"list"}
	switch operation {
	case "run":
		args = []string{"run", "--workflow", workflow, "--step", "operation"}
	case "cleanup":
		args = []string{"cleanup", runID, "--limits", limits}
	}
	args = append(args, "--parallel=1", "--memory-limit-mib=2048")
	command := exec.Command(fixture.supervisor, append([]string{"invoke", "--root", root, "--"}, args...)...)
	command.Dir = root
	command.Env = environment(goEnvironment(), map[string]string{
		"PATH":                            filepath.Join(fixture.controls, "tools") + string(os.PathListSeparator) + fixture.controls + string(os.PathListSeparator) + os.Getenv("PATH"),
		"ENKV_RESOURCE_FIXTURE_CONTROL":   control,
		"ENKV_RESOURCE_FIXTURE_BOOTSTRAP": filepath.Join(fixture.controls, "bootstrap"),
		"ENKV_RESOURCE_FIXTURE_RUNNER":    fixture.runner,
		"ENKV_RESOURCE_FIXTURE_OPERATION": operation,
		"ENKV_RESOURCE_FIXTURE_BIG":       fmt.Sprint(big),
		"ENKV_RESOURCE_FIXTURE_LIVE":      fmt.Sprint(live),
		"ENKV_RESOURCE_FIXTURE_MODE":      mode,
	})
	ctx, cancel := context.WithTimeout(withExecutionParallel(t.Context(), 1), time.Minute)
	invocation := &supervisorResourceInvocation{fixture: fixture, control: control, operation: operation, done: make(chan processResult, 1), cancel: cancel, output: new(setupScriptOutput)}
	command.Stdout, command.Stderr = invocation.output, invocation.output
	go func() { invocation.done <- superviseProcess(ctx, command) }()
	t.Cleanup(func() {
		cancel()
		if !invocation.finished {
			select {
			case result := <-invocation.done:
				invocation.finished = true
				invocation.result = result
				fixture.settled = fixture.settled && result.Joined
			case <-time.After(3 * processGroupSettlementTimeout):
				fixture.settled = false
				t.Error("resource fixture root did not join after cancellation")
			}
		}
	})
	return invocation
}

func (invocation *supervisorResourceInvocation) marker(t *testing.T, name string) string {
	t.Helper()
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	for {
		if body, err := os.ReadFile(filepath.Join(invocation.control, name)); err == nil && len(body) > 0 && body[len(body)-1] == '\n' {
			return strings.TrimSuffix(string(body), "\n")
		}
		select {
		case result := <-invocation.done:
			invocation.finished = true
			invocation.result = result
			invocation.fixture.settled = invocation.fixture.settled && result.Joined
			t.Fatalf("root returned before %s: %+v %s", name, result, invocation.output.String())
		case <-deadline.C:
			t.Fatal("resource fixture marker missing", invocation.operation, name, invocation.output.String())
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func (invocation *supervisorResourceInvocation) gate(t *testing.T, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(invocation.control, name), nil, 0600); err != nil {
		t.Fatal(err)
	}
}

func (invocation *supervisorResourceInvocation) blocked(t *testing.T, name string) {
	t.Helper()
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	for {
		if _, err := os.Stat(filepath.Join(invocation.control, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("blocked root crossed its gate", invocation.operation, name, err)
		}
		select {
		case result := <-invocation.done:
			invocation.finished = true
			invocation.result = result
			invocation.fixture.settled = invocation.fixture.settled && result.Joined
			t.Fatalf("blocked root returned: %+v %s", result, invocation.output.String())
		case <-timer.C:
			return
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func (invocation *supervisorResourceInvocation) wait(t *testing.T, passed bool, timeout time.Duration) processResult {
	t.Helper()
	if !invocation.finished {
		select {
		case result := <-invocation.done:
			invocation.finished = true
			invocation.result = result
		case <-time.After(timeout):
			t.Fatal("resource root did not finish", invocation.operation, invocation.output.String())
		}
	}
	invocation.cancel()
	result := invocation.result
	invocation.fixture.settled = invocation.fixture.settled && result.Joined
	if !result.Started || !result.Joined || invocation.output.Overflow() || passed && result.Status != "passed" || !passed && result.Status == "passed" {
		t.Fatalf("resource root outcome differs: %+v %s", result, invocation.output.String())
	}
	return result
}

func requireResourceLockWait(t *testing.T, acquire func(context.Context) (*resourceLease, error)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	lease, err := acquire(ctx)
	if lease != nil {
		if err := lease.Close(); err != nil {
			t.Error(err)
		}
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("native admitted root did not hold its resource lock", err)
	}
}

// full_only: false
func TestSupervisorResourcePhasesReleaseLocksAndTools(t *testing.T) {
	fixture := newSupervisorResourceFixture(t)
	for _, cancelWaiting := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel_wait_%t", cancelWaiting), func(t *testing.T) {
			root := fixture.checkout(t, fmt.Sprintf("phases-%t", cancelWaiting))
			invocation := fixture.start(t, root, fmt.Sprintf("phases-%t", cancelWaiting), "hermetic", false, false, false, "phases")
			stage := invocation.marker(t, "stage")
			stageInfo, err := os.Lstat(stage)
			if err != nil {
				t.Fatal(err)
			}
			invocation.marker(t, "phase-0-entered")
			shared, err := fixture.locks.acquireMachine(t.Context(), false)
			if err != nil {
				t.Fatal("normal phase did not share machine resources", err)
			}
			t.Cleanup(func() {
				if err := shared.Close(); err != nil {
					t.Error(err)
				}
			})
			available := func(acquire func(context.Context) (*resourceLease, error)) {
				t.Helper()
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				lease, err := acquire(ctx)
				if err != nil {
					t.Fatal("settled phase retained a resource lease", err)
				}
				if err := lease.Close(); err != nil {
					t.Fatal(err)
				}
			}
			available(fixture.locks.acquireLive)
			invocation.gate(t, "phase-0-release")
			invocation.marker(t, "phase-1-ready")
			invocation.blocked(t, "phase-1-entered")
			toolName := fmt.Sprintf("tool-%x.lock", sha256.Sum256([]byte(root)))
			available(func(ctx context.Context) (*resourceLease, error) {
				return fixture.locks.acquire(ctx, toolName, syscall.LOCK_EX)
			})
			compiler, err := strconv.Atoi(invocation.marker(t, "compiler"))
			if err != nil || !errors.Is(syscall.Kill(compiler, 0), syscall.ESRCH) {
				t.Fatal("compiler remained active during resource wait", compiler, err)
			}
			if cancelWaiting {
				runner, err := strconv.Atoi(invocation.marker(t, "runner-pid"))
				if err != nil {
					t.Fatal(err)
				}
				invocation.cancel()
				invocation.wait(t, false, 10*time.Second)
				if !errors.Is(syscall.Kill(runner, 0), syscall.ESRCH) {
					t.Fatal("cancelled resource waiter retained its runner", runner)
				}
				if err := shared.Close(); err != nil {
					t.Fatal(err)
				}
				available(func(ctx context.Context) (*resourceLease, error) { return fixture.locks.acquireMachine(ctx, true) })
				available(fixture.locks.acquireLive)
				available(func(ctx context.Context) (*resourceLease, error) {
					return fixture.locks.acquire(ctx, toolName, syscall.LOCK_EX)
				})
				// The fixture has joined the complete native process group. The
				// missing terminal keeps its exact scratch for this owner to remove.
				if _, err := os.Lstat(stage); err == nil {
					if err := removeSupervisorInvocationStage(t.Context(), stage, stageInfo, true); err != nil {
						t.Fatal(err)
					}
				} else if !errors.Is(err, os.ErrNotExist) {
					t.Fatal(err)
				}
				return
			}
			if err := shared.Close(); err != nil {
				t.Fatal(err)
			}
			invocation.marker(t, "phase-1-entered")
			requireResourceLockWait(t, func(ctx context.Context) (*resourceLease, error) { return fixture.locks.acquireMachine(ctx, false) })
			requireResourceLockWait(t, fixture.locks.acquireLive)
			invocation.gate(t, "phase-1-release")
			invocation.marker(t, "phase-2-entered")
			available(func(ctx context.Context) (*resourceLease, error) { return fixture.locks.acquireMachine(ctx, false) })
			available(fixture.locks.acquireLive)
			invocation.gate(t, "phase-2-release")
			invocation.wait(t, true, 5*time.Second)
		})
	}
}

// full_only: false
func TestSupervisorResourceAdmissionSharesNormalAndExcludesBig(t *testing.T) {
	fixture := newSupervisorResourceFixture(t)
	second := fixture.checkout(t, "second-checkout")
	third := fixture.checkout(t, "third-checkout")
	first := fixture.start(t, fixture.root, "normal-one", "hermetic", false, false, false, "")
	if got := first.marker(t, "entered"); got != "hermetic" {
		t.Fatal(got)
	}
	other := fixture.start(t, second, "normal-two", "hermetic", false, false, false, "")
	other.marker(t, "entered")
	first.blocked(t, "finished")
	shared, err := fixture.locks.acquireMachine(t.Context(), false)
	if err != nil {
		t.Fatal("normal roots prevented another shared owner", err)
	}
	if err := shared.Close(); err != nil {
		t.Fatal(err)
	}
	requireResourceLockWait(t, func(ctx context.Context) (*resourceLease, error) { return fixture.locks.acquireMachine(ctx, true) })
	big := fixture.start(t, third, "big", "big", true, false, false, "")
	big.marker(t, "ready")
	big.blocked(t, "entered")
	first.gate(t, "release")
	other.gate(t, "release")
	first.wait(t, true, 5*time.Second)
	other.wait(t, true, 5*time.Second)
	big.marker(t, "entered")
	requireResourceLockWait(t, func(ctx context.Context) (*resourceLease, error) { return fixture.locks.acquireMachine(ctx, false) })
	later := fixture.start(t, fixture.root, "normal-after-big", "hermetic", false, false, false, "")
	later.blocked(t, "compiler")
	big.gate(t, "release")
	big.wait(t, true, 5*time.Second)
	later.marker(t, "entered")
	later.gate(t, "release")
	later.wait(t, true, 5*time.Second)
}

// The operation syntax crosses native parsing. Fixture readiness supplies the
// live fact; these assertions do not establish actual recovery eligibility.
// full_only: false
func TestSupervisorResourceAdmissionKeepsLiveOperationsExclusive(t *testing.T) {
	fixture := newSupervisorResourceFixture(t)
	hermeticRoot := fixture.checkout(t, "hermetic-checkout")
	cleanupRoot := fixture.checkout(t, "cleanup-checkout")
	live := fixture.start(t, fixture.root, "live-run", "run", false, true, false, "")
	if got := live.marker(t, "entered"); got != "run" {
		t.Fatal(got)
	}
	hermetic := fixture.start(t, hermeticRoot, "hermetic", "hermetic", false, false, false, "")
	hermetic.marker(t, "entered")
	requireResourceLockWait(t, fixture.locks.acquireLive)
	cleanup := fixture.start(t, cleanupRoot, "live-cleanup", "cleanup", false, true, false, "")
	cleanup.marker(t, "ready")
	cleanup.blocked(t, "entered")
	live.gate(t, "release")
	live.wait(t, true, 5*time.Second)
	pending := []*supervisorResourceInvocation{cleanup}
	for len(pending) > 0 {
		deadline := time.NewTimer(5 * time.Second)
		admitted := -1
		for admitted < 0 {
			for index, invocation := range pending {
				if _, err := os.Stat(filepath.Join(invocation.control, "entered")); err == nil {
					if admitted >= 0 {
						t.Fatal("two live roots entered together")
					}
					admitted = index
				} else if !errors.Is(err, os.ErrNotExist) {
					t.Fatal(err)
				}
			}
			if admitted >= 0 {
				break
			}
			select {
			case <-deadline.C:
				t.Fatal("waiting live root did not enter")
			case <-time.After(5 * time.Millisecond):
			}
		}
		deadline.Stop()
		current := pending[admitted]
		if got := current.marker(t, "entered"); got != current.operation {
			t.Fatal("operation identity differs", got, current.operation)
		}
		requireResourceLockWait(t, fixture.locks.acquireLive)
		for index, invocation := range pending {
			if index != admitted {
				invocation.blocked(t, "entered")
			}
		}
		hermetic.blocked(t, "finished")
		current.gate(t, "release")
		current.wait(t, true, 5*time.Second)
		pending = append(pending[:admitted], pending[admitted+1:]...)
	}
	hermetic.gate(t, "release")
	hermetic.wait(t, true, 5*time.Second)
}

// full_only: false
func TestSupervisorRunnerExitCancelsPreparationToolCleanupWait(t *testing.T) {
	fixture := newSupervisorResourceFixture(t)
	root := fixture.root
	if _, err := os.Stat(filepath.Join(root, "core/internal/testmain")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("preparation directories already existed", err)
	}
	invocation := fixture.start(t, root, "exit-during-preparation", "hermetic", false, false, true, "exit_after_ready")
	stage := invocation.marker(t, "stage")
	invocation.marker(t, "started")
	if filepath.Dir(stage) != fixture.stages {
		t.Fatal("fixture stage escaped its parent", stage)
	}
	safeStage, err := records.SafePath(fixture.stages, filepath.Base(stage))
	if err != nil || safeStage != stage {
		t.Fatal("fixture stage path changed", err)
	}
	stageInfo, err := os.Lstat(stage)
	if err != nil || !stageInfo.IsDir() {
		t.Fatal(err)
	}
	// Native created these paths; this external borrower prevents EX cleanup.
	borrower, err := prepareToolDirectories(t.Context(), fixture.locks, root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := borrower.ReleaseAfterSettlement(context.Background()); err != nil {
			t.Error(err)
		}
	})
	invocation.gate(t, "prepare")
	invocation.marker(t, "ready")
	invocation.blocked(t, "entered")
	invocation.gate(t, "exit")
	invocation.wait(t, false, 5*time.Second)
	if err := borrower.Release(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	// Missing terminal proof retains native scratch. This fixture has separately
	// joined the complete native branch and may remove only its exact current stage.
	safeStage, err = records.SafePath(fixture.stages, filepath.Base(stage))
	if err != nil || safeStage != stage {
		t.Fatal("retained fixture stage path changed", err)
	}
	current, err := os.Lstat(stage)
	if err != nil || !current.IsDir() || !records.SameLocalFile(stageInfo, current) {
		t.Fatal("failed root did not retain its exact stage", err)
	}
	if err := os.RemoveAll(stage); err != nil {
		t.Fatal(err)
	}
}

// full_only: false

const supervisorResourceRunnerSource = `package main
import (
 "bytes"
 "go/format"
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "os/signal"
 "path/filepath"
 "syscall"
 "time"
)
type capacity struct { Parallel int ` + "`json:\"parallel\"`" + `; Memory int ` + "`json:\"memory_limit_mib\"`" + ` }
type policy struct { Requested capacity ` + "`json:\"requested\"`" + `; Resolved capacity ` + "`json:\"resolved\"`" + ` }
func main(){
 if len(os.Args)==2 && os.Args[1]=="--unjoined-child" {
  syscall.Close(3);syscall.Close(4)
  if err:=syscall.Setpgid(0,0);err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
  control:=os.Getenv("ENKV_RESOURCE_FIXTURE_CONTROL")
  if err:=os.WriteFile(filepath.Join(control,"unjoined-child"),[]byte(fmt.Sprintf("%d\n",os.Getpid())),0600);err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
  for {time.Sleep(time.Second)}
 }
 if err:=run();err!=nil { fmt.Fprintln(os.Stderr,err);os.Exit(1) }
}
func run()(retErr error){
 syscall.CloseOnExec(3);syscall.CloseOnExec(4)
 read,write:=os.NewFile(3,"root-read"),os.NewFile(4,"root-write")
 defer func(){retErr=errors.Join(retErr,read.Close(),write.Close())}()
 for _,file:=range []*os.File{read,write} { info,err:=file.Stat();if err!=nil || info.Mode()&os.ModeNamedPipe==0 { return errors.New("root pipes unavailable") } }
 ctx,stop:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM);defer stop()
 control:=os.Getenv("ENKV_RESOURCE_FIXTURE_CONTROL")
 marker:=func(name,value string)error{return os.WriteFile(filepath.Join(control,name),[]byte(value+"\n"),0600)}
 wait:=func(name string)error{for {if _,err:=os.Stat(filepath.Join(control,name));err==nil{return nil}else if !os.IsNotExist(err){return err};select{case <-ctx.Done():return ctx.Err();case <-time.After(5*time.Millisecond):}}}
 stage:=""
 for index,arg:=range os.Args[1:] {if index+2<len(os.Args){if arg=="--invocation-stage"{stage=os.Args[index+2]}}}
 if stage=="" {return errors.New("stage unavailable")}
 if err:=marker("stage",stage);err!=nil{return err}
 if err:=marker("started","started");err!=nil{return err}
 if err:=marker("runner-pid",fmt.Sprint(os.Getpid()));err!=nil{return err}
 if err:=wait("prepare");err!=nil{return err}
 expected:=policy{capacity{1,2048},capacity{1,2048}}
 encoder:=json.NewEncoder(write)
 decoder:=json.NewDecoder(read)
 knownMode:=os.Getenv("ENKV_RESOURCE_FIXTURE_MODE")
 phases:=1;if knownMode=="phases"{phases=3}
 for phase:=0;phase<phases;phase++ {
  big:=os.Getenv("ENKV_RESOURCE_FIXTURE_BIG")=="true"
  live:=os.Getenv("ENKV_RESOURCE_FIXTURE_LIVE")=="true"
  prefix:=""
  if phases>1 {big=phase==1;live=phase==1;prefix=fmt.Sprintf("phase-%d-",phase)}
  cleanup:=0;if live{cleanup=1}
  admission:=struct{Big bool ` + "`json:\"big\"`" + `;Live bool ` + "`json:\"live\"`" + `;Execution policy ` + "`json:\"execution\"`" + `;Cleanup int ` + "`json:\"cleanup_seconds\"`" + `}{big,live,expected,cleanup}
  ready:=struct{Operation string ` + "`json:\"operation\"`" + `;Admission any ` + "`json:\"admission\"`" + `}{"phase",admission}
  if err:=encoder.Encode(ready);err!=nil{return err}
  if err:=marker(prefix+"ready","ready");err!=nil{return err}
  if knownMode=="exit_after_ready" {return wait("exit")}
  var reply struct{Operation string ` + "`json:\"operation\"`" + `;Execution policy ` + "`json:\"execution\"`" + `}
  if err:=decoder.Decode(&reply);err!=nil{return err}
  if reply.Operation!="admitted" || reply.Execution!=expected{return errors.New("admission reply differs")}
  if err:=marker(prefix+"entered",os.Getenv("ENKV_RESOURCE_FIXTURE_OPERATION"));err!=nil{return err}
  if err:=wait(prefix+"release");err!=nil{return err}
 }
 success:=true
 if knownMode=="known_failed" || knownMode=="known_passed" {
  source:=[]byte("package fixture\n\nvar Value = 1\n")
  if knownMode=="known_failed"{source=[]byte("package fixture\nvar Value=1\n")}
  formatted,err:=format.Source(source);if err!=nil{return err}
  success=bytes.Equal(source,formatted)
  if success!=(knownMode=="known_passed"){return errors.New("fixture format condition differs")}

 }
 if os.Getenv("ENKV_LATE_GUARD_CASE")=="prior_join_unknown" {
  if err:=marker("identity-unavailable","unavailable");err!=nil{return err}
 }
 terminal:=struct{Operation string ` + "`json:\"operation\"`" + `;Success bool ` + "`json:\"success\"`" + `;Joined bool ` + "`json:\"joined\"`" + `}{"terminal",success,true}
 if err:=encoder.Encode(terminal);err!=nil{return err}
 if err:=marker("finished","finished");err!=nil{return err}
 if !success{return errors.New("fixture source is not formatted")}
 return nil
}
`

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	catalog "enkv.sh/core/internal/testcatalog"
)

// full_only: false
func TestCommandWorkflowClosesAcquiredPreparationAfterFailure(t *testing.T) {
	t.Run("retains-acquired-facts", testWorkflowAcquiredPreparationResults)
	t.Run("verification-ownership-boundaries", testVerificationOwnershipBoundaries)
	t.Run("retains-real-compiler-before-command-failure", testAssemblyCompilerFailureRetainsFacts)
	for _, row := range []struct {
		name, kind string
		cancel     bool
	}{
		{"component-failure", "component-tests", false},
		{"component-canceled", "component-tests", true},
		{"provider-failure", "assembly-checks", false},
		{"provider-canceled", "assembly-checks", true},
	} {
		t.Run(row.name, func(t *testing.T) {
			initialRoot, _, _ := overlayFixture(t)
			modfile := "tests/live/providers/aws/live.mod"
			if row.kind == "component-tests" {
				modfile = "tests/hermetic/hermetic.mod"
			}
			writeLocalGoFixture(t, initialRoot, modfile, "module "+componentPackage+"\n\ngo 1.27.0\n")
			fixture, err := newCurrentDirectory("enkv-preparation-cleanup-fixture-")
			if err != nil {
				t.Fatal(err)
			}
			settled := true
			t.Cleanup(func() {
				if t.Failed() || !settled {
					t.Log("retained preparation fixture:", fixture.path)
					return
				}
				if err := fixture.remove(true); err != nil {
					t.Error("remove positively settled preparation fixture", err)
				}
			})
			// Only the small initial fixture is copied. No command consumes its
			// automatically removed parent; every command input uses this owner.
			if err := os.CopyFS(fixture.path, os.DirFS(filepath.Dir(initialRoot))); err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(fixture.path, filepath.Base(initialRoot))
			bootstrap := filepath.Join(root, "bootstrap.json")
			initializeWorkflowExecutionFixture(t, root)
			control := filepath.Join(fixture.path, "control")
			if err := os.Mkdir(control, 0700); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(control, "body")
			t.Setenv("ENKV_PREPARATION_BODY", marker)
			writeLocalGoFixture(t, root, "tests/shared/fixture_test.go", `package core
import("os";"testing")
// full_only: false
func TestParent(t *testing.T) { if err:=os.WriteFile(os.Getenv("ENKV_PREPARATION_BODY"),[]byte("entered"),0600);err!=nil{t.Fatal(err)} }
`)
			// A pre-existing tool owner and its source must survive this invocation.
			source := filepath.Join(root, "core/internal/testcatalog/source.go")
			writeLocalGoFixture(t, root, "core/internal/testcatalog/source.go", "package catalog\n")
			sourceInfo, err := os.Lstat(source)
			if err != nil {
				t.Fatal(err)
			}
			sourceDirectory, err := os.Lstat(filepath.Dir(source))
			if err != nil {
				t.Fatal(err)
			}
			locks, err := openResourceLocks(filepath.Join(fixture.path, "resources"))
			if err != nil {
				t.Fatal(err)
			}
			ctx, stop := context.WithTimeout(withResourceLocks(withExecutionParallel(t.Context(), 1), locks), time.Minute)
			defer stop()
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			lease, err := prepareToolDirectories(ctx, locks, root)
			if err != nil {
				t.Fatal(err)
			}
			lockPath := lease.lock.Name()
			lockInfo, statErr := lease.lock.Stat()
			if err := errors.Join(statErr, lease.Release(ctx, true)); err != nil {
				t.Fatal(err)
			}
			if filepath.Dir(lockPath) != locks.directory {
				t.Fatal("tool lock escaped the fixture resource directory", lockPath)
			}
			temporary := filepath.Join(control, "temporary")
			alias := filepath.Join(control, "temporary-alias")
			if err := os.Mkdir(temporary, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(temporary, alias); err != nil {
				t.Fatal(err)
			}
			temporary, err = filepath.EvalSymlinks(temporary)
			if err != nil {
				t.Fatal(err)
			}
			realGo, err := exec.LookPath("go")
			if err != nil {
				t.Fatal(err)
			}
			realGo, err = filepath.EvalSymlinks(realGo)
			if err != nil {
				t.Fatal(err)
			}
			// Metadata comes from Go. The first acquired-overlay command is held
			// before its real list operation; no compiler result is fabricated.
			script := "#!/bin/sh\nprintf '%s\\n' \"$1\" >> " + shellQuote(filepath.Join(control, "operations")) + " || exit 91\nfor argument do\n case \"$argument\" in\n -overlay=*)\n  printf '%s' \"${argument#-overlay=}\" > " + shellQuote(filepath.Join(control, "overlay")) + "\n  printf '%s' \"$$\" > " + shellQuote(filepath.Join(control, "ready")) + "\n  while [ ! -f " + shellQuote(filepath.Join(control, "release")) + " ]; do sleep 0.01; done\n  printf 'controlled acquired preparation failure\\n' >&2\n  exit 9\n ;;\n esac\ndone\nexec " + shellQuote(realGo) + " \"$@\"\n"
			if err := os.WriteFile(filepath.Join(control, "go"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", control+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("TMPDIR", alias)
			admissions := 0
			ctx = context.WithValue(ctx, rootAdmitterContextKey{}, rootAdmitter(func(ctx context.Context, _ rootAdmission) (context.Context, error) {
				admissions++
				return ctx, errors.New("controlled execution admission refusal")
			}))
			step := resolvedWorkflowStep{ID: "selected", Kind: row.kind, Selected: true, Profile: "full"}
			if row.kind == "component-tests" {
				step.Focus = &componentFocus{Tests: singleTestRequest("TestParent")}
			} else {
				step.Responsibility = "aws"
				step.AssemblyFocus = &assemblyFocus{Requested: "TestParent", Provider: "aws"}
			}
			plan := workflowPlan{SchemaVersion: 1, Name: "preparation-failure", Profile: "full", Execution: executionPolicy{Resolved: executionCapacity{Parallel: 1, MemoryLimitMiB: 8192}}, Steps: []resolvedWorkflowStep{step}}
			type preparationResult struct {
				owner *preparedWorkflow
				err   error
			}
			done := make(chan preparationResult, 1)
			var output bytes.Buffer
			settled = false
			go func() {
				owner, err := prepareWorkflow(ctx, root, bootstrap, plan, &output)
				done <- preparationResult{owner, err}
			}()
			var preparation preparationResult
			collected := false
			pid := 0
			defer func() {
				cancel()
				if !collected {
					select {
					case preparation = <-done:
					case <-time.After(3 * processGroupSettlementTimeout):
						t.Error("preparation did not join after cancellation")
						return
					}
				}
				var failure *toolFailure
				if pid <= 0 || !errors.As(preparation.err, &failure) || !failure.process.Started || !failure.process.Joined || !toolCommandsJoined(preparation.err) || !sourceCommandsJoined(preparation.err) {
					t.Error("preparation fixture settlement is incomplete; inputs retained", fixture.path, preparation.err)
					return
				}
				if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
					t.Error("preparation fixture PID remains; inputs retained", fixture.path, err)
					return
				}
				if stopped, err := groupStopped(pid, nil); !stopped || err != nil {
					t.Error("preparation fixture group remains; inputs retained", fixture.path, err)
					return
				}
				settled = true
				if preparation.owner != nil && !preparation.owner.closed {
					finish, release := finalizationContext(ctx)
					defer release()
					if err := preparation.owner.close(finish); err != nil {
						t.Error(err)
					}
				}
			}()
			pid = waitProcessMarker(t, ctx, filepath.Join(control, "ready"))
			body, err := os.ReadFile(filepath.Join(control, "overlay"))
			if err != nil {
				t.Fatal(err)
			}
			overlay := string(body)
			scratch := filepath.Dir(overlay)
			for filepath.Dir(scratch) != scratch && !strings.HasPrefix(filepath.Base(scratch), "enkv-invocation-artifacts-") {
				scratch = filepath.Dir(scratch)
			}
			overlayInfo, err := os.Lstat(overlay)
			if err != nil || !overlayInfo.Mode().IsRegular() {
				t.Fatal("running command has no acquired overlay", err)
			}
			scratchInfo, err := os.Lstat(scratch)
			if err != nil || filepath.Dir(scratch) != temporary || !strings.HasPrefix(filepath.Base(scratch), "enkv-invocation-artifacts-") {
				t.Fatal("running command does not use canonical owned scratch", scratch, err)
			}
			if err := syscall.Kill(pid, 0); err != nil {
				t.Fatal("controlled command is not in flight", err)
			}
			if row.cancel {
				cancel()
			} else if err := os.WriteFile(filepath.Join(control, "release"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			select {
			case preparation = <-done:
				collected = true
			case <-time.After(3 * processGroupSettlementTimeout):
				t.Fatal("controlled preparation did not return after stop")
			}
			var failure *toolFailure
			if preparation.owner == nil || preparation.err == nil || !errors.As(preparation.err, &failure) || failure.operation != "go list" || !failure.process.Started || !failure.process.Joined || !toolCommandsJoined(preparation.err) || !sourceCommandsJoined(preparation.err) {
				t.Fatal("preparation lost its partial owner or actual positive command join", preparation.err)
			}
			if row.cancel {
				if !errors.Is(preparation.err, context.Canceled) || failure.process.Status != "interrupted" {
					t.Fatal("in-flight cancellation cause was lost", preparation.err)
				}
			} else {
				var exit *exec.ExitError
				if !errors.As(preparation.err, &exit) || exit.ExitCode() != 9 || string(failure.stderr) != "controlled acquired preparation failure\n" {
					t.Fatal("controlled failure cause or diagnostic was lost", preparation.err)
				}
			}
			if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
				t.Fatal("command PID remains after positive join", err)
			}
			if stopped, err := groupStopped(pid, nil); !stopped || err != nil {
				t.Fatal("command group remains after positive join", err)
			}
			owner := preparation.owner
			if owner.artifactOwner == nil || owner.artifactOwner.current == nil || owner.artifactOwner.current.path != scratch || !os.SameFile(scratchInfo, owner.artifactOwner.current.identity) || !owner.joined || owner.phase == nil || owner.phase.released {
				t.Fatal("partial owner lost its acquired cleanup responsibility")
			}
			for _, path := range []string{scratch, overlay} {
				info, err := os.Lstat(path)
				want := scratchInfo
				if path == overlay {
					want = overlayInfo
				}
				if err != nil || !os.SameFile(want, info) {
					t.Fatal("acquired input changed before command-owner close", path, err)
				}
			}
			if len(owner.providers) != 0 || owner.plan.Steps[0].Preparation != nil || owner.plan.Steps[0].AssemblyPreparation != nil {
				t.Fatal("failed preparation published a selected assembly")
			}
			for _, group := range owner.components {
				if group.assembled.Binary != "" || group.assembled.componentSelection != nil {
					t.Fatal("failed preparation published an executable component")
				}
			}
			created := append([]toolDirectoryPath(nil), owner.phase.lease.created...)
			wantCreated := map[string]bool{
				filepath.Join(root, "core/internal/testmain"):    true,
				filepath.Join(root, "core/internal/testrecords"): true,
			}
			if len(created) != len(wantCreated) {
				t.Fatal("generated tool-directory acquisition set differs", created)
			}
			for _, item := range created {
				info, err := os.Lstat(item.path)
				if !wantCreated[item.path] || err != nil || !os.SameFile(item.info, info) {
					t.Fatal("generated tool directory changed before close", item.path, err)
				}
			}
			acquired := owner.preparations[workflowPreparationKey(step)]
			if acquired == nil {
				t.Fatal("failed construction lost its acquired diagnostics")
			}
			frozen, err := json.Marshal(acquired)
			if err != nil {
				t.Fatal(err)
			}
			result, commandErr := executeCommandWorkflow(ctx, root, bootstrap, owner, preparation.err, &output)
			var returnedFailure *toolFailure
			wantAdmissions := 1
			if row.cancel {
				wantAdmissions = 0
			}
			if !errors.Is(commandErr, preparation.err) || !errors.As(commandErr, &returnedFailure) || returnedFailure != failure || !toolCommandsJoined(commandErr) || admissions != wantAdmissions {
				t.Fatal("failed preparation crossed admission/output or lost its cause", commandErr, admissions, output.String())
			}
			if result.Name != plan.Name || result.Profile != plan.Profile || result.Race == nil || *result.Race != plan.Race || result.Execution.Resolved != plan.Execution.Resolved || len(result.Steps) != 1 || result.Steps[0].ID != step.ID || result.Steps[0].Outcome != "not_run" || result.Steps[0].StartedAt != nil {
				t.Fatal("failed preparation lost its outer selection or accepted settings", result)
			}

			if failure.facts == nil {
				t.Fatal("real failed preparation command has no acquired facts")
			}

			if !row.cancel && !containedCheckFailure(ctx, preparation.err) {
				t.Fatal("settled child exit did not remain a contained preparation failure", preparation.err)
			}
			observed, err := os.ReadFile(filepath.Join(control, "operations"))
			operations := strings.Split(strings.TrimSpace(string(observed)), "\n")
			environments, listings := 0, 0
			for _, operation := range operations {
				switch operation {
				case "env":
					environments++
				case "list":
					listings++
				case "mod":
				default:
					t.Fatal("failed construction started unrelated work", operation)
				}
			}
			if err != nil || environments != 1 || listings != 1 {
				t.Fatal("failed construction repeated discovery or configuration capture", string(observed), err)
			}
			if module := failure.facts.ModulePreparation; module != nil && (!module.passed() || module.WallSeconds == nil) {
				t.Fatal("failed command lost its completed module preparation facts", module)
			}
			after, err := json.Marshal(acquired)
			if err != nil || !bytes.Equal(frozen, after) {
				t.Fatal("command completion changed acquired diagnostics", err)
			}
			wantPassed := 0
			for _, fact := range acquired.Commands {
				if fact.Phase == "preparation" && fact.Scope == "core" && fact.Process == "passed" && fact.Started && fact.Joined {
					wantPassed++
				}
			}
			passedLine := "Check phase=preparation scope=core process=passed started=true joined=true "
			if strings.Count(output.String(), passedLine) != wantPassed {
				t.Fatal("terminal omitted or repeated successful direct metadata commands", output.String())
			}
			line := fmt.Sprintf("Check phase=preparation scope=%s process=%s started=%t joined=%t ", failure.facts.Scope, failure.process.Status, failure.process.Started, failure.process.Joined)
			if strings.Count(output.String(), line) != 1 {
				t.Fatal("failed preparation terminal omitted or repeated actual command facts", line, output.String())
			}
			if !owner.closed || !owner.phase.released || !owner.phase.joined {
				t.Fatal("command did not close its joined preparation")
			}
			for _, path := range []string{scratch, owner.current.path, filepath.Join(root, "core/internal/testmain"), filepath.Join(root, "core/internal/testrecords")} {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal("command retained exact acquired scratch after positive joins", path, err)
				}
			}
			for path, want := range map[string]os.FileInfo{source: sourceInfo, filepath.Dir(source): sourceDirectory, lockPath: lockInfo} {
				info, err := os.Lstat(path)
				if err != nil || !os.SameFile(want, info) {
					t.Fatal("cleanup replaced or removed a pre-existing source or lock", path, err)
				}
			}
			if body, err := os.ReadFile(source); err != nil || string(body) != "package catalog\n" {
				t.Fatal("cleanup changed pre-existing source bytes", err)
			}
			if body, err := os.ReadFile(lockPath); err != nil || len(body) != 0 {
				t.Fatal("joined cleanup changed the stable lock marker", err)
			}
			for _, path := range []string{marker, filepath.Join(root, "tests/workflows/runs"), filepath.Join(root, "tests/hermetic/runs"), filepath.Join(root, "tests/live/runs")} {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal("failed preparation entered a body or made durable state", path, err)
				}
			}
		})
	}
}

// These identical-valued independent facts test ownership and projection only.
// The real prefix regressions above establish physical command acquisition.
func testVerificationOwnershipBoundaries(t *testing.T) {
	t.Run("actual-successful-suite-binding-owner", testActualSuccessfulSuiteBindingOwner)
	t.Run("suite-wrapper-refusal-keeps-actual-record", testSuiteWrapperRefusalKeepsActualRecord)
	t.Run("fresh-snapshot-resets-activity-state", testFreshSnapshotResetsActivityState)
	t.Run("parallel-recovery-isolated-fold", testParallelRecoveryIsolatedFold)
	t.Run("non-core-reconstruction-input-owner", testNonCoreReconstructionInputOwner)
	t.Run("actual-callback-failed-body-passed-preparation", testActualCallbackFailedBodyPreparation)
	t.Run("unjoined-complement-retains-inputs", testUnjoinedComplementRetainsInputs)
	t.Run("partial-writer-keeps-actual-and-later-facts", testPartialWriterKeepsActual)
	t.Run("ordinary-actual-wrapper-fresh-binding", testOrdinaryActualWrapperFreshBinding)
	fact := checkCommandFacts{Phase: "preparation", Scope: "core", Process: "passed", Started: true, Joined: true, Events: "not_run", ToolCleanup: "not_required", RaceObservation: "not_observed"}
	fresh := func() *checkDiagnostics {
		return &checkDiagnostics{Preparation: "passed", Commands: []checkCommandFacts{fact}}
	}
	t.Run("workflow-return", func(t *testing.T) {
		_, run := completeRunFixture(t, "memory")
		actual := run.Correctness.ComponentRun
		actual.Checks.Diagnostics = fresh()
		prefix := fresh()
		before, err := json.Marshal(actual)
		if err != nil {
			t.Fatal(err)
		}

		step := resolvedWorkflowStep{ID: "selected", Kind: "component-tests", Selected: true, Profile: "full"}
		prepared := &preparedWorkflow{plan: workflowPlan{Name: "owner-boundary", Profile: "full", Race: true, Steps: []resolvedWorkflowStep{step}}}
		result := workflowResult{Name: prepared.plan.Name, Profile: "full", Race: raceSetting(true), FinishedAt: actual.FinishedAt, Outcome: "passed", Steps: []workflowStepResult{{resolvedWorkflowStep: step, Outcome: "passed", FinishedAt: actual.FinishedAt}}, executions: map[string]workflowStepExecution{"selected": {Component: actual, Preparation: prefix}}}
		var terminal bytes.Buffer
		for range 2 {
			if err := prepared.retainWorkflowPreparation(&result, nil, &terminal); err != nil {
				t.Fatal(err)
			}
		}
		after, err := json.Marshal(actual)
		if err != nil || !bytes.Equal(before, after) || result.executions["selected"].Component != actual || result.Outcome != "passed" {
			t.Fatal("prefix retention replaced the actual component", err)
		}

	})
	t.Run("suite-preflight-binding", func(t *testing.T) {
		_, record := completeRunFixture(t, "memory")
		before, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		recovery := &liveRecovery{}
		current := suiteExecution{Record: &record, Recovery: recovery, Evidence: "actual-evidence"}
		first, binding := &preparedSuite{preparation: fresh()}, &preparedSuite{preparation: fresh()}
		var terminal bytes.Buffer
		for _, owner := range []*preparedSuite{first, binding, first, binding} {
			if err := owner.retainPreparation(&current, &terminal); err != nil {
				t.Fatal(err)
			}
		}
		after, err := json.Marshal(record)
		if err != nil || !bytes.Equal(before, after) || current.Record != &record || current.Recovery != recovery || current.Evidence != "actual-evidence" {
			t.Fatal("binding metadata replaced the actual suite", err)
		}
		if current.preparation == first.preparation || current.preparation == binding.preparation {
			t.Fatal("current result borrowed frozen acquisition")
		}
		if current.preparation == nil || len(current.preparation.Commands) != 2 {
			t.Fatal("actual binding lost an independent owner or repeated acquisition", current.preparation)
		}
		if !reflect.DeepEqual(current.preparation.Commands, []checkCommandFacts{fact, fact}) {
			t.Fatal("identical-valued independent facts were changed or deduplicated", current.preparation)
		}

		if strings.Count(terminal.String(), "Check phase=preparation scope=core process=passed started=true joined=true ") != 2 {
			t.Fatal("independent acquisition was omitted or printed twice", terminal.String())
		}
	})
	t.Run("acquisition-after-earlier-verification", func(t *testing.T) {
		verification := fresh()
		current := suiteExecution{preparation: verification}
		acquired := &preparedSuite{preparation: fresh()}
		source, err := json.Marshal(acquired.preparation)
		if err != nil {
			t.Fatal(err)
		}
		var terminal bytes.Buffer
		for range 2 {
			if err := acquired.retainPreparation(&current, &terminal); err != nil {
				t.Fatal(err)
			}
		}
		after, err := json.Marshal(acquired.preparation)
		if err != nil || !bytes.Equal(source, after) || current.preparation != verification {
			t.Fatal("later acquisition replaced current identity or changed frozen facts", err)
		}
		if len(current.preparation.Commands) != 2 || !reflect.DeepEqual(current.preparation.Commands, []checkCommandFacts{fact, fact}) {
			t.Fatal("earlier verification suppressed later independent acquisition or acquisition repeated", current.preparation)
		}
	})
	t.Run("delivery-status-and-sticky-error", func(t *testing.T) {
		t.Run("status-only-refusal", func(t *testing.T) {
			current := suiteExecution{}
			owner := &preparedSuite{preparation: fresh()}
			var terminal bytes.Buffer
			if err := owner.retainPreparation(&current, &terminal); err != nil {
				t.Fatal(err)
			}
			current.preparation.Preparation = "failed"
			for range 2 {
				if err := owner.retainPreparation(&current, &terminal); err != nil {
					t.Fatal(err)
				}
			}
			if len(current.preparation.Commands) != 1 || strings.Count(terminal.String(), "Check phase=preparation scope=core ") != 1 {
				t.Fatal("status refusal replayed or dropped command rows", terminal.String())
			}
			if strings.Count(terminal.String(), "Check preparation=passed; commands=1\n") != 1 || strings.Count(terminal.String(), "Check preparation=failed; commands=1\n") != 1 {
				t.Fatal("later non-command refusal lost its truthful status header", terminal.String())
			}
		})
		for _, failAt := range []int{1, 2} {
			t.Run(fmt.Sprintf("failed-attempt-%d", failAt), func(t *testing.T) {
				cause := errors.New("controlled terminal ownership failure")
				writer := &verificationOwnershipOutput{failAt: failAt, failure: cause}
				current := suiteExecution{}
				owner := &preparedSuite{preparation: fresh()}
				first := owner.retainPreparation(&current, writer)
				if !errors.Is(first, cause) || writer.attempts != failAt || current.preparation == nil {
					t.Fatal("original writer refusal was lost", first, writer.attempts)
				}
				current.preparation.Preparation = "failed"
				current.preparation.Commands = append(current.preparation.Commands, fact)
				if err := owner.retainPreparation(&current, writer); err != nil && !errors.Is(err, cause) {
					t.Fatal("retention changed the original terminal failure", err)
				}
				if writer.attempts != failAt || len(current.preparation.Commands) != 2 {
					t.Fatal("failed terminal delivery was repeated or lost acquired facts", writer.attempts, current.preparation)
				}

			})
		}
	})
	t.Run("combined-admission", func(t *testing.T) {
		shared, current := fresh(), fresh()
		shared.Commands = make([]checkCommandFacts, 128)
		current.Commands = make([]checkCommandFacts, 126)
		for index := range shared.Commands {
			shared.Commands[index] = fact
		}
		for index := range current.Commands {
			current.Commands[index] = fact
		}
		groups := []componentGroup{{Name: "boundary"}}
		frozen, err := json.Marshal(shared)
		if err != nil {
			t.Fatal(err)
		}
		if err := reserveComponentCommands(current, shared, groups); err != nil {
			t.Fatal("combined256-row control refused", err)
		}
		current.Commands = append(current.Commands, fact)
		if err := reserveComponentCommands(current, shared, groups); err != nil {
			t.Fatal("finite combined257-row control refused", err)
		}
		after, err := json.Marshal(shared)
		if err != nil || !bytes.Equal(frozen, after) {
			t.Fatal("reservation mutated frozen acquisition", err)
		}
		const future = `{"phase":"test","scope":"byte-bound","process":"group_stop_failed","started":false,"joined":false,"wall_seconds":1.7976931348623157e+308,"events":"unavailable","tool_cleanup":"retained_unjoined","requested_node":"unavailable","race_observation":"not_observed"}`
		var test checkCommandFacts
		if err := json.Unmarshal([]byte(future), &test); err != nil {
			t.Fatal(err)
		}
		conversion := test
		conversion.Phase = "conversion"
		prefix := fact
		prefix.Scope = ""
		body, err := json.Marshal(checkDiagnostics{Preparation: "pending", Commands: []checkCommandFacts{prefix, test, conversion}})
		if err != nil {
			t.Fatal(err)
		}
		prefix.Scope = strings.Repeat("x", (32<<20)-len(body)-1)
		current = &checkDiagnostics{Preparation: "passed", Commands: []checkCommandFacts{prefix}}
		groups = []componentGroup{{Name: "byte-bound"}}
		if err := reserveComponentCommands(current, nil, groups); err != nil {
			t.Fatal("last encoded command-byte control refused", err)
		}
		current.Commands[0].Scope += "x"
		if err := reserveComponentCommands(current, nil, groups); err == nil {
			t.Fatal("first encoded excess byte admitted")
		}
	})
}

type verificationOwnershipOutput struct {
	bytes.Buffer
	failAt, attempts int
	failure          error
}

func (writer *verificationOwnershipOutput) Write(body []byte) (int, error) {
	writer.attempts++
	if writer.attempts == writer.failAt {
		return 0, writer.failure
	}
	return writer.Buffer.Write(body)
}

func testAssemblyCompilerFailureRetainsFacts(t *testing.T) {
	t.Helper()
	_, initialRoot, _ := componentRepetitionAssemblyFixture(t)
	fixture, err := newCurrentDirectory("enkv-compiler-prefix-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	settled := true
	t.Cleanup(func() {
		if !settled {
			t.Log("retained compiler prefix fixture:", fixture.path)
			return
		}
		if err := fixture.remove(true); err != nil {
			t.Error("remove positively settled compiler fixture", err)
		}
	})
	inputs := filepath.Join(fixture.path, "inputs")
	if err := os.Mkdir(inputs, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(inputs, os.DirFS(filepath.Dir(initialRoot))); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(inputs, filepath.Base(initialRoot))
	bootstrap := repetitionTestBootstrap(t, root, fixture.path)
	locks, err := openResourceLocks(filepath.Join(fixture.path, "resources"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", fixture.path)
	ctx, cancel := context.WithTimeout(withResourceLocks(withRacePolicy(withExecutionParallel(t.Context(), 1), false), locks), 3*time.Minute)
	defer cancel()
	ctx, phase, err := localPreparationPhase(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	owner := &preparedWorkflow{phase: phase, joined: true}
	defer func() {
		if !owner.closed {
			finish, release := finalizationContext(ctx)
			defer release()
			if err := owner.close(finish); err != nil {
				t.Error("close compiler prefix owner", err)
			}
		}
	}()
	scratch, err := newCurrentDirectory("enkv-compiler-prefix-build-")
	if err != nil {
		t.Fatal(err)
	}
	owner.current = scratch
	build := filepath.Join(scratch.path, "build")
	if err := os.Mkdir(build, 0700); err != nil {
		t.Fatal(err)
	}
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	realGo, err = filepath.EvalSymlinks(realGo)
	if err != nil {
		t.Fatal(err)
	}
	compiled, witness := filepath.Join(fixture.path, "compiled"), filepath.Join(fixture.path, "body")
	// The real compiler finishes before its wrapper reports a failure. Its
	// acquired output-helper facts must survive the failed construction.
	script := "#!/bin/sh\n" + shellQuote(realGo) + ` "$@"
status=$?
if [ "$status" -ne 0 ]; then exit "$status"; fi
compile=false
for argument do
 if [ "$argument" = -c ]; then compile=true; fi
done
if [ "$PWD" = ` + shellQuote(filepath.Join(root, "core")) + ` ] && [ "$1" = test ] && [ "$compile" = true ]; then
 printf '%s\n' "$$" >> ` + shellQuote(compiled) + ` || exit 92
 printf 'controlled compiler tail failure\n' >&2
 exit 19
fi
exit 0
`
	if err := os.WriteFile(filepath.Join(fixture.path, "go"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fixture.path+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ENKV_COMPONENT_REPETITION_WITNESS", witness)
	ctx, owner.artifactOwner = withInvocationArtifacts(ctx)
	diagnostics := &checkDiagnostics{Preparation: "pending"}
	command := func(ctx context.Context, root, directory string, env []string, args ...string) ([]byte, error) {
		return diagnostics.runGoEnvironment(ctx, root, directory, env, args...)
	}
	policy := executionPolicy{Resolved: executionCapacity{Parallel: 1, MemoryLimitMiB: 8192}}
	plan := workflowPlan{SchemaVersion: 1, Name: "compiler-prefix-failure", Profile: "dev", Execution: policy, Steps: []resolvedWorkflowStep{{ID: "selected", Kind: "component-tests", Selected: true, Profile: "dev", Tests: singleTestRequest("TestFiniteRepetitionProcessWitness"), Focus: &componentFocus{Tests: singleTestRequest("TestFiniteRepetitionProcessWitness")}}}}
	owner.plan, owner.preparations, owner.class = plan, map[string]*checkDiagnostics{"selected": diagnostics}, rootAdmission{Execution: policy}
	settled, owner.joined = false, false
	assembled, buildErr := buildAssembly(command, diagnostics, ctx, root, "hermetic", "memory", bootstrap, build)
	var failure *toolFailure
	var exit *exec.ExitError
	if buildErr == nil || assembled.Binary != "" || !errors.As(buildErr, &failure) || !errors.As(buildErr, &exit) || exit.ExitCode() != 19 || failure.operation != "go test" || !failure.process.Started || !failure.process.Joined || !toolCommandsJoined(buildErr) || !sourceCommandsJoined(buildErr) {
		t.Fatal("failed compiler tail lost its real cause, join or unpublished build", buildErr)
	}
	body, err := os.ReadFile(compiled)
	var pid int
	if err != nil || strings.Count(string(body), "\n") != 1 {
		t.Fatal("exactly one real core compiler did not finish", string(body), err)
	}
	if n, err := fmt.Sscan(string(body), &pid); err != nil || n != 1 || pid <= 0 {
		t.Fatal("completed compiler PID unavailable", string(body), err)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatal("compiler PID remains after return", err)
	}
	if stopped, err := groupStopped(pid, nil); !stopped || err != nil {
		t.Fatal("compiler group remains after return", err)
	}
	owner.joined, settled = true, true
	if _, err := os.Stat(witness); !os.IsNotExist(err) {
		t.Fatal("compiler preparation entered a component body", err)
	}
	outputFacts, failedCompiles := 0, 0
	for _, fact := range diagnostics.Commands {
		if fact.Phase != "preparation" || !fact.Started || !fact.Joined || fact.Events != "not_run" || fact.WallSeconds == nil {
			t.Fatal("construction lost its actual command facts", fact)
		}
		if fact.ModulePreparation != nil && (!fact.ModulePreparation.passed() || fact.ModulePreparation.WallSeconds == nil) {
			t.Fatal("construction lost successful nested preparation", fact)
		}
		if fact.Scope == outputTestModule {
			if fact.Process != "passed" {
				t.Fatal("output construction did not finish before the core failure", fact)
			}
			outputFacts++
		} else if fact.Process != "passed" {
			if fact.Scope != "core" || fact.Process != "process_failed" {
				t.Fatal("unexpected construction failure", fact)
			}
			failedCompiles++
		}
	}
	if outputFacts == 0 || failedCompiles != 1 {
		t.Fatal("failed construction lost its passed output prefix or failed compiler", outputFacts, failedCompiles)
	}
	var output bytes.Buffer
	result, commandErr := executeCommandWorkflow(ctx, root, bootstrap, owner, diagnostics.recordPreparationFailure(buildErr), &output)
	if !errors.Is(commandErr, buildErr) || !owner.closed || !phase.released || !phase.joined || result.Outcome != "incomplete" || len(result.Steps) != 1 || result.Steps[0].Outcome != "not_run" || result.Steps[0].StartedAt != nil || result.Steps[0].FinishedAt != nil {
		t.Fatal("outer compiler failure lost its cause, joined cleanup or unstarted result", commandErr, result)
	}
	if _, err := os.Stat(scratch.path); !os.IsNotExist(err) {
		t.Fatal("joined compiler scratch survived its owner close", err)
	}
	acquired := result.executions["selected"].Preparation
	if acquired == diagnostics || acquired == nil || acquired.Preparation != diagnostics.Preparation || !reflect.DeepEqual(acquired.Commands, diagnostics.Commands) {
		t.Fatal("outer result did not retain an immutable copy of construction facts", acquired, diagnostics)
	}
	for _, fact := range diagnostics.Commands {
		line := fmt.Sprintf("Check phase=preparation scope=%s process=%s started=%t joined=%t ", fact.Scope, fact.Process, fact.Started, fact.Joined)
		want := 0
		for _, other := range diagnostics.Commands {
			if other.Scope == fact.Scope && other.Process == fact.Process && other.Started == fact.Started && other.Joined == fact.Joined {
				want++
			}
		}
		if strings.Count(output.String(), line) != want {
			t.Fatal("terminal omitted or repeated acquired construction facts", line, output.String())
		}
	}
}

// These acquired facts are synthetic: this checks outer result ownership and
// projection. The cases above establish actual command failure and settlement.
func testWorkflowAcquiredPreparationResults(t *testing.T) {
	for _, condition := range []string{"preparation-failed", "preparation-canceled", "admission-failed", "admission-canceled", "verification-refused", "prepared-verification-refused"} {
		t.Run(condition, func(t *testing.T) {
			ctx := withExecutionParallel(t.Context(), 1)
			policy := executionPolicy{Resolved: executionCapacity{Parallel: 1, MemoryLimitMiB: 8192}}
			plan := workflowPlan{SchemaVersion: 1, Name: "retained-preparation", Profile: "dev", Race: true, Execution: policy, Steps: []resolvedWorkflowStep{
				{ID: "first-1", ConfiguredStep: "first", Kind: "unit", Selected: true, Repetition: 1, Repetitions: 2},
				{ID: "first-2", ConfiguredStep: "first", Kind: "unit", Selected: true, Repetition: 2, Repetitions: 2},
				{ID: "later", Kind: "runner-tests", Selected: true},
				{ID: "excluded", Kind: "unit"},
			}}
			first := &checkDiagnostics{Preparation: "passed", Commands: []checkCommandFacts{
				{Phase: "preparation", Scope: "first-list", Process: "passed", Started: true, Joined: true, Events: "not_run", ToolCleanup: "passed", RaceObservation: "not_observed"},
				{Phase: "preparation", Scope: "first-build", Process: "passed", Started: true, Joined: true, Events: "not_run", ToolCleanup: "passed", RaceObservation: "not_observed"},
			}}
			later := &checkDiagnostics{Preparation: "passed", Commands: []checkCommandFacts{
				{Phase: "preparation", Scope: "later-build", Process: "passed", Started: true, Joined: true, Events: "not_run", ToolCleanup: "passed", RaceObservation: "not_observed"},
			}}
			cause := errors.New("controlled admission refusal")
			var prepareErr error
			if strings.HasPrefix(condition, "preparation-") {
				prepareErr = errors.New("controlled preparation refusal")
				later.Preparation, later.Commands[0].Process = "failed", "process_failed"
				if condition == "preparation-canceled" {
					prepareErr = context.Canceled
					later.Commands[0].Process = "interrupted"
					later.Commands[0].Started = false
				}
			}
			prepared := &preparedWorkflow{assemblyPreparations: ctx, binding: preparationBinding{ctx: ctx, race: plan.Race}, plan: plan, class: rootAdmission{Execution: policy}, joined: true,
				ordinary: map[string]*preparedOrdinaryGroup{
					"first": {ctx: ctx, cancel: func() {}, joined: true, preparation: first},
					"later": {ctx: ctx, cancel: func() {}, joined: true, preparation: later},
				},
			}
			admissions := 0
			ctx = context.WithValue(ctx, rootAdmitterContextKey{}, rootAdmitter(func(ctx context.Context, _ rootAdmission) (context.Context, error) {
				admissions++
				if condition == "admission-canceled" {
					return ctx, context.Canceled
				}
				if condition == "admission-failed" {
					return ctx, cause
				}
				return ctx, nil
			}))
			var terminal bytes.Buffer
			var result workflowResult
			var err error
			if condition == "prepared-verification-refused" {
				result, err = runPreparedWorkflow(ctx, "", "", prepared, &terminal)
				if closeErr := prepared.close(ctx); closeErr != nil {
					t.Fatal(closeErr)
				}
			} else {
				result, err = executeCommandWorkflow(ctx, "", "", prepared, prepareErr, &terminal)
			}
			if err == nil || !prepared.closed || !prepared.ordinary["first"].closed || !prepared.ordinary["later"].closed {
				t.Fatal("outer failure lost its error or acquired owner close", err)
			}
			if prepareErr != nil && (!errors.Is(err, prepareErr) || admissions != 0) || condition == "admission-failed" && !errors.Is(err, cause) || condition == "admission-canceled" && !errors.Is(err, context.Canceled) {
				t.Fatal("outer preparation/admission failure lost its original cause", err, admissions)
			}
			if strings.Contains(condition, "verification-refused") && !strings.Contains(err.Error(), "prepared workflow selection changed") {
				t.Fatal("verification did not refuse the changed prepared selection", err)
			}
			assertUnstartedWorkflowPreparation(t, result, err, terminal.String(), plan, map[string]*checkDiagnostics{"first-1": first, "later": later})
		})
	}

	t.Run("prepared-later-group-not-started", func(t *testing.T) {
		root := workflowExecutionFixture(t)
		ctx := withExecutionParallel(t.Context(), 1)
		policy := executionPolicy{Resolved: executionCapacity{Parallel: 1, MemoryLimitMiB: 8192}}
		plan := workflowPlan{SchemaVersion: 1, Name: "later-preparation", Profile: "dev", Race: true, Execution: policy, Steps: []resolvedWorkflowStep{
			{ID: "first", Kind: "unit", Selected: true}, {ID: "later", Kind: "runner-tests", Selected: true},
		}}
		preparation := &checkDiagnostics{Preparation: "passed", Commands: []checkCommandFacts{{Phase: "preparation", Scope: "later-build", Process: "passed", Started: true, Joined: true, Events: "not_run", ToolCleanup: "passed", RaceObservation: "not_observed"}}}
		groups := map[string]*preparedOrdinaryGroup{"later": {ctx: ctx, cancel: func() {}, joined: true, preparation: preparation}}
		plan.prepared = &preparedWorkflow{plan: plan, ordinary: groups, joined: true}
		cause := errors.New("controlled first activity failure")
		var terminal bytes.Buffer
		var owned []privateDirectory
		calls := 0
		result, err := executeWorkflow(ctx, root, plan, &terminal, &owned, groups, func(context.Context, resolvedWorkflowStep, io.Writer, string) (workflowStepExecution, error) {
			calls++
			return workflowStepExecution{}, cause
		})
		if !errors.Is(err, cause) || calls != 1 || len(result.Steps) != 2 || result.Steps[0].Outcome != "failed" || result.Steps[1].Outcome != "not_run" || result.Steps[1].StartedAt != nil {
			t.Fatal("first failure changed the unstarted later activity", err, calls, result.Steps)
		}

		if strings.Count(terminal.String(), "Check phase=preparation scope=later-build ") != 1 {
			t.Fatal("unstarted preparation terminal facts were missing or repeated", terminal.String())
		}
	})
}

func assertUnstartedWorkflowPreparation(t *testing.T, result workflowResult, cause error, terminal string, plan workflowPlan, acquired map[string]*checkDiagnostics) {
	t.Helper()
	if result.Name != plan.Name || result.Profile != plan.Profile || result.Race == nil || *result.Race != plan.Race || result.Execution.Resolved != plan.Execution.Resolved || len(result.Steps) != len(plan.Steps) {
		t.Fatal("outer result lost selected workflow or accepted settings", result)
	}

	for _, step := range result.Steps {
		want := "not_run"
		if !step.Selected {
			want = "not_selected"
		}
		if step.Outcome != want || step.StartedAt != nil || step.FinishedAt != nil {
			t.Fatal("preparation was presented as test execution", step)
		}
	}

}

func testOrdinaryActualWrapperFreshBinding(t *testing.T) {
	for _, fails := range []bool{false, true} {
		t.Run(fmt.Sprintf("body-fails-%t", fails), func(t *testing.T) {
			initialRoot, _, _ := overlayFixture(t)
			fixture, err := newCurrentDirectory("enkv-ordinary-owner-fixture-")
			if err != nil {
				t.Fatal(err)
			}
			joined := true
			var prepared *preparedWorkflow
			cleanupContext := t.Context()
			t.Cleanup(func() {
				if prepared != nil {
					finish, release := finalizationContext(cleanupContext)
					closeErr := prepared.close(finish)
					release()
					joined = joined && prepared.joined && closeErr == nil && toolCommandsJoined(closeErr) && sourceCommandsJoined(closeErr)
					if closeErr != nil {
						t.Error("close actual ordinary owner", closeErr)
					}
				}
				if !joined {
					t.Log("retained ordinary owner fixture:", fixture.path)
					return
				}
				if err := fixture.remove(true); err != nil {
					t.Error("remove positively settled ordinary fixture", err)
				}
			})
			if err := os.CopyFS(fixture.path, os.DirFS(filepath.Dir(initialRoot))); err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(fixture.path, filepath.Base(initialRoot))
			writeLocalGoFixture(t, root, "telemetry/go.mod", "module "+modulePath("telemetry")+"\n\ngo 1.27.0\n")
			writeLocalGoFixture(t, root, "telemetry/witness/witness_test.go", `package witness
import ("os"; "testing")
// full_only: false
func TestActualWrapper(t *testing.T) {
 if err := os.WriteFile(os.Getenv("ENKV_OWNER_BODY"), []byte("entered"), 0600); err != nil { t.Fatal(err) }
 if os.Getenv("ENKV_OWNER_FAIL") == "1" { t.Fatal("controlled owner body failure") }
}
`)
			initializeWorkflowExecutionFixture(t, root)
			directory := filepath.Join(fixture.path, "observations")
			if err := os.Mkdir(directory, 0700); err != nil {
				t.Fatal(err)
			}
			locks, err := openResourceLocks(filepath.Join(directory, "resources"))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(withResourceLocks(withRacePolicy(withExecutionParallel(t.Context(), 1), false), locks), 3*time.Minute)
			defer cancel()
			cleanupContext = ctx
			witness, journal := filepath.Join(directory, "body"), filepath.Join(directory, "commands")
			t.Setenv("ENKV_OWNER_BODY", witness)
			failure := "0"
			if fails {
				failure = "1"
			}
			t.Setenv("ENKV_OWNER_FAIL", failure)
			realGo, err := exec.LookPath("go")
			if err != nil {
				t.Fatal(err)
			}
			realGo, err = filepath.EvalSymlinks(realGo)
			if err != nil {
				t.Fatal(err)
			}
			observer := "#!/bin/sh\n" + shellQuote(realGo) + " \"$@\"\nstatus=$?\nif [ \"$status\" -ne 0 ]; then exit \"$status\"; fi\nif [ \"$PWD\" = " + shellQuote(filepath.Join(root, "core")) + " ]; then\n case \"$1\" in version|env) printf '%s\\n' \"$1\" >> " + shellQuote(journal) + " || exit 97;; esac\nfi\nexit 0\n"
			if err := os.WriteFile(filepath.Join(directory, "go"), []byte(observer), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
			path := filepath.Join(directory, "workflow.json")
			saveSelection(t, path, map[string]any{"schema_version": 1, "name": "actual-wrapper-owner", "profile": "dev", "execution": map[string]any{"parallel": 1}, "steps": []any{map[string]any{"id": "selected", "kind": "unit", "packages": []string{"telemetry/witness"}}}})
			joined = false
			plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: path})
			joined = toolCommandsJoined(err) && sourceCommandsJoined(err)
			if err != nil {
				t.Fatal(err)
			}
			joined = false
			prepared, err = prepareWorkflow(ctx, root, "", plan, io.Discard)
			joined = toolCommandsJoined(err) && sourceCommandsJoined(err)
			if err != nil {
				t.Fatal("actual ordinary preparation failed", err)
			}
			acquired := prepared.ordinary["selected"].preparation
			before, err := json.Marshal(acquired)
			if err != nil || acquired.Preparation != "passed" {
				t.Fatal("ordinary acquisition unavailable", err)
			}
			if err := os.WriteFile(journal, nil, 0600); err != nil {
				t.Fatal(err)
			}
			var terminal bytes.Buffer
			joined = false
			result, runErr := executeCommandWorkflow(ctx, root, "", prepared, nil, &terminal)
			joined = toolCommandsJoined(runErr) && sourceCommandsJoined(runErr) && prepared.joined
			if (runErr != nil) != fails || !prepared.closed {
				t.Fatal("actual wrapper changed body outcome or close", runErr, terminal.String())
			}
			if body, err := os.ReadFile(witness); err != nil || string(body) != "entered" {
				t.Fatal("actual ordinary body did not execute", string(body), err)
			}
			actual := result.executions["selected"].Ordinary
			if actual == nil || len(actual.Tests) != 1 || (actual.Tests[0].Outcome == "fail") != fails || actual.Diagnostics == nil || actual.Diagnostics.Preparation != "passed" {
				t.Fatal("actual body result or passed preparation was replaced", actual)
			}
			after, err := json.Marshal(acquired)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("wrapper changed frozen acquisition", err)
			}
			physical, err := os.ReadFile(journal)
			if err != nil || len(physical) != 0 {
				t.Fatal("actual wrapper repeated compiler configuration checks", string(physical), err)
			}
			prefix := result.executions["selected"].Preparation
			if prefix == nil || prefix == acquired || prefix == actual.Diagnostics || prefix.Preparation != "passed" || prefix.ordinaryCommandLimit != 0 || prefix.ordinaryCommandBytes != 0 {
				t.Fatal("actual wrapper lost independent fact-only passed preparation", prefix)
			}
			if !reflect.DeepEqual(prefix.Commands, acquired.Commands) {
				t.Fatal("wrapper omitted acquisition or added verification rows", prefix.Commands)
			}
			for _, fact := range actual.Diagnostics.Commands {
				if fact.Phase == "preparation" {
					t.Fatal("ordinary body duplicated immutable acquisition", fact)
				}
			}

		})
	}
}

func testNonCoreReconstructionInputOwner(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			module, err := reconstructionModule(provider)
			if err != nil {
				t.Fatal(err)
			}
			initial, _, _ := overlayFixture(t)
			fixture, err := newCurrentDirectory("enkv-noncore-owner-")
			if err != nil {
				t.Fatal(err)
			}
			joined := true
			var phase *toolDirectoryPhase
			cleanupContext := t.Context()
			t.Cleanup(func() {
				if phase != nil {
					finish, release := finalizationContext(cleanupContext)
					err := phase.Release(finish, joined)
					release()
					joined = joined && err == nil && toolCommandsJoined(err) && sourceCommandsJoined(err)
					if err != nil {
						t.Error("close noncore preparation phase", err)
					}
				}
				if !joined {
					t.Log("retained noncore fixture:", fixture.path)
					return
				}
				if err := fixture.remove(true); err != nil {
					t.Error(err)
				}
			})
			if err := os.CopyFS(fixture.path, os.DirFS(filepath.Dir(initial))); err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(fixture.path, filepath.Base(initial))
			mod := "module " + modulePath(module) + "\n\ngo 1.27.0\n"
			writeLocalGoFixture(t, root, module+"/go.mod", mod)
			if provider == "gcp" {
				writeLocalGoFixture(t, root, module+"/telemetry_test.mod", mod)
			}
			writeLocalGoFixture(t, root, module+"/input.go", "package "+provider+"\nvar Input=1\n")
			writeLocalGoFixture(t, root, module+"/input_test.go", strings.ReplaceAll(`package fixture
import("os";"testing")
// full_only: false
func TestRecoveryAcquisition(t *testing.T){if err:=os.WriteFile(os.Getenv("ENKV_NONCORE_BODY"),[]byte("entered"),0600);err!=nil{t.Fatal(err)};t.Fatal("constructor entered selected helper")}
`, "package fixture", "package "+provider))
			initializeWorkflowExecutionFixture(t, root)
			build, copyDirectory := filepath.Join(fixture.path, "build"), filepath.Join(fixture.path, "copy")
			for _, directory := range []string{build, copyDirectory} {
				if err := os.Mkdir(directory, 0700); err != nil {
					t.Fatal(err)
				}
			}
			locks, err := openResourceLocks(filepath.Join(fixture.path, "resources"))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(withResourceLocks(withRacePolicy(withExecutionParallel(t.Context(), 1), false), locks), 3*time.Minute)
			defer cancel()
			cleanupContext = ctx
			joined = false
			ctx, phase, err = localPreparationPhase(ctx, root)
			joined = toolCommandsJoined(err) && sourceCommandsJoined(err)
			if err != nil {
				t.Fatal(err)
			}
			joined = false
			source, err := sourceRevision(ctx, root)
			joined = toolCommandsJoined(err) && sourceCommandsJoined(err)
			if err != nil {
				t.Fatal(err)
			}
			journal, bodyMarker := filepath.Join(fixture.path, "commands"), filepath.Join(fixture.path, "body")
			t.Setenv("ENKV_NONCORE_BODY", bodyMarker)
			realGo, err := exec.LookPath("go")
			if err != nil {
				t.Fatal(err)
			}
			realGo, err = filepath.EvalSymlinks(realGo)
			if err != nil {
				t.Fatal(err)
			}
			observer := "#!/bin/sh\n" + shellQuote(realGo) + " \"$@\"\nstatus=$?\nif [ \"$status\" -ne 0 ]; then exit \"$status\"; fi\nscope=\nif [ \"$PWD\" = " + shellQuote(filepath.Join(root, module)) + " ]; then scope=" + shellQuote(module) + "; elif [ \"$PWD\" = " + shellQuote(filepath.Join(root, "core")) + " ]; then scope=core; fi\nif [ -n \"$scope\" ]; then printf '%s|%s\\n' \"$scope\" \"$1\" >> " + shellQuote(journal) + " || exit 97; fi\nexit 0\n"
			if err := os.WriteFile(filepath.Join(fixture.path, "go"), []byte(observer), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", fixture.path+string(os.PathListSeparator)+os.Getenv("PATH"))
			d := &checkDiagnostics{Preparation: "pending"}
			joined = false
			artifact, big, err := prepareConfigurationRecoveryArtifactOwned(d, ctx, root, build, provider, source, []string{"TestRecoveryAcquisition"})
			joined = toolCommandsJoined(err) && sourceCommandsJoined(err)
			if err != nil || !joined || big || len(artifact.inventory) != 1 || artifact.inventory[0] != "TestRecoveryAcquisition" || len(artifact.selected) != 1 || artifact.selected[0] != "TestRecoveryAcquisition" {
				t.Fatal("actual noncore constructor lost selected compiled helper", err, artifact)
			}

			for _, fact := range d.Commands {
				if fact.Process != "passed" || !fact.Started || !fact.Joined {
					t.Fatal("construction did not retain positive command joins", fact)
				}
			}
			initialFacts := append([]checkCommandFacts(nil), d.Commands...)
			observed, readErr := os.ReadFile(journal)
			if readErr != nil || strings.Count(string(observed), module+"|test\n") != 1 {
				t.Fatal("reconstruction did not construct exactly once", string(observed), readErr)
			}
			writeLocalGoFixture(t, root, module+"/input.go", "invalid source after construction")
			if err := checkRecoveryRace(ctx, artifact); err != nil {
				t.Fatal("source edit refused retained helper", err)
			}
			if !reflect.DeepEqual(initialFacts, d.Commands) {
				t.Fatal("borrowing changed construction facts")
			}
			after, readErr := os.ReadFile(journal)
			if readErr != nil || !bytes.Equal(observed, after) {
				t.Fatal("borrowing re-ran compiler checks", string(after), readErr)
			}
			if _, err := os.Stat(bodyMarker); !os.IsNotExist(err) {
				t.Fatal("noncore preparation entered a helper body", err)
			}
		})
	}
}
func testActualCallbackFailedBodyPreparation(t *testing.T) {
	root := workflowExecutionFixture(t)
	_, run := completeRunFixture(t, "memory")
	actual := run.Correctness.ComponentRun
	actual.Outcome = "failed"
	actual.Checks.Outcome = "failed"
	actual.Checks.Tests[0].Outcome = "fail"
	fact := checkCommandFacts{Phase: "preparation", Scope: "core", Process: "passed", Started: true, Joined: true, Events: "not_run", ToolCleanup: "not_required", RaceObservation: "not_observed"}
	actual.Checks.Diagnostics = &checkDiagnostics{Preparation: "passed", Commands: []checkCommandFacts{fact}}
	frozen, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	policy := executionPolicy{Resolved: executionCapacity{Parallel: 1, MemoryLimitMiB: 8192}}
	step := resolvedWorkflowStep{ID: "selected", Kind: "component-tests", Selected: true, Profile: "full"}
	plan := workflowPlan{SchemaVersion: 1, Name: "callback-owner", Profile: "full", Execution: policy, Steps: []resolvedWorkflowStep{step}}
	source := &checkDiagnostics{Preparation: "passed", Commands: []checkCommandFacts{fact}}
	prepared := &preparedWorkflow{plan: plan, preparations: map[string]*checkDiagnostics{"selected": source}, joined: true}
	plan.prepared = prepared
	cause := errors.New("controlled actual body failure")
	var output bytes.Buffer
	result, runErr := executeWorkflow(withExecutionParallel(t.Context(), 1), root, plan, &output, nil, nil, func(ctx context.Context, step resolvedWorkflowStep, output io.Writer, directory string) (workflowStepExecution, error) {
		d := step.currentPrefix
		if d == nil {
			t.Fatal("custom callback lost current live owner")
		}
		if err := d.reserveCommands([]checkCommandFacts{fact}); err != nil {
			t.Fatal(err)
		}
		if err := d.consumeCommands([]checkCommandFacts{fact}); err != nil {
			t.Fatal(err)
		}
		if err := d.append(fact); err != nil {
			t.Fatal(err)
		}
		d.cancelReservations()
		return workflowStepExecution{Component: actual}, cause
	})
	after, err := json.Marshal(actual)
	current := result.executions["selected"]
	if !errors.Is(runErr, cause) || err != nil || !bytes.Equal(frozen, after) || current.Component != actual || current.Preparation == nil || current.Preparation.Preparation != "passed" || len(current.Preparation.Commands) != 2 {
		t.Fatal("callback replaced actual failed body or successful setup", runErr, current)
	}

}
func testUnjoinedComplementRetainsInputs(t *testing.T) {
	_, run := completeRunFixture(t, "memory")
	fact := checkCommandFacts{Phase: "preparation", Scope: "core", Process: "group_stop_failed", Started: true, Joined: false}
	current, err := newCurrentDirectory("enkv-unjoined-prefix-")
	if err != nil {
		t.Fatal(err)
	}
	// This synthetic row starts no process. After observing refusal, the test owns positive settlement.
	defer func() {
		if err := current.remove(true); err != nil {
			t.Error(err)
		}
	}()
	execution := workflowStepExecution{Component: run.Correctness.ComponentRun, Preparation: &checkDiagnostics{Preparation: "failed", Commands: []checkCommandFacts{fact}}}
	if workflowExecutionJoined(execution, nil) {
		t.Fatal("actual passed component hid an unjoined independent prefix")
	}
	owner := &preparedWorkflow{current: current, joined: workflowExecutionJoined(execution, nil)}
	if err := owner.close(t.Context()); err == nil {
		t.Fatal("unjoined prefix allowed input cleanup")
	}
	if _, err := os.Stat(current.path); err != nil {
		t.Fatal("unjoined prefix inputs were removed", err)
	}
}

type ownershipPartialWriter struct {
	bytes.Buffer
	failure  error
	attempts int
}

func (w *ownershipPartialWriter) Write(body []byte) (int, error) {
	w.attempts++
	n := len(body) / 2
	_, _ = w.Buffer.Write(body[:n])
	return n, w.failure
}
func testPartialWriterKeepsActual(t *testing.T) {
	_, record := completeRunFixture(t, "memory")
	before, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	cause := errors.New("controlled partial terminal refusal")
	writer := &ownershipPartialWriter{failure: cause}
	fact := checkCommandFacts{Phase: "preparation", Scope: "core", Process: "passed", Started: true, Joined: true}
	first := &preparedSuite{preparation: &checkDiagnostics{Preparation: "passed", Commands: []checkCommandFacts{fact}}}
	second := &preparedSuite{preparation: &checkDiagnostics{Preparation: "passed", Commands: []checkCommandFacts{fact}}}
	current := suiteExecution{Record: &record, Evidence: "actual", Recovery: &liveRecovery{}}
	if err := first.retainPreparation(&current, writer); !errors.Is(err, cause) {
		t.Fatal("partial writer lost original cause", err)
	}
	if err := second.retainPreparation(&current, writer); !errors.Is(err, cause) {
		t.Fatal("later facts replaced sticky writer cause", err)
	}
	after, err := json.Marshal(record)
	if err != nil || !bytes.Equal(before, after) || current.Record != &record || current.Evidence != "actual" || current.Recovery == nil || current.preparation == nil || current.preparation.Preparation != "passed" || len(current.preparation.Commands) != 2 || writer.attempts != 1 || writer.Len() == 0 {
		t.Fatal("partial writer replayed, dropped facts, or replaced actual result", err, current, writer.attempts)
	}
}

func testParallelRecoveryIsolatedFold(t *testing.T) {
	fact := checkCommandFacts{Phase: "preparation", Scope: "output", Process: "interrupted", Started: false, Joined: true, Events: "not_run", ToolCleanup: "not_required", RaceObservation: "not_observed"}
	source := &checkDiagnostics{Preparation: "passed", Commands: []checkCommandFacts{{Phase: "preparation", Scope: "source", Process: "passed", Started: true, Joined: true}}}
	before, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	parent := &runState{preparation: &checkDiagnostics{Preparation: "passed"}, record: runRecord{Scenarios: make([]scenarioResult, 2)}}
	if err := parent.preparation.retainAcquisition(source, "fixture", source); err != nil {
		t.Fatal(err)
	}
	var scenario string
	for _, definition := range catalog.Definitions() {
		if !catalog.HasFixtureCapability(definition.Name, catalog.FixtureConfigurationRecovery) {
			scenario = definition.Name
			break
		}
	}
	if scenario == "" {
		t.Fatal("nonreconstruction catalog control unavailable")
	}
	entries := []catalog.Entry{{Scenario: scenario, Sequence: 1}, {Scenario: scenario, Sequence: 2}}
	children, forecasts, err := parent.prepareHermeticDiagnostics(entries)
	if err != nil || len(children) != 2 || children[0].preparation == nil || children[1].preparation == nil || children[0].preparation == children[1].preparation || children[0].preparation == parent.preparation || len(children[0].preparation.Commands) != 0 || len(children[1].preparation.Commands) != 0 {
		t.Fatal("parallel preparation reused an activity owner", err)
	}
	if err := parent.preparation.reserveCommands([]checkCommandFacts{fact, fact}); err != nil {
		t.Fatal(err)
	}
	for index, child := range children {
		forecasts[index] = []checkCommandFacts{fact}
		if err := child.preparation.reserveCommands(forecasts[index]); err != nil {
			t.Fatal(err)
		}
		if err := child.preparation.consumeCommands(forecasts[index]); err != nil {
			t.Fatal(err)
		}
		if err := child.preparation.append(fact); err != nil {
			t.Fatal(err)
		}
		child.preparation.Preparation = "failed"
		if index == 0 {
			child.record.Outcome = "failed"
		} else {
			child.record.Outcome = "interrupted"
		}
	}
	for index, child := range children {
		if err := parent.foldHermeticPreparation(child, forecasts[index]); err != nil {
			t.Fatal(err)
		}
	}
	if err := parent.foldHermeticPreparation(children[0], forecasts[0]); err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(source)
	if err != nil || !bytes.Equal(before, after) || len(parent.preparation.Commands) != 3 || !reflect.DeepEqual(parent.preparation.Commands[1:], []checkCommandFacts{fact, fact}) || parent.preparation.Preparation != "failed" {
		t.Fatal("parallel fold lost independent identical canceled/failed facts or changed source", err, parent.preparation)
	}
	parent.preparation.cancelReservations()
}

func testFreshSnapshotResetsActivityState(t *testing.T) {
	fact := checkCommandFacts{Phase: "preparation", Scope: "core", Process: "passed", Started: true, Joined: true}
	source := &checkDiagnostics{Preparation: "passed", Commands: []checkCommandFacts{fact}}
	owner := &preparedSuite{}
	source.acquisitions = map[checkAcquisition]struct{}{{owner, "source"}: {}}
	if err := source.reserveCommands([]checkCommandFacts{fact}); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := writeCheckDiagnostics(&output, source); err != nil {
		t.Fatal(err)
	}
	copy := source.snapshot()
	if copy == source || copy.Preparation != source.Preparation || !reflect.DeepEqual(copy.Commands, source.Commands) || copy.hasPlan() || copy.held.rows != 0 || copy.attempted != 0 || copy.headerAttempted || copy.deliveryFailed || copy.hasAcquisition(owner, "source") || copy.ordinaryCommandLimit != 0 || copy.ordinaryCommandBytes != 0 {
		t.Fatal("fresh activity inherited delivery, claims, or future reservations", copy)
	}
	if !source.hasPlan() || source.attempted != 1 || !source.headerAttempted || !source.hasAcquisition(owner, "source") {
		t.Fatal("snapshot changed source activity ownership", source)
	}
	source.cancelReservations()
}

func testSuiteWrapperRefusalKeepsActualRecord(t *testing.T) {
	_, record := completeRunFixture(t, "memory")
	before, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	d := &checkDiagnostics{Preparation: "passed", Commands: []checkCommandFacts{{Phase: "preparation", Scope: "core", Process: "passed", Started: true, Joined: true}}}
	recovery := &liveRecovery{}
	initial := suiteExecution{Record: &record, Recovery: recovery, Evidence: "actual-evidence", preparation: d}
	prepared := &preparedSuite{assemblyPreparations: t.Context(), binding: preparationBinding{ctx: t.Context()}, closed: true, joined: true}
	result, runErr := runPreparedSuiteResult(t.Context(), "", "", prepared, io.Discard, initial)
	after, err := json.Marshal(record)
	if runErr == nil || !strings.Contains(runErr.Error(), "scenario preparation is closed or unsettled") || err != nil || !bytes.Equal(before, after) || result.Record != &record || result.Recovery != recovery || result.Evidence != "actual-evidence" || result.preparation != d || d.Preparation != "failed" || len(d.Commands) != 1 {
		t.Fatal("suite wrapper setup refusal replaced actual result or current owner", runErr, result)
	}
}

func testActualSuccessfulSuiteBindingOwner(t *testing.T) {
	_, initial, _ := componentRepetitionAssemblyFixture(t)
	fixture, err := newCurrentDirectory("enkv-suite-binding-owner-")
	if err != nil {
		t.Fatal(err)
	}
	joined := true
	var phase *toolDirectoryPhase
	var prepared *preparedSuite
	cleanupContext := t.Context()
	t.Cleanup(func() {
		finish, release := finalizationContext(cleanupContext)
		defer release()
		if prepared != nil {
			err := prepared.close(finish)
			joined = joined && err == nil && prepared.joined
			if err != nil {
				t.Error(err)
			}
		}
		if phase != nil {
			err := phase.Release(finish, joined)
			joined = joined && err == nil
			if err != nil {
				t.Error(err)
			}
		}
		if !joined {
			t.Log("retained suite binding fixture:", fixture.path)
			return
		}
		if err := fixture.remove(true); err != nil {
			t.Error(err)
		}
	})
	if err := os.CopyFS(fixture.path, os.DirFS(filepath.Dir(initial))); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(fixture.path, filepath.Base(initial))
	bootstrap := repetitionTestBootstrap(t, root, fixture.path)
	marker, journal := filepath.Join(fixture.path, "body"), filepath.Join(fixture.path, "commands")
	t.Setenv("ENKV_BINDING_BODY", marker)
	writeLocalGoFixture(t, root, "tests/hermetic/binding_worker_test.go", `package core
import("os";"testing")
func bindingBody(t *testing.T){if err:=os.WriteFile(os.Getenv("ENKV_BINDING_BODY"),[]byte("entered"),0600);err!=nil{t.Fatal(err)};t.Fatal("binding entered worker")}
// full_only: false
func TestHermeticRun(t *testing.T){bindingBody(t)}
// full_only: false
func TestHermeticChild(t *testing.T){bindingBody(t)}
`)
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	realGo, err = filepath.EvalSymlinks(realGo)
	if err != nil {
		t.Fatal(err)
	}
	observer := "#!/bin/sh\nprintf 'BEGIN\\n' >> " + shellQuote(journal) + "\nprintf '%s\\n' \"$PWD\" \"$@\" >> " + shellQuote(journal) + "\nprintf 'END\\n' >> " + shellQuote(journal) + "\nexec " + shellQuote(realGo) + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(fixture.path, "go"), []byte(observer), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fixture.path+string(os.PathListSeparator)+os.Getenv("PATH"))
	locks, err := openResourceLocks(filepath.Join(fixture.path, "resources"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(withResourceLocks(withRacePolicy(withExecutionParallel(t.Context(), 1), true), locks), 3*time.Minute)
	defer cancel()
	cleanupContext = ctx
	joined = false
	ctx, phase, err = localPreparationPhase(ctx, root)
	joined = toolCommandsJoined(err) && sourceCommandsJoined(err)
	if err != nil {
		t.Fatal(err)
	}
	suite, environment := filepath.Join(root, "suite.json"), filepath.Join(root, "environment.json")
	saveSelection(t, suite, suiteFixture("binding-owner", []string{"state.single-value-update-preserves-other-values/members_32"}))
	saveSelection(t, environment, memoryEnvironment())
	request, err := parseRunRequest([]string{"run", "--race", "--suite", suite, "--environment", environment})
	if err != nil {
		t.Fatal(err)
	}
	joined = false
	prepared, err = prepareSuite(nil, ctx, root, bootstrap, request, io.Discard)
	joined = toolCommandsJoined(err) && sourceCommandsJoined(err)
	if err != nil || prepared == nil || prepared.inventory.Binary == "" || prepared.preparation == nil || len(prepared.preparation.Commands) == 0 {
		t.Fatal("actual suite preparation failed", err)
	}
	frozen, err := json.Marshal(prepared.preparation)
	if err != nil {
		t.Fatal(err)
	}
	_, full := completeRunFixture(t, "memory")
	current := suiteExecution{Record: &full, Recovery: &liveRecovery{}, Evidence: "actual-record"}
	if err := prepared.retainPreparation(&current, io.Discard); err != nil {
		t.Fatal(err)
	}
	constructorJournal, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	compiles := 0
	for _, block := range strings.Split(string(constructorJournal), "BEGIN\n")[1:] {
		lines := strings.Split(strings.TrimSuffix(block, "END\n"), "\n")
		if len(lines) > 2 && lines[1] == "test" {
			for _, arg := range lines[2:] {
				if arg == "-c" {
					compiles++
				}
			}
		}
	}
	if compiles != 1 {
		t.Fatal("suite preparation did not build one actual executable", compiles)
	}
	if err := os.WriteFile(filepath.Join(root, "core/fixture.go"), []byte("package core\ninvalid source after construction\n"), 0600); err != nil {
		t.Fatal(err)
	}
	actual := prepared.inventory
	joined = false
	err = prepared.bindActualOwned(current.preparation, ctx, root, &actual)
	joined = toolCommandsJoined(err) && sourceCommandsJoined(err)
	if err != nil || !joined || actual.Binary != prepared.inventory.Binary {
		t.Fatal("source edit invalidated the selected actual executable", err)
	}
	after, err := json.Marshal(prepared.preparation)
	if err != nil || !bytes.Equal(frozen, after) || current.Record != &full || current.Evidence != "actual-record" || current.Recovery == nil {
		t.Fatal("actual binding changed construction facts or the current record", err)
	}
	if current.preparation == prepared.preparation || !reflect.DeepEqual(current.preparation.Commands, prepared.preparation.Commands) {
		t.Fatal("binding repeated construction or aliased its recorded facts", current.preparation)
	}
	observed, err := os.ReadFile(journal)
	if err != nil || !bytes.Equal(observed, constructorJournal) {
		t.Fatal("borrowing an actual build started compiler verification", string(observed), err)
	}
	for _, fact := range prepared.preparation.Commands {
		if !fact.Started || !fact.Joined || fact.Process != "passed" || fact.WallSeconds == nil {
			t.Fatal("construction lost its physical command completion", fact)
		}
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("binding entered a Product body", err)
	}
	binary := actual.Binary
	finish, release := finalizationContext(ctx)
	err = prepared.close(finish)
	release()
	if err != nil {
		t.Fatal("binding owner did not positively close", err)
	}
	if _, err := os.Stat(binary); !os.IsNotExist(err) {
		t.Fatal("joined suite retained its invocation-owned executable", err)
	}
}

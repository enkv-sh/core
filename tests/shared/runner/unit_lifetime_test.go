package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// full_only: false
func TestUnitCumulativeExpiryKeepsJoinedRootAndRefusesNext(t *testing.T) {
	root, _, _ := overlayFixture(t)
	const directory = "providers/gcp"
	const pkg = modulePrefix + directory
	writeLocalGoFixture(t, root, directory+"/go.mod", "module "+pkg+"\n\ngo 1.27.0\n")
	writeLocalGoFixture(t, root, directory+"/lifetime_test.go", `package gcp
import ("os"; "strconv"; "testing")
// full_only: false
func TestAlpha(t *testing.T) { if err := os.WriteFile(os.Getenv("ENKV_UNIT_FIRST_PID"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil { t.Fatal(err) } }
// full_only: true
// exclusive: true
func TestLater(t *testing.T) { if err := os.WriteFile(os.Getenv("ENKV_UNIT_LATER_MARKER"), []byte("started"), 0600); err != nil { t.Fatal(err) } }
`)
	firstPID, later := filepath.Join(t.TempDir(), "first.pid"), filepath.Join(t.TempDir(), "later")
	t.Setenv("ENKV_UNIT_FIRST_PID", firstPID)
	t.Setenv("ENKV_UNIT_LATER_MARKER", later)
	parent := withExecutionParallel(withRacePolicy(t.Context(), true), 1)
	evidence := ordinaryStepEvidence{Diagnostics: &checkDiagnostics{Preparation: "passed"}}
	listed, err := listOrdinaryPackages(parent, root, directory, nil, []string{"."}, evidence.Diagnostics)
	if err != nil || len(listed) != 1 {
		t.Fatal("unit lifetime fixture lost its package placement", listed, err)
	}
	compiled, err := prepareOrdinaryPackage(parent, root, directory, nil, []string{"."}, listed[0], t.TempDir(), evidence.Diagnostics)
	if err != nil {
		t.Fatal(err)
	}
	retained := compiled.inventory
	want := map[string][]string{pkg: slices.Clone(retained.Tests)}
	if err := appendOrdinaryInventory(&evidence, want, []ordinaryPackage{retained}); err != nil {
		t.Fatal(err)
	}
	artifact := preparedOrdinaryArtifact{ordinaryArtifact: ordinaryArtifact{Directory: directory, Package: pkg, Tests: retained.Tests, CompiledTests: slices.Clone(retained.Inventory), Classifications: retained.Classifications}, binary: compiled.binary, cwd: compiled.cwd, converter: testEventConverterFixture(t, root), unit: true}
	values, err := testBuildEnvironment(runGoEnvironment, parent, root)
	if err != nil {
		t.Fatal(err)
	}
	duration := newPreparedGroupDuration(parent, 30*time.Second)
	defer duration.cancel()
	ctx, finish := duration.executionContext(parent)
	defer finish()
	barrier := &repetitionBarrier{}
	leave, err := barrier.enter(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	// The read lease permits the first root and holds the later exclusive root.
	var once sync.Once
	release := func() { once.Do(func() { leave(true) }) }
	defer release()
	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		release()
		close(done)
	}()
	artifact.barrier = barrier
	err = executePreparedOrdinary(ctx, root, artifact, values["GOROOT"], want, &evidence)
	finish()
	<-done
	if !errors.Is(err, context.DeadlineExceeded) || len(evidence.Tests) != 2 || evidence.Tests[0].Name != "TestAlpha" || evidence.Tests[0].Outcome != "pass" || evidence.Tests[1].Name != "TestLater" || evidence.Tests[1].Outcome != "not_run" {
		t.Fatal("unit expiry lost the completed root or its deadline cause", err, evidence.Tests)
	}
	var commands []checkCommandFacts
	for _, fact := range evidence.Diagnostics.Commands {
		if fact.Phase == "test" {
			commands = append(commands, fact)
		}
	}
	if len(commands) != 2 || !commands[0].Started || !commands[0].Joined || commands[0].Process != "passed" || commands[0].Events != "valid" || commands[1].Started || !commands[1].Joined || commands[1].Process != "timed_out" || commands[1].Events != "not_run" {
		t.Fatal("unit expiry changed completed or refused process facts", commands)
	}
	body, err := os.ReadFile(firstPID)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(body))
	if err != nil || pid <= 0 || !errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
		t.Fatal("completed unit process did not leave a joined PID", pid, err)
	}
	if _, err := os.Stat(later); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("expired unit owner started its later root", err)
	}
}

// full_only: false
func TestPreparedUnitTestlessTimeoutStopsAndJoinsBeforeCaller(t *testing.T) {
	root, _, _ := overlayFixture(t)
	const directory = "plugins/github-output"
	const module = modulePrefix + "plugins/outputs/github-actions"
	writeLocalGoFixture(t, root, directory+"/go.mod", "module "+module+"\n\ngo 1.27.0\n")
	for _, name := range []string{"enkv-output-github-repository", "enkv-output-github-organization"} {
		writeLocalGoFixture(t, root, directory+"/cmd/"+name+"/main.go", "package main\nfunc main() {}\n")
	}
	initializeWorkflowExecutionFixture(t, root)
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	pidPath, later := filepath.Join(bin, "hung.pid"), filepath.Join(bin, "later")
	shim := "#!/bin/sh\nif [ \"$1\" = test ]; then\n case \"$*\" in *enkv-output-github-repository*) printf started > " + shellQuote(later) + "; exit 0;; esac\n printf '%s\\n' \"$$\" > " + shellQuote(pidPath) + "\n exec sleep 120\nfi\nexec " + shellQuote(realGo) + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "go"), []byte(shim), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	setup, stopSetup := context.WithTimeout(withExecutionParallel(t.Context(), 1), time.Minute)
	defer stopSetup()
	source, err := sourceRevision(setup, root)
	if err != nil {
		t.Fatal(err)
	}
	var artifacts []preparedOrdinaryArtifact
	for _, name := range []string{"enkv-output-github-repository", "enkv-output-github-organization"} {
		artifact := preparedOrdinaryArtifact{unit: true, ordinaryArtifact: ordinaryArtifact{Directory: directory, Package: module + "/cmd/" + name, Patterns: []string{"./cmd/" + name}, TestFlags: []string{"-timeout=1ms"}}}
		artifacts = append(artifacts, artifact)
	}
	ctx, cancel := context.WithTimeout(withExecutionParallel(t.Context(), 1), 90*time.Second)
	defer cancel()
	group := preparedOrdinaryGroup{source: source, step: resolvedWorkflowStep{Kind: "unit"}}
	evidence := ordinaryStepEvidence{Diagnostics: &checkDiagnostics{Preparation: "passed"}}
	err = group.executeArtifacts(ctx, root, artifacts, &evidence, io.Discard)
	var failure *toolFailure
	if ctx.Err() != nil || !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &failure) || failure.operation != "go test" || failure.process.Status != "timed_out" || !failure.process.Started || !failure.process.Joined {
		t.Fatal("testless unit did not time out and join before its caller", err, ctx.Err())
	}
	if len(evidence.Diagnostics.Commands) != 1 || evidence.Diagnostics.Commands[0].Phase != "test" || evidence.Diagnostics.Commands[0].Process != "timed_out" || !evidence.Diagnostics.Commands[0].Started || !evidence.Diagnostics.Commands[0].Joined || len(evidence.Tests) != 0 || evidence.Complete {
		t.Fatal("testless timeout lost its exact failed process facts", evidence)
	}
	body, err := os.ReadFile(pidPath)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(body)))
	if err != nil || pid <= 0 || !errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
		t.Fatal("timed-out testless command did not leave a joined PID", pid, err)
	}
	if _, err := os.Stat(later); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("testless timeout started a later artifact", err)
	}
}

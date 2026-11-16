package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// full_only: false
func TestSupervisorSharedSourceBuildNeedsNoProductPackages(t *testing.T) {
	source := filepath.Clean(filepath.Join(filepath.Dir(savedWorkflowPath(t, "dev")), "../.."))
	root := t.TempDir()
	for _, item := range []struct{ source, target string }{
		{"core/go.mod", "core/go.mod"},
		{"core/go.sum", "core/go.sum"},
		{"tests/shared/records/io.go", "core/internal/testrecords/io.go"},
		{"tests/shared/runner/execution.go", "core/internal/supervisor/execution.go"},
		{"tests/shared/runner/command_arguments.go", "core/internal/supervisor/command_arguments.go"},
		{"tests/shared/runner/workflow_file.go", "core/internal/supervisor/workflow_file.go"},
		{"tests/shared/runner/workflow_preview.go", "core/internal/supervisor/workflow_preview.go"},
		{"tests/shared/runner/workflow_limits.go", "core/internal/supervisor/workflow_limits.go"},
		{"tests/shared/records/live_limits.go", "core/internal/testrecords/live_limits.go"},
		{"tests/shared/runner/selection_json.go", "core/internal/supervisor/selection_json.go"},
		{"tests/shared/runner/race_policy.go", "core/internal/supervisor/race_policy.go"},
		{"tests/shared/runner/process_environment.go", "core/internal/supervisor/process_environment.go"},
		{"tests/shared/runner/process_output.go", "core/internal/supervisor/process_output.go"},
		{"tests/shared/runner/module_sources.go", "core/internal/supervisor/module_sources.go"},
		{"tests/shared/runner/module_sources_generated.go", "core/internal/supervisor/module_sources_generated.go"},
	} {
		body, err := os.ReadFile(filepath.Join(source, item.source))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, item.target)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	const driver = `package main
import ("encoding/json"; "os")
func main() {
 parsed, err := parsePlanRunArguments([]string{"plan", "--workflow", os.Args[1], "--parallel=2", "--memory-limit-mib=512"})
 if err != nil { panic(err) }
 var workflow workflowFile
 if err := readSelectionFile(parsed.request.Path, &workflow); err != nil { panic(err) }
 policy, err := resolveExecution(workflow.Execution, parsed.request.Execution)
 if err != nil { panic(err) }
 if err := json.NewEncoder(os.Stdout).Encode(policy); err != nil { panic(err) }
}

`
	if err := os.WriteFile(filepath.Join(root, "core/internal/supervisor/main.go"), []byte(driver), 0600); err != nil {
		t.Fatal(err)
	}
	workflow := filepath.Join(root, "workflow.json")
	if err := os.WriteFile(workflow, []byte(`{"schema_version":1,"name":"capacity","execution":{"parallel":3},"steps":[{"id":"runner","kind":"runner-tests"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(cacheOnlyGoContext(t.Context()), time.Minute)
	defer cancel()
	binary := filepath.Join(root, "supervisor")
	if _, err := runGo(ctx, root, "core", "build", "-mod=readonly", "-race", "-o", binary, "./internal/supervisor"); err != nil {
		t.Fatal("shared source required a product package or changed module metadata", err)
	}
	command := exec.Command(binary, workflow)
	output := new(limitedOutput)
	command.Stdout, command.Stderr = output, output
	result := superviseProcess(ctx, command)
	const want = "{\"requested\":{\"parallel\":2,\"memory_limit_mib\":512},\"resolved\":{\"parallel\":2,\"memory_limit_mib\":512}}\n"
	if result.Status != "passed" || !result.Started || !result.Joined || output.overflow || output.String() != want {
		t.Fatalf("shared source changed capacity semantics: result=%+v output=%q", result, output.String())
	}
}

// full_only: false
func TestSupervisorNativeSetupPublishesItsBoundSource(t *testing.T) {
	root, admission, _, script := copiedSupervisorSetupFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	command := exec.Command("/bin/bash", script)
	command.Dir, command.Env = root, goEnvironment()
	stdout, stderr := new(limitedOutput), new(limitedOutput)
	command.Stdout, command.Stderr = stdout, stderr
	result := superviseProcess(ctx, command)
	if result.Status != "passed" || !result.Started || !result.Joined || stdout.overflow || stderr.overflow {
		logs, err := filepath.Glob(filepath.Join(root, "tests/.supervisor/setup.*/compiler.log"))
		if err == nil && len(logs) == 1 {
			file, openErr := os.Open(logs[0])
			if openErr == nil {
				body, readErr := io.ReadAll(io.LimitReader(file, 64<<10))
				closeErr := file.Close()
				t.Logf("setup compiler output (at most 64 KiB): %s; read=%v close=%v", body, readErr, closeErr)
			}
		}
		t.Fatalf("native setup failed: result=%+v stdout=%s stderr=%s", result, stdout.String(), stderr.String())
	}
	installation := filepath.Join(root, "tests/.supervisor")
	if stdout.String() != "Supervisor setup complete: "+filepath.Join(installation, "supervisor")+"\n" {
		t.Fatalf("native setup completion differs: %q", stdout.String())
	}
	entries, err := os.ReadDir(installation)
	if err != nil || len(entries) != 1 || entries[0].Name() != "supervisor" {
		t.Fatal("native setup did not dispose its source snapshot and cache", entries, err)
	}
	info, err := os.Lstat(filepath.Join(installation, "supervisor"))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0700 {
		t.Fatal("native supervisor is not a private executable", err)
	}
	entries, err = os.ReadDir(admission)
	if err != nil || len(entries) != 1 || entries[0].Name() != "machine.lock" {
		t.Fatal("native setup changed the stable resource lock set", entries, err)
	}
	lockPath := filepath.Join(admission, "machine.lock")
	before, err := os.Lstat(lockPath)
	if err != nil || !ownedLockFile(before, false, 0600) {
		t.Fatal("native setup resource lock owner or mode differs", err)
	}
	locks, err := openResourceLocks(admission)
	if err != nil {
		t.Fatal(err)
	}
	waitCtx, stopWait := context.WithTimeout(ctx, time.Second)
	defer stopWait()
	lease, err := locks.acquireMachine(waitCtx, true)
	if err != nil {
		t.Fatal("native setup retained its resource lock after positive completion", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(lockPath)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("resource lock inode changed after release", err)
	}
}

// full_only: false
func TestInstalledSupervisorPreviewStartsNoCompilerAndWaitsForNoResources(t *testing.T) {
	root, resources, controls, setup := copiedSupervisorSetupFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	command := exec.Command("/bin/bash", setup)
	command.Dir, command.Env = root, goEnvironment()
	setupOutput := new(limitedOutput)
	command.Stdout, command.Stderr = setupOutput, setupOutput
	result := superviseProcess(ctx, command)
	if result.Status != "passed" || !result.Started || !result.Joined || setupOutput.overflow {
		t.Fatalf("fixture supervisor setup failed: %+v: %s", result, setupOutput.String())
	}
	locks, err := openResourceLocks(resources)
	if err != nil {
		t.Fatal(err)
	}
	machine, err := locks.acquireMachine(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := machine.Close(); err != nil {
			t.Error(err)
		}
	})
	live, err := locks.acquireLive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := live.Close(); err != nil {
			t.Error(err)
		}
	})
	compilerWitness := filepath.Join(controls, "compiler-started")
	compiler := "#!/bin/sh\nprintf 'unexpected compiler\\n' > " + shellQuote(compilerWitness) + "\nexit 97\n"
	if err := os.WriteFile(filepath.Join(controls, "go"), []byte(compiler), 0700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"tests/scripts/bootstrap.go", "core/preview_broken.go"} {
		if err := os.WriteFile(filepath.Join(root, path), []byte("this Go source has a syntax error\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// This path cannot supply credentials. Preview must leave it unopened.
	credentials := filepath.Join(root, "absent-credentials.json")
	environment := filepath.Join(root, "environment.json")
	saveSelection(t, environment, map[string]any{"schema_version": 1, "mode": "live", "provider": "gcp", "participants": map[string]any{
		"reader": map[string]any{"access": map[string]any{"credentials_file": credentials}},
	}})
	budget := filepath.Join(root, "limits.json")
	saveSelection(t, budget, testLimits())
	workflow := filepath.Join(root, "workflow.json")
	saveSelection(t, workflow, workflowFile{SchemaVersion: 1, Name: "broken-source-preview", Profile: "dev", Steps: []workflowStep{
		{ID: "components", Kind: "component-tests", Profile: "dev", Tests: singleTestRequest("TestPreviewRequested/child[1]")},
		{ID: "live", Kind: "run", Suites: []string{"unresolved-suite.json"}, Environment: environment, RecoveryMode: "both", Limits: budget},
	}})
	previewContext, stop := context.WithTimeout(ctx, 10*time.Second)
	defer stop()
	command = exec.Command(filepath.Join(root, "tests/scripts/test"), "plan", "--workflow", workflow)
	command.Dir, command.Env = root, goEnvironment()
	output := new(limitedOutput)
	command.Stdout, command.Stderr = output, output
	result = superviseProcess(previewContext, command)
	if result.Status != "passed" || !result.Started || !result.Joined || output.overflow {
		t.Fatalf("preview compiled, waited for a held resource, or required credentials: %+v: %s", result, output.String())
	}
	var preview workflowPreview
	if err := json.Unmarshal([]byte(output.String()), &preview); err != nil || preview.Kind != "selection_preview" || len(preview.Steps) != 2 || len(preview.Unresolved) == 0 || preview.Steps[1].LimitsConfiguration == nil {
		t.Fatal("preview omitted requested work, configured limits or unresolved facts", err, output.String())
	}
	if _, err := os.Stat(compilerWitness); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("preview started a compiler", err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "tests/.supervisor"))
	if err != nil || len(entries) != 1 || entries[0].Name() != "supervisor" {
		t.Fatal("preview created a bootstrap or runner stage", entries, err)
	}
}

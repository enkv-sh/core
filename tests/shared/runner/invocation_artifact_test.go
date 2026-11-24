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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	catalog "enkv.sh/core/internal/testcatalog"
)

// full_only: false
func TestInvocationSharesActualAssemblyAcrossFocuses(t *testing.T) {
	for _, count := range []int{1, 10} {
		t.Run(fmt.Sprintf("focuses_%d", count), func(t *testing.T) {
			fixture, root, bootstrap := componentRepetitionAssemblyFixture(t)
			var source strings.Builder
			source.WriteString("package core\nimport \"testing\"\n")
			steps := make([]any, count)
			for index := range count {
				name := fmt.Sprintf("TestArtifactFocus%02d", index)
				fmt.Fprintf(&source, "// full_only: false\nfunc %s(t *testing.T) { t.Log(\"selected focus completed\") }\n", name)
				steps[index] = map[string]any{"id": fmt.Sprintf("focus-%02d", index), "kind": "component-tests", "profile": "dev", "tests": singleTestRequest(name)}
			}
			writeLocalGoFixture(t, root, "tests/shared/artifact_focus_fixture_test.go", source.String())
			directory := t.TempDir()
			realGo, err := exec.LookPath("go")
			if err != nil {
				t.Fatal(err)
			}
			commands := filepath.Join(directory, "commands")
			script := "#!/bin/sh\nprintf 'BEGIN\\n' >> " + shellQuote(commands) + "\nprintf '%s\\n' \"$PWD\" \"$@\" >> " + shellQuote(commands) + "\nprintf 'END\\n' >> " + shellQuote(commands) + "\n" + shellQuote(realGo) + " \"$@\"\nstatus=$?\ncompiled=false\nfor argument do [ \"$argument\" != -c ] || compiled=true; done\nif [ \"$status\" -eq 0 ] && [ \"$compiled\" = true ] && [ \"$PWD\" = " + shellQuote(filepath.Join(root, "core")) + " ]; then printf '%s\\n' 'invalid source after compiler joined' > " + shellQuote(filepath.Join(root, "tests/shared/artifact_focus_fixture_test.go")) + "; fi\nexit \"$status\"\n"

			if err := os.WriteFile(filepath.Join(directory, "go"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
			path := filepath.Join(directory, "workflow.json")
			saveSelection(t, path, map[string]any{"schema_version": 1, "name": "shared-artifacts", "execution": map[string]any{"parallel": 1}, "steps": steps})
			ctx, cancel := context.WithTimeout(fixture, 3*time.Minute)
			defer cancel()
			plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: path})
			if err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			var output bytes.Buffer
			prepared, err := prepareWorkflow(ctx, root, bootstrap, plan, &output)
			if prepared != nil {
				defer func() {
					if err := prepared.close(ctx); err != nil {
						t.Error(err)
					}
				}()
			}
			if err != nil {
				t.Fatal("prepare actual focuses", err, output.String())
			}
			before := time.Now()
			dispatch := &artifactDispatchObservation{started: started}
			result, runErr := runPreparedWorkflow(ctx, root, bootstrap, prepared, dispatch)
			if runErr != nil || result.Outcome != "passed" {
				t.Fatal("selected focuses did not complete", runErr, result.Outcome)
			}
			if len(prepared.components) != count {
				t.Fatal("selected focuses did not each acquire their execution owner", len(prepared.components), count)
			}
			binaries := map[string]bool{}
			for _, group := range prepared.components {
				binaries[group.assembled.Binary] = true
			}
			if len(binaries) != 1 {
				t.Fatalf("compatible focuses constructed %d actual assemblies; want 1", len(binaries))
			}
			body, err := os.ReadFile(commands)
			if err != nil {
				t.Fatal(err)
			}
			assemblies, converters, outputs := 0, 0, 0
			for _, block := range strings.Split(string(body), "BEGIN\n")[1:] {
				lines := strings.Split(block, "\n")
				if len(lines) < 3 {
					t.Fatal("incomplete compiler observation")
				}
				if lines[1] == "test" && strings.Contains(block, "\n-c\n") {
					assemblies++
				}
				if lines[1] == "build" && strings.Contains(block, "\ncmd/test2json\n") {
					converters++
				}
				if lines[1] == "build" && strings.Contains(block, "\n./cmd/enkv-output-contract-test\n") {
					outputs++
				}
			}
			if assemblies != 1 || converters != 1 || outputs != 1 {
				t.Fatalf("construction owners: assembly=%d converter=%d output=%d; want one each", assemblies, converters, outputs)
			}
			// A completed invocation build survives subsequent source edits.
			writeLocalGoFixture(t, root, "tests/shared/artifact_focus_fixture_test.go", "invalid source after completed construction")
			borrowed := newPreparedComponentGroup(prepared.binding.context(ctx))
			defer borrowed.cancel()
			reused, reuseErr := borrowed.prepare(root, bootstrap, "dev", []string{"TestArtifactFocus00"}, prepared.binding.source, prepared.binding.toolchain, t.TempDir())
			if reuseErr != nil || !binaries[reused.Binary] {
				t.Fatal("source edit replaced or refused completed executable", reuseErr)
			}
			retainedBytes := int64(0)
			var retainedFiles []os.FileInfo
			owner := invocationArtifactsFrom(prepared.binding.ctx)
			if err := filepath.WalkDir(owner.current.path, func(path string, entry os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if !entry.IsDir() {
					info, err := entry.Info()
					if err != nil {
						return err
					}
					duplicate := false
					for _, earlier := range retainedFiles {
						duplicate = duplicate || os.SameFile(earlier, info)
					}
					if !duplicate {
						retainedBytes += info.Size()
						retainedFiles = append(retainedFiles, info)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			after, readErr := os.ReadFile(commands)
			if readErr != nil || !bytes.Equal(body, after) {
				t.Fatal("borrowing repeated compiler discovery, helper construction or verification", readErr, string(after[len(body):]))
			}
			if dispatch.first == 0 {
				t.Fatal("first selected dispatch was not observed")
			}
			t.Logf("actual focuses=%d preparation=%s first_dispatch=%s execution=%s total=%s retained_bytes=%d assembly_builds=%d converter_builds=%d output_builds=%d", count, before.Sub(started), dispatch.first, time.Since(before), time.Since(started), retainedBytes, assemblies, converters, outputs)
			if path := os.Getenv("ENKV_ARTIFACT_MEASUREMENT"); path != "" {
				file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
				if err != nil {
					t.Fatal(err)
				}
				row := map[string]any{"focuses": count, "preparation_seconds": before.Sub(started).Seconds(), "first_test_dispatch_seconds": dispatch.first.Seconds(), "execution_seconds": time.Since(before).Seconds(), "total_seconds": time.Since(started).Seconds(), "retained_artifact_bytes": retainedBytes, "assembly_builds": assemblies, "converter_builds": converters, "output_builds": outputs, "compiler_commands_before_execution": len(strings.Split(string(body), "BEGIN\n")) - 1, "compiler_commands_after_execution": len(strings.Split(string(after), "BEGIN\n")) - 1, "toolchain": prepared.binding.toolchain, "native": prepared.binding.environment["GOOS"] + "/" + prepared.binding.environment["GOARCH"], "race": plan.Race, "cache": "existing Go cache retained"}
				if err := errors.Join(json.NewEncoder(file).Encode(row), file.Close()); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

type artifactDispatchObservation struct {
	started time.Time
	first   time.Duration
}

func (observation *artifactDispatchObservation) Write(body []byte) (int, error) {
	if observation.first == 0 && strings.HasPrefix(string(body), "Check phase=test scope=") {
		observation.first = time.Since(observation.started)
	}
	return len(body), nil
}

// full_only: false
func TestInvocationArtifactConstructionAndBorrowing(t *testing.T) {
	root := workflowExecutionFixture(t)
	writeLocalGoFixture(t, root, "core/fixture.go", "package core\n")
	parent, cancel := context.WithTimeout(workflowTestContext(t, root), 10*time.Second)
	defer cancel()
	ctx, owner := withInvocationArtifacts(parent)
	defer func() {
		if err := owner.close(context.WithoutCancel(ctx), true); err != nil {
			t.Error(err)
		}
	}()
	var constructions atomic.Int32
	entered, complete := make(chan struct{}), make(chan struct{})
	construct := func(directory string) (string, error) {
		if constructions.Add(1) != 1 {
			return "", errors.New("construction repeated")
		}
		close(entered)
		<-complete
		path := filepath.Join(directory, "built")
		return path, os.WriteFile(path, []byte("completed construction"), 0600)
	}
	type result struct {
		path string
		err  error
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			value, _, err := invocationArtifactValue(ctx, root, "", "controlled", "same", construct)
			results <- result{value, err}
		}()
	}
	select {
	case <-entered:
	case result := <-results:
		t.Fatal("construction did not reach controlled constructor", result.err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	close(complete)
	first, second := <-results, <-results
	if first.err != nil || second.err != nil || first.path != second.path || constructions.Load() != 1 {
		t.Fatal("concurrent consumers did not share construction", first, second)
	}
	failure := errors.New("controlled construction refusal")
	failed := 0
	for range 2 {
		_, _, err := invocationArtifactValue(ctx, root, "", "controlled", "failed", func(string) (string, error) { failed++; return "", failure })
		if !errors.Is(err, failure) {
			t.Fatal("construction refusal lost cause", err)
		}
	}
	if failed != 1 {
		t.Fatal("failed recipe constructed more than once", failed)
	}
	independent, _, err := invocationArtifactValue(ctx, root, "", "controlled", "independent", func(directory string) (string, error) { return directory, nil })
	if err != nil || independent == "" {
		t.Fatal("failed recipe blocked an independent construction", err)
	}
	sealed := filepath.Join(filepath.Dir(first.path), "sealed")
	if err := os.Mkdir(sealed, 0700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(sealed, "plugin")
	if err := os.WriteFile(executable, []byte("shared executable"), 0555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(executable, 0555); err != nil {
		t.Fatal(err)
	}
	retained := filepath.Join(t.TempDir(), "plugin")
	if err := os.Link(executable, retained); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sealed, 0555); err != nil {
		t.Fatal(err)
	}
	releaseFirst, err := owner.borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer releaseFirst(true)
	releaseLast, err := owner.borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer releaseLast(true)
	closed := make(chan error, 1)
	go func() { closed <- owner.close(ctx, true) }()
	for {
		owner.mu.Lock()
		closing := owner.closing
		owner.mu.Unlock()
		if closing {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("artifact owner did not start closing", ctx.Err())
		case <-time.After(processGroupPollInterval):
		}
	}
	releaseFirst(true)
	if _, err := os.Stat(first.path); err != nil {
		t.Fatal("artifact disposed before last borrower joined", err)
	}
	if info, err := os.Stat(sealed); err != nil || info.Mode().Perm() != 0555 {
		t.Fatal("artifact directory mode changed before last borrower joined", err)
	}
	releaseLast(true)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(first.path); !os.IsNotExist(err) {
		t.Fatal("joined invocation retained disposable artifact", err)
	}
	info, err := os.Stat(retained)
	body, readErr := os.ReadFile(retained)
	if err != nil || readErr != nil || info.Mode().Perm() != 0555 || string(body) != "shared executable" {
		t.Fatal("artifact disposal changed a shared executable", err, readErr)
	}
	if _, err := owner.borrow(); err == nil {
		t.Fatal("closed artifact owner accepted borrower")
	}
	t.Run("joined-cleanup-after-parent-cancellation", func(t *testing.T) {
		cleanupContext, stopWork := context.WithCancel(t.Context())
		defer stopWork()
		cleanupContext = context.WithValue(cleanupContext, finalizationTailKey{}, t.Context())
		cleanupContext, cleanupOwner := withInvocationArtifacts(cleanupContext)
		defer func() {
			if err := cleanupOwner.close(context.WithoutCancel(t.Context()), true); err != nil {
				t.Error(err)
			}
		}()
		path, _, err := invocationArtifactValue(cleanupContext, root, "", "controlled", "canceled-parent", func(directory string) (string, error) {
			path := filepath.Join(directory, "built")
			if err := os.WriteFile(path, []byte("joined artifact"), 0444); err != nil {
				return "", err
			}
			return path, os.Chmod(directory, 0555)
		})
		if err != nil {
			t.Fatal(err)
		}
		stopWork()
		if err := cleanupOwner.close(cleanupContext, true); err != nil {
			t.Fatal("parent cancellation prevented joined artifact disposal", err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("joined cleanup retained its artifact", err)
		}
	})
	_, unsettled := withInvocationArtifacts(parent)
	release, err := unsettled.borrow()
	if err != nil {
		t.Fatal(err)
	}
	release(false)
	if err := unsettled.close(ctx, true); err == nil {
		t.Fatal("unjoined consumer permitted artifact disposal")
	}
	if _, err := unsettled.borrow(); err == nil {
		t.Fatal("unjoined consumer permitted new construction or execution")
	}
}

// full_only: false
func TestInvocationSelectsOnlyActualProviderAssemblies(t *testing.T) {
	ctx, root, bootstrap := localLivePreparationFixture(t, "aws")
	writeLocalGoFixture(t, root, "providers/gcp/fixture.go", "package gcp\nimport _ \"enkv.sh/core/contract\"\n")
	writeLocalGoFixture(t, root, "tests/live/providers/gcp/fixture_test.go", "package core\nimport \"testing\"\n// full_only: false\nfunc TestPreparedLocalProvider(t *testing.T) { t.Fatal(\"provider regression must be explicitly selected\") }\n")
	writeLocalGoFixture(t, root, "tests/live/shared/bound_selection_test.go", `package core
import ("encoding/json"; "os"; "testing")
var publicationFixtureExpectations string
// full_only: false
func TestBoundActualSelection(t *testing.T) {
 var linked map[string][2]string
 if err := json.Unmarshal([]byte(publicationFixtureExpectations), &linked); err != nil { t.Fatal(err) }
 expected := os.Getenv("ENKV_BOUND_OUTPUT_COMMAND")
 if len(linked) != 1 || linked[expected][0] == "" || linked[expected][1] == "" { t.Fatal("actual linked output differs", linked, expected) }
}
`)

	target, err := sourcePath(root, "plugins/github-output")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(target); err != nil {
		t.Fatal(err)
	}
	copyPublicModuleKit(t, testRepositoryRoot(t), root, []string{"plugins/github-output"})
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	ctx, owner := withInvocationArtifacts(ctx)
	defer func() {
		if err := owner.close(ctx, true); err != nil {
			t.Error(err)
		}
	}()
	binaries := map[string]bool{}
	for _, selection := range []struct{ provider, scope string }{{"aws", "github-repository"}, {"gcp", "github-repository"}, {"aws", "github-environment"}, {"aws", "github-repository"}} {
		scenario := "publication." + selection.scope + ".plain-secret-lifecycle/plain1_secret1_create_value_inherited_policy_delete"
		schedule, err := catalog.Resolve(catalog.Request{Include: []string{scenario}, Repetitions: 1})
		if err != nil {
			t.Fatal(err)
		}
		configuration := environmentFile{Mode: "live", Provider: selection.provider, GitHubOutputTargets: &githubOutputReference{
			Repository:  &githubOutputTargetReference{Owner: "owner", Repository: "repo", SecretNamePrefix: "TARGET_"},
			Environment: &githubOutputTargetReference{Owner: "owner", Repository: "repo", Environment: "fixture", SecretNamePrefix: "OTHER_"},
		}}
		request := runRequest{Suite: "live", Provider: selection.provider, Profile: "full", Schedule: schedule, environment: &configuration, Resolved: &resolvedRequest{Race: false}}
		prepared, err := prepareSuite(nil, ctx, root, bootstrap, request, io.Discard)
		if prepared != nil {
			defer func() {
				if err := prepared.close(ctx); err != nil {
					t.Error(err)
				}
			}()
		}
		if err != nil {
			var details bytes.Buffer
			if diagnosticErr := writeAssemblyDiagnosticBody(&details, err); diagnosticErr != nil {
				t.Error(diagnosticErr)
			}
			t.Fatal("actual provider selection", selection, err, details.String())
		}
		binaries[prepared.inventory.Binary] = true
		if len(binaries) == 1 {
			if err := os.WriteFile(bootstrap, []byte("invalid config after first actual binding"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		wanted, err := productionOutputBinding("ENKV/OUTPUT/" + strings.ToUpper(selection.scope) + "/v3")
		if err != nil {
			t.Fatal(err)
		}
		linked, err := retainedOutputBindings(prepared.inventory.Closure.OutputArtifacts)
		if err != nil || len(linked) != 1 || linked[0] != wanted || prepared.inventory.Closure.Provider != selection.provider || prepared.inventory.providerSelection != nil {
			t.Fatal("selection used generic or wrong actual binding", selection, linked, err)
		}
		actual, err := buildBoundAssemblyMode(runGoEnvironment, nil, prepared.binding.context(ctx), root, "live", selection.provider, bootstrap, t.TempDir(), false, assemblyBindings{Output: []outputProfileBinding{wanted}})
		if err != nil || actual.Binary != prepared.inventory.Binary {
			t.Fatal("execution binding rebuilt prepared actual executable", err)
		}
		if err := prepared.bindActual(ctx, root, &actual); err != nil {
			t.Fatal(err)
		}
		converter, _, err := prepareTestEventConverter(prepared.binding.context(ctx), root, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		process, results, _, _ := executeComponentChecks(ctx, root, actual.Binary, converter, literalTestSelection("TestBoundActualSelection"), []string{"TestBoundActualSelection"}, environment(workerEnvironment(""), map[string]string{"ENKV_BOUND_OUTPUT_COMMAND": "enkv-output-" + selection.scope}))
		if process.Status != "passed" || !process.Joined || !results.TestsComplete || len(results.Tests) != 1 || results.Tests[0].Name != "TestBoundActualSelection" || results.Tests[0].Outcome != "passed" {
			t.Fatal("actual bound local selection did not pass", process, results)
		}
	}
	if len(binaries) != 3 {
		t.Fatal("provider and output bindings did not create exactly three required assemblies", len(binaries))
	}
	assemblies, outputs := 0, 0
	for _, entry := range owner.artifacts {
		if _, ok := entry.value.(assembly); ok {
			assemblies++
		}
		if value, ok := entry.value.(*outputArtifactClosure); ok {
			outputs++
			binding, err := outputBinding(value.Artifact)
			if err != nil {
				t.Fatal(err)
			}
			if binding.StoredProfileID == "ENKV/OUTPUT/TEST-PROFILE/v3" {
				t.Fatal("generic output child constructed before actual binding")
			}
		}
	}
	if assemblies != 3 || outputs != 2 {
		t.Fatal("actual construction count differs", assemblies, outputs)
	}
}

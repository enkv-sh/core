package main

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

// These literals identify the reviewed finite input set independently of the
// map parser. The abc SHA-256 is the published SHA-256 test vector.
var supervisorFixturePaths = []string{
	"core/go.mod", "core/go.sum", "tests/shared/records/io.go", "tests/shared/records/layout.go", "tests/shared/records/source.go",
	"tests/shared/runner/execution.go", "tests/shared/runner/command_arguments.go", "tests/shared/runner/workflow_file.go", "tests/shared/runner/workflow_preview.go", "tests/shared/runner/workflow_limits.go", "tests/shared/records/live_limits.go", "tests/shared/runner/selection_json.go",
	"tests/shared/runner/process_output.go", "tests/shared/runner/process_environment.go", "tests/shared/runner/process.go", "tests/shared/runner/process_memory.go", "tests/shared/runner/process_memory_darwin.go", "tests/shared/runner/process_memory_darwin_nocgo.go", "tests/shared/runner/process_memory_linux.go", "tests/shared/runner/process_memory_other.go",
	"tests/shared/runner/supervisor_policy.go", "tests/shared/runner/supervisor_control.go", "tests/shared/runner/supervisor_source.go", "tests/shared/runner/supervisor_driver.go",
	"tests/scripts/bootstrap.go", "tests/scripts/setup-supervisor", "tests/scripts/supervisor-sources.tsv", "tests/scripts/test",
	"tests/shared/runner/supervisor_invocation.go", "tests/shared/runner/module_sources.go", "tests/shared/runner/module_sources_generated.go", "tests/shared/runner/source_git.go", "tests/shared/runner/race_policy.go", "tests/shared/runner/resource_locks.go", "tests/shared/runner/tool_directories.go", "tests/shared/runner/invocation_lifetime.go",
}

func supervisorBindingFixture(t *testing.T) (string, fstest.MapFS, supervisorNativeTarget) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Clean(filepath.Join(filepath.Dir(savedWorkflowPath(t, "dev")), "../.."))
	sourceMap, err := os.ReadFile(filepath.Join(source, "tests/scripts/supervisor-sources.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	inputs := fstest.MapFS{}
	for _, name := range supervisorFixturePaths {
		body := []byte("abc")
		if name == "tests/scripts/supervisor-sources.tsv" {
			body = bytes.Clone(sourceMap)
		}
		file := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, body, 0600); err != nil {
			t.Fatal(err)
		}
		inputs[name+".source"] = &fstest.MapFile{Data: bytes.Clone(body), Mode: 0600}
	}
	native, err := currentSupervisorNativeTarget()
	if err != nil {
		t.Fatal(err)
	}
	return root, inputs, native
}

// full_only: false
func TestSupervisorSourceBindingIsExactAndImmutable(t *testing.T) {
	root, inputs, native := supervisorBindingFixture(t)
	binding, err := bindSupervisorSources(inputs, native)
	if err != nil {
		t.Fatal(err)
	}
	want := slices.Clone(supervisorFixturePaths)
	slices.Sort(want)
	var actual []string
	for _, input := range binding.Inputs {
		actual = append(actual, input.Path)
		if input.Path != "tests/scripts/supervisor-sources.tsv" && input.SHA256 != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
			t.Error("source bytes were not bound exactly", input.Path, input.SHA256)
		}
	}
	if !reflect.DeepEqual(actual, want) || binding.Format != 1 || binding.Native != native || len(binding.Digest) != 64 {
		t.Fatal("finite source/native binding differs", actual)
	}
	if err := binding.validate(root, native); err != nil {
		t.Fatal(err)
	}
	// Changing the caller's snapshot cannot rewrite the captured source identity.
	inputs["core/go.mod.source"].Data[0] = 'z'
	if !bytes.Equal(binding.bytes["core/go.mod"], []byte("abc")) {
		t.Fatal("binding borrowed mutable source bytes")
	}
	if err := os.WriteFile(filepath.Join(root, "core/go.mod"), []byte("abd"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := binding.validate(root, native); err != nil {
		t.Error("current source edit invalidated captured binding", err)
	}
	if err := os.WriteFile(filepath.Join(root, "core/go.mod"), []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "core/go.sum")); err != nil {
		t.Fatal(err)
	}
	if err := binding.validate(root, native); err != nil {
		t.Error("current source deletion invalidated captured binding", err)
	}
	for _, change := range []string{"omit", "extra", "symlink", "duplicate_map", "escaping_map", "extra_compiler_target"} {
		t.Run(change, func(t *testing.T) {
			_, inputs, native := supervisorBindingFixture(t)
			switch change {
			case "omit":
				delete(inputs, "core/go.mod.source")
			case "extra":
				inputs["unreviewed.go.source"] = &fstest.MapFile{Data: []byte("abc")}
			case "symlink":
				inputs["core/go.mod.source"].Mode = fs.ModeSymlink
			case "duplicate_map":
				inputs["tests/scripts/supervisor-sources.tsv.source"].Data = append(inputs["tests/scripts/supervisor-sources.tsv.source"].Data, []byte("core/go.mod\tcore/go.mod\n")...)
			case "escaping_map":
				inputs["tests/scripts/supervisor-sources.tsv.source"].Data = append(inputs["tests/scripts/supervisor-sources.tsv.source"].Data, []byte("../outside.go\t-\n")...)
			case "extra_compiler_target":
				inputs["tests/scripts/supervisor-sources.tsv.source"].Data = append(inputs["tests/scripts/supervisor-sources.tsv.source"].Data, []byte("outside.go\tcore/production.go\n")...)
			}
			if _, err := bindSupervisorSources(inputs, native); err == nil {
				t.Error("incomplete/nonclosed embedded sources admitted")
			}
		})
	}
}

// full_only: false
func TestSupervisorPublicationPreservesInstalledArtifactOnRefusal(t *testing.T) {
	for _, mode := range []string{"source_changed", "source_removed", "native_changed", "candidate_missing", "wrong_destination", "passed"} {
		t.Run(mode, func(t *testing.T) {
			root, inputs, native := supervisorBindingFixture(t)
			binding, err := bindSupervisorSources(inputs, native)
			if err != nil {
				t.Fatal(err)
			}
			stage := filepath.Join(root, "tests/.supervisor/setup.fixture")
			if err := os.MkdirAll(stage, 0700); err != nil {
				t.Fatal(err)
			}
			candidate := filepath.Join(stage, "supervisor-candidate")
			destination := filepath.Join(root, "tests/.supervisor/supervisor")
			if err := os.WriteFile(candidate, []byte("new"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(destination, []byte("previous"), 0700); err != nil {
				t.Fatal(err)
			}
			selectedDestination := destination
			switch mode {
			case "source_changed":
				if err := os.WriteFile(filepath.Join(root, "core/go.mod"), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "source_removed":
				if err := os.Remove(filepath.Join(root, "core/go.sum")); err != nil {
					t.Fatal(err)
				}
			case "native_changed":
				native.GOARCH = "wrong-native-target"
			case "candidate_missing":
				if err := os.Remove(candidate); err != nil {
					t.Fatal(err)
				}
			case "wrong_destination":
				selectedDestination = filepath.Join(root, "core/go.mod")
			}
			err = publishSupervisorArtifact(binding, root, candidate, selectedDestination, native)
			accepted := mode == "passed" || mode == "source_changed" || mode == "source_removed"
			if (err == nil) != accepted {
				t.Fatal("publication disposition differs", err)
			}
			body, err := os.ReadFile(destination)
			want := "previous"
			if accepted {
				want = "new"
			}
			if err != nil || string(body) != want {
				t.Fatal("publication changed the previous artifact on refusal", string(body), err)
			}
		})
	}
}

// full_only: false
func TestSupervisorPolicyPreflightUsesSharedGrammar(t *testing.T) {
	root, _, _ := savedSelectionFixture(t)
	for _, args := range [][]string{{"unit", "core/contract"}, {"runner-tests"}, {"plan", "--suite", "fixture", "--environment", "fixture"}} {
		inputs, err := preflightSupervisorExecution(root, args)
		if err != nil || inputs.Policy.Requested.Parallel != nil || inputs.Policy.Resolved != (executionCapacity{Parallel: 4, MemoryLimitMiB: 8192}) {
			t.Fatal("default supervisor capacity differs", args, inputs, err)
		}
	}
	limitsPath := filepath.Join(root, "limits.json")
	saveSelection(t, limitsPath, testLimits())
	limitsReference, err := json.Marshal(limitsPath)
	if err != nil {
		t.Fatal(err)
	}
	workflow := filepath.Join(root, "workflow.json")
	body := []byte(`{"schema_version":1,"name":"capacity","execution":{"parallel":3,"memory_limit_mib":4096},"steps":[{"id":"runner","kind":"runner-tests"},{"id":"unit","kind":"unit","packages":["core"]},{"id":"component","kind":"component-tests","profile":"dev"},{"id":"fuzz","kind":"fuzz","targets":["format"]},{"id":"run","kind":"run","suites":["suite.json"],"environment":"environment.json","additional_providers":{"cloudflare":"generator.json"},"recovery_mode":"both","limits":"limits.json","smoke_policy":"first-selected-point","repetitions":1,"telemetry_config":"telemetry.json","log_level":"warn","scenarios":["state.smoke"]}]}`)
	body = bytes.Replace(body, []byte(`"limits.json"`), limitsReference, 1)
	if err := os.WriteFile(workflow, body, 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"plan", "--workflow", workflow, "--parallel=2"}, {"run", "-workflow=" + workflow, "-memory-limit-mib", "512"}} {
		inputs, err := preflightSupervisorExecution(root, args)
		if err != nil {
			t.Fatal("complete shared workflow schema refused", err)
		}
		if inputs.Configured.Parallel == nil || *inputs.Configured.Parallel != 3 || inputs.Configured.MemoryLimitMiB == nil || *inputs.Configured.MemoryLimitMiB != 4096 {
			t.Fatal("configured policy was lost")
		}
		encoded, err := json.Marshal(struct {
			Execution executionPolicy `json:"execution"`
		}{inputs.Policy})
		if err != nil {
			t.Fatal(err)
		}
		if args[0] == "plan" {
			assertPublicExecutionCapacity(t, encoded, map[string]int{"parallel": 2, "memory_limit_mib": 4096}, 2, 4096)
		} else {
			assertPublicExecutionCapacity(t, encoded, map[string]int{"parallel": 3, "memory_limit_mib": 512}, 3, 512)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "tests/workflows"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tests/workflows/dev.json"), body, 0600); err != nil {
		t.Fatal(err)
	}
	inputs, err := preflightSupervisorExecution(root, []string{"dev", "--parallel=1"})
	if err != nil || inputs.Policy.Resolved != (executionCapacity{Parallel: 1, MemoryLimitMiB: 4096}) {
		t.Fatal("alias resolver differs", inputs, err)
	}
	for _, args := range [][]string{{"plan", "--suite", "--workflow", "--environment", "fixture", "--parallel=2"}, {"plan", "--suite", "--workflow=selection.json", "--environment", "fixture", "--parallel=2"}, {"cleanup", strings.Repeat("a", 32), "--limits", "--parallel=3", "--parallel=2"}, {"unit", "--parallel=2", "core/contract"}} {
		inputs, err := preflightSupervisorExecution(root, args)
		if err != nil || inputs.Configured.Parallel != nil || inputs.Policy.Resolved != (executionCapacity{Parallel: 2, MemoryLimitMiB: 8192}) {
			t.Fatal("shared lexical values changed", args, inputs, err)
		}
	}
	for _, args := range [][]string{{"--parallel=2", "list"}, {"plan", "--workflow", workflow, "--suite", "unwanted"}, {"plan", "--workflow", workflow, "--step=x", "--step=x"}, {"plan", "--workflow", workflow, "--parallel=0"}, {"plan", "--suite", "fixture", "--test", "TestUnknown"}} {
		if _, err := preflightSupervisorExecution(root, args); err == nil {
			t.Error("invalid shared grammar admitted", args)
		}
	}
	if err := os.WriteFile(workflow, []byte(`{"schema_version":1,"name":"capacity","execution":{"parallel":0},"steps":[{"id":"runner","kind":"runner-tests"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := preflightSupervisorExecution(root, []string{"plan", "--workflow", workflow, "--parallel=2"}); err == nil {
		t.Error("CLI concealed invalid configured capacity")
	}
}

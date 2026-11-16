package main

import (
	"context"
	"encoding/json"
	records "enkv.sh/core/internal/testrecords"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// full_only: false
func TestLauncherTransportsAcceptedRacePolicy(t *testing.T) {
	parent, err := filepath.EvalSymlinks("/var/tmp")
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.MkdirTemp(parent, "enkv-race-")
	if err != nil {
		t.Fatal(err)
	}
	root, resources := filepath.Join(fixture, "r"), filepath.Join(fixture, "a")
	settled := true
	t.Cleanup(func() {
		if t.Failed() || !settled {
			t.Log("retained launcher race fixture:", fixture)
			return
		}
		checkSupervisorFixtureResources(t, resources)
		if err := os.RemoveAll(fixture); err != nil {
			t.Error("remove settled launcher race fixture", err)
		}
	})
	initial, setupResources, _, _ := copiedSupervisorSetupFixture(t)
	for _, name := range supervisorFixturePaths {
		body, err := os.ReadFile(filepath.Join(initial, name))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0700); err != nil {
			t.Fatal(err)
		}
	}
	stageParent := supervisorFixtureStageParent(t, root, &settled)
	setup := filepath.Join(root, "tests/scripts/setup-supervisor")
	rewriteSupervisorFixtureResources(t, root, setupResources, resources)

	// Keep the copied bound inputs, including the fixture resource location.
	source := filepath.Clean(filepath.Join(filepath.Dir(savedWorkflowPath(t, "dev")), "../.."))
	copyProductionFile := func(relative string) error {
		destination := filepath.Join(root, relative)
		if _, err := os.Lstat(destination); err == nil {
			return nil
		} else if !os.IsNotExist(err) {
			return err
		}
		body, err := os.ReadFile(filepath.Join(source, relative))
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			return err
		}
		return os.WriteFile(destination, body, 0600)
	}
	for _, directory := range []string{"core", "crypto", "telemetry", "providers", "compositions", "tests/fixtures/output-contract-test", "tests/shared/runner", "tests/shared/records", "tests/shared/catalog"} {
		if err := filepath.WalkDir(filepath.Join(source, directory), func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return err
			}
			relative, err := filepath.Rel(source, path)
			if err != nil {
				return err
			}
			name := entry.Name()
			archive := strings.HasPrefix(filepath.ToSlash(relative), "crypto/testsupport/installedarchive/testdata/")
			if !archive && name != "go.mod" && name != "go.sum" && name != "telemetry_test.mod" && name != "telemetry_test.sum" && name != "LICENSE" && (!strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go")) {
				return nil
			}
			return copyProductionFile(relative)
		}); err != nil {
			t.Fatal("copy maintained launcher build inputs", err)
		}
	}
	var publicModules []string
	for _, module := range moduleSources {
		if module.Sibling != "" {
			publicModules = append(publicModules, module.Selector)
		}
	}
	copyPublicModuleKit(t, source, root, publicModules)
	for _, admission := range records.TestAdmissionOverlays() {
		if err := copyProductionFile(admission.Source); err != nil {
			t.Fatal("copy maintained test admission input", admission.Source, err)
		}
	}
	for _, relative := range []string{"tests/hermetic/hermetic.mod", "tests/hermetic/hermetic.sum", "core/testsupport/nativeprocess/runtime.go.txt", "core/testsupport/nativeprocess/recovery.go.txt", "core/testsupport/nativeprocess/sourcekind.go.txt"} {
		if err := copyProductionFile(relative); err != nil {
			t.Fatal("copy maintained launcher build input", relative, err)
		}
	}
	for _, directory := range []string{"testmain", "testrecords", "testcatalog"} {
		if err := os.MkdirAll(filepath.Join(root, "core/internal", directory), 0700); err != nil {
			t.Fatal(err)
		}
	}
	witnessRoot, workflow, witness := invocationRaceFixture(t, "dev")
	for _, name := range []string{"race.go", "plain.go", "witness_test.go"} {
		body, err := os.ReadFile(filepath.Join(witnessRoot, "telemetry/witness", name))
		if err != nil {
			t.Fatal(err)
		}
		writeLocalGoFixture(t, root, "telemetry/witness/"+name, string(body))
	}
	initializeWorkflowExecutionFixture(t, root)

	// Each copied native root uses its own actual resource owner.
	env := goEnvironment()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	command := exec.Command("/bin/bash", setup)
	command.Dir, command.Env = root, env
	output := new(limitedOutput)
	command.Stdout, command.Stderr = output, output
	result := superviseProcess(ctx, command)
	cancel()
	settled = result.Joined
	if result.Status != "passed" || !result.Started || !result.Joined || output.overflow {
		t.Fatalf("launcher fixture setup did not pass and join: result=%+v output=%s", result, output.String())
	}
	for _, row := range []struct {
		name, profile string
		enable, want  bool
	}{
		{"small-default", "dev", false, false},
		{"full-default", "full", false, false},
		{"full-enabled", "full", true, true},
	} {
		if !settled {
			break
		}
		t.Run(row.name, func(t *testing.T) {
			saveSelection(t, workflow, map[string]any{
				"schema_version": 1, "name": "race-policy", "profile": row.profile,
				"steps": []map[string]any{{"id": "witness", "kind": "unit", "packages": []string{"telemetry/witness"}}},
			})
			if err := os.Remove(witness); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			args := []string{filepath.Join(root, "tests/scripts/test"), "run", "--workflow", workflow, "--step", "witness", "--package", "telemetry/witness", "--test", "TestParent/child", "--parallel=1", "--memory-limit-mib=2048"}
			if row.enable {
				args = append(args, "--race")
			}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
			defer cancel()
			command := exec.Command("/bin/sh", args...)
			command.Dir, command.Env = root, env
			output := new(limitedOutput)
			command.Stdout, command.Stderr = output, output
			result := superviseProcess(ctx, command)
			settled = settled && result.Joined
			if result.Status != "passed" || !result.Started || !result.Joined || output.overflow {
				t.Fatalf("outer evidence invocation did not pass and join: result=%+v output=%s", result, output.String())
			}
			if !errors.Is(syscall.Kill(-command.Process.Pid, 0), syscall.ESRCH) {
				settled = false
				t.Fatal("outer evidence process group remains present or uncertain")
			}
			checkSupervisorFixtureResources(t, resources)
			checkSupervisorInvocationStages(t, stageParent)
			body, err := os.ReadFile(witness)
			if err != nil {
				t.Fatal("selected compiled test did not publish its mode", err)
			}
			var observed invocationRaceObservation
			if err := json.Unmarshal(body, &observed); err != nil {
				t.Fatal(err)
			}
			wantOptions := ""
			if row.want {
				wantOptions = raceOptions
			}
			if observed.Race != row.want || observed.GORACE != wantOptions || observed.Test != "TestParent/child" {
				t.Fatalf("selected compiled mode differs: got %+v want race=%t GORACE=%q", observed, row.want, wantOptions)
			}

		})
	}
}

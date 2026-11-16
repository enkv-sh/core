package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	records "enkv.sh/core/internal/testrecords"
)

type workflowBigProgress struct {
	output   io.Writer
	ready    chan<- string
	step     string
	reported bool
}

func (writer *workflowBigProgress) Write(body []byte) (int, error) {
	if !writer.reported && bytes.HasPrefix(body, []byte("Check phase=test scope=")) {
		writer.reported = true
		writer.ready <- writer.step
	}
	return writer.output.Write(body)
}

// Both rows are empty controlled artifact fixtures. They qualify process
// isolation across workflow members, not a Product maximum or cloud effect.
// full_only: false
func TestWorkflowBigProcessBarrierCoversDistinctComponentAndAssemblySteps(t *testing.T) {
	for _, kind := range []string{"component", "provider"} {
		t.Run(kind, func(t *testing.T) {
			root := assemblyGroupExecutionRoot(t)
			controls := t.TempDir()
			t.Setenv("ENKV_WORKFLOW_BIG_CONTROLS", controls)
			var flags []string
			var values map[string]assembly
			inventory := []string{"TestBig", "TestNormal"}
			if kind == "component" {
				inventory = append(ordinaryMemoryTestInventory(), maximumCapacityComponent, "TestBig", "TestNormal")
				classifications := componentProfileFixtureClassifications(inventory)
				for index := range classifications {
					if classifications[index].Name == "TestBig" {
						value := true
						classifications[index].FullOnly = &value
						classifications[index].Exclusive = true
					}
				}
				flags = componentMetadataBuildFlags(t, root, classifications)
			} else {
				fixture, bootstrap, build := overlayFixture(t)
				root = fixture
				writeLocalGoFixture(t, root, "tests/shared/process_fixture_test.go", "package core\n// full_only: false\nfunc TestFreshProcessChild() {}\n")
				writeLocalGoFixture(t, root, "tests/live/runner/worker_test.go", "package core\n// full_only: false\nfunc TestLiveInventoryFreshProcess() {}\n")
				writeLocalGoFixture(t, root, "tests/live/providers/aws/provider_test.go", "package core\n// full_only: false\nfunc TestNormal() {}\n")
				writeLocalGoFixture(t, root, "tests/live/providers/gcp/provider_test.go", "package core\n// full_only: true\n// exclusive: true\nfunc TestBig() {}\n")
				initializeWorkflowExecutionFixture(t, root)
				values = map[string]assembly{}
				for _, provider := range []string{"gcp", "aws"} {
					directory := filepath.Join(build, provider)
					if err := os.Mkdir(directory, 0700); err != nil {
						t.Fatal(err)
					}
					overlay, err := buildOverlay(root, "live", provider, bootstrap, directory)
					if err != nil {
						t.Fatal(err)
					}
					digest, err := assemblyFileSHA256(overlay)
					if err != nil {
						t.Fatal(err)
					}
					values[provider] = assembly{root: root, buildFlags: []string{"-overlay=" + overlay}, Closure: assemblyClosure{Suite: "live", Provider: provider, OverlaySHA256: digest}}
				}
			}
			script := `#!/bin/sh
set -eu
case "$*" in *-test.list=^Test*) printf '%s\n' ` + strings.Join(inventory, " ") + `; exit 0;; esac
key=''
for argument do
 case "$argument" in
  '-test.run=^TestBig$') key=TestBig ;;
  '-test.run=^TestNormal$') key=TestNormal ;;
 esac
done
if [ -z "$key" ]; then
 printf 'controlled fixture refused selector:' >&2
 printf ' %s' "$@" >&2
 printf '\n' >&2
 exit 72
fi
printf '%s\n' "$@" > "$ENKV_WORKFLOW_BIG_CONTROLS/$key.arguments"
printf '%s\n' "$$" > "$ENKV_WORKFLOW_BIG_CONTROLS/$key.pending"
mv "$ENKV_WORKFLOW_BIG_CONTROLS/$key.pending" "$ENKV_WORKFLOW_BIG_CONTROLS/$key.pid"
peer=TestBig
if [ "$key" = TestBig ]; then peer=TestNormal; fi
if [ -f "$ENKV_WORKFLOW_BIG_CONTROLS/$peer.pid" ]; then
 read -r other < "$ENKV_WORKFLOW_BIG_CONTROLS/$peer.pid"
 if kill -0 "$other" 2>/dev/null; then
  printf 'self=%s pid=%s peer=%s pid=%s\n' "$key" "$$" "$peer" "$other" > "$ENKV_WORKFLOW_BIG_CONTROLS/collision.$key"
 fi
fi
while [ ! -f "$ENKV_WORKFLOW_BIG_CONTROLS/$key.release" ]; do sleep 0.01; done
printf '%s\n' "=== RUN   $key" "--- PASS: $key (0.01s)" PASS
`
			binary := filepath.Join(root, "controlled-components")
			if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			if kind == "provider" {
				// Each artifact lists exactly its own provider root and shared helpers.
				for provider, value := range values {
					rootName := "TestNormal"
					if provider == "gcp" {
						rootName = "TestBig"
					}
					body := strings.Replace(script, strings.Join(inventory, " "), "TestFreshProcessChild TestLiveInventoryFreshProcess "+rootName, 1)
					directory := filepath.Dir(strings.TrimPrefix(value.buildFlags[0], "-overlay="))
					value.Binary = filepath.Join(directory, "controlled-components")
					if err := os.WriteFile(value.Binary, []byte(body), 0700); err != nil {
						t.Fatal(err)
					}
					digest, err := assemblyFileSHA256(value.Binary)
					if err != nil {
						t.Fatal(err)
					}
					value.Closure.BinarySHA256 = digest
					bindAssemblyFailureSources(t, &value, directory)
					values[provider] = value
				}
			}

			policy := executionPolicy{Resolved: executionCapacity{Parallel: 4, MemoryLimitMiB: 3072}}
			plan := workflowPlan{Execution: policy, SchemaVersion: 1, Name: "shared-big", Profile: "full"}
			if kind == "component" {
				plan.Steps = []resolvedWorkflowStep{{ID: "big", Kind: "component-tests", Profile: "full", ParallelGroup: "controlled", Selected: true, Tests: singleTestRequest("TestBig"), Focus: &componentFocus{Tests: singleTestRequest("TestBig")}}, {ID: "normal", Kind: "component-tests", Profile: "full", ParallelGroup: "controlled", Selected: true, Tests: singleTestRequest("TestNormal"), Focus: &componentFocus{Tests: singleTestRequest("TestNormal")}}}
			} else {
				plan.Steps = []resolvedWorkflowStep{{ID: "gcp", Kind: "assembly-checks", Responsibility: "gcp", ParallelGroup: "controlled", Selected: true}, {ID: "aws", Kind: "assembly-checks", Responsibility: "aws", ParallelGroup: "controlled", Selected: true}}
			}
			var converter preparedTestEventConverter
			if kind == "component" {
				converter = testEventConverterFixture(t, root)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			ready := make(chan string, 2)
			done := make(chan assemblyGroupCompletion, 1)
			var output bytes.Buffer
			go func() {
				defer close(done)
				result, err := executeWorkflow(ctx, root, plan, &output, nil, nil, func(child context.Context, step resolvedWorkflowStep, out io.Writer, _ string) (workflowStepExecution, error) {
					writer := &workflowBigProgress{output: out, ready: ready, step: step.ID}
					if kind == "component" {
						process, _, stdout, stderr := executeFixtureProfileComponentChecks(t, nil, child, root, binary, converter, flags, os.Environ(), "full", step.Focus.Tests, executionCapacityFromContext(child).Parallel, writer, nil)
						if process.Status != "passed" || !process.Joined {
							failure := &toolFailure{operation: "controlled component", process: process}
							if process.Joined {
								failure.stdout, failure.stderr, failure.overflow = stdout.Bytes(), stderr.Bytes(), stdout.overflow || stderr.overflow
							}
							return workflowStepExecution{}, errors.Join(failure, writeAssemblyDiagnosticBody(writer, failure))
						}
						return workflowStepExecution{}, nil
					}
					value := values[step.Responsibility]
					request := "TestNormal"
					if step.Responsibility == "gcp" {
						request = "TestBig"
					}
					err := checkLiveAssemblySelection(child, root, controls, &value, "full", false, request, records.Source{Revision: strings.Repeat("a", 40)}, "go1.27.0", writer)
					return workflowStepExecution{}, errors.Join(err, writeAssemblyDiagnosticBody(writer, err))
				})
				done <- assemblyGroupCompletion{result, err}
			}()
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					t.Error("controlled workflow processes did not settle")
				}
			})
			for range 2 {
				select {
				case <-ready:
				case result := <-done:
					t.Fatal("controlled artifact did not reach dispatch", result.err, output.String())
				case <-ctx.Done():
					t.Fatal("controlled artifact preparation did not complete", ctx.Err())
				}
			}
			tick := time.NewTicker(5 * time.Millisecond)
			defer tick.Stop()
			pidDetails := func(paths []string) []string {
				var details []string
				for _, path := range paths {
					body, err := os.ReadFile(path)
					details = append(details, fmt.Sprintf("%s pid=%s read_error=%v", filepath.Base(path), strings.TrimSpace(string(body)), err))
				}
				return details
			}
			var first string
			for {
				paths, err := filepath.Glob(filepath.Join(controls, "*.pid"))
				if err != nil {
					t.Fatal(err)
				}
				if len(paths) > 1 {
					t.Fatal("Big process overlapped a distinct workflow member", pidDetails(paths))
				}
				if len(paths) == 1 {
					first = paths[0]
					break
				}
				select {
				case <-tick.C:
				case <-ctx.Done():
					t.Fatal("no actual controlled process entered", ctx.Err())
				case result := <-done:
					t.Fatal("workflow ended before controlled admission", result.err, output.String())
				}
			}
			window := time.NewTimer(30 * time.Millisecond)
		held:
			for {
				paths, err := filepath.Glob(filepath.Join(controls, "*.pid"))
				if err != nil || len(paths) != 1 {
					t.Fatal("Big process overlapped while peer was dispatch-ready", pidDetails(paths), err)
				}
				select {
				case <-tick.C:
				case <-window.C:
					break held
				}
			}
			if err := os.WriteFile(strings.TrimSuffix(first, ".pid")+".release", nil, 0600); err != nil {
				t.Fatal(err)
			}
			var second string
			for {
				paths, err := filepath.Glob(filepath.Join(controls, "*.pid"))
				if err != nil {
					t.Fatal(err)
				}
				if len(paths) == 2 {
					for _, path := range paths {
						if path != first {
							second = path
						}
					}
					break
				}
				select {
				case <-tick.C:
				case <-ctx.Done():
					t.Fatal("queued controlled peer did not enter", ctx.Err())
				case result := <-done:
					t.Fatal("workflow ended before both members", result.err, output.String())
				}
			}
			readPID := func(path string) int {
				t.Helper()
				body, err := os.ReadFile(path)
				pid, parseErr := strconv.Atoi(strings.TrimSpace(string(body)))
				if err != nil || parseErr != nil || pid <= 0 {
					t.Fatal("invalid controlled PID", err, parseErr, pid)
				}
				return pid
			}
			firstPID := readPID(first)
			if probe := syscall.Kill(firstPID, 0); !errors.Is(probe, syscall.ESRCH) {
				t.Fatal("next controlled process started before physical predecessor join", probe)
			}
			if err := os.WriteFile(strings.TrimSuffix(second, ".pid")+".release", nil, 0600); err != nil {
				t.Fatal(err)
			}
			completion := awaitAssemblyGroupValue(t, ctx, done)
			if completion.err != nil || completion.result.Outcome != "passed" || len(completion.result.Steps) != 2 {
				t.Fatal("controlled workflow did not retain both members", completion.err, output.String())
			}
			for _, step := range completion.result.Steps {
				if step.Outcome != "passed" {
					t.Error("controlled member did not pass", fmt.Sprint(step))
				}
			}
			collisions, collisionErr := filepath.Glob(filepath.Join(controls, "collision.*"))
			if collisionErr != nil || len(collisions) != 0 {
				t.Fatal("process retained a durable Big overlap observation", pidDetails(collisions), pidDetails([]string{first, second}), collisionErr)
			}
			for _, name := range []string{"TestBig", "TestNormal"} {
				body, err := os.ReadFile(filepath.Join(controls, name+".arguments"))
				if err != nil {
					t.Fatal(err)
				}
				var parallel []string
				for _, arg := range strings.Split(strings.TrimSpace(string(body)), "\n") {
					if strings.HasPrefix(arg, "-test.parallel=") {
						parallel = append(parallel, arg)
					}
				}
				want := "-test.parallel=1"
				if kind == "provider" && name == "TestNormal" {
					want = "-test.parallel=2"
				}
				if len(parallel) != 1 || parallel[0] != want {
					t.Fatal("controlled process lost its Big/assigned inner allowance", name, parallel, want)
				}
			}
			if pid := readPID(second); !errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
				t.Fatal("controlled peer survived workflow join", pid)
			}
		})
	}
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func assertPublicExecutionCapacity(t *testing.T, body []byte, requested map[string]int, parallel, memory int) {
	t.Helper()
	var public map[string]json.RawMessage
	if err := json.Unmarshal(body, &public); err != nil {
		t.Fatal("public output is not JSON", err)
	}
	var execution map[string]json.RawMessage
	if err := json.Unmarshal(public["execution"], &execution); err != nil || len(execution) != 2 {
		t.Fatalf("public execution requires requested and resolved: %s; error %v", public["execution"], err)
	}
	var actualRequested, actualResolved map[string]int
	if err := json.Unmarshal(execution["requested"], &actualRequested); err != nil {
		t.Fatal("requested execution fields are absent or invalid", err)
	}
	if err := json.Unmarshal(execution["resolved"], &actualResolved); err != nil {
		t.Fatal("resolved execution fields are absent or invalid", err)
	}
	if actualRequested == nil || !reflect.DeepEqual(actualRequested, requested) {
		t.Fatalf("requested execution = %#v, want %#v", actualRequested, requested)
	}
	wantResolved := map[string]int{"parallel": parallel, "memory_limit_mib": memory}
	if !reflect.DeepEqual(actualResolved, wantResolved) {
		t.Fatalf("resolved execution = %#v, want %#v", actualResolved, wantResolved)
	}
	var steps []map[string]json.RawMessage
	if raw, ok := public["steps"]; ok {
		if err := json.Unmarshal(raw, &steps); err != nil {
			t.Fatal(err)
		}
		for _, step := range steps {
			if _, present := step["parallelism"]; present {
				t.Fatal("public step retains a second scheduling limit")
			}
		}
	}
}

// full_only: false
func TestWorkflowExecutionCapacity(t *testing.T) {
	type capacityCase struct {
		name, execution, stepFields string
		flags                       []string
		requested                   map[string]int
		parallel, memory            int
		refused                     bool
	}
	cases := []capacityCase{
		{name: "defaults", requested: map[string]int{}, parallel: 4, memory: 8192},
		{name: "empty_execution", execution: `{}`, requested: map[string]int{}, parallel: 4, memory: 8192},
		{name: "workflow_parallel_one", execution: `{"parallel":1}`, requested: map[string]int{"parallel": 1}, parallel: 1, memory: 8192},
		{name: "workflow_parallel_two", execution: `{"parallel":2}`, requested: map[string]int{"parallel": 2}, parallel: 2, memory: 8192},
		{name: "workflow_parallel_three", execution: `{"parallel":3}`, requested: map[string]int{"parallel": 3}, parallel: 3, memory: 8192},
		{name: "workflow_parallel_four", execution: `{"parallel":4}`, requested: map[string]int{"parallel": 4}, parallel: 4, memory: 8192},
		{name: "workflow_memory_one", execution: `{"memory_limit_mib":1}`, requested: map[string]int{"memory_limit_mib": 1}, parallel: 4, memory: 1},
		{name: "workflow_memory_maximum", execution: `{"memory_limit_mib":24576}`, requested: map[string]int{"memory_limit_mib": 24576}, parallel: 4, memory: 8192},
		{name: "cli_overrides_parallel_keeps_memory", execution: `{"parallel":2,"memory_limit_mib":512}`, flags: []string{"--parallel", "3"}, requested: map[string]int{"parallel": 3, "memory_limit_mib": 512}, parallel: 3, memory: 512},
		{name: "cli_overrides_memory_keeps_parallel", execution: `{"parallel":2,"memory_limit_mib":512}`, flags: []string{"--memory-limit-mib=1024"}, requested: map[string]int{"parallel": 2, "memory_limit_mib": 1024}, parallel: 2, memory: 1024},
		{name: "cli_only_both", flags: []string{"--parallel=4", "--memory-limit-mib", "1"}, requested: map[string]int{"parallel": 4, "memory_limit_mib": 1}, parallel: 4, memory: 1},
		{name: "execution_null", execution: `null`, refused: true},
		{name: "parallel_zero", execution: `{"parallel":0}`, refused: true},
		{name: "parallel_negative", execution: `{"parallel":-1}`, refused: true},
		{name: "parallel_over_maximum", execution: `{"parallel":5}`, refused: true},
		{name: "parallel_fraction", execution: `{"parallel":1.5}`, refused: true},
		{name: "parallel_null", execution: `{"parallel":null}`, refused: true},
		{name: "memory_zero", execution: `{"memory_limit_mib":0}`, refused: true},
		{name: "memory_negative", execution: `{"memory_limit_mib":-1}`, refused: true},
		{name: "memory_over_maximum", execution: `{"memory_limit_mib":24577}`, refused: true},
		{name: "memory_fraction", execution: `{"memory_limit_mib":1.5}`, refused: true},
		{name: "memory_null", execution: `{"memory_limit_mib":null}`, refused: true},
		{name: "unknown_execution_field", execution: `{"lane":2}`, refused: true},
		{name: "removed_lanes_execution_field", execution: `{"lanes":2}`, refused: true},
		{name: "duplicate_execution_field", execution: `{"parallel":2,"parallel":3}`, refused: true},
		{name: "invalid_workflow_not_hidden_by_cli", execution: `{"parallel":0}`, flags: []string{"--parallel=2"}, refused: true},
		{name: "cli_parallel_zero", flags: []string{"--parallel=0"}, refused: true},
		{name: "cli_parallel_negative", flags: []string{"--parallel=-1"}, refused: true},
		{name: "cli_parallel_over_maximum", flags: []string{"--parallel=5"}, refused: true},
		{name: "cli_parallel_fraction", flags: []string{"--parallel=1.5"}, refused: true},
		{name: "cli_parallel_null", flags: []string{"--parallel=null"}, refused: true},
		{name: "cli_parallel_duplicate", flags: []string{"--parallel=2", "--parallel", "2"}, refused: true},
		{name: "cli_memory_zero", flags: []string{"--memory-limit-mib=0"}, refused: true},
		{name: "cli_memory_negative", flags: []string{"--memory-limit-mib=-1"}, refused: true},
		{name: "cli_memory_over_maximum", flags: []string{"--memory-limit-mib=24577"}, refused: true},
		{name: "cli_memory_fraction", flags: []string{"--memory-limit-mib=1.5"}, refused: true},
		{name: "cli_memory_null", flags: []string{"--memory-limit-mib=null"}, refused: true},
		{name: "cli_memory_duplicate", flags: []string{"--memory-limit-mib=512", "--memory-limit-mib", "512"}, refused: true},
		// Per-step capacity would create a second independent limit.
		{name: "superseded_step_parallelism", stepFields: `,"parallelism":2`, refused: true},
		{name: "superseded_step_parallelism_with_execution", execution: `{"parallel":2}`, stepFields: `,"parallelism":2`, refused: true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			root, _, _ := savedSelectionFixture(t)
			path := filepath.Join(root, "workflow.json")
			execution := ""
			if test.execution != "" {
				execution = `,"execution":` + test.execution
			}
			body := fmt.Sprintf(`{"schema_version":1,"name":"capacity"%s,"steps":[{"id":"components","kind":"component-tests","profile":"dev"%s}]}`, execution, test.stepFields)
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			var firstPlan []byte
			for _, command := range []string{"plan", "run"} {
				args := append([]string{command, "--workflow", path}, test.flags...)
				request, err := workflowArguments(args)
				var plan workflowPlan
				if err == nil {
					plan, err = resolveWorkflow(withExecutionCapacity(t.Context(), defaultExecutionPolicy()), root, request)
				}
				if test.refused {
					if err == nil {
						t.Fatalf("%s accepted invalid capacity", command)
					}
					continue
				}
				if err != nil {
					t.Fatalf("%s refused valid capacity: %v", command, err)
				}
				var output bytes.Buffer
				if err := json.NewEncoder(&output).Encode(plan); err != nil {
					t.Fatal(err)
				}
				assertPublicExecutionCapacity(t, output.Bytes(), test.requested, test.parallel, test.memory)
				bigMemory := 24576
				if requested, present := test.requested["memory_limit_mib"]; present {
					bigMemory = requested
				}
				big := executionForClass(plan.Execution, true)
				bigBody, err := json.Marshal(struct {
					Execution executionPolicy `json:"execution"`
				}{big})
				if err != nil {
					t.Fatal(err)
				}
				assertPublicExecutionCapacity(t, bigBody, test.requested, test.parallel, bigMemory)
				if firstPlan == nil {
					firstPlan = append([]byte(nil), output.Bytes()...)
				} else if !bytes.Equal(firstPlan, output.Bytes()) {
					t.Fatal("plan and run resolved different public capacity or selection")
				}
				// Public workflow results must retain the policy on standard
				// JSON persistence. This does not execute a workflow, create a
				// result, or claim executeWorkflow's copy path is qualified.
				var persisted workflowResult
				if err := json.Unmarshal(output.Bytes(), &persisted); err != nil {
					t.Fatal(err)
				}
				persistedBody, err := json.Marshal(persisted)
				if err != nil {
					t.Fatal(err)
				}
				assertPublicExecutionCapacity(t, persistedBody, test.requested, test.parallel, test.memory)
			}
			if _, err := os.Stat(filepath.Join(root, "tests")); !os.IsNotExist(err) {
				t.Fatal("capacity resolution created execution state")
			}
		})
	}
}

// full_only: false
func TestRemovedLanesCommandInputsRefused(t *testing.T) {
	root, suite, environment := savedSelectionFixture(t)
	workflow := filepath.Join(root, "workflow.json")
	if err := os.WriteFile(workflow, []byte(`{"schema_version":1,"name":"removed-lanes","steps":[{"id":"components","kind":"component-tests","profile":"dev"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []struct {
		name string
		args []string
		want string
	}{
		{"plan-workflow", []string{"plan", "--workflow", workflow}, "unknown plan/run flag"},
		{"run-workflow", []string{"run", "--workflow", workflow}, "unknown plan/run flag"},
		{"plan-direct", []string{"plan", "--suite", suite, "--environment", environment}, "unknown plan/run flag"},
		{"run-direct", []string{"run", "--suite", suite, "--environment", environment}, "unknown plan/run flag"},
		{"run-resume", []string{"run", "--workflow", workflow, "--resume", strings.Repeat("a", 32)}, "unknown plan/run flag"},
		{"cleanup", []string{"cleanup", strings.Repeat("a", 32), "--limits", "new-limits.json"}, "cleanup requires a run ID and new limits"},
		{"unit", []string{"unit"}, "flag provided but not defined: -lanes"},
		{"list", []string{"list"}, "flag provided but not defined: -lanes"},
	} {
		for _, form := range []string{"equals", "separate"} {
			t.Run(command.name+"/"+form, func(t *testing.T) {
				args := append([]string{}, command.args...)
				if form == "equals" {
					args = append(args, "--lanes=2")
				} else {
					args = append(args, "--lanes", "2")
				}
				admissions := 0
				ctx := context.WithValue(withRacePolicy(t.Context(), false), rootAdmitterContextKey{}, rootAdmitter(func(ctx context.Context, _ rootAdmission) (context.Context, error) {
					admissions++
					return ctx, errors.New("removed option reached root admission")
				}))
				var output bytes.Buffer
				err := runCommand(ctx, root, "must-not-build", args, &output)
				observed := output.String()
				observationAllowed := args[0] == "run" || args[0] == "cleanup" || args[0] == "unit"
				if err == nil || err.Error() != command.want || admissions != 0 ||
					observed != "" && (!observationAllowed || observed != "Source observation incomplete; prepared builds remain in use\n") {
					t.Fatalf("removed lanes reached preparation/admission or failed outside argument parsing: error=%v admissions=%d output=%q", err, admissions, output.String())
				}
				if _, err := os.Stat(filepath.Join(root, "tests")); !os.IsNotExist(err) {
					t.Fatal("removed option created execution state", err)
				}
			})
		}
	}
}

// full_only: false
func TestExecutionArgumentsPreserveCommandBoundaries(t *testing.T) {
	root, suite, environment := savedSelectionFixture(t)
	path := filepath.Join(root, "workflow.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"name":"capacity","execution":{"parallel":3},"steps":[{"id":"runner","kind":"runner-tests"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []struct {
		name string
		args []string
	}{
		{"workflow", []string{"plan", "--workflow", path}},
		{"direct", []string{"plan", "--suite", suite, "--environment", environment}},
	} {
		t.Run(command.name, func(t *testing.T) {
			var output bytes.Buffer
			// This test owns parsing and selection. Compiled plan preparation is
			// covered by the prepared workflow and suite owner tests.
			parsed, err := parsePlanRunArguments(append(command.args, "--parallel=2"))
			if err != nil {
				t.Fatal("command-first capacity refused", err)
			}
			if command.name == "workflow" {
				request, err := workflowRequestFromArguments(parsed)
				if err != nil {
					t.Fatal(err)
				}
				plan, err := resolveWorkflow(withExecutionCapacity(t.Context(), defaultExecutionPolicy()), root, request)
				if err != nil {
					t.Fatal(err)
				}
				if err := json.NewEncoder(&output).Encode(plan); err != nil {
					t.Fatal(err)
				}
			} else {
				request, err := savedRequestFromArguments(parsed)
				if err != nil {
					t.Fatal(err)
				}
				if err := json.NewEncoder(&output).Encode(runRecord{Resolved: request.Resolved, Execution: recordExecutionPolicy(request.execution), EffectiveTelemetry: request.effectiveTelemetry}); err != nil {
					t.Fatal(err)
				}
			}
			assertPublicExecutionCapacity(t, output.Bytes(), map[string]int{"parallel": 2}, 2, 8192)
			for _, prefix := range []string{"--parallel=2", "--memory-limit-mib=512"} {
				output.Reset()
				args := append([]string{prefix}, command.args...)
				if err := runCommand(t.Context(), root, "must-not-build", args, &output); err == nil || output.Len() != 0 {
					t.Error("accepted a capacity flag before the command", prefix)
				}
			}
		})
	}
	t.Run("literal_workflow_flag_value", func(t *testing.T) {
		for _, path := range []string{"--parallel=2", "--memory-limit-mib=512"} {
			request, err := workflowArguments([]string{"plan", "--workflow", path, "--parallel=3"})
			if err != nil || request.Path != path || request.Execution.Parallel == nil || *request.Execution.Parallel != 3 || request.Execution.MemoryLimitMiB != nil {
				t.Error("workflow filename was consumed as execution policy", path, err)
			}
		}
	})
	t.Run("literal_suite_flag_value", func(t *testing.T) {
		t.Chdir(root)
		body, err := os.ReadFile(suite)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"--workflow", "--workflow=selection.json", "-workflow=selection.json", "--step=runner", "--parallel=4"} {
			if err := os.WriteFile(name, body, 0600); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			args := []string{"plan", "--suite", name, "--environment", environment, "--parallel=2"}
			parsed, err := parsePlanRunArguments(args)
			if err != nil || parsed.workflowPresent || len(parsed.suites) != 1 || parsed.suites[0] != name {
				t.Error("suite filename changed command mode", name, err)
				continue
			}
			request, err := savedRequestFromArguments(parsed)
			if err != nil {
				t.Error("literal suite filename was refused", name, err)
				continue
			}
			if err := json.NewEncoder(&output).Encode(runRecord{Resolved: request.Resolved, Execution: recordExecutionPolicy(request.execution), EffectiveTelemetry: request.effectiveTelemetry}); err != nil {
				t.Fatal(err)
			}
			assertPublicExecutionCapacity(t, output.Bytes(), map[string]int{"parallel": 2}, 2, 8192)
		}
	})
}

// full_only: false
func TestComponentGroupsKeepInventoryIndependentOfDiscoveryOrder(t *testing.T) {
	names := []string{
		"TestSubstantialA",
		"TestSubstantialB",
		"TestSubstantialC",
		"TestSubstantialD",
	}
	for i := 0; i < 40; i++ {
		names = append(names, fmt.Sprintf("TestNewOrdinary%02d", i))
	}
	for _, profile := range []string{"dev", "full"} {
		inventory := slices.Clone(names)
		if profile == "full" {
			inventory = append(inventory, maximumCapacityComponent,
				"TestSuccessionJointMaximumMemory", "TestGeneratedRecordPrefixPerformance",
				"TestGeneratedPurpose3CleanupAtJointMemberAndGenerationMaximum",
				"TestGeneratedMaximumDeclarationReservationMemory")
		}
		before := slices.Clone(inventory)
		groups, err := componentGroupsForProfile(inventory, componentProfileFixtureClassifications(inventory), profile, 4, componentEstimates)
		if err != nil || !slices.Equal(before, inventory) || profile == "dev" && len(groups) != 4 {
			t.Fatal("group planning changed input or failed", groups, err)
		}
		slices.Reverse(inventory)
		reversed, err := componentGroupsForProfile(inventory, componentProfileFixtureClassifications(inventory), profile, 4, componentEstimates)
		if err != nil || !reflect.DeepEqual(groups, reversed) {
			t.Fatal("discovery order changes group membership", err)
		}
		seen := map[string]bool{}
		for _, group := range groups {
			for _, name := range group.Tests {
				if seen[name] {
					t.Fatal("test was grouped twice", name)
				}
				seen[name] = true
			}
		}
		if len(seen) != len(inventory) {
			t.Fatal("group planning dropped a selected test")
		}
	}
}

// full_only: false
func TestComponentGroupsDistributeNormalWorkWithoutChangingClasses(t *testing.T) {
	estimates := componentEstimates
	t.Cleanup(func() { componentEstimates = estimates })
	componentEstimates = map[string]float64{
		maximumCapacityComponent: 10,
		"TestFullOnlyMeasured":   20,
	}
	longFull := "Test" + strings.Repeat("F", 251)
	longOrdinary := "Test" + strings.Repeat("O", 251)
	fullOnlyExtra := []string{"TestFullOnlyMeasured", "TestFullOnlyUnmeasured", "TestFullOnlyCaseA", "TestFullOnlyCasea", longFull}
	inventory := append(ordinaryMemoryTestInventory(), maximumCapacityComponent, "TestNewOrdinary")
	inventory = append(inventory, fullOnlyExtra...)
	inventory = append(inventory, "TestExplicitExclusive")
	for _, name := range []string{"TestLargeOrdinaryCaseA", "TestLargeOrdinaryCasea", longOrdinary} {
		inventory = append(inventory, name)
		componentEstimates[name] = componentCheckTimeout.Seconds() + 1
	}
	for i := 0; i < 8; i++ {
		name := fmt.Sprintf("TestLargeOrdinary%02d", i)
		inventory = append(inventory, name)
		// Scheduling weights do not establish a need for process isolation.
		componentEstimates[name] = componentCheckTimeout.Seconds() + 1
	}
	classifications := func(names []string) []testClassification {
		result := componentProfileFixtureClassifications(names)
		for i := range result {
			result[i].Exclusive = result[i].Name == "TestExplicitExclusive"
			if slices.Contains(fullOnlyExtra, result[i].Name) {
				value := true
				result[i].FullOnly = &value
			}
		}
		return result
	}
	for _, profile := range []string{"dev", "full"} {
		t.Run(profile, func(t *testing.T) {
			before := slices.Clone(inventory)
			selected, _, groups, _, err := resolveComponentGroups(inventory, classifications(inventory), profile, singleTestRequest(""), 4, componentEstimates)
			if err != nil || !slices.Equal(before, inventory) {
				t.Fatal("group planning failed or changed its input", err)
			}
			reversed := slices.Clone(inventory)
			slices.Reverse(reversed)
			_, _, again, _, err := resolveComponentGroups(reversed, classifications(reversed), profile, singleTestRequest(""), 4, componentEstimates)
			if err != nil || !reflect.DeepEqual(groups, again) {
				t.Fatal("discovery order changes the queued partition", err)
			}
			seen, labels := map[string]bool{}, map[string]bool{}
			ordinaryGroups := 0
			for _, group := range groups {
				if len(group.Tests) == 0 || labels[group.Name] {
					t.Fatal("empty or repeated group", group)
				}
				labels[group.Name] = true
				if len(group.Name) > 96 {
					t.Fatal("group label is not a usable bounded public alias", group.Name)
				}
				if !group.Exclusive {
					ordinaryGroups++
				}
				var cost float64
				for _, name := range group.Tests {
					if seen[name] || !slices.Contains(selected, name) {
						t.Fatal("duplicate or unselected group owner", name)
					}
					seen[name] = true
					cost += componentEstimate(name)
					memory := slices.Contains(ordinaryMemoryTestInventory(), name)
					fullOnly := name == maximumCapacityComponent || slices.Contains(fullOnlyExtra, name)
					if memory && (!group.Exclusive || len(group.Tests) != 1) {
						t.Fatal("memory proof lost fresh exclusive process", group)
					}
					if fullOnly && !memory && group.Exclusive {
						t.Fatal("coverage profile made a test exclusive", group)
					}
					if name == "TestExplicitExclusive" && !group.Exclusive {
						t.Fatal("explicit resource classification lost exclusivity", group)
					}
				}
				if group.EstimatedSeconds != cost {
					t.Fatal("group estimate differs from its owners", group)
				}
			}
			if len(seen) != len(selected) || ordinaryGroups != 4 || !seen["TestNewOrdinary"] {
				t.Fatal("planner dropped work or did not fill normal workers", len(seen), len(selected), ordinaryGroups)
			}
		})
	}
}

// full_only: false
func TestComponentQueuedGroupsKeepHelperProofOwnersTogether(t *testing.T) {
	estimates := componentEstimates
	t.Cleanup(func() { componentEstimates = estimates })
	componentEstimates = map[string]float64{maximumCapacityComponent: 1}
	bundles := [][]string{
		{"TestFreshProcessChild", "TestThreeGenerationHistoryAndStaleCandidate", "TestHermeticWorkerEntrypointsNeedExplicitInvocation"},
		{"TestScenarioPhaseFailureChild", "TestScenarioPhaseRetainsFailureEvidence"},
		{"TestWriterTerminationChild", "TestWriterTerminationPreservesCompleteSelection"},
	}
	inventory := append(ordinaryMemoryTestInventory(), maximumCapacityComponent)
	for _, bundle := range bundles {
		inventory = append(inventory, bundle...)
	}
	for i := 0; i < 8; i++ {
		name := fmt.Sprintf("TestBoundedQueue%02d", i)
		inventory = append(inventory, name)
		componentEstimates[name] = componentCheckTimeout.Seconds() + 1
	}
	for _, profile := range []string{"dev", "full"} {
		t.Run(profile, func(t *testing.T) {
			_, _, groups, _, err := resolveComponentGroups(inventory, componentProfileFixtureClassifications(inventory), profile, singleTestRequest(""), 4, componentEstimates)
			if err != nil {
				t.Fatal(err)
			}
			owner := map[string]string{}
			for _, group := range groups {
				for _, name := range group.Tests {
					owner[name] = group.Name
				}
			}
			for _, bundle := range bundles {
				for _, name := range bundle {
					if owner[name] == "" || owner[name] != owner[bundle[0]] {
						t.Fatal("helper and its existing proving owner were separated", bundle, owner)
					}
				}
			}
		})
	}
	for _, dependency := range []struct{ dependent, parent string }{
		{"TestFreshProcessChild", "TestThreeGenerationHistoryAndStaleCandidate"},
		{"TestHermeticWorkerEntrypointsNeedExplicitInvocation", "TestThreeGenerationHistoryAndStaleCandidate"},
		{"TestScenarioPhaseFailureChild", "TestScenarioPhaseRetainsFailureEvidence"},
		{"TestWriterTerminationChild", "TestWriterTerminationPreservesCompleteSelection"},
	} {
		for _, conflict := range []string{"missing-parent", "full-only-dependent", "full-only-parent"} {
			t.Run(dependency.dependent+"/"+conflict, func(t *testing.T) {
				names := append(ordinaryMemoryTestInventory(), maximumCapacityComponent, dependency.dependent)
				if conflict != "missing-parent" {
					names = append(names, dependency.parent)
				}
				classifications := componentProfileFixtureClassifications(names)
				if conflict != "missing-parent" {
					marked := dependency.dependent
					if conflict == "full-only-parent" {
						marked = dependency.parent
					}
					for i := range classifications {
						if classifications[i].Name == marked {
							value := true
							classifications[i].FullOnly = &value
						}
					}
				}
				_, _, _, _, resolvedErr := resolveComponentGroups(names, classifications, "full", nil, 4, componentEstimates)
				_, groupedErr := componentGroupsForProfile(names, classifications, "full", 4, componentEstimates)
				if conflict == "missing-parent" {
					if resolvedErr == nil || resolvedErr.Error() != "component helper lacks its selected proving parent" {
						t.Fatal("selector admitted a helper without its required parent", resolvedErr)
					}
					if groupedErr != nil {
						t.Fatal("placement repeated selector admission", groupedErr)
					}
				} else if resolvedErr != nil || groupedErr != nil {
					t.Fatal("coverage profile changed helper process ownership", resolvedErr, groupedErr)
				}
			})
		}
	}
}

// full_only: false
func TestComponentGroupsShareNormalRootsAcrossWorkers(t *testing.T) {
	const owners, ownerSeconds = 24, 600
	estimates := map[string]float64{maximumCapacityComponent: 1}
	inventory := append(ordinaryMemoryTestInventory(), maximumCapacityComponent)
	moderate := make(map[string]bool, owners)
	for i := 0; i < owners; i++ {
		name := fmt.Sprintf("TestModerateOrdinary%02d", i)
		inventory = append(inventory, name)
		moderate[name] = true
		estimates[name] = ownerSeconds
	}
	for _, profile := range []string{"dev", "full"} {
		for _, parallel := range []int{1, 2, 4} {
			t.Run(fmt.Sprintf("%s/parallel=%d", profile, parallel), func(t *testing.T) {
				_, _, groups, _, err := resolveComponentGroups(inventory, componentProfileFixtureClassifications(inventory), profile, nil, parallel, estimates)
				if err != nil {
					t.Fatal(err)
				}
				moderateGroups, groupedOwners, multiOwnerGroups := 0, 0, 0
				seen := map[string]bool{}
				for _, group := range groups {
					inGroup := 0
					for _, name := range group.Tests {
						if moderate[name] {
							if seen[name] || group.Exclusive || group.Worker < 1 || group.Worker > parallel {
								t.Fatal("ordinary owner repeated or left its assigned worker", group)
							}
							seen[name] = true
							inGroup++
						}
					}
					if inGroup != 0 {
						moderateGroups++
						groupedOwners += inGroup
						if len(group.Tests) > 1 {
							multiOwnerGroups++
						}
					}
				}
				if groupedOwners != owners || moderateGroups != parallel || multiOwnerGroups != parallel {
					t.Fatal("ordinary roots did not share every assigned worker", groupedOwners, moderateGroups, multiOwnerGroups)
				}
			})
		}
	}
}

// full_only: false
func TestComponentQueueCapacityRefusesBeforeDispatch(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "components")
	inventory := append(ordinaryMemoryTestInventory(), maximumCapacityComponent)
	// Distinct literal child paths require separate Go selectors. At 4096
	// groups, even the shortest failure framing exceeds its capture share.
	for i := 0; len(inventory) < 4096; i++ {
		inventory = append(inventory, fmt.Sprintf("TestFullOnlyQueue%03d", i))
	}
	classifications := componentProfileFixtureClassifications(inventory)
	requests := make([]string, len(inventory))
	for i := range classifications {
		requests[i] = classifications[i].Name + "/leaf"
		if strings.HasPrefix(classifications[i].Name, "TestFullOnlyQueue") {
			value := true
			classifications[i].FullOnly = &value
		}
	}
	// Inventory may start and join. Any later invocation is a group dispatch
	// and leaves a durable test-local marker before failing. A correct capacity
	// refusal must occur before this branch is reached by any worker.
	script := `#!/bin/sh
set -eu
case "$*" in
  *-test.list=^Test*) printf '%s\n' ` + strings.Join(inventory, " ") + `; exit 0 ;;
esac
printf started > group-started
exit 7
`
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	converter := testEventConverterFixture(t, root)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	process, evidence, _, _ := executeFixtureProfileComponentChecks(t, nil, ctx, root, binary, converter,
		componentMetadataBuildFlags(t, root, classifications), os.Environ(), "full", requests, 4, io.Discard, nil)
	if process.Status != "process_failed" || process.Cause == nil || process.Cause.Error() != "component failure capture plan exceeds its bound" || process.Started || !process.Joined || evidence.TestsComplete || len(evidence.Groups) != 0 || len(evidence.Tests) != 0 {
		t.Fatal("oversized queue did not refuse before test dispatch", process, evidence)
	}
	if evidence.Profile != "full" || !slices.Equal(evidence.Inventory, inventory) || !sameTestClassifications(evidence.Classifications, classifications) || len(evidence.NotSelected) != 0 {
		t.Fatal("capacity refusal occurred before complete inventory and classification", evidence)
	}
	if _, err := os.Stat(filepath.Join(root, "group-started")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a group started before failure capture capacity was checked", err)
	}
	if evidence.Diagnostics == nil || len(evidence.Diagnostics.Commands) == 0 || len(evidence.Diagnostics.Commands) > maximumCheckCommands {
		t.Fatal("capacity refusal lost preparation evidence", evidence.Diagnostics)
	}
	started := 0
	for _, command := range evidence.Diagnostics.Commands {
		if command.Phase != "preparation" || command.Process != "passed" || !command.Started || !command.Joined || command.ToolCleanup != "passed" && command.ToolCleanup != "not_required" {
			t.Fatal("started preparation was not retained and positively joined", command)
		}
		started++
	}
	if started == 0 {
		t.Fatal("fixture did not exercise real preparation before refusal")
	}
}

// full_only: false
func TestComponentHelperResourceClassKeepsRequiredParent(t *testing.T) {
	names := []string{"TestScenarioPhaseRetainsFailureEvidence", "TestScenarioPhaseFailureChild", "TestOrdinary"}
	rows := componentFixtureClassifications(names)
	rows[1].Exclusive = true
	for _, profile := range []string{"dev", "full"} {
		groups, err := componentGroupsForProfile(names, rows, profile, 4, componentEstimates)
		if err != nil || len(groups) != 2 || groups[0].Exclusive || !slices.Equal(groups[0].Tests, []string{"TestOrdinary"}) || !groups[1].Exclusive || len(groups[1].Tests) != 2 {
			t.Fatal("helper resource need lost its required parent or selected independent work", groups, err)
		}
	}
}

package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/observability"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"go.opentelemetry.io/otel"
)

const hermeticCheckRunID = "0123456789abcdef0123456789abcdef"

func hermeticCheckInvocation(t *testing.T, scenario string) records.Invocation {
	t.Helper()
	return hermeticCheckInvocationLayout(t, scenario, "2026-09-08/03-11-01+1000-"+hermeticCheckRunID)
}

func hermeticCheckInvocationLayout(t *testing.T, scenario string, layout string) records.Invocation {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	token, err := catalog.CaseDirectoryToken(scenario)
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "tests/hermetic/runs", filepath.FromSlash(layout), "private", "0000-"+token)
	output := filepath.Join(state, "workers", "writer")
	if err := os.MkdirAll(output, 0o700); err != nil {
		t.Fatal(err)
	}
	inv := records.Invocation{SchemaVersion: records.SchemaVersion, Scenario: scenario, Nonce: "0123456789abcdef0123456789abcdef", RunID: hermeticCheckRunID, Worker: "0000-" + token + "-writer", Role: "writer", Input: filepath.Join(state, "input.json"), StateDir: state, OutputDir: output}
	inv.Nonce = hermeticCheckNonce(t)
	inv.FailureSources = &records.FailureSourceBinding{Path: os.Getenv("ENKV_TEST_FAILURE_SOURCES"), SHA256: os.Getenv("ENKV_TEST_FAILURE_SOURCES_SHA256")}
	if _, err := records.ReadFailureSources(*inv.FailureSources); err != nil {
		t.Fatal("qualified assembly source mapping unavailable")
	}
	execution, known := catalog.ExecutionFor(scenario, "hermetic")
	if !known {
		t.Fatal("test invocation scenario unavailable")
	}
	for index := range execution.ExpandedFreshBefore() {
		inv.FreshBefore = append(inv.FreshBefore, records.InvocationBinding{Worker: fmt.Sprintf("%s-fresh-%04d-before", filepath.Base(inv.StateDir), index), Nonce: hermeticCheckNonce(t)})
	}
	input := hermeticWorkerInput{RecoveryMode: "both", Participants: map[string]string{"authority": "operator", "recovery": "recovery"}, Scenarios: []string{scenario}, Repetitions: 1, RunID: hermeticCheckRunID}
	definition, _ := catalog.DefinitionFor(scenario)
	for _, role := range definition.Roles {
		if input.Participants[role] == "" {
			input.Participants[role] = role
		}
	}
	if err := records.WriteJSON(inv.Input, input, 0o400); err != nil {
		t.Fatal(err)
	}
	hermeticCheckSaveInvocation(t, inv)
	return inv
}

// full_only: false
func TestHermeticWorkerRetainedLayouts(t *testing.T) {
	ctx, cancel := hermeticWorkerContext(t)
	defer cancel()
	deadline, _ := t.Deadline()
	if actual, finite := ctx.Deadline(); !finite || !actual.Equal(deadline) {
		t.Fatal("worker context changed the common test deadline", actual, deadline)
	}
	for _, allowance := range []time.Duration{30 * time.Second, 2 * time.Minute} {
		t.Run("worker_deadline_"+allowance.String(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), allowance)
			defer cancel()
			deadline, _ := ctx.Deadline()
			before := time.Now()
			command, _ := hermeticWorkerCommand(t, ctx, "controlled-invocation", "TestHermeticChild")
			after := time.Now()
			if len(command.Args) != 3 || command.Args[1] != "-test.run=^TestHermeticChild$" || !strings.HasPrefix(command.Args[2], "-test.timeout=") {
				t.Fatal("worker command changed its exact child selection", command.Args)
			}
			alarm := strings.TrimPrefix(command.Args[2], "-test.timeout=")
			actual, err := time.ParseDuration(alarm)
			if err != nil || actual <= 0 || actual > deadline.Sub(before) || actual < deadline.Sub(after) {
				t.Fatalf("worker alarm = %q, want remaining allowance in [%s, %s]", alarm, deadline.Sub(after), deadline.Sub(before))
			}
		})
	}
	for _, layout := range []string{hermeticCheckRunID, "undated/" + hermeticCheckRunID} {
		for _, recovery := range []string{"both", "disabled", "enabled"} {
			t.Run(layout+"/"+recovery, func(t *testing.T) {
				inv := hermeticCheckInvocationLayout(t, "state.single-value-update-preserves-other-values/members_1", layout)
				execution, known := catalog.ExecutionFor(inv.Scenario, "hermetic")
				if !known {
					t.Fatal("full execution unavailable")
				}
				var input hermeticWorkerInput
				if records.ReadJSON(inv.Input, &input) != nil {
					t.Fatal("worker input fixture unavailable")
				}
				input.RecoveryMode = recovery
				input.Participants = make(map[string]string)
				for _, role := range catalog.RolesForScenarios(input.Scenarios, recovery) {
					input.Participants[role] = role
				}
				if records.WriteJSON(inv.Input, input, 0400) != nil {
					t.Fatal("selected worker input could not be saved")
				}
				if recovery != "both" {
					inv.RecoveryMode = recovery
				}
				inv.FreshBefore = nil
				for _, child := range execution.ExpandedFreshBefore() {
					if recovery == "both" || child.Step.RecoveryMode == recovery {
						index := len(inv.FreshBefore)
						inv.FreshBefore = append(inv.FreshBefore, records.InvocationBinding{Worker: fmt.Sprintf("%s-fresh-%04d-before", filepath.Base(inv.StateDir), index), Nonce: hermeticCheckNonce(t)})
					}
				}
				if output, err := hermeticCheckCommand(t, inv, "", "TestHermeticRun"); err != nil {
					t.Fatalf("retained layout writer: %v %s", err, output)
				}
				writer := hermeticCheckResult(t, inv)
				wantAfter := 1
				if recovery == "both" {
					wantAfter = 2
				}
				if writer.Outcome != "passed" || len(writer.Children) != len(inv.FreshBefore) || len(writer.FreshChecks) != wantAfter {
					t.Fatal("retained layout lost selected writer or fresh reader evidence")
				}
				for _, phase := range writer.Phases {
					if recovery != "both" && phase.RecoveryMode != recovery {
						t.Fatal("writer ran an omitted recovery mode")
					}
				}
				owner, _, id, err := records.PrivateOwner(inv.StateDir)
				if err != nil || id != inv.RunID {
					t.Fatal("retained original owner refused")
				}
				for index, child := range writer.Children {
					path, err := records.SafePath(owner, child.Invocation)
					if err != nil {
						t.Fatal(err)
					}
					fresh, err := records.LoadInvocation(path)
					if err != nil || fresh.Worker != inv.FreshBefore[index].Worker || fresh.RunID != inv.RunID || fresh.StateDir != inv.StateDir || recovery != "both" && fresh.RecoveryMode != recovery {
						t.Fatal("retained layout child descriptor changed selected ownership or mode")
					}
				}
				for _, check := range writer.FreshChecks {
					if recovery != "both" && check.RecoveryMode != recovery {
						t.Fatal("after-exit reader includes an omitted recovery mode")
					}
					after := hermeticCheckAfter(t, inv, check.Facts, check.RecoveryMode)
					if output, err := hermeticCheckCommand(t, after, "", "TestHermeticChild"); err != nil {
						t.Fatalf("retained layout reader after writer exit: %v %s", err, output)
					}
				}
			})
		}
	}
}

func hermeticCheckSaveInvocation(t *testing.T, inv records.Invocation) {
	t.Helper()
	if err := records.WriteJSON(filepath.Join(inv.OutputDir, "invocation.json"), inv, 0o400); err != nil {
		t.Fatal(err)
	}
}

func hermeticCheckCommand(t *testing.T, inv records.Invocation, telemetry, entry string) ([]byte, error) {
	t.Helper()
	if telemetry == "1" {
		settings, err := observability.Decode([]byte(`{"schema_version":1,"metrics":{"exporters":["local"]},"exporters":{"local":{"type":"otlp_file","directory":"telemetry"}}}`), observability.Options{})
		if err != nil {
			t.Fatal(err)
		}
		inv.TelemetrySettings = &settings
	}
	hermeticCheckSaveInvocation(t, inv)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command, _ := hermeticWorkerCommand(t, ctx, filepath.Join(inv.OutputDir, "invocation.json"), entry)
	return command.CombinedOutput()
}

// full_only: false
func TestHermeticWorkerEntrypointsNeedExplicitInvocation(t *testing.T) {
	t.Setenv("ENKV_TEST_INVOCATION", "")
	t.Setenv("ENKV_TELEMETRY", "1")
	directory := t.TempDir()
	t.Setenv("ENKV_SCENARIO_REPORT", filepath.Join(directory, "legacy-scenario.json"))
	t.Setenv("ENKV_PROCESS_METRICS", filepath.Join(directory, "legacy-calls.json"))
	t.Setenv("ENKV_PROCESS_FIXTURE", "")
	before := otel.GetMeterProvider()
	for _, entry := range []struct {
		name string
		run  func(*testing.T)
	}{{"writer", TestHermeticRun}, {"fresh", TestHermeticChild}, {"fixture", TestFreshProcessChild}} {
		skipped := false
		t.Run(entry.name, func(t *testing.T) {
			defer func() { skipped = t.Skipped() }()
			entry.run(t)
		})
		if !skipped {
			t.Fatal("unused helper was reported as executed")
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 || otel.GetMeterProvider() != before {
		t.Fatal("unselected hermetic entry point caused file or SDK effects")
	}
}

func hermeticCheckResult(t *testing.T, inv records.Invocation) records.WorkerResult {
	t.Helper()
	var result records.WorkerResult
	if err := records.ReadJSON(filepath.Join(inv.OutputDir, "worker.json"), &result); err != nil {
		t.Fatal(err)
	}
	if result.RunID != inv.RunID || result.Worker != inv.Worker || result.Role != inv.Role {
		t.Fatal("worker evidence identity differs")
	}
	return result
}

func hermeticCheckTelemetry(t *testing.T, inv records.Invocation, enabled bool) []records.Snapshot {
	t.Helper()
	result := hermeticCheckResult(t, inv)
	path := filepath.Join(inv.OutputDir, "telemetry.json")
	if !enabled {
		if result.Telemetry.Enabled || result.Telemetry.Status != "disabled" {
			t.Fatal("disabled telemetry changed its status")
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("disabled worker created a telemetry file")
		}
		return nil
	}
	var snapshots []records.Snapshot
	if err := records.ReadJSON(path, &snapshots); err != nil {
		t.Fatal(err)
	}
	if result.Telemetry.Status != "complete" || len(snapshots) != len(result.Phases)+1 || snapshots[len(snapshots)-1].Phase != "final" {
		t.Fatalf("phase or final telemetry missing: %+v", result)
	}
	for index, snapshot := range snapshots {
		if snapshot.Worker != inv.Worker || snapshot.RunID != inv.RunID || snapshot.Sequence != uint64(index+1) || snapshot.Status != "complete" || snapshot.Temporality != "delta" {
			t.Fatal("snapshot identity, order or status differs")
		}
	}
	return snapshots
}

// full_only: false
func TestHermeticWorkerHistoryKeepsEachProcessEvidence(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			inv := hermeticCheckInvocation(t, "state.historical-bytes-get-new-identities/members_32_three_generations")
			telemetry := ""
			if enabled {
				telemetry = "1"
			}
			if output, err := hermeticCheckCommand(t, inv, telemetry, "TestHermeticRun"); err != nil {
				t.Fatalf("writer: %v %s", err, output)
			}
			writer := hermeticCheckResult(t, inv)
			if writer.Outcome != "passed" || len(writer.Children) != 8 || len(writer.FreshChecks) != 2 {
				t.Fatalf("history lost prior children or latest facts: %+v", writer)
			}
			parentSnapshots := hermeticCheckTelemetry(t, inv, enabled)
			for index, phase := range writer.Phases {
				if phase.Name == "reopen" {
					if phase.MeasurementsExpected {
						t.Fatal("writer claims child measurements")
					}
					if enabled {
						for _, metric := range parentSnapshots[index].Metrics {
							if metric.Value != nil && *metric.Value != 0 || metric.Count != nil && *metric.Count != 0 {
								t.Fatal("child measurements entered writer snapshot")
							}
						}
					}
				}
			}
			beforeFiles := map[string][]byte{}
			seenFacts := map[string]bool{}
			for _, descriptor := range writer.Children {
				path, err := records.SafePath(filepath.Dir(inv.StateDir), descriptor.Invocation)
				if err != nil {
					t.Fatal(err)
				}
				child, err := records.LoadInvocation(path)
				if err != nil || child.Worker != descriptor.Worker || child.Role != "fresh_before" || child.OutputDir == inv.OutputDir || seenFacts[child.Facts] {
					t.Fatalf("child invocation or immutable facts differ: %+v %v", child, err)
				}
				seenFacts[child.Facts] = true
				if result := hermeticCheckResult(t, child); result.Outcome != "passed" {
					t.Fatalf("before reader failed: %+v", result)
				}
				hermeticCheckTelemetry(t, child, enabled)
				fileNames := []string{"worker.json", "invocation.json"}
				if enabled {
					fileNames = append(fileNames, "telemetry.json")
				}
				for _, name := range fileNames {
					path := filepath.Join(child.OutputDir, name)
					body, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					beforeFiles[path] = body
				}
			}
			for _, check := range writer.FreshChecks {
				after := hermeticCheckAfter(t, inv, check.Facts, check.RecoveryMode)
				if !seenFacts[after.Facts] {
					t.Fatal("after reader does not use retained before-reader facts")
				}
				if output, err := hermeticCheckCommand(t, after, telemetry, "TestHermeticChild"); err != nil {
					t.Fatalf("reader after writer exit: %v %s", err, output)
				}
				if result := hermeticCheckResult(t, after); result.Outcome != "passed" {
					t.Fatal("after reader did not verify selected state")
				}
				hermeticCheckTelemetry(t, after, enabled)
			}
			for path, before := range beforeFiles {
				current, err := os.ReadFile(path)
				if err != nil || !reflect.DeepEqual(current, before) {
					t.Fatal("after reader replaced before-reader evidence")
				}
			}
		})
	}
}

func hermeticCheckAfter(t *testing.T, writer records.Invocation, facts, recovery string) records.Invocation {
	t.Helper()
	child := writer
	child.Nonce, child.FreshBefore = hermeticCheckNonce(t), nil
	child.RecoveryMode = recovery
	label := "fresh-after-" + strings.TrimSuffix(filepath.Base(facts), ".json")
	child.Worker, child.Role, child.Facts = label, "fresh_after", facts
	child.OutputDir = filepath.Join(writer.StateDir, "workers", label)
	if err := os.Mkdir(child.OutputDir, 0o700); err != nil {
		t.Fatal(err)
	}
	hermeticCheckSaveInvocation(t, child)
	return child
}

// full_only: false
func TestHermeticMaximumSnapshotSurvivesWriterExit(t *testing.T) {
	inv := hermeticCheckInvocation(t, "capacity.maximum-size-state-refuses-growth-and-allows-update/members_512_value_16kib")
	if output, err := hermeticCheckCommand(t, inv, "", "TestHermeticRun"); err != nil {
		t.Fatalf("maximum writer: %v %s", err, output)
	}
	writer := hermeticCheckResult(t, inv)
	if writer.Outcome != "passed" || len(writer.Children) != 2 || len(writer.FreshChecks) != 2 {
		t.Fatal("maximum writer lost its fresh reader evidence")
	}
	for _, check := range writer.FreshChecks {
		factsPath := filepath.Join(inv.StateDir, check.Facts)
		var facts hermeticFreshFacts
		if records.ReadJSON(factsPath, &facts) != nil || facts.ExpectedImageFile == "" {
			t.Fatal("maximum fixture lost its separate oracle record")
		}
		expectedPath := filepath.Join(inv.StateDir, facts.ExpectedImageFile)
		var expected stateImage
		if records.ReadJSON(expectedPath, &expected) != nil || len(facts.Fixture.Objects) <= int(expected.Root.ChildCount)+2 {
			t.Fatal("maximum fixture discarded old objects to fit a record")
		}
		factsInfo, factsErr := os.Stat(factsPath)
		expectedInfo, expectedErr := os.Stat(expectedPath)
		if factsErr != nil || expectedErr != nil || factsInfo.Size() > 32<<20 || expectedInfo.Size() > 32<<20 || factsInfo.Size()+expectedInfo.Size() <= 32<<20 || factsInfo.Mode().Perm() != 0o400 || expectedInfo.Mode().Perm() != 0o400 {
			t.Fatal("maximum snapshot did not exercise two bounded private records")
		}
		after := hermeticCheckAfter(t, inv, check.Facts, check.RecoveryMode)
		if output, err := hermeticCheckCommand(t, after, "", "TestHermeticChild"); err != nil {
			t.Fatalf("maximum reader after writer exit: %v %s", err, output)
		}
		if result := hermeticCheckResult(t, after); result.Outcome != "passed" {
			t.Fatal("maximum state failed after writer exit")
		}
	}
}

// full_only: false
func TestHermeticOracleRecordsKeepOneOwnerAndReadRetainedInlineFacts(t *testing.T) {
	inv := hermeticCheckInvocation(t, "state.single-value-update-preserves-other-values/members_1")
	if output, err := hermeticCheckCommand(t, inv, "", "TestHermeticRun"); err != nil {
		t.Fatalf("oracle fixture writer: %v %s", err, output)
	}
	writer := hermeticCheckResult(t, inv)
	for _, mode := range []string{"inline", "missing", "different_owner", "competing_inline", "escape"} {
		t.Run(mode, func(t *testing.T) {
			var facts hermeticFreshFacts
			if records.ReadJSON(filepath.Join(inv.StateDir, writer.FreshChecks[0].Facts), &facts) != nil {
				t.Fatal("oracle fixture facts")
			}
			child := inv
			child.Nonce, child.FreshBefore = hermeticCheckNonce(t), nil
			child.Worker, child.Role = "oracle-"+mode, "fresh_after"
			child.RecoveryMode = facts.RecoveryMode
			child.Facts = "facts/" + mode + ".json"
			child.OutputDir = filepath.Join(inv.StateDir, "workers", mode)
			if os.Mkdir(child.OutputDir, 0o700) != nil {
				t.Fatal("oracle reader output")
			}
			switch mode {
			case "inline", "competing_inline":
				if records.ReadJSON(filepath.Join(inv.StateDir, facts.ExpectedImageFile), &facts.Fixture.ExpectedImage) != nil {
					t.Fatal("oracle fixture image")
				}
				facts.ExpectedImageFile = ""
				if mode == "competing_inline" {
					facts.ExpectedImageFile = "facts/" + mode + "-expected.json"
					if records.WriteJSON(filepath.Join(inv.StateDir, facts.ExpectedImageFile), facts.Fixture.ExpectedImage, 0o400) != nil {
						t.Fatal("competing oracle fixture")
					}
				}
			case "missing":
				facts.ExpectedImageFile = "facts/" + mode + "-expected.json"
			case "escape":
				facts.ExpectedImageFile = "../outside.json"
			}
			if records.WriteJSON(filepath.Join(inv.StateDir, child.Facts), facts, 0o400) != nil {
				t.Fatal("oracle case facts")
			}
			hermeticCheckSaveInvocation(t, child)
			output, err := hermeticCheckCommand(t, child, "", "TestHermeticChild")
			passed := mode == "inline"
			if (err == nil) != passed || (hermeticCheckResult(t, child).Outcome == "passed") != passed {
				t.Fatalf("oracle ownership %s: %v %s", mode, err, output)
			}
		})
	}
}

// full_only: false
func TestHermeticWorkerRefusalSurvivesWriterExit(t *testing.T) {
	for _, scenario := range []string{"evidence.missing-selected-child-prevents-open/members_32_missing_page", "evidence.corrupt-selected-child-prevents-open/members_32_corrupt_page"} {
		t.Run(scenario, func(t *testing.T) {
			inv := hermeticCheckInvocation(t, scenario)
			if output, err := hermeticCheckCommand(t, inv, "1", "TestHermeticRun"); err != nil {
				t.Fatalf("refusal writer: %v %s", err, output)
			}
			writer := hermeticCheckResult(t, inv)
			if writer.Outcome != "passed" || len(writer.Children) != 2 || len(writer.FreshChecks) != 2 {
				t.Fatalf("refusal evidence missing: %+v", writer)
			}
			for index, check := range writer.FreshChecks {
				childPath := filepath.Join(filepath.Dir(inv.StateDir), writer.Children[index].Invocation)
				before, err := records.LoadInvocation(childPath)
				if err != nil || hermeticCheckResult(t, before).Outcome != "passed" {
					t.Fatalf("before reader did not verify refusal: %v", err)
				}
				var facts hermeticFreshFacts
				if err := records.ReadJSON(filepath.Join(inv.StateDir, check.Facts), &facts); err != nil || facts.Refusal != scenario || len(facts.Fixture.Objects) == 0 {
					t.Fatal("refusal facts are absent or incomplete")
				}
				after := hermeticCheckAfter(t, inv, check.Facts, check.RecoveryMode)
				if output, err := hermeticCheckCommand(t, after, "1", "TestHermeticChild"); err != nil {
					t.Fatalf("refusal after writer exit: %v %s", err, output)
				}
				for _, worker := range []records.Invocation{inv, before, after} {
					if hermeticCheckResult(t, worker).Outcome != "passed" {
						t.Fatal("refusal was not verified")
					}
					hermeticCheckTelemetry(t, worker, true)
				}
			}
		})
	}
}

// full_only: false
func TestHermeticWorkerFailureRetainsAssertionWithoutTelemetry(t *testing.T) {
	inv := hermeticCheckInvocation(t, "state.single-value-update-preserves-other-values/members_1")
	inv.FreshBefore = nil
	if _, err := hermeticCheckCommand(t, inv, "", "TestHermeticRun"); err == nil {
		t.Fatal("missing fresh reader binding passed")
	}
	result := hermeticCheckResult(t, inv)
	if result.Outcome != "failed" || len(result.Children) != 0 || len(result.Phases) != 4 || result.Phases[3].Outcome != "failed" {
		t.Fatal("failed recovery subtest lost its worker evidence")
	}
	for _, phase := range result.Phases {
		if phase.RecoveryMode != "disabled" {
			t.Fatal("writer continued after failed recovery mode")
		}
	}
	// Pin the missing-binding assertion, not any Fatal in the same phase.
	hermeticCheckFailureMarker(t, inv, "tests/hermetic/run_test.go", 282, 4, records.CompletedCheckpoint{Code: "verification", Sequence: 3})
	hermeticCheckTelemetry(t, inv, false)
}

func hermeticCheckFailureMarker(t *testing.T, inv records.Invocation, source string, line int, sequence uint64, completed records.CompletedCheckpoint) {
	t.Helper()
	sources, err := records.ReadFailureSources(*inv.FailureSources)
	if err != nil {
		t.Fatal("failure source mapping unavailable")
	}
	var marker records.FailureMarker
	if records.ReadJSON(filepath.Join(inv.OutputDir, "failure.json"), &marker) != nil || marker.Validate(inv, sources) != nil {
		t.Fatal("worker did not retain a valid assertion marker")
	}
	if marker.Code != "fatal" || marker.Source != source || marker.Line != line || marker.Phase != "reopen" || marker.Sequence != sequence || marker.Completed != completed || marker.OperationFailure != nil {
		t.Fatal("worker assertion location or checkpoint differs")
	}
	assertions := records.InspectAssertions(inv, false)
	if assertions.Marker != "valid_failure_marker" || assertions.Completed != completed || assertions.MarkerWriteError {
		t.Fatal("worker assertion evidence unavailable")
	}
	files := []string{"failure.json", "worker.json"}
	if completed.Code == "none" {
		if _, err := os.Lstat(filepath.Join(inv.OutputDir, "checkpoint.json")); !os.IsNotExist(err) || assertions.Checkpoint != "no_checkpoint" {
			t.Fatal("failed first phase acquired a completed checkpoint")
		}
	} else {
		if assertions.Checkpoint != "valid_checkpoint" {
			t.Fatal("completed phase checkpoint unavailable")
		}
		files = append(files, "checkpoint.json")
	}
	for _, name := range files {
		path := filepath.Join(inv.OutputDir, name)
		body, err := os.ReadFile(path)
		info, statErr := os.Stat(path)
		if err != nil || statErr != nil || info.Mode().Perm() != 0600 || name == "failure.json" && len(body) > records.MaximumFailureBytes {
			t.Fatal("private failure evidence missing or unbounded")
		}
		if strings.Contains(string(body), "deliberate wrong expected value") || strings.Contains(string(body), inv.StateDir) {
			t.Fatal("private assertion data entered failure evidence")
		}
	}
}

// full_only: false
func TestHermeticWorkerFailedOracleRetainsFinalEvidence(t *testing.T) {
	inv := hermeticCheckInvocation(t, "state.single-value-update-preserves-other-values/members_1")
	if output, err := hermeticCheckCommand(t, inv, "", "TestHermeticRun"); err != nil {
		t.Fatalf("writer: %v %s", err, output)
	}
	writer := hermeticCheckResult(t, inv)
	var facts hermeticFreshFacts
	if err := records.ReadJSON(filepath.Join(inv.StateDir, writer.FreshChecks[0].Facts), &facts); err != nil {
		t.Fatal(err)
	}
	if records.ReadJSON(filepath.Join(inv.StateDir, facts.ExpectedImageFile), &facts.Fixture.ExpectedImage) != nil {
		t.Fatal("retained oracle unavailable")
	}
	facts.ExpectedImageFile = ""
	facts.Fixture.ExpectedImage.Pages[0].Slots[0].ValueBytes = []byte("deliberate wrong expected value")
	for _, telemetry := range []string{"", "1"} {
		t.Run("telemetry_"+fmt.Sprint(telemetry == "1"), func(t *testing.T) {
			// Each child owns a separate invocation and cannot reuse a prior marker.
			caseFacts := "facts/wrong-expectation-" + fmt.Sprint(telemetry == "1") + ".json"
			if records.WriteJSON(filepath.Join(inv.StateDir, caseFacts), facts, 0o400) != nil {
				t.Fatal("wrong oracle case unavailable")
			}
			after := hermeticCheckAfter(t, inv, caseFacts, facts.RecoveryMode)
			if _, err := hermeticCheckCommand(t, after, telemetry, "TestHermeticChild"); err == nil {
				t.Fatal("wrong oracle expectation passed")
			}
			result := hermeticCheckResult(t, after)
			if result.Outcome != "failed" || result.Failure == nil || len(result.Phases) != 1 || result.Phases[0].Outcome != "failed" {
				t.Fatal("failed oracle lost failure evidence")
			}
			// Pin assertStateImage's value mismatch assertion.
			hermeticCheckFailureMarker(t, after, "tests/shared/state_oracle_test.go", 359, 1, records.CompletedCheckpoint{Code: "none"})
			hermeticCheckTelemetry(t, after, telemetry == "1")
		})
	}
}

// full_only: false
func TestHermeticWorkerMissingOrCorruptFactsCannotPass(t *testing.T) {
	for _, damage := range []string{"missing", "invalid-json", "wrong-run", "wrong-scenario", "wrong-recovery-mode", "empty-fixture", "refusal-without-evidence"} {
		t.Run(damage, func(t *testing.T) {
			scenario := "state.single-value-update-preserves-other-values/members_32"
			if damage == "refusal-without-evidence" {
				scenario = "evidence.missing-selected-child-prevents-open/members_32_missing_page"
			}
			inv := hermeticCheckInvocation(t, scenario)
			if err := os.Mkdir(filepath.Join(inv.StateDir, "facts"), 0o700); err != nil {
				t.Fatal(err)
			}
			const factsName = "facts/invalid.json"
			path := filepath.Join(inv.StateDir, factsName)
			switch damage {
			case "invalid-json":
				if err := os.WriteFile(path, []byte("{"), 0o400); err != nil {
					t.Fatal(err)
				}
			case "wrong-run", "wrong-scenario", "wrong-recovery-mode", "empty-fixture", "refusal-without-evidence":
				facts := hermeticFreshFacts{RunID: inv.RunID, Scenario: scenario, RecoveryMode: "disabled"}
				switch damage {
				case "wrong-run":
					facts.RunID = "abcdef0123456789abcdef0123456789"
				case "wrong-scenario":
					facts.Scenario = "state.identical-input-keeps-current-state/members_32"
				case "wrong-recovery-mode":
					facts.RecoveryMode = "enabled"
				case "refusal-without-evidence":
					facts.Refusal = scenario
				}
				if err := records.WriteJSON(path, facts, 0o400); err != nil {
					t.Fatal(err)
				}
			}
			after := hermeticCheckAfter(t, inv, factsName, "disabled")
			if output, err := hermeticCheckCommand(t, after, "1", "TestHermeticChild"); err == nil {
				t.Fatalf("absent or invalid fresh facts passed: %s", output)
			}
			if damage == "missing" {
				if _, err := os.Lstat(filepath.Join(after.OutputDir, "worker.json")); !os.IsNotExist(err) {
					t.Fatal("missing facts passed invocation admission")
				}
				return
			}
			result := hermeticCheckResult(t, after)
			if result.Outcome != "failed" || result.Failure == nil || result.Failure.Class != "worker_failed" || result.Failure.Stage != "execution" {
				t.Fatalf("invalid facts lost worker failure: outcome=%s failure=%+v", result.Outcome, result.Failure)
			}
			phaseStarted := damage == "empty-fixture" || damage == "refusal-without-evidence"
			wantSnapshots := 1
			if phaseStarted {
				wantSnapshots = 2
				if len(result.Phases) != 1 || result.Phases[0].Outcome != "failed" || result.Telemetry.Status != "incomplete" {
					t.Fatal("invalid fixture lost admitted phase failure")
				}
			} else {
				execution, known := catalog.ExecutionFor(scenario, "hermetic")
				if !known || len(result.Phases) != 0 || result.Actor != execution.FreshAfter[0].Role || result.Telemetry.Status != "complete" {
					t.Fatalf("invalid facts admission evidence: phases=%d actor=%s telemetry=%s", len(result.Phases), result.Actor, result.Telemetry.Status)
				}
			}
			var snapshots []records.Snapshot
			if err := records.ReadJSON(filepath.Join(after.OutputDir, "telemetry.json"), &snapshots); err != nil || len(snapshots) != wantSnapshots || snapshots[len(snapshots)-1].Phase != "final" {
				t.Fatal("invalid facts lost final telemetry collection")
			}
		})
	}
}

// full_only: false
func TestHermeticWorkerRefusesInvalidInputBeforeEffects(t *testing.T) {
	for _, name := range []string{"unknown scenario", "wrong run", "numeric override", "numeric zero", "numeric null", "legacy scenario", "extra field"} {
		t.Run(name, func(t *testing.T) {
			inv := hermeticCheckInvocation(t, "state.single-value-update-preserves-other-values/members_32")
			body, err := os.ReadFile(inv.Input)
			if err != nil {
				t.Fatal(err)
			}
			var input map[string]any
			if err := json.Unmarshal(body, &input); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "unknown scenario":
				input["scenarios"] = []string{"unknown"}
			case "wrong run":
				input["run_id"] = "abcdef0123456789abcdef0123456789"
			case "numeric override":
				input["member_count"] = 1
			case "numeric zero":
				input["member_count"] = 0
			case "numeric null":
				input["member_count"] = nil
			case "legacy scenario":
				input["scenarios"] = []string{"state.single-value-update-preserves-other-values"}
			case "extra field":
				input["extra"] = true
			}
			body, err = json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(inv.Input, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(inv.Input, []byte(body), 0o400); err != nil {
				t.Fatal(err)
			}
			if output, err := hermeticCheckCommand(t, inv, "1", "TestHermeticRun"); err == nil {
				t.Fatalf("invalid input admitted: %s", output)
			}
			for _, path := range []string{filepath.Join(inv.OutputDir, "worker.json"), filepath.Join(inv.OutputDir, "telemetry.json"), filepath.Join(inv.StateDir, "facts")} {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal("invalid input caused worker or fixture effects")
				}
			}
		})
	}
}

// full_only: false
func TestHermeticFirstFlowSurvivesWriterExit(t *testing.T) {
	for _, name := range []string{"genesis.empty-domain-reopens/empty_genesis", "secret.empty-domain-first-selection-survives-restart/genesis_first_shared_secret", "secret.authority-only-survives-restart/plain_neighbor_authority_secret", "secret.shared-reader-survives-restart/plain_neighbor_shared_secret", "secret.provider-refuses-reader/plain_neighbor_denied_reader"} {
		t.Run(name, func(t *testing.T) {
			inv := hermeticCheckInvocation(t, name)
			if output, err := hermeticCheckCommand(t, inv, "", "TestHermeticRun"); err != nil {
				t.Fatalf("first flow writer: %v %s", err, output)
			}
			writer := hermeticCheckResult(t, inv)
			if writer.Outcome != "passed" || len(writer.Children) != 2 || len(writer.FreshChecks) != 2 {
				t.Fatal("first flow omitted a recovery mode or process boundary")
			}
			for i, check := range writer.FreshChecks {
				mode := []string{"disabled", "enabled"}[i]
				if check.RecoveryMode != mode {
					t.Fatal("fresh mode ordering differs")
				}
				child := hermeticCheckAfter(t, inv, check.Facts, check.RecoveryMode)
				if output, err := hermeticCheckCommand(t, child, "", "TestHermeticChild"); err != nil {
					t.Fatalf("first flow after writer exit: %v %s", err, output)
				}
				result := hermeticCheckResult(t, child)
				execution, known := catalog.ExecutionFor(name, "hermetic")
				if !known {
					t.Fatal("first flow execution facts unavailable")
				}
				var fresh catalog.FreshChild
				for _, child := range execution.FreshAfter {
					if child.Step.RecoveryMode == mode {
						fresh = child
						break
					}
				}
				if result.Outcome != "passed" || result.Actor != writer.Phases[len(writer.Phases)-1].Actor || len(result.Phases) != 1 || result.Phases[0].RecoveryMode != mode || result.Phases[0].Actual != fresh.Step.Expected {
					t.Fatal("fresh consumer evidence differs from the admitted actor, mode, or outcome")
				}
			}
		})
	}
}

func hermeticCheckNonce(t testing.TB) string {
	t.Helper()
	nonce, err := records.NewInvocationNonce()
	if err != nil {
		t.Fatal("test invocation nonce unavailable")
	}
	return nonce
}

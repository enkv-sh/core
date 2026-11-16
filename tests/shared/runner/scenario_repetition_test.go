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
	"slices"
	"strings"
	"testing"
	"time"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

// This is an actual instrumented Product run. The controlled schedule witness
// separately proves PID/nonce/fixture freshness and live recovery retention.
// full_only: false
func TestScenarioRepetitionsRetainSeparateLocalTelemetry(t *testing.T) {
	root := testRepositoryRoot(t)
	owned := t.TempDir()
	bootstrap := repetitionTestBootstrap(t, root, owned)
	t.Setenv("ENKV_TELEMETRY", "")
	t.Setenv("OTEL_SERVICE_NAME", "")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "")
	const scenario = "secret.competing-supplied-candidates-preserve-atomic-outcomes/plain2_secret2_competing_and_lost_reply"
	workflow := filepath.Join(owned, "workflow.json")
	saveSelection(t, workflow, map[string]any{"schema_version": 1, "name": "file-repetitions", "execution": map[string]any{"parallel": 4}, "steps": []any{
		map[string]any{"id": "candidates", "kind": "run", "repetitions": 3, "recovery_mode": "both",
			"suites": []string{filepath.Join(root, "tests/suites/state-secret-lifecycle.json")}, "scenarios": []string{scenario},
			"environment": filepath.Join(root, "tests/environments/hermetic.json"), "telemetry_config": filepath.Join(root, "tests/telemetry/local.json")},
	}})
	ctx, cancel := context.WithTimeout(workflowTestContext(t, root), 4*time.Minute)
	defer cancel()
	plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: workflow})
	if err != nil || len(plan.Steps) != 1 {
		t.Fatal("saved scenario repetition selection refused", err)
	}
	ctx = withExecutionCapacity(ctx, plan.Execution)
	request := plan.Steps[0].request
	source, err := sourceRevision(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	version, err := runGo(ctx, root, "core", "version")
	if err != nil {
		t.Fatal(err)
	}
	state, err := newRunState(root, request, source, strings.TrimSpace(string(version)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Log("current telemetry fixture retained:", state.directory)
		}
	})
	ctx, err = state.privateOwner.protectedFixtureContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	build := filepath.Join(state.private, "build")
	if err := os.Mkdir(build, 0700); err != nil {
		t.Fatal(err)
	}
	assembled, err := buildAssembly(runGoEnvironment, nil, ctx, root, "hermetic", "memory", bootstrap, build)
	if err != nil {
		t.Fatal(err)
	}

	buildOwner := state
	var attempts []*runState
	var attemptErrors []error
	t.Cleanup(func() {
		joined := true
		for _, attempt := range attempts {
			joined = joined && runProcessesJoined(attempt.record)
		}
		for _, cause := range attemptErrors {
			joined = joined && toolCommandsJoined(cause)
		}
		if err := buildOwner.current.remove(joined); err != nil {
			t.Error("shared assembly owner could not settle", err)
		}
	})
	for _, parallel := range []int{1, 4, 2} {
		name := fmt.Sprintf("parallel_%d", parallel)
		if parallel == 2 {
			name += "_point"
		}
		t.Run(name, func(t *testing.T) {
			child := withExecutionParallel(ctx, parallel)
			selected := request
			selected.execution = selected.execution.clone()
			selected.execution.Resolved = executionCapacityFromContext(child)
			if parallel == 2 {
				if err := resolveSelection(&selected, catalog.Request{Include: []string{"state.single-value-update-preserves-other-values/members_1"},
					Repetitions: 3, RecoveryMode: "both", SmokePolicy: catalog.SmokeFirstSelectedPoint}, request.Resolved.Suite, *request.environment); err != nil {
					t.Fatal(err)
				}
				selected.Resolved.Profile, selected.Resolved.Race = request.Resolved.Profile, request.Resolved.Race
				selected.Resolved.Suites = slices.Clone(request.Resolved.Suites)
			}
			attempt, err := newRunState(root, selected, source, strings.TrimSpace(string(version)))
			if err != nil {
				t.Fatal(err)
			}
			attempts = append(attempts, attempt)
			child, err = attempt.privateOwner.protectedFixtureContext(child)
			if err != nil {
				t.Fatal(err)
			}
			attempt.record.BuildClosure, attempt.failureSources = &assembled.Closure, assembled.FailureSources
			if parallel == 2 {
				executionErr := attempt.executeSchedule(child, assembled.Binary, nil, limits{})
				attemptErrors = append(attemptErrors, executionErr)
				if executionErr != nil {
					t.Fatal(executionErr)
				}
				attempt.finish()
				if attempt.record.Outcome != "passed" || len(attempt.record.Scenarios) != 3 {
					t.Fatal("two-share queue did not complete every selected point", attempt.record.Outcome)
				}
				nonces := map[string]bool{}
				for index, result := range attempt.record.Scenarios {
					if result.Entry != selected.Schedule.Entries[index] || !result.CorrectnessPassed || result.Outcome != "passed" || result.Writer == nil || len(result.Children) != 2 || len(result.PostExit) != 2 {
						t.Fatal("point lost selection, both fresh children or post-exit reads", result)
					}
					name, err := currentCaseDirectory(result.Entry)
					if err != nil {
						t.Fatal(err)
					}
					var invocation records.Invocation
					if records.ReadJSON(filepath.Join(attempt.private, name, "workers", "writer", "invocation.json"), &invocation) != nil || invocation.Nonce == "" || nonces[invocation.Nonce] {
						t.Fatal("point reused writer identity")
					}
					nonces[invocation.Nonce] = true
					for _, worker := range scenarioWorkers(result) {
						if !worker.Started || !worker.Joined || worker.Process != "passed" || worker.Outcome != "passed" {
							t.Fatal("point process did not pass and join", worker)
						}
					}
				}
				groups, err := scenarioRepetitionGroups(attempt.record)
				if err != nil || len(groups) != 1 || groups[0].RequestedExecutions != 3 || groups[0].CompletedExecutions != 3 || groups[0].Outcome != "passed" || !slices.Equal(groups[0].CaseSequences, []int{0, 1, 2}) {
					t.Fatal("two-share repetition facts differ", groups, err)
				}
				if err := attempt.finishCurrentRun(io.Discard, nil); err != nil {
					t.Fatal(err)
				}
				return
			}
			checkScenarioRepetitionTelemetry(t, child, attempt, assembled, scenario, &attemptErrors)
		})
	}
}

func checkScenarioRepetitionTelemetry(t *testing.T, ctx context.Context, state *runState, assembled assembly, scenario string, attemptErrors *[]error) {
	t.Helper()
	state.record.BuildClosure = &assembled.Closure
	state.failureSources = assembled.FailureSources
	executionErr := state.executeSchedule(ctx, assembled.Binary, nil, limits{})
	*attemptErrors = append(*attemptErrors, executionErr)
	if executionErr != nil {
		t.Fatal("actual repeated Product execution failed", executionErr)
	}
	state.finish()
	if err := state.save(); err != nil {
		t.Fatal(err)
	}
	run := state.record
	directory := state.directory
	outputs := map[string]string{}
	if err := filepath.WalkDir(state.private, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || entry.Name() != "invocation.json" {
			return nil
		}
		var invocation records.Invocation
		if err := records.ReadJSON(path, &invocation); err != nil {
			return err
		}
		if invocation.RunID != run.RunID || outputs[invocation.Worker] != "" {
			return errors.New("current worker output identity differs")
		}
		outputs[invocation.Worker] = invocation.OutputDir
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if run.Outcome != "passed" || !run.Correctness.Passed || !run.Correctness.EvidenceComplete || run.FullCoverage || run.ScenarioCoverage || len(run.Scenarios) != 4 || run.BuildClosure == nil || run.BuildClosure.Race != raceEnabled(ctx) || run.BuildClosure.RaceOptions != acceptedRaceOptions(raceEnabled(ctx)) || run.BuildClosure.BinarySHA256 == "" {
		t.Fatal("repetition changed local correctness, preparation or partial scope")
	}
	if !validTelemetryDisplay(run.EffectiveTelemetry) || !slices.Equal(run.EffectiveTelemetry.Logs, []string{"file"}) || !slices.Equal(run.EffectiveTelemetry.Metrics, []string{"file"}) || !slices.Equal(run.EffectiveTelemetry.Traces, []string{"file"}) {
		t.Fatal("repetition changed file-only signal destinations")
	}
	var groups struct {
		Groups []struct {
			Scenario  string `json:"scenario"`
			N         int    `json:"requested_executions"`
			K         int    `json:"completed_executions"`
			Outcome   string `json:"outcome"`
			Sequences []int  `json:"case_sequences"`
		} `json:"repetition_groups"`
	}
	groupBytes, groupReadErr := json.Marshal(run)
	if groupReadErr != nil || json.Unmarshal(groupBytes, &groups) != nil || len(groups.Groups) != 1 {
		t.Error("scenario repetition accounting absent")
	} else {
		g := groups.Groups[0]
		if g.Scenario != scenario || g.N != 3 || g.K != 3 || g.Outcome != "passed" || !slices.Equal(g.Sequences, []int{1, 2, 3}) {
			t.Error("auxiliary smoke changed requested/complete accounting", g)
		}
	}
	workers := map[string]bool{}
	deliveryLoss := false
	traceRoots := map[string]bool{}
	for index, result := range run.Scenarios {
		if result.Outcome != "passed" || !result.CorrectnessPassed || result.Writer == nil {
			t.Fatal("selected execution missing", index)
		}
		if index == 0 {
			if !result.Smoke || result.Repetition != 0 {
				t.Fatal("auxiliary smoke entered selected repetitions")
			}
		} else if result.Scenario != scenario || result.Smoke || result.Repetition != index || result.Fixture.Members != 2 || result.Fixture.SmallValueBytes != 1 {
			t.Fatal("selected repeated fixture changed", index)
		}
		writerRoot := ""
		for _, worker := range scenarioWorkers(result) {
			if workers[worker.Worker] || worker.Worker == "" || !worker.Joined || worker.Process != "passed" || worker.Outcome != "passed" {
				t.Fatal("worker identity/result reused", worker.Worker)
			}
			workers[worker.Worker] = true
			if len(worker.Deliveries) != 3 {
				t.Fatal("worker file delivery facts incomplete")
			}
			files := map[string]bool{}
			for _, signal := range []string{"logs", "metrics", "traces"} {
				path := filepath.Join(outputs[worker.Worker], "telemetry", signal+".jsonl")
				body, readErr := os.ReadFile(path)
				delivery := worker.Deliveries[signal+".file"]
				if os.IsNotExist(readErr) && delivery.Written != nil && *delivery.Written == 0 {
					continue
				}
				info, statErr := os.Lstat(path)
				if readErr != nil || statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != int64(len(body)) {
					t.Fatal("current telemetry output unavailable", worker.Worker, signal, readErr, statErr)
				}
				files[signal] = true
				if worker.Role == "writer" && signal == "traces" {
					for _, line := range bytes.Split(bytes.TrimSpace(body), []byte{'\n'}) {
						var message struct {
							ResourceSpans []struct {
								ScopeSpans []struct {
									Spans []struct {
										Name         string `json:"name"`
										TraceID      string `json:"traceId"`
										SpanID       string `json:"spanId"`
										ParentSpanID string `json:"parentSpanId"`
										Attributes   []struct {
											Key   string `json:"key"`
											Value struct {
												StringValue string `json:"stringValue"`
											} `json:"value"`
										} `json:"attributes"`
									} `json:"spans"`
								} `json:"scopeSpans"`
							} `json:"resourceSpans"`
						}
						// The file exporter records hexadecimal OTLP IDs.
						// Generic protobuf JSON would decode these as base64.
						if err := json.Unmarshal(line, &message); err != nil {
							t.Fatal("retained trace payload invalid", err)
						}
						for _, resource := range message.ResourceSpans {
							for _, scope := range resource.ScopeSpans {
								for _, span := range scope.Spans {
									if span.Name != "worker.invocation" {
										continue
									}
									workerID, runID := "", ""
									for _, attribute := range span.Attributes {
										switch attribute.Key {
										case "worker.id":
											workerID = attribute.Value.StringValue
										case "invocation.id":
											runID = attribute.Value.StringValue
										}
									}
									id := span.TraceID + "/" + span.SpanID
									if workerID != worker.Worker || runID != run.RunID || !hexString(span.TraceID, 32) || !hexString(span.SpanID, 16) || span.ParentSpanID != "" || writerRoot != "" || traceRoots[id] {
										t.Fatal("trace invocation was reused or lost its execution identity")
									}
									writerRoot = id
									traceRoots[id] = true
								}
							}
						}
					}
				}
			}
			for _, signal := range []string{"logs", "metrics", "traces"} {
				delivery := worker.Deliveries[signal+".file"]
				if delivery.Accepted == nil || delivery.Written == nil || delivery.Dropped == nil || delivery.Failed == nil || delivery.Incomplete == nil || *delivery.Accepted != *delivery.Written || *delivery.Failed != 0 {
					t.Fatal("file delivery lacks actual retained counters", worker.Worker, signal)
				}
				if *delivery.Written > 0 && !files[signal] {
					t.Fatal("delivered signal lost retained bytes", signal)
				}
				if signal != "logs" && (*delivery.Written == 0 || signal == "traces" && (*delivery.Dropped != 0 || delivery.EvidenceIncomplete())) {
					t.Fatalf("measurement signal not delivered: scenario_index=%d role=%s worker=%s signal=%s accepted=%d written=%d dropped=%d failed=%d incomplete=%t", index, worker.Role, worker.Worker, signal, *delivery.Accepted, *delivery.Written, *delivery.Dropped, *delivery.Failed, *delivery.Incomplete)
				}
				if signal == "logs" || signal == "metrics" {
					if *delivery.Incomplete != (*delivery.Dropped != 0) {
						t.Fatal("counted loss and delivery status differ", worker.Worker, signal)
					}
					deliveryLoss = deliveryLoss || *delivery.Dropped != 0
				}
			}
		}
		if writerRoot == "" {
			t.Fatal("real writer trace root missing", index)
		}
	}
	snapshots, _ := combineTelemetry(true, state.snapshots...)
	if len(snapshots) == 0 {
		t.Fatal("current observation snapshots unavailable")
	}
	observed := map[string]bool{}
	for _, snapshot := range snapshots {
		if snapshot.RunID != run.RunID || !workers[snapshot.Worker] || snapshot.Resource["service.name"] != "enkv" {
			t.Fatal("snapshot lost actual worker/resource identity")
		}
		for _, metric := range snapshot.Metrics {
			invocationOnly := metric.Attributes["provider"] == "worker" && metric.Attributes["operation"] == "worker.invocation"
			positive := metric.Value != nil && *metric.Value > 0 || metric.Count != nil && *metric.Count > 0
			if snapshot.Status == "complete" && !invocationOnly && positive {
				observed[snapshot.Worker] = true
			}
		}
	}
	for _, result := range run.Scenarios {
		if !observed[result.Writer.Worker] {
			t.Fatal("writer has no retained positive complete observation", result.Writer.Worker)
		}
	}
	wantStatus, wantFailure := "complete", ""
	if deliveryLoss {
		wantStatus, wantFailure = "incomplete", "worker_evidence_incomplete"
	}
	if run.Telemetry.Status != wantStatus || run.Telemetry.FailureClass != wantFailure {
		t.Fatal("run telemetry status differs from counted loss")
	}
	if err := state.finishCurrentRun(io.Discard, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(directory); !os.IsNotExist(err) {
		t.Error("telemetry consumers joined but current files remain", err)
	}
}

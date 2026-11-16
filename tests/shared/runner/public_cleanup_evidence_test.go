package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
)

// The controlled cleanup worker copies these local protocol fixtures. They
// establish evidence-owner behavior, not a cloud observation or Product pass.
func publicCleanupEvidenceFixture(t *testing.T, provider, recovery string) (*runState, recoveryPlan, map[string][]byte) {
	t.Helper()
	const scenario = "public-configuration.empty-initialization/empty_initialization"
	old := publicEvidenceDisposalFixtureForScenario(t, 1, scenario)
	_, _, selected := publicCleanupFixture(t, provider, recovery)
	old.run.record.Provider, old.run.record.Target = provider, provider
	old.run.record.Schedule.RecoveryMode, old.run.record.Resolved.RecoveryMode, old.run.record.Resolved.Provider = recovery, recovery, provider
	input := selected.Input
	input.RunID, input.Prefix = old.run.record.RunID, old.prefix
	input.PublicConfiguration.Artifact = old.participants.input.PublicConfiguration.Artifact
	inputBody, err := json.Marshal(input)
	if err != nil || records.WriteJSON(old.participants.writer.Input, input, 0400) != nil {
		t.Fatal("original cleanup-only input unavailable", err)
	}
	cleanupInputPath := filepath.Join(old.state, "cleanup-input.json")
	if records.WriteJSON(cleanupInputPath, input, 0400) != nil {
		t.Fatal("original role-owned cleanup input unavailable")
	}
	if os.MkdirAll(filepath.Join(old.state, "public-source"), 0700) != nil {
		t.Fatal("original cleanup-only source owner unavailable")
	}
	source := filepath.Join(old.state, "public-source", "configuration.json")
	if os.WriteFile(source, []byte("{\"schema\":\"enkv/configuration/v1\"}\n"), 0600) != nil {
		t.Fatal("original selector-only source unavailable")
	}
	build := filepath.Join(old.run.private, "build")
	if os.MkdirAll(build, 0700) != nil {
		t.Fatal("retained original build owner unavailable")
	}
	retainedMap := controlledFailureSources(t, build)
	mapBody, err := os.ReadFile(retainedMap.Path)
	if err != nil {
		t.Fatal(err)
	}
	ephemeral := filepath.Join(t.TempDir(), "failure-sources.json")
	if os.WriteFile(ephemeral, mapBody, 0400) != nil {
		t.Fatal("original ephemeral source map unavailable")
	}
	origin := old.result
	origin.Outcome, origin.CorrectnessPassed = "failed", false
	origin.Failure = &records.Failure{Class: "writer_failed", Stage: "writer"}
	origin.PostExit = nil
	if os.RemoveAll(filepath.Join(old.state, "workers", "fresh-0000-after")) != nil {
		t.Fatal("unused original reader fixture could not be removed")
	}
	origin.BudgetReserved = &records.BudgetReservation{Requests: 128, BodyBytes: 16 << 20, Objects: 16, ObjectBytes: 8 << 20}
	origin.Cleanup = records.Cleanup{Outcome: "unresolved", Failure: &records.Failure{Class: "cleanup_unresolved", Stage: "cleanup"}, BudgetReserved: &records.BudgetReservation{Requests: 2, BodyBytes: 1 << 20}}
	origin.WorkloadElapsed, origin.CleanupElapsed = time.Second, time.Second
	for _, worker := range []*workerEvidence{origin.Writer, origin.CleanupWorker} {
		worker.Outcome, worker.Process = "failed", "process_failed"
		actorRole := worker.Role
		if actorRole == "writer" {
			actorRole = "authority"
		}
		worker.Actor = input.Participants[actorRole]
		route := "writer"
		phase, sequence, completed := "transition", uint64(2), records.CompletedCheckpoint{Code: "setup", Sequence: 1}
		if worker.Role == "cleanup" {
			route, phase, sequence, completed = "cleanup", "cleanup", 1, records.CompletedCheckpoint{Code: "none"}
		}
		path := filepath.Join(old.state, "workers", route, "invocation.json")
		var inv records.Invocation
		if records.ReadJSON(path, &inv) != nil {
			t.Fatal("original invocation fixture unavailable")
		}
		inv.FailureSources = &records.FailureSourceBinding{Path: ephemeral, SHA256: retainedMap.SHA256}
		if inv.Role == "writer" {
			inv.RecoveryMode = recovery
		} else {
			inv.Input = cleanupInputPath
		}
		if records.WriteJSON(path, inv, 0400) != nil {
			t.Fatal("original invocation source binding unavailable")
		}
		identity := records.FailureIdentity{SchemaVersion: 1, RunID: inv.RunID, Worker: inv.Worker, Role: inv.Role, Scenario: inv.Scenario, Nonce: inv.Nonce}
		marker := records.FailureMarker{FailureIdentity: identity, Code: "fatal", Source: "tests/shared/runner/coordinator_test.go", Line: 1, Phase: phase, Sequence: sequence, Completed: completed}
		checkpoint := records.FailureCheckpoint{FailureIdentity: identity, Completed: completed}
		if records.WriteJSON(filepath.Join(inv.OutputDir, "failure.json"), marker, 0600) != nil || records.WriteJSON(filepath.Join(inv.OutputDir, "checkpoint.json"), checkpoint, 0600) != nil {
			t.Fatal("original failed assertion fixture unavailable")
		}
		assertions := records.InspectAssertions(inv, false)
		if assertions.Marker != "valid_failure_marker" || assertions.Checkpoint != "valid_checkpoint" {
			t.Fatal("original assertion fixture is not admitted")
		}
		worker.Assertions = &assertions
		raw := records.WorkerResult{SchemaVersion: records.SchemaVersion, RunID: inv.RunID, Worker: inv.Worker, Role: inv.Role, Actor: worker.Actor, Scenario: inv.Scenario, Outcome: "failed", Failure: &records.Failure{Class: "worker_failed", Stage: "execution"}}
		if worker.Role == "cleanup" {
			raw.Cleanup, raw.BudgetReserved = &origin.Cleanup, origin.Cleanup.BudgetReserved
		} else {
			raw.BudgetReserved = origin.BudgetReserved
		}
		if records.WriteJSON(filepath.Join(inv.OutputDir, "worker.json"), raw, 0600) != nil {
			t.Fatal("original failed worker fixture unavailable")
		}
	}
	if os.Remove(ephemeral) != nil {
		t.Fatal("original ephemeral map was not retired")
	}
	capturePath := filepath.Join(old.state, "public-command-1", "capture.jsonl")
	captureBody := []byte("{\"kind\":\"footer\",\"code\":2}\n")
	if os.WriteFile(capturePath, captureBody, 0600) != nil {
		t.Fatal("original failed no-send capture unavailable")
	}
	// Use the existing disposal fixture's fixed binding literal. The shared
	// owner binds exact input bytes; only the live worker computes this digest.
	binding := strings.Repeat("b", 64)
	registration := records.PublicConfigurationCaptureRegistration{Path: capturePath, SHA256: publicEvidenceFixtureDigest(captureBody), Complete: true, ParentWorker: origin.Writer.Worker, ParentNonce: old.participants.writer.Nonce, ParentRole: "writer", Actor: input.Participants["authority"], NativeKind: "cli", ExitCode: 2, Bytes: uint64(len(captureBody))}
	ownership := records.PublicConfigurationOwnership{Version: 1, RunID: input.RunID, Prefix: input.Prefix, Binding: binding, Source: source, PreflightEmpty: true, Captures: []records.PublicConfigurationCaptureRegistration{registration}}
	readerPath := filepath.Join(old.state, "public-command-2", "capture.jsonl")
	readerBody := []byte("{\"kind\":\"footer\"}\n")
	if os.Mkdir(filepath.Dir(readerPath), 0700) != nil || os.WriteFile(readerPath, readerBody, 0600) != nil {
		t.Fatal("writer-owned distinct reader capture unavailable")
	}
	readerRegistration := registration
	readerRegistration.Ordinal, readerRegistration.Path, readerRegistration.Actor, readerRegistration.ExitCode = 1, readerPath, input.Participants["reader"], 0
	readerRegistration.SHA256, readerRegistration.Bytes = publicEvidenceFixtureDigest(readerBody), uint64(len(readerBody))
	ownership.Captures = append(ownership.Captures, readerRegistration)
	if records.WriteJSON(filepath.Join(old.state, "public-ownership.json"), ownership, 0600) != nil {
		t.Fatal("original no-domain ownership unavailable")
	}
	for _, name := range []string{"public-controlled-inventory.json", "public-controlled-inventory.json.token-evidence.json", "public-cleanup-inventory.json", "public-cleanup-inventory.json.token-evidence.json", "workers/cleanup/public-configuration-evidence.json"} {
		if err := os.Remove(filepath.Join(old.state, filepath.FromSlash(name))); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	domain := contract.Hash([]byte(input.Prefix))
	tokens := records.PublicConfigurationTokenSource{Version: 1, RunID: input.RunID, Prefix: input.Prefix, Binding: binding, Domain: domain}
	tokenBody, err := json.Marshal(tokens)
	if err != nil {
		t.Fatal(err)
	}
	tokenBody = append(tokenBody, '\n')
	cleanup := grantInventory{Version: 1, RunID: input.RunID, Prefix: input.Prefix, Binding: binding, Domain: domain, Deleted: map[string]int{}}
	cleanupBody, err := json.Marshal(cleanup)
	if err != nil {
		t.Fatal(err)
	}
	cleanupBody = append(cleanupBody, '\n')
	ownershipBody, err := os.ReadFile(filepath.Join(old.state, "public-ownership.json"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := records.PublicConfigurationEvidenceSnapshot{Version: 1, RunID: input.RunID, Scenario: scenario, Provider: provider, RecoveryMode: recovery, Prefix: input.Prefix, Binding: binding, PreflightEmpty: true,
		Cleanup:                 records.PublicConfigurationInventoryEvidence{RunID: input.RunID, Prefix: input.Prefix, Binding: binding, Domain: domain, TokenSource: &tokens, OriginalTokenSourceSHA256: publicEvidenceFixtureDigest(tokenBody)},
		OriginalOwnershipSHA256: publicEvidenceFixtureDigest(ownershipBody), OriginalCleanupSHA256: publicEvidenceFixtureDigest(cleanupBody)}
	for _, captured := range ownership.Captures {
		relative, err := filepath.Rel(old.state, captured.Path)
		if err != nil {
			t.Fatal(err)
		}
		snapshot.Captures = append(snapshot.Captures, records.PublicConfigurationCaptureReceipt{Ordinal: captured.Ordinal, ParentWorker: captured.ParentWorker, ParentNonce: captured.ParentNonce,
			ParentRole: captured.ParentRole, Actor: captured.Actor, NativeKind: captured.NativeKind, SourceRelative: filepath.ToSlash(relative), Complete: captured.Complete, ExitCode: captured.ExitCode, SHA256: captured.SHA256, Bytes: captured.Bytes})
	}
	if records.WritePublicConfigurationEvidenceSnapshot(filepath.Join(old.state, "controlled-public-cleanup-snapshot.json"), snapshot) != nil ||
		os.WriteFile(filepath.Join(old.state, "controlled-public-cleanup-inventory.json"), cleanupBody, 0600) != nil || os.WriteFile(filepath.Join(old.state, "controlled-public-cleanup-token-source.json"), tokenBody, 0600) != nil {
		t.Fatal("controlled empty cleanup evidence unavailable")
	}
	old.run.record.Limits = input.Limits
	old.run.record.Context = safeRunContext(input.Settings)
	old.run.record.BuildClosure.Suite, old.run.record.BuildClosure.Provider = "live", provider
	old.run.record.BuildClosure.BinarySHA256, old.run.record.BuildClosure.OverlaySHA256, old.run.record.BuildClosure.FailureSourcesSHA256 = strings.Repeat("1", 64), strings.Repeat("2", 64), retainedMap.SHA256
	old.run.record.Outcome, old.run.record.Failure = "failed", &records.Failure{Class: "scenario_failed", Stage: "execution"}
	finished := time.Now().UTC()
	old.run.record.FinishedAt = &finished
	old.result = origin
	old.identity, err = caseIdentitySHA256(old.run.record)
	if err != nil {
		t.Fatal(err)
	}
	sealPublicEvidenceFixture(t, &old)
	request := cleanupRequest{RunID: input.RunID, Limits: filepath.Join(old.run.root, "cleanup-limits.json")}
	if records.WriteJSON(request.Limits, input.Limits, 0600) != nil {
		t.Fatal("cleanup allowance unavailable")
	}
	plan, err := prepareRecovery(old.run.root, request)
	if err != nil {
		t.Fatal("original cleanup-only route is not admissible", err)
	}
	if _, basis, err := prepareFixtureRecovery(old.run.root, request, plan); err != nil || basis != nil {
		t.Fatal("ordinary cleanup unexpectedly requires new authority", err)
	}
	current, err := newRunState(old.run.root, runRequest{Suite: "live", Provider: provider, Target: provider, Profile: "full", Schedule: recoverySchedule(plan)}, records.Source{Revision: strings.Repeat("b", 40)}, "controlled")
	if err != nil {
		t.Fatal(err)
	}
	current.record.RecoveryRunID, current.record.Limits = input.RunID, &plan.Limits
	current.record.Context, current.record.CoverageScope = safeRunContext(plan.Settings), "live_scenarios"
	current.failureSources = controlledFailureSources(t, current.private)
	current.record.BuildClosure = &assemblyClosure{Suite: "live", Provider: provider, BinarySHA256: strings.Repeat("1", 64), OverlaySHA256: strings.Repeat("2", 64), FailureSourcesSHA256: current.failureSources.SHA256, PublicConfiguration: old.run.record.BuildClosure.PublicConfiguration}
	originals := map[string][]byte{}
	for _, path := range []string{filepath.Join(old.run.directory, "run.json"), filepath.Join(old.run.directory, "cases", "0000.json"), old.participants.writer.Input, cleanupInputPath, source, filepath.Join(old.state, "public-ownership.json"), capturePath, readerPath, retainedMap.Path} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		originals[path] = body
	}
	if !bytes.Equal(originals[old.participants.writer.Input], append(inputBody, '\n')) || snapshot.Validate(records.PublicConfigurationEvidenceBinding{RunID: input.RunID, Scenario: scenario, Provider: provider, RecoveryMode: recovery, Prefix: input.Prefix, Binding: binding}) != nil {
		t.Fatal("independent origin/snapshot fixture is not valid")
	}
	return current, plan, originals
}

// full_only: false
func TestPublicCleanupOnlyEvidenceSurvivesFinalizationAndReopen(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "")
	s, plan, originals := publicCleanupEvidenceFixture(t, "gcp", "disabled")
	binary, err := os.Executable()
	if err == nil {
		err = s.executeRecovery(t.Context(), binary, plan)
	}
	if err != nil {
		t.Fatal("controlled exact cleanup did not join", err)
	}
	s.finish()
	if err := s.finishCurrentRun(io.Discard, nil); err != nil {
		t.Fatal("joined public cleanup lost its evidence during real finalization", err)
	}
	if len(s.record.Scenarios) != 1 || s.record.Outcome != "passed" || s.record.Correctness.Passed || s.record.FullCoverage {
		t.Fatal("cleanup-only recovery changed Product completion")
	}
	result := s.record.Scenarios[0]
	if result.Writer != nil || result.CorrectnessPassed || len(result.Children)+len(result.PostExit) != 0 || result.PublicConfigurationEvidence == nil || !cleanupPassed(result.Cleanup) {
		t.Fatal("cleanup-only recovery fabricated lifecycle evidence or lost its retained proof")
	}
	var saved runRecord
	if records.ReadJSON(filepath.Join(s.directory, "run.json"), &saved) != nil || readPublicConfigurationEvidence(s.directory, saved, saved.Scenarios[0]) != nil {
		t.Fatal("finalized public cleanup proof could not reopen")
	}
	for path, before := range originals {
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("cleanup changed an original failed Product record", err)
		}
	}
	for _, path := range []string{s.private, filepath.Dir(plan.Entries[0].State)} {
		if err := os.Rename(path, path+"-unavailable"); err != nil {
			t.Fatal("local private-disposal fixture unavailable", err)
		}
	}
	if readPublicConfigurationEvidence(s.directory, saved, saved.Scenarios[0]) != nil {
		t.Fatal("retained cleanup proof depended on disposed original or new private files")
	}
}

// full_only: false
func TestPublicCleanupOnlyEvidenceRejectsBrokenOriginAndSnapshot(t *testing.T) {
	for _, condition := range []string{"missing-map", "wrong-original-entry", "unjoined-origin", "missing-cleanup-input", "foreign-child-actor", "snapshot-owner", "unowned-no-domain-object"} {
		t.Run(condition, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "")
			s, plan, _ := publicCleanupEvidenceFixture(t, "gcp", "disabled")
			state := plan.Entries[0].State
			originPath := filepath.Join(filepath.Dir(filepath.Dir(state)), "run.json")
			var original runRecord
			if records.ReadJSON(originPath, &original) != nil {
				t.Fatal("original negative fixture unavailable")
			}
			beforeDispatch := true
			switch condition {
			case "missing-map":
				if os.Remove(filepath.Join(filepath.Dir(filepath.Dir(state)), "private", "build", "failure-sources.json")) != nil {
					t.Fatal("source-map damage unavailable")
				}
			case "wrong-original-entry":
				original.Scenarios[0].Sequence++
				if records.WriteJSON(originPath, original, 0600) != nil {
					t.Fatal("original entry damage unavailable")
				}
			case "unjoined-origin":
				original.Scenarios[0].CleanupWorker.Joined = false
				if records.WriteJSON(originPath, original, 0600) != nil {
					t.Fatal("original join damage unavailable")
				}
			case "missing-cleanup-input":
				if os.Remove(filepath.Join(state, "cleanup-input.json")) != nil {
					t.Fatal("original input damage unavailable")
				}
			case "foreign-child-actor":
				path := filepath.Join(state, "public-ownership.json")
				var owner records.PublicConfigurationOwnership
				if records.ReadJSON(path, &owner) != nil {
					t.Fatal("original actor fixture unavailable")
				}
				owner.Captures[1].Actor = "unselected"
				if records.WriteJSON(path, owner, 0600) != nil {
					t.Fatal("original actor damage unavailable")
				}
			default:
				beforeDispatch = false
				path := filepath.Join(state, "controlled-public-cleanup-snapshot.json")
				var snapshot records.PublicConfigurationEvidenceSnapshot
				if records.ReadJSON(path, &snapshot) != nil {
					t.Fatal("snapshot damage fixture unavailable")
				}
				if condition == "snapshot-owner" {
					snapshot.Prefix += "/foreign"
				} else {
					key := snapshot.Prefix + "/" + strings.Repeat("d", 64) + "/root/0/" + strings.Repeat("e", 64)
					digest := strings.Repeat("f", 64)
					token := records.PublicConfigurationToken{Family: contract.GCP, Value: []byte("9")}
					tokens := *snapshot.Cleanup.TokenSource
					tokens.Observations = []records.PublicConfigurationTokenObservation{{Kind: "cleanup-condition", Index: 0, TargetIntent: 0, AttemptOrdinal: 1, Key: key, Digest: digest, Bytes: 1, Token: token}}
					tokenBody, _ := json.Marshal(tokens)
					tokenBody = append(tokenBody, '\n')
					image := map[string]any{"version": 1, "run_id": snapshot.RunID, "prefix": snapshot.Prefix, "binding": snapshot.Binding, "domain": snapshot.Cleanup.Domain,
						"intents": []any{map[string]any{"key": key, "digest": digest, "bytes": 1, "kind": "fixture_create", "state": "acknowledged"}}, "deleted": map[string]int{key: 1},
						"cleanup_attempts": []any{map[string]any{"target_intent": 0, "ordinal": 1, "key": key, "digest": digest, "bytes": 1, "token": map[string]any{"Family": 2, "Value": "9"}, "cutoff": 0, "state": "acknowledged"}}}
					imageBody, _ := json.Marshal(image)
					imageBody = append(imageBody, '\n')
					snapshot.Cleanup.Intents = []records.PublicConfigurationObjectIntent{{Key: key, Digest: digest, Bytes: 1, Kind: "fixture_create", State: "acknowledged"}}
					snapshot.Cleanup.Deleted = []records.PublicConfigurationDeleted{{Key: key, Cutoff: 1}}
					snapshot.Cleanup.CleanupAttempts = []records.PublicConfigurationCleanupAttempt{{TargetIntent: 0, Ordinal: 1, Key: key, Digest: digest, Bytes: 1, Token: token, State: "acknowledged"}}
					snapshot.Cleanup.TokenSource, snapshot.Cleanup.OriginalTokenSourceSHA256 = &tokens, publicEvidenceFixtureDigest(tokenBody)
					snapshot.OriginalCleanupSHA256 = publicEvidenceFixtureDigest(imageBody)
					if snapshot.Validate(records.PublicConfigurationEvidenceBinding{RunID: snapshot.RunID, Scenario: snapshot.Scenario, Provider: "gcp", RecoveryMode: "disabled", Prefix: snapshot.Prefix}) != nil ||
						os.WriteFile(filepath.Join(state, "controlled-public-cleanup-inventory.json"), imageBody, 0600) != nil || os.WriteFile(filepath.Join(state, "controlled-public-cleanup-token-source.json"), tokenBody, 0600) != nil {
						t.Fatal("internally consistent unowned-inventory fixture unavailable")
					}
				}
				if records.WriteJSON(path, snapshot, 0600) != nil {
					t.Fatal("snapshot damage unavailable")
				}
			}
			binary, err := os.Executable()
			if err != nil || s.executeRecovery(t.Context(), binary, plan) == nil {
				t.Fatal("broken original or snapshot admitted cleanup completion", err)
			}
			if _, err := os.Stat(filepath.Join(state, "cleanup-called.json")); beforeDispatch && !os.IsNotExist(err) {
				t.Fatal("bad original evidence reached cleanup dispatch", err)
			}
			if s.record.Correctness.Passed || len(s.record.Scenarios) != 1 || s.record.Scenarios[0].Writer != nil || s.record.Scenarios[0].PublicConfigurationEvidence != nil {
				t.Fatal("failed proof fabricated a Product pass or retained successful evidence")
			}
		})
	}
}

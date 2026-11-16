package main

import (
	"bytes"
	"context"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

func publicCleanupFixture(t *testing.T, provider, recovery string) (string, cleanupRequest, recoveryEntry) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var environment environmentFile
	if err := readSelectionFile(filepath.Join(maintainedCloudflareRoot(t), "tests/environments/public-"+provider+".example.json"), &environment); err != nil {
		t.Fatal(err)
	}
	if err := selectRecoveryMode(&environment, recovery); err != nil {
		t.Fatal(err)
	}
	allowance := testLimits()
	request := cleanupRequest{RunID: strings.Repeat("d", 32), Limits: filepath.Join(root, "limits.json")}
	scenario := "public-configuration.empty-initialization/empty_initialization"
	name, err := recordedCaseDirectory(catalog.Entry{Scenario: scenario})
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "tests/live/runs", request.RunID, "private", name)
	if err := os.MkdirAll(state, 0700); err != nil {
		t.Fatal(err)
	}
	actors := map[string]liveSettings{}
	for _, role := range []string{"authority", "reader", "cleanup"} {
		settings, err := environment.publicConfigurationSettings(role)
		if err != nil {
			t.Fatal(err)
		}
		actors[role] = settings
	}
	input := workerInput{Settings: maps.Clone(actors["authority"]), Limits: &allowance,
		Scenarios: []string{scenario}, Repetitions: 1, RunID: request.RunID,
		Prefix: "enkv-test/" + request.RunID + "/0000", RecoveryMode: recovery,
		Participants:        map[string]string{"authority": "initializer", "reader": "auditor", "cleanup": "janitor"},
		PublicConfiguration: &publicConfigurationInput{Actors: actors}}
	entry := recoveryEntry{State: state, InputPath: filepath.Join(state, "input.json"), Input: input}
	if records.WriteJSON(request.Limits, allowance, 0600) != nil || records.WriteJSON(entry.InputPath, input, 0400) != nil ||
		records.WriteJSON(filepath.Join(state, "public-ownership.json"), map[string]int{"schema_version": 1}, 0600) != nil {
		t.Fatal("public cleanup fixture")
	}
	return root, request, entry
}

// full_only: false
func TestPublicCleanupPreparationRetainsSelectorOnlySDKInputs(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		for _, recovery := range []string{"disabled", "enabled"} {
			t.Run(provider+"/"+recovery, func(t *testing.T) {
				root, request, entry := publicCleanupFixture(t, provider, recovery)
				before, err := os.ReadFile(entry.InputPath)
				if err != nil {
					t.Fatal(err)
				}
				plan, err := prepareRecovery(root, request)
				if err != nil || plan.Provider != provider || len(plan.Entries) != 1 || !reflect.DeepEqual(plan.Settings, entry.Input.Settings) || !reflect.DeepEqual(plan.Entries[0].Input, entry.Input) {
					t.Fatal("public cleanup required injected credentials or changed retained routes", err)
				}
				if plan.Settings["credentials_file"] != "" || plan.Settings["public_key_pem"] != "" {
					t.Fatal("public cleanup introduced private fixture inputs")
				}
				after, err := os.ReadFile(entry.InputPath)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("public cleanup changed original ownership input", err)
				}
			})
		}
	}
}

// full_only: false
func TestPublicCleanupPreparationRefusesIncompleteOrChangedRoutes(t *testing.T) {
	for _, condition := range []string{"missing_public_input", "missing_cleanup_participant", "invalid_cleanup_participant", "missing_cleanup_actor", "extra_actor", "wrong_actor_provider", "wrong_actor_bucket", "wrong_actor_key", "relative_actor_home", "wrong_sdk_provider", "invalid_resource", "replacement_environment"} {
		t.Run(condition, func(t *testing.T) {
			root, request, entry := publicCleanupFixture(t, "gcp", "enabled")
			input := entry.Input
			switch condition {
			case "missing_public_input":
				input.PublicConfiguration = nil
			case "missing_cleanup_participant":
				delete(input.Participants, "cleanup")
			case "invalid_cleanup_participant":
				input.Participants["cleanup"] = "../authority"
			case "missing_cleanup_actor":
				delete(input.PublicConfiguration.Actors, "cleanup")
			case "extra_actor":
				input.PublicConfiguration.Actors["unselected"] = maps.Clone(input.Settings)
			case "wrong_actor_provider":
				input.PublicConfiguration.Actors["cleanup"]["provider"] = "aws"
			case "wrong_actor_bucket":
				input.PublicConfiguration.Actors["cleanup"]["bucket"] = "other-bucket"
			case "wrong_actor_key":
				input.PublicConfiguration.Actors["cleanup"]["authority_kek_id"] = input.Settings["reader_kek_id"]
			case "relative_actor_home":
				input.PublicConfiguration.Actors["cleanup"]["sdk_home"] = "relative-home"
			case "wrong_sdk_provider":
				input.PublicConfiguration.Actors["cleanup"]["sdk_mode"] = "aws-sso"
			case "invalid_resource":
				input.Settings["bucket"] = "invalid/bucket"
			case "replacement_environment":
				request.Environment = filepath.Join(root, "must-not-open-environment.json")
			}
			if err := records.WriteJSON(entry.InputPath, input, 0400); err != nil {
				t.Fatal(err)
			}
			if _, err := prepareRecovery(root, request); err == nil {
				t.Fatal("invalid public cleanup reached assembly admission")
			}
			children, err := os.ReadDir(filepath.Join(root, "tests/live/runs"))
			if err != nil || len(children) != 1 {
				t.Fatal("invalid public cleanup created a new run", err)
			}
		})
	}
}

// full_only: false
func TestPublicCleanupDispatchRequiresItsOwnRegularOwnershipLedger(t *testing.T) {
	for _, condition := range []string{"public_only", "missing_public", "directory_public", "symlink_public"} {
		t.Run(condition, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "")
			root, _, entry := publicCleanupFixture(t, "gcp", "disabled")
			ledger := filepath.Join(entry.State, "public-ownership.json")
			if condition != "public_only" {
				if os.Remove(ledger) != nil || records.WriteJSON(filepath.Join(entry.State, "inventory.json"), struct{}{}, 0600) != nil {
					t.Fatal("legacy inventory fixture")
				}
				switch condition {
				case "directory_public":
					if err := os.Mkdir(ledger, 0700); err != nil {
						t.Fatal(err)
					}
				case "symlink_public":
					if err := os.Symlink(filepath.Join(entry.State, "inventory.json"), ledger); err != nil {
						t.Fatal(err)
					}
				}
			}
			scenario := entry.Input.Scenarios[0]
			plan := recoveryPlan{Entries: []recoveryEntry{entry}}
			s, err := newRunState(root, runRequest{Suite: "live", Provider: "gcp", Target: "gcp", Schedule: recoverySchedule(plan)}, records.Source{}, "controlled")
			if err != nil {
				t.Fatal(err)
			}
			inv, err := makeInvocation(records.Invocation{Scenario: scenario, RunID: s.record.RunID, Worker: "public-cleanup", Role: "cleanup", Input: entry.InputPath, StateDir: entry.State, OutputDir: filepath.Join(s.private, "cleanup"), FailureSources: controlledFailureSources(t, s.private)}, "live")
			if err != nil {
				t.Fatal(err)
			}
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			joined, cleanup := s.executeCleanup(context.Background(), binary, inv, scenario, testLimits())
			_, markerErr := os.Lstat(filepath.Join(entry.State, "cleanup-called.json"))
			if condition == "public_only" {
				if joined == nil || !joined.Joined || joined.Process != "passed" || joined.Outcome != "passed" || joined.Actor != "janitor" || !cleanupPassed(cleanup) || markerErr != nil {
					t.Fatal("public ledger did not dispatch and join the selected cleanup actor", joined, cleanup, markerErr)
				}
			} else if joined != nil || cleanupPassed(cleanup) || !os.IsNotExist(markerErr) {
				t.Fatal("legacy inventory bypassed public ownership refusal", joined, cleanup, markerErr)
			}
		})
	}
}

// full_only: false
func TestPublicCleanupRecoveryPreservesAllOriginalRoutesAndOwnership(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "")
	s, plan, _ := publicCleanupEvidenceFixture(t, "aws", "enabled")
	request, entry := cleanupRequest{RunID: s.record.RecoveryRunID}, plan.Entries[0]
	original, err := os.ReadFile(entry.InputPath)
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.executeRecovery(t.Context(), binary, plan); err != nil {
		t.Fatal(err)
	}
	s.finish()
	name, err := recordedCaseDirectory(catalog.Entry{Scenario: entry.Input.Scenarios[0]})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := records.LoadInvocation(filepath.Join(s.private, name, "cleanup/invocation.json"))
	if err != nil {
		t.Fatal("standalone cleanup invocation unavailable", err)
	}
	var input workerInput
	if err := records.ReadJSON(inv.Input, &input); err != nil {
		t.Fatal(err)
	}
	if inv.RunID == request.RunID || inv.StateDir != entry.State || input.RunID != request.RunID || input.Prefix != entry.Input.Prefix ||
		!reflect.DeepEqual(input.Participants, entry.Input.Participants) || !reflect.DeepEqual(input.PublicConfiguration, entry.Input.PublicConfiguration) || !reflect.DeepEqual(input.Settings, entry.Input.Settings) {
		t.Fatal("standalone cleanup changed original ownership or dropped selected SDK actors")
	}
	if len(s.record.Scenarios) != 1 {
		t.Fatal("standalone cleanup created extra Product work")
	}
	result := s.record.Scenarios[0]
	if result.Writer != nil || len(result.Children) != 0 || len(result.PostExit) != 0 || result.CorrectnessPassed || s.record.Correctness.Passed || s.record.FullCoverage || s.record.Outcome != "passed" || result.CleanupWorker == nil || result.CleanupWorker.Actor != "janitor" || !result.CleanupWorker.Joined || !cleanupPassed(result.Cleanup) {
		t.Fatal("standalone public cleanup resumed Product work or lost selected cleanup evidence")
	}
	after, err := os.ReadFile(entry.InputPath)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("standalone cleanup changed retained input", err)
	}
}

// full_only: false
func TestPublicCleanupRecoveryRequiresOriginalRunAndPositiveJoins(t *testing.T) {
	for _, condition := range []string{"joined_failed_writer", "missing_writer", "unstarted_writer", "unjoined_writer", "unjoined_child", "unjoined_fresh_after", "unjoined_cleanup", "unjoined_cleanup_attempt", "wrong_run", "wrong_provider", "wrong_scenario", "wrong_directory", "unfinished"} {
		t.Run(condition, func(t *testing.T) {
			root, request, entry := publicCleanupFixture(t, "gcp", "enabled")
			plan := recoveryPlan{Provider: "gcp", Settings: entry.Input.Settings, Limits: *entry.Input.Limits, Entries: []recoveryEntry{entry}}
			finished := time.Date(2026, 10, 19, 1, 2, 3, 0, time.UTC)
			result := scenarioResult{Entry: catalog.Entry{Scenario: entry.Input.Scenarios[0]}, Outcome: "failed",
				Writer:          &workerEvidence{Role: "writer", Started: true, Joined: true, Outcome: "failed", Process: "failed"},
				PostExit:        []workerEvidence{{Role: "fresh_after", Started: true, Joined: true}},
				CleanupWorker:   &workerEvidence{Role: "cleanup", Started: true, Joined: true},
				CleanupAttempts: []cleanupAttemptEvidence{{Ordinal: 1, Worker: &workerEvidence{Role: "cleanup", Started: true, Joined: true}}}}
			original := runRecord{SchemaVersion: records.SchemaVersion, RunID: request.RunID, Suite: "live", Provider: "gcp",
				FinishedAt: &finished, Outcome: "failed", Failure: &records.Failure{Class: "scenario_failed", Stage: "execution"},
				Scenarios: []scenarioResult{result}}
			switch condition {
			case "missing_writer":
				original.Scenarios[0].Writer = nil
			case "unstarted_writer":
				original.Scenarios[0].Writer.Started = false
			case "unjoined_writer":
				original.Scenarios[0].Writer.Joined = false
			case "unjoined_child":
				original.Scenarios[0].Children = []workerEvidence{{Role: "fresh_before", Started: true}}
			case "unjoined_fresh_after":
				original.Scenarios[0].PostExit[0].Joined = false
			case "unjoined_cleanup":
				original.Scenarios[0].CleanupWorker.Joined = false
			case "unjoined_cleanup_attempt":
				original.Scenarios[0].CleanupAttempts[0].Worker.Joined = false
			case "wrong_run":
				original.RunID = strings.Repeat("e", 32)
			case "wrong_provider":
				original.Provider = "aws"
			case "wrong_scenario":
				original.Scenarios[0].Scenario = "public-configuration.normal-signing-denied/normal_signing_denied"
			case "wrong_directory":
				name, err := recordedCaseDirectory(catalog.Entry{Scenario: entry.Input.Scenarios[0], Sequence: 1})
				if err != nil {
					t.Fatal(err)
				}
				plan.Entries[0].State = filepath.Join(filepath.Dir(entry.State), name)
			case "unfinished":
				original.FinishedAt = nil
			}
			if err := records.WriteJSON(filepath.Join(root, "tests/live/runs", request.RunID, "run.json"), original, 0600); err != nil {
				t.Fatal(err)
			}
			got, basis, err := prepareFixtureRecovery(root, request, plan)
			if condition == "joined_failed_writer" {
				if err != nil || basis != nil || !reflect.DeepEqual(got, plan) {
					t.Fatal("complete failed Product work could not receive cleanup-only recovery", err)
				}
			} else if err == nil {
				t.Fatal("public cleanup admitted unjoined or unrelated original work")
			}
		})
	}
}

// full_only: false
func TestPublicCleanupRequiresEveryImpersonatedQuota(t *testing.T) {
	for _, role := range []string{"authority", "reader", "cleanup"} {
		for _, quota := range []string{"selected-project", "", "another-project"} {
			t.Run(role+"/quota="+quota, func(t *testing.T) {
				root, request, entry := publicCleanupFixture(t, "gcp", "enabled")
				for _, actor := range entry.Input.PublicConfiguration.Actors {
					actor["sdk_mode"], actor["sdk_quota_project"], actor["quota_project"] = "gcp-impersonated-adc", "selected-project", "selected-project"
				}
				entry.Input.PublicConfiguration.Actors[role]["sdk_quota_project"] = quota
				entry.Input.Settings = maps.Clone(entry.Input.PublicConfiguration.Actors["authority"])
				if err := records.WriteJSON(entry.InputPath, entry.Input, 0400); err != nil {
					t.Fatal(err)
				}
				plan, err := prepareRecovery(root, request)
				if quota != "selected-project" {
					if err == nil {
						t.Fatal("cleanup admitted a mismatched impersonated quota")
					}
					return
				}
				if err != nil || len(plan.Entries) != 1 || !reflect.DeepEqual(plan.Entries[0].Input, entry.Input) {
					t.Fatal("cleanup changed the selected impersonated quota or actor routes", err)
				}
			})
		}
	}
}

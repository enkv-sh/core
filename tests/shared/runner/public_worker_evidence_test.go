package main

import (
	"maps"
	"path/filepath"
	"reflect"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

func publicWorkerParticipants(condition, recovery string) map[string]string {
	switch condition {
	case "credential-discovery":
		return map[string]string{"authority": "operator", "apply": "operator", "reader": "operator", "consumer": "operator", "cleanup": "operator"}
	case "normal-signing-denied":
		return map[string]string{"authority": "initializer", "denied-normal-signing": "denied-signer", "reader": "auditor", "cleanup": "janitor"}
	case "prepare-complete-loss":
		return map[string]string{"authority": "initializer", "apply": "editor", "reader": "auditor", "consumer": "application", "cleanup": "janitor"}
	case "portable-validation":
		participants := map[string]string{"authority": "initializer", "apply": "editor", "reader": "auditor", "consumer": "application", "cleanup": "janitor"}
		if recovery == "enabled" {
			participants["successor"] = "successor"
		}
		return participants
	default:
		panic("unknown public evidence fixture")
	}
}

// Literal observations follow the public worker entry points, independently of
// the coordinator's phase-shape construction.
func publicWorkerResult(scenario, role string, participants map[string]string) records.WorkerResult {
	result := records.WorkerResult{Scenario: scenario, Role: role, Outcome: "passed"}
	switch role {
	case "writer":
		result.Actor = participants["authority"]
		result.Phases = []records.PhaseResult{
			{Sequence: 1, Name: "setup", Outcome: "passed", MeasurementsExpected: true, Actor: result.Actor, Expected: "selector-only-source-and-exact-roles-ready", Actual: "selector-only-source-and-exact-roles-ready"},
			{Sequence: 2, Name: "transition", Outcome: "passed", MeasurementsExpected: true, Actor: result.Actor, Expected: "joined-public-configuration-actions-exact", Actual: "joined-public-configuration-actions-exact"},
			{Sequence: 3, Name: "verification", Outcome: "passed", MeasurementsExpected: true, Actor: result.Actor, Expected: "independent-public-private-and-source-facts-exact", Actual: "independent-public-private-and-source-facts-exact"},
		}
		result.FreshChecks = []records.FreshCheck{{Facts: "after.json"}}
	case "fresh_after":
		result.Actor = participants["reader"]
		result.Phases = []records.PhaseResult{{Sequence: 1, Name: "reopen", Outcome: "passed", MeasurementsExpected: true, Actor: result.Actor, Expected: "pair-only-independent-public-observation-exact", Actual: "pair-only-independent-public-observation-exact"}}
	case "cleanup":
		result.Actor = participants["cleanup"]
		result.Phases = []records.PhaseResult{{Sequence: 1, Name: "cleanup", Outcome: "passed", MeasurementsExpected: true, Actor: result.Actor, Expected: "success", Actual: "success"}}
		result.Cleanup = &records.Cleanup{Outcome: "passed", RemainingOwnedObjects: new(int64), UnknownEffects: new(int64), BudgetReserved: &records.BudgetReservation{Requests: 5}}
	default:
		panic("unknown public worker role")
	}
	return result
}

// full_only: false
func TestPublicWorkerAdmissionUsesExactPublicPhaseShapes(t *testing.T) {
	for _, condition := range []string{"credential-discovery", "normal-signing-denied", "portable-validation", "prepare-complete-loss"} {
		scenario := "public-configuration." + condition + "/" + map[string]string{"credential-discovery": "credential_discovery", "normal-signing-denied": "normal_signing_denied", "portable-validation": "portable_validation", "prepare-complete-loss": "prepare_complete_loss"}[condition]
		for _, recovery := range []string{"disabled", "enabled"} {
			participants := publicWorkerParticipants(condition, recovery)
			for _, role := range []string{"writer", "fresh_after", "cleanup"} {
				t.Run(condition+"/"+recovery+"/"+role, func(t *testing.T) {
					if !completeWorker(publicWorkerResult(scenario, role, participants), "live", participants, "", nil) {
						t.Fatal("exact public worker observations were refused")
					}
					changes := []struct {
						name   string
						change func(*records.WorkerResult)
					}{
						{"missing_phase", func(r *records.WorkerResult) { r.Phases = r.Phases[:len(r.Phases)-1] }},
						{"wrong_worker_actor", func(r *records.WorkerResult) { r.Actor = "unselected" }},
						{"wrong_phase_actor", func(r *records.WorkerResult) { r.Phases[0].Actor = "unselected" }},
						{"wrong_expected", func(r *records.WorkerResult) { r.Phases[0].Expected = "unavailable" }},
						{"wrong_actual", func(r *records.WorkerResult) { r.Phases[0].Actual = "unavailable" }},
						{"missing_measurement", func(r *records.WorkerResult) { r.Phases[0].MeasurementsExpected = false }},
						{"skipped_phase", func(r *records.WorkerResult) { r.Phases[0].Outcome = "skipped" }},
						{"skipped_worker", func(r *records.WorkerResult) { r.Outcome = "skipped" }},
						{"wrong_recovery_annotation", func(r *records.WorkerResult) { r.Phases[0].RecoveryMode = recovery }},
					}
					if role == "writer" {
						changes = append(changes, struct {
							name   string
							change func(*records.WorkerResult)
						}{"missing_fresh_check", func(r *records.WorkerResult) { r.FreshChecks = nil }})
					}
					if role == "cleanup" {
						changes = append(changes, []struct {
							name   string
							change func(*records.WorkerResult)
						}{
							{"missing_cleanup", func(r *records.WorkerResult) { r.Cleanup = nil }},
							{"unknown_effects", func(r *records.WorkerResult) { *r.Cleanup.UnknownEffects = 1 }},
							{"remaining_objects", func(r *records.WorkerResult) { *r.Cleanup.RemainingOwnedObjects = 1 }},
							{"missing_absence", func(r *records.WorkerResult) { r.Cleanup.RemainingOwnedObjects = nil }},
						}...)
					}
					for _, change := range changes {
						t.Run(change.name, func(t *testing.T) {
							result := publicWorkerResult(scenario, role, participants)
							change.change(&result)
							if completeWorker(result, "live", participants, "", nil) {
								t.Fatal("changed public worker evidence was admitted")
							}
						})
					}
				})
			}
		}
	}
}

// full_only: false
func TestPublicWorkerImportBindsEverySelectedParticipant(t *testing.T) {
	for _, row := range []struct{ condition, scenario string }{
		{"credential-discovery", "public-configuration.credential-discovery/credential_discovery"},
		{"normal-signing-denied", "public-configuration.normal-signing-denied/normal_signing_denied"},
		{"portable-validation", "public-configuration.portable-validation/portable_validation"},
	} {
		for _, recovery := range []string{"disabled", "enabled"} {
			for _, change := range []string{"complete", "missing_cleanup_route", "missing_reader_route", "switched_cleanup_route", "wrong_recovery"} {
				t.Run(row.condition+"/"+recovery+"/"+change, func(t *testing.T) {
					inv, _, _ := telemetryImportFixture(t)
					inv.Scenario, inv.Role, inv.Worker = row.scenario, "cleanup", "cleanup-1"
					participants := publicWorkerParticipants(row.condition, recovery)
					input := workerInput{RecoveryMode: recovery, Participants: maps.Clone(participants), Scenarios: []string{row.scenario}}
					switch change {
					case "missing_cleanup_route":
						delete(input.Participants, "cleanup")
					case "missing_reader_route":
						delete(input.Participants, "reader")
					case "switched_cleanup_route":
						input.Participants["cleanup"] = "unselected"
					case "wrong_recovery":
						input.RecoveryMode = map[string]string{"disabled": "enabled", "enabled": "disabled"}[recovery]
					}
					result := publicWorkerResult(row.scenario, "cleanup", participants)
					result.SchemaVersion, result.RunID, result.Worker = records.SchemaVersion, inv.RunID, inv.Worker
					if err := records.WriteJSON(inv.Input, input, 0400); err != nil {
						t.Fatal(err)
					}
					if err := records.WriteJSON(filepath.Join(inv.OutputDir, "worker.json"), result, 0600); err != nil {
						t.Fatal(err)
					}
					state := &runState{record: runRecord{RunID: inv.RunID, Suite: "live", Resolved: &resolvedRequest{Mode: "live", RecoveryMode: recovery, RoleBindings: participants}}}
					evidence, raw, err := state.importWorker(inv, row.scenario, processResult{Status: "passed", Started: true, Joined: true}, nil)
					accepted := change == "complete"
					if (err == nil) != accepted || (evidence.Outcome == "passed") != accepted || !reflect.DeepEqual(evidence.Phases, result.Phases) || evidence.Actor != result.Actor || !reflect.DeepEqual(raw.Cleanup, result.Cleanup) {
						t.Fatalf("public cleanup import changed or misclassified exact evidence: accepted=%t error=%v evidence=%+v", accepted, err, evidence)
					}
				})
			}
		}
	}
}

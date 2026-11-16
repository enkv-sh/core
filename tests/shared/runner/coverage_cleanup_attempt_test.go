package main

import (
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestFullCoverageAcceptsValidatedAutomaticCleanupSettlement(t *testing.T) {
	_, value := coverageFixture(t)
	if !fullCoverage(value) {
		t.Fatal("complete control fixture was refused")
	}
	result := &value.Scenarios[0]
	zeroBudget := records.BudgetReservation{}
	result.Cleanup.BudgetReserved = &zeroBudget
	setScenarioWorkerEvidence(result, "live", value.Resolved.RoleBindings)
	target := uint32(0)
	one := int64(1)
	cause := records.HarnessFailure{Operation: "object_cleanup", Stage: "conditional_delete", Cause: "transport",
		Effect: "unknown", TargetKind: "inventory", TargetIndex: &target, Attempt: 1}
	failure := records.Failure{Class: "cleanup_run_failed", Stage: "cleanup"}
	failedCleanup := records.Cleanup{Outcome: "unresolved", RemainingOwnedObjects: &one, UnknownEffects: &one,
		Failure: &failure, HarnessFailure: &cause, BudgetReserved: &zeroBudget}
	failedWorker := *result.CleanupWorker
	failedWorker.Worker = "automatic-cleanup-first"
	failedWorker.Outcome, failedWorker.Process = "failed", "process_failed"
	failedWorker.Failure, failedWorker.HarnessFailure = &failure, &cause
	result.CleanupAttempts = []cleanupAttemptEvidence{
		{Ordinal: 1, Decision: "initial", TargetIndex: &target, Worker: &failedWorker, Cleanup: failedCleanup},
		{Ordinal: 2, Decision: "gcp_exact_generation", TargetIndex: &target, Worker: result.CleanupWorker, Cleanup: result.Cleanup},
	}
	if !validCleanupHistory(value) {
		t.Fatal("valid automatic cleanup history was refused")
	}
	if !fullCoverage(value) {
		t.Fatal("validated automatic cleanup settlement lost full coverage")
	}
	result.CleanupAttempts[1].Ordinal = 3
	if fullCoverage(value) {
		t.Fatal("invalid cleanup attempt order gained full coverage")
	}
}

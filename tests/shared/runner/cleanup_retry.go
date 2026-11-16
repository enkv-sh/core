package main

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"time"

	records "enkv.sh/core/internal/testrecords"
)

// cleanupRetryTarget grants only a candidate for one new cleanup worker. The
// worker must check the private inventory and exact saved GCP generation before
// it can send a DELETE. A public cause never grants an effect by itself.
func cleanupRetryTarget(result *scenarioResult, provider string, joined bool, ordinal uint8) (uint32, string) {
	if provider != "gcp" {
		return 0, "cause_ineligible"
	}
	return cleanupFailureTarget(result, joined, ordinal)
}

func cleanupFailureTarget(result *scenarioResult, joined bool, ordinal uint8) (uint32, string) {
	if !result.CorrectnessPassed || result.Writer == nil {
		return 0, "product_incomplete"
	}
	if !joined || result.CleanupWorker == nil || !result.CleanupWorker.Joined {
		return 0, "worker_unjoined"
	}
	if result.Cleanup.Outcome != "unresolved" || result.Cleanup.RemainingOwnedObjects == nil || *result.Cleanup.RemainingOwnedObjects < 1 {
		return 0, "evidence_unavailable"
	}
	fact := result.Cleanup.HarnessFailure
	if fact == nil || !fact.Validate() || fact.Operation != "object_cleanup" ||
		fact.TargetKind != "inventory" || fact.TargetIndex == nil {
		return 0, "evidence_unavailable"
	}
	if fact.Cause == "ownership_mismatch" {
		return 0, "target_changed"
	}
	if fact.Effect != "unknown" {
		return 0, "cause_ineligible"
	}
	if fact.Attempt != ordinal {
		return 0, "evidence_unavailable"
	}
	transient := false
	switch fact.Cause {
	case "transport", "missing_response", "deadline":
		transient = fact.Stage == "conditional_delete"
	case "early_eof":
		transient = fact.Stage == "response_intake"
	case "provider_refused":
		transient = fact.Stage == "conditional_delete" && fact.HTTPStatus != nil &&
			(*fact.HTTPStatus == 429 || *fact.HTTPStatus == 503) && fact.EnvelopeStatus != nil && *fact.EnvelopeStatus == *fact.HTTPStatus
	}
	if !transient {
		return 0, "cause_ineligible"
	}
	if result.Cleanup.UnknownEffects == nil || *result.Cleanup.UnknownEffects < 1 {
		return 0, "evidence_unavailable"
	}
	return *fact.TargetIndex, ""
}

func waitCleanupRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (s *runState) retryLiveCleanup(ctx context.Context, binary string, original records.Invocation, input workerInput, allowance limits,
	started time.Time, joined bool, result *scenarioResult) error {
	if ctx.Err() != nil {
		result.CleanupRetryBlocker = "interrupted"
		return nil
	}
	if input.Generator != nil {
		result.CleanupRetryBlocker = "generator_fixture"
		return nil
	}
	deadline := started.Add(time.Duration(allowance.CleanupSeconds) * time.Second)
	total := result.Cleanup.BudgetReserved
	var originalTarget uint32
	for ordinal := uint8(2); ordinal <= 3; ordinal++ {
		target, blocker := cleanupRetryTarget(result, s.record.Provider, joined, ordinal-1)
		if blocker != "" {
			result.CleanupRetryBlocker = blocker
			return nil
		}
		if ordinal == 2 {
			originalTarget = target
		} else if target != originalTarget {
			result.CleanupRetryBlocker = "target_changed"
			return nil
		}
		if time.Until(deadline) <= time.Second {
			result.CleanupRetryBlocker = "deadline_exhausted"
			return nil
		}
		remaining := allowance
		if total == nil {
			result.CleanupRetryBlocker = "evidence_unavailable"
			return nil
		}
		if debitBudget(&remaining, &records.BudgetReservation{}, total, 0, time.Since(started)) != nil {
			result.CleanupRetryBlocker = "budget_exhausted"
			return nil
		}
		if remaining.CleanupRequests == 0 || remaining.CleanupBytes == 0 || remaining.CleanupSeconds == 0 {
			result.CleanupRetryBlocker = "budget_exhausted"
			return nil
		}
		if ctx.Err() != nil {
			result.CleanupRetryBlocker = "interrupted"
			return nil
		}
		retryCtx, cancel := context.WithDeadline(ctx, deadline)
		wait := 100 * time.Millisecond
		if ordinal == 3 {
			wait = 400 * time.Millisecond
		}
		if !waitCleanupRetry(retryCtx, wait) {
			cancel()
			result.CleanupRetryBlocker = "interrupted"
			if ctx.Err() == nil {
				result.CleanupRetryBlocker = "deadline_exhausted"
			}
			return nil
		}
		seconds := uint64(time.Until(deadline) / time.Second)
		if seconds == 0 {
			cancel()
			result.CleanupRetryBlocker = "deadline_exhausted"
			return nil
		}
		if seconds < remaining.CleanupSeconds {
			remaining.CleanupSeconds = seconds
		}
		var outputResidue publicationResidue
		var outputInventoryHash string
		if input.Outputs != nil {
			if validateRetainedPublication(original.StateDir, s.record, *result) != nil {
				cancel()
				result.CleanupRetryBlocker = "evidence_unavailable"
				return nil
			}
			var outputErr error
			outputResidue, outputErr = publicationResidueState(input.Outputs)
			before, readErr := readRecordBytes(input.Outputs.InventoryPath)
			if outputErr != nil || readErr != nil || len(before) > records.MaximumOutputFixtureInventoryBytes {
				cancel()
				result.CleanupRetryBlocker = "evidence_unavailable"
				return nil
			}
			outputInventoryHash = digestBytes(before)
		}
		copyInput := input.authorityOnly()
		if copyInput.Outputs.Validate(records.OutputFixtureScope{}, "rerun") != nil {
			cancel()
			return errPublicationInput
		}
		copyInput.Limits = &remaining
		copyInput.CleanupRetry = &cleanupRetryInput{TargetIndex: target, Ordinal: ordinal}
		inputPath := filepath.Join(original.StateDir, fmt.Sprintf("cleanup-retry-input-%d.json", ordinal))
		if err := records.WriteJSON(inputPath, copyInput, 0400); err != nil {
			cancel()
			result.CleanupRetryBlocker = "evidence_unavailable"
			return err
		}
		inv, err := makeInvocation(records.Invocation{
			Scenario: result.Scenario, FailureSources: s.failureSources, TelemetrySettings: s.telemetrySettings,
			RunID: original.RunID, Worker: fmt.Sprintf("%s-retry-%d", original.Worker, ordinal), Role: "cleanup",
			Input: inputPath, StateDir: original.StateDir,
			OutputDir: filepath.Join(original.StateDir, "workers", fmt.Sprintf("cleanup-retry-%d", ordinal)),
		}, "live")
		if err != nil {
			cancel()
			result.CleanupRetryBlocker = "evidence_unavailable"
			return err
		}
		if len(result.CleanupAttempts) == 0 {
			index := originalTarget
			result.CleanupAttempts = append(result.CleanupAttempts, cleanupAttemptEvidence{
				Ordinal: 1, Decision: "initial", TargetIndex: &index, Worker: result.CleanupWorker,
				Cleanup: result.Cleanup, Elapsed: time.Since(started),
			})
		}
		index := target
		result.CleanupAttempts = append(result.CleanupAttempts, cleanupAttemptEvidence{
			Ordinal: ordinal, Decision: "gcp_exact_generation", TargetIndex: &index, Cleanup: unresolvedCleanup(),
		})
		if err := s.save(); err != nil {
			cancel()
			result.CleanupRetryBlocker = "evidence_unavailable"
			return err
		}
		attemptStarted := time.Now()
		worker, cleanup := s.executeCleanup(retryCtx, binary, inv, result.Scenario, remaining)
		elapsed := time.Since(attemptStarted)
		cancel()
		attempt := &result.CleanupAttempts[len(result.CleanupAttempts)-1]
		if worker == nil || !worker.Joined {
			result.CleanupRetryBlocker = "worker_unjoined"
			return nil
		}
		if input.Outputs != nil {
			after, readErr := readRecordBytes(input.Outputs.InventoryPath)
			if readErr != nil || len(after) > records.MaximumOutputFixtureInventoryBytes || digestBytes(after) != outputInventoryHash {
				result.CleanupRetryBlocker = "evidence_unavailable"
				return errPublicationInput
			}
			cleanup = preservePublicationResidue(cleanup, outputResidue)
			result.OutputScheduled = uint32(outputResidue.Scheduled)
		}
		attempt.Worker, attempt.Cleanup, attempt.Elapsed = worker, cleanup, elapsed
		result.CleanupWorker, result.Cleanup = worker, cleanup
		if total == nil || cleanup.BudgetReserved == nil {
			result.CleanupRetryBlocker = "evidence_unavailable"
			return nil
		}
		total, err = addReservations(total, cleanup.BudgetReserved)
		if err != nil {
			result.CleanupRetryBlocker = "evidence_unavailable"
			return nil
		}
		result.Cleanup.BudgetReserved = total
		if err := s.save(); err != nil {
			result.CleanupRetryBlocker = "evidence_unavailable"
			return err
		}
		if scenarioCleanupPassed(*result) {
			result.CleanupRetryBlocker = ""
			return nil
		}
	}
	if _, blocker := cleanupRetryTarget(result, s.record.Provider, joined, 3); blocker != "" {
		result.CleanupRetryBlocker = blocker
	} else {
		result.CleanupRetryBlocker = "attempts_exhausted"
	}
	return nil
}

func validCleanupHistory(value runRecord) bool {
	for _, result := range value.Scenarios {
		if !validCleanupRetryBlocker(result.CleanupRetryBlocker) {
			return false
		}
		if len(result.CleanupAttempts) == 0 {
			if result.CleanupRetryBlocker != "" && (value.Suite != "live" || result.Cleanup.Outcome == "passed" || result.Outcome == "passed" || value.Outcome == "passed") {
				return false
			}
			continue
		}
		if value.Suite != "live" || len(result.CleanupAttempts) > 3 || result.CleanupRetryBlocker != "" && (result.Cleanup.Outcome == "passed" || result.Outcome == "passed" || value.Outcome == "passed") {
			return false
		}
		seenWorkers := map[string]bool{}
		var total records.BudgetReservation
		budgetComplete, pending := true, false
		for index, attempt := range result.CleanupAttempts {
			if attempt.Ordinal != uint8(index+1) || attempt.Elapsed < 0 || attempt.TargetIndex != nil && *attempt.TargetIndex > maximumCleanupCount {
				return false
			}
			if index == 0 {
				if attempt.Decision != "initial" {
					return false
				}
			} else if attempt.Decision != "gcp_exact_generation" || value.Provider != "gcp" || attempt.TargetIndex == nil || cleanupPassed(result.CleanupAttempts[index-1].Cleanup) {
				return false
			}
			if !validScenarioAttemptCleanup(attempt.Cleanup, result) {
				return false
			}
			if attempt.Worker == nil {
				if index == 0 || index != len(result.CleanupAttempts)-1 || attempt.Cleanup.Outcome != "unresolved" || attempt.Elapsed != 0 || attempt.Cleanup.BudgetReserved != nil {
					return false
				}
				pending = true
				continue
			}
			if !validAttemptWorker(*attempt.Worker) || seenWorkers[attempt.Worker.Worker] || scenarioCleanupPassed(scenarioResult{Entry: result.Entry, OutputsSHA256: result.OutputsSHA256, OutputScheduled: result.OutputScheduled, Cleanup: attempt.Cleanup}) && (attempt.Worker.Outcome != "passed" || attempt.Worker.Process != "passed") {
				return false
			}
			seenWorkers[attempt.Worker.Worker] = true
			if attempt.Cleanup.HarnessFailure != nil && attempt.Cleanup.HarnessFailure.TargetKind == "inventory" && attempt.TargetIndex != nil && *attempt.Cleanup.HarnessFailure.TargetIndex != *attempt.TargetIndex {
				return false
			}
			if attempt.Cleanup.BudgetReserved == nil {
				budgetComplete = false
			} else if !addCleanupReservation(&total, *attempt.Cleanup.BudgetReserved) {
				return false
			}
		}
		last := result.CleanupAttempts[len(result.CleanupAttempts)-1]
		if pending {
			if scenarioCleanupPassed(result) || result.Outcome == "passed" || value.Outcome == "passed" {
				return false
			}
		} else if !sameCleanupReceipt(last.Cleanup, result.Cleanup) || result.CleanupWorker == nil || !reflect.DeepEqual(*last.Worker, *result.CleanupWorker) || result.Outcome == "passed" && !scenarioCleanupPassed(result) || value.Outcome == "passed" && !scenarioCleanupPassed(result) {
			return false
		}
		if budgetComplete {
			if result.Cleanup.BudgetReserved == nil || *result.Cleanup.BudgetReserved != total {
				return false
			}
		} else if scenarioCleanupPassed(result) {
			return false
		}
	}
	return true
}

func validCleanupRetryBlocker(blocker string) bool {
	switch blocker {
	case "", "product_incomplete", "worker_unjoined", "cause_ineligible", "generator_fixture", "target_changed", "evidence_unavailable", "budget_exhausted", "deadline_exhausted", "attempts_exhausted", "interrupted":
		return true
	}
	return false
}

func validAttemptCleanup(value records.Cleanup) bool {
	if value.Outcome != "passed" && value.Outcome != "unresolved" ||
		value.RemainingOwnedObjects != nil && (*value.RemainingOwnedObjects < 0 || *value.RemainingOwnedObjects > maximumCleanupCount) ||
		value.UnknownEffects != nil && (*value.UnknownEffects < 0 || *value.UnknownEffects > maximumCleanupCount) ||
		value.Failure != nil && !validCleanupFailure(*value.Failure) ||
		value.HarnessFailure != nil && !value.HarnessFailure.Validate() {
		return false
	}
	if value.Outcome == "passed" && (!cleanupPassed(value) || value.Failure != nil || value.HarnessFailure != nil) {
		return false
	}
	return true
}

func validAttemptWorker(value workerEvidence) bool {
	if value.Role != "cleanup" || !value.Joined || !telemetryLabel.MatchString(value.Worker) ||
		value.Actor != "" && !telemetryLabel.MatchString(value.Actor) ||
		!slices.Contains([]string{"passed", "failed", "incomplete"}, value.Outcome) ||
		!slices.Contains([]string{"passed", "process_failed", "timed_out", "interrupted", "group_stop_failed", "output_limit_exceeded", "resource_limit"}, value.Process) ||
		value.Failure != nil && !validCleanupFailure(*value.Failure) ||
		value.HarnessFailure != nil && !value.HarnessFailure.Validate() ||
		value.Assertions != nil && value.Assertions.Validate() != nil ||
		len(value.Phases) > maximumWorkerPhases {
		return false
	}
	for index, phase := range value.Phases {
		if phase.Sequence != uint64(index+1) || !validPhase(phase.Name) || !slices.Contains([]string{"passed", "failed", "incomplete"}, phase.Outcome) {
			return false
		}
	}
	return true
}

func validCleanupFailure(value records.Failure) bool {
	if value.Class == "public_configuration_evidence_unavailable" && value.Stage == "evidence" {
		return true
	}
	return slices.Contains([]string{"run_failed", "source_changed", "assembly_failed", "assembly_checks_failed", "component_checks_failed", "budget_exhausted", "interrupted", "scenario_failed", "cleanup_unresolved", "budget_evidence_unavailable", "worker_evidence_incomplete", "worker_failed", "store_transport_exhausted", "same_domain_rerun_failed", "cleanup_run_failed", "cleanup_budget_exhausted", "scenario_setup_failed", "fresh_evidence_unavailable", "writer_failed", "fresh_read_failed", "worker_group_not_joined"}, value.Class) &&
		slices.Contains([]string{"execution", "source", "build", "checks", "schedule", "cleanup", "budget", "setup", "transition", "writer", "rerun", "fresh_before", "fresh_after"}, value.Stage)
}

func sameCleanupReceipt(first, second records.Cleanup) bool {
	first.BudgetReserved, second.BudgetReserved = nil, nil
	return reflect.DeepEqual(first, second)
}

func addCleanupReservation(total *records.BudgetReservation, item records.BudgetReservation) bool {
	fields := [][2]*uint64{{&total.Requests, &item.Requests}, {&total.BodyBytes, &item.BodyBytes}, {&total.Objects, &item.Objects}, {&total.ObjectBytes, &item.ObjectBytes}, {&total.GeneratorCreates, &item.GeneratorCreates}, {&total.GeneratorRetires, &item.GeneratorRetires}}
	for _, field := range fields {
		if *field[1] > ^uint64(0)-*field[0] {
			return false
		}
		*field[0] += *field[1]
	}
	return true
}

func validScenarioAttemptCleanup(value records.Cleanup, result scenarioResult) bool {
	if validAttemptCleanup(value) {
		return true
	}
	result.Cleanup = value
	return scenarioCleanupPassed(result)
}

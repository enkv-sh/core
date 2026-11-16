package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

const (
	maximumWorkerPhases           = records.MaximumWorkerPhases
	maximumWorkerChildren         = records.MaximumWorkerChildren
	maximumWorkerFreshChecks      = 64
	maximumCleanupCount           = 1000000
	childWorkerDigestPrefixLength = 12
)

// A valid partial result can still supply telemetry and retained child facts.
// Only complete phase and process evidence can supply a successful outcome.
func readWorkerResult(inv records.Invocation, scenario string) (records.WorkerResult, error) {
	var result records.WorkerResult
	if inv.Scenario != scenario {
		return records.WorkerResult{}, errors.New("worker scenario binding differs")
	}
	path, err := records.SafePath(inv.OutputDir, "worker.json")
	if err != nil || readEvidence(path, &result) != nil || result.SchemaVersion != records.SchemaVersion || result.RunID != inv.RunID || result.Worker != inv.Worker || result.Role != inv.Role || result.Scenario != scenario {
		return records.WorkerResult{}, errors.New("worker identity evidence unavailable")
	}
	if !slices.Contains([]string{"passed", "failed", "incomplete"}, result.Outcome) || len(result.Phases) > maximumWorkerPhases || len(result.Children) > maximumWorkerChildren || len(result.FreshChecks) > maximumWorkerFreshChecks {
		return records.WorkerResult{}, errors.New("worker result refused")
	}
	if result.HarnessFailure != nil && (!result.HarnessFailure.Validate() || result.Outcome == "passed") ||
		result.Cleanup != nil && result.Cleanup.HarnessFailure != nil && (!result.Cleanup.HarnessFailure.Validate() || result.Cleanup.Outcome == "passed") {
		return records.WorkerResult{}, errors.New("worker harness failure refused")
	}
	for i, phase := range result.Phases {
		if phase.RecoveryMode != "" && phase.RecoveryMode != "disabled" && phase.RecoveryMode != "enabled" {
			return records.WorkerResult{}, errors.New("worker recovery mode refused")
		}
		if phase.Sequence != uint64(i+1) || !validPhase(phase.Name) || !slices.Contains([]string{"passed", "failed", "incomplete"}, phase.Outcome) || !validActor(phase.Actor) || !validStepOutcome(phase.Expected) || !validStepOutcome(phase.Actual) {
			return records.WorkerResult{}, errors.New("worker phase evidence refused")
		}
	}
	if !validActor(result.Actor) {
		return records.WorkerResult{}, errors.New("worker actor evidence refused")
	}
	// Only one exact typed disposition can become rerun evidence. All other
	// worker failure fields are diagnostic text, not recovery authority.
	transport := validTransportFailure(result)
	original := result
	result.Failure, result.StoreFailure = nil, nil
	if result.Outcome != "passed" {
		result.Failure = &records.Failure{Class: "worker_failed", Stage: inv.Role}
		if transport {
			result.Failure = &records.Failure{Class: "store_transport_exhausted", Stage: "transition"}
			copy := *original.StoreFailure
			result.StoreFailure = &copy
		}
	}
	return result, nil
}

func validTransportFailure(result records.WorkerResult) bool {
	if result.Role != "writer" || result.Outcome != "failed" || result.Failure == nil || *result.Failure != (records.Failure{Class: "store_transport_exhausted", Stage: "transition"}) || result.StoreFailure == nil || result.StoreFailure.StoreReason != "transport" || len(result.Phases) == 0 {
		return false
	}
	last := result.Phases[len(result.Phases)-1]
	if last.Name != "transition" || last.Outcome != "failed" || last.Actual != "failed" {
		return false
	}
	f := result.StoreFailure
	return f.Outcome == "evidence-unavailable" && (f.Reason == "read-unavailable" || f.Reason == "write-uncertain") && !f.CommitMayHaveOccurred || f.Outcome == "unresolved-commit" && f.Reason == "write-uncertain" && f.CommitMayHaveOccurred
}

func completeWorker(result records.WorkerResult, mode string, participants map[string]string, recovery string, before *catalog.Step) bool {
	if !result.Assertions.PermitsSuccess() || result.Outcome != "passed" || result.Failure != nil || !completeWorkerPhases(result.Role, result.Actor, result.Phases, result.Scenario, mode, participants, result.Cleanup, recovery, before) {
		return false
	}
	if result.Role == "writer" {
		execution, known := recordedExecutionForRecovery(result.Scenario, mode, recovery)
		return known && len(result.Children) == len(execution.ExpandedFreshBefore()) && len(result.FreshChecks) == len(execution.ExpandedFreshAfter()) && freshChecksMatch(result.Scenario, mode, result.FreshChecks, recovery)
	}
	if result.Role == "rerun" {
		return mode == "live" && recordedSameDomainRecovery(result.Scenario) && len(result.Children) == 0 && freshChecksMatch(result.Scenario, mode, result.FreshChecks, recovery)
	}
	return len(result.Children) == 0 && len(result.FreshChecks) == 0
}

func (s *runState) importWorker(inv records.Invocation, scenario string, process processResult, before *catalog.Step) (workerEvidence, records.WorkerResult, error) {
	return s.importWorkerOwned(nil, inv, scenario, process, before)
}

func (s *runState) importWorkerOwned(parent context.Context, inv records.Invocation, scenario string, process processResult, before *catalog.Step) (workerEvidence, records.WorkerResult, error) {
	return s.importWorkerWithAnchor(parent, inv, scenario, process, before, nil)
}

func (s *runState) importWorkerWithAnchor(parent context.Context, inv records.Invocation, scenario string, process processResult, before *catalog.Step, writer *processResult) (workerEvidence, records.WorkerResult, error) {
	evidence := workerEvidence{RecoveryMode: inv.RecoveryMode, Worker: inv.Worker, Role: inv.Role, Outcome: "failed", Process: process.Status,
		Started: process.Started, Joined: process.Joined, Phases: []records.PhaseResult{}}
	if process.Started && s.record.BuildClosure != nil && !s.record.BuildClosure.raceMissing {
		evidence.Race = raceSetting(s.record.BuildClosure.Race)
		evidence.RaceOptions = acceptedRaceOptions(s.record.BuildClosure.Race)
	}
	result, err := readWorkerResult(inv, scenario)
	assertions := records.InspectAssertions(inv, process.Status == "passed" || result.Outcome == "passed")
	evidence.Assertions, result.Assertions = &assertions, &assertions
	if err == nil {
		evidence.Phases = result.Phases
		evidence.Actor = result.Actor
		evidence.StoreFailure = result.StoreFailure
		evidence.HarnessFailure = result.HarnessFailure
	}
	var input workerInput
	inputErr := readEvidence(inv.Input, &input)
	if s.record.Resolved != nil {
		participants, err := s.record.Resolved.scenarioParticipants(scenario)
		if inv.Role == "cleanup" && !recordedHasFixture(scenario, catalog.FixturePublicConfiguration) {
			participants = map[string]string{"authority": s.record.Resolved.RoleBindings["authority"]}
		}
		if err != nil || !reflect.DeepEqual(input.Participants, participants) || input.RecoveryMode != s.record.Resolved.RecoveryMode {
			inputErr = errors.New("worker participant routes or recovery mode differ from the resolved run")
		}
	}
	// A current hermetic writer binds the same narrowed execution as its
	// admitted input. Empty descriptor mode retains the existing both layout.
	if _, current := catalog.Name(scenario); current && s.record.Suite == "hermetic" && inv.Role == "writer" {
		selected := inv.RecoveryMode
		if selected == "" {
			selected = "both"
		}
		if selected != input.RecoveryMode {
			inputErr = errors.New("writer recovery selection differs from its input")
		}
	}
	complete := inputErr == nil && completeWorker(result, s.record.Suite, input.Participants, inv.RecoveryMode, before)
	if complete && inv.Role == "cleanup" {
		if _, publication := recordedPublication(scenario); publication && (result.Cleanup == nil || !cleanupPassed(*result.Cleanup) || !s.publicationStoreCleanup(inv, input)) {
			_, proofErr := s.publicationCleanupEvidence(inv, scenario, result.Cleanup)
			complete = proofErr == nil
		}
	}
	if s.workerRecords == nil {
		s.workerRecords = make(map[string]bool)
	}
	terminal := result.Outcome == "passed" && complete || result.Outcome == "failed" && process.Status != "passed"
	s.workerRecords[inv.Worker] = err == nil && inputErr == nil && terminal && assertions.Validate() == nil && assertions.Marker != "invalid_failure_marker" && assertions.Marker != "contradictory_failure_marker"
	snapshots, measurement := loadWorkerTelemetry(inv, result, s.record.Telemetry.Enabled)
	s.snapshots = append(s.snapshots, snapshots)
	evidence.Telemetry = measurement
	diagnostics := records.InspectLogs(inv, result.Diagnostics)
	result.Diagnostics = diagnostics
	diagnostics.Source = ""
	evidence.Diagnostics = diagnostics
	s.diagnostics = append(s.diagnostics, diagnostics)
	evidence.Deliveries = records.InspectDeliveryStatuses(inv, result.Deliveries)
	evidence.SDKCallbacks = result.SDKCallbacks
	for _, status := range evidence.Deliveries {
		if status.EvidenceIncomplete() {
			s.telemetryIncomplete = true
		}
	}
	recoveryFailure := recordedSameDomainRecovery(scenario) && err == nil && inputErr == nil && process.Status == "process_failed" && process.Joined && validTransportFailure(result) && len(result.Children) == 0
	if measurement.Enabled && measurement.Status != "complete" || err != nil || !recoveryFailure && (process.Status != "passed" || !process.Joined || !complete) {
		s.telemetryIncomplete = true
	}
	if err != nil || process.Status != "passed" || !process.Joined || !complete {
		evidence.Failure = &records.Failure{Class: "worker_evidence_incomplete", Stage: inv.Role}
		if err == nil && process.Joined && result.StoreFailure != nil && result.Failure != nil {
			evidence.Failure = result.Failure
		}
		var failure error = errors.New("worker execution or evidence incomplete")
		if s.record.Suite == "hermetic" {
			failure = errors.Join(failure, process.diagnostic)
			settled := parent != nil && settledLocalProcessFailure(parent, process) && containedCheckFailure(parent, containProcessFailure(parent, process.diagnostic))
			if parent != nil && writer != nil && parent.Err() == nil && process.Started && process.Joined && process.Status == "process_failed" {
				settled = writer.Started && writer.Joined && writer.Status == "passed" && writer.Cause == nil || settledLocalProcessFailure(parent, *writer)
			}
			if settled && err == nil && inputErr == nil &&
				validFailedWorkerPrefix(inv, result, input, before) && validFailedWorkerObservations(inv, result, measurement, diagnostics) {
				failure = &localCheckFailure{cause: failure}
			}
			return evidence, result, failure
		}
		return evidence, result, failure
	}
	evidence.Outcome = "passed"
	return evidence, result, nil
}

func validFailedWorkerPrefix(inv records.Invocation, result records.WorkerResult, input workerInput, before *catalog.Step) bool {
	if input.RunID != inv.RunID || input.Repetitions != 1 || len(input.Scenarios) != 1 || input.Scenarios[0] != inv.Scenario || input.Limits != nil ||
		result.Outcome != "failed" && result.Outcome != "incomplete" || result.HarnessFailure != nil || result.Cleanup != nil || result.Assertions == nil ||
		result.Assertions.Validate() != nil || result.Assertions.Marker != "no_failure_marker" && result.Assertions.Marker != "valid_failure_marker" ||
		result.Assertions.Checkpoint == "invalid_checkpoint" || result.Assertions.MarkerWriteError {
		return false
	}
	execution, known := recordedExecutionForRecovery(inv.Scenario, "hermetic", inv.RecoveryMode)
	if !known || !workerPhasesMatch(execution, inv.Role, result.Actor, result.Phases, inv.Scenario, "hermetic", input.Participants, result.Cleanup, inv.RecoveryMode, before, true) {
		return false
	}
	if inv.Role != "writer" {
		return len(result.Children) == 0 && len(result.FreshChecks) == 0
	}
	if len(result.Children) > len(execution.ExpandedFreshBefore()) || len(result.FreshChecks) > len(execution.ExpandedFreshAfter()) {
		return false
	}
	seen := make(map[string]bool, len(result.FreshChecks))
	for index, check := range result.FreshChecks {
		if check.Facts == "" || seen[check.Facts] || check.RecoveryMode != expectedFreshMode(inv.Scenario, "hermetic", "fresh_after", index, inv.RecoveryMode) {
			return false
		}
		if _, err := records.SafePath(inv.StateDir, check.Facts); err != nil {
			return false
		}
		seen[check.Facts] = true
	}
	return true
}

func validFailedWorkerObservations(inv records.Invocation, result records.WorkerResult, measurement records.Telemetry, diagnostics records.Diagnostics) bool {
	if measurement.Enabled && measurement.Status != "complete" && !validTerminatedWorkerTelemetry(inv, result) {
		return false
	}
	if diagnostics.DroppedWriter != 0 || diagnostics.Status == "complete" && diagnostics.FailureClass != "" {
		return false
	}
	if diagnostics.Enabled && diagnostics.Status != "complete" &&
		!(diagnostics.Status == "incomplete" && diagnostics.Source == "" && (diagnostics.FailureClass == "" || diagnostics.FailureClass == "worker_terminated")) {
		return false
	}
	for _, status := range result.Deliveries {
		if status.Failed != nil && *status.Failed != 0 || status.Dropped != nil && *status.Dropped != 0 || status.Incomplete != nil && *status.Incomplete {
			return false
		}
	}
	return true
}

// A killed worker can lose its final telemetry write. Available snapshots must
// still be a valid contiguous prefix; a malformed file is never a lost tail.
func validTerminatedWorkerTelemetry(inv records.Invocation, result records.WorkerResult) bool {
	if !result.Telemetry.Enabled || result.Telemetry.Status != "incomplete" || result.Telemetry.FailureClass != "" || result.Telemetry.Source != "telemetry.json" {
		return false
	}
	path, err := records.SafePath(inv.OutputDir, result.Telemetry.Source)
	if err != nil {
		return false
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return true
	} else if err != nil {
		return false
	}
	var raw []json.RawMessage
	if records.ReadJSON(path, &raw) != nil || raw == nil || len(raw) > len(result.Phases)+1 {
		return false
	}
	for index, body := range raw {
		candidate, invalidMetric, err := decodeTelemetryCandidate(body)
		snapshot, valid := projectTelemetrySnapshot(candidate)
		if err != nil || invalidMetric || !valid || snapshot.RunID != inv.RunID || snapshot.Worker != inv.Worker ||
			snapshot.Sequence != uint64(index+1) || snapshot.Status != "complete" || snapshot.FailureClass != "" {
			return false
		}
		if index == len(result.Phases) {
			if snapshot.Phase != "final" {
				return false
			}
		} else {
			phase := result.Phases[index]
			if snapshot.Phase != phase.Name || phase.Outcome == "passed" && phase.MeasurementsExpected && !records.PositiveObservation(snapshot.Metrics) {
				return false
			}
		}
	}
	return true
}

// Store-only workers retain zero-only admission. Their callers validate and
// merge the unchanged output inventory after the worker has joined.
func (s *runState) publicationStoreCleanup(inv records.Invocation, input workerInput) bool {
	if input.Outputs != nil || inv.RunID != s.record.RunID {
		return false
	}
	if retry := input.CleanupRetry; retry != nil {
		for _, result := range s.record.Scenarios {
			state, err := publicationScenarioState(s.directory, result)
			if err != nil || state != inv.StateDir || result.Scenario != inv.Scenario || len(result.CleanupAttempts) < 2 {
				continue
			}
			last := result.CleanupAttempts[len(result.CleanupAttempts)-1]
			return last.Worker == nil && last.Decision == "gcp_exact_generation" && last.Ordinal == retry.Ordinal && last.TargetIndex != nil && *last.TargetIndex == retry.TargetIndex && inv.Input == filepath.Join(state, fmt.Sprintf("cleanup-retry-input-%d.json", retry.Ordinal)) && inv.OutputDir == filepath.Join(state, "workers", fmt.Sprintf("cleanup-retry-%d", retry.Ordinal))
		}
		return false
	}
	return input.CleanupGrant != nil && s.record.RecoveryRunID != "" && inv.Input == filepath.Join(filepath.Dir(inv.OutputDir), "input.json") && filepath.Base(inv.OutputDir) == "cleanup"
}

func validActor(actor string) bool {
	return actor == "" || telemetryLabel.MatchString(actor)
}

func validStepOutcome(outcome string) bool {
	if slices.Contains([]string{"", "success", "access-refused", "unavailable", "integrity-failure", "failed", "incomplete"}, outcome) {
		return true
	}
	return catalog.HasStepOutcome(outcome)
}

// Infrastructure phases describe process work; scenario steps describe the Go
// assertions. Neither may be omitted or relabelled when admitting success.
func workerSteps(scenario, mode, role string, cleanup *records.Cleanup, before *catalog.Step, recovery string) []catalog.Step {
	execution, known := recordedExecutionForRecovery(scenario, mode, recovery)
	if !known || before != nil && role != "fresh_before" {
		return nil
	}
	public := mode == "live" && execution.HasFixtureCapability(catalog.FixturePublicConfiguration)
	auth := catalog.Step{Name: "authentication", Role: "authority", Expected: "success"}
	resource := catalog.Step{Name: "resource_check", Role: "authority", Expected: "success"}
	switch role {
	case "writer":
		steps := execution.WriterSteps()
		if mode == "live" && !public {
			steps = append([]catalog.Step{auth, resource}, steps...)
		}
		return steps
	case "rerun":
		if mode != "live" || !recordedSameDomainRecovery(scenario) {
			return nil
		}
		return []catalog.Step{auth, resource, {Name: "transition", Role: "authority", Expected: "success"}}
	case "fresh_before", "fresh_after":
		if role == "fresh_before" && before == nil {
			return nil
		}
		var fresh catalog.Step
		var purpose catalog.FreshPurpose
		if before != nil {
			for _, child := range execution.ExpandedFreshBefore() {
				if child.Step != *before {
					continue
				}
				if purpose != "" && purpose != child.Purpose {
					return nil
				}
				purpose = child.Purpose
			}
			if purpose == "" {
				return nil
			}
			fresh = *before
		} else {
			if len(execution.FreshAfter) == 0 {
				return nil
			}
			fresh = execution.FreshAfter[0].Step
		}
		if mode == "live" && !public {
			auth.Role = fresh.Role
			if purpose == catalog.FreshGeneratedRecord {
				return []catalog.Step{auth, fresh}
			}
			return []catalog.Step{auth, fresh, {Name: "verification", Role: fresh.Role, Expected: "success"}}
		}
		return []catalog.Step{fresh}
	case "cleanup":
		if mode != "live" || cleanup == nil || cleanup.Outcome != "passed" || cleanup.Failure != nil || cleanup.HarnessFailure != nil {
			return nil
		}
		if !cleanupPassed(*cleanup) {
			_, publication := recordedPublication(scenario)
			publication = publication || scenario == records.StockPluginScenario && cleanup.RemainingOwnedObjects != nil && *cleanup.RemainingOwnedObjects == 2
			// These counts describe phase shape only. Publication admission also
			// requires the exact retained inventory, input and writer-group join.
			if !publication || cleanup.RemainingOwnedObjects == nil || *cleanup.RemainingOwnedObjects <= 0 || *cleanup.RemainingOwnedObjects > 10 || cleanup.UnknownEffects == nil || *cleanup.UnknownEffects != 0 {
				return nil
			}
		}
		if public {
			if cleanup.BudgetReserved == nil || *cleanup.BudgetReserved == (records.BudgetReservation{}) {
				return nil
			}
			return []catalog.Step{{Name: "cleanup", Role: "cleanup", Expected: "success"}}
		}
		step := catalog.Step{Name: "cleanup", Role: "authority", Expected: "success"}
		if cleanup.BudgetReserved != nil && *cleanup.BudgetReserved == (records.BudgetReservation{}) {
			// The worker has proved an empty inventory without provider calls.
			return []catalog.Step{step}
		}
		return []catalog.Step{auth, resource, step}
	}
	return nil
}

func completeWorkerPhases(role, actor string, phases []records.PhaseResult, scenario, mode string, participants map[string]string, cleanup *records.Cleanup, recovery string, before *catalog.Step) bool {
	execution, known := recordedExecutionForRecovery(scenario, mode, recovery)
	return known && completeWorkerPhasesForExecution(execution, role, actor, phases, scenario, mode, participants, cleanup, recovery, before)
}

func completeWorkerPhasesForExecution(execution catalog.Execution, role, actor string, phases []records.PhaseResult, scenario, mode string, participants map[string]string, cleanup *records.Cleanup, recovery string, before *catalog.Step) bool {
	return workerPhasesMatch(execution, role, actor, phases, scenario, mode, participants, cleanup, recovery, before, false)
}

func workerPhasesMatch(execution catalog.Execution, role, actor string, phases []records.PhaseResult, scenario, mode string, participants map[string]string, cleanup *records.Cleanup, recovery string, before *catalog.Step, failedPrefix bool) bool {
	if before != nil && role != "fresh_before" {
		return false
	}
	participantRole := "authority"
	switch role {
	case "cleanup":
		if mode == "live" && execution.HasFixtureCapability(catalog.FixturePublicConfiguration) {
			participantRole = "cleanup"
		}
	case "fresh_before":
		if before == nil || before.RecoveryMode != recovery {
			return false
		}
		participantRole = before.Role
	case "fresh_after":
		if len(execution.FreshAfter) == 0 {
			return false
		}
		participantRole = execution.FreshAfter[0].Role
	}
	if role == "fresh_after" && mode == "hermetic" {
		for _, child := range execution.FreshAfter {
			if child.Step.RecoveryMode == recovery {
				participantRole = child.Role
				break
			}
		}
	}
	if actor == "" || !telemetryLabel.MatchString(actor) || actor != participants[participantRole] {
		return false
	}
	steps := workerSteps(scenario, mode, role, cleanup, before, recovery)
	fresh := role == "fresh_before" || role == "fresh_after"
	if mode == "hermetic" && fresh {
		definition, definitionKnown := recordedDefinition(scenario)
		if !definitionKnown || !slices.Contains(definition.RecoveryModes, recovery) {
			return false
		}
		if role == "fresh_after" {
			matched := false
			for _, child := range execution.FreshAfter {
				if child.Step.RecoveryMode == recovery {
					steps[0] = child.Step
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	} else if recovery != "" && !(mode == "hermetic" && role == "writer") {
		return false
	}
	if len(steps) == 0 || len(phases) > len(steps) || !failedPrefix && len(phases) != len(steps) {
		return false
	}
	scenarioPosition := 0
	for index, phase := range phases {
		step := steps[index]
		measurementExpected, measurementKnown := true, true
		if step.Name == "authentication" || step.Name == "resource_check" {
			measurementExpected = true
		} else if role == "cleanup" {
			measurementExpected = step.Name != "cleanup" || cleanup != nil && cleanup.BudgetReserved != nil && *cleanup.BudgetReserved != (records.BudgetReservation{})
		} else if mode == "live" && (role == "fresh_before" || role == "fresh_after") && step.Name == "verification" {
			measurementExpected = false
		} else if role == "rerun" {
			measurementExpected = true
		} else {
			measurementExpected, measurementKnown = execution.MeasurementFor(role, scenarioPosition, step)
			scenarioPosition++
		}
		if !measurementKnown || phase.MeasurementsExpected != measurementExpected {
			return false
		}
		if phase.RecoveryMode != step.RecoveryMode {
			return false
		}
		participant := participants[step.Role]
		if participant == "" || !telemetryLabel.MatchString(participant) || phase.Sequence != uint64(index+1) || phase.Name != step.Name || phase.Actor != participant || phase.Expected != step.Expected {
			return false
		}
		if phase.Outcome != "passed" || phase.Actual != step.Expected {
			if !failedPrefix || index != len(phases)-1 || phase.Outcome != "failed" && phase.Outcome != "incomplete" || phase.Actual == "" || !validStepOutcome(phase.Actual) {
				return false
			}
		}
	}
	return true
}

func childInvocation(suite, scenario, private string, writer records.Invocation, child records.ChildInvocation, index int) (records.Invocation, catalog.Step, error) {
	execution, known := recordedExecutionForRecovery(scenario, suite, writer.RecoveryMode)
	if !known {
		return records.Invocation{}, catalog.Step{}, errors.New("scenario execution facts unavailable")
	}
	children := execution.ExpandedFreshBefore()
	if index < 0 || index >= len(children) || len(writer.FreshBefore) != len(children) {
		return records.Invocation{}, catalog.Step{}, errors.New("child position refused")
	}
	step := children[index].Step
	path, err := records.SafePath(private, child.Invocation)
	if err != nil {
		return records.Invocation{}, catalog.Step{}, errors.New("child invocation refused")
	}
	inv, err := records.LoadRecordedInvocation(path)
	if err != nil || inv.Scenario != scenario || inv.Nonce != writer.FreshBefore[index].Nonce || inv.Worker != writer.FreshBefore[index].Worker || !reflect.DeepEqual(inv.FailureSources, writer.FailureSources) || inv.RunID != writer.RunID || inv.Worker != child.Worker || inv.Role != "fresh_before" || inv.StateDir != writer.StateDir || inv.RecoveryMode != step.RecoveryMode {
		return records.Invocation{}, catalog.Step{}, errors.New("child identity refused")
	}
	if suite == "live" && (execution.HasFixtureCapability(catalog.FixtureGeneratedProcess) || execution.HasFixtureCapability(catalog.FixturePublication)) {
		if inv.Input != filepath.Join(writer.StateDir, fmt.Sprintf("fresh-input-%d.json", index)) {
			return records.Invocation{}, catalog.Step{}, errors.New("isolated child input path refused")
		}
		var original, isolated workerInput
		if records.ReadJSON(writer.Input, &original) != nil || records.ReadJSON(inv.Input, &isolated) != nil || execution.HasFixtureCapability(catalog.FixtureGeneratedProcess) && original.Generator == nil || execution.HasFixtureCapability(catalog.FixturePublication) && original.Outputs == nil {
			return records.Invocation{}, catalog.Step{}, errors.New("isolated child input unavailable")
		}
		original.Generator, original.GeneratorCleanupLedger = nil, ""
		original.ConfigurationRecovery = nil
		original.Outputs = nil
		if !reflect.DeepEqual(original, isolated) {
			return records.Invocation{}, catalog.Step{}, errors.New("isolated child input differs")
		}
	} else if inv.Input != writer.Input {
		return records.Invocation{}, catalog.Step{}, errors.New("child input identity refused")
	}
	var worker, output string
	if suite == "hermetic" {
		worker = fmt.Sprintf("%s-fresh-%04d-before", filepath.Base(writer.StateDir), index)
		output = filepath.Join(writer.StateDir, "workers", fmt.Sprintf("fresh-%04d-before", index))
	} else {
		worker = fmt.Sprintf("fresh-before-%s-%d", digestBytes([]byte(writer.Worker))[:childWorkerDigestPrefixLength], index)
		output = filepath.Join(writer.OutputDir, fmt.Sprintf("fresh-before-%d", index))
	}
	if inv.Worker != worker || inv.OutputDir != output {
		return records.Invocation{}, catalog.Step{}, errors.New("child output owner refused")
	}
	return inv, step, nil
}

func workerReservation(inv records.Invocation, cleanup bool) (*records.BudgetReservation, error) {
	var raw struct {
		Budget  json.RawMessage `json:"budget_reserved"`
		Cleanup struct {
			Budget json.RawMessage `json:"budget_reserved"`
		} `json:"cleanup"`
	}
	if readEvidence(filepath.Join(inv.OutputDir, "worker.json"), &raw) != nil {
		return nil, errors.New("budget evidence unavailable")
	}
	if cleanup {
		return decodeReservation(raw.Cleanup.Budget, true)
	}
	return decodeReservation(raw.Budget, false)
}

func safeCleanup(result records.WorkerResult, evidence workerEvidence) records.Cleanup {
	value := unresolvedCleanup()
	if result.Cleanup == nil {
		return value
	}
	if result.Cleanup.HarnessFailure != nil && result.Cleanup.HarnessFailure.Validate() && result.Cleanup.Outcome != "passed" {
		fact := *result.Cleanup.HarnessFailure
		value.HarnessFailure = &fact
	}
	for _, item := range []struct {
		from *int64
		to   **int64
	}{
		{result.Cleanup.RemainingOwnedObjects, &value.RemainingOwnedObjects}, {result.Cleanup.UnknownEffects, &value.UnknownEffects},
	} {
		if item.from != nil && *item.from >= 0 && *item.from <= maximumCleanupCount {
			copy := *item.from
			*item.to = &copy
		}
	}
	if evidence.Outcome == "passed" && evidence.Process == "passed" && evidence.Joined && evidence.Failure == nil && result.Cleanup.Outcome == "passed" && value.RemainingOwnedObjects != nil && *value.RemainingOwnedObjects == 0 && value.UnknownEffects != nil && *value.UnknownEffects == 0 {
		value.Outcome, value.Failure = "passed", nil
	}
	return value
}

func freshAfterCount(scenario, suite, recovery string) int {
	execution, known := recordedExecutionForRecovery(scenario, suite, recovery)
	if !known {
		return 0
	}
	return len(execution.ExpandedFreshAfter())
}
func expectedFreshMode(scenario, suite, role string, index int, recovery string) string {
	execution, known := recordedExecutionForRecovery(scenario, suite, recovery)
	if !known {
		return "invalid"
	}
	if role == "fresh_after" {
		children := execution.ExpandedFreshAfter()
		if index >= 0 && index < len(children) {
			return children[index].Step.RecoveryMode
		}
		return "invalid"
	}
	children := execution.ExpandedFreshBefore()
	if index >= 0 && index < len(children) {
		return children[index].Step.RecoveryMode
	}
	return "invalid"
}
func freshChecksMatch(scenario, suite string, checks []records.FreshCheck, recovery string) bool {
	if len(checks) != freshAfterCount(scenario, suite, recovery) {
		return false
	}
	for i, check := range checks {
		if check.RecoveryMode != expectedFreshMode(scenario, suite, "fresh_after", i, recovery) {
			return false
		}
	}
	return true
}

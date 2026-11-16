package main

import (
	"context"
	"encoding/json"
	"errors"
	"math/bits"
	"path/filepath"
	"time"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
)

const sameDomainRecoveryScenario = "state.transient-before-send-rerun/one_value_before_send"

// The local reader is strict, so its shape must cover the complete inventory
// written by the live worker. The worker validates each intent before use.
type sameDomainInventoryRecord struct {
	Version int               `json:"version"`
	RunID   string            `json:"run_id"`
	Binding string            `json:"binding"`
	Prefix  string            `json:"prefix"`
	Domain  contract.ID       `json:"domain"`
	Intents []json.RawMessage `json:"intents"`
	Deleted map[string]int    `json:"deleted"`
}

func eligibleSameDomainRerun(scenario string, process processResult, worker records.WorkerResult, children []workerEvidence) bool {
	return scenario == sameDomainRecoveryScenario && sameDomainRerunEvidence(process, worker, children)
}

func sameDomainRerunEvidence(process processResult, worker records.WorkerResult, children []workerEvidence) bool {
	return process.Status == "process_failed" && process.Joined && len(children) == 0 && validTransportFailure(worker)
}

func readSameDomainHandoff(state string, input workerInput) (records.RecoveryHandoff, error) {
	path, err := records.SafePath(state, "recovery-handoff.json")
	var handoff records.RecoveryHandoff
	if err != nil || records.ReadJSON(path, &handoff) != nil || len(input.Scenarios) != 1 || handoff.Validate(input.RunID, input.Scenarios[0], input.Prefix) != nil {
		return records.RecoveryHandoff{}, errors.New("same-domain recovery handoff unavailable")
	}
	inventoryPath, err := records.SafePath(state, "inventory.json")
	var inventory sameDomainInventoryRecord
	if err != nil || records.ReadJSON(inventoryPath, &inventory) != nil || inventory.Version != 1 || inventory.Binding == "" || inventory.Intents == nil || inventory.Deleted == nil || inventory.RunID != input.RunID || inventory.Prefix != input.Prefix || inventory.Domain != handoff.Domain {
		return records.RecoveryHandoff{}, errors.New("same-domain inventory differs from handoff")
	}
	return handoff, nil
}

func addReservations(a, b *records.BudgetReservation) (*records.BudgetReservation, error) {
	if a == nil || b == nil {
		return nil, errors.New("combined budget evidence unavailable")
	}
	out := &records.BudgetReservation{}
	for _, row := range []struct{ dst, left, right *uint64 }{
		{&out.Requests, &a.Requests, &b.Requests},
		{&out.BodyBytes, &a.BodyBytes, &b.BodyBytes},
		{&out.Objects, &a.Objects, &b.Objects},
		{&out.ObjectBytes, &a.ObjectBytes, &b.ObjectBytes},
		{&out.GeneratorCreates, &a.GeneratorCreates, &b.GeneratorCreates},
		{&out.GeneratorRetires, &a.GeneratorRetires, &b.GeneratorRetires},
	} {
		value, carry := bits.Add64(*row.left, *row.right, 0)
		if carry != 0 {
			return nil, errors.New("combined budget evidence overflow")
		}
		*row.dst = value
	}
	return out, nil
}

func (s *runState) executeSameDomainRerun(ctx context.Context, binary string, writer records.Invocation, input workerInput, allowance limits, deadline time.Time, elapsed time.Duration, result *scenarioResult, first records.WorkerResult) (records.WorkerResult, string, bool, error) {
	if _, err := readSameDomainHandoff(writer.StateDir, input); err != nil {
		return records.WorkerResult{}, "", true, err
	}
	remaining := allowance
	zeroCleanup := &records.BudgetReservation{}
	if err := debitBudget(&remaining, result.BudgetReserved, zeroCleanup, elapsed, 0); err != nil || !remaining.valid() || time.Until(deadline) <= 0 {
		return records.WorkerResult{}, "", true, errors.New("same-domain rerun allowance exhausted")
	}
	rerunInput := input
	rerunInput.Limits = &remaining
	inputPath := filepath.Join(writer.StateDir, "rerun-input.json")
	if err := records.WriteJSON(inputPath, rerunInput, 0400); err != nil {
		return records.WorkerResult{}, "", true, err
	}
	inv, err := makeInvocation(records.Invocation{Scenario: writer.Scenario, FailureSources: s.failureSources, TelemetrySettings: s.telemetrySettings, RunID: writer.RunID,
		Worker: writer.Worker + "-rerun", Role: "rerun", Input: inputPath, StateDir: writer.StateDir,
		OutputDir: filepath.Join(writer.StateDir, "workers", "rerun")}, s.record.Suite)
	if err != nil {
		return records.WorkerResult{}, "", true, err
	}
	result.FirstFailure = first.Failure
	if err := s.save(); err != nil {
		return records.WorkerResult{}, "", true, err
	}
	process := runInvocation(ctx, binary, s.root, "live", inv, time.Until(deadline), s.record.Telemetry.Enabled)
	evidence, raw, workerErr := s.importWorker(inv, result.Scenario, process, nil)
	result.Rerun = &evidence
	reservation, reservationErr := workerReservation(inv, false)
	if reservationErr == nil {
		result.BudgetReserved, reservationErr = addReservations(result.BudgetReserved, reservation)
	}
	if err := s.save(); err != nil {
		return raw, inputPath, process.Joined, err
	}
	if workerErr != nil || reservationErr != nil {
		return raw, inputPath, process.Joined, errors.Join(workerErr, reservationErr, errors.New("same-domain rerun failed"))
	}
	return raw, inputPath, process.Joined, nil
}

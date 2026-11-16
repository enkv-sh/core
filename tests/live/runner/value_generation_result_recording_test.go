package core

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

type liveGeneratedRecordOutput struct {
	SelectedDigest string `json:"selected_digest"`
}

func liveGeneratedFreshFacts(t testing.TB, admitted OpenContext, session *StateSession, domain contract.ID, prefix string) freshFacts {
	t.Helper()
	facts := freshFacts{Domain: domain, Prefix: prefix, Expected: sessionStateImage(t, session), Receipts: freshReceiptExpectations(t, session)}
	if admitted.admission.current != nil {
		basis := successionBasisTransport(admitted.admission.current)
		facts.CurrentBasis = &basis
	} else {
		facts.DomainBasis = bytes.Clone(admitted.admission.descriptor)
	}
	return facts
}

func runLiveGeneratedRecordCheck(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput,
	worker *records.WorkerRecorder, budget *runBudget, inventory *objectInventory, env fixtureEnvironment,
	selected *StateSession, attempt contract.ID, packet []byte) *StateSession {
	t.Helper()
	if selected == nil || attempt.IsZero() || len(packet) == 0 {
		t.Fatal("fresh generated record input refused")
	}
	index := len(worker.Result.Children)
	execution, known := catalog.ExecutionFor(input.Scenarios[0], "live")
	children := execution.ExpandedFreshBefore()
	if !known || index >= len(children) || children[index].Purpose != catalog.FreshGeneratedRecord {
		t.Fatal("generated record child differs from live catalog")
	}
	facts := liveGeneratedFreshFacts(t, OpenContext{admission: &selected.admission}, selected, selected.admission.domain, input.Prefix)
	facts.GeneratedRecord = &generatedRecordInput{Attempt: attempt, Result: bytes.Clone(packet)}
	facts.GeneratedOutput = fmt.Sprintf("fresh-generated-%d.json", index)
	remaining := budget.remaining()
	remaining.GeneratorCreates, remaining.GeneratorRetires = 0, 0
	facts.PhaseLimits = &remaining
	path, err := prepareFreshChild(inv, worker, facts)
	if err != nil {
		t.Fatal("generated record child input refused", err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal("generated record child executable unavailable")
	}
	child, process, err := executeFreshChild(ctx, binary, path)
	worker.Result.Children[len(worker.Result.Children)-1].Process = process
	if worker.Save() != nil {
		t.Fatal("fresh process observation could not be saved")
	}
	if err != nil || child.BudgetReserved == nil {
		t.Fatal("fresh generated record child failed", err)
	}
	reserved := budgetReservation{Requests: child.BudgetReserved.Requests, BodyBytes: child.BudgetReserved.BodyBytes,
		Objects: child.BudgetReserved.Objects, ObjectBytes: child.BudgetReserved.ObjectBytes,
		GeneratorCreates: child.BudgetReserved.GeneratorCreates, GeneratorRetires: child.BudgetReserved.GeneratorRetires}
	if reserved.GeneratorCreates != 0 || reserved.GeneratorRetires != 0 || !budget.absorbChild(reserved) {
		t.Fatal("fresh generated record exceeded remaining live budget")
	}
	outputPath, err := records.SafePath(inv.StateDir, facts.GeneratedOutput)
	var output liveGeneratedRecordOutput
	if err != nil || readPrivateJSON(outputPath, &output) != nil || output.SelectedDigest == "" {
		t.Fatal("fresh generated record selection output missing")
	}
	var updated inventoryImage
	if readPrivateJSON(inventory.path, &updated) != nil || updated.Version != 1 || updated.RunID != input.RunID || updated.Binding != settingsBinding(input.Settings) ||
		updated.Prefix != input.Prefix || updated.Domain != selected.admission.domain {
		t.Fatal("fresh generated record inventory changed identity")
	}
	inventory.mu.Lock()
	inventory.image = updated
	inventory.mu.Unlock()
	cold, result := Open(ctx, OpenContext{admission: &selected.admission}, env.Store)
	if cold == nil || result.Outcome != ObservedCurrent || bodyDigest(cold.body) == bodyDigest(selected.body) || bodyDigest(cold.body) != output.SelectedDigest {
		t.Fatal("fresh generated record did not select authenticated current state", result)
	}
	return cold
}

func runLiveGeneratedRecordChild(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput,
	worker *records.WorkerRecorder, budget *runBudget, backend *liveBackend, inventoryPath string, inventoryImage inventoryImage,
	facts freshFacts, execution catalog.Execution) {
	t.Helper()
	validPurpose := false
	for _, child := range execution.ExpandedFreshBefore() {
		validPurpose = validPurpose || child.Step == facts.Step && child.Purpose == catalog.FreshGeneratedRecord
	}
	limit := facts.PhaseLimits
	if !validPurpose || facts.GeneratedRecord == nil || facts.GeneratedRecord.Attempt.IsZero() || len(facts.GeneratedRecord.Result) == 0 ||
		facts.GeneratedOutput == "" || limit == nil || limit.GeneratorCreates != 0 || limit.GeneratorRetires != 0 ||
		limit.Requests > input.Limits.Requests || limit.BodyBytes > input.Limits.BodyBytes || limit.Objects > input.Limits.Objects || limit.ObjectBytes > input.Limits.ObjectBytes {
		t.Fatal("fresh generated record purpose or finite budget refused")
	}
	budget.limits = *limit
	image := &objectInventory{path: inventoryPath, image: inventoryImage}
	store := recordedStore{Store: backend.Store, inventory: image, budget: budget}
	admission := processPublicAdmission(facts.Domain, backend.Trust.Identity(), backend.Store.Descriptor(), backend.PublicKey, facts.DomainBasis)
	if facts.CurrentBasis != nil {
		current, ok := liveCurrentPublicBasis(input, facts.Domain, facts.CurrentBasis)
		if !ok {
			t.Fatal("fresh generated current basis refused")
		}
		admission = processPublicAdmission(facts.Domain, current.NormalSigning.Binding.Trust, backend.Store.Descriptor(), current.NormalSigning.SPKI, nil)
		admission.admission.current, admission.admission.epoch = facts.CurrentBasis.owned(), current.NormalSigning.Binding.Epoch
	}
	sequence, err := worker.BeginStep(facts.Step, worker.Result.Actor)
	if err != nil {
		t.Fatal("fresh generated record phase refused")
	}
	selected, result := Open(ctx, admission, store)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("fresh generated record cannot open authenticated state", result)
	}
	assertStateImage(t, selected, facts.Expected)
	keys, _, err := openLiveCustody(t, ctx, input, facts.Domain, budget)
	if err != nil {
		t.Fatal("fresh generated record custody refused", err)
	}
	admitted := generatedPlanInputFixture(t, selected).context
	admitted.AdmissionID = contract.Hash(append([]byte("ENKV/live-generated-record/admission/v1\x00"), facts.GeneratedRecord.Attempt[:]...))
	admitted.SessionID = contract.Hash(append([]byte("ENKV/live-generated-record/session/v1\x00"), facts.GeneratedRecord.Attempt[:]...))
	plan, err := selected.generatedRecordRequest(context.Background(), facts.GeneratedRecord.Attempt, facts.GeneratedRecord.Result, admitted)
	if err != nil {
		t.Fatal("fresh generated record request refused", err)
	}
	env := fixtureEnvironment{Store: store, Trust: budgetTrust{Trust: backend.Trust, budget: budget}, Custody: keys}
	prepared := preparePrivateGeneratedRecord(t, env, selected, plan)
	recorded, result := selected.selectCandidate(ctx, prepared.reservation.candidate)
	if recorded == nil || result.Outcome != ObservedCurrent || bodyDigest(recorded.body) == bodyDigest(selected.body) {
		t.Fatal("fresh generated record selection refused", result)
	}
	keys.RetireGenerated()
	outputPath, err := records.SafePath(inv.StateDir, facts.GeneratedOutput)
	if err != nil || writeNewLiveJSON(outputPath, liveGeneratedRecordOutput{SelectedDigest: bodyDigest(recorded.body)}) != nil {
		t.Fatal("fresh generated record output refused")
	}
	if worker.ObservePhase(sequence, facts.Step.Expected) != nil {
		t.Fatal("fresh generated record observation refused")
	}
	liveEndPhase(t, worker, sequence, !budget.exhausted && ctx.Err() == nil)
}

package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"unsafe"

	"enkv.sh/core/contract"
)

func generatedInvocationFinalCaptureFixture(t *testing.T) (*StateSession, *generatedSelection, *generatedFinalPlan, *generatedReservation) {
	t.Helper()
	base := generatedEmptyPredecessor(t)
	reservation, err := base.deriveGeneratedReservation(t.Context(), generatedReservationInputForGenerations(t, base, generatedVectorID(10), []string{"alpha", "omega"}))
	if err != nil {
		t.Fatal(err)
	}
	state := reservation.state
	for i := range 2 {
		work := mustSelectedGeneratedWork(t, state)
		attempt := work.attempts[work.phase.FrontierAttemptID]
		packet := generatedPublicResultFixtureWithRawToken(t, attempt, contract.GeneratorDispositionCompleteCreate, 1, generatedVectorID(byte(90+i)))
		plan, err := state.generatedRecordRequest(t.Context(), attempt.record.AttemptID, packet, generatedContinuationContext(t, state, byte(150+4*i), byte(151+4*i)))
		if err != nil {
			t.Fatal(err)
		}
		next, err := state.deriveGeneratedRecord(t.Context(), plan)
		if err != nil {
			t.Fatal(err)
		}
		state = next.state
	}
	work := mustSelectedGeneratedWork(t, state)
	plan, err := state.generatedFinalRequest(t.Context(), generatedContinuationContext(t, state, 160, 161))
	if err != nil || !plan.selecting || len(plan.entryPlans) != 2 {
		t.Fatal("complete sibling Final", err)
	}
	prepared := make([]contract.CryptoGeneratedValueEntryResult, len(plan.entryPlans))
	for i, row := range plan.entryPlans {
		prepared[i] = generatedPreparedValueEntryFixture(t, state, row)
	}
	proposal, err := state.deriveGeneratedFinal(t.Context(), plan, prepared)
	if err != nil {
		t.Fatal(err)
	}
	return state, work, plan, proposal
}

// full_only: false
func TestGeneratedInvocationCaptureKeepsCompleteSiblingsAfterParentClosure(t *testing.T) {
	state, work, plan, proposal := generatedInvocationFinalCaptureFixture(t)
	capture, err := captureGeneratedFinalInvocationResult(t.Context(), state, work, plan, proposal, nil)
	if err != nil {
		t.Fatal("capture before parent closure", err)
	}
	closed := mustSelectedGeneratedWork(t, proposal.state)
	if closed.parent != nil || len(closed.attempts) != 0 {
		t.Fatal("fixture did not close operational support")
	}
	// Disposal of the owner's borrowed view cannot erase returned facts.
	work.records = nil
	work.attempts = nil
	work.bundles = nil
	work.image = nil
	actual := *proposal.state
	actual.head.K1 = []byte("equivalent proof backing")
	result, err := capture.observe(t.Context(), &actual, Result{Outcome: ObservedCurrent, Evidence: AuthenticatedClosure})
	if err != nil || result.StateResult != "success" || result.CanonicalOutcome != contract.ReceiptCanonicalSelected || result.EffectSummary != contract.ReceiptEffectComplete || len(result.Effects) != 2 || !result.EffectsAvailable || !result.RelatedWorkAvailable {
		t.Fatal("closed parent lost complete original effects", result, err)
	}
	if result.Effects[0].Name != "alpha" || result.Effects[1].Name != "omega" || result.SummaryCounts[contract.ReceiptSummarySuccessCount] != 2 || result.EffectsCommitment == nil || result.EffectsCommitment.Count != 2 {
		t.Fatal("effect order or exact commitment changed")
	}
	for _, effect := range result.Effects {
		if effect.Record.State != contract.GeneratedEffectSucceeded || effect.Target == nil || effect.GenerationID.IsZero() || effect.SummaryClass != contract.ReceiptSummarySuccessCount || !effect.DutyID.IsZero() || !effect.HazardID.IsZero() {
			t.Fatal("selected sibling relation differs", effect)
		}
	}
	if capture.backingBytes == 0 {
		t.Fatal("capture backing was not accounted")
	}
}

// full_only: false
func TestGeneratedInvocationCaptureNeverPromotesUnobservedCandidate(t *testing.T) {
	for _, outcome := range []Outcome{Contention, UnresolvedCommit, AdmissionRefused, EvidenceUnavailable} {
		t.Run(map[Outcome]string{Contention: "contention", UnresolvedCommit: "unknown", AdmissionRefused: "refused", EvidenceUnavailable: "unavailable"}[outcome], func(t *testing.T) {
			state, work, plan, proposal := generatedInvocationFinalCaptureFixture(t)
			capture, err := captureGeneratedFinalInvocationResult(t.Context(), state, work, plan, proposal, nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			result, err := capture.observe(ctx, proposal.state, Result{Outcome: outcome, CommitMayHaveOccurred: outcome == UnresolvedCommit})
			if err != nil || result.CanonicalOutcome != contract.ReceiptCanonicalNotSelected || result.EffectSummary != contract.ReceiptEffectComplete || len(result.Effects) != 2 {
				t.Fatal("candidate observation changed actual effect evidence", result, err)
			}
			for _, effect := range result.Effects {
				if !effect.GenerationID.IsZero() {
					t.Fatal("unobserved candidate supplied canonical generation")
				}
			}
			if result.StateResult == "success" || result.StateResult == "retirement-pending" || result.ReceiptObservation {
				t.Fatal("unobserved candidate became terminal evidence")
			}
		})
	}
	state, work, plan, proposal := generatedInvocationFinalCaptureFixture(t)
	capture, err := captureGeneratedFinalInvocationResult(t.Context(), state, work, plan, proposal, nil)
	if err != nil {
		t.Fatal(err)
	}
	wrong := *proposal.state
	wrong.head.Core.Root.Digest[0] ^= 1
	if _, err := capture.observe(t.Context(), &wrong, Result{Outcome: ObservedCurrent, Evidence: AuthenticatedClosure}); err == nil {
		t.Fatal("different root accepted as exact candidate")
	}
}

// full_only: false
func TestGeneratedInvocationCaptureOwnsUnknownRetirementFactsAndWarnings(t *testing.T) {
	state, attempt, duty := generatedParkedRetirementState(t)
	work := mustSelectedGeneratedWork(t, state)
	expected := work.attempts[attempt.record.AttemptID].record
	target, err := work.retirementTarget(t.Context(), duty)
	if err != nil {
		t.Fatal(err)
	}
	scope := generatedInvocationResultScope{OperationKind: contract.OperationRetireGeneratedGeneration, OperationID: attempt.record.OperationID,
		RequestIdentity: generatedVectorID(240), OriginalPredecessorRevisionID: generatedVectorID(241),
		Effects:       []contract.SupportRecord{work.records[generatedRecordKey{contract.GeneratedAttemptSupportKind, attempt.record.AttemptID}]},
		EffectClasses: map[contract.ID]int{attempt.record.AttemptID: contract.ReceiptSummaryUnknownCount}, RelatedDutyIDs: []contract.ID{duty.DutyID}}
	capture, err := captureGeneratedInvocationResult(t.Context(), state, work, scope, nil)
	if err != nil {
		t.Fatal(err)
	}
	work.records = nil
	work.attempts = nil
	work.bundles = nil
	work.image = nil
	result, err := capture.observe(t.Context(), nil, Result{Outcome: UnresolvedCommit, CommitMayHaveOccurred: true})
	if err != nil || len(result.Effects) != 1 || len(result.Duties) != 1 || !slices.Equal(result.RelatedDutyIDs, []contract.ID{duty.DutyID}) || result.EffectSummary != contract.ReceiptEffectUnknown || result.Duties[0].Target == nil || *result.Duties[0].Target != target {
		t.Fatal("unknown retirement lost its exact selected facts", result, err)
	}
	if !reflect.DeepEqual(result.Effects[0].Record, expected) || result.SummaryCounts[contract.ReceiptSummaryUnknownCount] != 1 || result.UnknownCount != 1 {
		t.Fatal("unknown frontier changed its owner classification")
	}
	hazardState, hazardAttempt, hazard, _ := generatedDeleteHazardForOperation(t, generatedVectorID(97), 1)
	hazardWork := mustSelectedGeneratedWork(t, hazardState)
	hazardScope := generatedInvocationResultScope{OperationKind: contract.OperationRetireGeneratedGeneration, OperationID: hazardAttempt.record.OperationID,
		RequestIdentity: generatedVectorID(238), OriginalPredecessorRevisionID: generatedVectorID(239),
		Effects:       []contract.SupportRecord{hazardWork.records[generatedRecordKey{contract.GeneratedAttemptSupportKind, hazardAttempt.record.AttemptID}]},
		EffectClasses: map[contract.ID]int{hazardAttempt.record.AttemptID: contract.ReceiptSummaryUnknownCount}, RelatedHazardIDs: []contract.ID{hazard.HazardID}}
	hazardCapture, err := captureGeneratedInvocationResult(t.Context(), hazardState, hazardWork, hazardScope, nil)
	if err != nil {
		t.Fatal(err)
	}
	hazardResult, err := hazardCapture.observe(t.Context(), nil, Result{Outcome: EvidenceUnavailable})
	if err != nil || len(hazardResult.Hazards) != 1 || hazardResult.Warnings.PossibleLiveResidue != (hazard.Exposure == contract.GeneratedExposurePossibleLive) || hazardResult.Warnings.LateEffect != (hazard.Exposure == contract.GeneratedExposureLateEffect) {
		t.Fatal("per-effect warning was lost or became a domain warning", hazardResult, err)
	}
}

// full_only: false
func TestGeneratedInvocationResultBackingAccountsSharedFactsOnce(t *testing.T) {
	if unsafe.Sizeof(contract.GeneratorTarget{}) != 296 || unsafe.Sizeof(contract.GeneratorProgress{}) != 128 {
		t.Fatal("safe fact layout changed")
	}
	result := GeneratedInvocationResult{Effects: make([]GeneratedEffectFact, 1), RelatedDutyIDs: make([]contract.ID, 1)}
	result.Effects[0].Name = "owned-name"
	result.Effects[0].Target = &contract.GeneratorTarget{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratorTargetSchema, Name: result.Effects[0].Name}
	result.Effects[0].Progress = make([]contract.GeneratorProgress, 1)
	one, err := generatedInvocationBackingBytes(&result)
	if err != nil {
		t.Fatal(err)
	}
	two, err := generatedInvocationBackingBytes(&result, &result)
	if err != nil || two-one != uint64(unsafe.Sizeof(result)) {
		t.Fatal("shared immutable backing was charged twice", one, two, err)
	}
	want := uint64(unsafe.Sizeof(result)+unsafe.Sizeof(GeneratedEffectFact{})+296+128+32) + uint64(len(result.Effects[0].Name))
	if one != want {
		t.Fatal("owned fact/name/target/progress/ID backing differs", one, want)
	}
}

// full_only: false
func TestGeneratedReceiptObservationSeparatesHistoricalResultFromCurrentObservation(t *testing.T) {
	state, input := generatedTerminalMutationFixture(t, false)
	delta, retained, err := state.generatedTerminalMutation(t.Context(), input)
	if err != nil || !retained {
		t.Fatal(err)
	}
	row := contract.CompactMutationReceipt(delta.NewReceipt)
	row.RequestIdentityDigest = input.Parent.RequestIdentityDigest
	raw, err := contract.EncodeCompactMutationReceipt(row)
	if err != nil {
		t.Fatal(err)
	}
	want := slices.Clone(raw)
	out := installedGeneratedReceiptObservation(PublicApplyResult{RequestID: generatedVectorID(249)}, state, row, raw)
	clear(raw)
	if out.Result.Outcome != ObservedCurrent || out.Result.ObservedRevision != state.head.Core.Revision || out.WarningBits != state.root.WarningBits || out.Payload == nil ||
		out.Payload.ObservedRevisionID != row.ObservedRevisionID || out.Payload.PredecessorRevisionID != row.PredecessorRevisionID || !slices.Equal(out.Receipt, want) {
		t.Fatal("receipt observation changed historical bytes or current observation", out.Result)
	}
	result := out.Generated
	if result == nil || !result.ReceiptObservation || !result.SummaryCountsAvailable || result.EffectsAvailable || result.RelatedWorkAvailable || result.Effects != nil || result.Duties != nil || result.Hazards != nil ||
		result.SummaryCounts != row.SummaryCounts || result.StateResult != "effect-terminal-failure" || !result.Warnings.PossibleLiveResidue || result.EffectsCommitment != nil || result.RelatedDutiesCommitment != nil || result.RelatedHazardsCommitment != nil {
		t.Fatal("historical receipt invented empty vectors or lost its effect warning", result)
	}
}

// full_only: false
func TestGeneratedInvocationCompletionRequiresExactConfirmedProgress(t *testing.T) {
	attempt := generatedVectorID(230)
	ack := contract.GeneratorProgress{Schema: 1, AttemptID: generatedVectorID(229), ResultID: generatedVectorID(231),
		Evidence:      contract.GeneratorDescriptor{Digest: generatedVectorID(232), Length: contract.GeneratedResultCoreLength, Count: 1},
		RequiredSteps: contract.GeneratorConfirmedRequiredSteps, CompletedSteps: contract.GeneratorProgressAcknowledged, CompletionClass: contract.GeneratedCompletionConfirmed}
	confirmed := ack
	confirmed.AttemptID, confirmed.ResultID, confirmed.Evidence.Digest = attempt, generatedVectorID(233), generatedVectorID(234)
	confirmed.CompletedSteps = contract.GeneratorProgressConfirmed
	fact := GeneratedEffectFact{Record: contract.GeneratedAttemptRecord{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratedAttemptRecordSchema, AttemptID: attempt, State: contract.GeneratedEffectUnknown, CompletionClass: contract.GeneratedCompletionConfirmed},
		Action: contract.GeneratorActionDelete, Progress: []contract.GeneratorProgress{ack, confirmed}}
	if !generatedInvocationCompletionValid(fact, contract.GeneratedCompletionConfirmed) || fact.Record.State != contract.GeneratedEffectUnknown {
		t.Fatal("owned reflected completion lost original state")
	}
	fact.Progress = fact.Progress[:1]
	if generatedInvocationCompletionValid(fact, contract.GeneratedCompletionConfirmed) {
		t.Fatal("acknowledgement alone became confirmed completion")
	}
	fact.Progress = append(fact.Progress, confirmed)
	fact.Progress[1].AttemptID = generatedVectorID(235)
	if generatedInvocationCompletionValid(fact, contract.GeneratedCompletionConfirmed) {
		t.Fatal("another attempt's confirmation became this completion")
	}
}

// full_only: false
func TestGeneratedInvocationCaptureSortsRelatedFactsWithoutReorderingEffects(t *testing.T) {
	base := generatedEmptyPredecessor(t)
	reservation, err := base.deriveGeneratedReservation(t.Context(), generatedReservationInputForGenerations(t, base, generatedVectorID(10), []string{"alpha", "omega"}))
	if err != nil {
		t.Fatal(err)
	}
	check := func(t *testing.T, state *StateSession, kind uint8) {
		t.Helper()
		work := mustSelectedGeneratedWork(t, state)
		operational, err := generatedFinalOperationalRows(work, &generatedFinalPlan{}, state.supportRecords())
		if err != nil {
			t.Fatal(err)
		}
		scope := generatedInvocationResultScope{OperationKind: work.bundles[0].Request.OperationKind, OperationID: work.parent.OperationID,
			RequestIdentity: work.parent.RequestIdentityDigest, OriginalPredecessorRevisionID: work.bundles[0].Request.PredecessorRevisionID,
			Effects: operational.effects, EffectClasses: operational.classes}
		var rows []contract.SupportRecord
		for key, row := range work.records {
			if key.kind == kind {
				rows = append(rows, row)
			}
		}
		if len(rows) < 2 {
			t.Fatal("fixture must contain two real related rows", kind, len(rows))
		}
		slices.SortFunc(rows, func(a, b contract.SupportRecord) int { return bytes.Compare(b.RecordID[:], a.RecordID[:]) })
		if kind == contract.GeneratedDutySupportKind {
			scope.Duties = rows
		} else {
			scope.Hazards = rows
		}
		before := slices.Clone(rows)
		result, err := generatedInvocationFacts(t.Context(), work, scope, operational.effects, scope.Duties, scope.Hazards)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(rows, before) {
			t.Fatal("capture reordered borrowed related rows")
		}
		ordered := slices.Clone(rows)
		slices.Reverse(ordered)
		label := "result-duties"
		commitment := result.RelatedDutiesCommitment
		if kind == contract.GeneratedHazardSupportKind {
			label, commitment = "result-hazards", result.RelatedHazardsCommitment
		}
		want := generatedResultVectorFraming(label, ordered)
		if commitment == nil || *commitment != want {
			t.Error("related commitment does not describe exact returned order", commitment, want)
		}
		for _, count := range []int{0, 1, len(ordered)} {
			t.Run(fmt.Sprint(count), func(t *testing.T) {
				duties, hazards := ordered[:count], []contract.SupportRecord(nil)
				if kind == contract.GeneratedHazardSupportKind {
					duties, hazards = nil, duties
				}
				canonical, err := generatedInvocationFacts(t.Context(), work, scope, operational.effects, duties, hazards)
				if err != nil {
					t.Fatal(err)
				}
				got := canonical.RelatedDutiesCommitment
				if kind == contract.GeneratedHazardSupportKind {
					got = canonical.RelatedHazardsCommitment
				}
				if got == nil || *got != generatedResultVectorFraming(label, ordered[:count]) || !canonical.RelatedWorkAvailable {
					t.Fatal("canonical related vector lost exact complete commitment", got)
				}
				if count == len(ordered) && !reflect.DeepEqual(canonical, result) {
					t.Error("source order changed returned facts or commitment")
				}
			})
		}
		for i, row := range operational.effects {
			if result.Effects[i].Record.AttemptID != row.RecordID {
				t.Fatal("effect lineage order changed")
			}
		}
		if kind == contract.GeneratedDutySupportKind {
			for i, fact := range result.Duties {
				if fact.Record.DutyID != result.RelatedDutyIDs[i] || i > 0 && bytes.Compare(result.Duties[i-1].Record.DutyID[:], fact.Record.DutyID[:]) >= 0 {
					t.Fatal("sorted related Duty IDs no longer identify their paired facts")
				}
			}
		} else {
			for i, fact := range result.Hazards {
				if fact.Record.HazardID != result.RelatedHazardIDs[i] || i > 0 && bytes.Compare(result.Hazards[i-1].Record.HazardID[:], fact.Record.HazardID[:]) >= 0 {
					t.Fatal("sorted related Hazard IDs no longer identify their paired facts")
				}
			}
		}
	}
	t.Run("duties", func(t *testing.T) { check(t, reservation.state, contract.GeneratedDutySupportKind) })
	t.Run("hazards", func(t *testing.T) {
		state := generatedRetainedClosureResidue(t, reservation.state, 230)
		state = generatedReservePlannedSuccessor(t, state, 232)
		state = generatedRetainedClosureResidue(t, state, 234)
		check(t, state, contract.GeneratedHazardSupportKind)
	})
}

// The result-vector wire grammar is length/count, then length-prefixed typed
// records. This independent framing uses only returned raw record bytes.
func generatedResultVectorFraming(label string, rows []contract.SupportRecord) contract.GeneratorDescriptor {
	length := 4
	for _, row := range rows {
		length += 4 + 37 + len(row.Body)
	}
	body := []byte("ENKV/GENERATOR/v1/" + label + "\x00")
	body = binary.BigEndian.AppendUint32(body, uint32(length))
	body = binary.BigEndian.AppendUint32(body, uint32(len(rows)))
	for _, row := range rows {
		body = binary.BigEndian.AppendUint32(body, uint32(37+len(row.Body)))
		body = append(body, row.Kind)
		body = append(body, row.RecordID[:]...)
		body = binary.BigEndian.AppendUint32(body, uint32(len(row.Body)))
		body = append(body, row.Body...)
	}
	return contract.GeneratorDescriptor{Digest: sha256.Sum256(body), Length: uint64(length), Count: uint32(len(rows))}
}

// full_only: false
func TestGeneratedReleasedDeleteTargetRequiresExactSelectedIdentity(t *testing.T) {
	state, attempt := installedGeneratedUnknownCleanupFixture(t, contract.GeneratedCompletionAcknowledged, false)
	packet := generatedRetirementResultFixture(t, state, attempt, contract.GeneratorDispositionRetirementAcknowledged)
	plan, err := state.generatedReflectionPlan(t.Context(), attempt.record.ResultID, packet, generatedLifecycleFixture(t, state))
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := state.deriveGeneratedLifecycle(t.Context(), plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	before, selected := mustSelectedGeneratedWork(t, state), mustSelectedGeneratedWork(t, proposal.state)
	original, err := generatedEffectFact(t.Context(), before, attempt.record.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	effect, err := generatedEffectFact(t.Context(), selected, attempt.record.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	if original.Target == nil || effect.Target != nil {
		t.Fatal("fixture does not cross Target-owner release")
	}
	target, err := generatedReleasedDeleteTarget(before, selected, original, effect)
	if err != nil || target != original.Target {
		t.Fatal("exact released request lost immutable owned Target", err)
	}
	for _, name := range []string{"token", "resource", "account", "profile", "assumption", "request", "domain", "template", "result", "inbox", "unobserved"} {
		t.Run(name, func(t *testing.T) {
			old, next := *before, *selected
			prior := before.attempts[attempt.record.AttemptID]
			release := selected.releases[attempt.record.AttemptID]
			from, to := original, effect
			damagedTarget := *original.Target
			from.Target = &damagedTarget
			switch name {
			case "token":
				damagedTarget.ResourceDigest = generatedVectorID(201)
			case "resource":
				damagedTarget.ResourceID = generatedVectorID(202)
			case "account":
				damagedTarget.ResourceContractID = generatedVectorID(203)
			case "profile":
				damagedTarget.ConfigContractID = generatedVectorID(204)
			case "assumption":
				damagedTarget.ResourceContractID = generatedVectorID(205)
			case "request":
				to.Record.RequestDigest = generatedVectorID(206)
				release.attempt = to.Record
			case "domain":
				to.Record.DomainID = generatedVectorID(207)
				release.attempt = to.Record
				release.release.DomainID = to.Record.DomainID
			case "template":
				release.template.ResourceContractID = generatedVectorID(208)
			case "result":
				release.release.OriginalResultID = generatedVectorID(209)
			case "inbox":
				release.release.InboxID = generatedVectorID(210)
			case "unobserved":
				release.release.State = contract.GeneratedReleaseUnobserved
			}
			old.attempts = map[contract.ID]generatedAttempt{attempt.record.AttemptID: prior}
			next.releases = map[contract.ID]generatedReleasedAttempt{attempt.record.AttemptID: release}
			if _, err := generatedReleasedDeleteTarget(&old, &next, from, to); err == nil {
				t.Fatal("different identity became original released Target")
			}
		})
	}
}

// full_only: false
func TestGeneratedFailedFinalReceiptCommitsCanonicalRelatedOrder(t *testing.T) {
	base := generatedEmptyPredecessor(t)
	reservation, err := base.deriveGeneratedReservation(t.Context(), generatedReservationInputForGenerations(t, base, generatedVectorID(19), []string{"alpha", "omega"}))
	if err != nil {
		t.Fatal(err)
	}
	state := generatedRetainedClosureResidue(t, reservation.state, 230)
	state = generatedReservePlannedSuccessor(t, state, 232)
	state = generatedRetainedClosureResidue(t, state, 234)
	work := mustSelectedGeneratedWork(t, state)
	last := work.attempts[work.phase.FrontierAttemptID]
	if work.bundles[0].Lineages[work.phase.LineageIndex].Name != "omega" {
		t.Fatal("exhausted alpha lineage did not reach omega")
	}
	packet := generatedPublicResultFixtureWithRawToken(t, last, contract.GeneratorDispositionOwnedUnusableCreate, 0, generatedVectorID(98))
	record, err := state.generatedRecordRequest(t.Context(), last.record.AttemptID, packet, generatedContinuationContext(t, state, 236, 237))
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := state.deriveGeneratedRecord(t.Context(), record)
	if err != nil {
		t.Fatal(err)
	}
	state = recorded.state
	work = mustSelectedGeneratedWork(t, state)
	plan, err := state.generatedFinalRequest(t.Context(), generatedContinuationContext(t, state, 238, 239))
	if err != nil || plan.selecting {
		t.Fatal("exhausted mixed aggregate requires nonselecting Final", err)
	}
	proposal, err := state.deriveGeneratedFinal(t.Context(), plan, nil)
	if err != nil {
		t.Fatal("derive exact terminal Final", err)
	}
	wantEffects := []string{"bb42252be043bd03f20b79f5923a00bed57c9b4aa99ffaee42bbc08d7442083d", "7d0cefd00513938ce7b9b8bad2218e4ec1dfa87d635d433244f13c48ca156b2d", "2e38edba47ef402490549cf23b7a43fbba3a9bd9484bd08a7db8a074b9f18dc1"}
	wantHazards := []string{"12d10c2ed4d0a9f86aec1eea1c5bb5f8bb9d5cdc35d824ba3b2dc56ff3f325a7", "1506573557759099d005b0b00ec41bad5d393f56481cfd12eba201c942998c77", "696829b243b55f0ee850015cfc7c7831d28f682a539398d6e98a70e57f976d4e"}
	selectedRows := proposal.state.supportRecords()
	var rows []contract.SupportRecord
	for _, id := range wantHazards {
		position := slices.IndexFunc(selectedRows, func(row contract.SupportRecord) bool {
			return row.Kind == contract.GeneratedHazardSupportKind && fmt.Sprintf("%x", row.RecordID) == id
		})
		if position < 0 {
			t.Fatal("fixture does not contain the independently derived Hazard", id)
		}
		rows = append(rows, selectedRows[position])
	}
	capture, err := captureGeneratedFinalInvocationResult(t.Context(), state, work, plan, proposal, nil)
	if err != nil {
		t.Fatal("Final receipt disagrees with complete canonical related facts", err)
	}
	result, err := capture.observe(t.Context(), proposal.state, Result{Outcome: ObservedCurrent, Evidence: AuthenticatedClosure})
	if err != nil || result == nil || len(result.Effects) != 3 || len(result.Hazards) != 3 || result.RelatedHazardsCommitment == nil || *result.RelatedHazardsCommitment != generatedResultVectorFraming("result-hazards", rows) {
		t.Fatal("terminal Final lost exact canonical related commitment", err)
	}
	for i, want := range wantEffects {
		if fmt.Sprintf("%x", result.Effects[i].Record.AttemptID) != want {
			t.Fatal("Final changed lineage/template effect order", i)
		}
	}
	for i, want := range wantHazards {
		if fmt.Sprintf("%x", result.Hazards[i].Record.HazardID) != want || result.RelatedHazardIDs[i] != result.Hazards[i].Record.HazardID {
			t.Fatal("Final returned a different canonical related order", i)
		}
	}
}

// full_only: false
func TestGeneratedFailedFinalReceiptCommitsCanonicalDutyOrder(t *testing.T) {
	base := generatedEmptyPredecessor(t)
	reservation, err := base.deriveGeneratedReservation(t.Context(), generatedReservationInputForGenerations(t, base, generatedVectorID(19), []string{"alpha", "beta", "omega"}))
	if err != nil {
		t.Fatal(err)
	}
	state := reservation.state
	for i, name := range []string{"alpha", "beta", "omega"} {
		work := mustSelectedGeneratedWork(t, state)
		attempt := work.attempts[work.phase.FrontierAttemptID]
		if work.bundles[0].Lineages[work.phase.LineageIndex].Name != name {
			t.Fatal("Final fixture lost actual lineage order", name)
		}
		disposition, raw := uint8(contract.GeneratorDispositionCompleteCreate), uint32(1)
		if name == "omega" {
			disposition, raw = contract.GeneratorDispositionOwnedUnusableCreate, 0
		}
		packet := generatedPublicResultFixtureWithRawToken(t, attempt, disposition, raw, generatedVectorID(byte(90+i)))
		record, err := state.generatedRecordRequest(t.Context(), attempt.record.AttemptID, packet, generatedContinuationContext(t, state, byte(150+4*i), byte(151+4*i)))
		if err != nil {
			t.Fatal(err)
		}
		recorded, err := state.deriveGeneratedRecord(t.Context(), record)
		if err != nil {
			t.Fatal(err)
		}
		state = recorded.state
	}
	work := mustSelectedGeneratedWork(t, state)
	plan, err := state.generatedFinalRequest(t.Context(), generatedContinuationContext(t, state, 170, 171))
	if err != nil || plan.selecting {
		t.Fatal("mixed aggregate requires nonselecting Final", err)
	}
	proposal, err := state.deriveGeneratedFinal(t.Context(), plan, nil)
	if err != nil {
		t.Fatal("derive exact terminal Final", err)
	}
	wantEffects := []string{"bb42252be043bd03f20b79f5923a00bed57c9b4aa99ffaee42bbc08d7442083d", "94cd36f977abb6e963f083a33b924c8176f8211113f963345e4d71c044205621", "2e38edba47ef402490549cf23b7a43fbba3a9bd9484bd08a7db8a074b9f18dc1"}
	wantDuties := []string{"8577581f30ed66e3fb2d91ca432b6bf43c4481efaa5f873df5e5ad1e74be79d2", "912d243ecfd506dad7de0136c3499e25b62018481a2e297e4f477b7a30ef289b"}
	selectedRows := proposal.state.supportRecords()
	var rows []contract.SupportRecord
	for _, id := range wantDuties {
		position := slices.IndexFunc(selectedRows, func(row contract.SupportRecord) bool {
			return row.Kind == contract.GeneratedDutySupportKind && fmt.Sprintf("%x", row.RecordID) == id
		})
		if position < 0 {
			t.Fatal("fixture does not contain the independently derived Duty", id)
		}
		rows = append(rows, selectedRows[position])
	}
	capture, err := captureGeneratedFinalInvocationResult(t.Context(), state, work, plan, proposal, nil)
	if err != nil {
		t.Fatal("Final receipt disagrees with complete canonical Duty facts", err)
	}
	result, err := capture.observe(t.Context(), proposal.state, Result{Outcome: ObservedCurrent, Evidence: AuthenticatedClosure})
	if err != nil || result == nil || len(result.Effects) != 3 || len(result.Duties) != 2 || result.RelatedDutiesCommitment == nil || *result.RelatedDutiesCommitment != generatedResultVectorFraming("result-duties", rows) {
		t.Fatal("terminal Final lost exact canonical Duty commitment", err)
	}
	for i, want := range wantEffects {
		if fmt.Sprintf("%x", result.Effects[i].Record.AttemptID) != want {
			t.Fatal("Final changed lineage/template effect order", i)
		}
	}
	for i, want := range wantDuties {
		if fmt.Sprintf("%x", result.Duties[i].Record.DutyID) != want || result.RelatedDutyIDs[i] != result.Duties[i].Record.DutyID {
			t.Fatal("Final returned a different canonical Duty order", i)
		}
	}
}

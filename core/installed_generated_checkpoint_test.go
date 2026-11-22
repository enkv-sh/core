package core

import (
	"context"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedPersistenceStopKeepsConflictAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	selected := Result{Outcome: ObservedCurrent, Evidence: AuthenticatedClosure}
	out := PublicApplyResult{Result: selected}
	if !out.stopForResultPersistence(ctx, failure(IntegrityFailure, ImmutableConflict)) || out.Result != selected ||
		len(out.Diagnostics) != 1 || out.Diagnostics[0].Reason != contract.ReasonImmutableConflict || !out.Diagnostics[0].ImmutableConflictShape() {
		t.Fatal("cancelled caller hid a confirmed Store conflict")
	}
}

// full_only: false
func TestGeneratedSelectionCheckpointPreservesSelectionAndClosedFailureReason(t *testing.T) {
	actual := PublicApplyResult{OperationID: generatedVectorID(41), Result: Result{Outcome: ObservedCurrent, RequestedRevision: generatedVectorID(42), ObservedRevision: generatedVectorID(42), ObservedSnapshotID: generatedVectorID(43), Evidence: AuthenticatedClosure}, Generated: &GeneratedInvocationResult{OperationKind: contract.OperationApplyDeclaration}, Receipt: []byte{1}, WarningBits: 3}
	var checkpoint generatedSelectionCheckpoint
	checkpoint.recordSelected(actual)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, test := range []struct {
		name    string
		ctx     context.Context
		failure Result
		reason  contract.DiagnosticReason
	}{
		{"cancel", cancelled, failure(EvidenceUnavailable, ReadUnavailable), contract.ReasonCancelled},
		{"capacity", t.Context(), refused(CapacityExceeded), contract.ReasonLimitExceeded},
		{"proof", t.Context(), failure(IntegrityFailure, InvalidProof), contract.ReasonProofInvalid},
		{"relation", t.Context(), failure(IntegrityFailure, InvalidRelation), contract.ReasonSelectedRelationInvalid},
		{"read", t.Context(), failure(EvidenceUnavailable, ReadUnavailable), contract.ReasonSelectedObjectUnavailable},
		{"admission", t.Context(), refused(AdmissionInvalid), contract.ReasonInvalidInput},
		{"sign", t.Context(), failure(EvidenceUnavailable, SigningUnavailable), contract.ReasonEvidenceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			out := checkpoint.preparationFailure(test.ctx, PublicApplyResult{OperationID: actual.OperationID}, test.failure)
			if out.Result != actual.Result || out.Generated != actual.Generated || &out.Receipt[0] != &actual.Receipt[0] || out.WarningBits != actual.WarningBits || len(out.Diagnostics) != 1 || out.Diagnostics[0].Outcome != contract.DiagnosticUnable || out.Diagnostics[0].Reason != test.reason {
				t.Fatal("later preparation replaced selection or its safe evidence", out)
			}
		})
	}
	// A later passive observation or a pre-selector refusal cannot replace CAS evidence.
	checkpoint.recordSelected(PublicApplyResult{Result: Result{Outcome: ObservedCurrent, Evidence: AuthenticatedClosure}})
	checkpoint.recordSelected(PublicApplyResult{Result: refused(AdmissionInvalid)})
	if checkpoint.result != actual.Result || checkpoint.generated != actual.Generated {
		t.Fatal("read/preparation became a selection")
	}
}

// full_only: false
func TestGeneratedInvocationCaptureReusesOwnedBeforeWithoutRetainingUnusedVariant(t *testing.T) {
	state, work, plan, proposal := generatedInvocationFinalCaptureFixture(t)
	scope, err := generatedActiveResultScope(work)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := generatedInvocationFacts(t.Context(), work, scope, scope.Effects, scope.Duties, scope.Hazards)
	if err != nil {
		t.Fatal(err)
	}
	original := facts.Effects[0]
	var checkpoint generatedSelectionCheckpoint
	result := state.observed(ObservedCurrent)
	result.RequestedRevision = state.head.Core.Revision
	checkpoint.recordSelected(PublicApplyResult{OperationID: scope.OperationID, Result: result, Generated: &facts})
	capture, err := captureGeneratedFinalInvocationResult(t.Context(), state, work, plan, proposal, &checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if &capture.observed.Effects[0] != &facts.Effects[0] {
		t.Fatal("before vector was cloned")
	}
	selected, err := capture.observe(t.Context(), proposal.state, Result{Outcome: ObservedCurrent, Evidence: AuthenticatedClosure})
	if err != nil {
		t.Fatal(err)
	}
	if selected != &capture.selected || len(capture.observed.Effects) != 0 || len(capture.observed.Duties) != 0 || len(capture.observed.Hazards) != 0 || capture.hasCandidate || capture.candidate.session != nil || capture.candidate.head.Generator != nil {
		t.Fatal("unused before or candidate was retained")
	}
	if facts.Effects[0].Record != original.Record || facts.Effects[0].GenerationID != original.GenerationID || facts.Effects[0].SummaryClass != original.SummaryClass {
		t.Fatal("selected projection changed immutable before facts")
	}
}

// full_only: false
func TestGeneratedPassivePreparationFailureClosesStateWithoutOwningSelection(t *testing.T) {
	for _, kind := range []uint16{contract.OperationApplyDeclaration, contract.OperationRetireGeneratedGeneration} {
		name := "apply"
		if kind == contract.OperationRetireGeneratedGeneration {
			name = "retire"
		}
		t.Run(name, func(t *testing.T) {
			facts := &GeneratedInvocationResult{OperationKind: kind, StateResult: "effect-unknown", CanonicalOutcome: contract.ReceiptCanonicalNotSelected, EffectSummary: contract.ReceiptEffectUnknown, EffectsAvailable: true, RelatedWorkAvailable: true, SummaryCountsAvailable: true,
				Effects: []GeneratedEffectFact{{Record: contract.GeneratedAttemptRecord{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratedAttemptRecordSchema, AttemptID: generatedVectorID(51), State: contract.GeneratedEffectTransmitted}, SummaryClass: contract.ReceiptSummaryUnknownCount}},
				Duties:  []GeneratedDutyFact{{Record: contract.GeneratedDutyRecord{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratedDutyRecordSchema, DutyID: generatedVectorID(52)}}}, RelatedDutyIDs: []contract.ID{generatedVectorID(52)}}
			facts.SummaryCounts[contract.ReceiptEffectCount] = 1
			facts.SummaryCounts[contract.ReceiptDutyCount] = 1
			facts.SummaryCounts[contract.ReceiptSummaryUnknownCount] = 1
			var checkpoint generatedSelectionCheckpoint
			failure := refused(AdmissionInvalid)
			out := checkpoint.preparationFailure(t.Context(), PublicApplyResult{Generated: facts}, failure)
			if checkpoint.valid || out.Result != failure || !out.Result.RequestedRevision.IsZero() || out.Payload != nil || len(out.Receipt) != 0 {
				t.Fatal("passive preparation claimed a selection", out)
			}
			if out.Generated == nil {
				t.Fatal("passive evidence was discarded")
			}
			if out.Generated.StateResult != "refused" || out.Generated.CanonicalOutcome != contract.ReceiptCanonicalNotSelected {
				t.Error("passive facts retained a stale invocation state", out.Generated.StateResult, out.Generated.CanonicalOutcome)
			}
			if out.Generated.EffectSummary != facts.EffectSummary || out.Generated.SummaryCounts != facts.SummaryCounts || !out.Generated.EffectsAvailable || !out.Generated.RelatedWorkAvailable || !out.Generated.SummaryCountsAvailable || &out.Generated.Effects[0] != &facts.Effects[0] || &out.Generated.Duties[0] != &facts.Duties[0] || &out.Generated.RelatedDutyIDs[0] != &facts.RelatedDutyIDs[0] {
				t.Error("closed preparation state lost or cloned passive evidence")
			}
			if facts.StateResult != "effect-unknown" {
				t.Error("closing result mutated immutable before header")
			}
		})
	}
}

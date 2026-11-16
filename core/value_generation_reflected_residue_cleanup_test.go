package core

import (
	"bytes"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedReflectedResidueCreateContinuesToFirstCleanup(t *testing.T) {
	base := generatedEmptyPredecessor(t)
	reservation, err := base.deriveGeneratedReservation(t.Context(), generatedReservationInputFixture(t, base))
	if err != nil {
		t.Fatal("initial reservation", err)
	}
	s := reservation.state
	g := mustSelectedGeneratedWork(t, s)
	original := g.attempts[g.phase.FrontierAttemptID]
	// Both fences use the real producer. Exhaust the one residue-successor
	// allowance so a nonselecting Final can detach the original obligations.
	s = generatedRetainedClosureResidue(t, s, 230)
	s = generatedReservePlannedSuccessor(t, s, 232)
	g = mustSelectedGeneratedWork(t, s)
	sibling := g.attempts[g.phase.FrontierAttemptID]
	s = generatedRetainedClosureResidue(t, s, 234)
	finalPlan, err := s.generatedFinalRequest(t.Context(), generatedContinuationContext(t, s, 236, 237))
	if err != nil || finalPlan.selecting {
		t.Fatal("exhausted operation must admit nonselecting Final", err)
	}
	final, err := s.deriveGeneratedFinal(t.Context(), finalPlan, nil)
	if err != nil {
		t.Fatal("nonselecting Final", err)
	}
	s = final.state
	s.generatedWork = nil
	if err := s.validateGeneratedSelection(t.Context(), nil); err != nil {
		t.Fatal("cold nonselecting Final", err)
	}
	g = mustSelectedGeneratedWork(t, s)
	if g.parent != nil || g.phase != nil || len(g.attempts) != 2 || s.root.Generated.Hazards != 2 {
		t.Fatal("Final must retain exactly both uncertain creates")
	}
	original = g.attempts[original.record.AttemptID]
	if original.record.State != contract.GeneratedEffectClosedWithResidue || len(original.result) != 0 {
		t.Fatal("the original must still be unresolved residue")
	}
	historyWant := contract.GeneratorHistory{Schema: 1, PredecessorAttemptID: original.record.AttemptID,
		OwnerID: original.record.OwnerID, Outcome: contract.GeneratedEffectClosedWithResidue}
	checkHistory := func(g *generatedSelection, kind uint8, owner contract.ID, descriptor contract.GeneratorDescriptor) {
		t.Helper()
		rows, err := g.vectors.resolve(kind, owner, contract.GeneratorVectorHistory, descriptor)
		if err != nil || len(rows) != 1 {
			t.Fatal("one immutable unresolved history row", err)
		}
		history, err := contract.InspectGeneratorHistory(rows[0])
		if err != nil || history != historyWant {
			t.Fatal("immutable unresolved history changed", history, err)
		}
	}
	checkHistory(g, contract.GeneratedAttemptSupportKind, original.record.AttemptID, original.record.History)
	packet := generatedPublicResultFixture(t, original, contract.GeneratorDispositionCompleteCreate)
	reflectionPlan, err := s.generatedReflectionPlan(t.Context(), original.record.ResultID, packet, generatedContinuationContext(t, s, 238, 239))
	if err != nil {
		t.Fatal("exact late original reflection plan", err)
	}
	reflected, err := s.deriveGeneratedReflection(t.Context(), reflectionPlan)
	if err != nil {
		t.Fatal("exact late original reflection", err)
	}
	s = reflected.state
	s.generatedWork = nil
	if err := s.validateGeneratedSelection(t.Context(), nil); err != nil {
		t.Fatal("cold reflected state", err)
	}
	g = mustSelectedGeneratedWork(t, s)
	a := g.attempts[original.record.AttemptID]
	if a.record.State != contract.GeneratedEffectClosedWithResidue || !bytes.Equal(a.result, packet) ||
		g.parent != nil || g.phase != nil || len(g.attempts) != 2 || s.root.Generated.Hazards != 2 {
		t.Fatal("reflection must record the exact result without changing the historical outcome or entering cleanup")
	}
	selection, ok, err := g.selectGeneratedCleanup(t.Context(), nil)
	if err != nil || !ok || selection.kind != generatedCleanupHazard || selection.hazard.HazardID != original.expected.Template.HazardID ||
		selection.hazard.Exposure != contract.GeneratedExposureLateEffect || selection.hazard.Eligibility != contract.GeneratedExposureLateEffect ||
		selection.target.ResourceDigest != generatedFixtureResourceDigest(original.record.ResourceContractID, generatedVectorID(97)) || selection.target.OriginalAttemptID != original.record.AttemptID ||
		selection.target.ResourceID != original.record.ResourceID || selection.target.CompletionClass != contract.GeneratedCompletionAcknowledged {
		t.Fatal("the reflected original must become the first eligible owned cleanup", err)
	}
	checkHistory(g, contract.GeneratedAttemptSupportKind, a.record.AttemptID, a.record.History)
	checkHistory(g, contract.GeneratedHazardSupportKind, selection.hazard.HazardID, selection.hazard.History)
	source, err := contract.InspectGeneratedDeleteSource(g.records[selection.sourceKey()])
	if err != nil {
		t.Fatal(err)
	}
	cleanup, err := s.deriveGeneratedReservation(t.Context(), generatedOrdinaryCleanupReservationInput(t, s, source, generatedVectorID(180)))
	if err != nil {
		t.Fatal("first cleanup of a qualified late create must remain reachable", err)
	}
	s = cleanup.state
	s.generatedWork = nil
	if err := s.validateGeneratedSelection(t.Context(), nil); err != nil {
		t.Fatal("cold first cleanup reservation", err)
	}
	g = mustSelectedGeneratedWork(t, s)
	deleting := g.attempts[g.phase.FrontierAttemptID]
	if deleting.expected.Template.Action != contract.GeneratorActionDelete || deleting.expected.TargetResourceDigest != generatedFixtureResourceDigest(original.record.ResourceContractID, generatedVectorID(97)) ||
		deleting.record.OwnerID != original.record.OwnerID || deleting.record.State != contract.GeneratedEffectTransmitted {
		t.Fatal("cleanup must enter only its exact owned target")
	}
	deletePacket := generatedRetirementResultFixture(t, s, deleting, contract.GeneratorDispositionRetirementAcknowledged)
	recordPlan, err := s.generatedRecordRequest(t.Context(), deleting.record.AttemptID,
		deletePacket, generatedContinuationContext(t, s, 240, 241))
	if err != nil {
		t.Fatal("record exact cleanup acknowledgement", err)
	}
	recorded, err := s.deriveGeneratedRecord(t.Context(), recordPlan)
	if err != nil {
		t.Fatal("cleanup acknowledgement successor", err)
	}
	s = recorded.state
	closePlan, err := s.generatedOrdinaryCleanupClosePlan(t.Context(), deleting.record.AttemptID, generatedContinuationContext(t, s, 242, 243))
	if err != nil {
		t.Fatal("close acknowledged cleanup", err)
	}
	closed, err := s.deriveGeneratedCleanupClose(t.Context(), closePlan)
	if err != nil {
		t.Fatal("cleanup close successor", err)
	}
	s = closed.state
	s.generatedWork = nil
	if err := s.validateGeneratedSelection(t.Context(), nil); err != nil {
		t.Fatal("cold cleanup close", err)
	}
	g = mustSelectedGeneratedWork(t, s)
	if g.parent != nil || g.phase != nil || len(g.attempts) != 1 || len(g.releases) != 2 ||
		!g.hasRecord(generatedRecordKey{contract.GeneratedHazardSupportKind, sibling.expected.Template.HazardID}) ||
		g.hasRecord(generatedRecordKey{contract.GeneratedHazardSupportKind, original.expected.Template.HazardID}) {
		t.Fatal("cleanup must end only its own Hazard and preserve the uncertain sibling")
	}
	for _, expected := range []struct {
		attempt generatedAttempt
		packet  []byte
	}{{original, packet}, {deleting, deletePacket}} {
		released, ok := g.releases[expected.attempt.record.AttemptID]
		if !ok || released.release.State != contract.GeneratedReleasePending ||
			released.release.InboxID != expected.attempt.record.InboxID ||
			released.release.OriginalResultID != expected.attempt.record.ResultID ||
			released.release.SelectedHandoffDigest != contract.Hash(expected.packet) ||
			released.release.ObjectLength != uint32(len(expected.packet)) {
			t.Fatal("both exact observed originals need pending inbox release")
		}
	}
	if _, ok := s.materialAccess(contract.OperationSeedMaterialKind, original.material.Core.OperationMaterialID); !ok {
		t.Fatal("the uncertain sibling still needs the original operation seed")
	}
}

package core

import (
	"bytes"
	"math"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func continuationPhaseTestGrowth(t *testing.T, s *StateSession) continuationGrowth {
	t.Helper()
	g := mustSelectedGeneratedWork(t, s)
	var growth continuationGrowth
	continuationTestReadOnly(t, s, func() {
		population, err := selectedContinuationGroups(t.Context(), g.image, g)
		if err != nil {
			t.Fatal(err)
		}
		// This selected Attempt's width is already reserved. A replacement
		// of it must not be mistaken for a new successor Attempt population.
		if err := boundSelectedPhaseGroup(population, g); err != nil {
			t.Fatal(err)
		}
		growth, err = selectedContinuationGrowth(t.Context(), g.image, g, population)
		if err != nil {
			t.Fatal(err)
		}
	})
	return growth
}

// full_only: false
func TestContinuationCapacityLastRecordPhaseExcludesUnreachableSuccessors(t *testing.T) {
	// Only the finite counter is synthetic. All selected lifecycle facts and
	// the last-step Record below use their real constructors. This request-
	// owner test does not claim a signed history of billions of transitions.
	base := generatedEmptyPredecessor(t)
	reservation, err := base.deriveGeneratedReservation(t.Context(), generatedReservationInputFixture(t, base))
	if err != nil {
		t.Fatal("initial reservation", err)
	}
	s := reservation.state
	continuationTestPhase(t, s, math.MaxUint32-1)
	g := mustSelectedGeneratedWork(t, s)
	a := g.attempts[g.phase.FrontierAttemptID]
	if g.phase.Phase != math.MaxUint32-1 || g.phase.Branch != contract.GeneratorBranchInitial || len(g.attempts) != 1 || len(a.result) != 0 || a.record.State != contract.GeneratedEffectTransmitted {
		t.Fatal("fixture must retain one entered initial producer")
	}
	before := continuationTestSelectedDigest(t, s)
	materialKey := generatedRecordKey{contract.OperationMaterialSupportKind, g.parent.MaterialID}
	material := bytes.Clone(g.records[materialKey].Body)
	if len(material) == 0 {
		t.Fatal("initial seed material support absent")
	}
	bound := continuationTestBound(t, s)
	growth := continuationPhaseTestGrowth(t, s)
	packet := generatedPublicResultFixture(t, a, contract.GeneratorDispositionCompleteCreate)
	request, err := s.generatedRecordRequest(t.Context(), a.record.AttemptID, packet, generatedContinuationContext(t, s, 210, 211))
	if err != nil || request == nil || request.phase.BeforePhase != math.MaxUint32-1 || request.phase.AfterPhase != math.MaxUint32 {
		t.Fatal("lawful final-step Record refused", err)
	}
	recorded, err := s.deriveGeneratedRecord(t.Context(), request)
	if err != nil {
		t.Fatal("derive final-step Record", err)
	}
	continuationTestCandidateWithin(t, recorded.state, bound.Remaining)
	recordedBeforeEnd := continuationTestSelectedDigest(t, recorded.state)
	generatedInstallFixtureSupportReader(t, recorded.state)
	generatedVerifySelectedFixtureSlices(t, recorded.state)
	after := mustSelectedGeneratedWork(t, recorded.state)
	if after.phase.Phase != math.MaxUint32 || after.phase.Stage != contract.GeneratedStageTerminal || !bytes.Equal(after.attempts[a.record.AttemptID].result, packet) ||
		!bytes.Equal(after.records[materialKey].Body, material) || recorded.state.root.CurrentAccess.AccessRoot != s.root.CurrentAccess.AccessRoot || recorded.state.root.AccessRecordCount != s.root.AccessRecordCount {
		t.Fatal("Record lost the original seed/support or added selecting-Final access")
	}
	if plan, err := recorded.state.generatedSuccessorReservationRequest(t.Context(), generatedContinuationContext(t, recorded.state, 212, 213)); err == nil || plan != nil {
		t.Fatal("Reserve exceeded the finite phase budget")
	}
	if plan, err := recorded.state.generatedFinalRequest(t.Context(), generatedContinuationContext(t, recorded.state, 214, 215)); err == nil || plan != nil {
		t.Fatal("Final exceeded the finite phase budget")
	}
	recorded.state.admission.endWorkInvocation = generatedVectorID(235)
	ids := endWorkIDs{operation: generatedVectorID(236), transition: generatedVectorID(237), snapshot: generatedVectorID(238), revision: generatedVectorID(239), receipts: generatedVectorID(240), receiptIndex: generatedVectorID(241)}
	candidate, ended, err := recorded.state.deriveEndWorkCandidate(t.Context(), after.parent.OperationID, ids)
	if err != nil || candidate == nil || ended == nil || !ended.root.Generated.ActiveOwner.IsZero() || !ended.validEndWorkSelection() {
		t.Fatal("phase exhaustion prevented independent administrative ending", err)
	}
	if continuationTestSelectedDigest(t, s) != before || continuationTestSelectedDigest(t, recorded.state) != recordedBeforeEnd || s.prepared || recorded.state.prepared {
		t.Fatal("prefix or ending construction changed its selected predecessor")
	}
	// One step permits the current producer's Record or residue fence. It
	// cannot reserve an unentered create or cleanup Attempt. A current owner
	// may widen, or its Hazard may be added; those are not new Attempt groups.
	var creates, deletes, results continuationPartitionCharge
	for _, mandatory := range []bool{false, true} {
		part := growth.parts[continuationPartition{class: format.CreateContinuationSupport, mandatory: mandatory}]
		creates.count, creates.framed = creates.count+part.count, creates.framed+part.framed
		part = growth.parts[continuationPartition{class: format.DeleteContinuationSupport, mandatory: mandatory}]
		deletes.count, deletes.framed = deletes.count+part.count, deletes.framed+part.framed
		part = growth.parts[continuationPartition{class: format.ResultSupport, mandatory: mandatory}]
		results.count += part.count
	}
	evidence := growth.parts[continuationPartition{class: format.OldValueSupport, mandatory: true}]
	if creates.count != 0 || creates.framed != 0 || deletes.count != 0 || deletes.framed != 0 || results.count != 1 || evidence.count != 0 || evidence.framed != 0 || growth.accessCount != 0 || growth.accessBytes != 0 {
		t.Fatalf("last Record step reserved unreachable successor/result/Final populations: creates=%+v deletes=%+v results=%+v evidence=%+v access=%d/%d", creates, deletes, results, evidence, growth.accessCount, growth.accessBytes)
	}
}

// full_only: false
func TestContinuationCapacityLastReservePhaseExcludesFutureRecord(t *testing.T) {
	// The genuine residue transition supplies a planned unentered frontier.
	// Only its finite Phase counter is moved to this request-owner boundary.
	// This does not claim a signed billion-step history or a private replay.
	s := generatedReservationState(t)
	s = generatedRetainedClosureResidue(t, s, 130)
	continuationTestPhase(t, s, math.MaxUint32-1)
	g := mustSelectedGeneratedWork(t, s)
	x, _, predecessor, err := generatedPlannedSuccessor(g)
	if err != nil || g.phase.Phase != math.MaxUint32-1 || x.Branch != contract.GeneratorBranchResidue {
		t.Fatal("fixture must retain the real planned residue frontier", err)
	}
	if _, entered := g.attempts[x.AttemptID]; entered {
		t.Fatal("planned frontier was already entered")
	}
	before := continuationTestSelectedDigest(t, s)
	materialKey := generatedRecordKey{contract.OperationMaterialSupportKind, g.parent.MaterialID}
	hazardKey := generatedRecordKey{contract.GeneratedHazardSupportKind, g.bundles[0].Lineages[0].Templates[0].HazardID}
	material, hazard := bytes.Clone(g.records[materialKey].Body), bytes.Clone(g.records[hazardKey].Body)
	if len(material) == 0 || len(hazard) == 0 {
		t.Fatal("planned frontier lost original seed or fenced Hazard support")
	}
	bound := continuationTestBound(t, s)
	growth := continuationPhaseTestGrowth(t, s)
	request, err := s.generatedSuccessorReservationRequest(t.Context(), generatedContinuationContext(t, s, 132, 133))
	if err != nil || request == nil || request.attempt != x.AttemptID || request.phase.BeforePhase != math.MaxUint32-1 || request.phase.AfterPhase != math.MaxUint32 {
		t.Fatal("lawful final-step Reserve refused", err)
	}
	reserved, err := s.deriveGeneratedSuccessorReservation(t.Context(), request)
	if err != nil {
		t.Fatal("derive final-step Reserve", err)
	}
	continuationTestCandidateWithin(t, reserved.state, bound.Remaining)
	reservedBeforeEnd := continuationTestSelectedDigest(t, reserved.state)
	generatedInstallFixtureSupportReader(t, reserved.state)
	generatedVerifySelectedFixtureSlices(t, reserved.state)
	after := mustSelectedGeneratedWork(t, reserved.state)
	a := after.attempts[x.AttemptID]
	if after.phase.Phase != math.MaxUint32 || a.record.State != contract.GeneratedEffectTransmitted || len(a.result) != 0 || len(after.attempts) != len(g.attempts)+1 ||
		!bytes.Equal(after.records[materialKey].Body, material) || !bytes.Equal(after.records[hazardKey].Body, hazard) || after.attempts[predecessor.AttemptID].record != predecessor ||
		reserved.state.root.CurrentAccess.AccessRoot != s.root.CurrentAccess.AccessRoot || reserved.state.root.AccessRecordCount != s.root.AccessRecordCount {
		t.Fatal("Reserve lost original obligations or acquired future result/access")
	}
	packet := generatedPublicResultFixture(t, a, contract.GeneratorDispositionCompleteCreate)
	if plan, err := reserved.state.generatedRecordRequest(t.Context(), a.record.AttemptID, packet, generatedContinuationContext(t, reserved.state, 134, 135)); err == nil || plan != nil {
		t.Fatal("new producer acquired Record beyond the finite phase budget")
	}
	if plan, err := reserved.state.generatedFinalRequest(t.Context(), generatedContinuationContext(t, reserved.state, 136, 137)); err == nil || plan != nil {
		t.Fatal("new producer acquired Final beyond the finite phase budget")
	}
	reserved.state.admission.endWorkInvocation = generatedVectorID(235)
	ids := endWorkIDs{operation: generatedVectorID(236), transition: generatedVectorID(237), snapshot: generatedVectorID(238), revision: generatedVectorID(239), receipts: generatedVectorID(240), receiptIndex: generatedVectorID(241)}
	candidate, ended, err := reserved.state.deriveEndWorkCandidate(t.Context(), after.parent.OperationID, ids)
	if err != nil || candidate == nil || ended == nil || !ended.root.Generated.ActiveOwner.IsZero() || !ended.validEndWorkSelection() {
		t.Fatal("exhausted planned frontier prevented independent administrative ending", err)
	}
	if continuationTestSelectedDigest(t, s) != before || continuationTestSelectedDigest(t, reserved.state) != reservedBeforeEnd || s.prepared || reserved.state.prepared {
		t.Fatal("Reserve or ending construction changed its selected predecessor")
	}
	// Only the fixed planned Attempt/Duty can be installed. A new producer's
	// result, residue, cleanup and selecting access all need another phase.
	var creates, deletes, results continuationPartitionCharge
	for _, mandatory := range []bool{false, true} {
		part := growth.parts[continuationPartition{class: format.CreateContinuationSupport, mandatory: mandatory}]
		creates.framed += part.framed
		part = growth.parts[continuationPartition{class: format.DeleteContinuationSupport, mandatory: mandatory}]
		deletes.count, deletes.framed = deletes.count+part.count, deletes.framed+part.framed
		part = growth.parts[continuationPartition{class: format.ResultSupport, mandatory: mandatory}]
		results.count, results.framed = results.count+part.count, results.framed+part.framed
	}
	evidence := growth.parts[continuationPartition{class: format.OldValueSupport, mandatory: true}]
	if growth.templates != 1 || creates.framed == 0 || creates.framed > 65536 || deletes.count != 0 || deletes.framed != 0 || results.count != 0 || results.framed != 0 ||
		evidence.count != 0 || evidence.framed != 0 || growth.accessCount != 0 || growth.accessBytes != 0 {
		t.Fatalf("last Reserve step reserved a future Record/cleanup/Final: templates=%d creates=%+v deletes=%+v results=%+v evidence=%+v access=%d/%d", growth.templates, creates, deletes, results, evidence, growth.accessCount, growth.accessBytes)
	}
}

// full_only: false
func TestContinuationCapacityOriginalsShareOneFiniteResultBudget(t *testing.T) {
	for _, recoveredName := range []string{"alpha", "omega"} {
		t.Run(recoveredName, func(t *testing.T) {
			// The two real original Attempts share this synthetic request-owner
			// counter. It is not a signed history of billions of transitions.
			base := generatedEmptyPredecessor(t)
			reservation, err := base.deriveGeneratedReservation(t.Context(), generatedReservationInputForGenerations(t, base, generatedVectorID(10), []string{"alpha", "omega"}))
			if err != nil {
				t.Fatal("two-original reservation", err)
			}
			s := reservation.state
			continuationTestPhase(t, s, math.MaxUint32-4)
			initial := mustSelectedGeneratedWork(t, s)
			if len(initial.attempts) != 2 || initial.phase.Phase != math.MaxUint32-4 {
				t.Fatal("fixture must have two entered original producers")
			}
			for _, attempt := range initial.attempts {
				if attempt.expected.Template.Branch != contract.GeneratorBranchInitial || attempt.record.State != contract.GeneratedEffectTransmitted || len(attempt.result) != 0 {
					t.Fatal("fixture must have no previously recorded Result")
				}
			}
			source, before := s, continuationTestSelectedDigest(t, s)
			bound := continuationTestBound(t, s)
			growth := continuationPhaseTestGrowth(t, s)
			// Either original can consume the recovery pair. Its NoEffect
			// Record, Reserve and successful Record cost three increments;
			// the other original's Record costs the shared fourth increment.
			for index, name := range []string{"alpha", "omega"} {
				g := mustSelectedGeneratedWork(t, s)
				a := g.attempts[g.phase.FrontierAttemptID]
				if a.expected.Template.Action != contract.GeneratorActionCreate || g.bundles[0].Lineages[g.phase.LineageIndex].Name != name {
					t.Fatal("real Record scheduler changed original order", name)
				}
				nonce := byte(150 + 10*index)
				if name == recoveredName {
					request, err := s.generatedRecordRequest(t.Context(), a.record.AttemptID, generatedPublicResultFixture(t, a, contract.GeneratorDispositionConfirmedNoEffect), generatedContinuationContext(t, s, nonce, nonce+1))
					if err != nil {
						t.Fatal("NoEffect Record within shared budget", err)
					}
					recorded, err := s.deriveGeneratedRecord(t.Context(), request)
					if err != nil {
						t.Fatal(err)
					}
					s = recorded.state
					generatedInstallFixtureSupportReader(t, s)
					generatedVerifySelectedFixtureSlices(t, s)
					s = generatedReservePlannedSuccessor(t, s, nonce+2)
					generatedInstallFixtureSupportReader(t, s)
					generatedVerifySelectedFixtureSlices(t, s)
				}
				g = mustSelectedGeneratedWork(t, s)
				a = g.attempts[g.phase.FrontierAttemptID]
				packet := generatedPublicResultFixtureWithRawToken(t, a, contract.GeneratorDispositionCompleteCreate, 1, generatedVectorID(byte(220+index)))
				request, err := s.generatedRecordRequest(t.Context(), a.record.AttemptID, packet, generatedContinuationContext(t, s, nonce+4, nonce+5))
				if err != nil {
					t.Fatal("successful Record within shared budget", err)
				}
				recorded, err := s.deriveGeneratedRecord(t.Context(), request)
				if err != nil {
					t.Fatal(err)
				}
				s = recorded.state
				generatedInstallFixtureSupportReader(t, s)
				generatedVerifySelectedFixtureSlices(t, s)
			}
			continuationTestCandidateWithin(t, s, bound.Remaining)
			terminal := mustSelectedGeneratedWork(t, s)
			results := 0
			for _, row := range terminal.records {
				if row.Kind == contract.GeneratedResultSupportKind {
					results++
				}
			}
			if terminal.phase.Phase != math.MaxUint32 || terminal.phase.Stage != contract.GeneratedStageTerminal || len(terminal.attempts) != 3 || results != 3 || continuationTestSelectedDigest(t, source) != before || source.prepared || s.prepared {
				t.Fatal("lawful four-increment prefix lost its three Results or predecessor", results)
			}
			// Four selected Results need both original Records and two extra
			// Reserve/Record pairs: six increments. Partial prefixes can enter
			// two recovered Attempts without recording both, so no Attempt
			// ceiling is inferred from this independent Result-row ceiling.
			var resultGrowth uint64
			for _, mandatory := range []bool{false, true} {
				resultGrowth += growth.parts[continuationPartition{class: format.ResultSupport, mandatory: mandatory}].count
			}
			if resultGrowth != 3 {
				t.Fatalf("per-lineage maxima spent the shared four-increment budget more than once: Result rows=%d want3", resultGrowth)
			}
		})
	}
}

// full_only: false
func TestContinuationCapacityOneCanonicalFrontierPreservesPriorResultAndHazard(t *testing.T) {
	base := generatedEmptyPredecessor(t)
	reservation, err := base.deriveGeneratedReservation(t.Context(), generatedReservationInputFixture(t, base))
	if err != nil {
		t.Fatal(err)
	}
	s := reservation.state
	initial := mustSelectedGeneratedWork(t, s)
	if len(initial.bundles[0].ValueEntryPlans) != 1 || initial.bundles[0].ValueEntryPlans[0].IntendedMembership.Count != 1 || s.root.CurrentAccess.Core.Recovery != nil || s.root.Generated.GeneratedCurrent != 0 {
		t.Fatal("fixture must have one intended reader and no selected generation")
	}
	lineage := initial.bundles[0].Lineages[0]
	original := initial.attempts[initial.phase.FrontierAttemptID]
	source, before := s, continuationTestSelectedDigest(t, s)
	bound := continuationTestBound(t, s)
	growth := continuationPhaseTestGrowth(t, s)
	noEffect := generatedPublicResultFixture(t, original, contract.GeneratorDispositionConfirmedNoEffect)
	request, err := s.generatedRecordRequest(t.Context(), original.record.AttemptID, noEffect, generatedContinuationContext(t, s, 150, 151))
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := s.deriveGeneratedRecord(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	s = recorded.state
	generatedInstallFixtureSupportReader(t, s)
	generatedVerifySelectedFixtureSlices(t, s)
	s = generatedReservePlannedSuccessor(t, s, 152)
	generatedInstallFixtureSupportReader(t, s)
	generatedVerifySelectedFixtureSlices(t, s)
	g := mustSelectedGeneratedWork(t, s)
	if pending := g.attempts[g.phase.FrontierAttemptID]; pending.record.AttemptID != lineage.Templates[1].AttemptID || len(pending.result) != 0 {
		t.Fatal("residue fence requires an entered producer without a selected Result")
	}
	s = generatedRetainedClosureResidue(t, s, 154)
	generatedInstallFixtureSupportReader(t, s)
	generatedVerifySelectedFixtureSlices(t, s)
	s = generatedReservePlannedSuccessor(t, s, 156)
	generatedInstallFixtureSupportReader(t, s)
	generatedVerifySelectedFixtureSlices(t, s)
	g = mustSelectedGeneratedWork(t, s)
	frontier := g.attempts[g.phase.FrontierAttemptID]
	if frontier.record.AttemptID != lineage.Templates[3].AttemptID {
		t.Fatal("real recovery owners did not reach branch3")
	}
	complete := generatedPublicResultFixtureWithRawToken(t, frontier, contract.GeneratorDispositionCompleteCreate, 1, generatedVectorID(222))
	request, err = s.generatedRecordRequest(t.Context(), frontier.record.AttemptID, complete, generatedContinuationContext(t, s, 158, 159))
	if err != nil {
		t.Fatal(err)
	}
	recorded, err = s.deriveGeneratedRecord(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	s = recorded.state
	generatedInstallFixtureSupportReader(t, s)
	generatedVerifySelectedFixtureSlices(t, s)
	continuationTestCandidateWithin(t, s, bound.Remaining)
	g = mustSelectedGeneratedWork(t, s)
	results, hazards := 0, 0
	for _, row := range g.records {
		if row.Kind == contract.GeneratedResultSupportKind {
			results++
		}
		if row.Kind == contract.GeneratedHazardSupportKind {
			hazards++
		}
	}
	if results != 2 || hazards != 1 || len(g.attempts) != 3 || !bytes.Equal(g.attempts[original.record.AttemptID].result, noEffect) || !bytes.Equal(g.attempts[frontier.record.AttemptID].result, complete) || len(g.attempts[lineage.Templates[1].AttemptID].result) != 0 {
		t.Fatal("one-frontier witness lost prior Result/Hazard custody", results, hazards)
	}
	terminalGrowth := continuationPhaseTestGrowth(t, s)
	terminalBeforeFinal := continuationTestSelectedDigest(t, s)
	final, err := s.generatedFinalRequest(t.Context(), generatedContinuationContext(t, s, 160, 161))
	if err != nil || final == nil || !final.selecting || len(final.results) != 2 || len(final.entryPlans) != 1 || final.entryPlans[0].Generated.OriginAttemptID != frontier.record.AttemptID || final.entryPlans[0].Generated.CreateResultID != frontier.record.ResultID {
		t.Fatal("real Final did not select exactly the successful frontier", err)
	}
	if continuationTestSelectedDigest(t, source) != before || continuationTestSelectedDigest(t, s) != terminalBeforeFinal || source.prepared || s.prepared {
		t.Fatal("prefix or Final request changed its selected predecessor")
	}
	// Prior Results and the fenced Hazard remain possible custody. They do
	// not each become a selected canonical value. One frontier needs one
	// kind13 evidence row:37 support+120 fixed+452 core+4096 facts;
	// one access row:102 fixed+489 one-reader wrap.
	evidence := growth.parts[continuationPartition{class: format.OldValueSupport, mandatory: true}]
	if evidence.count != 1 || evidence.framed != 4705 || evidence.width != 4705 || growth.accessCount != 1 || growth.accessBytes != 591 || growth.accessWidth != 591 {
		t.Errorf("recovery alternatives duplicated canonical evidence/access: evidence=%+v access=%d/%d/%d", evidence, growth.accessCount, growth.accessBytes, growth.accessWidth)
	}
	// Completion removes recovery choices, but the selecting Final remains
	// reachable and must still install this same single canonical value.
	evidence = terminalGrowth.parts[continuationPartition{class: format.OldValueSupport, mandatory: true}]
	if evidence.count != 1 || evidence.framed != 4705 || evidence.width != 4705 || terminalGrowth.accessCount != 1 || terminalGrowth.accessBytes != 591 || terminalGrowth.accessWidth != 591 {
		t.Errorf("completed frontier lost reachable Final evidence/access: evidence=%+v access=%d/%d/%d", evidence, terminalGrowth.accessCount, terminalGrowth.accessBytes, terminalGrowth.accessWidth)
	}
}

// full_only: false
func TestContinuationCapacityAnchoredAutomaticLastPhaseExcludesNextTarget(t *testing.T) {
	for _, cursor := range []string{"unentered", "pending", "terminal"} {
		t.Run(cursor, func(t *testing.T) {
			base := generatedEmptyPredecessor(t)
			recorded, final := generatedAutomaticPreselectionForNames(t, base, []contract.ID{base.admission.recipient}, []string{"alpha", "omega"})
			s := generatedAutomaticSelectFixture(t, recorded, final)
			initial := mustSelectedGeneratedWork(t, s)
			current, _, ok := generatedAutomaticTemplate(initial, initial.phase.LineageIndex)
			if !ok {
				t.Fatal("initial automatic cursor absent")
			}
			_, next, ok := generatedAutomaticNext(initial, int(initial.phase.LineageIndex))
			if !ok || next.AttemptID == current.AttemptID {
				t.Fatal("fixture needs two distinct automatic targets")
			}
			// Build the entered/ACK states with the real writers first. Only
			// the final finite counter is synthetic, not its signed history.
			if cursor != "unentered" {
				request, err := s.generatedAutomaticReservationRequest(t.Context(), generatedContinuationContext(t, s, 186, 187), generatedVectorID(202))
				if err != nil {
					t.Fatal(err)
				}
				reserved, err := s.deriveGeneratedSuccessorReservation(t.Context(), request)
				if err != nil {
					t.Fatal(err)
				}
				s = reserved.state
				generatedInstallFixtureSupportReader(t, s)
				generatedVerifySelectedFixtureSlices(t, s)
			}
			if cursor == "terminal" {
				g := mustSelectedGeneratedWork(t, s)
				a := g.attempts[current.AttemptID]
				request, err := s.generatedRecordRequest(t.Context(), current.AttemptID, generatedRetirementResultFixture(t, s, a, contract.GeneratorDispositionRetirementAcknowledged), generatedContinuationContext(t, s, 188, 189))
				if err != nil {
					t.Fatal(err)
				}
				acknowledged, err := s.deriveGeneratedRecord(t.Context(), request)
				if err != nil {
					t.Fatal(err)
				}
				s = acknowledged.state
				generatedInstallFixtureSupportReader(t, s)
				generatedVerifySelectedFixtureSlices(t, s)
			}
			continuationTestPhase(t, s, math.MaxUint32-1)
			g := mustSelectedGeneratedWork(t, s)
			anchor := *g.phase
			if !generatedSelectionAnchored(g) || anchor.FrontierAttemptID != current.AttemptID {
				t.Fatal("fixture lost its selected automatic anchor")
			}
			if _, entered := g.attempts[next.AttemptID]; entered {
				t.Fatal("second automatic target already entered")
			}
			dutyKey := generatedRecordKey{contract.GeneratedDutySupportKind, next.DutyID}
			seedKey := generatedRecordKey{contract.OperationMaterialSupportKind, g.parent.MaterialID}
			secondDuty, seed := bytes.Clone(g.records[dutyKey].Body), bytes.Clone(g.records[seedKey].Body)
			if len(secondDuty) == 0 || len(seed) == 0 {
				t.Fatal("unrelated target or shared seed absent")
			}
			currentDuty, err := contract.InspectGeneratedDutyRecord(g.records[generatedRecordKey{contract.GeneratedDutySupportKind, current.DutyID}].Body)
			if err != nil {
				t.Fatal(err)
			}
			target, err := g.retirementTarget(t.Context(), currentDuty)
			if err != nil {
				t.Fatal("selected old retirement target", err)
			}
			access, err := contract.EncodeCurrentAccessSection(s.root.CurrentAccess)
			if err != nil {
				t.Fatal(err)
			}
			var values [][]byte
			for _, name := range s.root.Names {
				entry := *s.valueEntry(name.Slot)
				if cursor == "terminal" && entry.Generated.RetiringDutyID == current.DutyID {
					// Close releases only this pointer, not canonical value data.
					entry.Generated.RetiringDutyPresent, entry.Generated.RetiringDutyID = 0, contract.ID{}
				}
				body, err := contract.EncodeValueEntry(entry)
				if err != nil {
					t.Fatal(err)
				}
				values = append(values, body)
			}
			before := continuationTestSelectedDigest(t, s)
			bound := continuationTestBound(t, s)
			var growth continuationGrowth
			continuationTestReadOnly(t, s, func() {
				population, err := selectedContinuationGroups(t.Context(), g.image, g)
				if err != nil {
					t.Fatal(err)
				}
				if err := boundSelectedPhaseGroup(population, g); err != nil {
					t.Fatal(err)
				}
				if cursor != "unentered" {
					// Isolate new automatic target groups from valid replacement
					// slack in the already-selected current delete owner group.
					const width = uint64(65536)
					population.atLeastWholeGroup(continuationGroupKey{class: format.DeleteContinuationSupport, owner: current.AttemptID}, width/contract.SupportRecordMinLength, width)
				}
				growth, err = selectedContinuationGrowth(t.Context(), g.image, g, population)
				if err != nil {
					t.Fatal(err)
				}
			})
			var after *StateSession
			switch cursor {
			case "unentered":
				request, err := s.generatedAutomaticReservationRequest(t.Context(), generatedContinuationContext(t, s, 210, 211), generatedVectorID(203))
				if err != nil {
					t.Fatal("last-step automatic Reserve", err)
				}
				candidate, err := s.deriveGeneratedSuccessorReservation(t.Context(), request)
				if err != nil {
					t.Fatal(err)
				}
				after = candidate.state
			case "pending":
				a := g.attempts[current.AttemptID]
				request, err := s.generatedRecordRequest(t.Context(), current.AttemptID, generatedRetirementResultFixture(t, s, a, contract.GeneratorDispositionRetirementAcknowledged), generatedContinuationContext(t, s, 210, 211))
				if err != nil {
					t.Fatal("last-step automatic Record", err)
				}
				candidate, err := s.deriveGeneratedRecord(t.Context(), request)
				if err != nil {
					t.Fatal(err)
				}
				after = candidate.state
			case "terminal":
				request, err := s.generatedAutomaticClosePlan(t.Context(), generatedContinuationContext(t, s, 210, 211))
				if err != nil {
					t.Fatal("last-step automatic Close", err)
				}
				candidate, err := s.deriveGeneratedAutomaticClose(t.Context(), request)
				if err != nil {
					t.Fatal(err)
				}
				after = candidate.state
			}
			continuationTestCandidateWithin(t, after, bound.Remaining)
			generatedInstallFixtureSupportReader(t, after)
			generatedVerifySelectedFixtureSlices(t, after)
			afterWork := mustSelectedGeneratedWork(t, after)
			afterAccess, err := contract.EncodeCurrentAccessSection(after.root.CurrentAccess)
			if err != nil || !bytes.Equal(afterAccess, access) || afterWork.phase.Phase != math.MaxUint32 || afterWork.phase.SelectionPhaseID != anchor.SelectionPhaseID || afterWork.phase.ChangedSubjects != anchor.ChangedSubjects || afterWork.phase.ChangedAccess != anchor.ChangedAccess || after.root.AccessRecordCount != s.root.AccessRecordCount || !bytes.Equal(afterWork.records[dutyKey].Body, secondDuty) || !bytes.Equal(afterWork.records[seedKey].Body, seed) {
				t.Fatal("last automatic step changed anchor/access/seed/unrelated target")
			}
			if cursor == "terminal" {
				generatedAssertAutomaticHistory(t, after, current, target)
			} else if retained, err := afterWork.retirementAttemptTarget(t.Context(), afterWork.bundles[0], afterWork.attempts[current.AttemptID].record); err != nil || retained != target {
				t.Fatal("last automatic step changed exact old target custody", err)
			}
			for index, name := range after.root.Names {
				body, err := contract.EncodeValueEntry(*after.valueEntry(name.Slot))
				if err != nil || !bytes.Equal(body, values[index]) {
					t.Fatal("last automatic step changed selected canonical data", err)
				}
			}
			if _, entered := afterWork.attempts[next.AttemptID]; entered {
				t.Fatal("last step entered the second automatic target")
			}
			switch cursor {
			case "unentered":
				a := afterWork.attempts[current.AttemptID]
				if request, err := after.generatedRecordRequest(t.Context(), current.AttemptID, generatedRetirementResultFixture(t, after, a, contract.GeneratorDispositionRetirementAcknowledged), generatedContinuationContext(t, after, 212, 213)); err == nil || request != nil {
					t.Fatal("automatic Record exceeded finite phase budget")
				}
			case "pending":
				if request, err := after.generatedAutomaticClosePlan(t.Context(), generatedContinuationContext(t, after, 212, 213)); err == nil || request != nil {
					t.Fatal("automatic Close exceeded finite phase budget")
				}
			case "terminal":
				if afterWork.phase.FrontierAttemptID != next.AttemptID {
					t.Fatal("Close did not advance to the unentered second target")
				}
				if request, err := after.generatedAutomaticReservationRequest(t.Context(), generatedContinuationContext(t, after, 212, 213), generatedVectorID(204)); err == nil || request != nil {
					t.Fatal("second automatic Reserve exceeded finite phase budget")
				}
			}
			if continuationTestSelectedDigest(t, s) != before || s.prepared || after.prepared {
				t.Fatal("last-step construction changed the selected predecessor")
			}
			var deletes continuationPartitionCharge
			for _, mandatory := range []bool{false, true} {
				part := growth.parts[continuationPartition{class: format.DeleteContinuationSupport, mandatory: mandatory}]
				deletes.count, deletes.framed = deletes.count+part.count, deletes.framed+part.framed
			}
			evidence := growth.parts[continuationPartition{class: format.OldValueSupport, mandatory: true}]
			badDelete := deletes.count != 0 || deletes.framed != 0
			if cursor == "unentered" {
				badDelete = deletes.framed == 0 || deletes.framed > 65536
			}
			if badDelete || evidence.count != 0 || evidence.framed != 0 || growth.accessCount != 0 || growth.accessBytes != 0 {
				t.Fatalf("one anchored step reserved another automatic target or Final: cursor=%s deletes=%+v evidence=%+v access=%d/%d", cursor, deletes, evidence, growth.accessCount, growth.accessBytes)
			}
		})
	}
}

// full_only: false
func TestContinuationCapacityAutomaticAdvanceRetainsPriorDeleteCustody(t *testing.T) {
	for _, ending := range []string{"park", "ack"} {
		t.Run(ending, func(t *testing.T) {
			base := generatedEmptyPredecessor(t)
			recorded, final := generatedAutomaticPreselectionForNames(t, base, []contract.ID{base.admission.recipient}, []string{"alpha", "omega"})
			s := generatedAutomaticSelectFixture(t, recorded, final)
			steps := uint32(3) // Reserve, Park unknown, next Reserve.
			if ending == "ack" {
				steps = 4 // Reserve, ACK Record, Close, next Reserve.
			}
			// Only the finite counter is synthetic, on real selected facts.
			// This is not a claimed signed history of billions of transitions.
			continuationTestPhase(t, s, math.MaxUint32-steps)
			initial := mustSelectedGeneratedWork(t, s)
			first, _, ok := generatedAutomaticTemplate(initial, initial.phase.LineageIndex)
			if !ok {
				t.Fatal("first automatic target absent")
			}
			_, second, ok := generatedAutomaticNext(initial, int(initial.phase.LineageIndex))
			if !ok || second.AttemptID == first.AttemptID {
				t.Fatal("fixture needs two automatic targets")
			}
			for _, x := range []contract.GeneratorAttemptTemplate{first, second} {
				if _, entered := initial.attempts[x.AttemptID]; entered {
					t.Fatal("automatic target already entered")
				}
			}
			source, before := s, continuationTestSelectedDigest(t, s)
			bound := continuationTestBound(t, s)
			reserve, err := s.generatedAutomaticReservationRequest(t.Context(), generatedContinuationContext(t, s, 186, 187), generatedVectorID(202))
			if err != nil {
				t.Fatal(err)
			}
			reserved, err := s.deriveGeneratedSuccessorReservation(t.Context(), reserve)
			if err != nil {
				t.Fatal(err)
			}
			s = reserved.state
			generatedInstallFixtureSupportReader(t, s)
			generatedVerifySelectedFixtureSlices(t, s)
			work := mustSelectedGeneratedWork(t, s)
			a := work.attempts[first.AttemptID]
			var ack []byte
			var advance *generatedLifecyclePlan
			if ending == "park" {
				facts, err := contract.EncodeGeneratorSafeFacts(generatedRetirementFactsFixture(t, s, a, contract.GeneratorDispositionUnknown))
				if err != nil {
					t.Fatal(err)
				}
				advance, err = s.generatedAutomaticParkPlan(t.Context(), generatedContinuationContext(t, s, 188, 189), facts)
				if err != nil {
					t.Fatal("unknown Park", err)
				}
			} else {
				ack = generatedRetirementResultFixture(t, s, a, contract.GeneratorDispositionRetirementAcknowledged)
				request, err := s.generatedRecordRequest(t.Context(), first.AttemptID, ack, generatedContinuationContext(t, s, 188, 189))
				if err != nil {
					t.Fatal(err)
				}
				acknowledged, err := s.deriveGeneratedRecord(t.Context(), request)
				if err != nil {
					t.Fatal(err)
				}
				s = acknowledged.state
				generatedInstallFixtureSupportReader(t, s)
				generatedVerifySelectedFixtureSlices(t, s)
				advance, err = s.generatedAutomaticClosePlan(t.Context(), generatedContinuationContext(t, s, 190, 191))
				if err != nil {
					t.Fatal("ACK Close", err)
				}
			}
			advanced, err := s.deriveGeneratedAutomaticClose(t.Context(), advance)
			if err != nil {
				t.Fatal(err)
			}
			s = advanced.state
			generatedInstallFixtureSupportReader(t, s)
			generatedVerifySelectedFixtureSlices(t, s)
			work = mustSelectedGeneratedWork(t, s)
			attemptKey := generatedRecordKey{contract.GeneratedAttemptSupportKind, first.AttemptID}
			retainedAttempt := bytes.Clone(work.records[attemptKey].Body)
			mapping, err := contract.InspectGeneratedAttemptRecord(retainedAttempt)
			if err != nil || mapping.AttemptID != first.AttemptID || mapping.InboxID != first.InboxID || work.phase.Phase != math.MaxUint32-1 || work.phase.FrontierAttemptID != second.AttemptID {
				t.Fatal("advance lost first delete mapping or next cursor", err)
			}
			var retainedKey generatedRecordKey
			if ending == "park" {
				retainedKey = generatedRecordKey{contract.GeneratedDutySupportKind, first.DutyID}
				duty, err := contract.InspectGeneratedDutyRecord(work.records[retainedKey].Body)
				if err != nil || duty.Status != contract.GeneratedEffectUnknown || mapping.State != contract.GeneratedEffectUnknown {
					t.Fatal("Park lost unknown Attempt/Duty", err)
				}
			} else {
				retainedKey = generatedRecordKey{contract.PendingInboxReleaseSupportKind, first.InboxID}
				release, err := contract.InspectPendingInboxReleaseRecord(work.records[retainedKey].Body)
				if err != nil || release.InboxID != first.InboxID || release.OriginalResultID != first.ResultID || release.SelectedHandoffDigest != contract.Hash(ack) || release.ObjectLength != uint32(len(ack)) || release.State != contract.GeneratedReleasePending {
					t.Fatal("ACK Close lost exact pending release", err)
				}
				if _, present := work.records[generatedRecordKey{contract.GeneratedDutySupportKind, first.DutyID}]; present {
					t.Fatal("ACK Close retained its ended Duty")
				}
			}
			retainedOwner := bytes.Clone(work.records[retainedKey].Body)
			nextReserve, err := s.generatedAutomaticReservationRequest(t.Context(), generatedContinuationContext(t, s, 192, 193), generatedVectorID(203))
			if err != nil || nextReserve == nil || nextReserve.attempt != second.AttemptID {
				t.Fatal("last-step next automatic Reserve", err)
			}
			next, err := s.deriveGeneratedSuccessorReservation(t.Context(), nextReserve)
			if err != nil {
				t.Fatal(err)
			}
			s = next.state
			generatedInstallFixtureSupportReader(t, s)
			generatedVerifySelectedFixtureSlices(t, s)
			work = mustSelectedGeneratedWork(t, s)
			current := work.attempts[second.AttemptID]
			if work.phase.Phase != math.MaxUint32 || current.record.State != contract.GeneratedEffectTransmitted || len(current.result) != 0 || !bytes.Equal(work.records[attemptKey].Body, retainedAttempt) || !bytes.Equal(work.records[retainedKey].Body, retainedOwner) {
				t.Fatal("next Reserve overwrote prior delete custody")
			}
			if request, err := s.generatedRecordRequest(t.Context(), second.AttemptID, generatedRetirementResultFixture(t, s, current, contract.GeneratorDispositionRetirementAcknowledged), generatedContinuationContext(t, s, 194, 195)); err == nil || request != nil {
				t.Fatal("next Record exceeded shared phase budget")
			}
			continuationTestCandidateWithin(t, s, bound.Remaining)
			// Measure the actual writer's selected class/owner rows, not a
			// coarse per-template width or the numeric growth implementation.
			groups, err := generatedReservationGroupsForState(s, s.supportRecords(), selectedGeneratedLocations(work), work.bundles)
			if err != nil {
				t.Fatal(err)
			}
			var count, framed uint64
			owners := make(map[contract.ID]bool)
			for _, group := range groups {
				if group.Class != format.DeleteContinuationSupport {
					continue
				}
				owners[group.Owner] = true
				for _, row := range group.Records {
					count++
					framed += uint64(37 + len(row.Body))
				}
			}
			actual := bound.Remaining.Groups[contract.GeneratorCapacityDeletes]
			if !owners[first.AttemptID] || !owners[second.AttemptID] || actual.MaxCount < count || actual.MaxFramedBytes < framed {
				t.Fatal("bound omitted retained first or current second Delete group", owners, count, framed, actual)
			}
			if continuationTestSelectedDigest(t, source) != before || source.prepared || s.prepared {
				t.Fatal("automatic prefix changed its selected predecessor")
			}
		})
	}
}

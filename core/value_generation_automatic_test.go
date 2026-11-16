package core

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestGeneratedAutomaticTerminalKeepsIndependentCreateHazardSupport(t *testing.T) {
	for _, mode := range []uint8{0, 2} {
		for _, disposition := range []uint8{0, contract.GeneratorDispositionCompleteCreate, contract.GeneratorDispositionOwnedUnusableCreate} {
			t.Run(fmt.Sprintf("mode=%d/disposition=%d", mode, disposition), func(t *testing.T) {
				state, original, hazard := generatedCreateHazardState(t, mode, disposition)
				selected := mustSelectedGeneratedWork(t, state)
				facts := *selected
				// This fixture has already ended all Parent-only consumers. Its
				// complete support is independently owned by the surviving Hazard.
				facts.parent = &contract.GeneratedParentRecord{OperationID: original.record.OperationID,
					MaterialID: original.material.Core.OperationMaterialID}
				before := state.supportRecords()
				after, err := generatedAutomaticTerminalRows(&facts, before)
				if err != nil || !reflect.DeepEqual(after, before) {
					t.Fatal("terminal pruning changed independently owned Hazard support", err)
				}
				if got := selected.attempts[hazard.OriginalAttemptID]; !reflect.DeepEqual(got, original) ||
					(len(got.result) != 0) != (disposition != 0) {
					t.Fatal("fixture lost the original absent or qualified result")
				}
			})
		}
	}
}

func generatedAutomaticPreselectionFixture(t *testing.T) (*StateSession, *generatedFinalPlan) {
	t.Helper()
	base := generatedEmptyPredecessor(t)
	return generatedAutomaticPreselectionForRecipients(t, base, []contract.ID{base.admission.recipient})
}

func generatedAutomaticPreselectionForRecipients(t *testing.T, base *StateSession, recipients []contract.ID) (*StateSession, *generatedFinalPlan) {
	t.Helper()
	return generatedAutomaticPreselectionForNames(t, base, recipients, []string{"generated"})
}

func generatedAutomaticPreselectionForNames(t *testing.T, base *StateSession, recipients []contract.ID, names []string) (*StateSession, *generatedFinalPlan) {
	t.Helper()
	initial := generatedReservationInputForMembershipStateIntent(t, base, generatedVectorID(10), recipients, names, []byte(`{"name":"generated"}`), defaultGeneratedFixtureProfile(), 0, nil, nil)
	reservation, err := base.deriveGeneratedReservation(t.Context(), initial)
	if err != nil {
		t.Fatal("initial generated reservation", err)
	}
	oldState := generatedAutomaticRecordCreatesFixture(t, reservation.state, len(names), 160)
	initialPlan, err := oldState.generatedFinalRequest(t.Context(), generatedContinuationContext(t, oldState, 180, 181))
	if err != nil {
		t.Fatal("initial generated final plan", err)
	}
	oldState = generatedAutomaticSelectFixture(t, oldState, initialPlan)
	incarnations, retiring := make(map[string]contract.ID), make(map[string]contract.ValueEntry)
	for _, entry := range oldState.root.Names {
		old := *oldState.valueEntry(entry.Slot)
		incarnations[entry.Name], retiring[entry.Name] = old.Incarnation, old
	}
	profile := defaultGeneratedFixtureProfile()
	profile.RetirementMode = contract.GeneratedRetirementAuto
	profile.DescriptorID = generatedVectorID(235)
	input := generatedReservationInputForMembershipStateIntent(t, oldState, generatedVectorID(181), recipients, names, []byte(`{"name":"rotated"}`), profile, 1, incarnations, retiring)
	reservation, err = oldState.deriveGeneratedReservation(t.Context(), input)
	if err != nil {
		t.Fatal("automatic rotation reservation", err)
	}
	recorded := generatedAutomaticRecordCreatesFixture(t, reservation.state, len(names), 199)
	plan, err := recorded.generatedFinalRequest(t.Context(), generatedContinuationContext(t, recorded, 184, 185))
	if err != nil {
		t.Fatal("rotation selection plan", err)
	}
	return recorded, plan
}

func generatedAutomaticRecordCreatesFixture(t *testing.T, state *StateSession, count int, token byte) *StateSession {
	t.Helper()
	for index := range count {
		g := mustSelectedGeneratedWork(t, state)
		a := g.attempts[g.phase.FrontierAttemptID]
		packet := generatedPublicResultFixtureWithRawToken(t, a, contract.GeneratorDispositionCompleteCreate, 1, generatedVectorID(token+byte(index)))
		record, err := state.generatedRecordRequest(t.Context(), a.record.AttemptID, packet, generatedContinuationContext(t, state, 182, 183))
		if err != nil {
			t.Fatal("create result request", err)
		}
		recorded, err := state.deriveGeneratedRecord(t.Context(), record)
		if err != nil {
			t.Fatal("create result", err)
		}
		state = recorded.state
	}
	return state
}

func generatedAutomaticSelectedFixture(t *testing.T) *StateSession {
	t.Helper()
	recorded, plan := generatedAutomaticPreselectionFixture(t)
	return generatedAutomaticSelectFixture(t, recorded, plan)
}

func generatedAutomaticSelectFixture(t *testing.T, recorded *StateSession, plan *generatedFinalPlan) *StateSession {
	t.Helper()
	prepared := make([]contract.CryptoGeneratedValueEntryResult, len(plan.entryPlans))
	for i, entry := range plan.entryPlans {
		prepared[i] = generatedPreparedValueEntryFixture(t, recorded, entry)
	}
	final, err := recorded.deriveGeneratedFinal(t.Context(), plan, prepared)
	if err != nil {
		t.Fatal("automatic first B selection", err)
	}
	generatedInstallFixtureSupportReader(t, final.state)
	generatedVerifySelectedFixtureSlices(t, final.state)
	return final.state
}

// full_only: false
func TestGeneratedAutomaticSelectionRetainsOneParentAndNoReceipt(t *testing.T) {
	s := generatedAutomaticSelectedFixture(t)
	g := mustSelectedGeneratedWork(t, s)
	if !generatedSelectionAnchored(g) || g.phase.SelectionPhaseID != g.phase.PhaseID || g.phase.FinalPreparationID != (contract.ID{}) {
		t.Fatal("first selection did not retain exact anchor")
	}
	x, _, ok := generatedAutomaticTemplate(g, g.phase.LineageIndex)
	if !ok || x.AttemptID != g.phase.FrontierAttemptID {
		t.Fatal("selected cursor did not name exact original auto delete")
	}
	if _, entered := g.attempts[x.AttemptID]; entered {
		t.Fatal("unentered delete was fabricated as an Attempt")
	}
	if _, _, found, err := s.retainedMutationReceipt(g.parent.OperationID); err != nil || found {
		t.Fatal("first B selection appended an early receipt", err)
	}
	if len(g.sources) != 0 || len(g.protected) != 0 || len(g.declaredCanonicals) != 0 {
		t.Fatal("selected parent retained obsolete CREATE input authority")
	}
	if err := s.validateGeneratedSelection(t.Context(), nil); err != nil {
		t.Fatal("cold selected anchor", err)
	}
	if plan, err := s.generatedFinalRequest(t.Context(), generatedContinuationContext(t, s, 186, 187)); err == nil || plan != nil {
		t.Fatal("selected parent admitted another canonical selection")
	}
}

// full_only: false
func TestGeneratedAutomaticReserveRecordClosePreservesFrozenCommitments(t *testing.T) {
	s := generatedAutomaticSelectedFixture(t)
	before := mustSelectedGeneratedWork(t, s)
	anchor := *before.phase
	seed := *generatedFixtureMaterialAccess(t, s, contract.OperationSeedMaterialKind, before.parent.MaterialID)
	plan, err := s.generatedAutomaticReservationRequest(t.Context(), generatedContinuationContext(t, s, 186, 187), generatedVectorID(202))
	if err != nil {
		t.Fatal("fresh exact K2-RETIRE plan", err)
	}
	reserved, err := s.deriveGeneratedSuccessorReservation(t.Context(), plan)
	if err != nil {
		t.Fatal("automatic delete reservation", err)
	}
	if err := reserved.state.validateGeneratedSelection(t.Context(), nil); err != nil {
		t.Fatal("cold automatic delete reservation", err)
	}
	g := mustSelectedGeneratedWork(t, reserved.state)
	a := g.attempts[g.phase.FrontierAttemptID]
	if a.expected.Template.Action != contract.GeneratorActionDelete || g.parent.OperationID != before.parent.OperationID {
		t.Fatal("auto reserve replaced original apply")
	}
	record, err := reserved.state.generatedRecordRequest(t.Context(), a.record.AttemptID, generatedRetirementResultFixture(t, reserved.state, a, contract.GeneratorDispositionRetirementAcknowledged), generatedContinuationContext(t, reserved.state, 188, 189))
	if err != nil {
		t.Fatal("delete ACK request", err)
	}
	recorded, err := reserved.state.deriveGeneratedRecord(t.Context(), record)
	if err != nil {
		t.Fatal("delete ACK selection", err)
	}
	g = mustSelectedGeneratedWork(t, recorded.state)
	if g.phase.SelectionPhaseID != anchor.SelectionPhaseID || g.phase.ChangedSubjects != anchor.ChangedSubjects || g.phase.ChangedAccess != anchor.ChangedAccess {
		t.Fatal("auto changed frozen original commitments")
	}
	gotSeed := *generatedFixtureMaterialAccess(t, recorded.state, contract.OperationSeedMaterialKind, g.parent.MaterialID)
	first, _ := contract.EncodeAccessRecord(seed)
	last, _ := contract.EncodeAccessRecord(gotSeed)
	if !bytes.Equal(first, last) {
		t.Fatal("auto rewrote shared parent seed")
	}
	closePlan, err := recorded.state.generatedAutomaticClosePlan(t.Context(), generatedContinuationContext(t, recorded.state, 190, 191))
	if err != nil {
		t.Fatal("automatic close plan", err)
	}
	closed, err := recorded.state.deriveGeneratedAutomaticClose(t.Context(), closePlan)
	if err != nil {
		t.Fatal("automatic terminal close", err)
	}
	scope, err := generatedAutomaticInvocationScope(t.Context(), recorded.state, g)
	if err != nil {
		t.Fatal("automatic before scope", err)
	}
	facts, err := generatedInvocationFacts(t.Context(), g, scope, scope.Effects, scope.Duties, scope.Hazards)
	if err != nil {
		t.Fatal("automatic before facts", err)
	}
	var checkpoint generatedSelectionCheckpoint
	result := recorded.state.observed(ObservedCurrent)
	result.RequestedRevision = recorded.state.head.Core.Revision
	checkpoint.recordSelected(PublicApplyResult{OperationID: g.parent.OperationID, Result: result, Generated: &facts})
	capture, err := captureGeneratedFinalInvocationResult(t.Context(), recorded.state, g, &generatedFinalPlan{}, closed, &checkpoint)
	if err != nil {
		t.Fatal("capture automatic close before owner ends", err)
	}
	if &capture.observed.Effects[0] != &facts.Effects[0] || len(capture.observed.Duties) != len(scope.Duties) {
		t.Fatal("automatic close changed its owned before subset or backing")
	}
	observed, err := capture.observe(t.Context(), closed.state, Result{Outcome: ObservedCurrent, Evidence: AuthenticatedClosure})
	if err != nil || observed == nil || len(observed.Effects) != 2 || len(observed.Duties) != 0 || len(observed.Hazards) != 0 || observed.AcknowledgedCount != 1 || observed.Effects[1].Target == nil {
		t.Fatal("automatic close lost exact effects or retained ended work", observed, err)
	}
	if !closed.state.root.Generated.ActiveOwner.IsZero() {
		t.Fatal("terminal close retained original parent")
	}
	ended := mustSelectedGeneratedWork(t, closed.state)
	for _, create := range before.attempts {
		if create.expected.Template.Action != contract.GeneratorActionCreate {
			continue
		}
		for _, key := range []generatedRecordKey{{contract.GeneratedAttemptSupportKind, create.record.AttemptID},
			{contract.GeneratedResultSupportKind, create.record.ResultID}, {contract.GeneratedDutySupportKind, create.record.OwnerID},
			{contract.GeneratedLineageSupportKind, create.record.LineageID}} {
			if ended.hasRecord(key) {
				t.Fatal("terminal no-Hazard close retained ended CREATE support", key.kind)
			}
		}
	}
	row, _, found, err := closed.state.retainedMutationReceipt(before.parent.OperationID)
	if err != nil || !found || row.ChangedSubjects != anchor.ChangedSubjects || row.SummaryCounts[contract.ReceiptEffectCount] != 2 || row.AcknowledgedCount != 1 {
		t.Fatal("original receipt lost frozen commitments or ordered effects", err)
	}
	for _, access := range closed.state.accessRecords() {
		if access.MaterialKind == contract.OperationSeedMaterialKind && access.MaterialID == before.parent.MaterialID {
			t.Fatal("terminal close retained unused shared seed")
		}
	}
}

// full_only: false
func TestGeneratedAutomaticAccessGuardRejectsRewritesAndAllowsWholeRemoval(t *testing.T) {
	s := generatedAutomaticSelectedFixture(t)
	rows := s.accessRecords()
	if err := generatedAutomaticAccessPreserved(rows, rows); err != nil {
		t.Fatal(err)
	}
	changed := slices.Clone(rows)
	changed[0].Wraps = slices.Clone(changed[0].Wraps)
	changed[0].Wraps[0].RSACiphertext = bytes.Clone(changed[0].Wraps[0].RSACiphertext)
	changed[0].Wraps[0].RSACiphertext[0] ^= 1
	if generatedAutomaticAccessPreserved(rows, changed) == nil {
		t.Fatal("automatic candidate rewrote surviving access")
	}
	if err := generatedAutomaticAccessPreserved(rows, rows[1:]); err != nil {
		t.Fatal("whole unused record removal refused", err)
	}
	added := slices.Clone(rows)
	extra := rows[0]
	extra.MaterialID = generatedVectorID(203)
	added = append(added, extra)
	if generatedAutomaticAccessPreserved(rows, added) == nil {
		t.Fatal("automatic candidate added access")
	}
}

// full_only: false
func TestGeneratedAutomaticUnenteredDutyEndsWithOriginalParent(t *testing.T) {
	s := generatedAutomaticSelectedFixture(t)
	g := mustSelectedGeneratedWork(t, s)
	x, _, ok := generatedAutomaticTemplate(g, g.phase.LineageIndex)
	if !ok {
		t.Fatal("missing auto cursor")
	}
	generatedAssertUnenteredAutomaticDependency(t, s)
	current := *s.valueEntry(0)
	s.admission.endWorkInvocation = generatedVectorID(235)
	ids := endWorkIDs{operation: generatedVectorID(236), transition: generatedVectorID(237), snapshot: generatedVectorID(238), revision: generatedVectorID(239), receipts: generatedVectorID(240), receiptIndex: generatedVectorID(241)}
	_, ended, err := s.deriveEndWorkCandidate(t.Context(), g.parent.OperationID, ids)
	if err != nil || ended == nil || !ended.root.Generated.ActiveOwner.IsZero() {
		t.Fatal("exact selected apply abandonment", err)
	}
	after := ended.valueEntry(0)
	if after == nil || after.Generated.GenerationID != current.Generated.GenerationID || !bytes.Equal(after.ValueBytes, current.ValueBytes) {
		t.Fatal("ending apply changed selected B")
	}
	for _, row := range ended.supportRecords() {
		if row.Kind == contract.GeneratedDutySupportKind && row.RecordID == x.DutyID {
			t.Fatal("abandon left unentered dependent auto Duty")
		}
	}
}

func generatedAssertUnenteredAutomaticDependency(t *testing.T, s *StateSession) {
	t.Helper()
	g := mustSelectedGeneratedWork(t, s)
	x, _, ok := generatedAutomaticTemplate(g, g.phase.LineageIndex)
	if !ok {
		t.Fatal("missing unentered automatic template")
	}
	if _, entered := g.attempts[x.AttemptID]; entered {
		t.Fatal("administrative dependency fabricated a delete Attempt")
	}
	parentIndex, dutyIndex := -1, -1
	for index, group := range s.adminIndex.Groups {
		if group.GroupID == g.parent.OperationID {
			parentIndex = index
		}
		if group.GroupID == x.DutyID {
			dutyIndex = index
		}
	}
	if parentIndex < 0 || dutyIndex < 0 || !slices.Contains(s.adminIndex.Groups[dutyIndex].RelatedGroupIndexes, uint16(parentIndex)) || slices.Contains(s.adminIndex.Groups[parentIndex].RelatedGroupIndexes, uint16(dutyIndex)) {
		t.Fatal("unentered auto Duty has wrong parent dependency")
	}
}

// full_only: false
func TestGeneratedAutomaticAfterKeySuccessionUsesCurrentAccessAndFrozenAnchor(t *testing.T) {
	// This exercises ordinary recipient replacement and subsequent generated
	// retirement. Authority succession admission has its own native roots.
	base := generatedEmptyPredecessor(t)
	peer := contract.RecipientRecord{RecipientID: generatedVectorID(206), Status: contract.CurrentRecipient, DisplayName: "independent peer"}
	peerBinding := *base.authority().CurrentBinding
	peerBinding.BindingID, peerBinding.BindingIncarnationID = generatedVectorID(207), generatedVectorID(208)
	peer.CurrentBinding = &peerBinding
	basis, err := contract.DecodeGenesisDescriptorCore(base.admission.descriptor)
	if err != nil {
		t.Fatal(err)
	}
	basis.Recipients = append(basis.Recipients, peer)
	slices.SortFunc(basis.Recipients, func(a, b contract.RecipientRecord) int { return bytes.Compare(a.RecipientID[:], b.RecipientID[:]) })
	base.admission.descriptor, err = contract.EncodeGenesisDescriptorCore(basis)
	if err != nil {
		t.Fatal("independent fixture reader basis", err)
	}
	for i := range basis.Recipients {
		base.recipients[0].Slots[i] = &basis.Recipients[i]
	}
	generatedSealSelectedFixture(t, base)
	generatedInstallFixtureSupportReader(t, base)
	generatedVerifySelectedFixtureSlices(t, base)
	recipients := []contract.ID{base.admission.recipient, peer.RecipientID}
	slices.SortFunc(recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	recorded, final := generatedAutomaticPreselectionForNames(t, base, recipients, []string{"alpha", "omega"})
	s := generatedAutomaticSelectFixture(t, recorded, final)
	g := mustSelectedGeneratedWork(t, s)
	anchor := *g.phase
	generatedAssertUnenteredAutomaticDependency(t, s)
	firstTemplate, _, ok := generatedAutomaticTemplate(g, g.phase.LineageIndex)
	if !ok {
		t.Fatal("first automatic retirement")
	}
	duty, err := contract.InspectGeneratedDutyRecord(g.records[generatedRecordKey{contract.GeneratedDutySupportKind, firstTemplate.DutyID}].Body)
	if err != nil {
		t.Fatal(err)
	}
	firstTarget, err := g.retirementTarget(t.Context(), duty)
	if err != nil {
		t.Fatal(err)
	}
	firstPlan, err := s.generatedAutomaticReservationRequest(t.Context(), generatedContinuationContext(t, s, 186, 187), generatedVectorID(202))
	if err != nil {
		t.Fatal(err)
	}
	firstReservation, err := s.deriveGeneratedSuccessorReservation(t.Context(), firstPlan)
	if err != nil {
		t.Fatal(err)
	}
	firstWork := mustSelectedGeneratedWork(t, firstReservation.state)
	firstAttempt := firstWork.attempts[firstTemplate.AttemptID]
	ack, err := firstReservation.state.generatedRecordRequest(t.Context(), firstTemplate.AttemptID, generatedRetirementResultFixture(t, firstReservation.state, firstAttempt, contract.GeneratorDispositionRetirementAcknowledged), generatedContinuationContext(t, firstReservation.state, 188, 189))
	if err != nil {
		t.Fatal(err)
	}
	acknowledged, err := firstReservation.state.deriveGeneratedRecord(t.Context(), ack)
	if err != nil {
		t.Fatal(err)
	}
	closePlan, err := acknowledged.state.generatedAutomaticClosePlan(t.Context(), generatedContinuationContext(t, acknowledged.state, 190, 191))
	if err != nil {
		t.Fatal(err)
	}
	closed, err := acknowledged.state.deriveGeneratedAutomaticClose(t.Context(), closePlan)
	if err != nil {
		t.Fatal("first of two automatic closes", err)
	}
	s = closed.state
	generatedInstallFixtureSupportReader(t, s)
	generatedVerifySelectedFixtureSlices(t, s)
	g = mustSelectedGeneratedWork(t, s)
	if _, present := g.records[generatedRecordKey{contract.GeneratedDutySupportKind, firstTemplate.DutyID}]; present || !generatedSelectionAnchored(g) {
		t.Fatal("first close lost the original Parent or retained its ended Duty")
	}
	if _, _, found, err := s.retainedMutationReceipt(g.parent.OperationID); err != nil || found {
		t.Fatal("first close appended an early original apply receipt", err)
	}
	generatedAssertUnenteredAutomaticDependency(t, s)
	generatedAssertAutomaticHistory(t, s, firstTemplate, firstTarget)
	generatedAssertAutomaticChangedEvidenceNotOwned(t, s, firstTarget)
	successor := peerBinding
	successor.BindingID = generatedVectorID(210)
	successor.BindingSerial++
	bindingDigest, err := contract.PublicBindingDigest(successor)
	if err != nil {
		t.Fatal(err)
	}
	after := make(map[materialIdentity]contract.AccessRecord)
	target := contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: peer.RecipientID, Binding: successor}
	coverage, err := s.replacementMaterialRows(t.Context(), 0, 1, target)
	if err != nil || len(coverage) != 2 {
		t.Fatal("selected apply key succession coverage", err)
	}
	for _, material := range coverage {
		row := material.BeforeAccessRecord
		row.Wraps = slices.Clone(row.Wraps)
		for j, wrap := range row.Wraps {
			if wrap.SubjectKind == target.SubjectKind && wrap.SubjectID == target.SubjectID {
				wrap.BindingID, wrap.BindingSerial, wrap.PublicBindingDigest = successor.BindingID, successor.BindingSerial, bindingDigest
				wrap.RSACiphertext = bytes.Repeat([]byte{211}, len(wrap.RSACiphertext))
				row.Wraps[j] = wrap
			}
		}
		after[materialIdentity{row.MaterialKind, row.MaterialID}] = row
	}
	p := transitionPlan{snapshot: generatedVectorID(212), transition: generatedVectorID(213)}
	p.recipientPages[0] = generatedVectorID(214)
	for index, page := range s.access {
		if page != nil {
			p.accessPages[index] = generatedVectorID(byte(215 + index))
		}
	}
	indexes, err := s.generatedSnapshotPageIndexes()
	if err != nil {
		t.Fatal(err)
	}
	for j, index := range indexes {
		p.supportPages[index] = generatedVectorID(byte(220 + j))
	}
	next, ok := s.replacementSuccessor(contract.RecipientReplacementIntent{RecipientID: peer.RecipientID, Successor: successor}, p, after)
	if !ok {
		t.Fatal("key succession state projection")
	}
	if _, err := s.rebindGeneratedSnapshot(t.Context(), next, p); err != nil {
		t.Fatal("key succession selected work", err)
	}
	// Keep the real predecessor ownership through the generic rewrite. A
	// synthetic full refresh would discard that authenticated history.
	generatedInstallFixtureSupportReader(t, next)
	generatedVerifySelectedFixtureSlices(t, next)
	// Exercise the generic caller with no graph bundle. The authenticated
	// predecessor index, exact Parent and exact Phase must preserve this edge.
	if err := s.installAdministrativeIndex(t.Context(), next, &Candidate{session: s}); err != nil {
		t.Fatal("replacement administrative index", err)
	}
	root, err := format.EncodeRoot(next.root)
	if err != nil {
		t.Fatal(err)
	}
	next.head.Core.Root, err = format.Reference(format.RootKind, next.root.Domain, next.root.Snapshot, 0, root)
	if err != nil {
		t.Fatal(err)
	}
	generatedInstallFixtureSupportReader(t, next)
	generatedVerifySelectedFixtureSlices(t, next)
	generatedAssertUnenteredAutomaticDependency(t, next)
	generatedAssertAutomaticHistory(t, next, firstTemplate, firstTarget)
	selected := mustSelectedGeneratedWork(t, next)
	if selected.phase.SelectionPhaseID != anchor.SelectionPhaseID || selected.phase.ChangedSubjects != anchor.ChangedSubjects || selected.phase.ChangedAccess != anchor.ChangedAccess {
		t.Fatal("independent key succession rewrote original apply anchor")
	}
	if generatedAutomaticAccessPreserved(s.accessRecords(), next.accessRecords()) == nil {
		t.Fatal("fixture key succession did not actually rewrap access")
	}
	plan, err := next.generatedAutomaticReservationRequest(t.Context(), generatedContinuationContext(t, next, 230, 231), generatedVectorID(232))
	if err != nil {
		t.Fatal("fresh retirement after succession", err)
	}
	reserved, err := next.deriveGeneratedSuccessorReservation(t.Context(), plan)
	if err != nil {
		t.Fatal("retirement after succession", err)
	}
	if err := generatedAutomaticAccessPreserved(next.accessRecords(), reserved.state.accessRecords()); err != nil {
		t.Fatal("automatic step changed successor access", err)
	}
}

func generatedAssertAutomaticHistory(t *testing.T, s *StateSession, template contract.GeneratorAttemptTemplate, want contract.GeneratorTarget) {
	t.Helper()
	g := mustSelectedGeneratedWork(t, s)
	target, err := generatedAutomaticReleasedTarget(t.Context(), g, template)
	if err != nil || target == nil || *target != want {
		t.Fatal("released automatic Delete lost its exact target", err)
	}
	result, err := generatedCreateResultID(s.root.Domain, want.OriginalOperationID, want.OriginalAttemptID)
	if err != nil {
		t.Fatal(err)
	}
	row, present := g.records[generatedRecordKey{contract.GeneratedCreateEvidenceSupportKind, result}]
	if !present {
		t.Fatal("released automatic Delete lost old Create evidence")
	}
	evidence, err := contract.InspectGeneratedCreateEvidence(row.Body)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := contract.InspectGeneratorSafeFacts(evidence.SafeFacts)
	if err != nil {
		t.Fatal(err)
	}
	core, err := contract.InspectGeneratedResultCore(evidence.ResultCore)
	if err != nil || core.DescriptorID == template.DescriptorID {
		t.Fatal("automatic retirement did not retain the different original Create implementation", err)
	}
	if _, err := g.readSelectedLogicalSlice(t.Context(), contract.GeneratorContentIntent, facts.IntentDigest, evidence.Intent, contract.GeneratorIntentMaxLength); err != nil {
		t.Fatal("released automatic Delete lost old intent", err)
	}
	prior, err := s.priorAdministrativeRows()
	if err != nil {
		t.Fatal(err)
	}
	position, present := prior[generatedRecordKey{row.Kind, row.RecordID}]
	if !present || !slices.Contains(s.priorAdministrativeOwnership(position).groups, g.parent.OperationID) {
		t.Fatal("retained historical Create evidence has no original Parent owner")
	}
	fragments, err := s.selectedFragmentFactsByRecord()
	if err != nil {
		t.Fatal(err)
	}
	var foundIntent bool
	for _, location := range g.content.locations {
		if location.ContentKind != contract.GeneratorContentIntent || location.ContentID != facts.IntentDigest {
			continue
		}
		foundIntent = true
		for _, page := range s.support {
			for _, candidate := range page.Records {
				if candidate.Kind != contract.GeneratedFragmentSupportKind {
					continue
				}
				var blob contract.ID
				if candidate.Body == nil {
					blob = fragments[candidate.RecordID].blob
				} else {
					fragment, err := contract.InspectGeneratedFragment(candidate.Body)
					if err != nil {
						t.Fatal(err)
					}
					blob = fragment.BlobID
				}
				if blob == location.BlobID {
					position, present := prior[generatedRecordKey{candidate.Kind, candidate.RecordID}]
					if !present || !slices.Contains(s.priorAdministrativeOwnership(position).groups, g.parent.OperationID) {
						t.Fatal("retained historical intent blob has no original Parent owner")
					}
				}
			}
		}
	}
	if !foundIntent {
		t.Fatal("historical intent directory entry is absent")
	}
}

// A selected anchor cannot give a changed or unrelated evidence row the
// ownership of the exact old Create. Exercise both typed and generic callers.
func generatedAssertAutomaticChangedEvidenceNotOwned(t *testing.T, s *StateSession, target contract.GeneratorTarget) {
	t.Helper()
	g := mustSelectedGeneratedWork(t, s)
	result, err := generatedCreateResultID(s.root.Domain, target.OriginalOperationID, target.OriginalAttemptID)
	if err != nil {
		t.Fatal(err)
	}
	prior, err := s.priorAdministrativeRows()
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"profile", "token", "result-contract"} {
		t.Run(mutation, func(t *testing.T) {
			pages := make([]format.RequiredSupportPage, len(s.support))
			for i, page := range s.support {
				pages[i] = format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index}
				for _, row := range page.Records {
					candidate := contract.SupportRecord(row)
					if row.Kind == contract.GeneratedCreateEvidenceSupportKind && row.RecordID == result {
						evidence, err := contract.InspectGeneratedCreateEvidence(row.Body)
						if err != nil {
							t.Fatal(err)
						}
						core, err := contract.InspectGeneratedResultCore(evidence.ResultCore)
						if err != nil {
							t.Fatal(err)
						}
						switch mutation {
						case "profile":
							core.ConfigContractID = generatedVectorID(234)
						case "token":
							facts, err := contract.DecodeGeneratorSafeFacts(evidence.SafeFacts)
							if err != nil {
								t.Fatal(err)
							}
							facts.ResourceData = bytes.Repeat([]byte{234}, 32)
							evidence.SafeFacts, err = contract.EncodeGeneratorSafeFacts(facts)
							if err != nil {
								t.Fatal(err)
							}
							core.SafeFactsDigest, err = contract.GeneratorSafeFactsDigest(facts)
							if err != nil {
								t.Fatal(err)
							}
						case "result-contract":
							core.ResultContractID = generatedVectorID(234)
						}
						evidence.ResultCore, err = contract.EncodeGeneratedResultCore(core)
						if err != nil {
							t.Fatal(err)
						}
						candidate.Body, err = contract.EncodeGeneratedCreateEvidence(contract.GeneratedCreateEvidence(evidence))
						if err != nil {
							t.Fatal(err)
						}
					}
					pages[i].Records = append(pages[i].Records, candidate)
				}
			}
			for _, caller := range []string{"typed", "generic"} {
				t.Run(caller, func(t *testing.T) {
					var bundles []contract.GeneratorPlanBundle
					if caller == "typed" {
						bundles = g.bundles
					}
					consumers, err := selectedAdministrativeConsumersWithValidated(pages, nil, bundles, g)
					if err != nil {
						t.Fatal(err)
					}
					if err := s.bindAutomaticHistoricalConsumers(s.root, pages, bundles, prior, &consumers); err != nil {
						t.Fatal(err)
					}
					if slices.Contains(consumers.attemptOwners(target.OriginalAttemptID, target.OriginalOperationID), g.parent.OperationID) {
						t.Fatal("anchored historical ownership accepted changed Create evidence")
					}
				})
			}
		})
	}
}

// full_only: false
func TestGeneratedAutomaticUnknownParksInsideOriginalApply(t *testing.T) {
	s := generatedAutomaticSelectedFixture(t)
	original := mustSelectedGeneratedWork(t, s)
	operation := original.parent.OperationID
	plan, err := s.generatedAutomaticReservationRequest(t.Context(), generatedContinuationContext(t, s, 186, 187), generatedVectorID(202))
	if err != nil {
		t.Fatal(err)
	}
	reserved, err := s.deriveGeneratedSuccessorReservation(t.Context(), plan)
	if err != nil {
		t.Fatal(err)
	}
	g := mustSelectedGeneratedWork(t, reserved.state)
	a := g.attempts[g.phase.FrontierAttemptID]
	facts, err := contract.EncodeGeneratorSafeFacts(generatedRetirementFactsFixture(t, reserved.state, a, contract.GeneratorDispositionUnknown))
	if err != nil {
		t.Fatal(err)
	}
	park, err := reserved.state.generatedAutomaticParkPlan(t.Context(), generatedContinuationContext(t, reserved.state, 188, 189), facts)
	if err != nil {
		t.Fatal("qualified automatic parking", err)
	}
	parked, err := reserved.state.deriveGeneratedAutomaticClose(t.Context(), park)
	if err != nil {
		t.Fatal("original automatic parking selection", err)
	}
	if err := parked.state.validateGeneratedSelection(t.Context(), nil); err != nil {
		t.Fatal("cold automatic terminal Park", err)
	}
	row, _, found, err := parked.state.retainedMutationReceipt(operation)
	if err != nil || !found || row.OperationKind != contract.OperationApplyDeclaration || row.CanonicalOutcome != contract.ReceiptCanonicalSelected || row.UnknownCount != 1 || row.AcknowledgedCount != 0 || row.SummaryCounts[contract.ReceiptDutyCount] != 1 {
		t.Fatal("qualified Park changed original operation or claimed deletion", err)
	}
	current := parked.state.valueEntry(0)
	if current == nil || current.Generated.OriginOperationID != operation || current.Generated.RetiringDutyPresent != 1 {
		t.Fatal("qualified Park lost B or exact pending Duty")
	}
	capture, err := captureGeneratedFinalInvocationResult(t.Context(), reserved.state, g, &generatedFinalPlan{}, parked, nil)
	if err != nil {
		t.Fatal("capture original automatic Park result", err)
	}
	actual := Result{Outcome: ObservedCurrent, Evidence: AuthenticatedClosure, RequestedRevision: parked.state.head.Core.Revision,
		ObservedRevision: parked.state.head.Core.Revision, ObservedSnapshotID: parked.state.root.Snapshot}
	result, err := capture.observe(t.Context(), parked.state, actual)
	if err != nil || result == nil {
		t.Fatal("observe original automatic Park result", err)
	}
	if result.StateResult != "retirement-pending" || result.CanonicalOutcome != contract.ReceiptCanonicalSelected || result.UnknownCount != 1 || result.AcknowledgedCount != 0 || len(result.Effects) != 2 || len(result.Duties) != 1 {
		t.Fatal("automatic Park projection lost selected B or retained uncertainty")
	}
	deleted := result.Effects[1]
	if deleted.Record.AttemptID != a.record.AttemptID || deleted.Record.OperationID != operation || deleted.Record.State != contract.GeneratedEffectUnknown || deleted.Target == nil || deleted.Target.ResourceDigest != a.expected.TargetResourceDigest {
		t.Fatal("automatic Park projection lost exact changed Delete facts")
	}
}

// full_only: false
func TestGeneratedAutomaticSelectionReservesFiniteCloseBudget(t *testing.T) {
	for _, remaining := range []uint32{4, 5} {
		t.Run(string(rune('0'+remaining)), func(t *testing.T) {
			s, _ := generatedAutomaticPreselectionFixture(t)
			g := mustSelectedGeneratedWork(t, s)
			phase := *g.phase
			phase.Phase = ^uint32(0) - remaining
			body, err := contract.EncodeGeneratedPhaseRecord(phase)
			if err != nil {
				t.Fatal(err)
			}
			generatedReplaceRecord(t, s, contract.GeneratedPhaseSupportKind, phase.OperationID, body)
			generatedRefreshSupport(t, s)
			generatedVerifySelectedFixtureSlices(t, s)
			if selected := mustSelectedGeneratedWork(t, s); selected.phase.Phase != phase.Phase {
				t.Fatal("finite-budget fixture lost its selected Phase")
			}
			plan, err := s.generatedFinalRequest(t.Context(), generatedContinuationContext(t, s, 186, 187))
			if remaining == 4 {
				if err == nil || plan != nil {
					t.Fatal("first B selection omitted finite auto reserve/record/close budget")
				}
			} else if err != nil || plan == nil {
				t.Fatal("complete finite auto budget refused", err)
			}
		})
	}
}

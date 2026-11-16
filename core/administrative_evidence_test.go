package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

// full_only: false
func TestAdministrativeEvidenceClosedStatusAndQualifiedResultMatrix(t *testing.T) {
	status := []struct {
		name  string
		state uint8
		want  uint16
	}{
		{"not started", contract.GeneratedEffectNotStarted, contract.AdministrativeEvidenceMissing},
		{"prepared", contract.GeneratedEffectPrepared, contract.AdministrativeEvidenceMissing},
		{"transmitted", contract.GeneratedEffectTransmitted, contract.AdministrativeEvidenceMissing},
		{"succeeded needs result", contract.GeneratedEffectSucceeded, 0},
		{"confirmed needs result", contract.GeneratedEffectConfirmedNoEffect, 0},
		{"terminal failure", contract.GeneratedEffectFailedTerminal, contract.AdministrativeEvidenceTerminalFailure},
		{"qualified unknown", contract.GeneratedEffectUnknown, contract.AdministrativeEvidenceQualifiedUnknown},
		{"possible live", contract.GeneratedEffectPossibleLive, contract.AdministrativeEvidencePossibleLive},
		{"closed residue", contract.GeneratedEffectClosedWithResidue, contract.AdministrativeEvidencePossibleLive},
	}
	for _, tc := range status {
		t.Run(tc.name, func(t *testing.T) {
			got, err := administrativeEffectStateEvidence(tc.state)
			if err != nil || got != tc.want {
				t.Fatalf("state=%d evidence=%x err=%v", tc.state, got, err)
			}
		})
	}
	for _, state := range []uint8{0, contract.GeneratedEffectClosedWithResidue + 1} {
		if _, err := administrativeEffectStateEvidence(state); err == nil {
			t.Fatal("unknown selected effect state accepted", state)
		}
	}
	result := []struct {
		name        string
		disposition uint8
		want        uint16
	}{
		{"complete create", contract.GeneratorDispositionCompleteCreate, contract.AdministrativeEvidenceAcknowledged},
		{"owned unusable", contract.GeneratorDispositionOwnedUnusableCreate, contract.AdministrativeEvidenceTerminalFailure},
		{"create no effect", contract.GeneratorDispositionConfirmedNoEffect, contract.AdministrativeEvidenceConfirmed},
		{"delete ACK after closure", contract.GeneratorDispositionRetirementAcknowledged, contract.AdministrativeEvidenceAcknowledged},
		{"unknown", contract.GeneratorDispositionUnknown, contract.AdministrativeEvidenceQualifiedUnknown},
		{"controlled confirmed", contract.GeneratorDispositionScopedUnusability, contract.AdministrativeEvidenceConfirmed},
		{"continued usability", contract.GeneratorDispositionContinuedUsability, contract.AdministrativeEvidenceContradiction},
		{"conflicting binding", contract.GeneratorDispositionConflictingBinding, contract.AdministrativeEvidenceContradiction},
	}
	for _, tc := range result {
		t.Run(tc.name, func(t *testing.T) {
			got, err := administrativeResultEvidence(tc.disposition)
			if err != nil || got != tc.want {
				t.Fatalf("disposition=%d evidence=%x err=%v", tc.disposition, got, err)
			}
		})
	}
	if _, err := administrativeResultEvidence(0); err == nil {
		t.Fatal("unknown selected disposition accepted")
	}
}

// full_only: false
func TestAdministrativeIndexBindsMixedSelectedRetirementEvidence(t *testing.T) {
	s, _, duty := generatedRepeatedRetirementState(t, 1)
	position := slices.IndexFunc(s.adminIndex.Groups, func(group format.AdministrativeGroup) bool {
		return group.GroupID == duty.DutyID
	})
	if position < 0 {
		t.Fatal("selected retirement owner is absent")
	}
	want := contract.AdministrativeEvidenceMissing | contract.AdministrativeEvidenceQualifiedUnknown
	if s.adminIndex.Groups[position].SelectedEvidenceSummary&want != want {
		t.Fatalf("selected mixed evidence=%x want bits %x", s.adminIndex.Groups[position].SelectedEvidenceSummary, want)
	}
	derived, err := administrativeSelectedEvidence(s.adminIndex, s.support)
	if err != nil || derived[position] != s.adminIndex.Groups[position].SelectedEvidenceSummary {
		t.Fatalf("complete selected evidence=%x: %v", derived, err)
	}
	bad := s.adminIndex
	bad.Groups = slices.Clone(s.adminIndex.Groups)
	bad.Groups[position].SelectedEvidenceSummary = contract.AdministrativeEvidenceMissing
	if !bad.Valid() || bad.Groups[position].SelectedEvidenceSummary == derived[position] {
		t.Fatal("tampered authenticated summary was not distinguishable from complete selected rows")
	}
}

// full_only: false
func TestAdministrativeSelectedEvidenceKeepsDeleteACKAfterAttemptClosure(t *testing.T) {
	s, _, _, _ := generatedDeleteHazardState(t, 2)
	selected, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal("result was not qualified by complete selected work", err)
	}
	var found bool
	for _, group := range s.adminIndex.Groups {
		if group.OwnerKind != format.AdministrativeGeneratedHazard || !selected.hasRecord(generatedRecordKey{kind: contract.GeneratedHazardSupportKind, id: group.GroupID}) {
			continue
		}
		if group.SelectedEvidenceSummary&contract.AdministrativeEvidenceAcknowledged == 0 ||
			group.SelectedEvidenceSummary&contract.AdministrativeEvidenceConfirmed != 0 {
			t.Fatal("later Attempt state relabeled selected delete ACK", group.SelectedEvidenceSummary)
		}
		found = true
	}
	if !found {
		t.Fatal("qualified selected hazard was not indexed")
	}
}

func administrativeRetirementFactsState(t *testing.T, conflict string) (*StateSession, generatedAttempt, contract.GeneratedDutyRecord) {
	t.Helper()
	state, attempt, duty := generatedParkedRetirementState(t)
	selected := mustSelectedGeneratedWork(t, state)
	attempt = selected.attempts[attempt.record.AttemptID]
	facts := generatedRetirementFactsFixture(t, state, attempt, contract.GeneratorDispositionUnknown)
	switch conflict {
	case "identity":
		facts.Reason = contract.GeneratorReasonIdentityConflict
	case "resource":
		facts.Target, facts.ResourceData = []byte("another exact target"), bytes.Repeat([]byte{96}, 32)
	}
	body, err := contract.EncodeGeneratorSafeFacts(facts)
	if err != nil {
		t.Fatal(err)
	}
	body, err = contract.EncodeGeneratorFactsRow(contract.GeneratorFactsRow{Schema: 1, ResultID: attempt.record.ResultID, Facts: body})
	if err != nil {
		t.Fatal(err)
	}
	var carriers []contract.SupportRecord
	attempt.record.Facts, carriers = generatedVectorRows(t, contract.GeneratedAttemptSupportKind, attempt.record.AttemptID, contract.GeneratorVectorFacts, [][]byte{body})
	for i := range state.support {
		state.support[i].Records = slices.DeleteFunc(state.support[i].Records, func(row contract.SupportRecordView) bool {
			if row.Kind != contract.GeneratorVectorSupportKind {
				return false
			}
			carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			return carrier.OwnerKind == contract.GeneratedAttemptSupportKind && carrier.OwnerID == attempt.record.AttemptID && carrier.VectorKind == contract.GeneratorVectorFacts
		})
	}
	for _, row := range carriers {
		state.support[len(state.support)-1].Records = append(state.support[len(state.support)-1].Records, contract.SupportRecordView(row))
	}
	body, err = contract.EncodeGeneratedAttemptRecord(attempt.record)
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceRecord(t, state, contract.GeneratedAttemptSupportKind, attempt.record.AttemptID, body)
	generatedRepackSupport(t, state, state.supportRecords(), selected.bundles)
	qualified := mustSelectedGeneratedWork(t, state)
	actual := qualified.attempts[attempt.record.AttemptID]
	contradiction, err := qualified.validateDeleteFacts(actual)
	if err != nil || contradiction != (conflict != "transport") || len(actual.result) != 0 || qualified.hasRecord(generatedRecordKey{contract.GeneratedResultSupportKind, actual.record.ResultID}) {
		t.Fatal("fact-only retirement fixture is not qualified", err)
	}
	return state, actual, duty
}

// full_only: false
func TestAdministrativeRetirementFactOnlyContradictionIsDurableEvidence(t *testing.T) {
	for _, conflict := range []string{"identity", "resource", "transport"} {
		t.Run(conflict, func(t *testing.T) {
			state, attempt, duty := administrativeRetirementFactsState(t, conflict)
			want := uint16(contract.AdministrativeEvidenceQualifiedUnknown)
			if conflict != "transport" {
				want |= contract.AdministrativeEvidenceContradiction
			}
			position := slices.IndexFunc(state.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == duty.DutyID })
			if position < 0 {
				t.Fatal("retirement group absent")
			}
			want |= contract.AdministrativeEvidenceAcknowledged
			if state.adminIndex.Groups[position].SelectedEvidenceSummary != want {
				t.Error("index writer omitted qualified fact-only evidence", state.adminIndex.Groups[position].SelectedEvidenceSummary, want)
			}
			derived, err := administrativeSelectedEvidence(state.adminIndex, state.support)
			if err != nil || derived[position] != want {
				t.Error("complete summary omitted fact-only contradiction or uncertainty", derived, err)
			}
			for i, group := range state.adminIndex.Groups {
				if i != position && group.SelectedEvidenceSummary&contract.AdministrativeEvidenceContradiction != 0 {
					t.Error("contradiction contaminated another owner", group.GroupID)
				}
			}
			bad := *state
			bad.support = slices.Clone(state.support)
			for i := range bad.support {
				bad.support[i].Records = slices.Clone(state.support[i].Records)
				for j, row := range bad.support[i].Records {
					if row.Kind != contract.GeneratedAttemptSupportKind || row.RecordID != attempt.record.AttemptID {
						continue
					}
					changed := attempt.record
					changed.Facts.Digest[0] ^= 1
					body, err := contract.EncodeGeneratedAttemptRecord(changed)
					if err != nil {
						t.Fatal(err)
					}
					bad.support[i].Records[j].Body = body
				}
			}
			if _, err := administrativeSelectedEvidence(bad.adminIndex, bad.support); err == nil {
				t.Error("summary trusted facts outside exact Attempt descriptor")
			}
		})
	}
}

type administrativeEvidenceSelectionStore struct{ *observationSelectionStore }

func (s *administrativeEvidenceSelectionStore) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	if ctx == nil || ctx.Err() != nil || key != s.descriptor.HeadKey || token != s.token {
		s.t.Fatal("administrative evidence selection lost its exact current condition")
	}
	return s.observationSelectionStore.CompareAndSwap(ctx, key, token, body)
}

func administrativeFactOnlyColdEnding(t *testing.T, conflict string) {
	t.Helper()
	state, _, duty := administrativeRetirementFactsState(t, conflict)
	observationProtectFixture(t, state)
	reservation, err := state.deriveGeneratedReservation(t.Context(), generatedReservationInputForGenerations(t, state, generatedVectorID(175), []string{"later"}))
	if err != nil {
		t.Fatal("following independent generation", err)
	}
	cold := generatedReflectionSelectAndColdOpen(t, state, reservation)
	position := slices.IndexFunc(cold.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == duty.DutyID })
	want := uint16(contract.AdministrativeEvidenceQualifiedUnknown | contract.AdministrativeEvidenceAcknowledged)
	if conflict != "transport" {
		want |= contract.AdministrativeEvidenceContradiction
	}
	if position < 0 || cold.adminIndex.Groups[position].SelectedEvidenceSummary != want {
		t.Error("cold complete reader lost original mixed evidence")
	}
	store := &administrativeEvidenceSelectionStore{cold.store.(*generatedReflectionSelectionStore).observationSelectionStore}
	cold.store = store
	reader := &installedAdministrativeTestReader{store: store}
	optionalPages := 0
	for _, page := range cold.adminIndex.Pages {
		if !page.ReadRequired && !slices.ContainsFunc(page.Spans, func(span format.AdministrativeSpan) bool { return span.Mandatory }) {
			optionalPages++
		}
	}
	if optionalPages == 0 {
		t.Fatal("partial reader fixture has no optional work body")
	}
	optionalReads := 0
	reader.beforeRead = func(_ context.Context, key string) (contract.ReadResult, bool) {
		for _, page := range cold.adminIndex.Pages {
			if page.ReadRequired || slices.ContainsFunc(page.Spans, func(span format.AdministrativeSpan) bool { return span.Mandatory }) {
				continue
			}
			optional, err := format.Key(cold.admission.store.Prefix, page.Ref)
			if err != nil {
				t.Fatal(err)
			}
			if key == optional {
				optionalReads++
				return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}, true
			}
		}
		return contract.ReadResult{}, false
	}
	observer, err := NewInstalledAdministrativeReader(installedAdministrativeReadInput(cold, reader), AdministrativeList)
	if err != nil {
		t.Fatal(err)
	}
	listed := observer.List(installedAdministrativeTestContext(t), generatedVectorID(176))
	if listed.Result.Outcome != ObservedCurrent || listed.List == nil {
		t.Fatal("partial read required optional work body", listed.Result)
	}
	row := slices.IndexFunc(listed.List.Groups, func(group AuthorityGroup) bool { return group.GroupID == duty.DutyID })
	if row < 0 || listed.List.Groups[row].SelectedEvidenceSummary != want || optionalReads != 0 {
		t.Error("partial administrative reader recomputed or lost authenticated evidence", optionalReads)
	}
	if err := observer.Close(); err != nil {
		t.Fatal(err)
	}
	cold.admission.endWorkInvocation = generatedVectorID(177)
	ids := endWorkIDs{operation: generatedVectorID(178), transition: generatedVectorID(179), snapshot: generatedVectorID(180), revision: generatedVectorID(181), receipts: generatedVectorID(182), receiptIndex: generatedVectorID(183)}
	candidate, next, err := cold.deriveEndWorkCandidate(t.Context(), duty.DutyID, ids)
	if err != nil || candidate == nil || next == nil {
		t.Fatal("exact retirement ending", err)
	}
	preview, ok := previewFromCandidate(candidate)
	if !ok || preview.SelectedEvidenceSummary != want || candidate.head.EndWork == nil || candidate.head.EndWork.SelectedEvidenceSummary != want {
		t.Error("ending preview/subject lost original evidence")
	}
	windows, err := next.receiptWindowsFromAdministrativeSupport()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, receipt := range windows.Successes {
		if receipt.OperationID == ids.operation {
			found = true
			if receipt.AdministrativeOriginalEvidence != want {
				t.Error("ending receipt lost original mixed evidence")
			}
		}
	}
	if !found {
		t.Fatal("ending receipt absent")
	}
	physical := store
	signer := testtrust.New(t, cold.admission.store.Family, cold.admission.trust)
	authority, err := NewInstalledAdministrativeAuthority(AdministrativeAuthorityInstallation{ExpectedDomain: cold.admission.domain, ExpectedStore: cold.admission.store, PublicBasis: cold.admission.publicBasis(), CompositionID: generatedVectorID(184), SourcePins: installedAdministrativeTestPins(), Store: store, Trust: signer, CheckSource: func(context.Context) error { return nil }, CloseInstalled: func() error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	sends, signs := physical.sends, signer.Calls()
	applied := authority.Apply(installedAdministrativeTestContext(t), generatedVectorID(185), preview)
	if applied.Result.Outcome != ObservedCurrent || applied.End == nil || applied.End.Receipt.AdministrativeOriginalEvidence != want || physical.sends != sends+1 || signer.Calls() != signs+1 {
		t.Fatal("selected ending lost original uncertainty/contradiction", applied.Result)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	freshReader := &installedAdministrativeTestReader{store: store}
	lookup, err := NewInstalledAdministrativeReader(installedAdministrativeReadInput(cold, freshReader), AdministrativeReceipt)
	if err != nil {
		t.Fatal(err)
	}
	observed := lookup.Receipt(installedAdministrativeTestContext(t), generatedVectorID(186), applied.OperationID)
	if observed.Result.Outcome != ObservedCurrent || observed.Receipt == nil || observed.Receipt.Receipt.AdministrativeOriginalEvidence != want || !bytes.Equal(observed.Receipt.ReceiptBytes, applied.End.ReceiptBytes) || freshReader.heads.Load() != 1 || physical.sends != sends+1 || signer.Calls() != signs+1 {
		t.Fatal("cold GET-only receipt lost original fact-only history", observed.Result)
	}
	if err := lookup.Close(); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestAdministrativeFactOnlyContradictionSurvivesColdEnding(t *testing.T) {
	for _, conflict := range []string{"identity", "transport"} {
		t.Run(conflict, func(t *testing.T) { administrativeFactOnlyColdEnding(t, conflict) })
	}
}

// full_only: false
func TestAdministrativeCompleteReadRejectsOmittedFactOnlyContradiction(t *testing.T) {
	for _, tc := range []struct {
		name, conflict string
		omit           bool
	}{
		{"uncontested-transport", "transport", false},
		{"exact-contradiction", "identity", false},
		{"omitted-contradiction", "identity", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, _, duty := administrativeRetirementFactsState(t, tc.conflict)
			observationProtectFixture(t, before)
			reservation, err := before.deriveGeneratedReservation(t.Context(), generatedReservationInputForGenerations(t, before, generatedVectorID(175), []string{"later"}))
			if err != nil {
				t.Fatal("following independent generation", err)
			}
			state := generatedReflectionSelectAndColdOpen(t, before, reservation)
			newParent := state.root.Generated.ActiveOwner
			position := slices.IndexFunc(state.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == duty.DutyID })
			if position < 0 || newParent.IsZero() || newParent == duty.DutyID {
				t.Fatal("independent surviving retirement and ended Parent required")
			}
			state.adminIndex.Groups = slices.Clone(state.adminIndex.Groups)
			state.adminIndex.Groups[position].SelectedEvidenceSummary = contract.AdministrativeEvidenceQualifiedUnknown | contract.AdministrativeEvidenceAcknowledged
			if tc.conflict == "identity" && !tc.omit {
				state.adminIndex.Groups[position].SelectedEvidenceSummary |= contract.AdministrativeEvidenceContradiction
			}
			if !state.adminIndex.Valid() {
				t.Fatal("summary mutation broke administrative index framing")
			}
			state.admission.endWorkInvocation = generatedVectorID(187)
			ids := endWorkIDs{operation: generatedVectorID(188), transition: generatedVectorID(189), snapshot: generatedVectorID(190), revision: generatedVectorID(191), receipts: generatedVectorID(192), receiptIndex: generatedVectorID(193)}
			candidate, next, err := state.deriveEndWorkCandidate(t.Context(), newParent, ids)
			if err != nil || candidate == nil || next == nil || !next.validEndWorkSelection() {
				t.Fatal("independently ended Parent lacks exact ending proof", err)
			}
			retained := slices.IndexFunc(next.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == duty.DutyID })
			if retained < 0 || next.adminIndex.Groups[retained].SelectedEvidenceSummary != state.adminIndex.Groups[position].SelectedEvidenceSummary {
				t.Fatal("ending did not preserve the exact tested retained summary")
			}
			physical := &administrativeEvidenceSelectionStore{state.store.(*generatedReflectionSelectionStore).observationSelectionStore}
			state.store = physical
			signer := testtrust.New(t, state.admission.store.Family, state.admission.trust)
			candidate, prepared := state.persistCandidate(t.Context(), candidate, signer)
			if candidate == nil || prepared.Outcome != ObservedCurrent {
				t.Fatal("actual signed administrative candidate", prepared)
			}
			control, valid := state.selectedControl()
			if !valid || !selectedHeadProofs(candidate.head, control, nil) {
				t.Fatal("test candidate lacks actual current signed HEAD proof")
			}
			selected, result := state.selectCandidate(t.Context(), candidate)
			if selected == nil || result.Outcome != ObservedCurrent || !selected.validEndWorkSelection() {
				t.Fatal("partial selected observation refused exact ending", result)
			}
			admission := state.admission
			admission.composition, admission.entropy = generatedVectorID(194), nil
			cold, result := Open(t.Context(), OpenContext{admission: &admission}, physical)
			if tc.omit {
				if cold != nil || result.Outcome != IntegrityFailure || result.Reason != InvalidRelation {
					t.Error("complete cold read accepted omitted fact-only contradiction", result)
				}
			} else if cold == nil || result.Outcome != ObservedCurrent || cold.adminIndex.Groups[retained].SelectedEvidenceSummary != next.adminIndex.Groups[retained].SelectedEvidenceSummary {
				t.Error("complete cold read refused exact authenticated evidence", result)
			}
		})
	}
}

// full_only: false
func TestAdministrativeReleasedUnknownDeleteKeepsExactUnobservedEvidence(t *testing.T) {
	for _, hazard := range []bool{false, true} {
		t.Run(fmt.Sprint(hazard), func(t *testing.T) {
			state, source := generatedOrdinaryCleanupSourceState(t, contract.GeneratedCompletionAcknowledged, hazard)
			var attempts []contract.ID
			for invocation := byte(0); invocation < 2; invocation++ {
				reserved, err := state.deriveGeneratedReservation(t.Context(), generatedOrdinaryCleanupReservationInput(t, state, source, generatedVectorID(180+invocation)))
				if err != nil {
					t.Fatal("reserve actual unknown cleanup", err)
				}
				state = reserved.state
				work := mustSelectedGeneratedWork(t, state)
				attempt := work.attempts[work.phase.FrontierAttemptID]
				attempts = append(attempts, attempt.record.AttemptID)
				facts, err := contract.EncodeGeneratorSafeFacts(generatedRetirementFactsFixture(t, state, attempt, contract.GeneratorDispositionUnknown))
				if err != nil {
					t.Fatal(err)
				}
				plan, err := state.generatedOrdinaryCleanupAmbiguityPlan(t.Context(), attempt.record.AttemptID, facts, generatedLifecycleFixture(t, state))
				if err != nil {
					t.Fatal("plan exact unknown cleanup", err)
				}
				parked, err := state.deriveGeneratedOrdinaryCleanupAmbiguity(t.Context(), plan)
				if err != nil {
					t.Fatal("park exact unknown cleanup", err)
				}
				state = parked.state
				work = mustSelectedGeneratedWork(t, state)
				source, err = work.generatedDeleteSource(source.OwnerID)
				if err != nil {
					t.Fatal(err)
				}
			}
			work := mustSelectedGeneratedWork(t, state)
			older, later := work.attempts[attempts[0]], work.attempts[attempts[1]]
			packet := generatedRetirementResultFixture(t, state, older, contract.GeneratorDispositionRetirementAcknowledged)
			plan, err := state.generatedReflectionPlan(t.Context(), older.record.ResultID, packet, generatedLifecycleFixture(t, state))
			if err != nil {
				t.Fatal("plan exact acknowledged closure", err)
			}
			closed, err := state.deriveGeneratedCleanupClose(t.Context(), plan)
			if err != nil {
				t.Fatal("close source with a later unobserved result", err)
			}
			state = closed.state
			work = mustSelectedGeneratedWork(t, state)
			released, ok := work.releases[later.record.AttemptID]
			if !ok || released.release.State != contract.GeneratedReleaseUnobserved || work.hasRecord(generatedRecordKey{source.Record.Kind, source.SourceID}) || len(work.attempts) != 0 {
				t.Fatal("fixture did not retain exact release-only unknown work")
			}
			position := slices.IndexFunc(state.adminIndex.Groups, func(group format.AdministrativeGroup) bool {
				return group.OwnerKind == format.AdministrativeInboxRelease && group.GroupID == later.record.InboxID
			})
			want := uint16(contract.AdministrativeEvidenceQualifiedUnknown | contract.AdministrativeEvidenceReleaseUnobserved)
			derived, err := administrativeSelectedEvidence(state.adminIndex, state.support)
			if err != nil || position < 0 || derived[position] != want || state.adminIndex.Groups[position].SelectedEvidenceSummary != want {
				t.Fatal("release-only mapping lost uncertainty or invented contradiction", derived, err)
			}
			bad := state.adminIndex
			bad.Groups = slices.Clone(bad.Groups)
			bad.Groups[position].TargetID = generatedVectorID(250)
			if !bad.Valid() {
				t.Fatal("damaged release owner fixture is not codec-valid")
			}
			if _, err := administrativeSelectedEvidence(bad, state.support); err == nil {
				t.Fatal("source-absent mapping borrowed another release owner")
			}
		})
	}
}

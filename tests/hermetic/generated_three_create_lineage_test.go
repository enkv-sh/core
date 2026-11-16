package core

import (
	"bytes"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestActualThreeCreateLineageFinalKeepsOnlyUnresolvedOwners(t *testing.T) {
	actualThreeCreateLineage(t, nil)
}

func actualThreeCreateLineage(t *testing.T, capture func(string, fixtureEnvironment, *StateSession)) {
	t.Helper()
	t.Log("producer shape: one Create lineage; actual returned but unrecorded first Create; residue; actual qualified no-effect second Create; actual owned-unusable third Create; nonselecting Final")
	ctx := t.Context()
	first := newGeneratedActualOperation(t, false, custody.StandardValue)
	env := first.env
	env.Context = ctx
	defer env.Custody.RetireGenerated()
	defer env.Custody.RetireApply()
	selected := generatedLifecycleReopen(t, ctx, first.fixture.session, env.Store)
	work := mustSelectedGeneratedWork(t, selected)
	original := work.attempts[first.expected.Template.AttemptID]
	if first.sends != 1 || len(first.result) == 0 || len(original.result) != 0 || original.record.State != contract.GeneratedEffectTransmitted {
		t.Fatal("first Create did not actually return before its missing Record")
	}
	checkGroups := func(stage string, state *StateSession, groups ...contract.ID) {
		t.Helper()
		t.Logf("selected stage=%s groups=%d duties=%d hazards=%d", stage, len(state.adminIndex.Groups), state.root.Generated.Duties, state.root.Generated.Hazards)
		slices.SortFunc(groups, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		assertSharedIntentGroupIDs(t, state, groups)
	}
	checkGroups("initial Create entered", selected, original.record.OperationID, original.record.OwnerID)
	firstPacket := bytes.Clone(first.result)
	// The actual-operation helper returns the sealed packet without publishing
	// its inbox. Publish through Core while leaving the selected Record absent.
	if persisted := selected.persistGeneratedResult(ctx, generatedResultWrite{attempt: original.record.AttemptID, body: firstPacket}); persisted != (Result{}) {
		t.Fatal("publish exact original result before residue", persisted)
	}
	durable, present, read := selected.ReadGeneratedResult(ctx, original.record.AttemptID)
	if read != (Result{}) || !present || !bytes.Equal(durable, firstPacket) || len(mustSelectedGeneratedWork(t, selected).attempts[original.record.AttemptID].result) != 0 {
		t.Fatal("published original packet was absent or adopted without Record", read)
	}
	selected = selectGeneratedResiduePlan(t, ctx, env, selected, original.record.AttemptID)
	checkGroups("residue selected", selected, original.record.OperationID, original.expected.Template.HazardID)
	prior := preparePrivateGeneratedSuccessorReservation(t, env, selected)
	entered, secondRecord, second, secondPacket := selectActualGeneratedPacketRecord(t, env, selected, prior, custody.GeneratedConfirmedNoEffect, false, nil)
	enteredCold := generatedLifecycleReopen(t, ctx, entered, env.Store)
	checkGroups("residue successor entered before Record", enteredCold, original.record.OperationID, original.expected.Template.HazardID, second.Template.DutyID)
	if enteredCold.root.Generated.Attempts != 2 || enteredCold.root.Generated.Duties != 1 || enteredCold.root.Generated.Hazards != 1 ||
		len(mustSelectedGeneratedWork(t, enteredCold).attempts[second.Template.AttemptID].result) != 0 {
		t.Fatal("selected residue successor does not add exactly one new Duty")
	}
	if capture != nil {
		capture("active-residue", env, enteredCold)
	}
	selected, outcome := entered.selectCandidate(ctx, secondRecord.reservation.candidate)
	if selected == nil || outcome.Outcome != ObservedCurrent {
		t.Fatal("actual residue successor qualified no-effect Record", outcome)
	}
	env.Custody.RetireGenerated()
	selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
	checkGroups("qualified no-effect Record selected", selected, original.record.OperationID, original.expected.Template.HazardID, second.Template.DutyID)
	secondResult, err := contract.InspectGeneratedResultRecord(secondPacket)
	if err != nil || secondResult.SafeFacts.Disposition != contract.GeneratorDispositionConfirmedNoEffect || len(secondResult.SafeFacts.Target) != 0 || len(secondResult.SafeFacts.ResourceData) != 0 {
		t.Fatal("second Create lacks its actual qualified no-effect packet", err)
	}
	prior = preparePrivateGeneratedSuccessorReservation(t, env, selected)
	selected, _, third, thirdPacket := selectActualGeneratedPacketRecord(t, env, selected, prior, custody.GeneratedTerminalFailure, true, nil)
	selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
	work = mustSelectedGeneratedWork(t, selected)
	checkGroups("third terminal Record selected", selected, original.record.OperationID, original.expected.Template.HazardID, second.Template.DutyID, third.Template.DutyID)
	terminal := work.attempts[third.Template.AttemptID]
	residueOriginal := work.attempts[original.record.AttemptID]
	if len(work.attempts) != 3 || len(work.releases) != 0 || work.parent == nil ||
		second.Template.Branch != contract.GeneratorBranchResidue || third.Template.Branch != contract.GeneratorBranchResidueThenNoEffect ||
		second.Template.PredecessorAttemptID != original.record.AttemptID || third.Template.PredecessorAttemptID != second.Template.AttemptID ||
		second.Template.LineageID != original.record.LineageID || third.Template.LineageID != original.record.LineageID ||
		terminal.record.State != contract.GeneratedEffectFailedTerminal || terminal.record.History.Count != 3 || !bytes.Equal(terminal.result, thirdPacket) {
		t.Fatal("three actual Create entries do not follow the fixed single-lineage path")
	}
	graph, err := work.retainedGraph(original.record.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	createLineages := 0
	for _, lineage := range graph.Lineages {
		if lineage.Purpose == contract.GeneratorLineageCreate {
			createLineages++
		}
	}
	if createLineages != 1 {
		t.Fatal("producer did not use exactly one Create lineage")
	}
	history, err := work.vectors.resolve(contract.GeneratedAttemptSupportKind, terminal.record.AttemptID, contract.GeneratorVectorHistory, terminal.record.History)
	if err != nil || len(history) != 3 {
		t.Fatal("three-entry lineage lacks its complete selected history", err)
	}
	for i := range history {
		history[i] = bytes.Clone(history[i])
	}
	t.Logf("before Final: entered Creates=%d selected Attempts=%d releases=%d children=%d child-bytes=%d", 3, len(work.attempts), len(work.releases), selected.root.ChildCount, selected.root.ChildEncodedBytes)
	admitted := generatedPlanInputFixture(t, selected).context
	admitted.AdmissionID, admitted.SessionID = testID("three Create Final admission"), testID("three Create Final session")
	plan, err := selected.generatedFinalRequest(ctx, admitted)
	if err != nil || plan == nil || plan.selecting {
		t.Fatal("failed third Create did not admit a nonselecting Final", err)
	}
	selected, final := preparePrivateGeneratedFinal(t, env, selected, plan)
	closed, result := selected.selectCandidate(ctx, final.reservation.candidate)
	if closed == nil || result.Outcome != ObservedCurrent {
		t.Fatal("actual three-Create nonselecting Final", result)
	}
	env.Custody.RetireGenerated()
	closed = generatedLifecycleReopen(t, ctx, closed, env.Store)
	work = mustSelectedGeneratedWork(t, closed)
	t.Logf("after Final: Attempts=%d hazards=%d duties=%d releases=%d groups=%d children=%d child-bytes=%d", len(work.attempts), closed.root.Generated.Hazards, closed.root.Generated.Duties, len(work.releases), len(closed.adminIndex.Groups), closed.root.ChildCount, closed.root.ChildEncodedBytes)
	if work.parent != nil || work.phase != nil || len(work.attempts) != 2 || len(work.releases) != 0 || closed.root.Generated.Hazards != 2 || closed.root.Generated.Duties != 0 || len(closed.adminIndex.Groups) != 2 {
		t.Fatal("Final did not retain exactly the two unresolved owners")
	}
	if _, kept := work.attempts[second.Template.AttemptID]; kept {
		t.Fatal("qualified no-effect entry was incorrectly counted as a retained owner")
	}
	if _, kept := work.records[generatedRecordKey{contract.GeneratedResultSupportKind, second.Template.ResultID}]; kept {
		t.Fatal("qualified no-effect result retained without a selected owner")
	}
	keptOriginal := work.attempts[original.record.AttemptID]
	keptTerminal := work.attempts[terminal.record.AttemptID]
	if !reflect.DeepEqual(keptOriginal, residueOriginal) || keptOriginal.record.State != contract.GeneratedEffectClosedWithResidue ||
		len(keptOriginal.result) != 0 || !reflect.DeepEqual(keptTerminal, terminal) {
		t.Fatal("Final changed the exact unresolved original or terminal Create")
	}
	keptHistory, err := work.vectors.resolve(contract.GeneratedAttemptSupportKind, terminal.record.AttemptID, contract.GeneratorVectorHistory, terminal.record.History)
	if err != nil || !reflect.DeepEqual(keptHistory, history) {
		t.Fatal("Final changed immutable three-entry history", err)
	}
	wantGroups := []contract.ID{original.expected.Template.HazardID, third.Template.HazardID}
	slices.SortFunc(wantGroups, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	assertSharedIntentGroupIDs(t, closed, wantGroups)
	packet, present, outcome := closed.ReadGeneratedResult(ctx, original.record.AttemptID)
	if outcome != (Result{}) || !present || !bytes.Equal(packet, firstPacket) {
		t.Fatal("real unrecorded first result no longer exists in its original inbox", outcome)
	}
	if capture != nil {
		capture("final-hazards", env, closed)
	}

}

package core

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestEndWorkSelectsAndReopensAuthenticatedStoreState(t *testing.T) {
	env, selected, _, _ := generatedAuthenticatedDeleteHazardFixture(t, false, 0)
	store := env.Store.(*memoryStore)
	admin, observed := openAdministrative(context.Background(), OpenContext{admission: &selected.admission}, store)
	if admin == nil || observed.Outcome != ObservedCurrent {
		t.Fatal("administrative predecessor did not reopen", observed)
	}
	if len(admin.adminIndex.Groups) == 0 {
		t.Fatal("selected administrative work is absent")
	}
	groupID := admin.adminIndex.Groups[0].GroupID
	wrongRole := *admin
	issueTestEndWorkInvocation(t, admin)
	wrongRole.admission.endWorkInvocation = admin.admission.endWorkInvocation
	wrongRole.admission.recipient = generatedVectorID(245)
	store.creates, store.cas = 0, 0
	if candidate, refused := wrongRole.prepareEndSelectedWork(context.Background(), groupID, env.Trust); candidate != nil || refused.Outcome != AdmissionRefused || store.creates != 0 || store.cas != 0 {
		t.Fatal("non-Authority recipient reached end-work signing or Store", refused)
	}
	beforeAccess := admin.root.AccessRecordCount
	beforeRoot := admin.root.CurrentAccess.AccessRoot
	store.creates, store.cas = 0, 0
	candidate, prepared := prepareTestEndSelectedWork(t, admin, context.Background(), groupID, env.Trust)
	if candidate == nil || prepared.Outcome != ObservedCurrent || store.creates == 0 || store.cas != 0 {
		t.Fatal("end-work preparation did not stage the Store candidate", prepared, store.creates, store.cas)
	}
	ended, outcome := admin.selectCandidate(context.Background(), candidate)
	if ended == nil || outcome.Outcome != ObservedCurrent || store.cas != 1 {
		t.Fatal("end-work selection failed", outcome, store.cas)
	}
	reopened := generatedLifecycleReopen(t, t.Context(), ended, store)
	if beforeAccess != 2 || reopened.root.AccessRecordCount != 1 || reopened.root.CurrentAccess.AccessRoot == beforeRoot ||
		len(reopened.adminIndex.Groups) != 0 {
		t.Fatal("exclusive seed/access charge was not recovered while current value access survived")
	}
	for _, group := range reopened.adminIndex.Groups {
		if group.GroupID == groupID {
			t.Fatal("ended duty returned after complete reopen")
		}
	}
	prior := *reopened.valueEntry(0)
	input := generatedStatePlanInput(t, reopened, generatedVectorID(201), []string{prior.Name},
		defaultGeneratedFixtureProfile(), prior.Generated.Epoch+1,
		map[string]contract.ID{prior.Name: prior.Incarnation}, map[string]contract.ValueEntry{prior.Name: prior})
	continued := selectPrivateGeneratedOperation(t, env, reopened, input, "ordinary work after end")
	if continued == nil || continued.valueEntry(0).Generated.Epoch != prior.Generated.Epoch+1 {
		t.Fatal("ordinary generated successor did not continue after administrative end")
	}
	secondAdmin, observed := openAdministrative(context.Background(), OpenContext{admission: &continued.admission}, store)
	if secondAdmin == nil || observed.Outcome != ObservedCurrent || len(secondAdmin.adminIndex.Groups) == 0 {
		t.Fatal("second selected work did not reopen for administrative exit", observed)
	}
	retiring := secondAdmin.valueEntry(0)
	if retiring == nil || retiring.Generated.RetiringDutyPresent != 1 || !secondAdmin.currentRetiringPointersSelected() {
		t.Fatal("selected retirement pointer is not authenticated")
	}
	wrong := *secondAdmin
	wrong.adminIndex = secondAdmin.adminIndex
	wrong.adminIndex.Groups = slices.Clone(secondAdmin.adminIndex.Groups)
	for i := range wrong.adminIndex.Groups {
		if wrong.adminIndex.Groups[i].GroupID == retiring.Generated.RetiringDutyID {
			wrong.adminIndex.Groups[i].DutyKind = contract.GeneratedDutyCreate
		}
	}
	if wrong.currentRetiringPointersSelected() {
		t.Fatal("mismatched retirement owner accepted")
	}
	secondGroup := secondAdmin.adminIndex.Groups[0].GroupID
	secondCandidate, prepared := prepareTestEndSelectedWork(t, secondAdmin, context.Background(), secondGroup, env.Trust)
	if secondCandidate == nil || prepared.Outcome != ObservedCurrent {
		t.Fatal("second end-work preparation failed", prepared)
	}
	secondEnded, outcome := secondAdmin.selectCandidate(context.Background(), secondCandidate)
	if secondEnded == nil || outcome.Outcome != ObservedCurrent {
		t.Fatal("second end-work selection failed", outcome)
	}
	secondReopened := generatedLifecycleReopen(t, t.Context(), secondEnded, store)
	retainedAccess, err := secondAdmin.endWorkAccessRows(t.Context(), secondEnded.adminIndex)
	if err != nil {
		t.Fatal("remaining logical access", err)
	}
	beforeExact, err := administrativePreservedCurrent(secondAdmin.root, secondAdmin.pages, retainedAccess, nil)
	if err != nil {
		t.Fatal("unfiltered predecessor projection", err)
	}
	clear := map[contract.ID]contract.ID{retiring.ValueState: retiring.Generated.RetiringDutyID}
	beforeFiltered, err := administrativePreservedCurrent(secondAdmin.root, secondAdmin.pages, retainedAccess, clear)
	if err != nil {
		t.Fatal("filtered predecessor projection", err)
	}
	afterExact, err := administrativePreservedCurrent(secondReopened.root, secondReopened.pages, secondReopened.generatedCoverageRecords(), nil)
	if err != nil || beforeExact == afterExact || beforeFiltered != afterExact {
		t.Fatal("retirement pointer normalization changed other current state", err)
	}
	if _, err := administrativePreservedCurrent(secondAdmin.root, secondAdmin.pages, retainedAccess,
		map[contract.ID]contract.ID{retiring.ValueState: generatedVectorID(250)}); err == nil {
		t.Fatal("unmatched retirement pointer normalized")
	}
	if secondReopened.root.AccessRecordCount != 1 || secondReopened.valueEntry(0).Generated.RetiringDutyPresent != 0 ||
		!secondReopened.valueEntry(0).Generated.RetiringDutyID.IsZero() {
		t.Fatal("second exit retained obsolete access or retiring pointer")
	}
}

// full_only: false
func TestAdministrativeEndWorkReceiptSurvivesOrdinarySuccessors(t *testing.T) {
	for _, kind := range []uint8{format.GeneratorAuth, format.LifecycleAuth} {
		t.Run(fmt.Sprintf("auth%d", kind), func(t *testing.T) {
			ctx := t.Context()
			env, selected, _, _ := generatedAuthenticatedDeleteHazardFixture(t, false, 0)
			store := env.Store.(*memoryStore)
			admin, result := openAdministrative(ctx, OpenContext{admission: &selected.admission}, store)
			if admin == nil || result.Outcome != ObservedCurrent || len(admin.adminIndex.Groups) == 0 {
				t.Fatal("fixture has no administrative work", result)
			}
			target := admin.adminIndex.Groups[0].GroupID
			candidate, prepared := prepareTestEndSelectedWork(t, admin, ctx, target, env.Trust)
			if candidate == nil || prepared.Outcome != ObservedCurrent {
				t.Fatal("EndWork prepare", prepared)
			}
			ended, result := admin.selectCandidate(ctx, candidate)
			if ended == nil || result.Outcome != ObservedCurrent || ended.head.EndWork == nil {
				t.Fatal("EndWork select", result)
			}
			operation := ended.head.EndWork.OperationID
			complete := generatedLifecycleReopen(t, ctx, ended, store)
			want, result := complete.MutationReceipt(ctx, operation)
			if result.Outcome != ObservedCurrent {
				t.Fatal("complete EndWork receipt", result)
			}
			wantReceipt, err := contract.InspectCompactMutationReceipt(want)
			if err != nil || wantReceipt.OperationID != operation || wantReceipt.OperationKind != contract.OperationEndSelectedWork || wantReceipt.AdministrativeGroupID != target {
				t.Fatal("wrong complete EndWork receipt", err)
			}
			stale, result := openAdministrative(ctx, OpenContext{admission: &complete.admission}, store)
			if stale == nil || result.Outcome != ObservedCurrent {
				t.Fatal("stale administrative read", result)
			}
			var next *StateSession
			if kind == format.GeneratorAuth {
				prior := *complete.valueEntry(0)
				input := generatedStatePlanInput(t, complete, generatedVectorID(201), []string{prior.Name},
					defaultGeneratedFixtureProfile(), prior.Generated.Epoch+1,
					map[string]contract.ID{prior.Name: prior.Incarnation}, map[string]contract.ValueEntry{prior.Name: prior})
				next = selectPrivateGeneratedOperation(t, env, complete, input, "receipt ordinary generated successor")
			} else {
				input := append(complete.currentEntryInputs(), ApplyEntryInput{Name: "zz-receipt-control", Recipients: []contract.ID{complete.admission.recipient},
					ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputBytes: []byte("public control"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
				parent := admitSuppliedComparison(t, complete, env.Custody, input)
				comparison, compared := complete.Compare(ctx, input, parent)
				if comparison == nil {
					t.Fatal("lifecycle compare", compared)
				}
				ordinary, prepared := complete.Prepare(ctx, comparison, admit(t, complete, comparison), env.Trust)
				if ordinary == nil {
					t.Fatal("lifecycle prepare", prepared)
				}
				next, result = complete.selectCandidate(ctx, ordinary)
				if next == nil || result.Outcome != ObservedCurrent {
					t.Fatal("lifecycle select", result)
				}
				env.Custody.RetireApply()
			}
			if next.head.AuthKind != kind {
				t.Fatal("fixture selected wrong successor", next.head.AuthKind, kind)
			}
			cold, result := openAdministrative(ctx, OpenContext{admission: &next.admission}, store)
			if cold == nil || result.Outcome != ObservedCurrent {
				t.Fatal("cold administrative successor", result)
			}
			ordinary := generatedLifecycleReopen(t, ctx, next, store)
			creates, cas := store.creates, store.cas
			public, private := env.Custody.Calls()
			view, listed := (&AuthoritySession{state: cold, mode: LocalAuthorityInspect}).Inspect(ctx)
			if listed.Outcome != ObservedCurrent || view.Revision != next.head.Core.Revision ||
				view.Revision == wantReceipt.ObservedRevisionID || view.WarningBits != cold.root.WarningBits {
				t.Fatal("history did not use the later authenticated selected image", listed)
			}
			var retained []AuthorityAbandonment
			for _, row := range view.Abandonments {
				if row.Receipt.OperationID == operation {
					retained = append(retained, row)
				}
			}
			if len(retained) != 1 || retained[0].Receipt != wantReceipt || !bytes.Equal(retained[0].ReceiptBytes, want) {
				t.Fatal("later ordinary HEAD lost exact retained abandonment")
			}
			for _, reader := range []struct {
				name  string
				state *StateSession
			}{{"complete", ordinary}, {"cold", cold}, {"refreshed", stale}} {
				got, observed := reader.state.MutationReceipt(ctx, operation)
				receipt, err := contract.InspectCompactMutationReceipt(got)
				if observed.Outcome != ObservedCurrent || err != nil || !bytes.Equal(got, want) || receipt != wantReceipt {
					t.Fatal("ordinary successor hid retained EndWork receipt", reader.name, observed, err)
				}
			}
			if store.creates != creates || store.cas != cas {
				t.Fatal("receipt read wrote Store")
			}
			if p, k := env.Custody.Calls(); p != public || k != private {
				t.Fatal("receipt read used private custody")
			}
		})
	}
}

// full_only: false
func TestEndWorkPacksExclusiveCurrentIntentFromMandatoryBytes(t *testing.T) {
	ctx := context.Background()
	env, selected, _, _ := generatedAuthenticatedDeleteHazardFixture(t, false, 0)
	selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
	old := *selected.valueEntry(0)
	operation := generatedVectorID(239)
	profile := defaultGeneratedFixtureProfile()
	incarnations := map[string]contract.ID{old.Name: old.Incarnation}
	retiring := map[string]contract.ValueEntry{old.Name: old}
	input := generatedStatePlanInput(t, selected, operation, []string{old.Name}, profile, old.Generated.Epoch+1, incarnations, retiring)
	replacement := generatedReservationInputForStateIntent(t, selected, operation, []string{old.Name},
		[]byte(`{"name":"distinct-current-intent"}`), profile, old.Generated.Epoch+1, incarnations, retiring)
	input.graph, input.declaration, input.registry, input.recoveryPolicy, input.requestBindings = replacement.graph,
		replacement.declaration, replacement.graph.Request.Registry, replacement.graph.Request.RecoveryPolicyID, slices.Clone(replacement.requestBindings)
	selected = selectPrivateGeneratedOperation(t, env, selected, input, "distinct current beside old hazard")
	selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
	current := selected.valueEntry(0)
	if current == nil || current.ValueSource != contract.Generated {
		t.Fatal("selected predecessor lacks a generated current value")
	}
	prior, err := selected.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	intent, err := prior.readSelectedSlice(ctx, contract.GeneratorContentIntent, current.Generated.IntentDigest, contract.GeneratorIntentMaxLength)
	if err != nil {
		t.Fatal(err)
	}
	beforeLocation := prior.content.locations[generatedContentKey{kind: contract.GeneratorContentIntent, id: current.Generated.IntentDigest}]
	admin, observed := openAdministrative(ctx, OpenContext{admission: &selected.admission}, env.Store)
	if admin == nil || observed.Outcome != ObservedCurrent {
		t.Fatal("administrative predecessor", observed)
	}
	var target contract.ID
	var unreadable format.Ref
	for _, group := range admin.adminIndex.Groups {
		work, _, err := admin.administrativeWorkClosure(group.GroupID)
		if err != nil {
			t.Fatal(err)
		}
		work, err = admin.administrativeWorkWithoutOldReceipts(work)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := admin.planAdministrativeCurrentIntents(t.Context(), work)
		if err != nil {
			t.Fatal(err)
		}
		if plan.changed && plan.dropBlobs[beforeLocation.BlobID] {
			target = group.GroupID
			for _, page := range work.Pages {
				if !page.ReadRequired && !slices.ContainsFunc(page.Spans, func(span format.AdministrativeSpan) bool { return span.Mandatory }) {
					unreadable = page.Ref
					break
				}
			}
			break
		}
	}
	if target.IsZero() || unreadable.Object.IsZero() {
		t.Fatal("fixture has no compacting exit beside unreadable retained work")
	}
	store := env.Store.(*memoryStore)
	key, err := format.Key(admin.admission.store.Prefix, unreadable)
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	oldObject, present := store.objects[key]
	delete(store.objects, key)
	store.mu.Unlock()
	if !present || len(oldObject.Body) == 0 {
		t.Fatal("selected optional support was not present before damage")
	}
	defer func() {
		store.mu.Lock()
		store.objects[key] = oldObject
		store.mu.Unlock()
	}()
	admin, observed = openAdministrative(ctx, OpenContext{admission: &selected.admission}, store)
	if admin == nil || observed.Outcome != ObservedCurrent {
		t.Fatal("fresh administrative reader needed disposable work", observed)
	}
	beforeCAS, beforeCreates := store.cas, store.creates
	public, private := env.Custody.Calls()
	candidate, prepared := prepareTestEndSelectedWork(t, admin, ctx, target, env.Trust)
	if candidate == nil || prepared.Outcome != ObservedCurrent || store.cas != beforeCAS {
		t.Fatal("compacting exit preparation", prepared)
	}
	if _, outcome := admin.selectCandidate(ctx, candidate); outcome.Outcome != ObservedCurrent || store.cas != beforeCAS+1 || store.creates <= beforeCreates {
		t.Fatal("compacting exit selection", outcome)
	}
	if ordinary, result := Open(ctx, OpenContext{admission: &admin.admission}, store); ordinary != nil || result.Outcome != EvidenceUnavailable {
		t.Fatal("ordinary reader accepted missing retained work", result)
	}
	store.mu.Lock()
	store.objects[key] = oldObject
	store.mu.Unlock()
	after, outcome := Open(ctx, OpenContext{admission: &admin.admission}, store)
	if after == nil || outcome.Outcome != ObservedCurrent {
		t.Fatal("compacted ordinary successor", outcome)
	}
	if nowPublic, nowPrivate := env.Custody.Calls(); nowPublic != public || nowPrivate != private {
		t.Fatal("administrative compaction used Crypto custody", nowPublic-public, nowPrivate-private)
	}
	expectedCurrent := *current
	if expectedCurrent.Generated.RetiringDutyPresent == 1 && expectedCurrent.Generated.RetiringDutyID == target {
		expectedCurrent.Generated.RetiringDutyPresent = 0
		expectedCurrent.Generated.RetiringDutyID = contract.ID{}
	}
	if !reflect.DeepEqual(after.valueEntry(0), &expectedCurrent) {
		t.Fatal("physical intent relocation changed the logical current value")
	}
	work, err := after.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	location := work.content.locations[generatedContentKey{kind: contract.GeneratorContentIntent, id: current.Generated.IntentDigest}]
	actual, err := work.readSelectedSlice(ctx, contract.GeneratorContentIntent, current.Generated.IntentDigest, contract.GeneratorIntentMaxLength)
	if err != nil || !bytes.Equal(actual, hermeticGeneratorIntent(intent)) || location.BlobID != contract.Hash(intent) || location.Offset != 0 ||
		location.Logical() != beforeLocation.Logical() || after.root.Generated.Slices == selected.root.Generated.Slices ||
		after.adminIndex.SliceSnapshot == admin.adminIndex.SliceSnapshot {
		t.Fatal("compacted successor changed logical bytes or kept stale physical mapping", err)
	}
	if slices.ContainsFunc(after.root.Generated.Fragments, func(fragment format.FragmentLocation) bool {
		return fragment.BlobID == beforeLocation.BlobID
	}) {
		t.Fatal("exclusive predecessor blob remained selected")
	}
	continuedValue := *after.valueEntry(0)
	if continuedValue.Generated.RetiringDutyPresent == 1 {
		// A new rotation cannot retire the same current value again while its
		// prior retirement Duty remains selected. End that Duty first.
		remaining, result := openAdministrative(ctx, OpenContext{admission: &after.admission}, store)
		if remaining == nil || result.Outcome != ObservedCurrent {
			t.Fatal("remaining retirement Duty did not reopen", result)
		}
		candidate, prepared := prepareTestEndSelectedWork(t, remaining, ctx, continuedValue.Generated.RetiringDutyID, env.Trust)
		if candidate == nil || prepared.Outcome != ObservedCurrent {
			t.Fatal("remaining retirement Duty could not end", prepared)
		}
		if next, selectedResult := remaining.selectCandidate(ctx, candidate); next == nil || selectedResult.Outcome != ObservedCurrent {
			t.Fatal("remaining retirement Duty was not selected", selectedResult)
		}
		after, result = Open(ctx, OpenContext{admission: &remaining.admission}, store)
		if after == nil || result.Outcome != ObservedCurrent {
			t.Fatal("ordinary reader could not reopen after both exits", result)
		}
		continuedValue = *after.valueEntry(0)
		if continuedValue.Generated.RetiringDutyPresent != 0 {
			t.Fatal("ending the exact retirement Duty left its current pointer")
		}
	}
	continuedInput := generatedStatePlanInput(t, after, generatedVectorID(240), []string{continuedValue.Name},
		defaultGeneratedFixtureProfile(), continuedValue.Generated.Epoch+1,
		map[string]contract.ID{continuedValue.Name: continuedValue.Incarnation},
		map[string]contract.ValueEntry{continuedValue.Name: continuedValue})
	continued := selectPrivateGeneratedOperation(t, env, after, continuedInput, "ordinary work after compacted exit")
	continued = generatedLifecycleReopen(t, ctx, continued, store)
	if continued.valueEntry(0).Generated.Epoch != continuedValue.Generated.Epoch+1 {
		t.Fatal("compacted current intent blocked the next ordinary generated selection")
	}
}

func selectTwoNameCurrentGeneration(t *testing.T, operationCtx context.Context, env fixtureEnvironment, before *StateSession, input generatedPlanInput, label string) *StateSession {
	t.Helper()
	ctx := context.Background()
	reservation, _ := preparePrivateGeneratedReservation(t, env, before, input, nil)
	if len(input.requestBindings) != 2 {
		t.Fatal(label, "requires two exact original bindings")
	}
	selected, first, second, firstBody, secondBody := runParallelGeneratedCreates(t, ctx, env, before, reservation,
		[2]contract.ID{input.requestBindings[0].AttemptID, input.requestBindings[1].AttemptID}, custody.StandardValue)
	for _, result := range []struct {
		attempt contract.ID
		body    []byte
	}{{first.Template.AttemptID, firstBody}, {second.Template.AttemptID, secondBody}} {
		selected = selectFreshGeneratedRecord(t, env.Store.(*memoryStore), selected, result.attempt, result.body)
		selected = generatedLifecycleReopen(t, operationCtx, selected, env.Store)
	}
	finalContext := generatedPlanInputFixture(t, selected).context
	finalContext.AdmissionID = contract.Hash(append([]byte(label+" final admission"), input.graph.Request.OperationID[:]...))
	finalContext.SessionID = contract.Hash(append([]byte(label+" final session"), input.graph.Request.OperationID[:]...))
	finalPlan, err := selected.generatedFinalRequest(t.Context(), finalContext)
	if err != nil {
		t.Fatal(label, "final request", err)
	}
	selected, final := preparePrivateGeneratedFinal(t, env, selected, finalPlan)
	closed, outcome := selected.selectCandidate(ctx, final.reservation.candidate)
	if closed == nil || outcome.Outcome != ObservedCurrent || !closed.root.Generated.ActiveOwner.IsZero() {
		t.Fatal(label, "final selection", outcome)
	}
	env.Custody.RetireGenerated()
	return generatedLifecycleReopen(t, operationCtx, closed, env.Store)
}

// full_only: false
func TestEndWorkPacksCurrentIntentStillOwnedBySurvivingGroup(t *testing.T) {
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	fixture := newEnvironmentFixture(t, ctx, env, nil, false)
	names := []string{"alpha", "omega"}
	firstIntent := hermeticGeneratorIntent([]byte(`{"name":"shared-A"}`))
	firstIntentForName := func(string) []byte { return firstIntent }
	secondIntentForName := func(name string) []byte {
		if name == "alpha" {
			return hermeticGeneratorIntent([]byte(`{"name":"replacement-C"}`))
		}
		return firstIntent
	}
	profile := defaultGeneratedFixtureProfile()
	firstOperation := generatedVectorID(239)
	input := generatedStatePlanInput(t, fixture.session, firstOperation, names, profile, 0, nil, nil)
	first := generatedReservationInputForMembershipStateIntents(t, fixture.session, firstOperation,
		[]contract.ID{fixture.session.admission.recipient}, names, firstIntentForName, profile, 0, nil, nil)
	input.graph, input.declaration, input.registry, input.recoveryPolicy, input.requestBindings = first.graph,
		first.declaration, first.graph.Request.Registry, first.graph.Request.RecoveryPolicyID, slices.Clone(first.requestBindings)
	selected := selectTwoNameCurrentGeneration(t, ctx, env, fixture.session, input, "two-name first generation")
	firstWork, err := selected.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		intentID, digestErr := contract.GeneratorIntentDigest(hermeticGeneratorIntent(firstIntentForName(name)))
		if digestErr != nil {
			t.Fatal(digestErr)
		}
		location := firstWork.content.locations[generatedContentKey{kind: contract.GeneratorContentIntent, id: intentID}]
		t.Logf("first current intent %s blob=%x offset=%d length=%d canonical=%t", name, location.BlobID, location.Offset, location.Length, location.BlobID == contract.Hash(firstIntentForName(name)))
	}
	old := map[string]contract.ValueEntry{}
	incarnations := map[string]contract.ID{}
	for _, name := range names {
		for _, entry := range selected.root.Names {
			if entry.Name == name {
				old[name] = *selected.valueEntry(entry.Slot)
				incarnations[name] = old[name].Incarnation
			}
		}
		if old[name].ValueSource != contract.Generated {
			t.Fatal("first generation lacks a current generated value", name)
		}
	}
	secondOperation := generatedVectorID(240)
	input = generatedStatePlanInput(t, selected, secondOperation, names, profile, old[names[0]].Generated.Epoch+1, incarnations, old)
	second := generatedReservationInputForMembershipStateIntents(t, selected, secondOperation,
		[]contract.ID{selected.admission.recipient}, names, secondIntentForName, profile,
		old[names[0]].Generated.Epoch+1, incarnations, old)
	input.graph, input.declaration, input.registry, input.recoveryPolicy, input.requestBindings = second.graph,
		second.declaration, second.graph.Request.Registry, second.graph.Request.RecoveryPolicyID, slices.Clone(second.requestBindings)
	selected = selectTwoNameCurrentGeneration(t, ctx, env, selected, input, "two-name second generation")
	current := old[names[0]]
	if selected.root.Generated.GeneratedCurrent != 2 {
		t.Fatal("signed predecessor lost two generated current entries")
	}
	prior, err := selected.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		intentID, digestErr := contract.GeneratorIntentDigest(hermeticGeneratorIntent(secondIntentForName(name)))
		if digestErr != nil {
			t.Fatal(digestErr)
		}
		location := prior.content.locations[generatedContentKey{kind: contract.GeneratorContentIntent, id: intentID}]
		t.Logf("second current intent %s blob=%x offset=%d length=%d canonical=%t", name, location.BlobID, location.Offset, location.Length, location.BlobID == contract.Hash(secondIntentForName(name)))
	}
	oldBlob := prior.content.locations[generatedContentKey{kind: contract.GeneratorContentIntent, id: current.Generated.IntentDigest}].BlobID
	newIntentID, err := contract.GeneratorIntentDigest(hermeticGeneratorIntent(secondIntentForName("alpha")))
	if err != nil {
		t.Fatal(err)
	}
	sharedOldBlob := prior.content.locations[generatedContentKey{kind: contract.GeneratorContentIntent, id: newIntentID}].BlobID
	if oldBlob.IsZero() {
		t.Fatal("selected predecessor lacks the current intent blob")
	}
	oldFragments := make([]format.FragmentLocation, 0)
	for _, fragment := range selected.root.Generated.Fragments {
		if fragment.BlobID == oldBlob {
			oldFragments = append(oldFragments, fragment)
		}
	}
	if len(oldFragments) == 0 {
		t.Fatal("selected predecessor lacks the current intent fragment directory")
	}
	admin, observed := openAdministrative(ctx, OpenContext{admission: &selected.admission}, env.Store)
	if admin == nil || observed.Outcome != ObservedCurrent {
		t.Fatal("signed administrative predecessor", observed)
	}
	var target contract.ID
	for _, group := range admin.adminIndex.Groups {
		work, scope, err := admin.administrativeWorkClosure(group.GroupID)
		if err != nil || len(scope) != 1 {
			t.Logf("skip group %x scope=%d err=%v", group.GroupID, len(scope), err)
			continue
		}
		work, err = admin.administrativeWorkWithoutOldReceipts(work)
		if err != nil {
			t.Logf("receipt group %x err=%v", group.GroupID, err)
			continue
		}
		plan, err := admin.planAdministrativeCurrentIntents(t.Context(), work)
		t.Logf("candidate group %x changed=%t drop-old=%t err=%v", group.GroupID, plan.changed, plan.dropBlobs[oldBlob], err)
		if err != nil || !plan.changed || !plan.dropBlobs[oldBlob] {
			continue
		}
		for _, fragment := range oldFragments {
			ref := generatedSelectedFragmentRef(t, selected, fragment)
			var physical uint16
			found := false
			for _, page := range admin.adminIndex.Pages {
				if page.Ref != ref {
					continue
				}
				logical := 0
				for _, span := range page.Spans {
					if int(fragment.RowSlot) >= logical && int(fragment.RowSlot) < logical+int(span.Count) {
						physical = span.First + uint16(int(fragment.RowSlot)-logical)
						found = true
						break
					}
					logical += int(span.Count)
				}
				break
			}
			if !found {
				t.Fatal("fragment logical slot has no authenticated physical ordinal")
			}
			for _, page := range work.Pages {
				if page.Ref != ref {
					continue
				}
				for _, span := range page.Spans {
					if physical >= span.First && physical < span.First+span.Count && len(span.GroupIndexes) != 0 {
						t.Logf("old fragment physical ordinal %d has surviving owners %v", physical, span.GroupIndexes)
						target = group.GroupID
					}
				}
			}
		}
		if !target.IsZero() {
			break
		}
	}
	if target.IsZero() {
		t.Fatal("signed predecessor lacks a surviving group on the current intent blob")
	}
	var other contract.ID
	for _, group := range admin.adminIndex.Groups {
		if group.GroupID != target && group.OwnerKind == format.AdministrativeGeneratedDuty &&
			group.DutyKind == contract.GeneratedDutyRetirement {
			other = group.GroupID
		}
	}
	if other.IsZero() || len(admin.adminIndex.Groups) != 2 || admin.root.Generated.Duties != 2 {
		t.Fatal("signed predecessor does not have exactly two independent retirement Duties")
	}
	sharedIntentOwners := func(s *StateSession) ([]contract.ID, bool) {
		t.Helper()
		var found int
		var owners []contract.ID
		var mandatory bool
		for i, page := range s.adminIndex.Pages {
			if !page.ReadRequired {
				continue
			}
			logical := 0
			for _, span := range page.Spans {
				for j := uint16(0); j < span.Count; j++ {
					if logical >= len(s.support[i].Records) {
						t.Fatal("shared Intent Slice span exceeds selected rows")
					}
					row := s.support[i].Records[logical]
					logical++
					if row.Kind != contract.GeneratorVectorSupportKind {
						continue
					}
					carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
					if err != nil || carrier.VectorKind != contract.GeneratorVectorSlices {
						t.Fatal("shared Intent Slice carrier", err)
					}
					location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
					if err != nil {
						t.Fatal("shared Intent Slice location", err)
					}
					if location.ContentKind != contract.GeneratorContentIntent || location.ContentID != current.Generated.IntentDigest {
						continue
					}
					found++
					mandatory = span.Mandatory
					for _, group := range span.GroupIndexes {
						owners = append(owners, s.adminIndex.Groups[group].GroupID)
					}
				}
			}
		}
		if found != 1 {
			t.Fatal("shared Intent has no unique selected Slice", found)
		}
		slices.SortFunc(owners, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		return owners, mandatory
	}
	wantBoth := []contract.ID{target, other}
	slices.SortFunc(wantBoth, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	if owners, mandatory := sharedIntentOwners(admin); !mandatory || !slices.Equal(owners, wantBoth) {
		t.Fatal("same-digest original attempts did not both own their shared Intent", owners, mandatory)
	}
	for _, order := range [][2]contract.ID{{target, other}, {other, target}} {
		store := selectedMemoryStoreCopy(env.Store.(*memoryStore))
		for step, groupID := range order {
			before, observed := openAdministrative(ctx, OpenContext{admission: &selected.admission}, store)
			if before == nil || observed.Outcome != ObservedCurrent {
				t.Fatal("independent signed predecessor did not reopen", step, observed)
			}
			beforeGroups := make(map[contract.ID]bool, len(before.adminIndex.Groups))
			for _, group := range before.adminIndex.Groups {
				beforeGroups[group.GroupID] = true
			}
			candidate, result := prepareTestEndSelectedWork(t, before, ctx, groupID, env.Trust)
			if candidate == nil || result.Outcome != ObservedCurrent {
				t.Fatal("shared-current-intent EndWork preparation refused", step, result)
			}
			if next, outcome := before.selectCandidate(ctx, candidate); next == nil || outcome.Outcome != ObservedCurrent {
				t.Fatal("shared-current-intent EndWork selection refused", step, outcome)
			}
			ordinary, reopened := Open(ctx, OpenContext{admission: &selected.admission}, store)
			if ordinary == nil || reopened.Outcome != ObservedCurrent || ordinary.head.EndWork == nil ||
				ordinary.head.EndWork.TargetGroupID != groupID || ordinary.root.Generated.GeneratedCurrent != 2 ||
				ordinary.root.Generated.Duties != uint32(1-step) ||
				len(ordinary.adminIndex.Groups) != len(beforeGroups)-1 {
				t.Fatal("shared-current-intent successor did not cold-open complete retained state", step, reopened)
			}
			for _, group := range ordinary.adminIndex.Groups {
				if !beforeGroups[group.GroupID] || group.GroupID == groupID {
					t.Fatal("exit changed an unrelated owner", step, group.GroupID)
				}
				delete(beforeGroups, group.GroupID)
			}
			if len(beforeGroups) != 1 || !beforeGroups[groupID] {
				t.Fatal("exit removed the wrong owner", step)
			}
			owners, mandatory := sharedIntentOwners(ordinary)
			wantOwners := []contract.ID(nil)
			if step == 0 {
				wantOwners = []contract.ID{order[1]}
			}
			if !mandatory || !slices.Equal(owners, wantOwners) {
				t.Fatal("exit changed a surviving same-digest Intent owner", step, owners, mandatory)
			}
			for _, named := range before.root.Names {
				priorCore, priorPayload, priorAccess, priorOK := before.selectedValue(named.Slot)
				nextCore, nextPayload, nextAccess, nextOK := ordinary.selectedValue(named.Slot)
				if !priorOK || !nextOK || !reflect.DeepEqual(priorCore, nextCore) ||
					!reflect.DeepEqual(priorPayload, nextPayload) ||
					priorAccess.MaterialKind != nextAccess.MaterialKind || priorAccess.MaterialID != nextAccess.MaterialID ||
					priorAccess.MaterialContextDigest != nextAccess.MaterialContextDigest ||
					priorAccess.PackageCheck != nextAccess.PackageCheck {
					t.Fatal("exit changed authenticated current material or access", step, named.Name)
				}
			}
			for _, fragment := range ordinary.root.Generated.Fragments {
				if fragment.BlobID != sharedOldBlob {
					continue
				}
				ref := generatedSelectedFragmentRef(t, ordinary, fragment)
				position := slices.IndexFunc(ordinary.adminIndex.Pages, func(page format.AdministrativePage) bool { return page.Ref == ref })
				if position < 0 {
					t.Fatal("surviving old fragment lacks an index page", step)
				}
				physical, ok := administrativePhysicalRowSlot(ordinary.adminIndex.Pages[position], fragment.RowSlot)
				if !ok {
					t.Fatal("surviving old fragment lacks a physical ordinal", step)
				}
				for _, span := range ordinary.adminIndex.Pages[position].Spans {
					if physical >= span.First && physical < span.First+span.Count && span.Mandatory {
						t.Fatal("relocated current intent left its old shared blob mandatory", step)
					}
				}
			}
		}
	}
}

// full_only: false
func TestEndWorkDemotesSharedOldIntentBlobAfterCurrentRelocation(t *testing.T) {
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	fixture := newEnvironmentFixture(t, ctx, env, nil, false)
	names := []string{"alpha", "omega"}
	profile := defaultGeneratedFixtureProfile()
	firstIntent := func(name string) []byte {
		if name == "alpha" {
			return hermeticGeneratorIntent([]byte(`{"name":"old-alpha"}`))
		}
		return hermeticGeneratorIntent([]byte(`{"name":"old-omega"}`))
	}
	secondIntent := func(name string) []byte {
		if name == "alpha" {
			return hermeticGeneratorIntent([]byte(`{"name":"new-alpha"}`))
		}
		return firstIntent(name)
	}
	firstOperation := generatedVectorID(241)
	first := generatedReservationInputForMembershipStateIntents(t, fixture.session, firstOperation,
		[]contract.ID{fixture.session.admission.recipient}, names, firstIntent, profile, 0, nil, nil)
	firstInput := generatedStatePlanInput(t, fixture.session, firstOperation, names, profile, 0, nil, nil)
	firstInput.graph, firstInput.declaration, firstInput.registry, firstInput.recoveryPolicy, firstInput.requestBindings = first.graph,
		first.declaration, first.graph.Request.Registry, first.graph.Request.RecoveryPolicyID, slices.Clone(first.requestBindings)
	selected := selectTwoNameCurrentGeneration(t, ctx, env, fixture.session, firstInput, "distinct first intents")
	old := make(map[string]contract.ValueEntry, 2)
	incarnations := make(map[string]contract.ID, 2)
	for _, named := range selected.root.Names {
		old[named.Name] = *selected.valueEntry(named.Slot)
		incarnations[named.Name] = old[named.Name].Incarnation
	}
	firstWork, err := selected.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal("first signed generated selection", err)
	}
	oldAlpha, err := contract.GeneratorIntentDigest(hermeticGeneratorIntent(firstIntent("alpha")))
	if err != nil {
		t.Fatal(err)
	}
	oldOmega, err := contract.GeneratorIntentDigest(hermeticGeneratorIntent(firstIntent("omega")))
	if err != nil {
		t.Fatal(err)
	}
	sharedBlob := firstWork.content.locations[generatedContentKey{kind: contract.GeneratorContentIntent, id: oldAlpha}].BlobID
	if sharedBlob.IsZero() || firstWork.content.locations[generatedContentKey{kind: contract.GeneratorContentIntent, id: oldOmega}].BlobID != sharedBlob {
		t.Fatal("first signed generation did not share its declaration blob")
	}
	secondOperation := generatedVectorID(242)
	second := generatedReservationInputForMembershipStateIntents(t, selected, secondOperation,
		[]contract.ID{selected.admission.recipient}, names, secondIntent, profile,
		old["alpha"].Generated.Epoch+1, incarnations, old)
	secondInput := generatedStatePlanInput(t, selected, secondOperation, names, profile,
		old["alpha"].Generated.Epoch+1, incarnations, old)
	secondInput.graph, secondInput.declaration, secondInput.registry, secondInput.recoveryPolicy, secondInput.requestBindings = second.graph,
		second.declaration, second.graph.Request.Registry, second.graph.Request.RecoveryPolicyID, slices.Clone(second.requestBindings)
	selected = selectTwoNameCurrentGeneration(t, ctx, env, selected, secondInput, "one changed and one retained intent")
	prior, err := selected.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal("second signed generated selection", err)
	}
	newAlpha, err := contract.GeneratorIntentDigest(hermeticGeneratorIntent(secondIntent("alpha")))
	if err != nil {
		t.Fatal(err)
	}
	newBlob := prior.content.locations[generatedContentKey{kind: contract.GeneratorContentIntent, id: newAlpha}].BlobID
	retainedBlob := prior.content.locations[generatedContentKey{kind: contract.GeneratorContentIntent, id: oldAlpha}].BlobID
	if newBlob == retainedBlob || retainedBlob.IsZero() ||
		prior.content.locations[generatedContentKey{kind: contract.GeneratorContentIntent, id: oldOmega}].BlobID != retainedBlob {
		t.Fatal("signed predecessor lacks current and retained intents in one old blob")
	}
	sharedBlob = retainedBlob
	admin, observed := openAdministrative(ctx, OpenContext{admission: &selected.admission}, env.Store)
	if admin == nil || observed.Outcome != ObservedCurrent {
		t.Fatal("administrative signed predecessor", observed)
	}
	var target contract.ID
	for _, named := range admin.root.Names {
		if named.Name == "omega" {
			entry := admin.valueEntry(named.Slot)
			if entry != nil && entry.Generated.RetiringDutyPresent == 1 {
				target = entry.Generated.RetiringDutyID
			}
		}
	}
	if target.IsZero() {
		t.Fatal("second signed generation lacks omega retirement Duty")
	}
	work, scope, err := admin.administrativeWorkClosure(target)
	if err != nil || len(scope) != 1 {
		t.Fatal("omega Duty has no independent closure", err, len(scope))
	}
	work, err = admin.administrativeWorkWithoutOldReceipts(work)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := admin.planAdministrativeCurrentIntents(t.Context(), work)
	if err != nil || !plan.changed || !plan.dropBlobs[newBlob] || plan.dropBlobs[sharedBlob] {
		t.Fatal("exit has no mixed retained-old-blob projection", err, plan.changed, plan.dropBlobs)
	}
	candidate, prepared := prepareTestEndSelectedWork(t, admin, ctx, target, env.Trust)
	if candidate == nil || prepared.Outcome != ObservedCurrent {
		t.Fatal("shared old-blob exit refused", prepared)
	}
	if next, outcome := admin.selectCandidate(ctx, candidate); next == nil || outcome.Outcome != ObservedCurrent {
		t.Fatal("shared old-blob exit did not select", outcome)
	}
	ordinary, reopened := Open(ctx, OpenContext{admission: &selected.admission}, env.Store)
	if ordinary == nil || reopened.Outcome != ObservedCurrent {
		t.Fatal("shared old-blob successor did not cold-open", reopened)
	}
	if len(ordinary.adminIndex.Groups) != 1 || ordinary.adminIndex.Groups[0].GroupID == target {
		t.Fatal("first exit did not preserve exactly the other Duty")
	}
	remaining := ordinary.adminIndex.Groups[0].GroupID
	var found bool
	for _, fragment := range ordinary.root.Generated.Fragments {
		if fragment.BlobID != sharedBlob {
			continue
		}
		found = true
		ref := generatedSelectedFragmentRef(t, ordinary, fragment)
		position := slices.IndexFunc(ordinary.adminIndex.Pages, func(page format.AdministrativePage) bool { return page.Ref == ref })
		if position < 0 {
			t.Fatal("retained old blob has no index page")
		}
		physical, ok := administrativePhysicalRowSlot(ordinary.adminIndex.Pages[position], fragment.RowSlot)
		if !ok {
			t.Fatal("retained old blob has no physical ordinal")
		}
		for _, span := range ordinary.adminIndex.Pages[position].Spans {
			if physical >= span.First && physical < span.First+span.Count {
				if span.Mandatory || len(span.GroupIndexes) != 1 ||
					ordinary.adminIndex.Groups[span.GroupIndexes[0]].GroupID != remaining {
					t.Fatal("non-current old blob retained mandatory or unrelated ownership")
				}
			}
		}
	}
	if !found {
		t.Fatal("shared old blob was lost while its retained intent survived")
	}
	secondAdmin, observed := openAdministrative(ctx, OpenContext{admission: &selected.admission}, env.Store)
	if secondAdmin == nil || observed.Outcome != ObservedCurrent {
		t.Fatal("remaining Duty did not reopen administratively", observed)
	}
	secondCandidate, prepared := prepareTestEndSelectedWork(t, secondAdmin, ctx, remaining, env.Trust)
	if secondCandidate == nil || prepared.Outcome != ObservedCurrent {
		t.Fatal("remaining Duty could not end", prepared)
	}
	if next, outcome := secondAdmin.selectCandidate(ctx, secondCandidate); next == nil || outcome.Outcome != ObservedCurrent {
		t.Fatal("remaining Duty did not select", outcome)
	}
	complete, reopened := Open(ctx, OpenContext{admission: &selected.admission}, env.Store)
	if complete == nil || reopened.Outcome != ObservedCurrent || len(complete.adminIndex.Groups) != 0 {
		t.Fatal("second exit did not cold-open complete work-free state", reopened)
	}
	for _, fragment := range complete.root.Generated.Fragments {
		if fragment.BlobID == sharedBlob {
			t.Fatal("last consumer ended but the old blob remained selected")
		}
	}
	currentValues := make(map[string]contract.ValueEntry, 2)
	currentIncarnations := make(map[string]contract.ID, 2)
	for _, named := range complete.root.Names {
		priorCore, priorPayload, priorAccess, priorOK := admin.selectedValue(named.Slot)
		nextCore, nextPayload, nextAccess, nextOK := complete.selectedValue(named.Slot)
		if !priorOK || !nextOK || !reflect.DeepEqual(priorCore, nextCore) ||
			!reflect.DeepEqual(priorPayload, nextPayload) ||
			priorAccess.MaterialKind != nextAccess.MaterialKind || priorAccess.MaterialID != nextAccess.MaterialID ||
			priorAccess.MaterialContextDigest != nextAccess.MaterialContextDigest || priorAccess.PackageCheck != nextAccess.PackageCheck {
			t.Fatal("two exits changed authenticated current material or access", named.Name)
		}
		entry := complete.valueEntry(named.Slot)
		if entry == nil || entry.Generated.RetiringDutyPresent != 0 {
			t.Fatal("two exits left a current retirement pointer", named.Name)
		}
		currentValues[named.Name], currentIncarnations[named.Name] = *entry, entry.Incarnation
	}
	thirdOperation := generatedVectorID(243)
	third := generatedStatePlanInput(t, complete, thirdOperation, names, profile,
		currentValues["alpha"].Generated.Epoch+1, currentIncarnations, currentValues)
	continued := selectTwoNameCurrentGeneration(t, ctx, env, complete, third, "ordinary work after both shared-blob exits")
	if continued.root.Generated.GeneratedCurrent != 2 {
		t.Fatal("ordinary successor lost the two current generated values")
	}
}

// full_only: false
func TestEndWorkKeepsUnchangedSelectedSlicesThroughLaterReceipt(t *testing.T) {
	ctx := context.Background()
	env, selected, _, _ := generatedAuthenticatedDeleteHazardFixture(t, false, 0)
	selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
	prior := *selected.valueEntry(0)
	input := generatedStatePlanInput(t, selected, generatedVectorID(236), []string{prior.Name},
		defaultGeneratedFixtureProfile(), prior.Generated.Epoch+1,
		map[string]contract.ID{prior.Name: prior.Incarnation}, map[string]contract.ValueEntry{prior.Name: prior})
	selected = selectPrivateGeneratedOperation(t, env, selected, input, "independent work beside current Slice")
	selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
	before, result := openAdministrative(ctx, OpenContext{admission: &selected.admission}, env.Store)
	if before == nil || result.Outcome != ObservedCurrent || before.root.Generated.Slices.Count == 0 || len(before.adminIndex.Groups) < 2 {
		t.Fatal("signed predecessor has no nonempty Slice and independent selected work", result)
	}
	var target contract.ID
	for _, group := range before.adminIndex.Groups {
		work, scope, err := before.administrativeWorkClosure(group.GroupID)
		if err != nil || len(scope) != 1 || len(work.Groups) == 0 {
			continue
		}
		projected, _, err := before.administrativeGeneratedProjection(work)
		if err == nil && projected.Slices == before.root.Generated.Slices {
			target = group.GroupID
			break
		}
	}
	if target.IsZero() {
		t.Fatal("signed two-owner predecessor has no independent unchanged-Slice exit")
	}
	var exactRefs []format.Ref
	for _, page := range before.adminIndex.Pages {
		if page.ReadRequired {
			exactRefs = append(exactRefs, page.Ref)
		}
	}
	if len(exactRefs) == 0 {
		t.Fatal("nonempty Slice descriptor has no selected carrier page")
	}
	store := env.Store.(*memoryStore)
	beforeCAS := store.cas
	public, private := env.Custody.Calls()
	candidate, prepared := prepareTestEndSelectedWork(t, before, ctx, target, env.Trust)
	if candidate == nil || prepared.Outcome != ObservedCurrent || store.cas != beforeCAS {
		t.Fatal("unchanged-Slice exit did not prepare before selection", prepared)
	}
	if _, selectedResult := before.selectCandidate(ctx, candidate); selectedResult.Outcome != ObservedCurrent || store.cas != beforeCAS+1 {
		t.Fatal("unchanged-Slice exit did not select through one Store CAS", selectedResult)
	}
	ordinary, ordinaryResult := Open(ctx, OpenContext{admission: &before.admission}, store)
	admin, adminResult := openAdministrative(ctx, OpenContext{admission: &before.admission}, store)
	if ordinary == nil || admin == nil || ordinaryResult.Outcome != ObservedCurrent || adminResult.Outcome != ObservedCurrent ||
		ordinary.head.EndWork == nil || ordinary.head.EndWork.TargetGroupID != target ||
		ordinary.root.Snapshot == before.root.Snapshot || ordinary.root.Generated.Slices != before.root.Generated.Slices ||
		ordinary.adminIndex.SliceSnapshot != before.adminIndex.SliceSnapshot ||
		admin.adminIndex.SliceSnapshot != before.adminIndex.SliceSnapshot ||
		len(ordinary.adminIndex.Groups) != len(before.adminIndex.Groups)-1 {
		t.Fatal("selected unchanged-Slice successor did not cold-open through both readers", ordinaryResult, adminResult)
	}
	for _, ref := range exactRefs {
		if !slices.Contains(ordinary.root.RequiredSupport, ref) || !slices.Contains(admin.root.RequiredSupport, ref) {
			t.Fatal("selected exit rewrote an unchanged Slice page", ref.Index)
		}
	}
	if p, k := env.Custody.Calls(); p != public || k != private {
		t.Fatal("unchanged-Slice exit used effect or decryption custody", p-public, k-private)
	}
	firstOperation := ordinary.head.EndWork.OperationID
	if len(admin.adminIndex.Groups) == 0 {
		t.Fatal("unchanged-Slice exit consumed independent selected work")
	}
	second := admin.adminIndex.Groups[0].GroupID
	nextCandidate, nextPrepared := prepareTestEndSelectedWork(t, admin, ctx, second, env.Trust)
	if nextCandidate == nil || nextPrepared.Outcome != ObservedCurrent {
		t.Fatal("later receipt-writing exit did not prepare from old Slice anchor", nextPrepared)
	}
	if _, nextSelected := admin.selectCandidate(ctx, nextCandidate); nextSelected.Outcome != ObservedCurrent || store.cas != beforeCAS+2 {
		t.Fatal("later receipt-writing exit did not select", nextSelected)
	}
	later, laterResult := Open(ctx, OpenContext{admission: &before.admission}, store)
	if later == nil || laterResult.Outcome != ObservedCurrent || later.head.EndWork == nil || later.head.EndWork.TargetGroupID != second {
		t.Fatal("later receipt-writing successor did not cold-open", laterResult)
	}
	body, receiptResult := later.MutationReceipt(ctx, firstOperation)
	receipt, err := contract.InspectCompactMutationReceipt(body)
	if receiptResult.Outcome != ObservedCurrent || err != nil || receipt.OperationID != firstOperation {
		t.Fatal("later exit lost the prior selected administrative receipt", receiptResult, err)
	}
}

// full_only: false
func TestAdministrativeReceiptRefreshKeepsPartialReadMode(t *testing.T) {
	ctx := context.Background()
	env, selected, _, _ := generatedAuthenticatedDeleteHazardFixture(t, false, 0)
	selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
	prior := *selected.valueEntry(0)
	input := generatedStatePlanInput(t, selected, generatedVectorID(202), []string{prior.Name},
		defaultGeneratedFixtureProfile(), prior.Generated.Epoch+1,
		map[string]contract.ID{prior.Name: prior.Incarnation}, map[string]contract.ValueEntry{prior.Name: prior})
	selected = selectPrivateGeneratedOperation(t, env, selected, input, "second selected owner before end")
	selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
	store := env.Store.(*memoryStore)
	initial, observed := openAdministrative(ctx, OpenContext{admission: &selected.admission}, store)
	if initial == nil || observed.Outcome != ObservedCurrent || len(initial.adminIndex.Groups) < 2 {
		t.Fatal("real continuation did not select distinct administrative owners", observed)
	}
	var target contract.ID
	var missing format.Ref
	for _, group := range initial.adminIndex.Groups {
		retained, scope, err := initial.administrativeWorkClosure(group.GroupID)
		if err != nil || len(scope) != 1 || len(retained.Groups) == 0 {
			continue
		}
		for _, page := range retained.Pages {
			if page.ReadRequired || slices.ContainsFunc(page.Spans, func(span format.AdministrativeSpan) bool { return span.Mandatory }) {
				continue
			}
			target, missing = group.GroupID, page.Ref
			break
		}
		if !target.IsZero() {
			break
		}
	}
	if target.IsZero() {
		t.Fatal("real two-owner continuation has no independent exit with unreadable retained work")
	}
	key, err := format.Key(initial.admission.store.Prefix, missing)
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	old, present := store.objects[key]
	delete(store.objects, key)
	store.mu.Unlock()
	if !present || len(old.Body) == 0 {
		t.Fatal("selected optional page was absent before simulated loss")
	}
	defer func() {
		store.mu.Lock()
		store.objects[key] = old
		store.mu.Unlock()
	}()
	stale, observed := openAdministrative(ctx, OpenContext{admission: &selected.admission}, store)
	if stale == nil || observed.Outcome != ObservedCurrent {
		t.Fatal("administrative session needed unrelated optional bytes", observed)
	}
	if normal, result := Open(ctx, OpenContext{admission: &selected.admission}, store); normal != nil || result.Outcome != EvidenceUnavailable {
		t.Fatal("ordinary reader accepted missing selected work", result)
	}
	actor, observed := openAdministrative(ctx, OpenContext{admission: &selected.admission}, store)
	if actor == nil || observed.Outcome != ObservedCurrent {
		t.Fatal("second administrative actor did not open", observed)
	}
	candidate, prepared := prepareTestEndSelectedWork(t, actor, ctx, target, env.Trust)
	if candidate == nil || prepared.Outcome != ObservedCurrent {
		t.Fatal("independent selected exit did not prepare", prepared)
	}
	current, outcome := actor.selectCandidate(ctx, candidate)
	if current == nil || outcome.Outcome != ObservedCurrent || current.head.EndWork == nil {
		t.Fatal("independent selected exit did not select", outcome)
	}
	if !slices.ContainsFunc(current.adminIndex.Pages, func(page format.AdministrativePage) bool { return page.Ref == missing }) {
		t.Fatal("exit removed unreadable work owned by the surviving group")
	}
	if normal, result := Open(ctx, OpenContext{admission: &selected.admission}, store); normal != nil || result.Outcome != EvidenceUnavailable {
		t.Fatal("ordinary successor accepted missing selected work", result)
	}
	creates, cas := store.creates, store.cas
	public, private := env.Custody.Calls()
	operation := current.head.EndWork.OperationID
	body, result := stale.MutationReceipt(ctx, operation)
	receipt, err := contract.InspectCompactMutationReceipt(body)
	if result.Outcome != ObservedCurrent || err != nil || receipt.OperationID != operation ||
		receipt.AdministrativeOriginalEvidence != current.head.EndWork.SelectedEvidenceSummary {
		t.Fatal("stale administrative session lost the new authenticated receipt", result, err)
	}
	fresh, observed := openAdministrative(ctx, OpenContext{admission: &selected.admission}, store)
	if fresh == nil || observed.Outcome != ObservedCurrent {
		t.Fatal("fresh public context could not open selected mandatory state", observed)
	}
	if again, result := fresh.MutationReceipt(ctx, operation); result.Outcome != ObservedCurrent || !bytes.Equal(again, body) {
		t.Fatal("fresh public context lost the exact retained receipt", result)
	}

	if store.creates != creates || store.cas != cas {
		t.Fatal("receipt refresh wrote Store objects")
	}
	if p, k := env.Custody.Calls(); p != public || k != private {
		t.Fatal("receipt refresh used effect or decryption custody", p-public, k-private)
	}
	var mandatory format.Ref
	for _, page := range current.adminIndex.Pages {
		if slices.ContainsFunc(page.Rows, func(row format.AdministrativeRowSummary) bool {
			return row.Kind == contract.MutationReceiptSupportKind && row.RecordID == operation
		}) {
			mandatory = page.Ref
			break
		}
	}
	if mandatory.Object.IsZero() {
		t.Fatal("selected administrative receipt has no mandatory page")
	}
	mandatoryKey, err := format.Key(current.admission.store.Prefix, mandatory)
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	mandatoryObject, present := store.objects[mandatoryKey]
	delete(store.objects, mandatoryKey)
	store.mu.Unlock()
	if !present || len(mandatoryObject.Body) == 0 {
		t.Fatal("mandatory receipt page was absent before simulated damage")
	}
	defer func() {
		store.mu.Lock()
		store.objects[mandatoryKey] = mandatoryObject
		store.mu.Unlock()
	}()
	if body, result := stale.MutationReceipt(ctx, operation); body != nil || result.Outcome != EvidenceUnavailable ||
		result.Reason != MissingSelectedObject {
		t.Fatal("administrative receipt accepted missing mandatory bytes", result)
	}
	store.mu.Lock()
	store.objects[mandatoryKey] = mandatoryObject
	store.mu.Unlock()
	if restored, result := stale.MutationReceipt(ctx, operation); result.Outcome != ObservedCurrent || !bytes.Equal(restored, body) {
		t.Fatal("exact mandatory repair did not restore the receipt", result)
	}
}

// full_only: false
func TestEndWorkReceiptReplacementKeepsMixedMandatoryPage(t *testing.T) {
	ctx := context.Background()
	env, selected, _, _ := generatedAuthenticatedDeleteHazardFixture(t, true, 0)
	selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
	prior := *selected.valueEntry(0)
	input := generatedStatePlanInput(t, selected, generatedVectorID(203), []string{prior.Name},
		defaultGeneratedFixtureProfile(), prior.Generated.Epoch+1,
		map[string]contract.ID{prior.Name: prior.Incarnation}, map[string]contract.ValueEntry{prior.Name: prior})
	selected = selectPrivateGeneratedOperation(t, env, selected, input, "second selected owner for mixed receipt page")
	selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
	first, result := openAdministrative(ctx, OpenContext{admission: &selected.admission}, env.Store)
	if first == nil || result.Outcome != ObservedCurrent || len(first.adminIndex.Groups) < 2 {
		t.Fatal("mixed-page fixture has no two selected owners", result)
	}
	var firstGroup contract.ID
	for _, group := range first.adminIndex.Groups {
		remaining, scope, err := first.administrativeWorkClosure(group.GroupID)
		if err == nil && len(scope) == 1 && len(remaining.Groups) != 0 {
			firstGroup = group.GroupID
			break
		}
	}
	if firstGroup.IsZero() {
		t.Fatal("mixed-page fixture has no independent first selected owner")
	}
	firstCandidate, result := prepareTestEndSelectedWork(t, first, ctx, firstGroup, env.Trust)
	if firstCandidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("mixed-page first exit did not prepare", result)
	}
	selected, result = first.selectCandidate(ctx, firstCandidate)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("mixed-page first exit did not select", result)
	}
	selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
	if selected.head.AuthKind != format.AdministrativeAuth || selected.head.EndWork == nil {
		t.Fatal("real selected predecessor has no administrative proof")
	}
	evidence, receipts := -1, -1
	for i, page := range selected.adminIndex.Pages {
		if len(page.Rows) == 1 && page.Rows[0].Kind == contract.GeneratedCreateEvidenceSupportKind &&
			len(page.Spans) == 1 && page.Spans[0].Mandatory {
			evidence = i
		}
		if len(page.Rows) >= 2 && page.Rows[0].Kind == contract.MutationReceiptSupportKind &&
			len(page.Spans) == 1 && page.Spans[0].Mandatory {
			receipts = i
		}
	}
	if evidence < 0 || receipts < 0 || len(selected.support[evidence].Records) != 1 || len(selected.support[receipts].Records) < 2 {
		t.Fatal("real selected image has no current generated evidence and prior receipt pages")
	}
	previous := contract.SupportRecord(selected.support[evidence].Records[0])
	oldReceipt := contract.SupportRecord(selected.support[receipts].Records[0])
	newRows := map[int][]contract.SupportRecord{
		evidence: {oldReceipt, previous},
		receipts: nil,
	}
	for _, record := range selected.support[receipts].Records[1:] {
		newRows[receipts] = append(newRows[receipts], contract.SupportRecord(record))
	}
	root := selected.root
	root.Snapshot = contract.Hash([]byte("signed v6 mixed receipt snapshot"))
	root.Transition = contract.Hash([]byte("signed v6 mixed receipt transition"))
	index := selected.adminIndex
	index.Object = administrativeIndexObject(root.Domain, root.Snapshot)
	index.Pages = slices.Clone(index.Pages)
	store := selectedMemoryStoreCopy(env.Store.(*memoryStore))
	put := func(ref format.Ref, body []byte) {
		t.Helper()
		key, err := format.Key(selected.admission.store.Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		store.mu.Lock()
		store.put(key, body)
		store.mu.Unlock()
	}
	for _, position := range []int{evidence, receipts} {
		page := format.RequiredSupportPage{Domain: root.Domain, Index: uint16(position),
			Object: contract.Hash([]byte{byte(position), 0x91, 0x71}), Records: newRows[position]}
		body, err := format.EncodeRequiredSupportPage(page)
		if err != nil {
			t.Fatal("valid nonfragment mandatory rows did not share one page", err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal(err)
		}
		root.RequiredSupport = slices.Clone(root.RequiredSupport)
		root.RequiredSupport[position] = ref
		index.Pages[position].Ref = ref
		index.Pages[position].Spans = []format.AdministrativeSpan{{First: 0, Count: uint16(len(page.Records)), Mandatory: true}}
		index.Pages[position].Rows = nil
		for _, record := range page.Records {
			index.Pages[position].Rows = append(index.Pages[position].Rows, format.AdministrativeRowSummary{
				Kind: record.Kind, RecordID: record.RecordID, BodyLength: uint32(len(record.Body))})
		}
		put(ref, body)
	}
	if !index.Valid() {
		t.Fatal("mixed selected administrative index is invalid")
	}
	indexPages, err := format.EncodeAdministrativeIndexPages(index)
	if err != nil || len(indexPages) != 1 {
		t.Fatal("mixed selected index was not encoded", err)
	}
	root.AdministrativeIndex, root.AdministrativeIndexShards = indexPages[0].Ref, nil
	put(indexPages[0].Ref, indexPages[0].Body)
	counted := StateSession{root: root}
	counted.recountChildren()
	root = counted.root
	if root.ChildCount != selected.root.ChildCount || root.ChildEncodedBytes != selected.root.ChildEncodedBytes {
		t.Fatal("mixed mandatory rows changed the selected physical charge")
	}
	rootBody, err := format.EncodeRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	rootRef, err := format.Reference(format.RootKind, root.Domain, root.Snapshot, 0, rootBody)
	if err != nil {
		t.Fatal(err)
	}
	put(rootRef, rootBody)
	head := selected.head
	head.Core.Root = rootRef
	coreBody, err := format.EncodeHeadCore(head.Core)
	if err != nil {
		t.Fatal(err)
	}
	conditionalBody, err := format.EncodeConditionalPlan(conditional(head.Core, coreBody))
	if err != nil {
		t.Fatal(err)
	}
	subject := *head.EndWork
	subject.HeadCoreDigest, subject.HeadCoreLength = contract.Hash(coreBody), uint32(len(coreBody))
	subject.ConditionalPlanDigest = contract.Hash(conditionalBody)
	head.EndWork = &subject
	request, err := contract.NewEndWorkRequest(subject)
	if err != nil {
		t.Fatal(err)
	}
	proof := env.Trust.Sign(ctx, request)
	if proof.Reason != contract.ReasonNone {
		t.Fatal("normal trust refused the mixed selected image", proof.Reason)
	}
	head.AuthorizationSignature = proof.Signature
	headBody, err := format.EncodeHead(head)
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.put(selected.admission.store.HeadKey, headBody)
	store.mu.Unlock()
	admin, result := openAdministrative(ctx, OpenContext{admission: &selected.admission}, store)
	if admin == nil || result.Outcome != ObservedCurrent || len(admin.adminIndex.Groups) == 0 {
		t.Fatal("signed mixed selected predecessor did not open administratively", result)
	}
	opened, result := Open(ctx, OpenContext{admission: &selected.admission}, store)
	if opened == nil || result.Outcome != ObservedCurrent {
		t.Fatal("signed mixed selected predecessor did not cold-open completely", result)
	}
	retained, err := admin.administrativeWorkWithoutOldReceipts(admin.adminIndex)
	if err != nil {
		t.Fatal("old receipt replacement refused a signed mixed mandatory page", err)
	}
	page := retained.Pages[evidence]
	if page.Ref != root.RequiredSupport[evidence] || len(page.Spans) != 1 || page.Spans[0].First != 1 ||
		page.Spans[0].Count != 1 || len(page.Rows) != 1 || page.Rows[0].Kind != contract.GeneratedCreateEvidenceSupportKind ||
		page.Rows[0].RecordID != previous.RecordID {
		t.Fatal("mixed page lost the exact surviving physical evidence ordinal")
	}
	secondGroup := admin.adminIndex.Groups[0].GroupID
	secondCandidate, prepared := prepareTestEndSelectedWork(t, admin, ctx, secondGroup, env.Trust)
	if secondCandidate == nil || prepared.Outcome != ObservedCurrent {
		t.Fatal("mixed selected predecessor did not prepare its remaining exit", prepared)
	}
	second, outcome := admin.selectCandidate(ctx, secondCandidate)
	if second == nil || outcome.Outcome != ObservedCurrent {
		t.Fatal("mixed selected predecessor did not select its remaining exit", outcome)
	}
	reopened, observed := Open(ctx, OpenContext{admission: &selected.admission}, store)
	if reopened == nil || observed.Outcome != ObservedCurrent || len(reopened.adminIndex.Groups) != 0 ||
		reopened.root.RequiredSupport[evidence] != root.RequiredSupport[evidence] ||
		len(reopened.adminIndex.Pages[evidence].Spans) != 1 ||
		reopened.adminIndex.Pages[evidence].Spans[0].First != 1 {
		t.Fatal("second real exit lost the unchanged physical evidence ordinal", observed)
	}
	for _, operation := range []contract.ID{selected.head.EndWork.OperationID, reopened.head.EndWork.OperationID} {
		body, receiptResult := reopened.MutationReceipt(ctx, operation)
		receipt, err := contract.InspectCompactMutationReceipt(body)
		if receiptResult.Outcome != ObservedCurrent || err != nil || receipt.OperationID != operation {
			t.Fatal("mixed-page second exit lost an authenticated administrative receipt", receiptResult, err)
		}
	}
	env.Store = store
	env = syntheticAuthorityScenarioEnvironment(t, env)
	actors := env.ReplacementActors(t, ctx, reopened, 3, 4, 2)
	permit := admitAuthorityReplacement(t, reopened, actors.Keys, actors.After, 3, 2, 4, actors.Source)
	successor, result := reopened.PrepareSuccession(ctx, permit, actors.Signers)
	if successor == nil || result.Outcome != ObservedCurrent {
		t.Fatal("sparse predecessor did not prepare a receipt-writing signer-only successor", result)
	}
	admission := deliverSuccessionBasis(t, successor)
	if result := reopened.Select(ctx, successor); result.Outcome != ObservedCurrent {
		t.Fatal("sparse predecessor did not select its signer-only successor", result)
	}
	selectedAfter, result := Open(ctx, admission, store)
	if selectedAfter == nil || result.Outcome != ObservedCurrent {
		t.Fatal("receipt-writing signer-only successor did not cold-open", result)
	}
	if selectedAfter.head.Succession == nil {
		t.Fatal("successor omitted its signed succession proof")
	}
	newOperation := selectedAfter.head.Succession.Subject.OperationID
	newReceipt, receiptResult := selectedAfter.MutationReceipt(ctx, newOperation)
	decoded, err := contract.InspectCompactMutationReceipt(newReceipt)
	if receiptResult.Outcome != ObservedCurrent || err != nil || decoded.OperationID != newOperation {
		t.Fatal("signer-only successor did not retain its new authenticated receipt", receiptResult, err)
	}
	if selectedAfter.root.RequiredSupport[evidence] != root.RequiredSupport[evidence] ||
		len(selectedAfter.adminIndex.Pages[evidence].Spans) != 1 || selectedAfter.adminIndex.Pages[evidence].Spans[0].First != 1 {
		t.Fatal("receipt-writing successor changed the surviving physical ordinal")
	}
}

// full_only: false
func TestSparseOptionalOwnerRebuildChargesSelectedLogicalRows(t *testing.T) {
	ctx := context.Background()
	env, selected, _, _ := generatedAuthenticatedDeleteHazardFixture(t, true, 0)
	selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
	prior := *selected.valueEntry(0)
	input := generatedStatePlanInput(t, selected, generatedVectorID(204), []string{prior.Name},
		defaultGeneratedFixtureProfile(), prior.Generated.Epoch+1,
		map[string]contract.ID{prior.Name: prior.Incarnation}, map[string]contract.ValueEntry{prior.Name: prior})
	selected = selectPrivateGeneratedOperation(t, env, selected, input, "second selected owner for sparse optional page")
	selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
	admin, result := openAdministrative(ctx, OpenContext{admission: &selected.admission}, env.Store)
	if admin == nil || result.Outcome != ObservedCurrent || len(admin.adminIndex.Groups) < 2 {
		t.Fatal("sparse optional fixture has no two selected owners", result)
	}
	var target contract.ID
	for _, group := range admin.adminIndex.Groups {
		remaining, scope, err := admin.administrativeWorkClosure(group.GroupID)
		if err == nil && len(scope) == 1 && len(remaining.Groups) != 0 {
			target = group.GroupID
			break
		}
	}
	if target.IsZero() {
		t.Fatal("sparse optional fixture has no independent first exit")
	}
	first, result := prepareTestEndSelectedWork(t, admin, ctx, target, env.Trust)
	if first == nil || result.Outcome != ObservedCurrent {
		t.Fatal("sparse optional first exit preparation", result)
	}
	selected, result = admin.selectCandidate(ctx, first)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("sparse optional first exit selection", result)
	}
	selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
	var sparse format.AdministrativePage
	var firstOrdinal uint16
	for _, page := range selected.adminIndex.Pages {
		for _, span := range page.Spans {
			if span.First > 0 && len(span.GroupIndexes) != 0 {
				sparse = page
				firstOrdinal = span.First
				break
			}
		}
	}
	beforePosition := slices.Index(selected.root.RequiredSupport, sparse.Ref)
	if beforePosition < 0 || len(selected.support[beforePosition].Records) == 0 {
		t.Fatal("real selected exit has no compact optional row under an unchanged physical page")
	}
	env = syntheticAuthorityScenarioEnvironment(t, env)
	actors := env.ReplacementActors(t, ctx, selected, 3, 4, 2)
	permit := admitAuthorityReplacement(t, selected, actors.Keys, actors.After, 3, 2, 4, actors.Source)
	successor, result := selected.PrepareSuccession(ctx, permit, actors.Signers)
	if successor == nil || result.Outcome != ObservedCurrent {
		t.Fatal("sparse optional owner did not prepare a receipt-writing successor", result)
	}
	admission := deliverSuccessionBasis(t, successor)
	if result := selected.Select(ctx, successor); result.Outcome != ObservedCurrent {
		t.Fatal("sparse optional owner did not select a receipt-writing successor", result)
	}
	reopened, result := Open(ctx, admission, env.Store)
	if reopened == nil || result.Outcome != ObservedCurrent {
		t.Fatal("sparse optional owner successor did not cold-open", result)
	}
	position := slices.Index(reopened.root.RequiredSupport, sparse.Ref)
	if position < 0 || !slices.ContainsFunc(reopened.adminIndex.Pages[position].Spans, func(span format.AdministrativeSpan) bool {
		return span.First == firstOrdinal && len(span.GroupIndexes) != 0
	}) {
		t.Fatal("sparse optional owner lost its physical span")
	}
}

// full_only: false
func TestEndWorkValueSuccessorKeepsUnrelatedRetiringPointer(t *testing.T) {
	_, selected, _, _ := generatedAuthenticatedDeleteHazardFixture(t, false, 0)
	if len(selected.root.Names) != 1 || selected.pages[0] == nil || selected.pages[0].Slots[1] != nil {
		t.Fatal("two-pointer fixture cannot be formed")
	}
	firstDuty, secondDuty := generatedVectorID(248), generatedVectorID(250)
	first := *selected.pages[0].Slots[0]
	first.Generated.RetiringDutyPresent, first.Generated.RetiringDutyID = 1, firstDuty
	second := first
	second.Name, second.Incarnation, second.ValueState = "zz-unrelated", generatedVectorID(251), generatedVectorID(252)
	second.Generated.GenerationID = second.ValueState
	second.Generated.RetiringDutyID = secondDuty
	page := *selected.pages[0]
	page.Object = generatedVectorID(253)
	page.Slots[0], page.Slots[1] = &first, &second
	body, err := format.EncodeValueEntryPage(page)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(format.ValueEntryPageKind, page.Domain, page.Object, page.Index, body)
	if err != nil {
		t.Fatal(err)
	}
	selected.pages[0], selected.root.ValueEntryPages[0] = &page, &ref
	selected.root.Names = append(selected.root.Names, format.NameEntry{Name: second.Name, Slot: 1})
	selected.root.ValueEntryCount++
	selected.root.SecretCount++
	selected.adminIndex.Groups = []format.AdministrativeGroup{
		{GroupID: firstDuty, OwnerID: firstDuty, TargetID: generatedVectorID(247),
			OwnerKind: format.AdministrativeGeneratedDuty, DutyKind: contract.GeneratedDutyRetirement,
			SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing,
			Affected:                administrativeDescriptor("first-affected"), Dependencies: administrativeDescriptor("first-dependencies"),
			Disposable: administrativeDescriptor("first-disposable")},
		{GroupID: secondDuty, OwnerID: secondDuty, TargetID: generatedVectorID(249),
			OwnerKind: format.AdministrativeGeneratedDuty, DutyKind: contract.GeneratedDutyRetirement,
			SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing,
			Affected:                administrativeDescriptor("second-affected"), Dependencies: administrativeDescriptor("second-dependencies"),
			Disposable: administrativeDescriptor("second-disposable")},
	}
	if !selected.currentRetiringPointersSelected() {
		t.Fatal("two selected retirement pointers refused")
	}
	next := *selected
	next.root = selected.root
	images, cleared, err := selected.endWorkValueSuccessor(&next, selected.adminIndex.Groups[:1], generatedVectorID(246))
	if err != nil || len(images) != 1 || len(cleared) != 1 || cleared[first.ValueState] != firstDuty ||
		next.pages[0].Slots[0].Generated.RetiringDutyPresent != 0 ||
		next.pages[0].Slots[1].Generated.RetiringDutyID != secondDuty ||
		next.pages[0].Slots[1].Generated.RetiringDutyPresent != 1 {
		t.Fatal("unrelated selected retirement pointer changed", err)
	}
	before, err := administrativePreservedCurrent(selected.root, selected.pages, nil, cleared)
	if err != nil {
		t.Fatal(err)
	}
	after, err := administrativePreservedCurrent(next.root, next.pages, nil, nil)
	if err != nil || before != after {
		t.Fatal("filtered predecessor did not preserve unrelated pointer", err)
	}
}

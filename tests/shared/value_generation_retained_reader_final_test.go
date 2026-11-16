package core

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestGeneratedRetainedContentFinalPreservesSurvivingReader(t *testing.T) {
	checkGeneratedRetainedFinalReaders(t, 1, contract.GeneratorValueChangeContent|contract.GeneratorValueChangeMembership)
}

// full_only: false
func TestGeneratedRetainedMembershipFinalDropsLastConsumerReader(t *testing.T) {
	checkGeneratedRetainedFinalReaders(t, 0, contract.GeneratorValueChangeMembership)
}

// full_only: false
func TestGeneratedRetainedFinalReaderOwnershipSequences(t *testing.T) {
	for _, tc := range []struct {
		name              string
		owners            int
		mask              uint8
		recovery, reverse bool
	}{
		{"zero_membership_recovery", 0, contract.GeneratorValueChangeMembership, true, false},
		{"one_content_recovery", 1, contract.GeneratorValueChangeContent | contract.GeneratorValueChangeMembership, true, false},
		{"two_content_forward", 2, contract.GeneratorValueChangeContent | contract.GeneratorValueChangeMembership, false, false},
		{"two_content_reverse", 2, contract.GeneratorValueChangeContent | contract.GeneratorValueChangeMembership, false, true},
		{"two_membership_recovery_forward", 2, contract.GeneratorValueChangeMembership, true, false},
		{"two_membership_recovery_reverse", 2, contract.GeneratorValueChangeMembership, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkGeneratedRetainedFinalReaderSequence(t, tc.owners, tc.mask, tc.recovery, tc.reverse, false)
		})
	}
}

// full_only: false
func TestGeneratedRetainedFinalCheckpointReusesExactArtifacts(t *testing.T) {
	for _, tc := range []struct {
		name     string
		owners   int
		mask     uint8
		recovery bool
	}{
		{"last_membership_owner", 0, contract.GeneratorValueChangeMembership, false},
		{"surviving_content_owner_recovery", 1, contract.GeneratorValueChangeContent | contract.GeneratorValueChangeMembership, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkGeneratedRetainedFinalReaderSequence(t, tc.owners, tc.mask, tc.recovery, false, true)
		})
	}
}

func checkGeneratedRetainedFinalReaders(t *testing.T, olderOwners int, mask uint8) {
	t.Helper()
	checkGeneratedRetainedFinalReaderSequence(t, olderOwners, mask, false, false, false)
}

func checkGeneratedRetainedFinalReaderSequence(t *testing.T, olderOwners int, mask uint8, recovery, reverse, checkpoint bool) {
	t.Helper()
	f := newCurrentRetainedFinalPrefix(t, olderOwners, mask, recovery)
	ctx, env, keys := t.Context(), f.env, f.keys
	authority, reader, originalReaders := f.authority, f.reader, f.originalReaders
	original, beforeAccess, recorded := f.original, f.originalAccess, f.recorded
	owners, ownerAttempts, ownerBodies := f.owners, f.ownerAttempts, f.ownerBodies
	selected := recorded
	mustSelectedGeneratedWork(t, recorded)
	admitted := generatedPlanInputFixture(t, recorded).context
	admitted.AdmissionID, admitted.SessionID = testID(t.Name()+" Final admission"), testID(t.Name()+" Final session")
	plan, err := recorded.generatedFinalRequest(ctx, admitted)
	if err != nil || plan == nil || !plan.selecting || len(plan.entryPlans) != 1 {
		t.Fatal("setup: actual selecting Final request", err)
	}
	wantReaders := []contract.ID{authority}
	if olderOwners != 0 {
		wantReaders = originalReaders
	}
	t.Logf("setup reached: Retained Secret mask=%d, older canonical owners=%d, fresh generated siblings=1, expected successor ordinary readers=%d", mask, olderOwners, len(wantReaders))
	if checkpoint {
		prepared := prepareCheckpointFinal(t, env, recorded, t.Name()+" checkpoint")
		if prepared.reservation.candidate.head.Generator == nil || prepared.reservation.candidate.head.Generator.Purpose != contract.GeneratorAuthorityFinalPreparation {
			t.Fatal("retained Final omitted its preparation checkpoint")
		}
		candidate, result := recorded.ClaimGeneratedPreparation(ctx, prepared.reservation.candidate, env.Trust)
		if candidate == nil || result.Outcome != ObservedCurrent {
			t.Fatal("retained checkpoint claim", result)
		}
		selected, result = recorded.selectCandidate(ctx, candidate)
		if selected == nil || result.Outcome != ObservedCurrent || !reflect.DeepEqual(selected.accessRecords(), recorded.accessRecords()) ||
			!reflect.DeepEqual(selected.currentEntryInputs(), recorded.currentEntryInputs()) {
			t.Fatal("retained checkpoint changed selected predecessor state", result)
		}
		keys.RetireGenerated()
		selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
		work := mustSelectedGeneratedWork(t, selected)
		image, err := selected.generatedFinalPreparationImage(ctx, work)
		if err != nil {
			t.Fatal("cold retained checkpoint image", err)
		}
		defer image.Clear()
		imageIndex := slices.IndexFunc(image.Supplied, func(row contract.CryptoPreparedSecret) bool { return row.Name == "shared" })
		if imageIndex < 0 {
			t.Fatal("checkpoint omitted the retained prepared Secret")
		}
		preparedAccess, err := contract.DecodeAccessRecord(image.Supplied[imageIndex].AccessRecord)
		preparedEntry, entryErr := contract.DecodeValueEntry(image.Supplied[imageIndex].EntryBytes)
		if err != nil || entryErr != nil || preparedEntry.ValueState == original.ValueState || preparedAccess.MaterialID != preparedEntry.ValueState ||
			len(preparedAccess.Wraps) != 1+boolInt(recovery) || preparedAccess.Wraps[0].SubjectID != authority {
			t.Fatal("checkpoint did not prepare fresh current-only protection", err, entryErr)
		}
		expected := generatedFinalCheckpointExpectation{Mode: "reuse", ImageID: work.preparation.Image.ContentID,
			MaterializationPhaseID: mustGeneratedPhaseID(work.preparation.MaterializationPhase)}
		replay := prepareCheckpointFinal(t, currentGeneratedEnvironment(t, env.Store, selected), selected, t.Name()+" actual Final")
		expected.Artifacts = checkpointArtifactBodies(t, selected, replay.reservation.candidate)
		keys.RetireGenerated()
		selected = checkpointFinalInFreshProcess(t, selected, requireAdmittedMemoryStore(t, env.Store), expected)
	} else {
		capture := &retainedFinalPreparationCapture{Crypto: keys.Crypto(), t: t, value: original.ValueState}
		var final *generatedPreparation
		recorded, final = preparePrivateGeneratedFinal(t, env, recorded, plan, capture)
		var result Result
		selected, result = recorded.selectCandidate(ctx, final.reservation.candidate)
		if selected == nil || result.Outcome != ObservedCurrent {
			t.Fatal("retained Final must select its exact successor reader set", result)
		}
	}
	keys.RetireGenerated()
	selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
	var currentProtection contract.ValueEntry
	checkCurrent := func(selected *StateSession) {
		t.Helper()
		_, current := lifecycleEntry(t, selected, "shared")
		if current.ValueState == original.ValueState || bytes.Equal(current.ValueBytes, original.ValueBytes) {
			t.Fatal("reader removal reused the old current protected material")
		}
		if current.Incarnation != original.Incarnation || current.ValueSource != original.ValueSource || current.ConfidentialityClass != original.ConfidentialityClass ||
			!slices.Equal(current.Recipients, []contract.ID{authority}) {
			t.Fatal("Final changed the value entry meaning or desired membership")
		}
		if currentProtection.ValueState.IsZero() {
			currentProtection = ownScenarioValueEntry(*current)
		} else if !reflect.DeepEqual(*current, currentProtection) {
			t.Fatal("ending an old owner changed current protection")
		}
		access, ok := selected.materialAccess(contract.ValueMaterialKind, current.ValueState)
		if !ok || len(access.Wraps) != 1+boolInt(recovery) || access.Wraps[0].SubjectKind != contract.OrdinaryWrapSubject || access.Wraps[0].SubjectID != authority {
			t.Fatal("Final did not select the exact current access set")
		}
		if recovery && access.Wraps[1].SubjectKind != contract.RecoveryWrapSubject {
			t.Fatal("Final lost the separate required Recovery wrap")
		}
		if check := keys.Consume(ctx, sessionConsumerSelection(t, selected, authority, "shared"), custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
			t.Fatal("current recipient cannot consume unchanged retained value", check)
		}
	}

	checkOwners := func(selected *StateSession, remaining []contract.ID) {
		t.Helper()
		work := mustSelectedGeneratedWork(t, selected)
		if len(work.consumers[materialIdentity{kind: contract.ValueMaterialKind, id: original.ValueState}]) != len(remaining) {
			t.Fatal("Final or cleanup did not end exactly the closed canonical obligations")
		}
		oldAccess, present := selected.materialAccess(contract.ValueMaterialKind, original.ValueState)
		if len(remaining) == 0 {
			if present {
				t.Fatal("last owner left old material access selected")
			}
		} else if !present || !reflect.DeepEqual(oldAccess, beforeAccess) {
			t.Fatal("surviving owners lost exact old material access")
		}
		for _, owner := range remaining {
			if !bytes.Equal(work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, owner}].Body, ownerBodies[owner]) {
				t.Fatal("transition changed a surviving named canonical owner")
			}
			selection, result := selected.generatedConsumerSelection(ctx, contract.GeneratedHazardSupportKind, owner, original.ValueState, reader)
			if result.Outcome != ObservedCurrent {
				t.Fatal("surviving named owner lost the retained reader", result)
			}
			if check := keys.ConsumeGenerated(ctx, selection, custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
				t.Fatal("surviving named owner cannot consume the exact old value", check)
			}
		}
	}
	checkCurrent(selected)
	checkOwners(selected, owners)
	if reverse {
		slices.Reverse(owners)
	}
	deleteStore := &generatedCleanupDeleteStore{memoryStore: requireAdmittedMemoryStore(t, env.Store)}
	for i, owner := range owners {
		selected = closeAndReleaseActualCleanup(t, env, selected, deleteStore, ownerAttempts[owner], contract.GeneratedHazardSupportKind, owner, i)
		selected = generatedLifecycleReopen(t, ctx, selected, deleteStore)
		remaining := owners[i+1:]
		checkCurrent(selected)
		checkOwners(selected, remaining)
	}
}

type retainedFinalPreparationCapture struct {
	contract.Crypto
	t     *testing.T
	value contract.ID
}

func (c *retainedFinalPreparationCapture) Exchange(ctx context.Context, request contract.CryptoRequest) contract.CryptoResponse {
	response := c.Crypto.Exchange(ctx, request)
	if request.Kind != contract.CryptoPrepare {
		return response
	}
	if _, err := contract.InspectCryptoGeneratedSuppliedRequest(request.Body); err != nil {
		return response
	}
	c.t.Logf("actual supplied preparation response code=%d", response.ResultCode)
	if response.ResultCode == contract.CryptoSuccess {
		view, err := contract.InspectCryptoGeneratedSuppliedResult(response.Body)
		if err != nil {
			c.t.Fatal("cannot inspect supplied preparation evidence", err)
		}
		rows, err := view.Own()
		if err != nil {
			c.t.Fatal("cannot own supplied preparation evidence", err)
		}
		for _, row := range rows {
			access, err := contract.DecodeAccessRecord(row.AccessRecord)
			if err != nil {
				c.t.Fatal("cannot inspect prepared reader set", err)
			}
			if access.MaterialID == c.value {
				c.t.Logf("actual retained supplied preparation ordinary wraps=%d", len(access.Wraps))
			}
		}
	}
	return response
}

// full_only: false
func TestGeneratedSelectingFinalRetainsReadersUntilLastCleanup(t *testing.T) {
	ctx := t.Context()
	env, keys := genesisEnvironment(t, contract.GCP, false)
	authority, reader := fixtureID(env.Domain, "recipient"), fixtureID(env.Domain, "reader")
	originalReaders := []contract.ID{authority, reader}
	slices.SortFunc(originalReaders, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, nil, false)
	run.suppliedSelection(f, []ApplyEntryInput{sharingSecretNamed(t, env, "shared", "retained selecting Final source", originalReaders)})
	_, original := lifecycleEntry(t, f.session, "shared")
	wantValue := ownScenarioValueEntry(*original)

	// Each independent primary owns its canonical source explicitly. A sibling
	// with only result-adoption consumers would not establish this requirement.
	selected := f.session
	owners := make(map[contract.ID][]byte)
	for i := range 2 {
		sources, canonical := generatedCurrentDeclaration(t, selected)
		label := fmt.Sprintf("%s retained owner %d", t.Name(), i)
		names := []string{fmt.Sprintf("failed-%d", i)}
		input := generatedPlanInputForGenerations(t, selected, testID(label+" operation"), names, defaultGeneratedFixtureProfile(), sources...)
		input.context.AdmissionID, input.context.SessionID = testID(label+" admission"), testID(label+" session")
		var failed generatedAttempt
		selected, failed = selectPrivateOwnedUnusableAggregateFromInput(t, env, selected, names, input, canonical)
		selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
		work := mustSelectedGeneratedWork(t, selected)
		ownerID := failed.expected.Template.HazardID
		owners[ownerID] = bytes.Clone(work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, ownerID}].Body)
		if _, result := selected.generatedConsumerSelection(ctx, contract.GeneratedHazardSupportKind, ownerID, wantValue.ValueState, reader); result.Outcome != ObservedCurrent {
			t.Fatal("initial retained owner does not consume the exact historical reader", result.Outcome, result.Reason)
		}
	}
	if selected.root.Generated.Duties != 0 || selected.root.Generated.Hazards != 2 || len(owners) != 2 {
		t.Fatal("retained reader baseline lost its two actual canonical owners")
	}

	// Older owners retain this exact source. Current reader removal must select
	// fresh protection independently of their old-material requirements.
	sources, canonical := generatedCurrentDeclaration(t, selected)
	if len(sources) != 1 || len(canonical) != 1 || sources[0].Kind != contract.GeneratorDeclarationRetained {
		t.Fatal("selecting Final fixture lacks the exact current canonical source")
	}
	sources[0].Recipients = []contract.ID{authority}
	input := generatedPlanInputForGenerations(t, selected, fixtureID(env.Domain, "reader Final selecting operation"),
		[]string{"generated"}, defaultGeneratedFixtureProfile(), sources...)
	input.context.AdmissionID, input.context.SessionID = testID(t.Name()+" reservation admission"), testID(t.Name()+" reservation session")
	for i := range input.graph.ValueEntryPlans {
		if input.graph.ValueEntryPlans[i].Name == "shared" && input.graph.ValueEntryPlans[i].ChangeMask != contract.GeneratorValueChangeMembership {
			t.Fatal("retained reader selecting plan changed content or omitted membership")
		}
	}
	prior, _ := preparePrivateGeneratedReservation(t, env, selected, input, canonical)
	recorded, _, _, _ := selectActualGeneratedPacketRecord(t, env, selected, prior, custody.StandardValue, true, nil)
	admitted := generatedPlanInputFixture(t, recorded).context
	admitted.AdmissionID, admitted.SessionID = testID(t.Name()+" Final admission"), testID(t.Name()+" Final session")
	plan, err := recorded.generatedFinalRequest(ctx, admitted)
	if err != nil || plan == nil || !plan.selecting {
		t.Fatal("retained reader selecting Final request", err)
	}
	recorded, final := preparePrivateGeneratedFinal(t, env, recorded, plan)
	selected, result := recorded.selectCandidate(ctx, final.reservation.candidate)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("retained reader selecting Final selection", result)
	}
	keys.RetireGenerated()

	var currentProtection contract.ValueEntry
	checkCurrent := func(s *StateSession, oldReaders []contract.ID) {
		t.Helper()
		_, entry := lifecycleEntry(t, s, "shared")
		if entry.ValueState == wantValue.ValueState || bytes.Equal(entry.ValueBytes, wantValue.ValueBytes) || entry.Incarnation != wantValue.Incarnation ||
			!slices.Equal(entry.Recipients, []contract.ID{authority}) {
			t.Fatal("retained reader transition did not select fresh current protection and intended membership")
		}
		if currentProtection.ValueState.IsZero() {
			currentProtection = ownScenarioValueEntry(*entry)
		} else if !reflect.DeepEqual(*entry, currentProtection) {
			t.Fatal("old-owner cleanup changed current protection")
		}
		access, ok := s.materialAccess(contract.ValueMaterialKind, entry.ValueState)
		if !ok || len(access.Wraps) != 1 || access.Wraps[0].SubjectKind != contract.OrdinaryWrapSubject || access.Wraps[0].SubjectID != authority {
			t.Fatal("current protection contains an old-only reader")
		}
		oldAccess, present := s.materialAccess(contract.ValueMaterialKind, wantValue.ValueState)
		if len(oldReaders) == 0 {
			if present {
				t.Fatal("last owner left obsolete old material access")
			}
		} else {
			if !present || len(oldAccess.Wraps) != len(oldReaders) {
				t.Fatal("retained reader transition has an inexact old wrap count")
			}
			for i, wrap := range oldAccess.Wraps {
				if wrap.SubjectKind != contract.OrdinaryWrapSubject || wrap.SubjectID != oldReaders[i] {
					t.Fatal("retained reader transition has an inexact old wrap subject", i)
				}
			}
		}
		if check := keys.Consume(ctx, sessionConsumerSelection(t, s, authority, "shared"), custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
			t.Fatal("current authority could not consume unchanged value", check)
		}
	}
	checkRetainedReader := func(s *StateSession, ownerKind uint8, ownerID contract.ID) {
		t.Helper()
		selection, result := s.generatedConsumerSelection(ctx, ownerKind, ownerID, wantValue.ValueState, reader)
		if result.Outcome != ObservedCurrent {
			t.Fatal("surviving retained reader admission", result.Outcome, result.Reason)
		}
		if check := keys.ConsumeGenerated(ctx, selection, custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
			t.Fatal("surviving retained reader could not consume unchanged value", check)
		}
	}
	selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
	checkCurrent(selected, originalReaders)
	for ownerID := range owners {
		checkRetainedReader(selected, contract.GeneratedHazardSupportKind, ownerID)
	}

	// Closing the first owner must keep the second owner's old reader.
	deleteStore := &generatedCleanupDeleteStore{memoryStore: env.Store.(*memoryStore)}
	for i := range 2 {
		work := mustSelectedGeneratedWork(t, selected)
		cleanup, present, err := work.selectGeneratedCleanup(ctx, nil)
		if err != nil || !present || cleanup.kind != generatedCleanupHazard || owners[cleanup.hazard.HazardID] == nil {
			t.Fatal("actual retained cleanup priority changed its exact owner", err)
		}
		selected = closeAndReleaseActualCleanup(t, env, selected, deleteStore, cleanup.attempt,
			contract.GeneratedHazardSupportKind, cleanup.hazard.HazardID, i)
		selected = generatedLifecycleReopen(t, ctx, selected, deleteStore)
		delete(owners, cleanup.hazard.HazardID)
		work = mustSelectedGeneratedWork(t, selected)
		if selected.root.Generated.Duties != 0 || selected.root.Generated.Hazards != uint32(len(owners)) {
			t.Fatal("retained cleanup changed the exact remaining owner count")
		}
		if len(owners) != 0 {
			checkCurrent(selected, originalReaders)
			for ownerID, body := range owners {
				if !bytes.Equal(work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, ownerID}].Body, body) {
					t.Fatal("first retained cleanup changed the surviving owner")
				}
				checkRetainedReader(selected, contract.GeneratedHazardSupportKind, ownerID)
			}
		} else {
			// Last-owner closure releases reader, not the still-current value.
			if len(work.canonical) != 0 || len(work.consumers[materialIdentity{kind: contract.ValueMaterialKind, id: wantValue.ValueState}]) != 0 {
				t.Fatal("last retained cleanup did not release the complete canonical ownership")
			}
			checkCurrent(selected, nil)
		}
	}
}

// currentRetainedFinalPrefix is produced by the actual current reservation and
// private result owners. It contains no historical wire input or legacy edits.
type currentRetainedFinalPrefix struct {
	env               fixtureEnvironment
	keys              *custody.Fixture
	authority, reader contract.ID
	originalReaders   []contract.ID
	original          contract.ValueEntry
	originalAccess    contract.AccessRecord
	recorded          *StateSession
	owners            []contract.ID
	ownerAttempts     map[contract.ID]generatedAttempt
	ownerBodies       map[contract.ID][]byte
}

func newCurrentRetainedFinalPrefix(t *testing.T, olderOwners int, mask uint8, recovery bool, materialKeyedSource ...bool) currentRetainedFinalPrefix {
	t.Helper()
	ctx := t.Context()
	env, keys := genesisEnvironment(t, contract.GCP, recovery)
	authority, reader := fixtureID(env.Domain, "recipient"), fixtureID(env.Domain, "reader")
	originalReaders := []contract.ID{authority, reader}
	slices.SortFunc(originalReaders, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, nil, false)
	run.suppliedSelection(f, []ApplyEntryInput{sharingSecretNamed(t, env, "shared", "retained Final reader boundary", originalReaders)})
	_, entry := lifecycleEntry(t, f.session, "shared")
	original := ownScenarioValueEntry(*entry)
	beforeAccess, ok := f.session.materialAccess(contract.ValueMaterialKind, original.ValueState)
	if !ok || len(beforeAccess.Wraps) != 2+boolInt(recovery) {
		t.Fatal("setup: original access does not contain exactly two ordinary readers and its separate Recovery wrap")
	}
	selected := f.session
	var owners []contract.ID
	ownerAttempts := make(map[contract.ID]generatedAttempt)
	ownerBodies := make(map[contract.ID][]byte)
	for i := range olderOwners {
		sources, canonical := generatedCurrentDeclaration(t, selected)
		label := fmt.Sprintf("%s older owner %d", t.Name(), i)
		names := []string{fmt.Sprintf("failed-%d", i)}
		input := generatedPlanInputForGenerations(t, selected, testID(label+" operation"), names, defaultGeneratedFixtureProfile(), sources...)
		input.context.AdmissionID, input.context.SessionID = testID(label+" admission"), testID(label+" session")
		var failed generatedAttempt
		selected, failed = selectPrivateOwnedUnusableAggregateFromInput(t, env, selected, names, input, canonical)
		selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
		owner := failed.expected.Template.HazardID
		owners = append(owners, owner)
		ownerAttempts[owner] = failed
		ownerBodies[owner] = bytes.Clone(mustSelectedGeneratedWork(t, selected).records[generatedRecordKey{contract.GeneratedHazardSupportKind, owner}].Body)
	}
	work := mustSelectedGeneratedWork(t, selected)
	consumers := work.consumers[materialIdentity{kind: contract.ValueMaterialKind, id: original.ValueState}]
	if len(consumers) != olderOwners || selected.root.Generated.Hazards != uint32(olderOwners) || selected.root.Generated.Duties != 0 {
		t.Fatal("setup: canonical consumer set does not match the fixed older owners")
	}
	for _, owner := range owners {
		if _, result := selected.generatedConsumerSelection(ctx, contract.GeneratedHazardSupportKind, owner, original.ValueState, reader); result.Outcome != ObservedCurrent {
			t.Fatal("setup: actual older owner does not require the removed reader", result)
		}
	}
	if len(materialKeyedSource) > 1 {
		t.Fatal("ambiguous current retained fixture source mode")
	}
	if len(materialKeyedSource) == 1 && materialKeyedSource[0] && olderOwners != 0 {
		selected = currentMaterialKeyedRetainedSource(t, env, selected, original.ValueState)
		for _, owner := range owners {
			ownerBodies[owner] = bytes.Clone(mustSelectedGeneratedWork(t, selected).records[generatedRecordKey{contract.GeneratedHazardSupportKind, owner}].Body)
		}
	}
	sources, canonical := generatedCurrentDeclaration(t, selected)
	if len(sources) != 1 || len(canonical) != 1 || sources[0].Kind != contract.GeneratorDeclarationRetained ||
		!sameRetainedEntryValue(canonical[0].Record.Entry, original) {
		t.Fatal("setup: declaration does not retain the exact current secret")
	}
	sources[0].Recipients = []contract.ID{authority}
	input := generatedPlanInputForGenerations(t, selected, testID(t.Name()+" selecting operation"), []string{"generated"}, defaultGeneratedFixtureProfile(), sources...)
	input.context.AdmissionID, input.context.SessionID = testID(t.Name()+" reservation admission"), testID(t.Name()+" reservation session")
	for i := range input.graph.ValueEntryPlans {
		if input.graph.ValueEntryPlans[i].Name == "shared" {
			input.graph.ValueEntryPlans[i].ChangeMask = mask
		}
	}
	var err error
	input.graph.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(input.graph.Header, input.graph.ValueEntryPlans, input.graph.Lineages, input.graph.Edges)
	if err != nil || contract.ValidateGeneratorEffectGraph(input.graph) != nil {
		t.Fatal("setup: retained graph is invalid", err)
	}
	prior, _ := preparePrivateGeneratedReservation(t, env, selected, input, canonical)
	recorded, _, _, _ := selectActualGeneratedPacketRecord(t, env, selected, prior, custody.StandardValue, true, nil)
	work = mustSelectedGeneratedWork(t, recorded)
	accepted, err := work.retainedGraph(input.graph.Header.OperationID)
	if err != nil || accepted.UsePlan.PlanGraphID != input.graph.UsePlan.PlanGraphID {
		t.Fatal("setup: selected graph does not bind the actual active operation", err)
	}
	retainedPlan := slices.IndexFunc(accepted.ValueEntryPlans, func(row contract.GeneratorValueEntryPlan) bool { return row.Name == "shared" })
	creates := 0
	for _, lineage := range accepted.Lineages {
		if lineage.Purpose == contract.GeneratorLineageCreate {
			creates++
		}
	}
	if retainedPlan < 0 || accepted.ValueEntryPlans[retainedPlan].ChangeMask != mask ||
		contract.ValidateGeneratorEffectGraph(accepted) != nil || creates != 1 {
		t.Fatal("setup: actual selected graph changed the retained mode or fresh sibling")
	}
	for _, owner := range owners {
		if _, result := recorded.generatedConsumerSelection(ctx, contract.GeneratedHazardSupportKind, owner, original.ValueState, reader); result.Outcome != ObservedCurrent {
			t.Fatal("setup: selected reservation lost an outside reader obligation", result)
		}
	}
	return currentRetainedFinalPrefix{env, keys, authority, reader, originalReaders, original, beforeAccess, recorded, owners, ownerAttempts, ownerBodies}
}

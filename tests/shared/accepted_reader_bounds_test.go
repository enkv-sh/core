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
func TestGeneratedReaderReplacementPreservesEnteredWork(t *testing.T) {
	for _, family := range []contract.Family{contract.GCP, contract.AWS} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("family%d/recovery%t", family, recovery), func(t *testing.T) {
				ctx := context.Background()
				env, keys := genesisEnvironment(t, family, recovery)
				reader := fixtureID(env.Domain, "reader")
				env.ReaderSuccessor = keys.RecipientSuccessor(t, reader)
				run := newScenarioRun(t, ctx, env)
				f := newEnvironmentFixture(t, ctx, run.env, nil, false)
				input, canonical := generatedSourcePlanInput(t, run, f, 2)
				reservation, _ := preparePrivateGeneratedReservation(t, env, f.session, input, canonical)
				producer, expected := preparePrivateGeneratedProducer(t, env, f.session, reservation, nil)
				var result []byte
				if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
					var code contract.CryptoResultCode
					result, _, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
					return code
				}) {
					t.Fatal("generated first-send handoff")
				}
				selected, res := f.session.selectCandidate(ctx, producer.reservation.candidate)
				if selected == nil || res.Outcome != ObservedCurrent || len(result) == 0 {
					t.Fatal("generated effect entry", res)
				}
				f.session = selected
				beforeWork, err := selected.preservedWorkSupportRecords(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				beforeReader := sessionConsumerSelection(t, selected, reader, "secret")
				keys.RetireGenerated()
				beforeMaterial, afterReader := replaceReaderInSelected(t, ctx, run, f)
				afterWork, err := f.session.preservedWorkSupportRecords(t.Context())
				if err != nil || !reflect.DeepEqual(beforeWork, afterWork) || beforeReader.Core.ValueStateID != afterReader.Core.ValueStateID ||
					!keys.MaterialPreserved(beforeMaterial, afterReader) {
					t.Fatal("reader replacement changed generated accepted work or current material", err)
				}
				check := env.readerSuccessorConsume(afterReader, custody.StandardValue)
				if check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched || check.SinkCalls != 1 {
					t.Fatal("reader successor could not consume the unchanged current value", check)
				}
				recorded := selectFreshGeneratedRecord(t, env.Store.(*memoryStore), f.session, expected.Template.AttemptID, result)
				g, err := recorded.selectedGeneratedWork(context.Background())
				if err != nil || !bytes.Equal(g.attempts[expected.Template.AttemptID].result, result) {
					t.Fatal("reader replacement changed the frozen generated result", err)
				}
				finalContext := generatedPlanInputFixture(t, recorded).context
				finalContext.AdmissionID, finalContext.SessionID = testID("reader generated final admission"), testID("reader generated final session")
				finalPlan, err := recorded.generatedFinalRequest(t.Context(), finalContext)
				if err != nil {
					t.Fatal(err)
				}
				recorded, final := preparePrivateGeneratedFinal(t, env, recorded, finalPlan)
				closed, res := recorded.selectCandidate(ctx, final.reservation.candidate)
				if closed == nil || res.Outcome != ObservedCurrent || closed.root.ValueEntryCount != 2 || closed.root.Generated.ActiveOwner != (contract.ID{}) {
					t.Fatal("generated final selection after reader replacement", res)
				}
				checkFreshGeneratedProcess(t, env.Store.(*memoryStore), closed)
			})
		}
	}
}

// full_only: false
func TestRetainedReaderUnionUsesBothAdmittedMemberSets(t *testing.T) {
	// Structural relation control for historical inputs, not a corrected producer history.
	// A new removal must select a different material for recipient exclusion.
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	ids := []contract.ID{fixtureID(env.Domain, "recipient")}
	for i := 1; i < 127; i++ {
		ids = append(ids, fixtureID(env.Domain, fmt.Sprintf("union reader %d", i)))
	}
	keys := custody.New(t, contract.GCP, fixtureID(env.Domain, "union capacity custody"), false, ids)
	env.Custody, env.Crypto, env.Bindings = keys, keys.Crypto(), keys.Bindings()
	env.AdmitInit, env.RetireInit = keys.AdmitInit, keys.RetireInit
	original := slices.Clone(ids[:64])
	current := append([]contract.ID{ids[0]}, ids[64:]...)
	for _, set := range [][]contract.ID{original, current} {
		slices.SortFunc(set, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	}
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, nil, false)
	run.suppliedSelection(f, []ApplyEntryInput{sharingSecret(t, env, "union boundary current", current)})
	slot, m := lifecycleEntry(t, f.session, "secret")
	core, payload, access, ok := f.session.selectedValue(slot)
	if !ok {
		t.Fatal("current member selection")
	}
	retained := *m
	retained.Recipients = original
	if _, err := contract.ValueEntryLength(*m); err != nil {
		t.Fatal(err)
	}
	if _, err := contract.ValueEntryLength(retained); err != nil {
		t.Fatal(err)
	}
	body, err := contract.EncodeRetainedCanonicalRecord(contract.RetainedCanonicalRecord{OriginalSlot: slot, Entry: retained})
	if err != nil {
		t.Fatal(err)
	}
	selected := *f.session
	selected.support = []format.RequiredSupportPageView{{Records: []contract.SupportRecordView{{Kind: 6, RecordID: m.ValueState, Body: body}}}}
	if !selected.indexSelectedMaterials() {
		t.Fatal("reader union indexing")
	}
	readers := selected.valueReaders[m.ValueState]
	if len(readers) != 127 {
		t.Fatal("reader union omitted one admitted set", len(readers))
	}
	// This test isolates public reader/wrap correspondence. RSA bodies are opaque
	// here; the separate accepted reader scenario proves actual recipient opening.
	access.Wraps = nil
	for _, id := range readers {
		binding := selected.recipientRecord(id).CurrentBinding
		digest, err := contract.PublicBindingDigest(*binding)
		if err != nil {
			t.Fatal(err)
		}
		access.Wraps = append(access.Wraps, contract.WrapRow{SubjectKind: 1, SubjectID: id, BindingID: binding.BindingID, BindingSerial: binding.BindingSerial, PublicBindingDigest: digest, RSACiphertext: make([]byte, 384)})
	}
	if !selected.validateValueAccess(core, payload, access, readers) {
		t.Fatal("127-reader current/retained union refused")
	}
	access.Wraps = access.Wraps[:126]
	if selected.validateValueAccess(core, payload, access, readers) {
		t.Fatal("missing admitted retained/current reader accepted")
	}
}

// full_only: false
func TestFreshIncarnationSlotsDeduplicatesAddedSourceChange(t *testing.T) {
	s := &StateSession{}
	s.pages[0] = &format.ValueEntryPage{}
	s.pages[0].Slots[2] = &format.ValueEntry{ValueSource: contract.Generated, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
	c := &Comparison{
		session:        s,
		desiredEntries: []ApplyEntryInput{{ValueSource: contract.Supplied}},
		slots:          []uint16{2},
		added:          []uint16{2},
	}
	if got := c.freshIncarnationSlots(); !slices.Equal(got, []uint16{2}) {
		t.Fatal("added source change allocated duplicate incarnation slots", got)
	}
}

// full_only: false
func TestGeneratedRetainedCurrentReaderFrontierAndReplacement(t *testing.T) {
	for _, tc := range []struct {
		name        string
		hazardOwner bool
	}{
		{name: "duty"},
		{name: "hazard", hazardOwner: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, recovery := range []bool{false, true} {
				t.Run(fmt.Sprintf("recovery=%t", recovery), func(t *testing.T) {
					testGeneratedRetainedCurrentReaderFrontierAndReplacement(t, tc.hazardOwner, recovery)
				})
			}
		})
	}
}

func testGeneratedRetainedCurrentReaderFrontierAndReplacement(t *testing.T, hazardOwner, recovery bool) {
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, recovery)
	authority := fixtureID(env.Domain, "recipient")
	reader := fixtureID(env.Domain, "reader")
	currentOnly := fixtureID(env.Domain, "retained frontier current-only reader")
	all := []contract.ID{authority, reader, currentOnly}
	var shared []contract.ID
	for i := 0; i < 62; i++ {
		id := fixtureID(env.Domain, fmt.Sprintf("retained frontier shared reader %02d", i))
		all = append(all, id)
		shared = append(shared, id)
	}
	keys := custody.New(t, contract.GCP, fixtureID(env.Domain, "retained frontier custody"), recovery, all)
	env.Custody, env.Crypto, env.Bindings = keys, keys.Crypto(), keys.Bindings()
	env.AdmitInit, env.RetireInit = keys.AdmitInit, keys.RetireInit
	v1 := append([]contract.ID{authority, reader}, shared...)
	v2 := append([]contract.ID{authority, currentOnly}, shared...)
	for _, set := range [][]contract.ID{v1, v2} {
		slices.SortFunc(set, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	}
	if len(v1) != 64 || len(v2) != 64 {
		t.Fatal("retained frontier recipient shape", len(v1), len(v2))
	}

	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, nil, false)
	v1Input := make([]ApplyEntryInput, 62)
	for i := range v1Input {
		name := fmt.Sprintf("retained-%02d", i)
		v1Input[i] = sharingSecretNamed(t, env, name, "retained frontier V1 "+name, v1)
	}
	run.suppliedSelection(f, v1Input)
	entries, canonical := generatedCurrentDeclaration(t, f.session)
	profile := defaultGeneratedFixtureProfile()
	operation := fixtureID(env.Domain, "retained frontier generated operation")
	names := []string{"omega"}
	if !hazardOwner {
		names = []string{"alpha", "omega"}
	}
	input := generatedPlanInputForGenerations(t, f.session, operation, names, profile, entries...)
	entered, failedAttempt := selectPrivateOwnedUnusableAggregateFromInput(t, env, f.session, names, input, canonical)
	failed := failedAttempt.expected
	finalWork := mustSelectedGeneratedWork(t, entered)
	failedAttempt = finalWork.attempts[failed.Template.AttemptID]
	if failedAttempt.record.AttemptID.IsZero() {
		t.Fatal("retained frontier attempt missing after Final")
	}
	var successful contract.GeneratorResultExpectation
	wantDuties := uint32(0)
	if !hazardOwner {
		succeeded, present := finalWork.attempts[input.requestBindings[0].AttemptID]
		if !present || succeeded.record.State != contract.GeneratedEffectSucceeded {
			t.Fatal("retained frontier succeeded original missing after Final")
		}
		successful = succeeded.expected
		wantDuties = 1
	}
	if entered.root.ValueEntryCount != 62 || entered.root.Generated.Duties != wantDuties || entered.root.Generated.Hazards != 1 || !entered.root.Generated.ActiveOwner.IsZero() {
		t.Fatal("retained frontier nonselecting Final shape", entered.root.ValueEntryCount, entered.root.Generated)
	}
	f.session = entered
	beforeWork, err := entered.preservedWorkSupportRecords(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	v2Input := make([]ApplyEntryInput, 0, 64)
	for i := 0; i < 62; i++ {
		name := fmt.Sprintf("retained-%02d", i)
		v2Input = append(v2Input, sharingSecretNamed(t, env, name, "retained frontier V2 "+name, v2))
	}
	v2Input = append(v2Input,
		sharingSecretNamed(t, env, "supplied-62", "retained frontier supplied 62", v2),
		sharingSecretNamed(t, env, "supplied-63", "retained frontier supplied 63", v2))
	current := run.suppliedSelection(f, v2Input)
	afterWork, err := current.preservedWorkSupportRecords(t.Context())
	if err != nil || !reflect.DeepEqual(beforeWork, afterWork) {
		t.Fatal("retained frontier normal handoff changed accepted work", err)
	}
	g, err := current.selectedGeneratedWork(context.Background())
	if err != nil || len(g.canonical) != 62 || current.root.ValueEntryCount != 64 || current.root.MembershipCount != 4096 {
		t.Fatal("retained frontier selected shape", err, len(g.canonical), current.root.ValueEntryCount, current.root.MembershipCount)
	}
	ownerKind, ownerID := uint8(11), failed.Template.HazardID
	if !hazardOwner {
		ownerKind = 10
		ownerID = successful.Template.DutyID
	}
	ownerRecord, present := g.records[generatedRecordKey{kind: ownerKind, id: ownerID}]
	if !present {
		t.Fatal("retained frontier owner record missing", ownerKind, ownerID)
	}
	if !hazardOwner {
		duty, dutyErr := contract.InspectGeneratedDutyRecord(ownerRecord.Body)
		target, targetErr := g.generatedCleanupTarget(10, ownerID, duty.Target)
		if dutyErr != nil || targetErr != nil || duty.DutyID != ownerID || duty.Kind != contract.GeneratedDutyUnselectedCleanup ||
			duty.Status != contract.GeneratedEffectSucceeded || duty.OriginalOperationID != operation || duty.OriginalAttemptID != successful.Template.AttemptID ||
			duty.ResourceID != successful.Template.ResourceIncarnationID || target.Name != "alpha" || target.ResourceID != successful.Template.ResourceIncarnationID ||
			target.OriginalOperationID != operation || target.OriginalAttemptID != successful.Template.AttemptID {
			t.Fatal("retained frontier cleanup Duty changed exact succeeded sibling", dutyErr, targetErr)
		}
	}
	retainedMemberships := 0
	for sourceID, source := range g.canonical {
		if len(source.record.Entry.Recipients) != 64 {
			t.Fatal("retained frontier source membership", len(source.record.Entry.Recipients))
		}
		expectedSourceID, err := contract.AdmissionEntryDigest(source.record)
		if err != nil || sourceID != expectedSourceID {
			t.Fatal("retained frontier complete-record source identity", err)
		}
		materialContext, contextErr := contract.ValueMaterialContextDigest(source.core)
		wantConsumer := contract.GeneratorConsumer{Schema: 1, OwnerID: ownerID, MaterialID: source.core.ValueStateID,
			ContextDigest: materialContext, SubjectKind: 2, SubjectID: expectedSourceID, Purpose: 2}
		consumers := g.consumers[materialIdentity{kind: 1, id: source.core.ValueStateID}]
		if contextErr != nil || !slices.Contains(consumers, wantConsumer) {
			t.Fatal("retained frontier owner changed a retained V1 consumer", contextErr, len(consumers))
		}
		retainedMemberships += len(source.record.Entry.Recipients)
	}
	if retainedMemberships != 3968 || int(current.root.MembershipCount)+retainedMemberships != 8064 {
		t.Fatal("retained/current membership frontier", current.root.MembershipCount, retainedMemberships)
	}
	// This is an ordinary handoff frontier. Adding a generated output here
	// would exceed the already full 4,096 current membership set.
	valueRows, wraps, accessBytes := 0, 0, 0
	for _, access := range current.accessRecords() {
		if access.MaterialKind != contract.ValueMaterialKind {
			continue
		}
		body, err := contract.EncodeAccessRecord(access)
		if err != nil {
			t.Fatal(err)
		}
		valueRows++
		wraps += len(access.Wraps)
		accessBytes += len(body)
	}
	if valueRows != 126 || wraps != 8064+126*boolInt(recovery) || accessBytes != 3956148+61614*boolInt(recovery) {
		t.Fatal("current/old value access frontier", valueRows, wraps, accessBytes)
	}
	first := current.valueEntry(current.root.Names[slices.IndexFunc(current.root.Names, func(row format.NameEntry) bool { return row.Name == "retained-00" })].Slot)
	retained := canonical[0].Record.Entry
	if first.ValueState == retained.ValueState || bytes.Equal(first.ValueBytes, retained.ValueBytes) {
		t.Fatal("retained frontier did not keep distinct V1 and V2 values")
	}
	if denied, result := current.generatedConsumerSelection(ctx, ownerKind, ownerID, retained.ValueState, currentOnly); result != refused(AdmissionInvalid) || !reflect.DeepEqual(denied, contract.GeneratedCanonicalSelection{}) {
		t.Fatal("current-only reader gained retained V1 authority", result)
	}
	v2Selection := sessionConsumerSelection(t, current, currentOnly, "retained-00")
	if check := keys.Consume(ctx, v2Selection, custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
		t.Fatal("current-only reader could not consume V2", check)
	}
	v1Selection, result := current.generatedConsumerSelection(ctx, ownerKind, ownerID, retained.ValueState, reader)
	if result.Outcome != ObservedCurrent {
		t.Fatal("retained-only reader admission", result)
	}
	if check := keys.ConsumeGenerated(ctx, v1Selection, custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
		t.Fatal("retained-only reader could not consume V1", check)
	}

	unrelated := sessionConsumerSelection(t, current, currentOnly, "retained-01")
	unrelatedEntryBytes, err := contract.EncodeValueEntry(unrelated.Entry)
	if err != nil {
		t.Fatal(err)
	}
	unrelatedAccess, err := contract.EncodeAccessRecord(unrelated.Access)
	if err != nil {
		t.Fatal(err)
	}
	successor := keys.RecipientSuccessor(t, reader)
	keys.LoseRecipientPredecessor(reader)
	if stale := keys.ConsumeGenerated(ctx, v1Selection, custody.StandardValue); stale.Code == contract.CryptoSuccess || stale.Delivery != 0 || stale.SinkCalls != 0 {
		t.Fatal("lost retained-only predecessor still consumed V1", stale)
	}
	permit := admitReaderReplacement(t, current, keys, reader, successor)
	candidate, result := current.PrepareRecipientReplacement(ctx, permit, env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("retained frontier reader replacement preparation", result)
	}
	if result = current.Select(ctx, candidate); result.Outcome != ObservedCurrent {
		t.Fatal("retained frontier reader replacement selection", result)
	}
	keys.RetireAccess()
	if err := keys.ActivateRecipientSuccessor(reader); err != nil {
		t.Fatal(err)
	}
	replaced, result := Open(ctx, f.admission, env.Store)
	if replaced == nil || result.Outcome != ObservedCurrent {
		t.Fatal("retained frontier reader replacement reopen", result)
	}
	afterReplacementWork, err := replaced.preservedWorkSupportRecords(t.Context())
	if err != nil || !reflect.DeepEqual(afterWork, afterReplacementWork) {
		t.Fatal("retained frontier replacement changed accepted work", err)
	}
	afterUnrelated := sessionConsumerSelection(t, replaced, currentOnly, "retained-01")
	afterUnrelatedEntryBytes, entryErr := contract.EncodeValueEntry(afterUnrelated.Entry)
	afterUnrelatedAccess, accessErr := contract.EncodeAccessRecord(afterUnrelated.Access)
	if entryErr != nil || accessErr != nil || !bytes.Equal(unrelatedEntryBytes, afterUnrelatedEntryBytes) || !bytes.Equal(unrelatedAccess, afterUnrelatedAccess) {
		t.Fatal("retained frontier replacement changed unrelated V2 material", entryErr, accessErr)
	}
	successorSelection, result := replaced.generatedConsumerSelection(ctx, ownerKind, ownerID, retained.ValueState, reader)
	if result.Outcome != ObservedCurrent || successorSelection.Selection.Binding.Binding.BindingID != successor.BindingID {
		t.Fatal("retained frontier successor admission", result)
	}
	if check := keys.ConsumeGenerated(ctx, successorSelection, custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
		t.Fatal("retained frontier successor could not consume V1", check)
	}
	checkFreshGeneratedProcess(t, env.Store.(*memoryStore), replaced)

}

// full_only: false
func TestGeneratedRetainedOwnerAliasClosePreservesOther(t *testing.T) {
	ctx := context.Background()
	env, keys := genesisEnvironment(t, contract.GCP, false)
	authority, reader := fixtureID(env.Domain, "recipient"), fixtureID(env.Domain, "reader")
	recipients := []contract.ID{authority, reader}
	slices.SortFunc(recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, nil, false)
	run.suppliedSelection(f, []ApplyEntryInput{sharingSecretNamed(t, env, "shared", "retained alias V1", recipients)})
	v1 := *f.session.valueEntry(0)

	for i := 0; i < 2; i++ {
		entries, canonical := generatedCurrentDeclaration(t, f.session)
		names := []string{fmt.Sprintf("alias-success-%d", i), fmt.Sprintf("alias-failure-%d", i)}
		input := generatedPlanInputForGenerations(t, f.session, fixtureID(env.Domain, fmt.Sprintf("retained alias operation %d", i)), names,
			defaultGeneratedFixtureProfile(), entries...)
		f.session, _ = selectPrivateOwnedUnusableAggregateFromInput(t, env, f.session, names, input, canonical)
		f.session = generatedLifecycleReopen(t, ctx, f.session, env.Store)
	}

	beforeHandoff, err := f.session.preservedWorkSupportRecords(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	v2 := []ApplyEntryInput{suppliedSecret(t, env, "shared", "retained alias V2", custody.EmptyValue)}
	parent := admitSuppliedComparison(t, f.session, keys, v2)
	comparison, result := f.session.Compare(ctx, v2, parent)
	if comparison == nil {
		t.Fatal("retained alias handoff comparison", result)
	}
	candidate, result := f.session.Prepare(ctx, comparison, admit(t, f.session, comparison), env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("retained alias handoff preparation", result)
	}
	selected, result := f.session.selectCandidate(ctx, candidate)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("retained alias handoff selection", result)
	}
	keys.RetireApply()
	selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
	afterHandoff, err := selected.preservedWorkSupportRecords(t.Context())
	if err != nil || !reflect.DeepEqual(beforeHandoff, afterHandoff) {
		t.Fatal("retained alias handoff changed accepted work", err)
	}
	if current := selected.valueEntry(0); current.ValueState == v1.ValueState || bytes.Equal(current.ValueBytes, v1.ValueBytes) {
		t.Fatal("retained alias handoff did not select distinct V2 material")
	}

	work := mustSelectedGeneratedWork(t, selected)
	selection, ok, selectErr := work.selectGeneratedCleanup(context.Background(), nil)
	consumers := work.consumers[materialIdentity{kind: 1, id: v1.ValueState}]
	remainingIndex := slices.IndexFunc(consumers, func(row contract.GeneratorConsumer) bool { return row.OwnerID != selection.duty.DutyID })
	if selectErr != nil || !ok || selection.kind != generatedCleanupDuty || len(consumers) != 2 || remainingIndex < 0 {
		t.Fatal("retained alias owner shape", selectErr, ok, selection.kind, len(consumers))
	}
	remainingConsumer := consumers[remainingIndex]
	remainingKind := uint8(10)
	beforeOwner, present := work.records[generatedRecordKey{kind: remainingKind, id: remainingConsumer.OwnerID}]
	if !present {
		remainingKind = 11
		beforeOwner, present = work.records[generatedRecordKey{kind: remainingKind, id: remainingConsumer.OwnerID}]
	}
	beforeAccess, accessPresent := selected.materialAccess(1, v1.ValueState)
	beforeAccessBody, accessErr := contract.EncodeAccessRecord(beforeAccess)
	if !present || !accessPresent || accessErr != nil {
		t.Fatal("retained alias close baseline", present, accessPresent, accessErr)
	}

	deleteStore := &generatedCleanupDeleteStore{memoryStore: env.Store.(*memoryStore)}
	closed := closeAndReleaseActualCleanup(t, env, selected, deleteStore, selection.attempt, 10, selection.duty.DutyID, 0)
	after := mustSelectedGeneratedWork(t, closed)
	afterOwner, present := after.records[generatedRecordKey{kind: remainingKind, id: remainingConsumer.OwnerID}]
	afterAccess, accessPresent := closed.materialAccess(1, v1.ValueState)
	afterAccessBody, accessErr := contract.EncodeAccessRecord(afterAccess)
	if !present || !bytes.Equal(beforeOwner.Body, afterOwner.Body) || !accessPresent || accessErr != nil ||
		!bytes.Equal(beforeAccessBody, afterAccessBody) ||
		!slices.Contains(after.consumers[materialIdentity{kind: 1, id: v1.ValueState}], remainingConsumer) {
		t.Fatal("closing one retained alias changed the other owner or access", present, accessPresent, accessErr)
	}
	remaining, result := closed.generatedConsumerSelection(ctx, remainingKind, remainingConsumer.OwnerID, v1.ValueState, reader)
	if result.Outcome != ObservedCurrent {
		t.Fatal("retained alias surviving reader admission", result)
	}
	if check := keys.ConsumeGenerated(ctx, remaining, custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
		t.Fatal("retained alias surviving reader failed after one close", check)
	}
}

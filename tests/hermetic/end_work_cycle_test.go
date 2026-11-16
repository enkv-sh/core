package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

func missingResultParentExitCycle(t *testing.T, operationCtx context.Context, env fixtureEnvironment, current *StateSession, iteration int) *StateSession {
	t.Helper()
	ctx := t.Context()
	store, keys := env.Store.(*memoryStore), env.Custody
	old := *current.valueEntry(0)
	operation := fixtureID(current.root.Domain, fmt.Sprintf("missing result operation %d", iteration))
	profile := defaultGeneratedFixtureProfile()
	incarnations, retiring := map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: old}
	input := generatedStatePlanInput(t, current, operation, []string{old.Name}, profile, old.Generated.Epoch+1, incarnations, retiring)
	intent := hermeticGeneratorIntent([]byte(fmt.Sprintf(`{"cycle":%d}`, iteration)))
	replacement := generatedReservationInputForStateIntent(t, current, operation, []string{old.Name}, intent, profile, old.Generated.Epoch+1, incarnations, retiring)
	input.graph, input.declaration, input.registry, input.recoveryPolicy, input.requestBindings = replacement.graph, replacement.declaration,
		replacement.graph.Request.Registry, replacement.graph.Request.RecoveryPolicyID, slices.Clone(replacement.requestBindings)
	prior, _ := preparePrivateGeneratedReservation(t, env, current, input, nil)
	producer, expected := preparePrivateGeneratedProducer(t, env, current, prior, nil)
	var packet []byte
	calls := 0
	if !producer.reservation.candidate.bindFirstSend(producer, func(dispatch context.Context, authority contract.ID) contract.CryptoResultCode {
		calls++
		var code contract.CryptoResultCode
		packet, _, code = keys.InvokeGeneratedProducer(dispatch, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		return code
	}) {
		t.Fatal("cycle first-send binding")
	}
	entered, result := current.selectCandidate(ctx, producer.reservation.candidate)
	if entered == nil || result.Outcome != ObservedCurrent || len(packet) == 0 || calls != 1 {
		t.Fatal("cycle real producer return", result)
	}
	admission, locator, authority := producer.operation.context.AdmissionID, producer.producerLocator, producer.reservation.candidate.generated.authority
	keys.RetireGenerated()
	producer = nil
	before := generatedLifecycleReopen(t, operationCtx, entered, store)
	work := mustSelectedGeneratedWork(t, before)
	attempt := work.attempts[expected.Template.AttemptID]
	inbox, err := format.GeneratedResultKey(store.desc.Prefix, before.root.Domain, attempt.record.InboxID)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := store.objects[inbox]; present || len(before.adminIndex.Groups) != 2 || work.parent == nil || work.parent.OperationID != operation ||
		work.phase == nil || len(work.attempts) != 1 || work.parent.MaterialID != input.graph.Header.MaterialID || old.Generated.IntentDigest == expected.Template.IntentDigest {
		t.Fatal("cycle is not one entered original with a distinct lost Intent and no Inbox")
	}
	var target format.AdministrativeGroup
	for _, group := range before.adminIndex.Groups {
		if group.GroupID == operation {
			target = group
		} else if group.GroupID != expected.Template.DutyID {
			t.Fatal("cycle includes an unrelated owner")
		}
	}
	if target.OwnerKind != format.AdministrativeGeneratedParent || target.OwnerID != operation || target.TargetID != operation {
		t.Fatal("cycle parent is not the declared operation")
	}
	oldWork := mustSelectedGeneratedWork(t, current)
	oldIntent, err := oldWork.readSelectedSlice(ctx, contract.GeneratorContentIntent, old.Generated.IntentDigest, contract.GeneratorIntentMaxLength)
	if err != nil {
		t.Fatal(err)
	}
	oldEvidence := bytes.Clone(oldWork.records[generatedRecordKey{contract.GeneratedCreateEvidenceSupportKind, old.Generated.CreateResultID}].Body)
	windows, err := before.receiptWindows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	admin, result := openAdministrative(ctx, OpenContext{admission: &before.admission}, store)
	if admin == nil || result.Outcome != ObservedCurrent {
		t.Fatal("cycle administrative cold Open", result)
	}
	public, private := keys.Calls()
	cas := store.cas
	candidate, result := prepareTestEndSelectedWork(t, admin, ctx, operation, env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent || candidate.firstSend != nil || store.cas != cas {
		t.Fatal("cycle parent EndWork preparation", result)
	}
	selected, result := admin.selectCandidate(ctx, candidate)
	if selected == nil || result.Outcome != ObservedCurrent || store.cas != cas+1 {
		t.Fatal("cycle parent EndWork selection", result)
	}
	after := generatedLifecycleReopen(t, operationCtx, selected, store)
	if p, k := keys.Calls(); p != public || k != private || calls != 1 {
		t.Fatal("cycle exit invoked a key route or sent again")
	}
	kept := mustSelectedGeneratedWork(t, after)
	if !reflect.DeepEqual(after.valueEntry(0), &old) || !reflect.DeepEqual(after.currentEntryInputs(), current.currentEntryInputs()) ||
		!reflect.DeepEqual(after.accessRecords(), current.accessRecords()) || !reflect.DeepEqual(after.root.ValueEntryPages, current.root.ValueEntryPages) ||
		!reflect.DeepEqual(after.root.Names, current.root.Names) || !reflect.DeepEqual(after.root.Recipients, current.root.Recipients) ||
		len(after.adminIndex.Groups) != 0 || kept.parent != nil || kept.phase != nil || len(kept.attempts) != 0 || len(kept.bundles) != 0 ||
		after.root.Generated.Attempts != 0 || after.root.Generated.Duties != 0 || after.root.Generated.Hazards != 0 || after.root.Generated.Materials != 0 ||
		after.root.Generated.Results != 0 || after.root.Generated.PendingReleases != 0 || after.root.Generated.GeneratedCurrent != 1 || after.root.Generated.Retiring != 0 {
		t.Fatal("cycle kept exclusive generated closure or changed exact current state/access")
	}
	gotIntent, err := kept.readSelectedSlice(ctx, contract.GeneratorContentIntent, old.Generated.IntentDigest, contract.GeneratorIntentMaxLength)
	if err != nil || !bytes.Equal(gotIntent, oldIntent) || !bytes.Equal(kept.records[generatedRecordKey{contract.GeneratedCreateEvidenceSupportKind, old.Generated.CreateResultID}].Body, oldEvidence) || len(kept.content.locations) != 1 {
		t.Fatal("cycle changed current Intent/evidence or kept exclusive content", err)
	}
	if _, present := after.materialAccess(contract.OperationSeedMaterialKind, input.graph.Header.MaterialID); present {
		t.Fatal("cycle retained discarded operation seed access")
	}
	ids := []contract.ID{operation, expected.Template.DutyID}
	slices.SortFunc(ids, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	body := binary.BigEndian.AppendUint32(nil, 2)
	for _, id := range ids {
		body = binary.BigEndian.AppendUint32(body, 32)
		body = append(body, id[:]...)
	}
	dependent := contract.GeneratorDescriptor{Digest: contract.ID(sha256.Sum256(append([]byte("ENKV/admin-descriptor/v1/ended-groups\x00"), body...))), Length: 76, Count: 2}
	warning := before.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningPossibleStoreGarbage
	q := after.head.EndWork
	if q == nil || q.TargetGroupID != operation || q.TargetOwnerID != operation || q.TargetID != operation || q.TargetKind != target.OwnerKind || q.SelectedEvidenceSummary != target.SelectedEvidenceSummary ||
		q.DependentGroups != dependent || q.PredecessorRevisionID != before.head.Core.Revision || q.PredecessorFullHEADDigest != contract.Hash(before.body) || q.PredecessorToken != before.token ||
		q.BeforeWarningBits != before.root.WarningBits || q.AfterWarningBits != warning || after.root.WarningBits != warning {
		t.Fatal("cycle exit changed exact parent scope, predecessor or warnings")
	}
	got, err := after.receiptWindows(ctx)
	if err != nil || len(got.Successes) == 0 {
		t.Fatal("cycle receipt window", err)
	}
	r := got.Successes[len(got.Successes)-1]
	if r.OperationID != q.OperationID || r.OperationKind != contract.OperationEndSelectedWork || r.StateResult != contract.ReceiptStateWorkEnded || r.CanonicalOutcome != contract.ReceiptCanonicalSelected ||
		r.EffectSummary != contract.ReceiptEffectNotApplicable || r.AdministrativeTargetKind != target.OwnerKind || r.AdministrativeTargetID != operation || r.AdministrativeOriginalEvidence != target.SelectedEvidenceSummary ||
		r.WarningBits != uint64(warning) || r.AdministrativeWarningChanges != warning&^before.root.WarningBits || r.PredecessorRevisionID != before.head.Core.Revision || r.ObservedRevisionID != after.head.Core.Revision {
		t.Fatal("cycle selected a different administrative receipt")
	}
	want := append(slices.Clone(windows.Successes), r)
	if len(want) > 256 {
		want = want[len(want)-256:]
	}
	if !slices.Equal(got.Successes, want) || !slices.Equal(got.Failures, windows.Failures) {
		t.Fatal("cycle changed append/trim order or failure receipts")
	}
	assertSuccessReceiptOrder(t, windows, got, r.OperationID)
	context := generatedPlanInputFixture(t, after).context
	context.AdmissionID, context.SessionID = fixtureID(after.root.Domain, fmt.Sprintf("cycle old-rights admission %d", iteration)), fixtureID(after.root.Domain, fmt.Sprintf("cycle old-rights session %d", iteration))
	reads, creates := store.reads, store.creates
	selectedHead := store.objects[store.desc.HeadKey]
	selectedBody, selectedToken := bytes.Clone(selectedHead.Body), selectedHead.Token
	allowedReads := make(map[string]bool)
	currentBlob := kept.content.locations[generatedContentKey{kind: contract.GeneratorContentIntent, id: old.Generated.IntentDigest}].BlobID
	for _, fact := range after.fragmentFacts {
		if fact.blob == currentBlob {
			key, err := format.Key(store.desc.Prefix, fact.ref)
			if err != nil || key == inbox {
				t.Fatal("current fragment read set includes the old Inbox", err)
			}
			allowedReads[key] = true
		}
	}
	if len(allowedReads) != 1 {
		t.Fatal("small current Intent does not have one exact authenticated fragment page")
	}
	store.readHook = func(key string, reply contract.ReadResult) contract.ReadResult {
		if !allowedReads[key] {
			t.Error("stale owner query read outside current Intent", key)
		}
		return reply
	}
	defer func() { store.readHook = nil }()
	if plan, err := after.generatedRecordRequest(ctx, expected.Template.AttemptID, packet, context); plan != nil || !errors.Is(err, contract.ErrRecord) {
		t.Fatal("cycle restored discarded Record rights", err)
	}
	if plan, err := after.generatedFinalRequest(ctx, context); plan != nil || !errors.Is(err, contract.ErrRecord) {
		t.Fatal("cycle restored discarded Final rights", err)
	}
	if packet, present, result := after.ReadGeneratedResult(ctx, expected.Template.AttemptID); len(packet) != 0 || present || result != refused(AdmissionInvalid) {
		t.Fatal("cycle restored original Inbox rights", result)
	}
	if result := after.persistGeneratedResult(ctx, generatedResultWrite{attempt: expected.Template.AttemptID, body: packet}); result != refused(AdmissionInvalid) || store.reads-reads > 4 || store.creates != creates || store.cas != cas+1 {
		t.Fatal("cycle stale rights reached Store", result)
	}
	if head := store.objects[store.desc.HeadKey]; head.Token != selectedToken || !bytes.Equal(head.Body, selectedBody) || !bytes.Equal(after.body, selectedBody) {
		t.Fatal("cycle stale rights changed selected HEAD")
	}
	store.readHook = nil
	if body, _, code := keys.InvokeGeneratedProducer(ctx, admission, locator, authority); code == contract.CryptoSuccess || len(body) != 0 || calls != 1 {
		t.Fatal("cycle restored a producer send", code)
	}
	if _, present := store.objects[inbox]; present {
		t.Fatal("cycle created its discarded original Inbox")
	}
	check := keys.Consume(ctx, sessionConsumerSelection(t, after, after.admission.recipient, old.Name), custody.StandardValue)
	if check.Code != contract.CryptoSuccess || !check.ValueMatched || check.SinkCalls != 1 {
		t.Fatal("cycle retained current value is not privately usable", check)
	}
	return after
}

// full_only: false
func TestEndWorkDiscardsActualDeleteHistoryBeyondSmallVectorBarrier(t *testing.T) {
	ctx := t.Context()
	captured := make(map[contract.ID][]byte)
	t.Cleanup(func() { t.Logf("actual Delete packets completed before terminal: %d", len(captured)) })
	env, before, original, packet := generatedAuthenticatedDeleteHazardFixtureForProfile(t, ctx, false, 60, defaultGeneratedFixtureProfile(), captured)
	before = generatedLifecycleReopen(t, ctx, before, env.Store)
	work := mustSelectedGeneratedWork(t, before)
	hazardID := work.deleteHazards[original.record.AttemptID]
	if hazardID.IsZero() {
		t.Fatal("original Delete has no selected detached Hazard owner")
	}
	row := work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, hazardID}]
	hazard, err := contract.InspectGeneratedHazardRecord(row.Body)
	if err != nil || len(captured) != 61 || len(work.attempts) != 61 || len(work.deleteHazards) != 61 || len(before.adminIndex.Groups) != 1 ||
		hazard.HazardID != hazardID || hazard.History.Count != 61 || hazard.History.Length != 4+61*(4+contract.GeneratorHistoryLength) ||
		hazard.Consumers.Count != 61 || hazard.OriginalResults.Count != 0 || !bytes.Equal(packet, captured[original.record.ResultID]) {
		t.Fatal("61 real Delete packets did not form one selected detached Hazard history", err)
	}
	history, err := work.vectors.resolve(contract.GeneratedHazardSupportKind, hazardID, contract.GeneratorVectorHistory, hazard.History)
	if err != nil || len(history) != 61 {
		t.Fatal("61-row authenticated Delete history", err)
	}
	store := env.Store.(*memoryStore)
	seenOperations := make(map[contract.ID]bool, 61)
	removedMaterials := make([]contract.ID, 0, 61)
	for i, body := range history {
		item, err := contract.InspectGeneratorHistory(body)
		attempt, ok := work.attempts[item.PredecessorAttemptID]
		if err != nil || !ok || seenOperations[attempt.record.OperationID] || len(captured[attempt.record.ResultID]) == 0 || len(attempt.result) != 0 ||
			item.OwnerID != hazard.OwnerID || item.Outcome != attempt.record.State || !item.ResultID.IsZero() || !item.ResultDigest.IsZero() ||
			work.deleteHazards[item.PredecessorAttemptID] != hazardID {
			t.Fatal("Delete history row is not an independently entered unresolved original", i, err)
		}
		seenOperations[attempt.record.OperationID] = true
		removedMaterials = append(removedMaterials, attempt.material.Core.OperationMaterialID)
		inbox, err := format.GeneratedResultKey(store.desc.Prefix, before.root.Domain, attempt.record.InboxID)
		if err != nil {
			t.Fatal(err)
		}
		if _, present := store.objects[inbox]; present {
			t.Fatal("unselected Delete packet was placed in its old Inbox", i)
		}
		if i+1 < len(history) {
			next, err := contract.InspectGeneratorHistory(history[i+1])
			if err != nil || item.NextAttemptID != next.PredecessorAttemptID || item.Edge != 4 {
				t.Fatal("Delete history lost its exact successor edge", i, err)
			}
		} else if !item.NextAttemptID.IsZero() || item.Edge != 0 {
			t.Fatal("last Delete history row has a fabricated successor")
		}
	}
	carrierCount, carrierCharge := 0, 0
	for _, row := range work.records {
		if row.Kind != contract.GeneratorVectorSupportKind {
			continue
		}
		carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			t.Fatal(err)
		}
		if carrier.OwnerKind == contract.GeneratedHazardSupportKind && carrier.OwnerID == hazardID && carrier.VectorKind == contract.GeneratorVectorHistory {
			carrierCount++
			carrierCharge += contract.SupportRecordOverhead + len(row.Body)
		}
	}
	if carrierCount != 61 || carrierCharge != 61*(contract.SupportRecordOverhead+contract.GeneratorCarrierFixedLength+contract.GeneratorHistoryLength) || carrierCharge <= 16*1024 {
		t.Fatal("actual selected History carriers did not cross the old 16 KiB boundary", carrierCount, carrierCharge)
	}
	assertEndWorkSelectedDeletePermissionCount(t, before, 61)
	warning := before.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningLateDestructiveEffect | WarningPossibleStoreGarbage
	after := endGeneratedObligation(t, ctx, env, before, hazardID, []contract.ID{hazardID}, before.currentEntryInputs(), warning, removedMaterials...)
	kept := mustSelectedGeneratedWork(t, after)
	if len(after.adminIndex.Groups) != 0 || len(kept.attempts) != 0 || len(kept.deleteHazards) != 0 || after.root.Generated.Hazards != 0 ||
		after.root.Generated.Attempts != 0 || after.root.Generated.Materials != 0 || after.root.Generated.Graphs.Count != 0 || after.root.Generated.GeneratedCurrent != 1 {
		t.Fatalf("History exit closure groups=%d attempts=%d owners=%d hazards=%d attemptRows=%d materials=%d graphs=%d current=%d",
			len(after.adminIndex.Groups), len(kept.attempts), len(kept.deleteHazards), after.root.Generated.Hazards,
			after.root.Generated.Attempts, after.root.Generated.Materials, after.root.Generated.Graphs.Count, after.root.Generated.GeneratedCurrent)
	}
	current := after.valueEntry(0)
	if current == nil || current.ValueSource != contract.Generated {
		t.Fatal("History exit lost the independently selected generated current value")
	}
	check := env.Custody.Consume(ctx, sessionConsumerSelection(t, after, after.admission.recipient, current.Name), custody.StandardValue)
	if check.Code != contract.CryptoSuccess || !check.ValueMatched || check.SinkCalls != 1 {
		t.Fatal("History exit current value is not privately usable", check)
	}
}

func assertSelectedReceiptIndexFragment(t *testing.T, current *StateSession, windows contract.MutationReceiptWindows, count int) {
	t.Helper()
	if len(windows.Successes) != count || len(windows.Failures) != 0 {
		t.Fatal("receipt index fixture has a different window", len(windows.Successes), len(windows.Failures))
	}
	indexes, err := windows.Indexes()
	if err != nil {
		t.Fatal("receipt indexes", err)
	}
	indexBody, err := contract.EncodeMutationReceiptIndexes(indexes)
	if err != nil || len(indexBody) != 26+72*count {
		t.Fatal("receipt index encoded length", len(indexBody), err)
	}
	blob, err := contract.MutationReceiptIndexBlobID(current.root.Domain, current.root.Generated.SuccessWindow, current.root.Generated.FailureWindow, current.root.Generated.ReceiptOrder)
	if err != nil {
		t.Fatal("receipt index identity", err)
	}
	fragmentID, err := contract.GeneratorFragmentID(blob, 0)
	if err != nil {
		t.Fatal("receipt fragment identity", err)
	}
	matched := 0
	for _, location := range current.root.Generated.Fragments {
		if location.BlobID != blob || location.FragmentIndex != 0 {
			continue
		}
		for _, page := range current.support {
			if page.Index != location.SupportPageIndex {
				continue
			}
			var ref *format.Ref
			for i := range current.root.RequiredSupport {
				if current.root.RequiredSupport[i].Index == page.Index {
					ref = &current.root.RequiredSupport[i]
					break
				}
			}
			if ref == nil || len(page.Records) != 1 || int(location.RowSlot) >= len(page.Records) {
				t.Fatal("receipt fragment has no one-row physical support page")
			}
			row := page.Records[location.RowSlot]
			fact, present := current.fragmentFacts[location]
			// Full success window: 75+37+86+26+72*256 = 18,656 physical bytes.
			if !present || row.Kind != contract.GeneratedFragmentSupportKind || row.RecordID != fragmentID ||
				fact.ref != *ref || fact.row.Kind() != contract.GeneratedFragmentSupportKind || fact.row.RecordID() != fragmentID ||
				fact.blob != blob || fact.index != 0 || fact.count != 1 || fact.total != uint64(len(indexBody)) ||
				fact.whole != contract.Hash(indexBody) || fact.payloadLength != uint32(len(indexBody)) ||
				ref.Length != uint32(contract.RequiredSupportPageHeaderLength+contract.SupportRecordOverhead+contract.GeneratedFragmentHeaderLength+len(indexBody)) ||
				count == 256 && ref.Length != 18656 {
				t.Fatal("receipt fragment metadata or exact physical page charge changed")
			}
			called := false
			result, err := current.withSelectedFragment(t.Context(), location, func(payload []byte) error {
				called = true
				if !bytes.Equal(payload, indexBody) {
					return contract.ErrRecord
				}
				return nil
			})
			if result.Outcome != 0 || err != nil || !called {
				t.Fatal("receipt index payload is not the authenticated selected fragment", result, err)
			}
			matched++
		}
	}
	if matched != 1 {
		t.Fatal("receipt index has no unique selected physical fragment", matched)
	}
}

// full_only: false
func TestEndWorkMissingResultPreservesCurrentProgress(t *testing.T) {
	t.Run("one_cycle", func(t *testing.T) {
		ctx := t.Context()
		env, _ := genesisEnvironment(t, contract.GCP, false)
		env.Context = ctx
		f := newEnvironmentFixture(t, ctx, env, nil, false)
		initializationOperation, initialized := observedHeadOperation(f.session.head)
		if !initialized || f.session.head.AuthKind != format.GenesisAuth {
			t.Fatal("cycle fixture does not start at its exact initialization")
		}
		input := generatedPlanInputForGenerations(t, f.session, fixtureID(env.Domain, "cycle initial operation"), []string{"generated"}, defaultGeneratedFixtureProfile())
		current := selectPrivateGeneratedOperationInProcess(t, env, f.session, input, "cycle initial")
		current = generatedLifecycleReopen(t, ctx, current, env.Store)
		initial, err := current.receiptWindows(ctx)
		initialOrder := []contract.ID{initializationOperation, input.graph.Header.OperationID}
		var initialKinds [2]uint16
		for i := range min(len(initial.Successes), len(initialKinds)) {
			initialKinds[i] = initial.Successes[i].OperationKind
		}
		if err != nil || len(initial.Successes) != 2 || len(initial.Failures) != 0 || initialKinds != [2]uint16{contract.OperationInitializeDomain, contract.OperationApplyDeclaration} || !slices.Equal(initial.Order, initialOrder) {
			t.Fatal("cycle fixture does not retain initialization then generated success", err,
				"lengths", [3]int{len(initial.Successes), len(initial.Failures), len(initial.Order)}, "kinds", initialKinds, "order_equal", slices.Equal(initial.Order, initialOrder))
		}
		after := missingResultParentExitCycle(t, ctx, env, current, 1)
		windows, err := after.receiptWindows(ctx)
		if err != nil {
			t.Fatal("one-cycle receipt window", err)
		}
		assertSelectedReceiptIndexFragment(t, after, windows, 3)
		t.Logf("cycle selected rows=%d support pages=%d child pages=%d child bytes=%d", after.root.RequiredSupportRecordCount, len(after.root.RequiredSupport), after.root.ChildCount, after.root.ChildEncodedBytes)
		fresh := freshGeneratedAfterObligationExit(t, ctx, env, after, "cycle short fresh progress")
		retiringID := fresh.valueEntry(0).Generated.RetiringDutyID
		if retiringID.IsZero() || len(fresh.adminIndex.Groups) != 1 || fresh.adminIndex.Groups[0].GroupID != retiringID {
			t.Fatal("short generated progress has no exact retirement Duty")
		}
		admin, result := openAdministrative(ctx, OpenContext{admission: &fresh.admission}, env.Store)
		if admin == nil || result.Outcome != ObservedCurrent {
			t.Fatal("short retirement administrative Open", result)
		}
		candidate, result := prepareTestEndSelectedWork(t, admin, ctx, retiringID, env.Trust)
		if candidate == nil || result.Outcome != ObservedCurrent {
			t.Fatal("short retirement Duty preparation", result)
		}
		selected, result := admin.selectCandidate(ctx, candidate)
		if selected == nil || result.Outcome != ObservedCurrent {
			t.Fatal("short retirement Duty selection", result)
		}
		fresh = generatedLifecycleReopen(t, ctx, selected, env.Store)
		if fresh.adminIndex.SliceSnapshot == fresh.root.Snapshot {
			t.Fatal("retirement Duty exit did not retain a distinct authenticated Slice owner")
		}
		run := newScenarioRun(t, ctx, env)
		wrapped := *fresh
		wrapped.store = run.env.Store
		fixture := &environmentFixture{admission: OpenContext{admission: &fresh.admission}, session: &wrapped}
		secret := suppliedSecret(t, env, "secret", "cycle post-exit supplied secret", custody.StandardValue)
		supplied := run.suppliedSelection(fixture, append(fresh.currentEntryInputs(), secret))
		if supplied.root.SecretCount != fresh.root.SecretCount+1 || supplied.root.WarningBits&fresh.root.WarningBits != fresh.root.WarningBits {
			t.Fatal("short supplied progress lost the retained generated Secret or exit warning")
		}
		for _, name := range []string{"generated", "secret"} {
			check := env.Custody.Consume(ctx, sessionConsumerSelection(t, supplied, supplied.admission.recipient, name), custody.StandardValue)
			if check.Code != contract.CryptoSuccess || !check.ValueMatched || check.SinkCalls != 1 {
				t.Fatal("short supplied progress lost current Secret consumption", name, check)
			}
		}
	})

}

// full_only: true
// The real maximum backlog/history complements the small behavior cases.
func TestEndWorkRepeatedMissingResultsFullWindowPreservesCurrentProgress(t *testing.T) {
	t.Run("full_window_and_fresh_progress", func(t *testing.T) {
		ctx := t.Context()
		env, _ := genesisEnvironment(t, contract.GCP, false)
		env.Context = ctx
		f := newEnvironmentFixture(t, ctx, env, nil, false)
		initializationOperation, initialized := observedHeadOperation(f.session.head)
		if !initialized || f.session.head.AuthKind != format.GenesisAuth {
			t.Fatal("cycle fixture does not start at its exact initialization")
		}
		input := generatedPlanInputForGenerations(t, f.session, fixtureID(env.Domain, "cycle full-window initial operation"), []string{"generated"}, defaultGeneratedFixtureProfile())
		current := selectPrivateGeneratedOperationInProcess(t, env, f.session, input, "cycle full-window initial")
		current = generatedLifecycleReopen(t, ctx, current, env.Store)
		initial, err := current.receiptWindows(ctx)
		initialOrder := []contract.ID{initializationOperation, input.graph.Header.OperationID}
		var initialKinds [2]uint16
		for i := range min(len(initial.Successes), len(initialKinds)) {
			initialKinds[i] = initial.Successes[i].OperationKind
		}
		if err != nil || len(initial.Successes) != 2 || len(initial.Failures) != 0 || initialKinds != [2]uint16{contract.OperationInitializeDomain, contract.OperationApplyDeclaration} || !slices.Equal(initial.Order, initialOrder) {
			t.Fatal("cycle fixture does not retain initialization then generated success", err,
				"lengths", [3]int{len(initial.Successes), len(initial.Failures), len(initial.Order)}, "kinds", initialKinds, "order_equal", slices.Equal(initial.Order, initialOrder))
		}
		initialEntry := *current.valueEntry(0)
		initialIntent, err := mustSelectedGeneratedWork(t, current).readSelectedSlice(ctx, contract.GeneratorContentIntent, initialEntry.Generated.IntentDigest, contract.GeneratorIntentMaxLength)
		if err != nil {
			t.Fatal(err)
		}
		exitIDs := make([]contract.ID, 0, 258)
		var plateauRows uint32
		var plateauChildBytes uint64
		var plateauChildCount uint32
		var plateauSupportBytes uint64
		var plateauSupportPages int
		for i := 1; i <= 258; i++ {
			current = missingResultParentExitCycle(t, ctx, env, current, i)
			exitIDs = append(exitIDs, current.head.EndWork.OperationID)
			if i != 1 && i != 253 && i != 254 && i != 255 && i != 256 && i != 257 && i != 258 {
				continue
			}
			var supportBytes uint64
			for _, ref := range current.root.RequiredSupport {
				supportBytes += uint64(ref.Length)
			}
			t.Logf("cycle %d rows=%d support pages=%d support bytes=%d child pages=%d child bytes=%d",
				i, current.root.RequiredSupportRecordCount, len(current.root.RequiredSupport), supportBytes, current.root.ChildCount, current.root.ChildEncodedBytes)
			if i == 254 {
				plateauRows, plateauChildBytes, plateauChildCount, plateauSupportBytes, plateauSupportPages = current.root.RequiredSupportRecordCount,
					current.root.ChildEncodedBytes, uint32(current.root.ChildCount), supportBytes, len(current.root.RequiredSupport)
			}
			if i >= 255 && (current.root.RequiredSupportRecordCount != 261 || current.root.RequiredSupportRecordCount != plateauRows ||
				current.root.ChildEncodedBytes != plateauChildBytes || uint32(current.root.ChildCount) != plateauChildCount ||
				supportBytes != plateauSupportBytes || len(current.root.RequiredSupport) != plateauSupportPages) {
				t.Fatal("full-window selected rows and physical support/child charges did not plateau")
			}
		}
		if !reflect.DeepEqual(*current.valueEntry(0), initialEntry) {
			t.Fatal("repeated parent exits changed the fixed current entry")
		}
		finalIntent, err := mustSelectedGeneratedWork(t, current).readSelectedSlice(ctx, contract.GeneratorContentIntent, initialEntry.Generated.IntentDigest, contract.GeneratorIntentMaxLength)
		if err != nil || !bytes.Equal(finalIntent, initialIntent) {
			t.Fatal("repeated exits changed the fixed current Intent", err)
		}
		windows, err := current.receiptWindows(ctx)
		if err != nil || len(windows.Successes) != 256 || len(windows.Failures) != 0 || len(exitIDs) != 258 || !slices.Equal(windows.Order, exitIDs[2:]) {
			t.Fatal("full receipt window did not retain exactly the latest 256 successes", err)
		}
		for i, receipt := range windows.Successes {
			if receipt.OperationID != exitIDs[i+2] || receipt.OperationKind != contract.OperationEndSelectedWork || receipt.StateResult != contract.ReceiptStateWorkEnded {
				t.Fatal("full receipt window retained an evicted or non-exit receipt", i)
			}
		}
		families := make(map[contract.SupportRecordKind]int)
		receiptPages := 0
		for _, page := range current.support {
			count := 0
			for _, row := range page.Records {
				families[row.Kind]++
				if row.Kind == contract.MutationReceiptSupportKind {
					count++
				}
			}
			if count == 0 {
				continue
			}
			receiptPages++
			want := contract.RequiredSupportPageHeaderLength + 256*(contract.SupportRecordOverhead+contract.CompactMutationReceiptLength)
			var ref *format.Ref
			for i := range current.root.RequiredSupport {
				if current.root.RequiredSupport[i].Index == page.Index {
					ref = &current.root.RequiredSupport[i]
					break
				}
			}
			if count != 256 || ref == nil || ref.Length != uint32(want) {
				t.Fatal("full receipt page has a different exact selected physical charge", count, page.Index)
			}
		}
		assertSelectedReceiptIndexFragment(t, current, windows, 256)
		if receiptPages != 1 || len(families) != 5 || families[contract.GeneratedCreateEvidenceSupportKind] != 1 ||
			families[contract.GeneratedFragmentSupportKind] != 2 || families[contract.GeneratorVectorSupportKind] != 1 ||
			families[contract.MutationReceiptSupportKind] != 256 || families[contract.OutputConfigurationSliceSupportKind] != 1 || current.root.RequiredSupportRecordCount != 261 {
			t.Fatal("full receipt window differs from the one-current 261-row index shape", families)
		}
		fresh := freshGeneratedAfterObligationExit(t, ctx, env, current, "cycle full-window generated progress")
		if fresh.root.WarningBits&current.root.WarningBits != current.root.WarningBits {
			t.Fatal("fresh generated work cleared permanent exit warnings")
		}
		retiringID := fresh.valueEntry(0).Generated.RetiringDutyID
		if fresh.valueEntry(0).Generated.RetiringDutyPresent != 1 || retiringID.IsZero() || len(fresh.adminIndex.Groups) != 1 ||
			fresh.adminIndex.Groups[0].GroupID != retiringID || fresh.adminIndex.Groups[0].OwnerKind != format.AdministrativeGeneratedDuty {
			t.Fatal("fresh generated progress did not retain one real retirement Duty")
		}
		retiringTarget := fresh.adminIndex.Groups[0]
		priorEntry := *fresh.valueEntry(0)
		priorAccess := slices.Clone(fresh.accessRecords())
		priorWindows, err := fresh.receiptWindows(ctx)
		if err != nil || len(priorWindows.Successes) != 256 || len(priorWindows.Failures) != 0 {
			t.Fatal("fresh generated progress did not retain a full receipt window", err)
		}
		assertEndWorkSelectedDeletePermissionCount(t, fresh, 0)
		admin, result := openAdministrative(ctx, OpenContext{admission: &fresh.admission}, env.Store)
		if admin == nil || result.Outcome != ObservedCurrent {
			t.Fatal("fresh retirement administrative Open", result)
		}
		public, private := env.Custody.Calls()
		candidate, result := prepareTestEndSelectedWork(t, admin, ctx, retiringID, env.Trust)
		if candidate == nil || result.Outcome != ObservedCurrent || candidate.firstSend != nil {
			t.Fatal("full-window retirement Duty preparation", result)
		}
		selected, result := admin.selectCandidate(ctx, candidate)
		if selected == nil || result.Outcome != ObservedCurrent {
			t.Fatal("full-window retirement Duty selection", result)
		}
		fresh = generatedLifecycleReopen(t, ctx, selected, env.Store)
		if p, k := env.Custody.Calls(); p != public || k != private {
			t.Fatal("full-window retirement exit invoked a custody key route")
		}
		priorEntry.Generated.RetiringDutyPresent, priorEntry.Generated.RetiringDutyID = 0, contract.ID{}
		if len(fresh.adminIndex.Groups) != 0 || !reflect.DeepEqual(*fresh.valueEntry(0), priorEntry) ||
			!reflect.DeepEqual(fresh.accessRecords(), priorAccess) || fresh.root.Generated.Duties != 0 || fresh.root.Generated.Retiring != 0 {
			t.Fatal("full-window retirement exit changed the retained current value or access")
		}
		warning := admin.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningPossibleStoreGarbage
		q := fresh.head.EndWork
		body := binary.BigEndian.AppendUint32(nil, 1)
		body = binary.BigEndian.AppendUint32(body, 32)
		body = append(body, retiringID[:]...)
		ended := contract.GeneratorDescriptor{Digest: contract.ID(sha256.Sum256(append([]byte("ENKV/admin-descriptor/v1/ended-groups\x00"), body...))), Length: 40, Count: 1}
		if q == nil || q.TargetGroupID != retiringID || q.TargetOwnerID != retiringTarget.OwnerID || q.TargetID != retiringTarget.TargetID ||
			q.TargetKind != retiringTarget.OwnerKind || q.DependentGroups != ended || q.PredecessorRevisionID != admin.head.Core.Revision ||
			q.PredecessorFullHEADDigest != contract.Hash(admin.body) || q.PredecessorToken != admin.token ||
			q.BeforeWarningBits != admin.root.WarningBits || q.AfterWarningBits != warning || fresh.root.WarningBits != warning {
			t.Fatal("full-window retirement exit changed exact selected target, predecessor or warnings")
		}
		retiredWindows, err := fresh.receiptWindows(ctx)
		if err != nil || len(retiredWindows.Successes) != 256 || len(retiredWindows.Failures) != 0 ||
			!slices.Equal(retiredWindows.Successes[:255], priorWindows.Successes[1:]) {
			t.Fatal("full-window retirement receipt did not evict exactly the oldest success", err)
		}
		last := retiredWindows.Successes[255]
		if last.OperationID != q.OperationID || last.OperationKind != contract.OperationEndSelectedWork || last.StateResult != contract.ReceiptStateWorkEnded ||
			last.CanonicalOutcome != contract.ReceiptCanonicalSelected || last.AdministrativeTargetKind != retiringTarget.OwnerKind ||
			last.AdministrativeTargetID != retiringTarget.TargetID || last.AdministrativeOriginalEvidence != retiringTarget.SelectedEvidenceSummary ||
			last.WarningBits != uint64(warning) || last.AdministrativeWarningChanges != warning&^admin.root.WarningBits {
			t.Fatal("full-window retirement did not append its exact administrative receipt")
		}
		generatedCheck := env.Custody.Consume(ctx, sessionConsumerSelection(t, fresh, fresh.admission.recipient, priorEntry.Name), custody.StandardValue)
		if generatedCheck.Code != contract.CryptoSuccess || !generatedCheck.ValueMatched || generatedCheck.SinkCalls != 1 {
			t.Fatal("retirement exit did not preserve useful generated current value", generatedCheck)
		}
		run := newScenarioRun(t, ctx, env)
		wrapped := *fresh
		wrapped.store = run.env.Store
		fixture := &environmentFixture{admission: OpenContext{admission: &fresh.admission}, session: &wrapped}
		secret := suppliedSecret(t, env, "secret", "cycle post-window supplied secret", custody.StandardValue)
		supplied := run.suppliedSelection(fixture, append(fresh.currentEntryInputs(), secret))
		if supplied.root.WarningBits&fresh.root.WarningBits != fresh.root.WarningBits || supplied.root.SecretCount != fresh.root.SecretCount+1 {
			t.Fatal("fresh supplied progress lost the prior exit warning or Secret")
		}
		check := env.Custody.Consume(ctx, sessionConsumerSelection(t, supplied, supplied.admission.recipient, "secret"), custody.StandardValue)
		if check.Code != contract.CryptoSuccess || !check.ValueMatched || check.SinkCalls != 1 {
			t.Fatal("post-window supplied Secret is not privately usable", check)
		}
		check = env.Custody.Consume(ctx, sessionConsumerSelection(t, supplied, supplied.admission.recipient, priorEntry.Name), custody.StandardValue)
		if check.Code != contract.CryptoSuccess || !check.ValueMatched || check.SinkCalls != 1 {
			t.Fatal("post-window supplied selection did not preserve generated current consumption", check)
		}
	})
}

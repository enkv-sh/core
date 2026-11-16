package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// These cuts lose the Record process after a real producer return. They do not
// model termination inside the provider or cancel a remote effect.
// full_only: false
func TestEndWorkDiscardsSelectedGeneratedParentProgress(t *testing.T) {
	for _, cut := range []string{"lost_unstored_packet", "sealed_inbox_before_record"} {
		t.Run(cut, func(t *testing.T) {
			ctx := t.Context()
			env, keys := genesisEnvironment(t, contract.GCP, false)
			env.Context = ctx
			run := newScenarioRun(t, ctx, env)
			f := newEnvironmentFixture(t, ctx, run.env, nil, false)
			input, canonical := generatedSourcePlanInput(t, run, f, 2)
			current := f.session
			prior, _ := preparePrivateGeneratedReservation(t, env, current, input, canonical)
			producer, expected := preparePrivateGeneratedProducer(t, env, current, prior, nil)
			var packet []byte
			calls := 0
			if !producer.reservation.candidate.bindFirstSend(producer, func(dispatch context.Context, authority contract.ID) contract.CryptoResultCode {
				calls++
				var code contract.CryptoResultCode
				packet, _, code = keys.InvokeGeneratedProducer(dispatch, producer.operation.context.AdmissionID, producer.producerLocator, authority)
				return code
			}) {
				t.Fatal("phase fixture original first send")
			}
			entered, result := current.selectCandidate(ctx, producer.reservation.candidate)
			if entered == nil || result.Outcome != ObservedCurrent || calls != 1 || len(packet) == 0 {
				t.Fatal("phase fixture real original return", result)
			}
			keys.RetireGenerated()
			before := generatedLifecycleReopen(t, ctx, entered, env.Store)
			work := mustSelectedGeneratedWork(t, before)
			original := work.attempts[expected.Template.AttemptID]
			if work.parent == nil || work.phase == nil || len(work.attempts) != 1 ||
				original.record.State != contract.GeneratedEffectTransmitted || len(original.result) != 0 ||
				!reflect.DeepEqual(original.expected, expected) || work.phase.FrontierAttemptID != original.record.AttemptID {
				t.Fatal("sealed Inbox predecessor differs from its original transmitted phase")
			}
			store := env.Store.(*memoryStore)
			inbox := expectedGeneratedResultKey(store.desc.Prefix, expected)
			directory := processStoreDiagnostics(t)
			facts := generatedProcessFacts(t, before, &generatedRecordInput{Attempt: original.record.AttemptID, Result: packet})
			child := startProcessStoreChild(t, directory, "generated-killed", facts)
			creates, cas := store.creates, store.cas
			barrier, wantCreates := "before-first-create", 0
			if cut == "sealed_inbox_before_record" {
				barrier, wantCreates = "after-result-readback", 1
			}
			if _, err := serveGeneratedProcess(t, child, store, before, *facts.Generated.GeneratedRecord, barrier); err != nil {
				t.Fatal("Record process cut", err)
			}
			stopErr := child.stop()
			_, inboxPresent := store.objects[inbox]
			if stopErr != nil || !child.joined || inboxPresent != (wantCreates == 1) || store.creates-creates != wantCreates || store.cas != cas ||
				(wantCreates == 1) != bytes.Equal(store.objects[inbox].Body, packet) {
				t.Fatal("Record cut changed original Inbox presence or bytes without a joined child", stopErr)
			}
			before = generatedLifecycleReopen(t, ctx, before, store)
			assertEndWorkPhaseExit(t, ctx, env, current, before, true, map[contract.ID][]byte{original.record.AttemptID: packet})
			_, inboxPresent = store.objects[inbox]
			if calls != 1 || inboxPresent != (wantCreates == 1) || (wantCreates == 1) != bytes.Equal(store.objects[inbox].Body, packet) {
				t.Fatal("local exit changed the original remote evidence or repeated its producer")
			}
		})
	}
	for _, phase := range []string{"partial_siblings", "no_effect_successor_installed", "residue_successor_installed", "residue_successor_reserved"} {
		t.Run(phase, func(t *testing.T) {
			ctx := t.Context()
			env, _ := genesisEnvironment(t, contract.GCP, false)
			env.Context = ctx
			current := newNamedEnvironmentFixture(t, ctx, env, []int{4}, false, []string{"kept"}).session
			var before *StateSession
			packets := make(map[contract.ID][]byte)
			var first, sibling contract.ID
			if phase == "partial_siblings" {
				input := generatedPlanInputForGenerations(t, current, generatedVectorID(230), []string{"alpha", "omega"}, defaultGeneratedFixtureProfile())
				first, sibling = input.requestBindings[0].AttemptID, input.requestBindings[1].AttemptID
				prior, _ := preparePrivateGeneratedReservation(t, env, current, input, nil)
				var expected contract.GeneratorResultExpectation
				var packet []byte
				before, _, expected, packet = selectActualGeneratedPacketRecord(t, env, current, prior, custody.StandardValue, true, nil)
				if first != expected.Template.AttemptID {
					t.Fatal("partial siblings recorded a different original")
				}
				packets[first] = packet
			} else {
				choice := uint8(custody.StandardValue)
				if phase == "no_effect_successor_installed" {
					choice = custody.GeneratedConfirmedNoEffect
				}
				var packet []byte
				before, first, sibling, packet = generatedTwoLineageUnfinishedFirst(t, ctx, env, current, choice)
				if phase == "no_effect_successor_installed" {
					if len(packet) == 0 {
						t.Fatal("no-effect phase has no real producer packet")
					}
					packets[first] = packet
					before = selectGeneratedNoEffectPlan(t, ctx, env, before, first, packet)
				} else {
					if len(packet) != 0 {
						t.Fatal("unfinished residue original unexpectedly returned a packet")
					}
					before = selectGeneratedResiduePlan(t, ctx, env, before, first)
				}
			}
			before = generatedLifecycleReopen(t, ctx, before, env.Store)
			work := mustSelectedGeneratedWork(t, before)
			original, siblingAttempt := work.attempts[first], work.attempts[sibling]
			if len(work.attempts) != 2 || siblingAttempt.record.State != contract.GeneratedEffectTransmitted || len(siblingAttempt.result) != 0 ||
				original.expected.Template.LineageID == siblingAttempt.expected.Template.LineageID || work.phase.Stage != contract.GeneratedStageRetainedResult ||
				before.root.Generated.PendingReleases != 0 {
				t.Fatal("later phase lost its two independent accepted originals")
			}
			if phase == "partial_siblings" {
				if original.record.State != contract.GeneratedEffectSucceeded || !bytes.Equal(original.result, packets[first]) ||
					work.phase.FrontierAttemptID != sibling || work.phase.NoEffectUsed != 0 || work.phase.ResidueUsed != 0 ||
					before.root.Generated.Duties != 2 || before.root.Generated.Hazards != 0 || before.root.Generated.Results != 1 {
					t.Fatal("partial sibling phase is not one success and one unobserved original")
				}
			} else {
				planned := work.phase.FrontierAttemptID
				if planned.IsZero() || planned == first || planned == sibling {
					t.Fatal("installed recovery phase has no distinct successor")
				}
				if _, entered := work.attempts[planned]; entered {
					t.Fatal("installed recovery plan dispatched an unreserved successor")
				}
				if phase == "no_effect_successor_installed" {
					if original.record.State != contract.GeneratedEffectConfirmedNoEffect || !bytes.Equal(original.result, packets[first]) ||
						work.phase.NoEffectUsed != 1 || work.phase.ResidueUsed != 0 || before.root.Generated.Duties != 2 ||
						before.root.Generated.Hazards != 0 || before.root.Generated.Results != 1 {
						t.Fatal("installed no-effect plan lost its real result or branch")
					}
				} else {
					if original.record.State != contract.GeneratedEffectClosedWithResidue || len(original.result) != 0 ||
						work.phase.NoEffectUsed != 0 || work.phase.ResidueUsed != 1 || before.root.Generated.Duties != 1 ||
						before.root.Generated.Hazards != 1 || before.root.Generated.Results != 0 {
						t.Fatal("installed residue plan lost its original exact Hazard or branch")
					}
					if _, oldDuty := work.records[generatedRecordKey{contract.GeneratedDutySupportKind, original.expected.Template.DutyID}]; oldDuty {
						t.Fatal("residue phase retained the replaced original Duty")
					}
					row := work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, original.expected.Template.HazardID}]
					hazard, err := contract.InspectGeneratedHazardRecord(row.Body)
					if err != nil || hazard.OriginalAttemptID != first || hazard.OwnerID != original.record.OwnerID || hazard.ResourceID != original.record.ResourceID {
						t.Fatal("residue phase replaced the wrong original owner", err)
					}
				}
				if phase == "residue_successor_reserved" {
					prior := preparePrivateGeneratedSuccessorReservation(t, env, before)
					producer, expected := preparePrivateGeneratedProducer(t, env, before, prior, nil)
					handoffs := 0
					if !producer.reservation.candidate.bindFirstSend(producer, func(context.Context, contract.ID) contract.CryptoResultCode {
						handoffs++
						return contract.CryptoSuccess // The selected first-send cut precedes provider invocation.
					}) {
						t.Fatal("residue successor handoff")
					}
					selected, result := before.selectCandidate(ctx, producer.reservation.candidate)
					if selected == nil || result.Outcome != ObservedCurrent || handoffs != 1 || expected.Template.AttemptID != planned {
						t.Fatal("residue successor reservation selection", result)
					}
					env.Custody.RetireGenerated()
					before = generatedLifecycleReopen(t, ctx, selected, env.Store)
					next := mustSelectedGeneratedWork(t, before)
					successor := next.attempts[planned]
					if len(next.attempts) != 3 || successor.record.State != contract.GeneratedEffectTransmitted || len(successor.result) != 0 ||
						successor.expected.Template.PredecessorAttemptID != first || !reflect.DeepEqual(next.attempts[first], original) ||
						!reflect.DeepEqual(next.attempts[sibling], siblingAttempt) || before.root.Generated.Duties != 2 || before.root.Generated.Hazards != 1 {
						t.Fatal("reserved residue successor changed original owners or invented a result")
					}
					bodies, err := next.vectors.resolve(contract.GeneratedAttemptSupportKind, planned, contract.GeneratorVectorHistory, successor.record.History)
					if err != nil || len(bodies) != 2 {
						t.Fatal("reserved successor has no exact two-step history", err)
					}
					for i, body := range bodies {
						history, err := contract.InspectGeneratorHistory(body)
						want := contract.GeneratorHistory{Schema: 1, PredecessorAttemptID: planned, OwnerID: expected.Template.DutyID, Outcome: contract.GeneratedEffectTransmitted}
						if i == 0 {
							want = contract.GeneratorHistory{Schema: 1, PredecessorAttemptID: first, NextAttemptID: planned, OwnerID: original.expected.Template.DutyID, Outcome: contract.GeneratedEffectClosedWithResidue, Edge: 2}
						}
						if err != nil || history != want {
							t.Fatal("reserved residue successor history differs from its exact predecessor", err)
						}
					}
				}
			}
			assertEndWorkPhaseExit(t, ctx, env, current, before, false, packets)
		})
	}

}

// Every owner in this fixture belongs to the one declared operation. Expected
// removal is derived from its actual Attempt templates and Duty/Hazard rows,
// independently of the administrative closure/projection implementation.
func assertEndWorkPhaseExit(t *testing.T, operationCtx context.Context, env fixtureEnvironment, current, before *StateSession, process bool, packets map[contract.ID][]byte, selectedExit ...*StateSession) *StateSession {
	t.Helper()
	ctx := t.Context()
	store := env.Store.(*memoryStore)
	work := mustSelectedGeneratedWork(t, before)
	if work.parent == nil || work.phase == nil || work.parent.OperationID != before.root.Generated.ActiveOwner {
		t.Fatal("phase exit has no selected generated parent")
	}
	groups := map[contract.ID]bool{work.parent.OperationID: true}
	for _, row := range work.records {
		switch row.Kind {
		case contract.GeneratedDutySupportKind:
			duty, err := contract.InspectGeneratedDutyRecord(row.Body)
			if err != nil || duty.OriginalOperationID != work.parent.OperationID {
				t.Fatal("phase fixture contains an unrelated Duty", err)
			}
			groups[duty.DutyID] = true
		case contract.GeneratedHazardSupportKind:
			hazard, err := contract.InspectGeneratedHazardRecord(row.Body)
			if err != nil || hazard.OriginalOperationID != work.parent.OperationID {
				t.Fatal("phase fixture contains an unrelated Hazard", err)
			}
			groups[hazard.HazardID] = true
		}
	}
	// Ended-group framing is u32 count followed by u32 length (32) and
	// each ID in byte order. The digest uses the literal domain prefix plus
	// NUL and that body; its independent length is 4 + 36*N bytes.
	ids := make([]contract.ID, 0, len(groups))
	for id := range groups {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	body := binary.BigEndian.AppendUint32(nil, uint32(len(ids)))
	for _, id := range ids {
		body = binary.BigEndian.AppendUint32(body, 32)
		body = append(body, id[:]...)
	}
	preimage := append([]byte("ENKV/admin-descriptor/v1/ended-groups\x00"), body...)
	dependent := contract.GeneratorDescriptor{Digest: contract.ID(sha256.Sum256(preimage)), Length: uint64(4 + 36*len(ids)), Count: uint32(len(ids))}

	var target format.AdministrativeGroup
	for _, group := range before.adminIndex.Groups {
		if !groups[group.GroupID] {
			t.Fatal("phase fixture contains an unrelated administrative group")
		}
		if group.GroupID == work.parent.OperationID {
			target = group
		}
	}
	if len(before.adminIndex.Groups) != len(groups) || target.GroupID.IsZero() || target.OwnerKind != format.AdministrativeGeneratedParent ||
		target.OwnerID != work.parent.OperationID || target.TargetID != work.parent.OperationID || len(target.RelatedGroupIndexes) != 0 {
		t.Fatal("phase fixture has no exact independent parent owner set")
	}
	rows, err := before.workSupportRecords(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rows = ownedProcessWorkRows(t, before, rows)
	locations := make(map[generatedContentKey]contract.ID, len(work.content.locations))
	for key, location := range work.content.locations {
		locations[key] = location.BlobID
	}
	windows, err := before.receiptWindows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	inboxes := make(map[string][]byte)
	present := make(map[string]bool)
	for _, original := range work.attempts {
		key, err := format.GeneratedResultKey(store.desc.Prefix, before.root.Domain, original.record.InboxID)
		if err != nil {
			t.Fatal("phase predecessor Inbox identity", err)
		}
		object, found := store.objects[key]
		present[key], inboxes[key] = found, bytes.Clone(object.Body)
	}

	public, private := env.Custody.Calls()
	var after *StateSession
	if len(selectedExit) == 1 {
		if selectedExit[0] == nil || selectedExit[0].head.EndWork == nil {
			t.Fatal("phase oracle received no selected exit")
		}
	} else if process {
		f := selectedProcessFacts(t, OpenContext{admission: &before.admission}, before)
		facts := processStoreFacts{Domain: f.Domain, Trust: f.Trust, Descriptor: f.Descriptor, PublicKey: f.PublicKey,
			DomainBasis: f.DomainBasis, ExpectedImage: f.ExpectedImage, EndWork: &processEndWorkFacts{GroupID: target.GroupID, CurrentBasis: f.CurrentBasis, Epoch: f.Epoch}}
		child := startProcessStoreChild(t, processStoreDiagnostics(t), "end-work", facts)
		if err := serveEndWorkProcess(t, child, store, before, target.GroupID, false); err != nil {
			t.Fatal("public-only phase EndWork child", err)
		}
		if err := child.join(); err != nil || !child.joined {
			t.Fatal("phase EndWork child did not join", err)
		}
	} else {
		candidate, result := prepareTestEndSelectedWork(t, before, ctx, target.GroupID, env.Trust)
		if candidate == nil || result.Outcome != ObservedCurrent || candidate.firstSend != nil {
			t.Fatal("phase EndWork preparation", result)
		}
		selected, result := before.selectCandidate(ctx, candidate)
		if selected == nil || result.Outcome != ObservedCurrent {
			t.Fatal("phase EndWork selection", result)
		}
	}
	after = generatedLifecycleReopen(t, operationCtx, before, store)
	if p, k := env.Custody.Calls(); p != public || k != private {
		t.Fatal("administrative phase exit invoked a custody key route")
	}
	kept := mustSelectedGeneratedWork(t, after)
	if kept.parent != nil || kept.phase != nil || len(kept.attempts) != 0 || len(kept.bundles) != 0 || len(after.adminIndex.Groups) != 0 ||
		after.root.Generated.Materials != 0 || after.root.Generated.Duties != 0 || after.root.Generated.Hazards != 0 ||
		after.root.Generated.Attempts != 0 || after.root.Generated.Results != 0 || after.root.Generated.PendingReleases != 0 {
		t.Fatal("phase EndWork retained its exclusive parent/owner/material/result closure")
	}
	configuration, configurationErr := after.selectedOutputFactsByRecord()
	if configurationErr != nil || len(configuration) != int(before.root.OutputConfiguration.SliceCount) ||
		after.root.OutputConfiguration != before.root.OutputConfiguration {
		t.Fatal("EndWork changed mandatory configuration", configurationErr)
	}
	for _, row := range rows {
		if row.Kind == contract.OutputConfigurationSliceSupportKind {
			fact, present := configuration[row.RecordID]
			if !present || fact.row.Kind() != row.Kind || fact.row.RecordID() != row.RecordID ||
				fact.row.BodyLength() != uint32(len(row.Body)) || fact.row.BodyDigest() != contract.Hash(row.Body) {
				t.Fatal("EndWork changed exact mandatory configuration facts")
			}
			continue
		}
		if _, present := kept.records[generatedRecordKey{row.Kind, row.RecordID}]; present {
			t.Fatal("phase EndWork retained an exclusive selected row", row.Kind, row.RecordID)
		}
	}
	for key, blob := range locations {
		if _, present := kept.content.locations[key]; present {
			t.Fatal("phase EndWork retained an exclusive content location", key.kind)
		}
		for _, fragment := range after.root.Generated.Fragments {
			if fragment.BlobID == blob {
				t.Fatal("phase EndWork retained an exclusive content fragment")
			}
		}
	}
	if _, present := after.materialAccess(contract.OperationSeedMaterialKind, work.parent.MaterialID); present ||
		!reflect.DeepEqual(after.currentEntryInputs(), current.currentEntryInputs()) || !reflect.DeepEqual(after.accessRecords(), current.accessRecords()) ||
		!reflect.DeepEqual(after.root.ValueEntryPages, current.root.ValueEntryPages) || !reflect.DeepEqual(after.root.Names, current.root.Names) ||
		!reflect.DeepEqual(after.root.Recipients, current.root.Recipients) || after.root.ValueEntryCount != current.root.ValueEntryCount ||
		after.root.RawBytes != current.root.RawBytes || after.root.MembershipCount != current.root.MembershipCount {
		t.Fatal("phase EndWork changed current values, provenance, membership or access")
	}
	warning := before.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningPossibleStoreGarbage
	q := after.head.EndWork
	if q == nil || q.TargetGroupID != target.GroupID || q.TargetOwnerID != target.OwnerID || q.TargetKind != target.OwnerKind || q.TargetID != target.TargetID ||
		q.SelectedEvidenceSummary != target.SelectedEvidenceSummary || q.DependentGroups != dependent ||
		q.PredecessorRevisionID != before.head.Core.Revision || q.PredecessorFullHEADDigest != contract.Hash(before.body) || q.PredecessorToken != before.token ||
		q.BeforeWarningBits != before.root.WarningBits || q.AfterWarningBits != warning || after.root.WarningBits != warning ||
		q.BeforeChildCount != uint16(before.root.ChildCount) || q.AfterChildCount != uint16(after.root.ChildCount) ||
		q.BeforeChildBytes != before.root.ChildEncodedBytes || q.AfterChildBytes != after.root.ChildEncodedBytes {
		t.Fatal("phase EndWork envelope changed exact owner, closure, warnings or capacity")
	}
	got, err := after.receiptWindows(ctx)
	if err != nil || len(got.Successes) != len(windows.Successes)+1 || !reflect.DeepEqual(got.Successes[:len(windows.Successes)], windows.Successes) ||
		!reflect.DeepEqual(got.Failures, windows.Failures) {
		t.Fatal("phase exit changed prior receipt windows", err)
	}
	receipt := got.Successes[len(got.Successes)-1]
	if receipt.OperationKind != contract.OperationEndSelectedWork || receipt.OperationID != q.OperationID || receipt.StateResult != contract.ReceiptStateWorkEnded ||
		receipt.CanonicalOutcome != contract.ReceiptCanonicalSelected || receipt.EffectSummary != contract.ReceiptEffectNotApplicable ||
		receipt.AdministrativeTargetKind != target.OwnerKind || receipt.AdministrativeTargetID != target.TargetID ||
		receipt.AdministrativeOriginalEvidence != target.SelectedEvidenceSummary || receipt.WarningBits != uint64(warning) ||
		receipt.AdministrativeWarningChanges != warning&^before.root.WarningBits || receipt.PredecessorRevisionID != before.head.Core.Revision || receipt.ObservedRevisionID != after.head.Core.Revision {
		t.Fatal("phase exit receipt changed the exact local disposition")
	}
	admitted := generatedPlanInputFixture(t, after).context
	admitted.AdmissionID, admitted.SessionID = testID("phase post-exit admission"), testID("phase post-exit session")
	if !after.generatedContextValid(admitted) || after.prepared {
		t.Fatal("phase post-exit context is not fresh")
	}
	reads, creates, cas := store.reads, store.creates, store.cas
	for id, original := range work.attempts {
		if plan, err := after.generatedRecordRequest(ctx, id, packets[id], admitted); plan != nil || !errors.Is(err, contract.ErrRecord) {
			t.Fatal("phase exit restored original Record rights", err)
		}
		if body, present, result := after.ReadGeneratedResult(ctx, id); len(body) != 0 || present || result != refused(AdmissionInvalid) {
			t.Fatal("phase exit restored an original result reader", result)
		}
		if packet := packets[id]; len(packet) != 0 {
			if result := after.persistGeneratedResult(ctx, generatedResultWrite{attempt: id, body: packet}); result != refused(AdmissionInvalid) {
				t.Fatal("phase exit restored original result persistence", result)
			}
			key, err := format.GeneratedResultKey(store.desc.Prefix, before.root.Domain, original.record.InboxID)
			if err != nil || len(store.objects[key].Body) != 0 && !bytes.Equal(store.objects[key].Body, packet) {
				t.Fatal("phase exit changed durable original Inbox evidence", err)
			}
		}
	}
	if plan, err := after.generatedFinalRequest(ctx, admitted); plan != nil || !errors.Is(err, contract.ErrRecord) ||
		store.reads != reads || store.creates != creates || store.cas != cas {
		t.Fatal("phase exit restored Final or reached an original Inbox", err)
	}
	for key, expected := range inboxes {
		object, found := store.objects[key]
		if found != present[key] || !bytes.Equal(object.Body, expected) {
			t.Fatal("local phase exit changed original remote Inbox presence or bytes")
		}
	}

	input := generatedPlanInputForGenerations(t, after, testID("phase fresh generated operation"), []string{"fresh"}, defaultGeneratedFixtureProfile())
	input.context.AdmissionID, input.context.SessionID = testID("phase fresh Plan admission"), testID("phase fresh Plan session")
	fresh := selectPrivateGeneratedOperationInProcess(t, env, after, input, "phase fresh generated progress")
	fresh = generatedLifecycleReopen(t, operationCtx, fresh, store)
	entry := fresh.valueEntry(0)
	if entry == nil || entry.Name != "fresh" || entry.ValueSource != contract.Generated || entry.Generated.IntentDigest != input.graph.Lineages[0].Templates[0].IntentDigest ||
		fresh.root.WarningBits != warning || !fresh.root.Generated.ActiveOwner.IsZero() {
		t.Fatal("phase exit did not permit fresh generated publication with sticky warnings")
	}
	check := env.Custody.Consume(ctx, sessionConsumerSelection(t, fresh, fresh.admission.recipient, "fresh"), custody.StandardValue)
	if check.Code != contract.CryptoSuccess || !check.ValueMatched || check.SinkCalls != 1 {
		t.Fatal("fresh generated progress is not privately usable", check)
	}
	return after
}

// full_only: false
func TestEndWorkAndGeneratedFinalKeepOneCompleteCurrentSet(t *testing.T) {
	for _, winner := range []string{"end_work_first", "final_first"} {
		t.Run(winner, func(t *testing.T) {
			ctx := t.Context()
			fixture := newGeneratedResultFixture(t, 2, false)
			env := fixture.env
			env.Context = ctx
			store := env.Store.(*memoryStore)
			// Candidate.session is the independently captured pre-reservation
			// session; its current values/access precede the operation seed.
			current := fixture.producer.reservation.candidate.session
			entered := generatedLifecycleReopen(t, ctx, fixture.f.session, store)
			plan := generatedRecordPlanForResult(t, entered, fixture.expected.Template.AttemptID, fixture.result, "phase race Record")
			record := preparePrivateGeneratedRecord(t, env, entered, plan)
			recorded, result := entered.selectCandidate(ctx, record.reservation.candidate)
			if recorded == nil || result.Outcome != ObservedCurrent {
				t.Fatal("phase race real Record selection", result)
			}
			env.Custody.RetireGenerated()
			finalSession := generatedLifecycleReopen(t, ctx, recorded, store)
			work := mustSelectedGeneratedWork(t, finalSession)
			original := work.attempts[fixture.expected.Template.AttemptID]
			if work.phase.Stage != contract.GeneratedStageTerminal || work.parent.LineageCount != 1 || len(work.attempts) != 1 ||
				original.record.State != contract.GeneratedEffectSucceeded || !bytes.Equal(original.result, fixture.result) || fixture.calls != 1 {
				t.Fatal("phase race has no complete real successful parent")
			}
			beforeReceipts, err := finalSession.receiptWindows(ctx)
			if err != nil {
				t.Fatal("phase race predecessor receipts", err)
			}
			admitted := generatedPlanInputFixture(t, finalSession).context
			admitted.AdmissionID, admitted.SessionID = testID("phase race Final admission"), testID("phase race Final session")
			finalPlan, err := finalSession.generatedFinalRequest(ctx, admitted)
			if err != nil || finalPlan == nil || !finalPlan.selecting {
				t.Fatal("phase race Final request", err)
			}
			finalSession, final := preparePrivateGeneratedFinal(t, env, finalSession, finalPlan)
			work = mustSelectedGeneratedWork(t, finalSession)
			beforeReceipts, err = finalSession.receiptWindows(ctx)
			if err != nil {
				t.Fatal("checkpoint contender predecessor receipts", err)
			}
			endSession := generatedLifecycleReopen(t, ctx, finalSession, store)
			if endSession.head.Core != finalSession.head.Core || endSession.token != finalSession.token || !bytes.Equal(endSession.body, finalSession.body) {
				t.Fatal("competing preparations do not share one exact selected predecessor")
			}
			end, result := prepareTestEndSelectedWork(t, endSession, ctx, work.parent.OperationID, env.Trust)
			if end == nil || result.Outcome != ObservedCurrent {
				t.Fatal("phase race EndWork preparation", result)
			}
			env.Custody.RetireGenerated()
			finalCandidate := final.reservation.candidate
			finalBody, endBody := bytes.Clone(finalCandidate.body), bytes.Clone(end.body)
			finalToken, endToken := finalSession.token, endSession.token
			firstSession, first, lastSession, last := endSession, end, finalSession, finalCandidate
			if winner == "final_first" {
				firstSession, first, lastSession, last = finalSession, finalCandidate, endSession, end
			}
			public, private := env.Custody.Calls()
			selected, result := firstSession.selectCandidate(ctx, first)
			if selected == nil || result.Outcome != ObservedCurrent {
				t.Fatal("phase race winner selection", result)
			}
			selected = generatedLifecycleReopen(t, ctx, selected, store)
			frozenImage, frozenBody, frozenToken := sessionStateImage(t, selected), bytes.Clone(selected.body), selected.token
			frozenWork, err := selected.workSupportRecords(ctx)
			if err != nil {
				t.Fatal(err)
			}
			frozenWork = ownedProcessWorkRows(t, selected, frozenWork)
			frozenReceipts, err := selected.receiptWindows(ctx)
			if err != nil {
				t.Fatal(err)
			}
			creates := store.creates
			if stale, result := lastSession.selectCandidate(ctx, last); stale != nil || result.Outcome != Contention || result.Reason != StalePrecondition ||
				store.creates != creates || finalSession.token != finalToken || endSession.token != endToken ||
				!bytes.Equal(finalCandidate.body, finalBody) || !bytes.Equal(end.body, endBody) {
				t.Fatal("competing loser rebased or selected a partial state", result)
			}
			cold := generatedLifecycleReopen(t, ctx, selected, store)
			coldWork, err := cold.workSupportRecords(ctx)
			if err != nil {
				t.Fatal(err)
			}
			coldWork = ownedProcessWorkRows(t, cold, coldWork)
			coldReceipts, err := cold.receiptWindows(ctx)
			if err != nil || !reflect.DeepEqual(sessionStateImage(t, cold), frozenImage) || !bytes.Equal(cold.body, frozenBody) || cold.token != frozenToken ||
				!reflect.DeepEqual(coldWork, frozenWork) || !reflect.DeepEqual(coldReceipts, frozenReceipts) {
				t.Fatal("competing loser changed the winner's complete frozen state", err)
			}
			loserOperation, ok := observedHeadOperation(last.head)
			if !ok {
				t.Fatal("competing loser has no fixed operation")
			}
			for _, window := range [][]contract.CompactMutationReceipt{coldReceipts.Successes, coldReceipts.Failures} {
				for _, receipt := range window {
					if receipt.OperationID == loserOperation {
						t.Fatal("competing loser selected a receipt")
					}
				}
			}
			if p, k := env.Custody.Calls(); p != public || k != private || fixture.calls != 1 || first.firstSend != nil || last.firstSend != nil {
				t.Fatal("competing selection gained a producer call or send right")
			}
			if winner == "end_work_first" {
				assertEndWorkPhaseExit(t, ctx, env, current, endSession, false,
					map[contract.ID][]byte{fixture.expected.Template.AttemptID: fixture.result}, cold)
				return
			}
			if len(coldReceipts.Successes) != len(beforeReceipts.Successes)+1 ||
				!reflect.DeepEqual(coldReceipts.Successes[:len(beforeReceipts.Successes)], beforeReceipts.Successes) ||
				!reflect.DeepEqual(coldReceipts.Failures, beforeReceipts.Failures) {
				t.Fatal("Final winner changed the prior receipt windows")
			}
			receipt := coldReceipts.Successes[len(coldReceipts.Successes)-1]
			var counts [contract.ReceiptSummaryCount]uint32
			counts[contract.ReceiptEffectCount], counts[contract.ReceiptSummarySuccessCount] = 1, 1
			if receipt.OperationKind != contract.OperationApplyDeclaration || receipt.OperationID != work.parent.OperationID ||
				receipt.RequestIdentityDigest != work.parent.RequestIdentityDigest ||
				receipt.StateResult != contract.ReceiptStateSuccess || receipt.EffectSummary != contract.ReceiptEffectComplete ||
				receipt.CanonicalOutcome != contract.ReceiptCanonicalSelected || receipt.EvidenceCeiling != contract.ReceiptEvidenceProviderFacts ||
				receipt.PredecessorRevisionID != current.head.Core.Revision || receipt.RequestedRevisionID != cold.head.Core.Revision || receipt.ObservedRevisionID != cold.head.Core.Revision ||
				receipt.SummaryCounts != counts || receipt.AcknowledgedCount != 0 || receipt.ConfirmedCount != 0 || receipt.UnknownCount != 0 || receipt.WarningBits != 0 {
				t.Fatal("Final winner receipt differs from one complete successful original operation")
			}

			if cold.root.ValueEntryCount != 2 || cold.root.Generated.GeneratedCurrent != 1 || !cold.root.Generated.ActiveOwner.IsZero() ||
				cold.head.Generator == nil || cold.head.EndWork != nil || cold.root.WarningBits != finalSession.root.WarningBits {
				t.Fatal("Final winner did not select the complete new current set")
			}
			var generated, retained *contract.ValueEntry
			for _, named := range cold.root.Names {
				switch named.Name {
				case "generated":
					generated = cold.valueEntry(named.Slot)
				case "secret":
					retained = cold.valueEntry(named.Slot)
				default:
					t.Fatal("Final winner selected an unexpected current member")
				}
			}
			if generated == nil || retained == nil || !reflect.DeepEqual(*retained, *current.valueEntry(0)) ||
				generated.ValueSource != contract.Generated || generated.Generated.OriginOperationID != work.parent.OperationID ||
				generated.Generated.OriginAttemptID != original.record.AttemptID || generated.Generated.CreateResultID != original.record.ResultID ||
				generated.Generated.IntentDigest != original.expected.Template.IntentDigest ||
				!reflect.DeepEqual(generated.Recipients, []contract.ID{current.admission.recipient}) {
				t.Fatal("Final winner mixed canonical membership or original result provenance")
			}
			kept := mustSelectedGeneratedWork(t, cold)
			evidence, err := contract.DecodeGeneratedCreateEvidence(kept.records[generatedRecordKey{contract.GeneratedCreateEvidenceSupportKind, original.record.ResultID}].Body)
			packet, packetErr := contract.DecodeGeneratedResultRecord(fixture.result)
			if err != nil || packetErr != nil || contract.ValidateGeneratedResult(original.expected, original.material, packet) != nil {
				t.Fatal("Final winner has no exact real packet evidence", err, packetErr)
			}
			coreBody, coreErr := contract.EncodeGeneratedResultCore(packet.Core)
			factsBody, factsErr := contract.EncodeGeneratorSafeFacts(packet.SafeFacts)
			if coreErr != nil || factsErr != nil || evidence.OriginalResultID != original.record.ResultID ||
				!bytes.Equal(evidence.ResultCore, coreBody) || !bytes.Equal(evidence.SafeFacts, factsBody) {
				t.Fatal("Final winner's selected evidence differs from the real original packet")
			}
			for _, name := range []string{"generated", "secret"} {
				check := env.Custody.Consume(ctx, sessionConsumerSelection(t, cold, cold.admission.recipient, name), custody.StandardValue)
				if check.Code != contract.CryptoSuccess || !check.ValueMatched || check.SinkCalls != 1 {
					t.Fatal("Final winner lost a current private value", name, check)
				}
			}
		})
	}
}

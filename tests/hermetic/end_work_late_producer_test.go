package core

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// EndWork removes selected local rights. An already admitted original producer
// can still enter or return, and its late packet does not restore those rights.
// full_only: false
func TestEndWorkRevokesSelectedReservationBeforeLateProducerReturn(t *testing.T) {
	for _, cut := range []string{"before_first_send", "after_provider_entry"} {
		t.Run(cut, func(t *testing.T) {
			ctx := t.Context()
			env, keys := genesisEnvironment(t, contract.GCP, false)
			env.Context = ctx
			run := newScenarioRun(t, ctx, env)
			f := newEnvironmentFixture(t, ctx, run.env, nil, false)
			store := env.Store.(*memoryStore)
			currentEntries, currentAccess := f.session.currentEntryInputs(), f.session.accessRecords()
			currentRoot := f.session.root
			input, canonical := generatedSourcePlanInput(t, run, f, 0)
			prior, _ := preparePrivateGeneratedReservation(t, env, f.session, input, canonical)
			var producer *generatedPreparation
			var expected contract.GeneratorResultExpectation
			var original generatedAttempt
			var after *StateSession
			var packet []byte
			entries, returns, exits := 0, 0, 0
			endParent := func() {
				t.Helper()
				exits++
				if exits != 1 || len(packet) != 0 || cut == "before_first_send" && entries != 0 || cut == "after_provider_entry" && entries != 1 {
					t.Fatal("EndWork did not occur at the declared original producer cut")
				}
				before, res := Open(ctx, f.admission, store)
				if before == nil || res.Outcome != ObservedCurrent {
					t.Fatal("selected original reservation cold Open", res)
				}
				work, err := before.selectedGeneratedWork(ctx)
				if err != nil || work.parent == nil || work.phase == nil || len(work.attempts) != 1 {
					t.Fatal("selected original reservation has no exact parent/frontier", err)
				}
				var present bool
				original, present = work.attempts[expected.Template.AttemptID]
				if !present || !reflect.DeepEqual(original.expected, expected) || original.record.InboxID.IsZero() ||
					original.record.ResultID != expected.Use.ResultID || original.material.Core.OperationMaterialID != work.parent.MaterialID ||
					work.phase.FrontierAttemptID != original.record.AttemptID || len(original.result) != 0 ||
					original.record.OperationID != work.parent.OperationID || before.root.AccessRecordCount != currentRoot.AccessRecordCount+1 {
					t.Fatal("original selected Attempt/result/material/Inbox differs from the producer expectation")
				}
				inbox, err := format.GeneratedResultKey(before.admission.store.Prefix, before.root.Domain, original.record.InboxID)
				if err != nil {
					t.Fatal("original Inbox coordinate", err)
				}
				if _, present := store.objects[inbox]; present {
					t.Fatal("original packet existed before the late return")
				}
				if len(before.adminIndex.Groups) != 2 {
					t.Fatal("original reservation has an unexpected administrative owner set")
				}
				parentIndex, dutyIndex := -1, -1
				for i, group := range before.adminIndex.Groups {
					switch group.GroupID {
					case original.record.OperationID:
						parentIndex = i
					case expected.Template.DutyID:
						dutyIndex = i
					default:
						t.Fatal("original reservation contains an unrelated administrative owner")
					}
				}
				if parentIndex < 0 || dutyIndex < 0 || original.record.OwnerID != expected.Template.DutyID {
					t.Fatal("original parent/Create Duty identity differs from the fixed template")
				}
				target, dutyGroup := before.adminIndex.Groups[parentIndex], before.adminIndex.Groups[dutyIndex]
				if target.OwnerKind != format.AdministrativeGeneratedParent || target.GroupID != work.parent.OperationID ||
					target.OwnerID != work.parent.OperationID || target.TargetID != work.parent.OperationID || len(target.RelatedGroupIndexes) != 0 {
					t.Fatal("selected parent closure is not the independent original operation")
				}
				dutyRow, present := work.records[generatedRecordKey{contract.GeneratedDutySupportKind, expected.Template.DutyID}]
				duty, dutyErr := contract.InspectGeneratedDutyRecord(dutyRow.Body)
				if !present || dutyErr != nil || duty.OriginalOperationID != original.record.OperationID ||
					duty.OriginalAttemptID != expected.Template.AttemptID || duty.Kind != contract.GeneratedDutyCreate ||
					dutyGroup.OwnerKind != format.AdministrativeGeneratedDuty || dutyGroup.DutyKind != contract.GeneratedDutyCreate ||
					dutyGroup.OwnerID != duty.OwnerID || dutyGroup.TargetID != duty.ResourceID ||
					!reflect.DeepEqual(dutyGroup.RelatedGroupIndexes, []uint16{uint16(parentIndex)}) {
					t.Fatal("original Create Duty does not have the exact incoming parent dependency", dutyErr)
				}
				oldRows, err := before.workSupportRecords(ctx)
				if err != nil {
					t.Fatal("original selected support closure", err)
				}
				oldRows = ownedProcessWorkRows(t, before, oldRows)
				oldLocations := make(map[generatedContentKey]contract.ID, len(work.content.locations))
				for key, location := range work.content.locations {
					oldLocations[key] = location.BlobID
				}
				if oldLocations[generatedContentKey{contract.GeneratorContentIntent, expected.Template.IntentDigest}].IsZero() ||
					oldLocations[generatedContentKey{contract.GeneratorContentGraph, work.parent.PlanGraphID}].IsZero() {
					t.Fatal("original selected closure lost its exact Intent or graph location")
				}
				windows, err := before.receiptWindows(ctx)
				if err != nil {
					t.Fatal("predecessor receipt windows", err)
				}
				public, private := keys.Calls()
				entryCount, returnCount := entries, returns
				candidate, res := prepareTestEndSelectedWork(t, before, ctx, target.GroupID, env.Trust)
				if candidate == nil || res.Outcome != ObservedCurrent {
					t.Fatal("actual parent EndWork preparation", res)
				}
				ended, res := before.selectCandidate(ctx, candidate)
				if ended == nil || res.Outcome != ObservedCurrent {
					t.Fatal("actual parent EndWork selection", res)
				}
				after, res = Open(ctx, f.admission, store)
				if after == nil || res.Outcome != ObservedCurrent || after.head.Core != ended.head.Core || after.prepared {
					t.Fatal("actual post-exit cold Open", res)
				}
				if p, k := keys.Calls(); p != public || k != private || entries != entryCount || returns != returnCount {
					t.Fatal("administrative exit entered a key route or original producer")
				}
				kept, err := after.selectedGeneratedWork(ctx)
				if err != nil || kept.parent != nil || kept.phase != nil || len(kept.attempts) != 0 || len(kept.bundles) != 0 ||
					len(kept.releases) != 0 || len(after.adminIndex.Groups) != 0 || !after.root.Generated.ActiveOwner.IsZero() ||
					!after.root.Generated.ActivePhase.IsZero() || !after.root.Generated.ActiveGraph.IsZero() ||
					after.root.Generated.Duties != 0 || after.root.Generated.Hazards != 0 || after.root.Generated.Materials != 0 ||
					after.root.Generated.Attempts != 0 || after.root.Generated.Results != 0 || after.root.Generated.PendingReleases != 0 {
					t.Fatal("EndWork retained original parent/phase/Attempt/Duty/graph closure", err)
				}
				configuration, configurationErr := after.selectedOutputFactsByRecord()
				if configurationErr != nil || len(configuration) != int(before.root.OutputConfiguration.SliceCount) ||
					after.root.OutputConfiguration != before.root.OutputConfiguration {
					t.Fatal("EndWork changed mandatory configuration", configurationErr)
				}
				for _, row := range oldRows {
					if row.Kind == contract.OutputConfigurationSliceSupportKind {
						fact, present := configuration[row.RecordID]
						if !present || fact.row.Kind() != row.Kind || fact.row.RecordID() != row.RecordID ||
							fact.row.BodyLength() != uint32(len(row.Body)) || fact.row.BodyDigest() != contract.Hash(row.Body) {
							t.Fatal("EndWork changed exact mandatory configuration facts")
						}
						continue
					}
					if _, present := kept.records[generatedRecordKey{row.Kind, row.RecordID}]; present {
						t.Fatal("EndWork retained an exclusive original support row", row.Kind)
					}
				}
				for key, blob := range oldLocations {
					if _, present := kept.content.locations[key]; present {
						t.Fatal("EndWork retained an original Intent/graph/content location", key.kind)
					}
					for _, fragment := range after.root.Generated.Fragments {
						if fragment.BlobID == blob {
							t.Fatal("EndWork retained an exclusive original content fragment")
						}
					}
				}
				if _, present := after.materialAccess(contract.OperationSeedMaterialKind, original.material.Core.OperationMaterialID); present ||
					!reflect.DeepEqual(after.currentEntryInputs(), currentEntries) || !reflect.DeepEqual(after.accessRecords(), currentAccess) ||
					!reflect.DeepEqual(after.root.ValueEntryPages, currentRoot.ValueEntryPages) || !reflect.DeepEqual(after.root.Names, currentRoot.Names) ||
					!reflect.DeepEqual(after.root.Recipients, currentRoot.Recipients) || after.root.ValueEntryCount != currentRoot.ValueEntryCount ||
					after.root.AccessRecordCount != currentRoot.AccessRecordCount || after.root.RawBytes != currentRoot.RawBytes ||
					after.root.MembershipCount != currentRoot.MembershipCount {
					t.Fatal("EndWork kept original seed/access or changed the exact current state")
				}
				warning := before.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningPossibleStoreGarbage
				q := after.head.EndWork
				if after.head.AuthKind != format.AdministrativeAuth || q == nil || q.TargetGroupID != target.GroupID || q.TargetOwnerID != target.OwnerID ||
					q.TargetKind != target.OwnerKind || q.TargetID != target.TargetID || q.SelectedEvidenceSummary != target.SelectedEvidenceSummary ||
					q.DependentGroups.Count != 2 || q.PredecessorRevisionID != before.head.Core.Revision ||
					q.PredecessorFullHEADDigest != contract.Hash(before.body) || q.PredecessorToken != before.token ||
					q.BeforeWarningBits != before.root.WarningBits || q.AfterWarningBits != warning || after.root.WarningBits != warning ||
					q.BeforeChildCount != uint16(before.root.ChildCount) || q.AfterChildCount != uint16(after.root.ChildCount) ||
					q.BeforeChildBytes != before.root.ChildEncodedBytes || q.AfterChildBytes != after.root.ChildEncodedBytes {
					t.Fatal("EndWork lost its exact selected target, closure or warning envelope")
				}
				got, err := after.receiptWindows(ctx)
				if err != nil || len(got.Successes) != len(windows.Successes)+1 ||
					!reflect.DeepEqual(got.Successes[:len(windows.Successes)], windows.Successes) || !reflect.DeepEqual(got.Failures, windows.Failures) {
					t.Fatal("EndWork changed prior receipt windows", err)
				}
				receipt := got.Successes[len(got.Successes)-1]
				if receipt.OperationKind != contract.OperationEndSelectedWork || receipt.OperationID != q.OperationID ||
					receipt.StateResult != contract.ReceiptStateWorkEnded || receipt.EffectSummary != contract.ReceiptEffectNotApplicable ||
					receipt.CanonicalOutcome != contract.ReceiptCanonicalSelected || receipt.AdministrativeTargetKind != target.OwnerKind ||
					receipt.AdministrativeTargetID != target.TargetID || receipt.AdministrativeOriginalEvidence != target.SelectedEvidenceSummary ||
					receipt.WarningBits != uint64(warning) || receipt.AdministrativeWarningChanges != warning&^before.root.WarningBits ||
					receipt.PredecessorRevisionID != before.head.Core.Revision || receipt.ObservedRevisionID != after.head.Core.Revision {
					t.Fatal("EndWork receipt does not record the exact local disposition")
				}
			}
			beforeReturn := func() {
				returns++
				if entries != 1 || returns != 1 || len(packet) != 0 {
					t.Fatal("original BeforeReturn did not precede sealing")
				}
				if cut == "after_provider_entry" {
					endParent()
				}
			}
			producer, expected = preparePrivateGeneratedProducer(t, env, f.session, prior, beforeReturn)
			if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
				if cut == "before_first_send" {
					endParent()
				}
				entries++
				var code contract.CryptoResultCode
				packet, _, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
				return code
			}) {
				t.Fatal("original producer first-send binding")
			}
			observed, res := f.session.selectCandidate(ctx, producer.reservation.candidate)
			if observed == nil || res.Outcome != ObservedCurrent || after == nil || entries != 1 || returns != 1 || exits != 1 || len(packet) == 0 ||
				observed.head.Core.Revision == after.head.Core.Revision {
				t.Fatal("real original packet did not follow the selected exit", res)
			}
			record, err := contract.DecodeGeneratedResultRecord(packet)
			if err != nil || contract.ValidateGeneratedResult(original.expected, original.material, record) != nil {
				t.Fatal("late original packet lost its captured exact expectation/material", err)
			}
			if body, _, code := keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator,
				producer.reservation.candidate.generated.authority); code != contract.CryptoAlreadyUsed || len(body) != 0 || entries != 1 || returns != 1 {
				t.Fatal("late original producer became reusable", code)
			}
			admitted := generatedPlanInputFixture(t, after).context
			admitted.AdmissionID, admitted.SessionID = testID("post-exit Record admission"), testID("post-exit Record session")
			if !after.generatedContextValid(admitted) || after.prepared {
				t.Fatal("post-exit refusal context is not fresh and valid")
			}
			inbox, err := format.GeneratedResultKey(after.admission.store.Prefix, after.root.Domain, original.record.InboxID)
			if err != nil {
				t.Fatal(err)
			}
			refuseOriginal := func() {
				t.Helper()
				reads, creates, cas := store.reads, store.creates, store.cas
				if plan, err := after.generatedRecordRequest(ctx, original.record.AttemptID, packet, admitted); plan != nil || !errors.Is(err, contract.ErrRecord) {
					t.Fatal("absent original owner admitted late Record", err)
				}
				if plan, err := after.generatedFinalRequest(ctx, admitted); plan != nil || !errors.Is(err, contract.ErrRecord) {
					t.Fatal("absent original parent admitted Final", err)
				}
				if body, present, result := after.ReadGeneratedResult(ctx, original.record.AttemptID); len(body) != 0 || present || result != refused(AdmissionInvalid) {
					t.Fatal("absent original coordinate read late Inbox", result)
				}
				if result := after.persistGeneratedResult(ctx, generatedResultWrite{attempt: original.record.AttemptID, body: packet}); result != refused(AdmissionInvalid) {
					t.Fatal("absent original coordinate persisted late Inbox", result)
				}
				if store.reads != reads || store.creates != creates || store.cas != cas || after.prepared {
					t.Fatal("owner-based late refusal reached Store or consumed post-exit preparation")
				}
			}
			refuseOriginal()
			store.put(inbox, packet)
			after, res = Open(ctx, f.admission, store)
			if after == nil || res.Outcome != ObservedCurrent {
				t.Fatal("stored late packet changed cold selected state", res)
			}
			if _, err := after.selectedGeneratedWork(ctx); err != nil || !after.generatedContextValid(admitted) {
				t.Fatal("late packet changed owner absence or fresh context", err)
			}
			refuseOriginal()
			if !bytes.Equal(store.objects[inbox].Body, packet) {
				t.Fatal("local owner refusal deleted remote late evidence")
			}
			if code := keys.BindGeneratedCandidate(ctx, producer.operation.context.AdmissionID, generatedPrivateCandidate(t, producer)); code == contract.CryptoSuccess {
				t.Fatal("used original candidate rebound after selected exit")
			}
			keys.RetireGenerated()
		})
	}
}

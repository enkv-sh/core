package core

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestGeneratedFinalPreservesDetachedIntentLifetime(t *testing.T) {
	t.Run("detached_intent_survives_distinct_success", func(t *testing.T) {
		ctx := t.Context()
		env := memoryScenarioEnvironmentMode(t, false)
		env.Context = ctx
		fixture := newNamedEnvironmentFixture(t, ctx, env, []int{1}, false, []string{"a-seed"})
		seed := *fixture.session.valueEntry(0)
		cold := func(selected *StateSession) *StateSession {
			t.Helper()
			opened, result := Open(ctx, OpenContext{admission: &selected.admission}, env.Store)
			if opened == nil || result.Outcome != ObservedCurrent {
				t.Fatal("authentic reserve history cold Open", result)
			}
			return opened
		}
		measure := func(label string, selected *StateSession) {
			t.Helper()
			indexBytes, err := format.AdministrativeIndexEncodedLength(selected.adminIndex)
			if err != nil {
				t.Fatal("selected reserve index", err)
			}
			t.Logf("reserve history %s: children=%d support_pages=%d index_bytes=%d index_shards=%d fragments=%d groups=%d duties=%d hazards=%d current_generated=%d",
				label, selected.root.ChildCount, len(selected.root.RequiredSupport), indexBytes,
				1+len(selected.root.AdministrativeIndexShards), len(selected.root.Generated.Fragments),
				len(selected.adminIndex.Groups), selected.root.Generated.Duties, selected.root.Generated.Hazards,
				selected.root.Generated.GeneratedCurrent)
		}
		before := cold(fixture.session)
		measure("seed", before)
		// 124 Plain values and two bounded generated outputs charge 126*64 KiB:
		// 7.875 MiB, below the 8 MiB desired-current raw-value bound.
		sources := make([]contract.GeneratorDeclarationEntry, 124)
		for i := range sources {
			payload := bytes.Repeat([]byte{byte(i + 1)}, 65536)
			sources[i] = contract.GeneratorDeclarationEntry{Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationPlain,
				Name: fmt.Sprintf("plain-%03d", i), Recipients: []contract.ID{before.admission.recipient}, Payload: payload}
		}
		oldIntent := hermeticSizedGeneratorIntent("detached old intent", 'x', 393216)

		failedNames := []string{"failed-alpha", "failed-omega"}
		input := generatedPlanInputForGenerationsIntent(t, before, fixtureID(env.Domain, "reserve mixed failed operation"),
			failedNames, oldIntent, defaultGeneratedFixtureProfile(), sources...)
		input.context.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
		plan, err := before.generatedPlanRequest(ctx, input)
		if err != nil || plan == nil {
			t.Fatal("mixed failed aggregate public plan", err)
		}
		var capacityPages uint32
		for _, group := range plan.capacity.Groups {
			capacityPages += group.MaxPages
		}
		t.Logf("reserve history mixed plan: declaration_bytes=%d capacity_group_pages=%d", len(input.declaration), capacityPages)
		failed, _ := selectPrivateOwnedUnusableAggregateFromInput(t, env, before, failedNames, input, nil)
		failed = cold(failed)
		measure("one mixed failed aggregate", failed)
		if failed.root.ValueEntryCount != 1 || !reflect.DeepEqual(*failed.valueEntry(0), seed) ||
			failed.root.Generated.Duties != 1 || failed.root.Generated.Hazards != 1 || len(failed.adminIndex.Groups) != 2 {
			t.Fatal("failed aggregate did not retain the exact seed and two real detached owners")
		}
		oldWork, err := failed.selectedGeneratedWork(ctx)
		if err != nil {
			t.Fatal("cold failed aggregate work", err)
		}
		oldRows := make(map[generatedRecordKey][]byte)
		for key, row := range oldWork.records {
			if key.kind == contract.GeneratedAttemptSupportKind || key.kind == contract.GeneratedDutySupportKind ||
				key.kind == contract.GeneratedHazardSupportKind {
				oldRows[key] = bytes.Clone(row.Body)
			}
		}
		if len(oldRows) != 4 || len(oldWork.attempts) != 2 {
			t.Fatal("mixed failed aggregate lacks its exact two Attempts, Duty and Hazard")
		}
		oldIntents := make(map[contract.ID][]byte)
		for _, attempt := range oldWork.attempts {
			if attempt.expected.Template.Action != contract.GeneratorActionCreate {
				t.Fatal("detached lifetime fixture sent a destructive action")
			}
			id := attempt.expected.Template.IntentDigest
			body, readErr := oldWork.readSelectedSlice(ctx, contract.GeneratorContentIntent, id, contract.GeneratorIntentMaxLength)
			if readErr != nil || !bytes.Equal(body, oldIntent) {
				t.Fatal("failed aggregate original Intent", readErr)
			}
			oldIntents[id] = bytes.Clone(body)
		}
		newIntent := hermeticGeneratorIntent([]byte("reserve distinct current Intent"))
		newInput := generatedPlanInputForGenerationsIntent(t, failed, fixtureID(env.Domain, "reserve distinct successful operation"),
			[]string{"current"}, newIntent, defaultGeneratedFixtureProfile())
		newInput.context.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
		if newPlan, planErr := failed.generatedPlanRequest(ctx, newInput); planErr != nil || newPlan == nil {
			t.Fatal("independent current generated public plan", planErr)
		}
		t.Log("reserve history entering actual independent successful operation after cold detached-owner validation")
		current := selectPrivateGeneratedOperation(t, env, failed, newInput, "reserve distinct success")
		current = cold(current)
		measure("independent current Generated selected", current)
		if current.root.ValueEntryCount != 1 || current.root.Generated.GeneratedCurrent != 1 ||
			current.root.Generated.Duties != 1 || current.root.Generated.Hazards != 1 {
			t.Fatal("independent success changed unrelated detached owners")
		}
		currentWork, err := current.selectedGeneratedWork(ctx)
		if err != nil {
			t.Fatal("cold independent current work", err)
		}
		entry := current.valueEntry(0)
		newDigest, err := contract.GeneratorIntentDigest(hermeticGeneratorIntent(newIntent))
		if err != nil || entry == nil || entry.Name != "current" || entry.ValueSource != contract.Generated ||
			entry.Generated.IntentDigest != newDigest {
			t.Fatal("independent success did not select the exact new current Intent", err)
		}
		for oldDigest := range oldIntents {
			if newDigest == oldDigest {
				t.Fatal("new current Intent reused an old detached digest")
			}
		}
		for key, expected := range oldRows {
			actual, present := currentWork.records[key]
			if !present || !bytes.Equal(actual.Body, expected) {
				t.Fatal("independent success changed retained detached owner row", key.kind)
			}
		}
		for id, expected := range oldIntents {
			actual, readErr := currentWork.readSelectedSlice(ctx, contract.GeneratorContentIntent, id, contract.GeneratorIntentMaxLength)
			if readErr != nil || !bytes.Equal(actual, expected) {
				t.Fatal("independent success lost original detached Intent", readErr)
			}
		}
		oldBlobs := make(map[contract.ID]bool)
		for id := range oldIntents {
			oldBlobs[oldWork.content.locations[generatedContentKey{contract.GeneratorContentIntent, id}].BlobID] = true
		}
		if oldBlobs[currentWork.content.locations[generatedContentKey{contract.GeneratorContentIntent, newDigest}].BlobID] {
			t.Fatal("current Intent shares the old exclusive declaration blob")
		}
		var pair [2]format.AdministrativeGroup
		for _, group := range current.adminIndex.Groups {
			switch group.OwnerKind {
			case format.AdministrativeGeneratedDuty:
				pair[0] = group
			case format.AdministrativeGeneratedHazard:
				pair[1] = group
			default:
				t.Fatal("unexpected detached administrative owner", group.OwnerKind)
			}
			closure, _, err := current.administrativeWorkClosure(group.GroupID)
			if err != nil || len(closure.Groups) != 1 || len(group.RelatedGroupIndexes) != 0 {
				t.Fatal("old detached owners are not independently endable", err)
			}
		}
		if pair[0].GroupID.IsZero() || pair[1].GroupID.IsZero() || pair[0].DutyKind != contract.GeneratedDutyUnselectedCleanup {
			t.Fatal("missing real unselected cleanup Duty or owned-unusable Hazard")
		}
		currentEntry := *entry
		currentAccess, present := current.materialAccess(contract.ValueMaterialKind, entry.ValueState)
		if !present {
			t.Fatal("new current value lacks authenticated access")
		}
		currentEvidence := bytes.Clone(currentWork.records[generatedRecordKey{contract.GeneratedCreateEvidenceSupportKind, entry.Generated.CreateResultID}].Body)
		for _, order := range [][2]format.AdministrativeGroup{pair, {pair[1], pair[0]}} {
			t.Run(fmt.Sprintf("first_owner_%d", order[0].OwnerKind), func(t *testing.T) {
				ctx := t.Context()
				store := selectedMemoryStoreCopy(env.Store.(*memoryStore))
				selected, observed := Open(ctx, OpenContext{admission: &current.admission}, store)
				if selected == nil || observed.Outcome != ObservedCurrent {
					t.Fatal("detached lifetime Store copy cold Open", observed)
				}
				var ended []contract.ID
				for step, target := range order {
					before := selected
					beforeWindows, err := before.receiptWindows(ctx)
					if err != nil {
						t.Fatal("detached lifetime predecessor receipts", err)
					}
					beforePublic, beforePrivate := env.Custody.Calls()
					beforeCAS := store.cas
					candidate, prepared := prepareTestEndSelectedWork(t, before, ctx, target.GroupID, env.Trust)
					if candidate == nil || prepared.Outcome != ObservedCurrent || store.cas != beforeCAS {
						t.Fatal("detached lifetime EndWork preparation", prepared)
					}
					if next, outcome := before.selectCandidate(ctx, candidate); next == nil || outcome.Outcome != ObservedCurrent || store.cas != beforeCAS+1 {
						t.Fatal("detached lifetime EndWork selection", outcome)
					}
					selected, observed = Open(ctx, OpenContext{admission: &before.admission}, store)
					if selected == nil || observed.Outcome != ObservedCurrent || len(selected.adminIndex.Groups) != 1-step {
						t.Fatal("detached lifetime successor cold Open", observed)
					}
					if public, private := env.Custody.Calls(); public != beforePublic || private != beforePrivate {
						t.Fatal("detached lifetime EndWork used a public or private key route")
					}
					warning := before.root.WarningBits | uint8(0x19)
					q := selected.head.EndWork
					if selected.head.AuthKind != format.AdministrativeAuth || q == nil || q.TargetGroupID != target.GroupID ||
						q.TargetOwnerID != target.OwnerID || q.TargetID != target.TargetID || q.TargetKind != target.OwnerKind ||
						q.SelectedEvidenceSummary != target.SelectedEvidenceSummary || q.DependentGroups.Count != 1 ||
						q.PredecessorRevisionID != before.head.Core.Revision || q.PredecessorFullHEADDigest != contract.Hash(before.body) ||
						q.PredecessorToken != before.token || q.BeforeWarningBits != before.root.WarningBits ||
						q.AfterWarningBits != warning || selected.root.WarningBits != warning ||
						q.BeforeChildCount != uint16(before.root.ChildCount) || q.AfterChildCount != uint16(selected.root.ChildCount) ||
						q.BeforeChildBytes != before.root.ChildEncodedBytes || q.AfterChildBytes != selected.root.ChildEncodedBytes {
						t.Fatal("detached lifetime EndWork envelope changed its exact target or warning")
					}
					work, err := selected.selectedGeneratedWork(ctx)
					if err != nil || !reflect.DeepEqual(selected.valueEntry(0), &currentEntry) ||
						!reflect.DeepEqual(selected.root.ValueEntryPages, current.root.ValueEntryPages) ||
						!reflect.DeepEqual(selected.root.Names, current.root.Names) || selected.root.ValueEntryCount != 1 ||
						selected.root.Generated.GeneratedCurrent != 1 || selected.root.RawBytes != current.root.RawBytes ||
						!bytes.Equal(work.records[generatedRecordKey{contract.GeneratedCreateEvidenceSupportKind, entry.Generated.CreateResultID}].Body, currentEvidence) {
						t.Fatal("detached lifetime exit changed exact new current value or evidence", err)
					}
					access, present := selected.materialAccess(contract.ValueMaterialKind, entry.ValueState)
					intent, readErr := work.readSelectedSlice(ctx, contract.GeneratorContentIntent, newDigest, contract.GeneratorIntentMaxLength)
					if !present || !reflect.DeepEqual(access, currentAccess) || readErr != nil || !bytes.Equal(intent, newIntent) {
						t.Fatal("detached lifetime exit changed exact new current access or Intent", readErr)
					}
					consumed := env.Custody.Consume(ctx, sessionConsumerSelection(t, selected, selected.admission.recipient, entry.Name), custody.StandardValue)
					if consumed.Code != contract.CryptoSuccess || consumed.Delivery != 1 || !consumed.ValueMatched {
						t.Fatal("new current value is not privately readable after detached exit", consumed)
					}
					windows, err := selected.receiptWindows(ctx)
					if err != nil || len(windows.Successes) != len(beforeWindows.Successes)+1 ||
						!reflect.DeepEqual(windows.Successes[:len(beforeWindows.Successes)], beforeWindows.Successes) ||
						!reflect.DeepEqual(windows.Failures, beforeWindows.Failures) {
						t.Fatal("detached lifetime exit changed prior receipts", err)
					}
					receipt := windows.Successes[len(windows.Successes)-1]
					if receipt.OperationKind != contract.OperationEndSelectedWork || receipt.OperationID != q.OperationID ||
						receipt.StateResult != contract.ReceiptStateWorkEnded || receipt.EffectSummary != contract.ReceiptEffectNotApplicable ||
						receipt.CanonicalOutcome != contract.ReceiptCanonicalSelected || receipt.AdministrativeTargetKind != target.OwnerKind ||
						receipt.AdministrativeTargetID != target.TargetID || receipt.AdministrativeOriginalEvidence != target.SelectedEvidenceSummary ||
						receipt.WarningBits != uint64(warning) || receipt.AdministrativeWarningChanges != warning&^before.root.WarningBits ||
						receipt.PredecessorRevisionID != before.head.Core.Revision || receipt.ObservedRevisionID != selected.head.Core.Revision {
						t.Fatal("detached lifetime exit receipt lost its exact local disposition")
					}
					ended = append(ended, q.OperationID)
					for _, operation := range ended {
						if !slices.ContainsFunc(windows.Successes, func(r contract.CompactMutationReceipt) bool { return r.OperationID == operation }) {
							t.Fatal("detached lifetime exit lost an earlier exit receipt")
						}
					}
					if step == 0 {
						for id, want := range oldIntents {
							got, err := work.readSelectedSlice(ctx, contract.GeneratorContentIntent, id, contract.GeneratorIntentMaxLength)
							if err != nil || !bytes.Equal(got, want) {
								t.Fatal("first exit lost surviving old owner's exact Intent", err)
							}
						}
					} else {
						if len(work.attempts) != 0 || len(work.bundles) != 0 || selected.root.Generated.Duties != 0 || selected.root.Generated.Hazards != 0 {
							t.Fatal("last detached exit retained old work")
						}
						for id := range oldIntents {
							if _, present := work.content.locations[generatedContentKey{contract.GeneratorContentIntent, id}]; present {
								t.Fatal("last detached exit retained an obsolete Intent location")
							}
						}
						for _, fragment := range selected.root.Generated.Fragments {
							if oldBlobs[fragment.BlobID] {
								t.Fatal("last detached exit retained an exclusive old blob fragment")
							}
						}
					}
					measure(fmt.Sprintf("exit order=%d step=%d", order[0].OwnerKind, step), selected)
				}
			})
		}
	})
}

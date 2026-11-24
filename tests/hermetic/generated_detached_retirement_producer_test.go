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
func TestActualFreshNameFinalAccumulatesDetachedRetirements(t *testing.T) {
	t.Log("producer shape: one initial Create, then two selecting C1/R1 operations with distinct six-byte names and the same exact Intent; no ordinary removal")
	ctx := t.Context()
	env, keys := genesisEnvironment(t, contract.GCP, false)
	env.Context = ctx
	defer keys.RetireGenerated()
	defer keys.RetireApply()
	selected := newEnvironmentFixture(t, ctx, env, nil, false).session
	profile := defaultGeneratedFixtureProfile()
	intent := hermeticSizedGeneratorIntent("shared exact detached retirement Intent", 'x', 256)
	intentID, err := contract.GeneratorIntentDigest(hermeticGeneratorIntent(intent))
	if err != nil {
		t.Fatal(err)
	}
	type originalGeneration struct {
		entry    contract.ValueEntry
		evidence []byte
	}
	var originals []originalGeneration
	priorRetirementRows := make(map[generatedRecordKey][]byte)
	var dutyIDs []contract.ID
	for step, name := range []string{"g00000", "g00001", "g00002"} {
		var retiring map[string]contract.ValueEntry
		if step != 0 {
			old := originals[step-1].entry
			retiring = map[string]contract.ValueEntry{old.Name: old}
		}
		operation := fixtureID(env.Domain, "fresh-name selecting Final "+name)
		bound := generatedReservationInputForMembershipStateIntents(t, selected, operation, []contract.ID{selected.admission.recipient},
			[]string{name}, func(string) []byte { return bytes.Clone(intent) }, profile, 0, nil, retiring)
		input := generatedPlanInputForGenerations(t, selected, operation, []string{name}, profile)
		input.graph, input.declaration, input.registry, input.recoveryPolicy, input.requestBindings = bound.graph, bound.declaration,
			bound.graph.Request.Registry, bound.graph.Request.RecoveryPolicyID, slices.Clone(bound.requestBindings)
		retirementLineages := 0
		for _, lineage := range input.graph.Lineages {
			if lineage.Purpose == contract.GeneratorLineageRetirement {
				retirementLineages++
			}
		}
		if input.graph.Header.LineageCount != 1 || len(input.graph.ValueEntryPlans) != 1 || retirementLineages != min(step, 1) {
			t.Fatal("producer input is not the exact C1/R0 or C1/R1 operation")
		}
		selected = selectGeneratedWriterBatch(t, env, selected, input, name, custody.StandardValue)
		selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
		work := mustSelectedGeneratedWork(t, selected)
		t.Logf("selected stage=%d current=%d retiring=%d Attempts=%d graphs=%d materials=%d access=%d groups=%d children=%d child-bytes=%d", step,
			selected.root.Generated.GeneratedCurrent, selected.root.Generated.Retiring, selected.root.Generated.Attempts,
			selected.root.Generated.Graphs.Count, selected.root.Generated.Materials, selected.root.AccessRecordCount,
			len(selected.adminIndex.Groups), selected.root.ChildCount, selected.root.ChildEncodedBytes)
		if selected.root.ValueEntryCount != 1 || len(selected.root.Names) != 1 || selected.root.Names[0].Name != name ||
			selected.root.Generated.GeneratedCurrent != 1 || selected.root.Generated.Retiring != uint32(step) || selected.root.Generated.Duties != uint32(step) ||
			selected.root.Generated.Hazards != 0 || selected.root.Generated.Attempts != 0 || selected.root.Generated.Results != 0 ||
			selected.root.Generated.Materials != 0 || selected.root.Generated.PendingReleases != 0 || selected.root.Generated.Graphs.Count != 0 ||
			selected.root.AccessRecordCount != 1 || len(work.attempts) != 0 || len(work.bundles) != 0 || len(work.releases) != 0 || work.parent != nil || work.phase != nil {
			t.Fatal("selecting Final did not retain only one current value and detached retirements")
		}
		for key, body := range priorRetirementRows {
			if row, present := work.records[key]; !present || !bytes.Equal(row.Body, body) {
				t.Fatal("later selecting Final changed an exact prior retirement row", key.kind)
			}
		}
		if step != 0 {
			old := originals[step-1].entry
			dutyID, err := contract.GeneratorDutyID(env.Domain, old.Generated.OriginOperationID, old.Generated.OriginAttemptID, contract.GeneratedDutyRetirement)
			if err != nil {
				t.Fatal(err)
			}
			dutyIDs = append(dutyIDs, dutyID)
		}
		for i, dutyID := range dutyIDs {
			old := originals[i]
			row, present := work.records[generatedRecordKey{contract.GeneratedDutySupportKind, dutyID}]
			duty, err := contract.InspectGeneratedDutyRecord(row.Body)
			if !present || err != nil || duty.Kind != contract.GeneratedDutyRetirement || duty.Status != contract.GeneratedEffectNotStarted || duty.Step != 1 ||
				duty.OriginalOperationID != old.entry.Generated.OriginOperationID || duty.OriginalAttemptID != old.entry.Generated.OriginAttemptID ||
				duty.ResourceID != old.entry.Generated.ResourceIncarnationID || duty.Support != old.entry.Generated.RequiredSupport ||
				duty.History != contract.EmptyGeneratorVector(contract.GeneratorVectorHistory) || duty.Progress != contract.EmptyGeneratorVector(contract.GeneratorVectorProgress) ||
				duty.Consumers != contract.EmptyGeneratorVector(contract.GeneratorVectorConsumers) || duty.Support != contract.EmptyGeneratorVector(contract.GeneratorVectorSupport) || len(row.Body) != 655 {
				t.Fatal("detached retirement changed its exact original owner or started an effect", err)
			}
			// Facts:115 framing+24 target+32 resource+1 provider=172 bytes.
			// Evidence:120 framing+452 result+172 facts=744 bytes.
			evidenceRow, present := work.records[generatedRecordKey{contract.GeneratedCreateEvidenceSupportKind, old.entry.Generated.CreateResultID}]
			if !present || !bytes.Equal(evidenceRow.Body, old.evidence) || len(evidenceRow.Body) != 744 {
				t.Fatal("detached retirement lost its exact compact original CreateEvidence")
			}
			evidence, err := contract.InspectGeneratedCreateEvidence(evidenceRow.Body)
			if err != nil || len(evidence.ResultCore) != 452 || len(evidence.SafeFacts) != 172 {
				t.Fatal("original evidence differs from the bounded actual producer facts", err)
			}
			core, err := contract.InspectGeneratedResultCore(evidence.ResultCore)
			if err != nil {
				t.Fatal(err)
			}
			wantTarget := contract.GeneratorTarget{Schema: contract.GeneratorTargetSchema, Name: old.entry.Name, IncarnationID: old.entry.Incarnation, Epoch: old.entry.Generated.Epoch, ResourceID: old.entry.Generated.ResourceIncarnationID, OriginalOperationID: old.entry.Generated.OriginOperationID, OriginalAttemptID: old.entry.Generated.OriginAttemptID, ResultContractID: core.ResultContractID, ResourceDigest: old.entry.Generated.ResourceDigest, CompletionClass: old.entry.Generated.CompletionClass, ConfigContractID: old.entry.Generated.ConfigContractID, ResourceContractID: old.entry.Generated.ResourceContractID, LifecycleMode: contract.GeneratorLifecycleManaged}
			target, err := work.retirementTarget(ctx, duty)
			if err != nil || !reflect.DeepEqual(target, wantTarget) {
				t.Fatal("detached retirement lost its exact original target", err)
			}
			targetRows := 0
			for key, carrierRow := range work.records {
				if key.kind != contract.GeneratorVectorSupportKind {
					continue
				}
				carrier, err := contract.InspectGeneratorVectorCarrier(carrierRow.Body)
				if err != nil {
					t.Fatal(err)
				}
				if carrier.OwnerKind == contract.GeneratedDutySupportKind && carrier.OwnerID == dutyID && carrier.VectorKind == contract.GeneratorVectorTargets {
					if carrier.Vector != duty.Target || carrier.Ordinal != 0 || len(carrier.Row) != 278 || len(carrierRow.Body) != 398 {
						t.Fatal("detached target carrier differs from its exact six-byte-name framing")
					}
					targetRows++
					priorRetirementRows[key] = bytes.Clone(carrierRow.Body)
				}
			}
			if targetRows != 1 {
				t.Fatal("detached retirement lacks its complete one-row target vector")
			}
			priorRetirementRows[generatedRecordKey{contract.GeneratedDutySupportKind, dutyID}] = bytes.Clone(row.Body)
			priorRetirementRows[generatedRecordKey{contract.GeneratedCreateEvidenceSupportKind, old.entry.Generated.CreateResultID}] = bytes.Clone(evidenceRow.Body)
			material, err := contract.GeneratorMaterialID(env.Domain, old.entry.Generated.OriginOperationID)
			if err != nil {
				t.Fatal(err)
			}
			if _, present := work.records[generatedRecordKey{contract.OperationMaterialSupportKind, material}]; present {
				t.Fatal("detached retirement retained the original operation material")
			}
			if _, present := selected.materialAccess(contract.OperationSeedMaterialKind, material); present {
				t.Fatal("detached retirement retained original seed access")
			}
			if _, present := selected.materialAccess(contract.ValueMaterialKind, old.entry.ValueState); present {
				t.Fatal("detached retirement retained old private value access")
			}
		}
		entry := *selected.valueEntry(entrySlot(t, selected, name))
		if entry.Generated.IntentDigest != intentID || entry.Generated.RetiringDutyPresent != 0 {
			t.Fatal("fresh current value does not have the exact independent current relation")
		}
		evidence, present := work.records[generatedRecordKey{contract.GeneratedCreateEvidenceSupportKind, entry.Generated.CreateResultID}]
		if !present {
			t.Fatal("new current generation lacks its original evidence")
		}
		originals = append(originals, originalGeneration{entry, bytes.Clone(evidence.Body)})
		wantGroups := slices.Clone(dutyIDs)
		slices.SortFunc(wantGroups, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		location, mandatory, owners, found := sharedIntentCarrier(t, selected, intentID)
		body, err := work.readSelectedSlice(ctx, contract.GeneratorContentIntent, intentID, contract.GeneratorIntentMaxLength)
		if !found || !mandatory || !slices.Equal(owners, wantGroups) || !bytes.Equal(body, intent) || err != nil || location.Length != uint32(len(intent)) {
			t.Fatal("current and detached retirements do not share the exact Intent carrier", err)
		}
		for _, location := range work.content.locations {
			if location.ContentKind == contract.GeneratorContentGraph {
				t.Fatal("detached retirement retained an original Create graph")
			}
		}
		assertSharedIntentGroupIDs(t, selected, wantGroups)
		consumed := env.Custody.Consume(ctx, sessionConsumerSelection(t, selected, selected.admission.recipient, name), custody.StandardValue)
		if consumed.Code != contract.CryptoSuccess || consumed.Delivery != 1 || !consumed.ValueMatched {
			t.Fatal("fresh current generation lost its private value", consumed.Code)
		}
	}
}

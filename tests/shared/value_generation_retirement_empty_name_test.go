package core

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedEmptyNameRetirementCloseSelectsAndReopens(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			env, entered, expected, packet, duty, target, sends := generatedEmptyNameEnteredRetirement(t, recovery)
			if env.FreshGeneratedRecord == nil {
				t.Fatal("empty-name retirement requires a fresh record hook")
			}
			recorded := env.FreshGeneratedRecord(t, entered, expected.Template.AttemptID, packet)
			work := mustSelectedGeneratedWork(t, recorded)
			original := work.attempts[expected.Template.AttemptID]
			if original.record.CompletionClass != contract.GeneratedCompletionAcknowledged || original.record.State != contract.GeneratedEffectSucceeded ||
				!bytes.Equal(original.result, packet) || original.expected.TargetResourceDigest != target.ResourceDigest {
				t.Fatal("empty-name retirement omitted the exact selected acknowledgement")
			}
			_, current := observeCurrentValueEntry(t, recorded, "")
			_, sibling := observeCurrentValueEntry(t, recorded, "healthy")
			if current.ValueSource != contract.Generated || current.Generated.RetiringDutyPresent != 1 || current.Generated.RetiringDutyID != duty.DutyID ||
				sibling.ValueSource != contract.Supplied || sibling.ConfidentialityClass != contract.Plain {
				t.Fatal("final-close predecessor lacks its exact generated and healthy entries")
			}
			beforeReceipts, err := recorded.receiptWindows(t.Context())
			if err != nil {
				t.Fatal("empty-name final-close predecessor receipt order", err)
			}
			permit, err := recorded.admitGeneratedRetirementClose(t.Context(), expected.Template.AttemptID, generatedPlanInputFixture(t, recorded).context)
			if err != nil {
				t.Fatal("empty-name final-close admission", err)
			}
			candidate, prepared := recorded.PrepareGeneratedLifecycle(t.Context(), permit, env.Trust)
			if candidate == nil || prepared.Outcome != ObservedCurrent {
				t.Fatal("empty-name final-close after-proof preparation", prepared)
			}
			closed, selected := recorded.selectCandidate(t.Context(), candidate)
			if closed == nil || selected.Outcome != ObservedCurrent {
				t.Fatal("empty-name final-close after-proof selection", selected)
			}
			cold := generatedLifecycleReopen(t, t.Context(), closed, env.Store)
			afterReceipts, err := cold.receiptWindows(t.Context())
			if err != nil {
				t.Fatal("empty-name final-close selected receipt order", err)
			}
			assertSuccessReceiptOrder(t, beforeReceipts, afterReceipts, original.record.OperationID)
			assertEmptyNameRetirementValues(t, cold, current, sibling)
			after := mustSelectedGeneratedWork(t, cold)
			release, present := after.releases[expected.Template.AttemptID]
			if cold.root.Generated.Retiring != 0 || cold.root.Generated.Duties != 0 || cold.root.Generated.Hazards != 0 ||
				cold.root.Generated.PendingReleases != 1 || len(after.releases) != 1 || len(after.attempts) != 0 ||
				after.hasRecord(generatedRecordKey{contract.GeneratedDutySupportKind, duty.DutyID}) || !present ||
				release.release.State != contract.GeneratedReleasePending || release.release.InboxID != expected.Template.InboxID ||
				release.release.OriginalResultID != expected.Template.ResultID || release.release.SelectedHandoffDigest != contract.Hash(packet) ||
				release.release.ObjectLength != uint32(len(packet)) || release.release.HandoffRevisionID != cold.head.Core.Revision {
				t.Fatal("empty-name final close lost the exact pending inbox handoff")
			}
			body, result := cold.MutationReceipt(t.Context(), original.record.OperationID)
			receipt, err := contract.InspectCompactMutationReceipt(body)
			if result.Outcome != ObservedCurrent || err != nil || receipt.EvidenceCeiling != contract.ReceiptEvidenceAcknowledged ||
				receipt.WarningBits != contract.ReceiptWarningInvalidationNotConfirmed || receipt.AcknowledgedCount != 1 || receipt.ConfirmedCount != 0 ||
				receipt.SummaryCounts[contract.ReceiptSummarySuccessCount] != 1 {
				t.Fatal("empty-name final close changed the acknowledgement ceiling", result, err)
			}
			inspection, err := cold.inspectGeneratedWork(t.Context())
			if err != nil || len(inspection.effects) != 1 || inspection.effects[0].attempt.AttemptID != expected.Template.AttemptID ||
				inspection.effects[0].evidenceCeiling != contract.ReceiptEvidenceAcknowledged || len(inspection.releases) != 1 {
				t.Fatal("empty-name final close lost acknowledged history", err)
			}
			checkFreshGeneratedProcess(t, env.Store.(*memoryStore), cold)
			if *sends != 1 {
				t.Fatal("final close or restart sent another delete")
			}
		})
	}
}

// full_only: false
func TestGeneratedEmptyNameRetirementResidueSelectsAndReopens(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			env, entered, expected, _, duty, target, sends := generatedEmptyNameEnteredRetirement(t, recovery)
			// The sealed original packet has not reached its inbox. Its local
			// producer result cannot grant Core acknowledgement or a retry.
			ambiguity, err := contract.EncodeGeneratorSafeFacts(generatedUnknownFixtureFacts(expected, generatedTargetEvidence(t, entered, target)))
			if err != nil {
				t.Fatal(err)
			}
			_, current := observeCurrentValueEntry(t, entered, "")
			_, sibling := observeCurrentValueEntry(t, entered, "healthy")
			if current.ValueSource != contract.Generated || current.Generated.RetiringDutyPresent != 1 || current.Generated.RetiringDutyID != duty.DutyID ||
				sibling.ValueSource != contract.Supplied || sibling.ConfidentialityClass != contract.Plain {
				t.Fatal("accepted-residue predecessor lacks its exact generated and healthy entries")
			}
			beforeReceipts, err := entered.receiptWindows(t.Context())
			if err != nil {
				t.Fatal("empty-name accepted-residue predecessor receipt order", err)
			}
			permit, err := entered.admitGeneratedActiveRetirementResidue(t.Context(), duty.DutyID, ambiguity, generatedPlanInputFixture(t, entered).context)
			if err != nil {
				t.Fatal("empty-name accepted-residue admission", err)
			}
			candidate, prepared := entered.PrepareGeneratedLifecycle(t.Context(), permit, env.Trust)
			if candidate == nil || prepared.Outcome != ObservedCurrent {
				t.Fatal("empty-name accepted-residue after-proof preparation", prepared)
			}
			closed, selected := entered.selectCandidate(t.Context(), candidate)
			if closed == nil || selected.Outcome != ObservedCurrent {
				t.Fatal("empty-name accepted-residue after-proof selection", selected)
			}
			cold := generatedLifecycleReopen(t, t.Context(), closed, env.Store)
			afterReceipts, err := cold.receiptWindows(t.Context())
			if err != nil {
				t.Fatal("empty-name accepted-residue selected receipt order", err)
			}
			assertSuccessReceiptOrder(t, beforeReceipts, afterReceipts, permit.plan.identity.operation)
			assertEmptyNameRetirementValues(t, cold, current, sibling)
			after := mustSelectedGeneratedWork(t, cold)
			original, present := after.attempts[expected.Template.AttemptID]
			if cold.root.Generated.Retiring != 0 || cold.root.Generated.Duties != 0 || cold.root.Generated.Hazards != 1 ||
				cold.root.Generated.PendingReleases != 0 || after.parent != nil || after.phase != nil || len(after.releases) != 0 ||
				len(after.attempts) != 1 || !present || len(original.result) != 0 || original.record.State != contract.GeneratedEffectClosedWithResidue ||
				original.record.Stage != contract.GeneratedStageTerminal || original.record.OwnerID != duty.DutyID ||
				original.record.InboxID != expected.Template.InboxID || original.record.ResultID != expected.Template.ResultID ||
				!after.materials[materialIdentity{contract.OperationSeedMaterialKind, original.material.Core.OperationMaterialID}] ||
				len(after.consumers[materialIdentity{contract.OperationSeedMaterialKind, original.material.Core.OperationMaterialID}]) != 1 {
				t.Fatal("empty-name accepted residue lost unknown history or granted inbox release")
			}
			hazard, err := contract.InspectGeneratedHazardRecord(after.records[generatedRecordKey{contract.GeneratedHazardSupportKind, expected.Template.HazardID}].Body)
			if err != nil || hazard.OwnerID != duty.DutyID || hazard.Exposure != contract.GeneratedExposurePossibleLive || hazard.Fenced != 1 ||
				hazard.CompletionClass != duty.CompletionClass || hazard.History.Count != 1 || hazard.Consumers.Count != 1 || hazard.OriginalResults.Count != 0 {
				t.Fatal("empty-name accepted residue changed the exact possible-live Hazard", err)
			}
			targetAfter, err := after.generatedCleanupTarget(contract.GeneratedHazardSupportKind, hazard.HazardID, hazard.Target)
			if err != nil || targetAfter != target {
				t.Fatal("empty-name accepted residue changed the exact retirement target", err)
			}
			body, result := cold.MutationReceipt(t.Context(), permit.plan.identity.operation)
			receipt, err := contract.InspectCompactMutationReceipt(body)
			if result.Outcome != ObservedCurrent || err != nil || receipt.OperationKind != contract.OperationAcceptGeneratedRetirementResidue ||
				receipt.SummaryCounts[contract.ReceiptEffectCount] != 0 || receipt.SummaryCounts[contract.ReceiptHazardCount] != 1 ||
				receipt.WarningBits != contract.ReceiptWarningPossibleLive || receipt.AcknowledgedCount != 0 || receipt.ConfirmedCount != 0 {
				t.Fatal("empty-name accepted residue invented acknowledgement", result, err)
			}
			inspection, err := cold.inspectGeneratedWork(t.Context())
			if err != nil || len(inspection.effects) != 1 || inspection.effects[0].attempt.AttemptID != expected.Template.AttemptID ||
				inspection.effects[0].evidenceCeiling != contract.ReceiptEvidenceProviderFacts || len(inspection.releases) != 0 ||
				inspection.warnings&contract.ReceiptWarningPossibleLive == 0 {
				t.Fatal("empty-name accepted residue lost its unknown evidence ceiling", err)
			}
			if _, err := after.generatedRetirementAcknowledgement(t.Context(), expected.Template.AttemptID, generatedVectorID(240)); err == nil {
				t.Fatal("unknown retirement closed as acknowledged")
			}
			if retry, result := entered.selectCandidate(t.Context(), candidate); retry != nil || result.Outcome != AdmissionRefused {
				t.Fatal("accepted residue restored selected transition permission", result)
			}
			checkFreshGeneratedProcess(t, env.Store.(*memoryStore), cold)
			if *sends != 1 {
				t.Fatal("accepted residue or restart sent another delete")
			}
		})
	}
}

func generatedEmptyNameEnteredRetirement(t *testing.T, recovery bool) (fixtureEnvironment, *StateSession, contract.GeneratorResultExpectation, []byte,
	contract.GeneratedDutyRecord, contract.GeneratorTarget, *int) {
	t.Helper()
	ctx := t.Context()
	env, keys := genesisEnvironment(t, contract.GCP, recovery)
	f := newNamedEnvironmentFixture(t, ctx, env, []int{3}, false, []string{"healthy"})
	sibling := ownScenarioValueEntry(*f.session.valueEntry(0))
	source := contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationPlain, Name: sibling.Name,
		Recipients: slices.Clone(sibling.Recipients), Payload: bytes.Clone(sibling.ValueBytes)}
	profile := defaultGeneratedFixtureProfile()
	s := selectPrivateGeneratedOperation(t, env, f.session,
		generatedPlanInputForGenerations(t, f.session, generatedVectorID(230), []string{""}, profile, source), "empty-name initial create")
	var slot uint16
	found := false
	for _, name := range s.root.Names {
		if name.Name == "" {
			slot, found = name.Slot, true
		}
	}
	if !found {
		t.Fatal("initial generated operation lost the empty name")
	}
	old := ownScenarioValueEntry(*s.valueEntry(slot))
	rotation := generatedReservationInputForState(t, s, generatedVectorID(231), []string{""}, profile, old.Generated.Epoch+1,
		map[string]contract.ID{"": old.Incarnation}, map[string]contract.ValueEntry{"": old}, source)
	plan := generatedPlanInputForGenerations(t, s, generatedVectorID(231), []string{""}, profile, source)
	plan.graph, plan.declaration, plan.registry, plan.recoveryPolicy, plan.requestBindings = rotation.graph, rotation.declaration,
		rotation.graph.Request.Registry, rotation.graph.Request.RecoveryPolicyID, slices.Clone(rotation.requestBindings)
	plan.context.AdmissionID, plan.context.SessionID = testID("empty-name rotation admission"), testID("empty-name rotation session")
	s = selectPrivateGeneratedOperation(t, env, s, plan, "empty-name rotation")
	current := ownScenarioValueEntry(*s.valueEntry(slot))
	if current.Name != "" || current.Incarnation != old.Incarnation || current.ValueState == old.ValueState ||
		current.Generated.Epoch != old.Generated.Epoch+1 || current.Generated.RetiringDutyPresent != 1 || s.root.Generated.Retiring != 1 {
		t.Fatal("empty-name rotation did not select a fresh value and exact retiring generation")
	}
	work := mustSelectedGeneratedWork(t, s)
	duty, err := contract.InspectGeneratedDutyRecord(work.records[generatedRecordKey{contract.GeneratedDutySupportKind, current.Generated.RetiringDutyID}].Body)
	if err != nil {
		t.Fatal(err)
	}
	target, err := work.retirementTarget(ctx, duty)
	if err != nil || target.Name != "" || target.ResourceID != old.Generated.ResourceIncarnationID || target.ResourceDigest != old.Generated.ResourceDigest {
		t.Fatal("empty-name rotation changed the exact old target", err)
	}
	input, inputCanonical := generatedDeletePlanInput(t, s, generatedVectorID(232), duty, target, 2)
	prior, _ := preparePrivateGeneratedReservation(t, env, s, input, inputCanonical)
	producer, expected := preparePrivateGeneratedProducer(t, env, s, prior, nil)
	var packet []byte
	sends := 0
	if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
		sends++
		var code contract.CryptoResultCode
		packet, _, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		return code
	}) {
		t.Fatal("empty-name original delete handoff")
	}
	entered, result := s.selectCandidate(ctx, producer.reservation.candidate)
	if entered == nil || result.Outcome != ObservedCurrent || len(packet) == 0 || sends != 1 {
		t.Fatal("empty-name exact delete entry", result)
	}
	keys.RetireGenerated()
	return env, entered, expected, packet, duty, target, &sends
}

func assertEmptyNameRetirementValues(t testing.TB, s *StateSession, current, sibling contract.ValueEntry) {
	t.Helper()
	current.Generated.RetiringDutyPresent, current.Generated.RetiringDutyID = 0, contract.ID{}
	want := map[string]contract.ValueEntry{"": current, sibling.Name: sibling}
	got := make(map[string]contract.ValueEntry)
	for _, name := range s.root.Names {
		entry := s.valueEntry(name.Slot)
		if entry == nil {
			t.Fatal("retirement retained a name without its entry")
		}
		got[name.Name] = *entry
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("retirement changed current value, incarnation, ciphertext, membership or healthy sibling")
	}
}

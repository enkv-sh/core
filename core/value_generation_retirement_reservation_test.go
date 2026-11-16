package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedFreshDeleteReservationPreservesNonemptySupportOwners(t *testing.T) {
	for _, kind := range []string{"retirement-duty", "cleanup-hazard"} {
		t.Run(kind, func(t *testing.T) {
			var before *StateSession
			var source contract.GeneratedDeleteSource
			var err error
			if kind == "retirement-duty" {
				old, duty, _ := generatedDetachedRetirementState(t, "absent", 0)
				before = generatedEmptyPredecessor(t)
				before.support, before.root.Generated = old.support, old.root.Generated
				generatedRefreshSupport(t, before)
				source, err = contract.InspectGeneratedDeleteSource(contract.SupportRecord{Kind: contract.GeneratedDutySupportKind, RecordID: duty.DutyID,
					Body: mustEncodeGeneratedDutyForSupportTest(t, duty)})
			} else {
				before, source = generatedOrdinaryCleanupSourceState(t, contract.GeneratedCompletionAcknowledged, true)
			}
			if err != nil {
				t.Fatal(err)
			}
			// Encode one executor binding and its complete vector hash directly:
			// schema 2, role 3, three IDs, empty blob; vector B(count || B(row)).
			binding := binary.BigEndian.AppendUint16(nil, 2)
			binding = append(binding, 3)
			for _, id := range []contract.ID{source.ConfigContractID, source.ExecutorID, source.DescriptorID} {
				binding = append(binding, id[:]...)
			}
			binding = binary.BigEndian.AppendUint32(binding, 0)
			length := uint32(8 + len(binding))
			preimage := binary.BigEndian.AppendUint32([]byte("ENKV/GENERATOR/v1/support-bindings\x00"), length)
			preimage = binary.BigEndian.AppendUint32(preimage, 1)
			preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(binding)))
			preimage = append(preimage, binding...)
			want := contract.GeneratorDescriptor{Count: 1, Length: uint64(length), Digest: contract.ID(sha256.Sum256(preimage))}
			actual, carriers, err := generatedCarrierRows(before.root.Domain, contract.GeneratedParentSupportKind, source.OriginalOperationID,
				contract.GeneratorVectorSupport, [][]byte{binding})
			if err != nil || actual != want {
				t.Fatal("independent support bytes or digest disagree", actual, want, err)
			}
			if source.Record.Kind == contract.GeneratedDutySupportKind {
				source.Duty.Support = want
				source.Record.Body = mustEncodeGeneratedDutyForSupportTest(t, source.Duty)
			} else {
				source.Hazard.Support = want
				source.Record.Body, err = contract.EncodeGeneratedHazardRecord(source.Hazard)
				if err != nil {
					t.Fatal(err)
				}
			}
			generatedReplaceRecord(t, before, source.Record.Kind, source.SourceID, source.Record.Body)
			for _, row := range carriers {
				last := &before.support[len(before.support)-1]
				last.Records = append(last.Records, contract.SupportRecordView(row))
			}
			generatedRefreshSupport(t, before)
			if _, err := before.validateRelationsMode(t.Context(), false); err != nil {
				t.Fatal("nonempty retained support predecessor", err)
			}
			source, err = contract.InspectGeneratedDeleteSource(source.Record)
			if err != nil {
				t.Fatal(err)
			}
			operation := generatedVectorID(98)
			var input generatedReservationInput
			if kind == "retirement-duty" {
				input = generatedDeleteReservationInputFixture(t, before, operation, 2)
			} else {
				input = generatedOrdinaryCleanupReservationInput(t, before, source, operation)
			}
			declaration, err := contract.InspectGeneratorDeclaration(input.declaration)
			if err != nil {
				t.Fatal(err)
			}
			prior, err := before.selectedGeneratedWork(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			shape, err := before.generatedAdmissionShape(t.Context(), input.graph, declaration, prior)
			if err != nil || shape.deleteSupport != want {
				t.Fatal("delete admission omitted exact copied support", err)
			}
			shape.DeclarationBytes, shape.RegistryBytes = uint64(len(input.declaration)), uint64(len(input.registryImage))
			withoutCopy := shape
			withoutCopy.deleteSupport = contract.GeneratorDescriptor{}
			capacity, err := generatedCapacityWithBacklog(shape, prior)
			if err != nil {
				t.Fatal(err)
			}
			baseline, err := generatedCapacityWithBacklog(withoutCopy, prior)
			if err != nil {
				t.Fatal(err)
			}
			// The 103-byte binding adds one 120-byte carrier and 37-byte record.
			// Both operation-owned copies fit the same auxiliary index page.
			baseline[contract.GeneratorCapacityAuxiliary].MaxCount++
			baseline[contract.GeneratorCapacityAuxiliary].MaxFramedBytes += 260
			if capacity != baseline {
				t.Fatal("fresh support copy has an incorrect complete capacity charge", capacity, baseline)
			}
			rows, direct, groups, err := generatedAdministrativeRowEnvelope(shape)
			if err != nil {
				t.Fatal(err)
			}
			withoutRows, withoutDirect, withoutGroups, err := generatedAdministrativeRowEnvelope(withoutCopy)
			withoutRows[contract.GeneratorVectorSupportKind]++
			if err != nil || rows != withoutRows || direct != withoutDirect || groups != withoutGroups {
				t.Fatal("fresh support copy changed the administrative row or owner charge", rows, withoutRows, err)
			}
			reservation, err := before.deriveGeneratedReservation(t.Context(), input)
			if err != nil {
				t.Fatal("fresh delete with nonempty retained support", err)
			}
			reservation.state.generatedWork = nil
			reservation.state.clearSelectedSupportFacts()
			after, err := reservation.state.selectedGeneratedWork(t.Context())
			if err != nil {
				t.Fatal("cold selection of fresh delete support", err)
			}
			x := input.graph.Lineages[0].Templates[0]
			attempt, present := after.attempts[x.AttemptID]
			retained, err := after.generatedDeleteSource(source.OwnerID)
			if err != nil || !present || attempt.record.OperationID != operation || attempt.record.Support != want || retained.Support != want ||
				retained.OriginalOperationID != source.OriginalOperationID || retained.ExecutorID != source.ExecutorID || retained.CredentialRouteID != source.CredentialRouteID {
				t.Fatal("fresh delete changed exact retained support or route", err)
			}
			if operation == source.OriginalOperationID {
				t.Fatal("fixture did not use distinct support owners")
			}
			for _, owner := range []contract.ID{source.OriginalOperationID, operation} {
				rows, err := after.vectors.resolve(contract.GeneratedParentSupportKind, owner, contract.GeneratorVectorSupport, want)
				if err != nil || len(rows) != 1 || !bytes.Equal(rows[0], binding) {
					t.Fatal("operation-owned support lost exact binding bytes", owner, err)
				}
			}
		})
	}
}

func mustEncodeGeneratedDutyForSupportTest(t testing.TB, duty contract.GeneratedDutyRecord) []byte {
	t.Helper()
	body, err := contract.EncodeGeneratedDutyRecord(duty)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func generatedDeleteReservationInputFixture(t testing.TB, before *StateSession, operation contract.ID, purpose uint8, sources ...contract.GeneratorDeclarationEntry) generatedReservationInput {
	t.Helper()
	t.Log("construct entered delete fixture")
	entered, _, duty, _ := generatedEnteredRetirementForOperation(t, operation, false)
	t.Log("construct clean reservation input")
	enteredWork, err := entered.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	deleteLineage := enteredWork.bundles[0].Lineages[0]
	deleteUse := enteredWork.bundles[0].ResultUses[0]
	if purpose != 2 {
		t.Fatal("cleanup fixture not implemented")
	}
	input := generatedReservationInputForOperation(t, before, operation, sources...)
	t.Log("rewrite clean reservation as delete-only")
	// This is a newly issued DELETE for an accepted original Duty. Its
	// enclosing graph and Attempt are current; the original result reader is not.
	input.graph.Header.Schema = contract.GeneratorGraphHeaderSchema
	input.graph.UsePlan.ValueDerivationID = contract.GeneratorValueDerivationID()
	deleteLineage.Schema = contract.GeneratorLineageTemplateSchema
	x := &deleteLineage.Templates[0]
	x.Schema, x.LifecycleMode, x.ResultReaderID = contract.GeneratorAttemptTemplateSchema, contract.GeneratorLifecycleManaged, contract.GeneratorResultReaderID()
	x.RequestPlanDigest, err = contract.GeneratorRequestPlanDigest(*x)
	if err != nil {
		t.Fatal("current delete request plan", err)
	}
	sources = slices.Clone(sources)
	for i := range sources {
		sources[i].Schema = contract.GeneratorDeclarationEntrySchema
	}
	declaration := contract.GeneratorDeclaration{Schema: 1, DomainID: input.graph.Header.DomainID, OperationID: operation, Entries: slices.Clone(sources)}
	input.declaration, err = contract.EncodeGeneratorDeclaration(declaration)
	if err != nil {
		t.Fatal("declaration", err)
	}
	input.graph.Request.Declaration, err = contract.GeneratorDeclarationDescriptor(declaration)
	if err != nil {
		t.Fatal("declaration descriptor", err)
	}
	input.graph.Request.OperationKind = 38
	input.graph.Header.RequestCoreDigest, err = contract.GeneratorRequestCoreDigest(input.graph.Request)
	if err != nil {
		t.Fatal("request core", err)
	}
	input.graph.ValueEntryPlans = slices.DeleteFunc(input.graph.ValueEntryPlans, func(v contract.GeneratorValueEntryPlan) bool {
		return v.ValueSource == contract.Generated
	})
	for i := range input.graph.ValueEntryPlans {
		input.graph.ValueEntryPlans[i].Schema, input.graph.ValueEntryPlans[i].Slot = contract.GeneratorValueEntryPlanSchema, uint16(i)
	}
	input.graph.Header.ValueEntryPlanCount = uint16(len(input.graph.ValueEntryPlans))
	input.graph.Lineages = []contract.GeneratorLineageTemplate{deleteLineage}
	input.graph.Header.LineageCount, input.graph.Header.TemplateCount = 0, 1
	input.requestBindings = generatedFixtureRequestBindings(input.graph, generatedVectorID(61))
	join, err := contract.GeneratorCompleteJoinID(input.graph.Header.RequestCoreDigest)
	if err != nil {
		t.Fatal("complete join", err)
	}
	template, err := contract.GeneratorTemplateID(deleteLineage.Templates[0])
	if err != nil {
		t.Fatal("template", err)
	}
	input.graph.Edges = nil
	for _, guard := range []uint8{3, 4} {
		input.graph.Edges = append(input.graph.Edges, contract.GeneratorEdge{Schema: 1, SourceTemplateID: template,
			DestinationTemplateID: join, Guard: guard, ResultSlotID: deleteLineage.Templates[0].ResultID, RequiredAuthoritySet: 1})
	}
	input.graph.ResultUses = []contract.GeneratorResultUse{deleteUse}
	input.graph.UsePlan.ResultUses, err = contract.GeneratorResultUsesDescriptor(input.graph.ResultUses)
	if err != nil {
		t.Fatal("result uses", err)
	}
	input.graph.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(input.graph.Header, input.graph.ValueEntryPlans, input.graph.Lineages, input.graph.Edges)
	if err != nil {
		t.Fatal("graph id", err)
	}
	input.parent.PlanGraphID, input.parent.TemplateCount, input.parent.LineageCount = input.graph.UsePlan.PlanGraphID, 1, 0
	input.parent.RequestCoreDigest, input.parent.ValueEntryPlanCount, input.parent.Declaration = input.graph.Header.RequestCoreDigest, input.graph.Header.ValueEntryPlanCount, input.graph.Request.Declaration
	input.parent.IntendedEntryPlans, err = contract.GeneratorValueEntryPlansDescriptor(input.graph.ValueEntryPlans)
	if err != nil {
		t.Fatal("intended members", err)
	}
	input.parent.UsePlanDigest, err = contract.GeneratorUsePlanDigest(input.graph.UsePlan)
	if err != nil {
		t.Fatal("use plan", err)
	}
	input.parent.Graph, err = contract.GeneratorPlanBundleDescriptor(input.graph)
	if err != nil {
		t.Fatal("bundle descriptor", err)
	}
	input.finished.Material.Core.UsePlanDigest = input.parent.UsePlanDigest
	for i := range input.finished.SourceProtections {
		input.finished.SourceProtections[i].Transfer.Core.UsePlanDigest = input.parent.UsePlanDigest
	}
	seed, err := contract.DecodeAccessRecord(input.finished.SeedAccess)
	if err != nil {
		t.Fatal("seed decode", err)
	}
	seed.MaterialContextDigest, err = contract.OperationMaterialContextDigest(input.finished.Material.Core)
	if err != nil {
		t.Fatal("material context", err)
	}
	input.finished.SeedAccess, err = contract.EncodeAccessRecord(seed)
	if err != nil {
		t.Fatal("seed encode", err)
	}
	if deleteLineage.Templates[0].DutyID != duty.DutyID {
		t.Fatal("delete fixture did not select predecessor duty")
	}
	return input
}

// full_only: false
func TestGeneratedFreshRetirementReservationInstallsExactDeleteAttempt(t *testing.T) {
	old, duty, target := generatedDetachedRetirementState(t, "absent", 0)
	assertOriginalDuty := func(actual contract.GeneratedDutyRecord) {
		t.Helper()
		actual.Status, actual.History, actual.Consumers = duty.Status, duty.History, duty.Consumers
		if actual != duty {
			t.Fatal("new invocation changed the accepted Duty's immutable tuple")
		}
	}
	before := generatedEmptyPredecessor(t)
	before.support, before.root.Generated = old.support, old.root.Generated
	generatedRefreshSupport(t, before)
	before.recountChildren()
	if _, relationErr := before.validateRelationsMode(t.Context(), false); relationErr != nil {
		t.Fatal("invalid detached retirement predecessor")
	}
	input := generatedDeleteReservationInputFixture(t, before, generatedVectorID(98), 2)
	prior, err := before.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal("select predecessor", err)
	}
	if err := contract.ValidateGeneratorEffectGraph(input.graph); err != nil {
		t.Fatal("delete graph", err)
	}
	if _, ok, err := before.generatedDeleteReservationSelection(t.Context(), input.graph, prior); err != nil || !ok {
		t.Fatal("delete reservation selection", err)
	}
	reservation, err := before.deriveGeneratedReservation(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	after, err := reservation.state.selectedGeneratedWork(context.Background())
	if err != nil || reservation.state.validateGeneratedSelection(t.Context(), nil) != nil {
		t.Fatal("fresh delete reservation is not a selected generated state", err)
	}
	x := input.graph.Lineages[0].Templates[0]
	attempt, ok := after.attempts[x.AttemptID]
	if !ok || attempt.record.State != contract.GeneratedEffectTransmitted || attempt.expected.TargetResourceDigest != target.ResourceDigest ||
		after.parent == nil || after.parent.OperationID != input.graph.Header.OperationID || after.phase == nil || after.phase.Phase != 2 {
		t.Fatal("fresh delete reservation lost exact target or active attempt")
	}
	if attempt.record.Schema != contract.GeneratedAttemptRecordSchema || attempt.record.LifecycleMode != contract.GeneratorLifecycleManaged || x.ResultReaderIdentity() != contract.GeneratorResultReaderID() {
		t.Fatal("new DELETE inherited the original stored Attempt schema or changed its reader")
	}
	row, ok := after.records[generatedRecordKey{kind: 10, id: duty.DutyID}]
	if !ok {
		t.Fatal("fresh delete reservation lost retirement duty")
	}
	reservedDuty, err := contract.InspectGeneratedDutyRecord(row.Body)
	if err != nil || reservedDuty.Schema != duty.Schema || reservedDuty.LifecycleMode != duty.LifecycleMode || reservedDuty.Status != contract.GeneratedEffectTransmitted || reservedDuty.Target != duty.Target ||
		reservedDuty.CapacityReservation != duty.CapacityReservation {
		t.Fatal("fresh delete reservation changed the exact obligation", err)
	}
	assertOriginalDuty(reservedDuty)
	if reservation.candidate.head.Generator == nil || reservation.candidate.head.Generator.Purpose != contract.GeneratorAuthorityRetireReserve ||
		reservation.candidate.head.Generator.OwnerID != duty.DutyID || reservation.candidate.head.Generator.CapacityReservation != duty.CapacityReservation {
		t.Fatal("fresh delete reservation did not bind retirement authority")
	}
	beforeEntryUnion, afterEntryUnion := before.generatedUnchangedEntryUnion(), reservation.state.generatedUnchangedEntryUnion()
	if !reflect.DeepEqual(beforeEntryUnion, afterEntryUnion) {
		t.Fatal("fresh delete reservation changed the member set")
	}
	packet := generatedRetirementResultFixture(t, reservation.state, attempt, contract.GeneratorDispositionRetirementAcknowledged)
	result, err := contract.DecodeGeneratedResultRecord(packet)
	if err != nil || result.Core.Schema != contract.GeneratedResultCoreSchema || result.SafeFacts.Schema != contract.GeneratorSafeFactsSchema {
		t.Fatal("new DELETE reinterpreted the original result reader", err)
	}
	record, err := reservation.state.generatedRecordRequest(t.Context(), x.AttemptID, packet, generatedContinuationContext(t, reservation.state, 130, 131))
	if err != nil {
		t.Fatal("original-reader DELETE ACK request", err)
	}
	recorded, err := reservation.state.deriveGeneratedRecord(t.Context(), record)
	if err != nil {
		t.Fatal("original-reader DELETE ACK selection", err)
	}
	continued := mustSelectedGeneratedWork(t, recorded.state)
	closedAttempt := continued.attempts[x.AttemptID].record
	closedDuty, err := contract.InspectGeneratedDutyRecord(continued.records[generatedRecordKey{10, duty.DutyID}].Body)
	if err != nil || closedAttempt.Schema != contract.GeneratedAttemptRecordSchema || closedAttempt.State != contract.GeneratedEffectSucceeded || closedDuty.Schema != duty.Schema || closedDuty.LifecycleMode != duty.LifecycleMode || closedDuty.Target != duty.Target || closedDuty.CapacityReservation != duty.CapacityReservation {
		t.Fatal("new original-reader DELETE changed stored version or accepted obligation", err)
	}
	assertOriginalDuty(closedDuty)
}

// full_only: false
func TestGeneratedFreshRetirementWithSealedSourceReservesConfigurationCarrier(t *testing.T) {
	old, _, _ := generatedDetachedRetirementState(t, "absent", 0)
	before := generatedEmptyPredecessor(t)
	before.support, before.root.Generated = old.support, old.root.Generated
	generatedRefreshSupport(t, before)
	before.recountChildren()
	if _, relationErr := before.validateRelationsMode(t.Context(), false); relationErr != nil {
		t.Fatal("invalid detached retirement predecessor")
	}
	source := generatedSealedSource(t, "sealed")
	envelope, err := contract.DecodeSealedInputEnvelope(source.Payload)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Core.CryptoSupportID = before.root.CurrentAccess.Core.CryptoSupportID
	bindingDigest, err := contract.PublicBindingDigest(*before.authority().CurrentBinding)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Core.IntendedRecipientBindingSetDigest, err = contract.IntendedRecipientBindingSetDigest(before.root.Domain,
		before.admission.recipient, []contract.RecipientBindingReference{{RecipientID: before.admission.recipient, PublicBindingDigest: bindingDigest}})
	if err != nil {
		t.Fatal(err)
	}
	source.Payload, err = contract.EncodeSealedInputEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	input := generatedDeleteReservationInputFixture(t, before, generatedVectorID(98), 2, source)
	declaration, err := contract.InspectGeneratorDeclaration(input.declaration)
	if err != nil || contract.ValidateGeneratorEffectGraph(input.graph) != nil || contract.ValidateGeneratorDeclarationGraph(declaration, input.graph) != nil {
		t.Fatal("one-retirement one-source graph is invalid", err)
	}
	prior, err := before.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	shape, err := before.generatedAdmissionShape(t.Context(), input.graph, declaration, prior)
	if err != nil || shape.Retirements != 1 || shape.Sources != 1 || shape.ControlledRetirements != 0 {
		t.Fatal("one-retirement one-source shape was not admitted", shape, err)
	}
	shape.DeclarationBytes = uint64(len(input.declaration))
	groups, err := generatedCleanCapacity(shape)
	if err != nil || groups[contract.GeneratorCapacityGraph].MaxCount < 9 {
		t.Fatal("configuration carrier omitted from one-retirement one-source charge", shape, groups[contract.GeneratorCapacityGraph], err)
	}
	if _, err := contract.EncodeCryptoGeneratedFinishPlanResult(input.finished); err != nil {
		t.Fatal("invalid supplied finish result", err)
	}
	reservation, err := before.deriveGeneratedReservation(context.Background(), input)
	if err != nil {
		t.Fatal("one-retirement one-source reservation", err)
	}
	if _, err := reservation.state.selectedGeneratedWork(context.Background()); err != nil {
		t.Fatal("one-retirement one-source successor", err)
	}
}

// full_only: false
func TestGeneratedFreshRetirementReservationPreservesPriorUnknownInvocation(t *testing.T) {
	before, original, duty := generatedParkedRetirementState(t)
	generatedLifecycleFixture(t, before)
	prior, err := before.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	oldAttempt := prior.records[generatedRecordKey{9, original.record.AttemptID}]
	oldFacts, err := prior.vectors.resolve(9, original.record.AttemptID, contract.GeneratorVectorFacts, original.record.Facts)
	if err != nil {
		t.Fatal(err)
	}
	input := generatedDeleteReservationInputFixture(t, before, generatedVectorID(98), 2)
	reservation, err := before.deriveGeneratedReservation(context.Background(), input)
	if err != nil {
		t.Fatal("fresh same-obligation reservation", err)
	}
	after, err := reservation.state.selectedGeneratedWork(context.Background())
	if err != nil || reservation.state.validateGeneratedSelection(t.Context(), nil) != nil {
		t.Fatal("fresh invocation is not authenticated", err)
	}
	if got := after.records[generatedRecordKey{9, original.record.AttemptID}]; !reflect.DeepEqual(got, oldAttempt) {
		t.Fatal("fresh invocation changed the terminated original Attempt")
	}
	gotFacts, err := after.vectors.resolve(9, original.record.AttemptID, contract.GeneratorVectorFacts, original.record.Facts)
	if err != nil || !reflect.DeepEqual(gotFacts, oldFacts) {
		t.Fatal("fresh invocation discarded prior uncertainty", err)
	}
	row := after.records[generatedRecordKey{10, duty.DutyID}]
	current, err := contract.InspectGeneratedDutyRecord(row.Body)
	if err != nil || current.Target != duty.Target || current.Progress != duty.Progress || current.CompletionClass != duty.CompletionClass ||
		current.History.Count != duty.History.Count+1 || current.Consumers.Count != duty.Consumers.Count+1 {
		t.Fatal("fresh invocation reset the exact obligation or its coverage", err)
	}
	if after.phase.FrontierAttemptID == original.record.AttemptID || after.parent.OperationID == original.record.OperationID ||
		len(after.attempts) != 2 || reservation.candidate.firstSend != nil {
		t.Fatal("fresh reservation restarted an old Attempt or fabricated a first-send right")
	}
}

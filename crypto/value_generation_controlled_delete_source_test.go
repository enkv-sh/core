package crypto

import (
	"bytes"
	"fmt"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/internal/custody"
)

func generatedReflectedControlledSourceFixture(t *testing.T, conflict string, fenced bool) (generatedAdmission, contract.GeneratedControlledPredecessor, contract.GeneratorProgress) {
	t.Helper()
	a, input := generatedResultFreeControlledSourceFixture(t, "exact")
	var attempt contract.GeneratedAttemptRecord
	var material contract.OperationMaterialRecord
	var unknown contract.GeneratorSafeFacts
	for _, row := range input.BeforeRecords {
		var err error
		switch row.Kind {
		case contract.OperationMaterialSupportKind:
			material, err = contract.InspectOperationMaterialRecord(row.Body)
		case contract.GeneratedAttemptSupportKind:
			attempt, err = contract.InspectGeneratedAttemptRecord(row.Body)
		case contract.GeneratorVectorSupportKind:
			carrier, inspectErr := contract.InspectGeneratorVectorCarrier(row.Body)
			if inspectErr != nil {
				t.Fatal(inspectErr)
			}
			if carrier.OwnerKind == contract.GeneratedAttemptSupportKind && carrier.VectorKind == contract.GeneratorVectorFacts {
				facts, inspectErr := contract.InspectGeneratorFactsRow(carrier.Row)
				if inspectErr != nil {
					t.Fatal(inspectErr)
				}
				view, inspectErr := contract.InspectGeneratorSafeFacts(facts.Facts)
				if inspectErr != nil {
					t.Fatal(inspectErr)
				}
				unknown, err = view.Own()
			}
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	seed := bytes.Repeat([]byte{61}, 32)
	defer clear(seed)
	var err error
	material.SeedCheck, err = custody.SeedCheck(material.Core, seed)
	if err != nil {
		t.Fatal(err)
	}
	ack := unknown
	ack.Disposition, ack.Reason = contract.GeneratorDispositionRetirementAcknowledged, contract.GeneratorReasonNone
	expected := contract.GeneratorResultExpectation{InputEncoding: contract.InputEncodingRaw, Plan: a.graph.UsePlan, Template: a.graph.Lineages[0].Templates[0], Use: a.graph.ResultUses[0],
		RequestDigest: attempt.RequestDigest, TargetResourceDigest: a.deleteTarget().ResourceDigest}
	result, err := custody.SealGeneratedResult(expected, material, ack, seed, nil)
	if err != nil {
		t.Fatal("seal exact late acknowledgement", err)
	}
	packet, err := contract.EncodeGeneratedResultRecord(result)
	if err != nil {
		t.Fatal(err)
	}
	progress := contract.GeneratorProgress{Schema: 1, AttemptID: attempt.AttemptID, ResultID: attempt.ResultID,
		Evidence:      contract.GeneratorDescriptor{Digest: contract.Hash(packet), Length: uint64(len(packet)), Count: 1},
		RequiredSteps: contract.GeneratorConfirmedRequiredSteps, CompletedSteps: contract.GeneratorProgressAcknowledged, CompletionClass: contract.GeneratedCompletionConfirmed}
	progressBody, err := contract.EncodeGeneratorProgress(progress)
	if err != nil {
		t.Fatal(err)
	}
	switch conflict {
	case "identity":
		unknown.Reason = contract.GeneratorReasonIdentityConflict
	case "resource":
		unknown.ResourceData = bytes.Repeat([]byte{62}, 32)
	}
	factsBody, err := contract.EncodeGeneratorSafeFacts(unknown)
	if err != nil {
		t.Fatal(err)
	}
	factsBody, err = contract.EncodeGeneratorFactsRow(contract.GeneratorFactsRow{Schema: 1, ResultID: attempt.ResultID, Facts: factsBody})
	if err != nil {
		t.Fatal(err)
	}
	attempt.Facts, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorFacts, [][]byte{factsBody})
	if err != nil {
		t.Fatal(err)
	}
	duty, err := contract.InspectGeneratedDutyRecord(input.Source.Body)
	if err != nil {
		t.Fatal(err)
	}
	duty.Step = 2
	duty.Progress, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorProgress, [][]byte{progressBody})
	if err != nil {
		t.Fatal(err)
	}
	input.Source.Body, err = contract.EncodeGeneratedDutyRecord(duty)
	if err != nil {
		t.Fatal(err)
	}
	var records []contract.SupportRecord
	for _, row := range input.BeforeRecords {
		switch row.Kind {
		case contract.OperationMaterialSupportKind:
			row.Body, err = contract.EncodeOperationMaterialRecord(material)
		case contract.GeneratedAttemptSupportKind:
			row.Body, err = contract.EncodeGeneratedAttemptRecord(attempt)
		case contract.GeneratedDutySupportKind:
			row = input.Source
		case contract.GeneratorVectorSupportKind:
			carrier, inspectErr := contract.InspectGeneratorVectorCarrier(row.Body)
			if inspectErr != nil {
				t.Fatal(inspectErr)
			}
			if carrier.OwnerKind == contract.GeneratedAttemptSupportKind && carrier.OwnerID == attempt.AttemptID && carrier.VectorKind == contract.GeneratorVectorFacts {
				continue
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, row)
	}
	records = append(records, contract.SupportRecord{Kind: contract.GeneratedResultSupportKind, RecordID: attempt.ResultID, Body: packet})
	records = append(records, generatedVectorSupport(t, duty.DomainID, contract.GeneratedAttemptSupportKind, attempt.AttemptID, contract.GeneratorVectorFacts, [][]byte{factsBody})...)
	records = append(records, generatedVectorSupport(t, duty.DomainID, contract.GeneratedDutySupportKind, duty.DutyID, contract.GeneratorVectorProgress, [][]byte{progressBody})...)
	if fenced {
		attempt.State = contract.GeneratedEffectClosedWithResidue
		historyBody, err := contract.EncodeGeneratorHistory(contract.GeneratorHistory{Schema: 1, PredecessorAttemptID: attempt.AttemptID,
			OwnerID: attempt.OwnerID, Outcome: contract.GeneratedEffectClosedWithResidue})
		if err != nil {
			t.Fatal(err)
		}
		attempt.History, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorHistory, [][]byte{historyBody})
		if err != nil {
			t.Fatal(err)
		}
		hazard := contract.GeneratedHazardRecord{Schema: contract.GeneratedHazardRecordSchema,
			DomainID: duty.DomainID, HazardID: a.graph.Lineages[0].Templates[0].HazardID, OriginalOperationID: attempt.OperationID, OriginalAttemptID: attempt.AttemptID,
			OwnerID: duty.OwnerID, ResourceID: duty.ResourceID, ConfigContractID: duty.ConfigContractID, ResourceContractID: duty.ResourceContractID,
			ExecutorID: duty.ExecutorID, CredentialRouteID: duty.CredentialRouteID, DescriptorID: duty.DescriptorID, ResultContractID: duty.ResultContractID,
			CapacityReservation: duty.CapacityReservation, Exposure: contract.GeneratedExposurePossibleLive, CompletionClass: duty.CompletionClass,
			Fenced: 1, Eligibility: contract.GeneratedExposurePossibleLive, Target: duty.Target, History: attempt.History, Support: duty.Support}
		hazard.OriginalResults, err = contract.GeneratorRecordSetDescriptor(contract.GeneratorHazardResults, duty.DomainID,
			[]contract.SupportRecord{{Kind: contract.GeneratedResultSupportKind, RecordID: attempt.ResultID, Body: packet}})
		if err != nil {
			t.Fatal(err)
		}
		var retained []contract.SupportRecord
		var targets, consumers [][]byte
		for _, row := range records {
			switch row.Kind {
			case contract.GeneratedDutySupportKind:
				continue
			case contract.GeneratedAttemptSupportKind:
				row.Body, err = contract.EncodeGeneratedAttemptRecord(attempt)
			case contract.GeneratorVectorSupportKind:
				carrier, inspectErr := contract.InspectGeneratorVectorCarrier(row.Body)
				if inspectErr != nil {
					t.Fatal(inspectErr)
				}
				if carrier.OwnerKind == contract.GeneratedDutySupportKind && carrier.OwnerID == duty.DutyID {
					switch carrier.VectorKind {
					case contract.GeneratorVectorTargets:
						targets = append(targets, carrier.Row)
					case contract.GeneratorVectorConsumers:
						consumer, inspectErr := contract.InspectGeneratorConsumer(carrier.Row)
						if inspectErr != nil {
							t.Fatal(inspectErr)
						}
						consumer.OwnerID = hazard.HazardID
						body, encodeErr := contract.EncodeGeneratorConsumer(consumer)
						if encodeErr != nil {
							t.Fatal(encodeErr)
						}
						consumers = append(consumers, body)
					}
					continue
				}
				if carrier.OwnerKind == contract.GeneratedAttemptSupportKind && carrier.OwnerID == attempt.AttemptID && carrier.VectorKind == contract.GeneratorVectorHistory {
					continue
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			retained = append(retained, row)
		}
		hazard.Consumers, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorConsumers, consumers)
		if err != nil {
			t.Fatal(err)
		}
		input.Source = contract.SupportRecord{Kind: contract.GeneratedHazardSupportKind, RecordID: hazard.HazardID}
		input.Source.Body, err = contract.EncodeGeneratedHazardRecord(hazard)
		if err != nil {
			t.Fatal(err)
		}
		retained = append(retained, input.Source)
		retained = append(retained, generatedVectorSupport(t, duty.DomainID, contract.GeneratedAttemptSupportKind, attempt.AttemptID, contract.GeneratorVectorHistory, [][]byte{historyBody})...)
		retained = append(retained, generatedVectorSupport(t, duty.DomainID, contract.GeneratedHazardSupportKind, hazard.HazardID, contract.GeneratorVectorHistory, [][]byte{historyBody})...)
		retained = append(retained, generatedVectorSupport(t, duty.DomainID, contract.GeneratedHazardSupportKind, hazard.HazardID, contract.GeneratorVectorTargets, targets)...)
		retained = append(retained, generatedVectorSupport(t, duty.DomainID, contract.GeneratedHazardSupportKind, hazard.HazardID, contract.GeneratorVectorConsumers, consumers)...)
		records = retained
	}
	slices.SortFunc(records, func(a, b contract.SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	a.before.RequiredSupport, err = contract.RequiredSupportDescriptor(duty.DomainID, records)
	if err != nil {
		t.Fatal(err)
	}
	input.BeforeRecords = records
	return a, input, progress
}

// full_only: false
func TestGeneratedControlledReflectedAcknowledgementKeepsHistoricalContradiction(t *testing.T) {
	for _, tc := range []struct {
		name, conflict string
		fenced         bool
	}{{"duty/clean", "none", false}, {"duty/identity", "identity", false}, {"duty/resource", "resource", false}, {"hazard/clean", "none", true}, {"hazard/identity", "identity", true}} {
		t.Run(tc.name, func(t *testing.T) {
			a, input, want := generatedReflectedControlledSourceFixture(t, tc.conflict, tc.fenced)
			source, progress, err := a.controlledSelectedSource(&input)
			if tc.conflict != "none" {
				if err == nil {
					t.Fatal("late acknowledgement hid contradictory historical facts")
				}
				return
			}
			if err != nil || source.SourceID != input.Source.RecordID || len(progress) != 1 {
				t.Fatal("uncontested late acknowledgement lost its exact nonfinal prefix", err)
			}
			got, err := contract.InspectGeneratorProgress(progress[0])
			if err != nil || got != want {
				t.Fatal("late acknowledgement changed its retained predecessor", err)
			}
		})
	}
}

func generatedResultFreeControlledSourceFixture(t *testing.T, damage string) (generatedAdmission, contract.GeneratedControlledPredecessor) {
	t.Helper()
	f := generatedSelectDeleteProducer(t, generatedDeleteProducerFixture(t, false), contract.GeneratedDutyRetirement)
	g, err := contract.DecodeGeneratorPlanBundle(f.graph)
	if err != nil {
		t.Fatal(err)
	}
	x := &g.Lineages[0].Templates[0]
	oldTemplate, err := contract.GeneratorTemplateID(*x)
	if err != nil {
		t.Fatal(err)
	}
	x.CompletionClass = contract.GeneratedCompletionConfirmed
	x.RequestPlanDigest, err = contract.GeneratorRequestPlanDigest(*x)
	if err != nil {
		t.Fatal(err)
	}
	newTemplate, err := contract.GeneratorTemplateID(*x)
	if err != nil {
		t.Fatal(err)
	}
	for i := range g.Edges {
		if g.Edges[i].SourceTemplateID == oldTemplate {
			g.Edges[i].SourceTemplateID = newTemplate
		}
	}
	g.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(g.Header, g.ValueEntryPlans, g.Lineages, g.Edges)
	if err != nil {
		t.Fatal(err)
	}
	graphBody, err := contract.EncodeGeneratorPlanBundle(g)
	if err != nil || contract.ValidateGeneratorEffectGraph(g) != nil {
		t.Fatal("controlled standalone graph", err)
	}

	material := f.producer.Material
	material.Core.UsePlanDigest, err = contract.GeneratorUsePlanDigest(g.UsePlan)
	if err != nil {
		t.Fatal(err)
	}
	if damage == "material" {
		material.Core.UsePlanDigest = consumerID("unrelated result-free material use plan")
	}
	materialBody, err := contract.EncodeOperationMaterialRecord(material)
	if err != nil {
		t.Fatal(err)
	}

	target := *f.producer.Target
	target.CompletionClass = contract.GeneratedCompletionConfirmed
	targetBody, err := contract.EncodeGeneratorTarget(target)
	if err != nil {
		t.Fatal(err)
	}
	targetDescriptor, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorTargets, [][]byte{targetBody})
	if err != nil {
		t.Fatal(err)
	}

	p := f.producer.Producer
	attempt := p.Attempt
	attempt.TemplateDigest = newTemplate
	attempt.CompletionClass = contract.GeneratedCompletionConfirmed
	attempt.State, attempt.Stage = contract.GeneratedEffectUnknown, contract.GeneratedStageTerminal
	if damage == "template" {
		attempt.TemplateDigest = consumerID("unrelated result-free delete template")
	}
	original, err := contract.InspectGeneratorSafeFacts(p.OriginalFacts)
	if err != nil {
		t.Fatal(err)
	}
	factsBody, err := contract.EncodeGeneratorSafeFacts(contract.GeneratorSafeFacts{Schema: contract.GeneratorSafeFactsSchema, Action: contract.GeneratorActionDelete, LifecycleMode: x.LifecycleMode, ResourceContractID: x.ResourceContractID, Disposition: contract.GeneratorDispositionUnknown, Reason: contract.GeneratorReasonTransport, RequestDigest: attempt.RequestDigest, IntentDigest: x.IntentDigest,
		Target: original.Target, ResourceData: original.ResourceData})
	if err != nil {
		t.Fatal(err)
	}
	factsRow, err := contract.EncodeGeneratorFactsRow(contract.GeneratorFactsRow{Schema: 1, ResultID: attempt.ResultID, Facts: factsBody})
	if err != nil {
		t.Fatal(err)
	}
	attempt.Facts, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorFacts, [][]byte{factsRow})
	if err != nil {
		t.Fatal(err)
	}
	historyBody, err := contract.EncodeGeneratorHistory(contract.GeneratorHistory{Schema: 1, PredecessorAttemptID: attempt.AttemptID,
		OwnerID: p.Duty.DutyID, Outcome: contract.GeneratedEffectUnknown})
	if err != nil {
		t.Fatal(err)
	}
	attempt.History, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorHistory, [][]byte{historyBody})
	if err != nil {
		t.Fatal(err)
	}
	attemptBody, err := contract.EncodeGeneratedAttemptRecord(attempt)
	if err != nil {
		t.Fatal(err)
	}

	consumerBody := bytes.Clone(p.Consumers[0])
	if damage == "result use" {
		consumer, inspectErr := contract.InspectGeneratorConsumer(consumerBody)
		if inspectErr != nil {
			t.Fatal(inspectErr)
		}
		consumer.ContextDigest = consumerID("unrelated result-free result use")
		consumerBody, err = contract.EncodeGeneratorConsumer(consumer)
		if err != nil {
			t.Fatal(err)
		}
	}
	duty := p.Duty
	duty.CompletionClass = contract.GeneratedCompletionConfirmed
	duty.Step, duty.Status = 1, contract.GeneratedEffectUnknown
	duty.Target = targetDescriptor
	duty.History = attempt.History
	duty.Progress = contract.EmptyGeneratorVector(contract.GeneratorVectorProgress)
	duty.Consumers, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorConsumers, [][]byte{consumerBody})
	if err != nil {
		t.Fatal(err)
	}
	dutyBody, err := contract.EncodeGeneratedDutyRecord(duty)
	if err != nil {
		t.Fatal(err)
	}
	source := contract.SupportRecord{Kind: 10, RecordID: duty.DutyID, Body: dutyBody}

	records := []contract.SupportRecord{
		{Kind: 1, RecordID: g.Header.MaterialID, Body: materialBody},
		{Kind: 9, RecordID: attempt.AttemptID, Body: attemptBody},
		source,
	}
	records = append(records, generatedVectorSupport(t, g.Header.DomainID, 9, attempt.AttemptID, contract.GeneratorVectorFacts, [][]byte{factsRow})...)
	records = append(records, generatedVectorSupport(t, g.Header.DomainID, 9, attempt.AttemptID, contract.GeneratorVectorHistory, [][]byte{historyBody})...)
	records = append(records, generatedVectorSupport(t, g.Header.DomainID, 10, duty.DutyID, contract.GeneratorVectorTargets, [][]byte{targetBody})...)
	records = append(records, generatedVectorSupport(t, g.Header.DomainID, 10, duty.DutyID, contract.GeneratorVectorHistory, [][]byte{historyBody})...)
	records = append(records, generatedVectorSupport(t, g.Header.DomainID, 10, duty.DutyID, contract.GeneratorVectorConsumers, [][]byte{consumerBody})...)

	if damage != "missing graph" {
		if damage == "edges" {
			graphBody = bytes.Clone(graphBody)
			graphBody[len(graphBody)-contract.GeneratorUsePlanCoreLength-contract.GeneratorEdgeLength-12] ^= 1
		}
		blobID := consumerID("result-free standalone graph blob")
		fragmentBody, encodeErr := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: 1, BlobID: blobID, Count: 1,
			TotalLength: uint64(len(graphBody)), WholeDigest: contract.Hash(graphBody), Payload: graphBody})
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		fragmentID, idErr := contract.GeneratorFragmentID(blobID, 0)
		if idErr != nil {
			t.Fatal(idErr)
		}
		records = append(records, contract.SupportRecord{Kind: 3, RecordID: fragmentID, Body: fragmentBody})
		locationBody, encodeErr := contract.EncodeGeneratorSliceLocation(contract.GeneratorSliceLocation{Schema: 1,
			ContentKind: contract.GeneratorContentGraph, ContentID: g.UsePlan.PlanGraphID, BlobID: blobID,
			Length: uint32(len(graphBody)), Digest: contract.Hash(graphBody)})
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		ref, decodeErr := contract.DecodeRef(f.compare.Context.PredecessorRootRef[:], contract.CanonicalSchema)
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		records = append(records, generatedVectorSupport(t, g.Header.DomainID, contract.GeneratorSnapshotOwner, ref.Object,
			contract.GeneratorVectorSlices, [][]byte{locationBody})...)
	}
	slices.SortFunc(records, func(a, b contract.SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	required, err := contract.RequiredSupportDescriptor(g.Header.DomainID, records)
	if err != nil {
		t.Fatal(err)
	}
	a := generatedAdmission{request: f.compare, graph: g, before: contract.PublicState{RequiredSupport: required},
		purpose: generatedPurposeState{producer: &generatedProducerPreparationState{target: &target}}}
	return a, contract.GeneratedControlledPredecessor{Source: source, BeforeRecords: records}
}

func generatedControlledRetainedGraph(t *testing.T, base contract.GeneratorPlanBundle, material contract.OperationMaterialRecord,
	attempt contract.GeneratedAttemptRecord, ordinal int) (contract.GeneratorPlanBundle, contract.OperationMaterialRecord, contract.GeneratedAttemptRecord, []byte) {
	t.Helper()
	g := base
	g.Lineages, g.Edges, g.ResultUses = slices.Clone(base.Lineages), slices.Clone(base.Edges), slices.Clone(base.ResultUses)
	operation := consumerID(fmt.Sprintf("retained controlled operation %d", ordinal))
	g.Request.OperationID = operation
	g.Request.CallerNonce = consumerID(fmt.Sprintf("retained controlled nonce %d", ordinal))
	declaration := contract.GeneratorDeclaration{Schema: 1, DomainID: g.Header.DomainID, OperationID: operation}
	var err error
	g.Request.Declaration, err = contract.GeneratorDeclarationDescriptor(declaration)
	if err != nil {
		t.Fatal(err)
	}
	g.Header.OperationID = operation
	g.Header.MaterialID, err = contract.GeneratorMaterialID(g.Header.DomainID, operation)
	if err != nil {
		t.Fatal(err)
	}
	g.Header.RequestCoreDigest, err = contract.GeneratorRequestCoreDigest(g.Request)
	if err != nil {
		t.Fatal(err)
	}
	lineage := &g.Lineages[0]
	lineage.OperationID = operation
	lineage.LineageID, err = contract.GeneratorObligationLineageID(lineage.DomainID, operation, lineage.ResourceIncarnationID, lineage.Purpose)
	if err != nil {
		t.Fatal(err)
	}
	x := &lineage.Templates[0]
	x.LineageID = lineage.LineageID
	x.AttemptID, err = contract.GeneratorAttemptID(x.LineageID, x.Branch)
	if err != nil {
		t.Fatal(err)
	}
	x.PlannedValueSlotID, err = contract.GeneratorValueSlotID(lineage.DomainID, operation, x.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	x.HazardID, err = contract.GeneratorHazardID(lineage.DomainID, x.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	x.TransmissionID, err = contract.GeneratorTransmissionID(x.AttemptID, x.Action)
	if err != nil {
		t.Fatal(err)
	}
	x.ResultID, err = contract.GeneratorResultID(lineage.DomainID, operation, x.AttemptID, x.TransmissionID, x.Action)
	if err != nil {
		t.Fatal(err)
	}
	x.InboxID, err = contract.GeneratorInboxID(lineage.DomainID, operation, x.AttemptID, x.ResultID)
	if err != nil {
		t.Fatal(err)
	}
	templateID, err := contract.GeneratorTemplateID(*x)
	if err != nil {
		t.Fatal(err)
	}
	joinID, err := contract.GeneratorCompleteJoinID(g.Header.RequestCoreDigest)
	if err != nil {
		t.Fatal(err)
	}
	for i := range g.Edges {
		g.Edges[i].SourceTemplateID, g.Edges[i].DestinationTemplateID, g.Edges[i].ResultSlotID = templateID, joinID, x.ResultID
	}
	use := &g.ResultUses[0]
	use.AttemptID, use.ResultID, use.InboxID, use.PlannedValueSlotID, use.MaterialID = x.AttemptID, x.ResultID, x.InboxID, x.PlannedValueSlotID, g.Header.MaterialID
	g.UsePlan.OperationID, g.UsePlan.MaterialID = operation, g.Header.MaterialID
	g.UsePlan.ResultUses, err = contract.GeneratorResultUsesDescriptor(g.ResultUses)
	if err != nil {
		t.Fatal(err)
	}
	g.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(g.Header, g.ValueEntryPlans, g.Lineages, g.Edges)
	if err != nil {
		t.Fatal(err)
	}
	graphBody, err := contract.EncodeGeneratorPlanBundle(g)
	if err != nil || contract.ValidateGeneratorEffectGraph(g) != nil {
		t.Fatal("retained controlled graph", err)
	}
	material.Core.OperationID, material.Core.OperationMaterialID = operation, g.Header.MaterialID
	material.Core.UsePlanDigest, err = contract.GeneratorUsePlanDigest(g.UsePlan)
	if err != nil {
		t.Fatal(err)
	}
	attempt.OperationID, attempt.LineageID, attempt.AttemptID, attempt.TemplateDigest = operation, x.LineageID, x.AttemptID, templateID
	attempt.TransmissionID, attempt.ResultID, attempt.InboxID = x.TransmissionID, x.ResultID, x.InboxID
	return g, material, attempt, graphBody
}

func generatedControlledRetainedHistory(t *testing.T, count int, damage string) (generatedAdmission, contract.GeneratedControlledPredecessor) {
	t.Helper()
	a, input := generatedResultFreeControlledSourceFixture(t, "exact")
	var material contract.OperationMaterialRecord
	var attempt contract.GeneratedAttemptRecord
	var targetBody []byte
	var facts contract.GeneratorFactsRow
	var consumer contract.GeneratorConsumer
	for _, record := range input.BeforeRecords {
		var err error
		switch record.Kind {
		case 1:
			material, err = contract.InspectOperationMaterialRecord(record.Body)
		case 9:
			attempt, err = contract.InspectGeneratedAttemptRecord(record.Body)
		case contract.GeneratorVectorSupportKind:
			carrier, carrierErr := contract.InspectGeneratorVectorCarrier(record.Body)
			if carrierErr != nil {
				t.Fatal(carrierErr)
			}
			switch carrier.VectorKind {
			case contract.GeneratorVectorTargets:
				targetBody = carrier.Row
			case contract.GeneratorVectorFacts:
				facts, err = contract.InspectGeneratorFactsRow(carrier.Row)
			case contract.GeneratorVectorConsumers:
				consumer, err = contract.InspectGeneratorConsumer(carrier.Row)
			}
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if attempt.AttemptID.IsZero() || material.Core.OperationID.IsZero() || len(targetBody) == 0 || consumer.OwnerID.IsZero() {
		t.Fatal("incomplete retained source fixture")
	}
	source, err := contract.InspectGeneratedDutyRecord(input.Source.Body)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := contract.DecodeRef(a.request.Context.PredecessorRootRef[:], contract.CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	var records []contract.SupportRecord
	var attempts []contract.GeneratedAttemptRecord
	var consumers, locations [][]byte
	for i := 0; i < count; i++ {
		g, m, v := a.graph, material, attempt
		graphBody, err := contract.EncodeGeneratorPlanBundle(g)
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 {
			g, m, v, graphBody = generatedControlledRetainedGraph(t, a.graph, material, attempt, i)
		}
		materialBody, err := contract.EncodeOperationMaterialRecord(m)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, contract.SupportRecord{Kind: 1, RecordID: m.Core.OperationMaterialID, Body: materialBody})
		facts.ResultID = v.ResultID
		factsBody, err := contract.EncodeGeneratorFactsRow(facts)
		if err != nil {
			t.Fatal(err)
		}
		v.Facts, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorFacts, [][]byte{factsBody})
		if err != nil {
			t.Fatal(err)
		}
		localHistory, err := contract.EncodeGeneratorHistory(contract.GeneratorHistory{Schema: 1, PredecessorAttemptID: v.AttemptID,
			OwnerID: source.OwnerID, Outcome: contract.GeneratedEffectUnknown})
		if err != nil {
			t.Fatal(err)
		}
		v.History, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorHistory, [][]byte{localHistory})
		if err != nil {
			t.Fatal(err)
		}
		attemptBody, err := contract.EncodeGeneratedAttemptRecord(v)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, contract.SupportRecord{Kind: 9, RecordID: v.AttemptID, Body: attemptBody})
		records = append(records, generatedVectorSupport(t, source.DomainID, 9, v.AttemptID, contract.GeneratorVectorFacts, [][]byte{factsBody})...)
		records = append(records, generatedVectorSupport(t, source.DomainID, 9, v.AttemptID, contract.GeneratorVectorHistory, [][]byte{localHistory})...)
		attempts = append(attempts, v)

		c := consumer
		c.SubjectID, c.MaterialID = v.ResultID, m.Core.OperationMaterialID
		c.ContextDigest, err = contract.GeneratorResultUseDigest(g.ResultUses[0])
		if err != nil {
			t.Fatal(err)
		}
		if damage == "changed last consumer" && i == count-1 {
			c.ContextDigest = consumerID("changed retained consumer context")
		}
		consumerBody, err := contract.EncodeGeneratorConsumer(c)
		if err != nil {
			t.Fatal(err)
		}
		consumers = append(consumers, consumerBody)

		if damage == "missing last graph" && i == count-1 {
			continue
		}
		blobID := consumerID(fmt.Sprintf("retained controlled graph blob %d", i))
		fragmentBody, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: 1, BlobID: blobID, Count: 1,
			TotalLength: uint64(len(graphBody)), WholeDigest: contract.Hash(graphBody), Payload: graphBody})
		if err != nil {
			t.Fatal(err)
		}
		fragmentID, err := contract.GeneratorFragmentID(blobID, 0)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, contract.SupportRecord{Kind: 3, RecordID: fragmentID, Body: fragmentBody})
		locationBody, err := contract.EncodeGeneratorSliceLocation(contract.GeneratorSliceLocation{Schema: 1,
			ContentKind: contract.GeneratorContentGraph, ContentID: g.UsePlan.PlanGraphID, BlobID: blobID,
			Length: uint32(len(graphBody)), Digest: contract.Hash(graphBody)})
		if err != nil {
			t.Fatal(err)
		}
		locations = append(locations, locationBody)
	}
	var history [][]byte
	for i, v := range attempts {
		h := contract.GeneratorHistory{Schema: 1, PredecessorAttemptID: v.AttemptID,
			OwnerID: source.OwnerID, Outcome: contract.GeneratedEffectUnknown}
		if i+1 < len(attempts) {
			h.NextAttemptID, h.Edge = attempts[i+1].AttemptID, 4
		}
		body, err := contract.EncodeGeneratorHistory(h)
		if err != nil {
			t.Fatal(err)
		}
		history = append(history, body)
	}
	slices.SortFunc(consumers, func(a, b []byte) int { return bytes.Compare(a[2:], b[2:]) })
	slices.SortFunc(locations, func(a, b []byte) int { return bytes.Compare(a[2:35], b[2:35]) })
	source.History, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorHistory, history)
	if err != nil {
		t.Fatal(err)
	}
	source.Consumers, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorConsumers, consumers)
	if err != nil {
		t.Fatal(err)
	}
	sourceBody, err := contract.EncodeGeneratedDutyRecord(source)
	if err != nil {
		t.Fatal(err)
	}
	input.Source = contract.SupportRecord{Kind: 10, RecordID: source.DutyID, Body: sourceBody}
	records = append(records, input.Source)
	records = append(records, generatedVectorSupport(t, source.DomainID, 10, source.DutyID, contract.GeneratorVectorTargets, [][]byte{targetBody})...)
	records = append(records, generatedVectorSupport(t, source.DomainID, 10, source.DutyID, contract.GeneratorVectorHistory, history)...)
	records = append(records, generatedVectorSupport(t, source.DomainID, 10, source.DutyID, contract.GeneratorVectorConsumers, consumers)...)
	records = append(records, generatedVectorSupport(t, source.DomainID, contract.GeneratorSnapshotOwner, ref.Object, contract.GeneratorVectorSlices, locations)...)
	slices.SortFunc(records, func(a, b contract.SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	a.before.RequiredSupport, err = contract.RequiredSupportDescriptor(source.DomainID, records)
	if err != nil {
		t.Fatal(err)
	}
	input.BeforeRecords = records
	return a, input
}

// full_only: false
func TestGeneratedControlledRetainedHistoryUsesDistinctGraphs(t *testing.T) {
	for _, count := range []int{1, 2, 4, 8, 16} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			a, input := generatedControlledRetainedHistory(t, count, "")
			for pass := 0; pass < 2; pass++ {
				if pass == 1 {
					// Rehydrate from independent support bytes for the second admission.
					input.Source.Body = bytes.Clone(input.Source.Body)
					input.BeforeRecords = slices.Clone(input.BeforeRecords)
					for i := range input.BeforeRecords {
						input.BeforeRecords[i].Body = bytes.Clone(input.BeforeRecords[i].Body)
					}
				}
				start := time.Now()
				source, progress, err := a.controlledSelectedSource(&input)
				elapsed := time.Since(start)
				if err != nil || source.SourceID != input.Source.RecordID || len(progress) != 0 {
					t.Fatalf("valid retained history pass %d: %v", pass, err)
				}
				if pass == 1 {
					var measureErr error
					allocs := testing.AllocsPerRun(3, func() {
						_, _, measureErr = a.controlledSelectedSource(&input)
					})
					if measureErr != nil {
						t.Fatal("repeated retained source selection", measureErr)
					}
					bytes := 0
					for _, row := range input.BeforeRecords {
						bytes += len(row.Body)
					}
					t.Logf("retained=%d graphs=%d records=%d bytes=%d rehydrated_pass=%s allocs_per_pass=%.0f",
						count, count, len(input.BeforeRecords), bytes, elapsed, allocs)
				}
			}
		})
	}
	for _, damage := range []string{"changed last consumer", "missing last graph"} {
		t.Run(damage, func(t *testing.T) {
			a, input := generatedControlledRetainedHistory(t, 8, damage)
			if _, _, err := a.controlledSelectedSource(&input); err == nil {
				t.Fatal("changed late retained graph relation admitted")
			}
		})
	}
}

func generatedControlledHistoryGroups(t *testing.T, records []contract.SupportRecord) []format.RequiredSupportGroup {
	t.Helper()
	type key struct {
		class format.SupportStorageGroup
		owner contract.ID
	}
	groups := make(map[key][]contract.SupportRecord)
	for _, record := range records {
		var k key
		switch record.Kind {
		case 1:
			material, err := contract.InspectOperationMaterialRecord(record.Body)
			if err != nil {
				t.Fatal(err)
			}
			k = key{format.MaterialSupport, material.Core.OperationID}
		case 3:
			fragment, err := contract.InspectGeneratedFragment(record.Body)
			if err != nil {
				t.Fatal(err)
			}
			k = key{format.GraphFragmentSupport, fragment.BlobID}
		case 9:
			k = key{format.DeleteContinuationSupport, record.RecordID}
		case 10:
			k = key{format.OwnerSupport, record.RecordID}
		case contract.GeneratorVectorSupportKind:
			carrier, err := contract.InspectGeneratorVectorCarrier(record.Body)
			if err != nil {
				t.Fatal(err)
			}
			switch carrier.VectorKind {
			case contract.GeneratorVectorFacts:
				k = key{format.DeleteContinuationSupport, carrier.OwnerID}
			case contract.GeneratorVectorHistory:
				h, err := contract.InspectGeneratorHistory(carrier.Row)
				if err != nil {
					t.Fatal(err)
				}
				k = key{format.DeleteContinuationSupport, h.PredecessorAttemptID}
			case contract.GeneratorVectorTargets:
				k = key{format.OwnerSupport, carrier.OwnerID}
			case contract.GeneratorVectorConsumers:
				k = key{format.AuxiliaryIndexSupport, record.RecordID}
			case contract.GeneratorVectorSlices:
				k = key{format.GraphIndexSupport, record.RecordID}
			default:
				t.Fatal("unexpected retained vector kind", carrier.VectorKind)
			}
		default:
			t.Fatal("unexpected retained record kind", record.Kind)
		}
		groups[k] = append(groups[k], record)
	}
	out := make([]format.RequiredSupportGroup, 0, len(groups))
	for k, rows := range groups {
		out = append(out, format.RequiredSupportGroup{Class: k.class, Owner: k.owner, Records: rows})
	}
	return out
}

// full_only: false
func TestGeneratedControlledRetainedHistoryFitsPageLimit(t *testing.T) {
	// Five nonfragment classes use one page each. Fragment pages hold at most
	// two graphs. With three other children, 496 graphs use all 256 children.
	const otherChildren = 3
	for _, tc := range []struct {
		count int
		fit   bool
	}{{496, true}, {497, false}} {
		t.Run(fmt.Sprint(tc.count), func(t *testing.T) {
			a, input := generatedControlledRetainedHistory(t, tc.count, "")
			groups := generatedControlledHistoryGroups(t, input.BeforeRecords)
			pages, err := format.PackRequiredSupportRows(a.request.Context.DomainID, groups, otherChildren)
			if (err == nil) != tc.fit {
				t.Fatalf("retained graph page limit fit=%v: %v", tc.fit, err)
			}
			if tc.fit {
				if len(pages)+otherChildren != contract.MaxChildPages {
					t.Fatal("retained graph fixture did not reach the page boundary", len(pages))
				}
				if _, _, err := a.controlledSelectedSource(&input); err != nil {
					t.Fatal("maximum retained graph selection", err)
				}
			}
		})
	}
}

// full_only: false
func TestGeneratedControlledResultFreeDeleteBindsStandaloneGraphMaterialAndUse(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"exact", true},
		{"missing graph", false},
		{"template", false},
		{"result use", false},
		{"material", false},
		{"edges", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, input := generatedResultFreeControlledSourceFixture(t, tc.name)
			_, _, err := a.controlledSelectedSource(&input)
			if (err == nil) != tc.want {
				t.Fatalf("result-free controlled source accepted=%v, want %v: %v", err == nil, tc.want, err)
			}
		})
	}
}

package core

import (
	"bytes"
	stdcontext "context"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

func generatedEnteredRetirementState(t testing.TB, recorded bool) (*StateSession, generatedAttempt, contract.GeneratedDutyRecord, contract.GeneratorTarget) {
	return generatedEnteredRetirementForOperation(t, generatedVectorID(99), recorded)
}

func generatedEnteredRetirementForOperation(t testing.TB, operation contract.ID, recorded bool, completion ...uint8) (*StateSession, generatedAttempt, contract.GeneratedDutyRecord, contract.GeneratorTarget) {
	t.Helper()
	id := generatedVectorID
	fixed := func(v contract.ID, err error) contract.ID {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	body := func(v []byte, err error) []byte {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	descriptor := func(v contract.GeneratorDescriptor, err error) contract.GeneratorDescriptor {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	old, duty, target := generatedDetachedRetirementState(t, "absent", 0)
	prior, err := old.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	resultID := fixed(generatedCreateResultID(old.root.Domain, target.OriginalOperationID, target.OriginalAttemptID))
	evidenceRow := prior.records[generatedRecordKey{13, resultID}]
	evidence, err := contract.InspectGeneratedCreateEvidence(evidenceRow.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(completion) > 0 {
		if len(completion) != 1 || completion[0] != contract.GeneratedCompletionConfirmed {
			t.Fatal("unsupported retirement fixture completion class")
		}
		duty.CompletionClass, target.CompletionClass, evidence.CompletionClass = completion[0], completion[0], completion[0]
		duty.Target = descriptor(contract.GeneratorVectorDescriptor(contract.GeneratorVectorTargets, [][]byte{body(contract.EncodeGeneratorTarget(target))}))
		evidenceRow.Body = body(contract.EncodeGeneratedCreateEvidence(contract.GeneratedCreateEvidence(evidence)))
		generatedReplaceRecord(t, old, contract.GeneratedCreateEvidenceSupportKind, resultID, evidenceRow.Body)
		generatedReplaceRetirementTarget(t, old, duty, target)
		prior, err = old.selectedGeneratedWork(stdcontext.Background())
		if err != nil {
			t.Fatal("stronger retirement fixture selected target", err)
		}
	}
	facts, err := contract.InspectGeneratorSafeFacts(evidence.SafeFacts)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := prior.readSelectedSlice(t.Context(), contract.GeneratorContentIntent, facts.IntentDigest, contract.GeneratorIntentMaxLength)
	if err != nil {
		t.Fatal(err)
	}
	bundle, declaration, parent := generatedContentPlanFixture(t)
	declaration.OperationID, declaration.Entries = operation, nil
	bundle.Request.OperationID, bundle.Request.OperationKind = declaration.OperationID, 38
	bundle.Request.Declaration = descriptor(contract.GeneratorDeclarationDescriptor(declaration))
	bundle.Header.OperationID = declaration.OperationID
	bundle.Header.MaterialID = fixed(contract.GeneratorMaterialID(bundle.Header.DomainID, bundle.Header.OperationID))
	bundle.Header.RequestCoreDigest = fixed(contract.GeneratorRequestCoreDigest(bundle.Request))
	bundle.Header.ValueEntryPlanCount, bundle.Header.LineageCount, bundle.Header.TemplateCount = 0, 0, 1
	bundle.ValueEntryPlans = nil
	lineage := contract.GeneratorLineageTemplate{Schema: contract.GeneratorLineageTemplateSchema, Purpose: 2, DomainID: duty.DomainID, OperationID: declaration.OperationID,
		Name: target.Name, EntryIncarnationID: target.IncarnationID, Epoch: target.Epoch, IntentDigest: facts.IntentDigest,
		ResourceIncarnationID: target.ResourceID, TemplateCount: 1}
	lineage.LineageID = fixed(contract.GeneratorObligationLineageID(lineage.DomainID, lineage.OperationID, lineage.ResourceIncarnationID, lineage.Purpose))
	x := contract.GeneratorAttemptTemplate{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratorAttemptTemplateSchema, ResultReaderID: contract.GeneratorResultReaderID(), ResourceDigest: target.ResourceDigest, Action: 2, LineageID: lineage.LineageID, ResourceIncarnationID: target.ResourceID,
		DutyID: duty.DutyID, ConfigContractID: duty.ConfigContractID, ResourceContractID: duty.ResourceContractID, ExecutorID: duty.ExecutorID,
		CredentialRouteID: duty.CredentialRouteID, DescriptorID: duty.DescriptorID, ResultContractID: duty.ResultContractID,
		IntentDigest: facts.IntentDigest, TargetKind: 2, TargetSourceID: target.ResourceID, CompletionClass: duty.CompletionClass, RequiredAuthoritySet: 1}
	x.AttemptID = fixed(contract.GeneratorAttemptID(x.LineageID, 0))
	x.PlannedValueSlotID = fixed(contract.GeneratorValueSlotID(lineage.DomainID, lineage.OperationID, x.AttemptID))
	x.HazardID = fixed(contract.GeneratorHazardID(lineage.DomainID, x.AttemptID))
	x.TransmissionID = fixed(contract.GeneratorTransmissionID(x.AttemptID, 2))
	x.ResultID = fixed(contract.GeneratorResultID(lineage.DomainID, lineage.OperationID, x.AttemptID, x.TransmissionID, 2))
	x.InboxID = fixed(contract.GeneratorInboxID(lineage.DomainID, lineage.OperationID, x.AttemptID, x.ResultID))
	x.RequestPlanDigest = fixed(contract.GeneratorRequestPlanDigest(x))
	lineage.Templates[0] = x
	bundle.Lineages = []contract.GeneratorLineageTemplate{lineage}
	join := fixed(contract.GeneratorCompleteJoinID(bundle.Header.RequestCoreDigest))
	for _, guard := range []uint8{3, 4} {
		bundle.Edges = append(bundle.Edges, contract.GeneratorEdge{Schema: 1, SourceTemplateID: fixed(contract.GeneratorTemplateID(x)),
			DestinationTemplateID: join, Guard: guard, ResultSlotID: x.ResultID, RequiredAuthoritySet: 1})
	}
	use := contract.GeneratorResultUse{Schema: 1, AttemptID: x.AttemptID, ResultID: x.ResultID, InboxID: x.InboxID,
		ExecutorID: x.ExecutorID, ResultContractID: x.ResultContractID, PlannedValueSlotID: x.PlannedValueSlotID,
		MaterialID: bundle.Header.MaterialID, Purpose: 1, MaxFacts: 4096}
	bundle.ResultUses = []contract.GeneratorResultUse{use}
	bundle.UsePlan.OperationID, bundle.UsePlan.MaterialID = bundle.Header.OperationID, bundle.Header.MaterialID
	bundle.UsePlan.ResultUses = descriptor(contract.GeneratorResultUsesDescriptor(bundle.ResultUses))
	bundle.UsePlan.PlanGraphID = fixed(contract.GeneratorGraphID(bundle.Header, bundle.ValueEntryPlans, bundle.Lineages, bundle.Edges))
	parent.OperationID, parent.RequestCoreDigest = bundle.Header.OperationID, bundle.Header.RequestCoreDigest
	parent.MaterialID, parent.PlanGraphID = bundle.Header.MaterialID, bundle.UsePlan.PlanGraphID
	parent.UsePlanDigest = fixed(contract.GeneratorUsePlanDigest(bundle.UsePlan))
	parent.ValueEntryPlanCount, parent.LineageCount, parent.TemplateCount = 0, 0, 1
	parent.Declaration, parent.Graph = bundle.Request.Declaration, descriptor(contract.GeneratorPlanBundleDescriptor(bundle))
	parent.IntendedEntryPlans = descriptor(contract.GeneratorValueEntryPlansDescriptor(nil))
	graphBody, declarationBody := body(contract.EncodeGeneratorPlanBundle(bundle)), body(contract.EncodeGeneratorDeclaration(declaration))
	content := generatedContentState(t, []generatedContentFixtureBlob{{id(31), graphBody}, {id(32), declarationBody}, {id(33), intent}},
		[]contract.GeneratorSliceLocation{
			{Schema: 1, ContentKind: contract.GeneratorContentGraph, ContentID: parent.PlanGraphID, BlobID: id(31), Length: uint32(len(graphBody)), Digest: contract.Hash(graphBody)},
			{Schema: 1, ContentKind: contract.GeneratorContentDeclaration, ContentID: parent.OperationID, BlobID: id(32), Length: uint32(len(declarationBody)), Digest: contract.Hash(declarationBody)},
			{Schema: 1, ContentKind: contract.GeneratorContentIntent, ContentID: facts.IntentDigest, BlobID: id(33), Length: uint32(len(intent)), Digest: contract.Hash(intent)},
		})
	s := generatedReservationState(t)
	initial, err := s.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	a := initial.attempts[initial.phase.FrontierAttemptID]
	a.material.Core.OperationID, a.material.Core.OperationMaterialID, a.material.Core.UsePlanDigest = parent.OperationID, parent.MaterialID, parent.UsePlanDigest
	a.expected = contract.GeneratorResultExpectation{InputEncoding: contract.InputEncodingRaw, Plan: bundle.UsePlan, Template: x, Use: use, RequestDigest: id(61), TargetResourceDigest: target.ResourceDigest}
	a.record = contract.GeneratedAttemptRecord{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratedAttemptRecordSchema, DomainID: parent.DomainID, OperationID: parent.OperationID, LineageID: x.LineageID, AttemptID: x.AttemptID,
		TemplateDigest: fixed(contract.GeneratorTemplateID(x)), OwnerID: x.DutyID, ResourceID: x.ResourceIncarnationID, TransmissionID: x.TransmissionID,
		ResultID: x.ResultID, InboxID: x.InboxID, ConfigContractID: x.ConfigContractID, ResourceContractID: x.ResourceContractID, ExecutorID: x.ExecutorID,
		CredentialRouteID: x.CredentialRouteID, DescriptorID: x.DescriptorID, ResultContractID: x.ResultContractID,
		RequestDigest: a.expected.RequestDigest, State: contract.GeneratedEffectTransmitted, Stage: contract.GeneratedStageRetainedResult,
		CompletionClass: x.CompletionClass, Facts: contract.EmptyGeneratorVector(contract.GeneratorVectorFacts),
		Progress: contract.EmptyGeneratorVector(contract.GeneratorVectorProgress), Support: duty.Support, History: contract.EmptyGeneratorVector(contract.GeneratorVectorHistory)}
	consumer := contract.GeneratorConsumer{Schema: 1, OwnerID: duty.DutyID, MaterialID: parent.MaterialID,
		ContextDigest: fixed(contract.GeneratorResultUseDigest(use)), SubjectKind: 3, SubjectID: x.ResultID, Purpose: 4}
	var rows []contract.SupportRecord
	duty.Consumers, rows = generatedVectorRows(t, 10, duty.DutyID, contract.GeneratorVectorConsumers, [][]byte{body(contract.EncodeGeneratorConsumer(consumer))})
	for _, row := range old.supportRecords() {
		if row.Kind == contract.GeneratorVectorSupportKind {
			carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			if carrier.OwnerKind == 10 && carrier.OwnerID == duty.DutyID {
				rows = append(rows, row)
			}
		}
	}
	phase := *initial.phase
	phase.OperationID, phase.OwnerID, phase.PlanGraphID, phase.UsePlanDigest = parent.OperationID, parent.OperationID, parent.PlanGraphID, parent.UsePlanDigest
	phase.PhaseID, phase.FrontierAttemptID = fixed(contract.GeneratorInitialPhaseID(parent.RequestCoreDigest)), x.AttemptID
	if recorded {
		retirementFacts, err := facts.Own()
		if err != nil {
			t.Fatal(err)
		}
		retirementFacts.Action, retirementFacts.Disposition = contract.GeneratorActionDelete, contract.GeneratorDispositionRetirementAcknowledged
		retirementFacts.RequestDigest = a.expected.RequestDigest
		a.result = generatedPublicResultWithFacts(t, a, retirementFacts, 0)
		a.record.State, a.record.Stage = contract.GeneratedEffectSucceeded, contract.GeneratedStageTerminal
		result, err := contract.InspectGeneratedResultRecord(a.result)
		if err != nil {
			t.Fatal(err)
		}
		ownedFacts, err := result.SafeFacts.Own()
		if err != nil {
			t.Fatal(err)
		}
		facts := body(contract.EncodeGeneratorFactsRow(contract.GeneratorFactsRow{Schema: 1, ResultID: x.ResultID, Facts: body(contract.EncodeGeneratorSafeFacts(ownedFacts))}))
		var carriers []contract.SupportRecord
		a.record.Facts, carriers = generatedVectorRows(t, 9, x.AttemptID, contract.GeneratorVectorFacts, [][]byte{facts})
		rows = append(rows, carriers...)
		rows = append(rows, contract.SupportRecord{Kind: 4, RecordID: x.ResultID, Body: a.result})
		phase.Phase, phase.PhaseID, phase.Stage = 2, id(95), a.record.Stage
		phase.AcceptedResultID, phase.ResultDigest = x.ResultID, contract.Hash(a.result)
	}
	duty.Status = a.record.State
	rows = append(rows, evidenceRow, contract.SupportRecord{Kind: 9, RecordID: x.AttemptID, Body: body(contract.EncodeGeneratedAttemptRecord(a.record))},
		contract.SupportRecord{Kind: 10, RecordID: duty.DutyID, Body: body(contract.EncodeGeneratedDutyRecord(duty))},
		contract.SupportRecord{Kind: 1, RecordID: parent.MaterialID, Body: body(contract.EncodeOperationMaterialRecord(a.material))},
		contract.SupportRecord{Kind: 2, RecordID: parent.OperationID, Body: body(contract.EncodeGeneratedParentRecord(parent))},
		contract.SupportRecord{Kind: 5, RecordID: parent.OperationID, Body: body(contract.EncodeGeneratedPhaseRecord(phase))})
	s.support, s.root.Generated = content.support, content.root.Generated
	for _, row := range rows {
		s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
	}
	s.root.Generated.ActiveOwner, s.root.Generated.ActivePhase, s.root.Generated.ActiveGraph = parent.OperationID, phase.PhaseID, parent.PlanGraphID
	s.root.Generated.Attempts, s.root.Generated.Duties, s.root.Generated.Retiring, s.root.Generated.Materials = 1, 1, 1, 1
	if recorded {
		s.root.Generated.Results = 1
	}
	s.root.Generated.Graphs = descriptor(contract.GeneratorIndexDescriptor(contract.GeneratorGraphSet, []contract.ID{parent.PlanGraphID}))
	owners := []contract.ID{parent.OperationID, duty.DutyID}
	slices.SortFunc(owners, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	s.root.Generated.LiveOwners = descriptor(contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, owners))
	s.access[0].Records[0].MaterialID = parent.MaterialID
	s.access[0].Records[0].MaterialContextDigest = fixed(contract.OperationMaterialContextDigest(a.material.Core))
	if !s.indexSelectedMaterials() {
		t.Fatal("delete material index")
	}
	history := contract.GeneratorHistory{Schema: 1, PredecessorAttemptID: x.AttemptID, OwnerID: duty.DutyID, Outcome: a.record.State}
	if recorded {
		history.ResultID, history.ResultDigest = x.ResultID, contract.Hash(a.result)
	}
	generatedSetHistoryUnrefreshed(t, s, 9, x.AttemptID, []contract.GeneratorHistory{history})
	generatedSetHistoryUnrefreshed(t, s, 10, duty.DutyID, []contract.GeneratorHistory{history})
	generatedRefreshPhaseSetsUnrefreshed(t, s)
	generatedRepackSupport(t, s, s.supportRecords(), []contract.GeneratorPlanBundle{bundle})
	for _, row := range s.supportRecords() {
		if row.Kind == 9 && row.RecordID == a.record.AttemptID {
			a.record, err = contract.InspectGeneratedAttemptRecord(row.Body)
		} else if row.Kind == 10 && row.RecordID == duty.DutyID {
			duty, err = contract.InspectGeneratedDutyRecord(row.Body)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	generatedSealSelectedFixture(t, s)
	if !s.indexSelectedMaterials() {
		t.Fatal("entered delete material index")
	}
	return s, a, duty, target
}

// full_only: false
func TestGeneratedEnteredRetirementKeepsOriginalObligation(t *testing.T) {
	for _, recorded := range []bool{false, true} {
		t.Run(fmt.Sprint(recorded), func(t *testing.T) {
			s, a, duty, target := generatedEnteredRetirementState(t, recorded)
			g, err := s.selectedGeneratedWork(stdcontext.Background())
			if err != nil {
				t.Fatal("entered exact retirement refused", err)
			}
			actual := g.attempts[a.record.AttemptID]
			if len(g.attempts) != 1 || actual.expected != a.expected || !bytes.Equal(actual.result, a.result) ||
				g.phase.Duties.Count != 1 || !g.hasRecord(generatedRecordKey{10, duty.DutyID}) ||
				duty.OriginalAttemptID != target.OriginalAttemptID || duty.OriginalAttemptID == a.record.AttemptID {
				t.Fatal("fresh delete changed the original obligation or result binding")
			}
			if len(g.consumers) != 1 || len(g.consumers[materialIdentity{3, a.material.Core.OperationMaterialID}]) != 1 {
				t.Fatal("delete restored a create value-derivation consumer")
			}
		})
	}
}

// full_only: false
func TestGeneratedRetirementRecordingPreservesCreateTarget(t *testing.T) {
	s, a, duty, _ := generatedEnteredRetirementState(t, false)
	g, err := s.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	result := generatedRetirementResultFixture(t, s, a, contract.GeneratorDispositionRetirementAcknowledged)
	phaseID := generatedVectorID(95)
	plan := &generatedRecordPlan{expected: a.expected, result: result, phase: contract.GeneratorPhaseIdentity{AfterPhase: g.phase.Phase + 1},
		reference: contract.GeneratorResultReference{Schema: 1, ResultID: a.record.ResultID, ResultBodyDigest: contract.Hash(result), ResultLength: uint32(len(result))}}
	rows, err := generatedRecordedRows(g, plan, phaseID)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Kind == 10 && row.RecordID == duty.DutyID {
			after, err := contract.InspectGeneratedDutyRecord(row.Body)
			if err != nil || after.Target != duty.Target || after.OriginalOperationID != duty.OriginalOperationID || after.OriginalAttemptID != duty.OriginalAttemptID {
				t.Fatal("recording a delete changed its original create target", err)
			}
		}
	}
	generatedRepackSupport(t, s, rows, g.bundles)
	s.root.Generated.ActivePhase, s.root.Generated.Results = phaseID, 1
	after, err := s.selectedGeneratedWork(stdcontext.Background())
	if err != nil || !bytes.Equal(after.attempts[a.record.AttemptID].result, result) || after.phase.Duties.Count != 1 || s.root.Generated.Retiring != 1 {
		t.Fatal("recorded delete lost the obligation before closure", err)
	}
}

// full_only: false
func TestGeneratedRetirementHistoryRejectsChangedFrontier(t *testing.T) {
	for _, recorded := range []bool{false, true} {
		for _, kind := range []uint8{9, 10} {
			for name, damage := range map[string]func(*contract.GeneratorHistory){
				"owner":   func(h *contract.GeneratorHistory) { h.OwnerID = generatedVectorID(96) },
				"attempt": func(h *contract.GeneratorHistory) { h.PredecessorAttemptID = generatedVectorID(96) },
				"outcome": func(h *contract.GeneratorHistory) { h.Outcome = contract.GeneratedEffectClosedWithResidue },
				"result": func(h *contract.GeneratorHistory) {
					h.ResultID, h.ResultDigest = generatedVectorID(96), generatedVectorID(97)
				},
			} {
				t.Run(fmt.Sprintf("recorded%v/owner%d/%s", recorded, kind, name), func(t *testing.T) {
					s, a, duty, _ := generatedEnteredRetirementState(t, recorded)
					h := contract.GeneratorHistory{Schema: 1, PredecessorAttemptID: a.record.AttemptID, OwnerID: duty.DutyID, Outcome: a.record.State}
					if recorded {
						h.ResultID, h.ResultDigest = a.record.ResultID, contract.Hash(a.result)
					}
					damage(&h)
					owner := a.record.AttemptID
					if kind == 10 {
						owner = duty.DutyID
					}
					generatedSetHistoryUnrefreshed(t, s, kind, owner, []contract.GeneratorHistory{h})
					generatedRefreshPhaseSetsUnrefreshed(t, s)
					s.generatedWork = nil
					if _, err := s.selectedGeneratedWork(stdcontext.Background()); err == nil {
						t.Fatal("retirement history changed its exact frontier")
					}
				})
			}
		}
	}
}

// full_only: false
func TestGeneratedRetirementResultCannotUseAnotherTarget(t *testing.T) {
	s, a, duty, _ := generatedEnteredRetirementState(t, true)
	g, err := s.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	changedFacts := generatedRetirementFactsFixture(t, s, a, contract.GeneratorDispositionRetirementAcknowledged)
	changedFacts.ResourceData = bytes.Repeat([]byte{96}, 32)
	a.expected.TargetResourceDigest = selectedConversionLiteralID(t, "1523ea7c6eec911de9b45724cb6641e5d89eab5b1790bdea36e441e5ed81971c")
	a.expected.Template.ResourceDigest = a.expected.TargetResourceDigest
	a.expected.Template.RequestPlanDigest, err = contract.GeneratorRequestPlanDigest(a.expected.Template)
	if err != nil {
		t.Fatal(err)
	}
	result := generatedPublicResultWithFacts(t, a, changedFacts, 0)
	generatedReplaceRecord(t, s, 4, a.record.ResultID, result)
	decoded, err := contract.DecodeGeneratedResultRecord(result)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := contract.EncodeGeneratorSafeFacts(decoded.SafeFacts)
	if err != nil {
		t.Fatal(err)
	}
	body, err := contract.EncodeGeneratorFactsRow(contract.GeneratorFactsRow{Schema: 1, ResultID: a.record.ResultID, Facts: facts})
	if err != nil {
		t.Fatal(err)
	}
	var carriers []contract.SupportRecord
	a.record.Facts, carriers = generatedVectorRows(t, 9, a.record.AttemptID, contract.GeneratorVectorFacts, [][]byte{body})
	for i := range s.support {
		s.support[i].Records = slices.DeleteFunc(s.support[i].Records, func(row contract.SupportRecordView) bool {
			if row.Kind != contract.GeneratorVectorSupportKind {
				return false
			}
			v, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			return v.OwnerKind == 9 && v.OwnerID == a.record.AttemptID && v.VectorKind == contract.GeneratorVectorFacts
		})
	}
	for _, row := range carriers {
		s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
	}
	body, err = contract.EncodeGeneratedAttemptRecord(a.record)
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceRecord(t, s, 9, a.record.AttemptID, body)
	phase := *g.phase
	phase.ResultDigest = contract.Hash(result)
	body, err = contract.EncodeGeneratedPhaseRecord(phase)
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceRecord(t, s, 5, phase.OperationID, body)
	history := []contract.GeneratorHistory{{Schema: 1, PredecessorAttemptID: a.record.AttemptID, ResultID: a.record.ResultID,
		ResultDigest: contract.Hash(result), OwnerID: duty.DutyID, Outcome: a.record.State}}
	generatedSetHistoryUnrefreshed(t, s, 9, a.record.AttemptID, history)
	generatedSetHistoryUnrefreshed(t, s, 10, duty.DutyID, history)
	generatedRefreshPhaseSetsUnrefreshed(t, s)
	locations := make([]contract.GeneratorSliceLocation, 0, len(g.content.locations))
	for _, location := range g.content.locations {
		locations = append(locations, location)
	}
	generatedRepackSupportAtLocations(t, s, s.supportRecords(), g.bundles, locations)
	if _, err := s.selectedGeneratedWork(stdcontext.Background()); err == nil {
		t.Fatal("delete result acknowledged a different token")
	}
}

// full_only: false
func TestGeneratedRetirementRequiresExactHistoryAndConsumer(t *testing.T) {
	for _, kind := range []uint8{9, 10} {
		t.Run(fmt.Sprintf("missing history %d", kind), func(t *testing.T) {
			s, a, duty, _ := generatedEnteredRetirementState(t, false)
			owner := a.record.AttemptID
			if kind == 10 {
				owner = duty.DutyID
			}
			generatedSetHistory(t, s, kind, owner, nil)
			if _, err := s.selectedGeneratedWork(stdcontext.Background()); err == nil {
				t.Fatal("delete lost its original history owner")
			}
		})
	}
	t.Run("create derivation consumer", func(t *testing.T) {
		s, a, duty, _ := generatedEnteredRetirementState(t, false)
		context, err := contract.GeneratorResultUseDigest(a.expected.Use)
		if err != nil {
			t.Fatal(err)
		}
		body, err := contract.EncodeGeneratorConsumer(contract.GeneratorConsumer{Schema: 1, OwnerID: duty.DutyID,
			MaterialID: a.material.Core.OperationMaterialID, ContextDigest: context, SubjectKind: 3, SubjectID: a.record.ResultID, Purpose: 3})
		if err != nil {
			t.Fatal(err)
		}
		var carriers []contract.SupportRecord
		duty.Consumers, carriers = generatedVectorRows(t, 10, duty.DutyID, contract.GeneratorVectorConsumers, [][]byte{body})
		for i := range s.support {
			s.support[i].Records = slices.DeleteFunc(s.support[i].Records, func(row contract.SupportRecordView) bool {
				if row.Kind != contract.GeneratorVectorSupportKind {
					return false
				}
				v, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				return v.OwnerKind == 10 && v.OwnerID == duty.DutyID && v.VectorKind == contract.GeneratorVectorConsumers
			})
		}
		for _, row := range carriers {
			s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
		}
		body, err = contract.EncodeGeneratedDutyRecord(duty)
		if err != nil {
			t.Fatal(err)
		}
		generatedReplaceRecord(t, s, 10, duty.DutyID, body)
		generatedRefreshPhaseSetsUnrefreshed(t, s)
		s.generatedWork = nil
		if _, err := s.selectedGeneratedWork(stdcontext.Background()); err == nil {
			t.Fatal("delete acquired create result derivation rights")
		}
	})
}

// full_only: false
func TestGeneratedRetirementBindsDutyAndDeleteContract(t *testing.T) {
	for name, damage := range map[string]func(*contract.GeneratedAttemptRecord, *contract.GeneratedDutyRecord){
		"executor": func(a *contract.GeneratedAttemptRecord, d *contract.GeneratedDutyRecord) {
			d.ExecutorID = generatedVectorID(96)
		},
		"credential": func(a *contract.GeneratedAttemptRecord, d *contract.GeneratedDutyRecord) {
			d.CredentialRouteID = generatedVectorID(96)
		},
		"permission": func(a *contract.GeneratedAttemptRecord, d *contract.GeneratedDutyRecord) {
			d.DescriptorID = generatedVectorID(96)
		},
		"result contract": func(a *contract.GeneratedAttemptRecord, d *contract.GeneratedDutyRecord) {
			d.ResultContractID = generatedVectorID(96)
		},
		"completion class": func(a *contract.GeneratedAttemptRecord, d *contract.GeneratedDutyRecord) { d.CompletionClass = 2 },
		"not started": func(a *contract.GeneratedAttemptRecord, d *contract.GeneratedDutyRecord) {
			d.Status = contract.GeneratedEffectNotStarted
		},
		"retry": func(a *contract.GeneratedAttemptRecord, d *contract.GeneratedDutyRecord) { a.RetryUsed = 1 },
		"stage": func(a *contract.GeneratedAttemptRecord, d *contract.GeneratedDutyRecord) {
			a.Stage = contract.GeneratedStageTerminal
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, a, duty, _ := generatedEnteredRetirementState(t, false)
			damage(&a.record, &duty)
			body, err := contract.EncodeGeneratedAttemptRecord(a.record)
			if err != nil {
				t.Fatal(err)
			}
			generatedReplaceRecord(t, s, 9, a.record.AttemptID, body)
			body, err = contract.EncodeGeneratedDutyRecord(duty)
			if err != nil {
				t.Fatal(err)
			}
			generatedReplaceRecord(t, s, 10, duty.DutyID, body)
			generatedRefreshPhaseSets(t, s)
			if _, err := s.selectedGeneratedWork(stdcontext.Background()); err == nil {
				t.Fatal("delete changed its exact retained obligation")
			}
		})
	}
}

// full_only: false
func TestGeneratedRetirementPhaseMustOwnOriginalDuty(t *testing.T) {
	s, _, _, _ := generatedEnteredRetirementState(t, false)
	g, err := s.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	phase := *g.phase
	phase.Duties = contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseDuties)
	body, err := contract.EncodeGeneratedPhaseRecord(phase)
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceRecord(t, s, 5, phase.OperationID, body)
	generatedRefreshSupport(t, s)
	if _, err := s.selectedGeneratedWork(stdcontext.Background()); err == nil {
		t.Fatal("delete phase omitted the older obligation it owns")
	}
}

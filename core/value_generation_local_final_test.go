package core

import (
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

func generatedLocalFinalProjectionFixture(t *testing.T) (*generatedSelection, generatedAttempt) {
	t.Helper()
	before := generatedEmptyPredecessor(t)
	input := generatedReservationInputFixture(t, before)
	x := input.graph.Lineages[0].Templates[0]
	x.Schema, x.LifecycleMode, x.ResultReaderID = contract.GeneratorAttemptTemplateSchema, contract.GeneratorLifecycleNone, contract.GeneratorResultReaderID()
	x.ResourceContractID, x.HazardID, x.TargetSourceID = contract.ID{}, contract.ID{}, contract.ID{}
	x.CompletionClass, x.NoEffectBudget, x.ResidueBudget, x.TargetKind = 0, 0, 0, 0
	var err error
	x.RequestPlanDigest, err = contract.GeneratorRequestPlanDigest(x)
	if err != nil {
		t.Fatal(err)
	}
	parent := contract.GeneratedParentRecord(input.parent)
	a, _, err := generatedCreateRecords(parent, x, generatedVectorID(90), contract.EmptyGeneratorVector(contract.GeneratorVectorConsumers))
	if err != nil {
		t.Fatal(err)
	}
	a.State, a.Stage, a.FailureReason = contract.GeneratedEffectFailedTerminal, contract.GeneratedStageTerminal, contract.GeneratorFailureUnavailable
	body, err := contract.EncodeGeneratedAttemptRecord(a)
	if err != nil || len(body) != contract.GeneratedAttemptRecordFixedLength {
		t.Fatal("terminal local fixture", err)
	}
	lineage := input.graph.Lineages[0]
	lineage.Schema, lineage.TemplateCount, lineage.Templates = contract.GeneratorLineageTemplateSchema, 1, [5]contract.GeneratorAttemptTemplate{x}
	attempt := generatedAttempt{record: a, expected: contract.GeneratorResultExpectation{InputEncoding: contract.InputEncodingRaw, Template: x}}
	g := &generatedSelection{session: before, image: before.selectedImage(), parent: &parent,
		phase:    &contract.GeneratedPhaseRecord{Stage: contract.GeneratedStageTerminal},
		bundles:  []contract.GeneratorPlanBundle{{Lineages: []contract.GeneratorLineageTemplate{lineage}}},
		attempts: map[contract.ID]generatedAttempt{a.AttemptID: attempt},
		records:  map[generatedRecordKey]contract.SupportRecord{{contract.GeneratedAttemptSupportKind, a.AttemptID}: {Kind: contract.GeneratedAttemptSupportKind, RecordID: a.AttemptID, Body: body}}}
	return g, attempt
}

// full_only: false
func TestGeneratedLocalFailedFinalRequiresExactSelectedFrontier(t *testing.T) {
	for _, damage := range []string{"exact", "reason", "stage", "predecessor", "parent", "result", "facts"} {
		t.Run(damage, func(t *testing.T) {
			g, attempt := generatedLocalFinalProjectionFixture(t)
			switch damage {
			case "reason":
				attempt.record.FailureReason = 0
			case "stage":
				attempt.record.Stage = contract.GeneratedStageRetainedResult
			case "predecessor":
				attempt.record.PredecessorAttemptID = generatedVectorID(91)
			case "parent":
				g.parent.OperationID = generatedVectorID(92)
			case "result":
				g.records[generatedRecordKey{contract.GeneratedResultSupportKind, attempt.record.ResultID}] = contract.SupportRecord{Kind: contract.GeneratedResultSupportKind, RecordID: attempt.record.ResultID}
			case "facts":
				attempt.record.Facts.Digest = generatedVectorID(93)
			}
			g.attempts[attempt.record.AttemptID] = attempt
			facts, err := selectedFinalResults(g)
			if damage != "exact" {
				if err == nil {
					t.Fatal("damaged local failure became a completed Final frontier")
				}
				return
			}
			empty, emptyErr := contract.GeneratorResultReferencesDescriptor(nil)
			if err != nil || emptyErr != nil || facts.selecting || len(facts.results) != 0 || len(facts.byLineage) != 0 || facts.evidence != contract.GeneratorDescriptor(empty) {
				t.Fatal("pure local failure fabricated a result or selected value", err)
			}
		})
	}
}

// full_only: false
func TestGeneratedLocalFinalSupportUsesExactSurvivingOwners(t *testing.T) {
	g, local := generatedLocalFinalProjectionFixture(t)
	binding, err := contract.EncodeGeneratorSupportBinding(contract.GeneratorSupportBinding{Schema: contract.GeneratorSupportBindingSchema, Role: 1,
		ContractID: generatedVectorID(94), ImplementationID: generatedVectorID(95), PublicBindingDigest: generatedVectorID(96)})
	if err != nil {
		t.Fatal(err)
	}
	descriptor, carriers, err := generatedCarrierRows(local.record.DomainID, contract.GeneratedParentSupportKind, local.record.OperationID, contract.GeneratorVectorSupport, [][]byte{binding})
	if err != nil {
		t.Fatal(err)
	}
	local.record.Support = descriptor
	local.record.State, local.record.FailureReason = contract.GeneratedEffectSucceeded, 0
	body, err := contract.EncodeGeneratedAttemptRecord(local.record)
	if err != nil {
		t.Fatal(err)
	}
	rows := append(slices.Clone(carriers), contract.SupportRecord{Kind: contract.GeneratedAttemptSupportKind, RecordID: local.record.AttemptID, Body: body})
	vectors, err := newGeneratedVectorSet(local.record.DomainID, rows)
	if err != nil {
		t.Fatal(err)
	}
	owners, err := g.generatedSupportOwners(rows, vectors)
	key := generatedVectorKey{contract.GeneratedParentSupportKind, local.record.OperationID, contract.GeneratorVectorSupport, descriptor}
	if err != nil || !owners[key] || len(owners) != 1 {
		t.Fatal("release-only local mapping lost its nonempty exact Support", err)
	}
	orphan := key
	orphan.vector.Digest = generatedVectorID(97)
	if owners[orphan] {
		t.Fatal("graph membership retained an unreferenced Support vector")
	}
	cf := generatedAttemptVectorFixture()
	cf.Support = descriptor
	cf.OperationID = local.record.OperationID
	cfBody, err := contract.EncodeGeneratedAttemptRecord(cf)
	if err != nil {
		t.Fatal(err)
	}
	rows = append(slices.Clone(carriers), contract.SupportRecord{Kind: contract.GeneratedAttemptSupportKind, RecordID: cf.AttemptID, Body: cfBody})
	owners, err = g.generatedSupportOwners(rows, vectors)
	if err != nil || !owners[key] || len(owners) != 1 {
		t.Fatal("Cloudflare sibling lost the same actual Support owner", err)
	}
	owners, err = g.generatedSupportOwners(carriers, vectors)
	if err != nil || len(owners) != 0 {
		t.Fatal("unreferenced carrier supplied its own retention root", err)
	}

	canonicalState := generatedSelectedEntryOrigin(t, generatedVectorID(201), generatedVectorID(202), 0)
	canonical := contract.RetainedCanonicalRecord{OriginalSlot: 0, Entry: *canonicalState.valueEntry(0)}
	canonical.Entry.Generated.RequiredSupport = descriptor
	canonicalBody, err := contract.EncodeRetainedCanonicalRecord(canonical)
	if err != nil {
		t.Fatal(err)
	}
	canonicalID, err := contract.AdmissionEntryDigest(canonical)
	if err != nil {
		t.Fatal(err)
	}
	canonicalRow := contract.SupportRecord{Kind: contract.RetainedCanonicalSupportKind, RecordID: canonicalID, Body: canonicalBody}
	_, canonicalCarriers, err := generatedCarrierRows(local.record.DomainID, contract.GeneratedParentSupportKind,
		canonical.Entry.Generated.OriginOperationID, contract.GeneratorVectorSupport, [][]byte{binding})
	if err != nil {
		t.Fatal(err)
	}
	valueCore, err := contract.ValueCoreForEntry(canonicalState.root.Domain, canonicalState.root.CurrentAccess.Core.CompatibilityID, canonical.Entry)
	if err != nil {
		t.Fatal(err)
	}
	contextID, err := contract.ValueMaterialContextDigest(valueCore)
	if err != nil {
		t.Fatal(err)
	}
	consumerOwner := generatedVectorID(203)
	consumer, err := contract.EncodeGeneratorConsumer(contract.GeneratorConsumer{Schema: 1, OwnerID: consumerOwner,
		MaterialID: canonical.Entry.ValueState, ContextDigest: contextID, SubjectKind: contract.GeneratorConsumerRetainedCanonicalValue,
		SubjectID: canonicalID, Purpose: contract.GeneratorConsumerUseRetainedCanonical})
	if err != nil {
		t.Fatal(err)
	}
	_, consumerCarriers, err := generatedCarrierRows(local.record.DomainID, contract.GeneratedDutySupportKind,
		consumerOwner, contract.GeneratorVectorConsumers, [][]byte{consumer})
	if err != nil {
		t.Fatal(err)
	}
	canonicalKey := generatedVectorKey{contract.GeneratedParentSupportKind, canonical.Entry.Generated.OriginOperationID,
		contract.GeneratorVectorSupport, descriptor}
	for _, consumed := range []bool{false, true} {
		t.Run(map[bool]string{false: "unconsumed-canonical", true: "consumer-owned-canonical"}[consumed], func(t *testing.T) {
			rows := append([]contract.SupportRecord{canonicalRow}, canonicalCarriers...)
			if consumed {
				rows = append(rows, consumerCarriers...)
			}
			before := slices.Clone(rows)
			vectors, err := newGeneratedVectorSet(local.record.DomainID, rows)
			if err != nil {
				t.Fatal(err)
			}
			owners, err := g.generatedSupportOwners(rows, vectors)
			if err != nil || owners[canonicalKey] != consumed || len(owners) != map[bool]int{false: 0, true: 1}[consumed] {
				t.Fatal("retained canonical support did not follow its exact surviving consumer", owners, err)
			}
			if !reflect.DeepEqual(rows, before) {
				t.Fatal("support-owner census changed caller rows before access pruning")
			}
		})
	}
}

// full_only: false
func TestGeneratedNoResourceNoEffectKeepsTerminalFactsWithoutRetry(t *testing.T) {
	before := generatedEmptyPredecessor(t)
	profile := defaultGeneratedFixtureProfile()
	profile.LifecycleMode = contract.GeneratorLifecycleNone
	profile.ResourceContractID = contract.ID{}
	profile.CompletionClass, profile.RetirementMode = 0, 0
	input := generatedReservationInputForProfileIntent(t, before, generatedVectorID(210), []string{"generated"}, []byte(`{}`), profile)
	if len(input.graph.Lineages) != 1 || input.graph.Lineages[0].TemplateCount != 1 {
		t.Fatal("no-resource graph acquired managed branches")
	}
	reserved, err := before.deriveGeneratedReservation(t.Context(), input)
	if err != nil {
		t.Fatal("no-resource reservation", err)
	}
	state := reserved.state
	selected := mustSelectedGeneratedWork(t, state)
	attempt := selected.attempts[selected.phase.FrontierAttemptID]
	packet := generatedPublicResultFixture(t, attempt, contract.GeneratorDispositionConfirmedNoEffect)
	request, err := state.generatedRecordRequest(t.Context(), attempt.record.AttemptID, packet, generatedContinuationContext(t, state, 211, 212))
	if err != nil {
		t.Fatal("no-resource confirmed-no-effect request", err)
	}
	recorded, err := state.deriveGeneratedRecord(t.Context(), request)
	if err != nil {
		t.Fatal("no-resource confirmed-no-effect record", err)
	}
	state = recorded.state
	state.generatedWork = nil
	cold, err := state.selectedGeneratedWork(t.Context())
	if err != nil {
		t.Fatal("cold no-resource no-effect facts", err)
	}
	terminal := cold.attempts[attempt.record.AttemptID]
	if len(cold.attempts) != 1 || state.root.Generated.Hazards != 0 || terminal.record.RetryUsed != 0 || terminal.record.State != contract.GeneratedEffectConfirmedNoEffect || terminal.record.Stage != contract.GeneratedStageTerminal || terminal.record.Facts.Count != 1 || state.root.Generated.GeneratedCurrent != 0 {
		t.Fatal("no-resource no-effect changed authority, targets or current values")
	}
	if _, _, ok := generatedNextNoEffect(cold, attempt.expected.Template); ok {
		t.Fatal("no-resource no-effect acquired a retry")
	}
}

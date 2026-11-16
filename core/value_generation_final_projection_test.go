package core

import (
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestSelectedFinalRowsRetainedCurrentOnlyCompatibilityWidth(t *testing.T) {
	// This is a public row-validation boundary witness. No narrow historical
	// preparation is selected, and no past producer or historical writer is
	// reconstructed. All current alias, graph and terminal-result facts below
	// come from the existing selected-state and mutation owners.
	s, _, _ := generatedCanonicalState(t, false)
	g := mustSelectedGeneratedWork(t, s)
	a := g.attempts[g.phase.FrontierAttemptID]
	record, err := s.generatedRecordRequest(t.Context(), a.record.AttemptID, generatedPublicResultFixture(t, a, contract.GeneratorDispositionOwnedUnusableCreate), generatedContinuationContext(t, s, 170, 171))
	if err != nil {
		t.Fatal("canonical backlog terminal request", err)
	}
	recorded, err := s.deriveGeneratedRecord(t.Context(), record)
	if err != nil {
		t.Fatal("canonical backlog terminal Record", err)
	}
	failedPlan, err := recorded.state.generatedFinalRequest(t.Context(), generatedContinuationContext(t, recorded.state, 172, 173))
	if err != nil || failedPlan.selecting {
		t.Fatal("canonical backlog must retain a nonselecting Final", err)
	}
	failed, err := recorded.state.deriveGeneratedFinal(t.Context(), failedPlan, nil)
	if err != nil {
		t.Fatal("canonical backlog nonselecting Final", err)
	}
	s = failed.state
	current := s.valueEntry(7)
	if current == nil || len(current.Recipients) != 64 || len(mustSelectedGeneratedWork(t, s).retainedReaders(current.ValueState)) != 64 {
		t.Fatal("real failed Final lost the current/historical aliases")
	}
	retained, err := contract.EncodeRetainedCanonicalRecord(contract.RetainedCanonicalRecord{OriginalSlot: 7, Entry: *current})
	if err != nil {
		t.Fatal(err)
	}
	source := contract.GeneratorDeclarationEntry{InputEncoding: current.InputEncoding, OutputEncoding: current.OutputEncoding, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationRetained, Name: current.Name, Recipients: slices.Clone(current.Recipients), Payload: retained}
	input := generatedReservationInputForState(t, s, generatedVectorID(250), []string{"beta"}, defaultGeneratedFixtureProfile(), 0, nil, nil, source)
	// Explicitly request a content replay of this exact retained value. Bind
	// every changed graph/use-plan/material commitment through its real codec;
	// the ordinary admission shape below must accept this request.
	for i := range input.graph.ValueEntryPlans {
		if input.graph.ValueEntryPlans[i].Name == current.Name {
			input.graph.ValueEntryPlans[i].ChangeMask = contract.GeneratorValueChangeContent
		}
	}
	input.graph.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(input.graph.Header, input.graph.ValueEntryPlans, input.graph.Lineages, input.graph.Edges)
	if err != nil {
		t.Fatal(err)
	}
	input.parent.PlanGraphID = input.graph.UsePlan.PlanGraphID
	input.parent.UsePlanDigest, err = contract.GeneratorUsePlanDigest(input.graph.UsePlan)
	if err != nil {
		t.Fatal(err)
	}
	input.parent.Graph, err = contract.GeneratorPlanBundleDescriptor(input.graph)
	if err != nil {
		t.Fatal(err)
	}
	input.parent.IntendedEntryPlans, err = contract.GeneratorValueEntryPlansDescriptor(input.graph.ValueEntryPlans)
	if err != nil {
		t.Fatal(err)
	}
	input.finished.Material.Core.UsePlanDigest = input.parent.UsePlanDigest
	seed, err := contract.DecodeAccessRecord(input.finished.SeedAccess)
	if err != nil {
		t.Fatal(err)
	}
	seed.MaterialContextDigest, err = contract.OperationMaterialContextDigest(input.finished.Material.Core)
	if err != nil {
		t.Fatal(err)
	}
	input.finished.SeedAccess, err = contract.EncodeAccessRecord(seed)
	if err != nil {
		t.Fatal(err)
	}
	declaration, err := contract.InspectGeneratorDeclaration(input.declaration)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.generatedAdmissionShape(t.Context(), input.graph, declaration, mustSelectedGeneratedWork(t, s)); err != nil {
		t.Fatal("retained replay real admission shape", err)
	}
	reservation, err := s.deriveGeneratedReservation(t.Context(), input)
	if err != nil {
		t.Fatal("retained replay actual reservation", err)
	}
	s = reservation.state
	g = mustSelectedGeneratedWork(t, s)
	a = g.attempts[g.phase.FrontierAttemptID]
	record, err = s.generatedRecordRequest(t.Context(), a.record.AttemptID, generatedPublicResultFixtureWithRawToken(t, a, contract.GeneratorDispositionCompleteCreate, 1, gcTestID("retained-replay-result")), generatedContinuationContext(t, s, 174, 175))
	if err != nil {
		t.Fatal("retained replay real result request", err)
	}
	recorded, err = s.deriveGeneratedRecord(t.Context(), record)
	if err != nil {
		t.Fatal("retained replay real terminal Record", err)
	}
	s = recorded.state
	g = mustSelectedGeneratedWork(t, s)
	plan, err := s.generatedFinalRequest(t.Context(), generatedContinuationContext(t, s, 176, 177))
	if err != nil || !plan.selecting || len(plan.entryPlans) != 1 || len(plan.supplied.Rows) != 1 {
		t.Fatal("retained replay exact terminal Final facts", err)
	}
	current = s.valueEntry(7)
	access := *generatedFixtureMaterialAccess(t, s, contract.ValueMaterialKind, current.ValueState)
	if len(access.Wraps) != 127 {
		t.Fatal("historical/current material union must be64+64-1")
	}
	entryBody, err := contract.EncodeValueEntry(*current)
	if err != nil {
		t.Fatal(err)
	}
	fullBody, err := contract.EncodeAccessRecord(access)
	if err != nil {
		t.Fatal(err)
	}
	narrow := access
	narrow.Wraps = nil
	for _, wrap := range access.Wraps {
		if slices.Contains(current.Recipients, wrap.SubjectID) {
			narrow.Wraps = append(narrow.Wraps, wrap)
		}
	}
	narrowBody, err := contract.EncodeAccessRecord(narrow)
	if err != nil || len(narrow.Wraps) != 64 || len(fullBody)-len(narrowBody) != 63*489 {
		t.Fatal("independent current-only/full-union width delta", len(fullBody), len(narrowBody), err)
	}
	generated := []contract.CryptoGeneratedValueEntryResult{generatedPreparedValueEntryFixture(t, s, plan.entryPlans[0])}
	for _, tc := range []struct {
		name         string
		materialized bool
		access       []byte
		want         bool
		replay       bool
	}{
		{"historical_current_only", true, narrowBody, true, true},
		{"fresh_current_only", false, narrowBody, false, false},
		{"fresh_full_union", false, fullBody, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			supplied := []contract.CryptoPreparedSecret{{Name: current.Name, Slot: 7, EntryBytes: entryBody, AccessRecord: tc.access}}
			rows, err := g.image.validateGeneratedFinalRows(t.Context(), g, &plan.generatedFinalProjection, tc.materialized, generated, supplied, tc.materialized)
			if (err == nil) != tc.want {
				t.Fatal("public compatibility/fresh boundary", err)
			}
			defer rows.clearOwnedSupplied()
			if tc.want && (rows.legacyExclusion || rows.supplied[7].currentOnlyReplay != tc.replay) {
				t.Fatal("unrecognized historical row escaped the exact replay branch")
			}
		})
	}
}

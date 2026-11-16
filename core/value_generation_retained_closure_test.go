package core

import (
	"context"
	"maps"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestGeneratedRetainedReaderAccessCapacityExactAndOneByteOver(t *testing.T) {
	s, _, _ := generatedCreateHazardState(t, 2, 0)
	generatedSealSelectedFixture(t, s)
	if _, err := s.validateRelationsMode(t.Context(), false); err != nil {
		t.Fatal("complete retained predecessor relations", err)
	}
	selected := mustSelectedGeneratedWork(t, s)
	if selected.parent != nil || len(selected.canonical) != 1 || len(s.root.Names) != 1 ||
		s.root.RecipientCount != 127 || s.root.MembershipCount != 64 || s.root.CurrentAccess.Core.Recovery == nil {
		t.Fatal("unexpected current and retained access closure")
	}
	current := s.valueEntry(s.root.Names[0].Slot)
	// The original and current 64-reader sets share exactly one reader.
	// Their 127-reader union plus Recovery has 128 wraps. The seed has
	// Authority and Recovery wraps. Formats fixes 102 bytes per record and
	// 489 bytes per wrap; these expected bytes do not use the size helper.
	const retainedBytes = uint64(62_694) // 102 + 489*(64+64-1+1)
	const seedBytes = uint64(1_080)      // 102 + 489*(1+1)
	rows := s.accessRecords()
	if len(rows) != 2 {
		t.Fatal("complete access row count", len(rows))
	}
	var valueRows, seedRows int
	for _, row := range rows {
		var want uint64
		switch row.MaterialKind {
		case contract.ValueMaterialKind:
			valueRows++
			if row.MaterialID != current.ValueState || len(row.Wraps) != 128 {
				t.Fatal("current and retained reader union", row.MaterialID, len(row.Wraps))
			}
			want = retainedBytes
		case contract.OperationSeedMaterialKind:
			seedRows++
			if len(row.Wraps) != 2 {
				t.Fatal("retained seed readers", len(row.Wraps))
			}
			want = seedBytes
		default:
			t.Fatal("unexpected access material kind", row.MaterialKind)
		}
		encoded, err := contract.EncodeAccessRecord(row)
		if err != nil || uint64(len(encoded)) != want {
			t.Fatal("independently counted complete access bytes", len(encoded), want, err)
		}
	}
	if valueRows != 1 || seedRows != 1 || len(s.root.CurrentAccess.Core.AccessPageRefs) != 1 {
		t.Fatal("complete selected access streams", valueRows, seedRows)
	}
	// Both complete rows fit together: 75 + 62,694 + 1,080 = 63,849.
	page, err := format.EncodeAccessPage(*s.access[0])
	if err != nil || len(page) != 63_849 {
		t.Fatal("independent selected access page bytes", len(page), err)
	}

	input := generatedPlanInputForOperation(t, s, generatedVectorID(98))
	plan, err := s.generatedPlanRequest(t.Context(), input)
	if err != nil || plan == nil || s.prepared {
		t.Fatal("complete retained closure refused public plan admission", err)
	}
	declaration, err := contract.InspectGeneratorDeclaration(input.declaration)
	if err != nil {
		t.Fatal(err)
	}
	shape, err := s.generatedAdmissionShape(t.Context(), input.graph, declaration, selected)
	if err != nil || shape.Recipients != 127 || !shape.Recovery || shape.ValueEntryCount != 1 ||
		shape.Secrets != 1 || shape.SecretMemberships != 64 || shape.OldGenerated != 0 || shape.Creates != 1 {
		t.Fatal("complete admitted capacity shape", shape, err)
	}
	// The new create reserves three create and three delete seeds. The
	// existing Hazard keeps one seed and the full canonical reader union.
	if got := plan.capacity.Groups[contract.GeneratorCapacityOldAccess]; got != (contract.GeneratorCapacityGroup{MaxCount: 1, MaxFramedBytes: retainedBytes, MaxPages: 1}) {
		t.Fatal("admission lost retained canonical access", got)
	}
	if got := plan.capacity.Groups[contract.GeneratorCapacitySeedAccess]; got != (contract.GeneratorCapacityGroup{MaxCount: 7, MaxFramedBytes: 7 * seedBytes, MaxPages: 1}) {
		t.Fatal("admission lost retained seed access", got)
	}

	// Check the actual unchanged selected image at the capacity owner. This
	// is a byte-bound proof, not an ordinary successor or physical page-edge
	// proof. Valid wire lengths cannot grow by one byte: 102 and 489 are
	// divisible by three. Instead, B-1 is a declared bound exceeded by one.
	c := &Comparison{session: s, slots: []uint16{s.root.Names[0].Slot},
		intent: []contract.CryptoIntentRow{{Name: current.Name, Recipients: slices.Clone(current.Recipients),
			ValueSource: current.ValueSource, ConfidentialityClass: current.ConfidentialityClass,
			ContentLength: 4, InputEncoding: current.InputEncoding, RetainedLength: current.RetainedLength, OutputEncoding: current.OutputEncoding, PayloadDigest: contract.Hash(current.ValueBytes), PayloadLength: uint32(len(current.ValueBytes))}},
		normalSupportSnapshot: s.root.Snapshot, normalSupportTransition: s.root.Transition}
	c.support, err = s.generatedSupportTransition(t.Context(), c, nil)
	if err != nil || c.support == nil {
		t.Fatal("admitted normal support witness", err)
	}
	c.normalSupportRows, err = s.selectedNormalSupportRows()
	if err != nil {
		t.Fatal("complete selected support facts", err)
	}
	usage, err := s.normalCapacityUsage(t.Context(), c)
	if err != nil || usage[contract.GeneratorCapacityCurrentAccess] != (contract.GeneratorCapacityGroup{MaxCount: 1, MaxFramedBytes: retainedBytes, MaxPages: 1}) ||
		usage[contract.GeneratorCapacitySeedAccess] != (contract.GeneratorCapacityGroup{MaxCount: 1, MaxFramedBytes: seedBytes, MaxPages: 1}) ||
		usage[contract.GeneratorCapacityOldAccess] != (contract.GeneratorCapacityGroup{}) {
		t.Fatal("actual current-retained and seed streams", usage, err)
	}
	c.support.Groups[contract.GeneratorCapacityCurrentAccess].MaxFramedBytes = retainedBytes
	if err := s.checkNormalCapacity(t.Context(), c); err != nil {
		t.Fatal("exact actual retained access byte bound refused", err)
	}
	c.support.Groups[contract.GeneratorCapacityCurrentAccess].MaxFramedBytes = retainedBytes - 1
	if err := s.checkNormalCapacity(t.Context(), c); err != contract.ErrRecord {
		t.Fatal("actual retained access one byte over declared bound accepted", err)
	}
}

func generatedRetainedClosureResidue(t *testing.T, s *StateSession, nonce byte) *StateSession {
	t.Helper()
	g := mustSelectedGeneratedWork(t, s)
	p, e := s.generatedCreateResidueRequest(t.Context(), g.phase.FrontierAttemptID, generatedContinuationContext(t, s, nonce, nonce+1))
	if e != nil {
		t.Fatal("residue request", e)
	}
	r, e := s.deriveGeneratedCreateResidue(t.Context(), p)
	if e != nil {
		t.Fatal("residue derivation", e)
	}
	return r.state
}

// full_only: false
func TestGeneratedRetainedLifecycleClosure(t *testing.T) {
	t.Run("residue-preserves-retained-consumers", func(t *testing.T) {
		s, retained, _ := generatedCanonicalState(t, false)
		if _, e := s.selectedGeneratedWork(t.Context()); e != nil {
			t.Fatal("baseline generated relations", e)
		}
		if _, e := s.validateRelationsMode(t.Context(), false); e != nil {
			t.Fatal("retained predecessor full relations", e)
		}
		g := mustSelectedGeneratedWork(t, s)
		p, e := s.generatedCreateResidueRequest(t.Context(), g.phase.FrontierAttemptID, generatedContinuationContext(t, s, 230, 231))
		if e != nil {
			t.Fatal(e)
		}
		change, e := generatedCreateResidueRows(g)
		if e != nil {
			t.Fatal(e)
		}
		consumerBodies, e := g.vectors.resolve(10, change.attempt.OwnerID, contract.GeneratorVectorConsumers, mustLifecycleDuty(t, g, change.attempt.OwnerID).Consumers)
		if e != nil {
			t.Fatal(e)
		}
		retainedConsumers := 0
		for _, b := range consumerBodies {
			c, e := contract.InspectGeneratorConsumer(b)
			if e != nil {
				t.Fatal(e)
			}
			if c.Purpose == contract.GeneratorConsumerUseRetainedCanonical {
				retainedConsumers++
			}
		}
		if retainedConsumers == 0 {
			t.Fatal("unexpected fixture", retainedConsumers, change.hazard.Consumers.Count)
		}
		r, e := s.deriveGeneratedCreateResidue(t.Context(), p)
		if e != nil || r == nil {
			t.Fatal("valid retained-canonical declaration refused residue admission", e)
		}
		if change.hazard.Consumers.Count != uint32(retainedConsumers)+1 {
			t.Fatal("residue did not retain canonical consumers and exact late-result consumer", change.hazard.Consumers)
		}
		if _, present := mustSelectedGeneratedWork(t, r.state).canonical[retained.Entry.ValueState]; !present {
			t.Fatal("residue lost retained canonical value")
		}
	})
	t.Run("exhausted-residue-advances-to-sibling", func(t *testing.T) {
		base := generatedEmptyPredecessor(t)
		r, e := base.deriveGeneratedReservation(context.Background(), generatedReservationInputForGenerations(t, base, generatedVectorID(10), []string{"alpha", "omega"}))
		if e != nil {
			t.Fatal(e)
		}
		s := generatedRetainedClosureResidue(t, r.state, 230)
		s = generatedReservePlannedSuccessor(t, s, 232)
		s = generatedRetainedClosureResidue(t, s, 234)
		s.generatedWork = nil
		if e := s.validateGeneratedSelection(t.Context(), nil); e != nil {
			t.Fatal("cold authentication", e)
		}
		g := mustSelectedGeneratedWork(t, s)
		if g.phase.Stage != contract.GeneratedStageRetainedResult || int(g.phase.LineageIndex) >= len(g.bundles[0].Lineages) ||
			g.bundles[0].Lineages[g.phase.LineageIndex].Name != "omega" || g.bundles[0].Lineages[g.phase.LineageIndex].Purpose != contract.GeneratorLineageCreate {
			t.Fatal("unexpected phase")
		}
		var sibling generatedAttempt
		for _, a := range g.attempts {
			if a.record.State == contract.GeneratedEffectTransmitted {
				sibling = a
			}
		}
		if sibling.record.AttemptID.IsZero() {
			t.Fatal("missing transmitted sibling")
		}
		plan, e := s.generatedRecordRequest(t.Context(), sibling.record.AttemptID, generatedPublicResultFixture(t, sibling, 1), generatedContinuationContext(t, s, 236, 237))
		if e != nil {
			t.Fatal("sibling record refused after exhaustion", e)
		}
		if _, e := s.generatedFinalRequest(t.Context(), generatedContinuationContext(t, s, 238, 239)); e == nil {
			t.Fatal("final unexpectedly accepted")
		}
		recorded, e := s.deriveGeneratedRecord(t.Context(), plan)
		if e != nil {
			t.Fatal("sibling record derivation", e)
		}
		final, e := recorded.state.generatedFinalRequest(t.Context(), generatedContinuationContext(t, recorded.state, 238, 239))
		if e != nil || final.selecting {
			t.Fatal("complete exhausted lineage and successful sibling did not admit nonselecting Final", e)
		}
	})
	t.Run("successor-with-retained-graph", func(t *testing.T) {
		base := generatedEmptyPredecessor(t)
		r, e := base.deriveGeneratedReservation(t.Context(), generatedReservationInputFixture(t, base))
		if e != nil {
			t.Fatal(e)
		}
		s, _ := generatedUnselectedCleanupFromReservation(t, r.state)
		r, e = s.deriveGeneratedReservation(t.Context(), generatedReservationInputForOperation(t, s, generatedVectorID(98)))
		if e != nil {
			t.Fatal("new initial", e)
		}
		s = generatedRetainedClosureResidue(t, r.state, 230)
		s.generatedWork = nil
		if e := s.validateGeneratedSelection(t.Context(), nil); e != nil {
			t.Fatal("cold valid state", e)
		}
		g := mustSelectedGeneratedWork(t, s)
		if len(g.bundles) != 2 {
			t.Fatal("need retained graph", len(g.bundles))
		}
		if _, e := s.generatedSuccessorReservationRequest(t.Context(), generatedContinuationContext(t, s, 232, 233)); e != nil {
			t.Fatal("valid retained graph prevented successor admission", e)
		}
	})
	t.Run("late-result-history-mismatch", func(t *testing.T) {
		s, a, h := generatedCreateHazardState(t, 0, 0)
		historical := contract.GeneratorHistory{Schema: 1, PredecessorAttemptID: a.record.AttemptID, OwnerID: a.record.OwnerID, Outcome: contract.GeneratedEffectClosedWithResidue}
		generatedSetHistory(t, s, 9, a.record.AttemptID, []contract.GeneratorHistory{historical})
		generatedSetHistory(t, s, 11, h.HazardID, []contract.GeneratorHistory{historical})
		g := mustSelectedGeneratedWork(t, s)
		packet := generatedPublicResultFixture(t, a, 1)
		selected, ok, e := g.selectGeneratedCleanup(t.Context(), map[contract.ID][]byte{a.record.ResultID: packet})
		if e != nil || !ok {
			t.Fatal("reflection selection", e)
		}
		change, e := g.generatedReflectLateCreate(selected)
		if e != nil {
			t.Fatal("row projection", e)
		}
		projected := *g
		projected.attempts = maps.Clone(g.attempts)
		projected.attempts[a.record.AttemptID] = change.attempt
		projected.records = make(map[generatedRecordKey]contract.SupportRecord, len(change.rows))
		for _, row := range change.rows {
			projected.records[generatedRecordKey{row.Kind, row.RecordID}] = row
		}
		projected.vectors, e = newGeneratedVectorSet(s.root.Domain, change.rows)
		if e != nil {
			t.Fatal(e)
		}
		builder := generatedSelectionBuilder{facts: &projected, vectors: newGeneratedVectorValidation(&projected.vectors)}
		if e := builder.validateCreateHistory(change.attempt, 9, a.record.AttemptID, change.attempt.record.History); e != nil {
			t.Fatal("qualified late packet invalidated immutable unresolved history", e)
		}
	})
	t.Run("retirement-close-loses-unknown-predecessor", func(t *testing.T) {
		s, attempts, _ := generatedRepeatedRetirementState(t, 1)
		g := mustSelectedGeneratedWork(t, s)
		a := attempts[len(attempts)-1]
		packet := generatedRetirementResultFixture(t, s, a, contract.GeneratorDispositionRetirementAcknowledged)
		p := &generatedRecordPlan{expected: a.expected, result: packet, phase: contract.GeneratorPhaseIdentity{AfterPhase: g.phase.Phase + 1}, reference: contract.GeneratorResultReference{Schema: 1, ResultID: a.record.ResultID, ResultBodyDigest: contract.Hash(packet), ResultLength: uint32(len(packet))}}
		rows, e := generatedRecordedRows(g, p, generatedVectorID(95))
		if e != nil {
			t.Fatal(e)
		}
		generatedRepackSupport(t, s, rows, g.bundles)
		s.root.Generated.ActivePhase, s.root.Generated.Results = generatedVectorID(95), 1
		g = mustSelectedGeneratedWork(t, s)
		closure, e := g.generatedRetirementAcknowledgement(t.Context(), a.record.AttemptID, generatedVectorID(96))
		if e != nil {
			t.Fatal("close row projection", e)
		}
		var oldAttempt, oldMaterial, oldRelease, duty bool
		for _, r := range closure.rows {
			oldAttempt = oldAttempt || r.Kind == 9 && r.RecordID == attempts[0].record.AttemptID
			oldMaterial = oldMaterial || r.Kind == 1 && r.RecordID == attempts[0].material.Core.OperationMaterialID
			oldRelease = oldRelease || r.Kind == 12 && r.RecordID == attempts[0].record.InboxID
			duty = duty || r.Kind == 10 && r.RecordID == a.record.OwnerID
		}
		if !oldAttempt || oldMaterial || !oldRelease || duty {
			t.Fatal("unexpected projected ownership", oldAttempt, oldMaterial, oldRelease, duty)
		}

		s.root.Generated.ActiveOwner, s.root.Generated.ActivePhase, s.root.Generated.ActiveGraph = contract.ID{}, contract.ID{}, contract.ID{}
		generatedRefreshClosureCounts(&s.root.Generated, closure.rows)
		s.root.Generated.Slices = closure.slices
		page := format.RequiredSupportPageView{Domain: s.root.Domain, Object: generatedVectorID(97)}
		for _, r := range closure.rows {
			page.Records = append(page.Records, contract.SupportRecordView(r))
		}
		s.support = []format.RequiredSupportPageView{page}
		if generatedIndexRejectsAlteredSupport(t, s) {
			t.Fatal("complete retirement release closure refused by ownership index")
		}

	})
	t.Run("parked-cleanup-late-ack-not-selected", func(t *testing.T) {
		for _, hazard := range []bool{false, true} {
			s, source := generatedOrdinaryCleanupSourceState(t, contract.GeneratedCompletionAcknowledged, hazard)
			r, e := s.deriveGeneratedReservation(t.Context(), generatedOrdinaryCleanupReservationInput(t, s, source, generatedVectorID(180)))
			if e != nil {
				t.Fatal(e)
			}
			s = r.state
			g := mustSelectedGeneratedWork(t, s)
			a := g.attempts[g.phase.FrontierAttemptID]
			facts, e := contract.EncodeGeneratorSafeFacts(generatedRetirementFactsFixture(t, s, a, contract.GeneratorDispositionUnknown))
			if e != nil {
				t.Fatal(e)
			}
			p, e := s.generatedOrdinaryCleanupAmbiguityPlan(t.Context(), a.record.AttemptID, facts, generatedLifecycleFixture(t, s))
			if e != nil {
				t.Fatal(e)
			}
			r, e = s.deriveGeneratedOrdinaryCleanupAmbiguity(t.Context(), p)
			if e != nil {
				t.Fatal(e)
			}
			s = r.state
			s.generatedWork = nil
			g = mustSelectedGeneratedWork(t, s)
			packet := generatedRetirementResultFixture(t, s, a, contract.GeneratorDispositionRetirementAcknowledged)
			selected, ok, e := g.selectGeneratedCleanup(t.Context(), map[contract.ID][]byte{a.record.ResultID: packet})
			if e != nil || !ok {
				t.Fatal(e)
			}
			if selected.kind != generatedCleanupReflection || selected.attempt.record.AttemptID != a.record.AttemptID {
				t.Fatal("exact parked cleanup acknowledgement was not selected")
			}
		}
	})
	t.Run("current-value-reader-wrap-projection", func(t *testing.T) {
		s, retained, _ := generatedCanonicalState(t, false)
		g := mustSelectedGeneratedWork(t, s)
		access, ok := s.materialAccess(contract.ValueMaterialKind, retained.Entry.ValueState)
		if !ok {
			t.Fatal("access missing")
		}
		if !s.validateMaterialWraps(access, s.valueReaders[retained.Entry.ValueState]) {
			t.Fatal("baseline wraps")
		}
		var retainedRow contract.SupportRecord
		for _, r := range s.supportRecords() {
			if r.Kind == 6 {
				retainedRow = r
			}
		}
		rows, values, e := g.generatedPruneRetainedCanonicals([]contract.SupportRecord{retainedRow})
		if e != nil || len(rows) != 0 || len(values) != 0 {
			t.Fatal("current value pruning", e)
		}
		projected, e := s.generatedDeleteLifecycleAccess(generatedDeleteReflection{values: values, rows: rows})
		current := s.valueEntry(retained.OriginalSlot)
		index := -1
		for i, row := range projected {
			if row.MaterialKind == contract.ValueMaterialKind && row.MaterialID == retained.Entry.ValueState {
				index = i
			}
		}
		if e != nil || index < 0 || len(projected[index].Wraps) != 64 || !s.validateMaterialWraps(projected[index], current.Recipients) {
			t.Fatal("unexpected wrap projection")
		}
	})
	t.Run("old-access-capacity-page-shrink", func(t *testing.T) {
		// This probes the arithmetic boundary, not a complete 67-entry stored state.
		base := generatedEmptyPredecessor(t)
		_, retained := generatedCanonicalSource(t)
		retained.Entry.Recipients = []contract.ID{base.admission.recipient}
		id := retained.Entry.ValueState
		g := &generatedSelection{session: base, content: &generatedContent{}, records: map[generatedRecordKey]contract.SupportRecord{}, canonical: map[contract.ID]generatedCanonical{id: {record: retained}}, materials: map[materialIdentity]bool{{kind: contract.ValueMaterialKind, id: id}: true}}
		shape := generatedCapacityShape{ValueEntryCount: 67, ValueEntryPageCount: uint64((67 + format.PageSlots - 1) / format.PageSlots), Recipients: 1, Secrets: 67, Memberships: 67, SecretMemberships: 67, Generated: 66, OldGenerated: 66, Creates: 1, ValueEntryPlanCount: 1, DeclarationBytes: 512}
		clean, e := generatedCleanCapacity(shape)
		if e != nil {
			t.Fatal(e)
		}
		charged, e := generatedCapacityWithBacklog(shape, g)
		if e != nil {
			t.Fatal(e)
		}
		before, after := clean[contract.GeneratorCapacityOldAccess], charged[contract.GeneratorCapacityOldAccess]
		if before.MaxPages != 2 || after.MaxPages < before.MaxPages || after.MaxFramedBytes != before.MaxFramedBytes+591 {
			t.Fatal("unexpected arithmetic", before, after)
		}
		evidence := contract.GeneratorCapacityEvidence{Schema: 1, BeforeRootDigest: generatedVectorID(251), PlanGraphID: generatedVectorID(252), Declaration: generatedCapacityReservationFixture(), Groups: charged}
		if _, e := contract.GeneratorCapacityDescriptor(evidence); e != nil {
			t.Fatal("complete retained byte charge refused", e)
		}
	})

}
func mustLifecycleDuty(t *testing.T, g *generatedSelection, id contract.ID) contract.GeneratedDutyRecord {
	t.Helper()
	d, e := contract.InspectGeneratedDutyRecord(g.records[generatedRecordKey{10, id}].Body)
	if e != nil {
		t.Fatal(e)
	}
	return d
}

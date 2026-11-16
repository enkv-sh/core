package core

import (
	"bytes"
	stdcontext "context"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func generatedParkedRetirementState(t testing.TB) (*StateSession, generatedAttempt, contract.GeneratedDutyRecord) {
	return generatedParkedRetirementForOperation(t, generatedVectorID(99))
}

// full_only: false
func TestGeneratedAcknowledgedRetirementReservationRejectsRetainedContradiction(t *testing.T) {
	for _, conflict := range []string{"identity", "resource", "uncontested transport"} {
		t.Run(conflict, func(t *testing.T) {
			s, a, _ := generatedParkedRetirementState(t)
			selected := mustSelectedGeneratedWork(t, s)
			a = selected.attempts[a.record.AttemptID]
			facts := generatedRetirementFactsFixture(t, s, a, contract.GeneratorDispositionUnknown)
			switch conflict {
			case "identity":
				facts.Reason = contract.GeneratorReasonIdentityConflict
			case "resource":
				facts.Target, facts.ResourceData = []byte("different target"), bytes.Repeat([]byte{96}, 32)
			}
			body, err := contract.EncodeGeneratorSafeFacts(facts)
			if err != nil {
				t.Fatal(err)
			}
			body, err = contract.EncodeGeneratorFactsRow(contract.GeneratorFactsRow{Schema: 1, ResultID: a.record.ResultID, Facts: body})
			if err != nil {
				t.Fatal(err)
			}
			var rows []contract.SupportRecord
			a.record.Facts, rows = generatedVectorRows(t, contract.GeneratedAttemptSupportKind, a.record.AttemptID, contract.GeneratorVectorFacts, [][]byte{body})
			for i := range s.support {
				s.support[i].Records = slices.DeleteFunc(s.support[i].Records, func(row contract.SupportRecordView) bool {
					if row.Kind != contract.GeneratorVectorSupportKind {
						return false
					}
					carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
					if err != nil {
						t.Fatal(err)
					}
					return carrier.OwnerKind == contract.GeneratedAttemptSupportKind && carrier.OwnerID == a.record.AttemptID && carrier.VectorKind == contract.GeneratorVectorFacts
				})
			}
			for _, row := range rows {
				s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
			}
			body, err = contract.EncodeGeneratedAttemptRecord(a.record)
			if err != nil {
				t.Fatal(err)
			}
			generatedReplaceRecord(t, s, contract.GeneratedAttemptSupportKind, a.record.AttemptID, body)
			generatedRepackSupport(t, s, s.supportRecords(), selected.bundles)
			cold := mustSelectedGeneratedWork(t, s)
			if contradiction, err := cold.validateDeleteFacts(cold.attempts[a.record.AttemptID]); err != nil || contradiction != (conflict != "uncontested transport") {
				t.Fatal("fixture did not preserve a qualified contradiction", err)
			}
			fresh, _, _, _ := generatedEnteredRetirementForOperation(t, generatedVectorID(98), false)
			graph := mustSelectedGeneratedWork(t, fresh).bundles[0]
			if _, admitted, err := s.generatedDeleteReservationSelection(t.Context(), graph, cold); err != nil || admitted != (conflict == "uncontested transport") {
				t.Fatal("acknowledged retirement ignored retained contradiction", admitted, err)
			}
		})
	}
}

func generatedParkedRetirementForOperation(t testing.TB, operation contract.ID) (*StateSession, generatedAttempt, contract.GeneratedDutyRecord) {
	t.Helper()
	s, a, h, target := generatedDeleteHazardForOperation(t, operation, 1)
	g, err := s.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	locations := make([]contract.GeneratorSliceLocation, 0, len(g.content.locations))
	for _, location := range g.content.locations {
		locations = append(locations, location)
	}
	d := contract.GeneratedDutyRecord{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratedDutyRecordSchema, DomainID: h.DomainID, DutyID: h.OwnerID, OwnerID: h.OwnerID,
		OriginalOperationID: target.OriginalOperationID, OriginalAttemptID: target.OriginalAttemptID,
		ResourceID: h.ResourceID, ConfigContractID: h.ConfigContractID, ResourceContractID: h.ResourceContractID, ExecutorID: h.ExecutorID,
		CredentialRouteID: h.CredentialRouteID, DescriptorID: h.DescriptorID, ResultContractID: h.ResultContractID,
		Kind: contract.GeneratedDutyRetirement, CompletionClass: h.CompletionClass, Step: 1, Status: contract.GeneratedEffectUnknown, CapacityReservation: h.CapacityReservation,
		Target: h.Target, Progress: contract.EmptyGeneratorVector(contract.GeneratorVectorProgress), History: h.History, Support: h.Support}
	a.record.State = contract.GeneratedEffectUnknown
	context, err := contract.GeneratorResultUseDigest(a.expected.Use)
	if err != nil {
		t.Fatal(err)
	}
	body, err := contract.EncodeGeneratorConsumer(contract.GeneratorConsumer{Schema: 1, OwnerID: d.DutyID, MaterialID: a.material.Core.OperationMaterialID,
		ContextDigest: context, SubjectKind: 3, SubjectID: a.record.ResultID, Purpose: 4})
	if err != nil {
		t.Fatal(err)
	}
	var carriers []contract.SupportRecord
	d.Consumers, carriers = generatedVectorRows(t, 10, d.DutyID, contract.GeneratorVectorConsumers, [][]byte{body})
	targetBody, err := contract.EncodeGeneratorTarget(target)
	if err != nil {
		t.Fatal(err)
	}
	var rows []contract.SupportRecord
	d.Target, rows = generatedVectorRows(t, 10, d.DutyID, contract.GeneratorVectorTargets, [][]byte{targetBody})
	carriers = append(carriers, rows...)
	for i := range s.support {
		s.support[i].Records = slices.DeleteFunc(s.support[i].Records, func(row contract.SupportRecordView) bool {
			if row.Kind == 11 {
				return true
			}
			if row.Kind != contract.GeneratorVectorSupportKind {
				return false
			}
			v, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			return v.OwnerKind == 11
		})
	}
	body, err = contract.EncodeGeneratedAttemptRecord(a.record)
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceRecord(t, s, 9, a.record.AttemptID, body)
	body, err = contract.EncodeGeneratedDutyRecord(d)
	if err != nil {
		t.Fatal(err)
	}
	carriers = append(carriers, contract.SupportRecord{Kind: 10, RecordID: d.DutyID, Body: body})
	for _, row := range carriers {
		s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
	}
	s.root.Generated.Hazards, s.root.Generated.Duties, s.root.Generated.Retiring = 0, 1, 1
	s.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, []contract.ID{d.DutyID})
	if err != nil {
		t.Fatal(err)
	}
	history := []contract.GeneratorHistory{{Schema: 1, PredecessorAttemptID: a.record.AttemptID, OwnerID: d.DutyID, Outcome: a.record.State}}
	generatedSetHistoryUnrefreshed(t, s, 9, a.record.AttemptID, history)
	generatedSetHistoryUnrefreshed(t, s, 10, d.DutyID, history)
	generatedRepackSupportAtLocations(t, s, s.supportRecords(), g.bundles, locations)
	return s, a, d
}

func generatedRepeatedRetirementState(t testing.TB, previous int) (*StateSession, []generatedAttempt, contract.GeneratedDutyRecord) {
	t.Helper()
	s, current, duty, _ := generatedEnteredRetirementForOperation(t, generatedVectorID(98), false)
	g, err := s.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	phase := *g.phase
	states := []*StateSession{s}
	access := slices.Clone(s.access[0].Records)
	var attempts []generatedAttempt
	for i := 0; i < previous; i++ {
		old, a, _ := generatedParkedRetirementForOperation(t, contract.Hash([]byte(fmt.Sprintf("older retirement %d", i))))
		states = append(states, old)
		attempts = append(attempts, a)
		access = append(access, old.access[0].Records[0])
	}
	attempts = append(attempts, current)
	var locations []contract.GeneratorSliceLocation
	var blobs []generatedContentFixtureBlob
	var rows []contract.SupportRecord
	var graphs []contract.ID
	var bundles []contract.GeneratorPlanBundle
	seen := make(map[generatedContentKey]bool)
	for i, state := range states {
		selected, err := state.selectedGeneratedWork(stdcontext.Background())
		if err != nil {
			t.Fatal(err)
		}
		bundles = append(bundles, selected.bundles...)
		for key, location := range selected.content.locations {
			if seen[key] {
				continue
			}
			seen[key] = true
			body, err := selected.readSelectedSlice(t.Context(), key.kind, key.id, location.Length)
			if err != nil {
				t.Fatal(err)
			}
			location.BlobID, location.Offset = contract.Hash(body), 0
			locations = append(locations, location)
			blobs = append(blobs, generatedContentFixtureBlob{location.BlobID, body})
			if key.kind == contract.GeneratorContentGraph {
				graphs = append(graphs, key.id)
			}
		}
		for _, row := range state.supportRecords() {
			if row.Kind == 3 {
				continue
			}
			if row.Kind == contract.GeneratorVectorSupportKind {
				v, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				if v.OwnerKind == contract.GeneratorSnapshotOwner || v.OwnerKind == 10 && v.VectorKind == contract.GeneratorVectorConsumers ||
					i != 0 && v.OwnerKind != 9 {
					continue
				}
			} else if i != 0 && row.Kind != 1 && row.Kind != 9 {
				continue
			}
			rows = append(rows, row)
		}
	}
	// Original inputs are read before the output acquires their material owners.
	s.access[0].Records = access
	var consumers [][]byte
	var history []contract.GeneratorHistory
	for i, a := range attempts {
		context, err := contract.GeneratorResultUseDigest(a.expected.Use)
		if err != nil {
			t.Fatal(err)
		}
		body, err := contract.EncodeGeneratorConsumer(contract.GeneratorConsumer{Schema: 1, OwnerID: duty.DutyID, MaterialID: a.material.Core.OperationMaterialID,
			ContextDigest: context, SubjectKind: 3, SubjectID: a.record.ResultID, Purpose: 4})
		if err != nil {
			t.Fatal(err)
		}
		consumers = append(consumers, body)
		h := contract.GeneratorHistory{Schema: 1, PredecessorAttemptID: a.record.AttemptID, OwnerID: duty.DutyID, Outcome: a.record.State}
		if i+1 < len(attempts) {
			h.NextAttemptID, h.Edge = attempts[i+1].record.AttemptID, 4
		}
		history = append(history, h)
	}
	slices.SortFunc(consumers, bytes.Compare)
	var carriers []contract.SupportRecord
	duty.Consumers, carriers = generatedVectorRows(t, 10, duty.DutyID, contract.GeneratorVectorConsumers, consumers)
	rows = append(rows, carriers...)
	content := generatedContentStateAtSnapshot(t, s.root.Snapshot, blobs, locations)
	s.support = content.support
	s.root.Generated.Fragments, s.root.Generated.Slices = content.root.Generated.Fragments, content.root.Generated.Slices
	for _, row := range rows {
		s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
	}
	body, err := contract.EncodeGeneratedDutyRecord(duty)
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceRecord(t, s, 10, duty.DutyID, body)
	s.root.Generated.Attempts, s.root.Generated.Materials = uint32(len(attempts)), uint32(len(attempts))
	slices.SortFunc(graphs, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	s.root.Generated.Graphs, err = contract.GeneratorIndexDescriptor(contract.GeneratorGraphSet, graphs)
	if err != nil {
		t.Fatal(err)
	}
	generatedSetHistoryUnrefreshed(t, s, 10, duty.DutyID, history)
	for _, row := range s.supportRecords() {
		if row.Kind == 9 && row.RecordID == current.record.AttemptID {
			phase.Attempts, err = contract.GeneratorRecordSetDescriptor(contract.GeneratorPhaseAttempts, s.root.Domain, []contract.SupportRecord{row})
		} else if row.Kind == 10 && row.RecordID == duty.DutyID {
			phase.Duties, err = contract.GeneratorRecordSetDescriptor(contract.GeneratorPhaseDuties, s.root.Domain, []contract.SupportRecord{row})
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	body, err = contract.EncodeGeneratedPhaseRecord(phase)
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceRecord(t, s, 5, phase.OperationID, body)
	generatedRepackSupportAtLocations(t, s, s.supportRecords(), bundles, locations)
	generatedSealSelectedFixture(t, s)
	if !s.indexSelectedMaterials() {
		t.Fatal("repeated retirement material index")
	}
	for _, row := range s.supportRecords() {
		if row.Kind == 10 && row.RecordID == duty.DutyID {
			duty, err = contract.InspectGeneratedDutyRecord(row.Body)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	return s, attempts, duty
}

// full_only: false
func TestGeneratedRepeatedRetirementKeepsEachUnknownInvocation(t *testing.T) {
	for _, previous := range []int{1, 60} {
		t.Run(fmt.Sprint(previous), func(t *testing.T) {
			s, attempts, duty := generatedRepeatedRetirementState(t, previous)
			g, err := s.selectedGeneratedWork(stdcontext.Background())
			if err != nil {
				t.Fatal("fresh same-obligation invocation discarded old uncertainty", err)
			}
			if len(g.attempts) != len(attempts) || len(g.materials) != len(attempts) || len(g.bundles) != len(attempts) ||
				g.phase.Attempts.Count != 1 || g.phase.Duties.Count != 1 || s.root.Generated.Duties != 1 || s.root.Generated.Retiring != 1 {
				t.Fatal("history changed active ownership or dropped older result readers")
			}
			for _, a := range attempts {
				consumers := g.consumers[materialIdentity{3, a.material.Core.OperationMaterialID}]
				if len(consumers) != 1 || consumers[0].OwnerID != duty.DutyID || consumers[0].SubjectID != a.record.ResultID || consumers[0].Purpose != 4 {
					t.Fatal("history restored effect rights or lost a late result")
				}
			}
			if previous == 60 {
				var bytes int
				for _, row := range s.supportRecords() {
					if row.Kind != contract.GeneratorVectorSupportKind {
						continue
					}
					v, err := contract.InspectGeneratorVectorCarrier(row.Body)
					if err != nil {
						t.Fatal(err)
					}
					if v.OwnerKind == 10 && v.OwnerID == duty.DutyID && v.VectorKind == contract.GeneratorVectorHistory {
						bytes += 37 + len(row.Body)
					}
				}
				if bytes <= 16*1024 {
					t.Fatal("history fixture no longer crosses one owner envelope", bytes)
				}
			}
			generatedRepackSupport(t, s, s.supportRecords(), g.bundles)
			if _, err := s.selectedGeneratedWork(stdcontext.Background()); err != nil {
				t.Fatal("packed repeated history refused", err)
			}
		})
	}
}

// full_only: false
func TestGeneratedParkedRetirementRequiresBoundUnknownFacts(t *testing.T) {
	for _, change := range []string{"missing", "result", "account", "request", "intent", "success"} {
		t.Run(change, func(t *testing.T) {
			s, a, _ := generatedParkedRetirementState(t)
			g, err := s.selectedGeneratedWork(stdcontext.Background())
			if err != nil {
				t.Fatal(err)
			}
			var bodies [][]byte
			if change != "missing" {
				facts := generatedRetirementFactsFixture(t, s, a, contract.GeneratorDispositionUnknown)
				result := a.record.ResultID
				switch change {
				case "result":
					result = generatedVectorID(94)
				case "account":
					facts.ResourceContractID = generatedVectorID(94)
				case "request":
					facts.RequestDigest = generatedVectorID(94)
				case "intent":
					facts.IntentDigest = generatedVectorID(94)
				case "success":
					facts = generatedRetirementFactsFixture(t, s, a, contract.GeneratorDispositionRetirementAcknowledged)
				}
				body, err := contract.EncodeGeneratorSafeFacts(facts)
				if err != nil {
					t.Fatal(err)
				}
				body, err = contract.EncodeGeneratorFactsRow(contract.GeneratorFactsRow{Schema: 1, ResultID: result, Facts: body})
				if err != nil {
					t.Fatal(err)
				}
				bodies = [][]byte{body}
			}
			a = g.attempts[a.record.AttemptID]
			var carriers []contract.SupportRecord
			a.record.Facts, carriers = generatedVectorRows(t, 9, a.record.AttemptID, contract.GeneratorVectorFacts, bodies)
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
			body, err := contract.EncodeGeneratedAttemptRecord(a.record)
			if err != nil {
				t.Fatal(err)
			}
			generatedReplaceRecord(t, s, 9, a.record.AttemptID, body)
			s.generatedWork = nil
			if _, err := s.selectedGeneratedWork(stdcontext.Background()); err == nil {
				t.Fatal("parked retirement accepted missing or unbound unknown facts")
			}
		})
	}
}

// full_only: false
func TestGeneratedParkedRetirementRetainsUnknownDelete(t *testing.T) {
	s, a, duty := generatedParkedRetirementState(t)
	g, err := s.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal("parked unknown retirement refused", err)
	}
	if g.parent != nil || g.phase != nil || len(g.attempts) != 1 || len(g.attempts[a.record.AttemptID].result) != 0 ||
		g.attempts[a.record.AttemptID].record.State != contract.GeneratedEffectUnknown ||
		!g.hasRecord(generatedRecordKey{10, duty.DutyID}) || s.root.Generated.Retiring != 1 {
		t.Fatal("parked retirement lost uncertainty, ownership or its late reader")
	}
	if _, coverageErr := s.validateGeneratedCoverage(t.Context(), s.access[0].Records); coverageErr != nil {
		t.Fatal("parked retirement lost uncertainty, ownership or its late reader")
	}
	generatedRepackSupport(t, s, s.supportRecords(), g.bundles)
	if _, err := s.selectedGeneratedWork(stdcontext.Background()); err != nil {
		t.Fatal("packed parked retirement refused", err)
	}
}

// full_only: false
func TestGeneratedRepeatedRetirementRecordingPreservesEarlierUncertainty(t *testing.T) {
	for _, previous := range []int{1, 60} {
		t.Run(fmt.Sprint(previous), func(t *testing.T) {
			s, attempts, duty := generatedRepeatedRetirementState(t, previous)
			g, err := s.selectedGeneratedWork(stdcontext.Background())
			if err != nil {
				t.Fatal(err)
			}
			a := attempts[len(attempts)-1]
			result := generatedRetirementResultFixture(t, s, a, contract.GeneratorDispositionRetirementAcknowledged)
			phaseID := generatedVectorID(95)
			plan := &generatedRecordPlan{expected: a.expected, result: result, phase: contract.GeneratorPhaseIdentity{AfterPhase: g.phase.Phase + 1},
				reference: contract.GeneratorResultReference{Schema: 1, ResultID: a.record.ResultID, ResultBodyDigest: contract.Hash(result), ResultLength: uint32(len(result))}}
			rows, err := generatedRecordedRows(g, plan, phaseID)
			if err != nil {
				t.Fatal(err)
			}
			generatedRepackSupport(t, s, rows, g.bundles)
			s.root.Generated.ActivePhase, s.root.Generated.Results = phaseID, 1
			after, err := s.selectedGeneratedWork(stdcontext.Background())
			if err != nil {
				t.Fatal("recorded later delete lost earlier uncertainty", err)
			}
			if !bytes.Equal(after.attempts[a.record.AttemptID].result, result) || len(after.attempts) != len(attempts) ||
				after.phase.Attempts.Count != 1 || after.phase.AcceptedResults.Count != 1 || s.root.Generated.Retiring != 1 {
				t.Fatal("recording changed old ownership or prematurely closed retirement")
			}
			for _, old := range attempts[:previous] {
				key := materialIdentity{3, old.material.Core.OperationMaterialID}
				if after.attempts[old.record.AttemptID].record != g.attempts[old.record.AttemptID].record ||
					!slices.Equal(after.consumers[key], g.consumers[key]) || !after.materials[key] {
					t.Fatal("recording changed an earlier Attempt, consumer or material root")
				}
			}
			beforeHistory, err := g.vectors.resolve(10, duty.DutyID, contract.GeneratorVectorHistory, duty.History)
			if err != nil {
				t.Fatal(err)
			}
			next, err := contract.InspectGeneratedDutyRecord(after.records[generatedRecordKey{10, duty.DutyID}].Body)
			if err != nil || next.Target != duty.Target || next.Status != contract.GeneratedEffectSucceeded || next.Consumers != duty.Consumers {
				t.Fatal("recording changed the retained target or result readers", err)
			}
			afterHistory, err := after.vectors.resolve(10, duty.DutyID, contract.GeneratorVectorHistory, next.History)
			if err != nil || len(afterHistory) != len(beforeHistory) {
				t.Fatal("recording changed history length", err)
			}
			for i := range previous {
				if !bytes.Equal(beforeHistory[i], afterHistory[i]) {
					t.Fatal("recording rewrote an earlier result history")
				}
			}
		})
	}
}

// full_only: false
func TestGeneratedRepeatedRetirementRejectsChangedHistory(t *testing.T) {
	for _, change := range []string{"owner", "attempt", "outcome", "result", "edge", "omitted predecessor", "reordered"} {
		t.Run(change, func(t *testing.T) {
			s, attempts, duty := generatedRepeatedRetirementState(t, 1)
			g, err := s.selectedGeneratedWork(stdcontext.Background())
			if err != nil {
				t.Fatal(err)
			}
			var history []contract.GeneratorHistory
			rows, err := g.vectors.resolve(10, duty.DutyID, contract.GeneratorVectorHistory, duty.History)
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range rows {
				h, err := contract.InspectGeneratorHistory(row)
				if err != nil {
					t.Fatal(err)
				}
				history = append(history, h)
			}
			switch change {
			case "owner":
				history[0].OwnerID = generatedVectorID(94)
			case "attempt":
				history[0].PredecessorAttemptID = generatedVectorID(94)
			case "outcome":
				history[0].Outcome = contract.GeneratedEffectConfirmedNoEffect
			case "result":
				history[0].ResultID, history[0].ResultDigest = generatedVectorID(94), generatedVectorID(93)
			case "edge":
				history[0].Edge = 1
			case "omitted predecessor":
				history = history[1:]
			case "reordered":
				history[0], history[1] = history[1], history[0]
				history[0].Edge, history[0].NextAttemptID = 4, history[1].PredecessorAttemptID
				history[1].Edge, history[1].NextAttemptID = 0, contract.ID{}
			}
			generatedSetHistoryUnrefreshed(t, s, 10, duty.DutyID, history)
			phase := *g.phase
			for _, row := range s.supportRecords() {
				if row.Kind == 10 && row.RecordID == duty.DutyID {
					phase.Duties, err = contract.GeneratorRecordSetDescriptor(contract.GeneratorPhaseDuties, s.root.Domain, []contract.SupportRecord{row})
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			body, err := contract.EncodeGeneratedPhaseRecord(phase)
			if err != nil {
				t.Fatal(err)
			}
			generatedReplaceRecord(t, s, 5, phase.OperationID, body)
			s.generatedWork = nil
			if _, err := s.selectedGeneratedWork(stdcontext.Background()); err == nil {
				t.Fatal("accepted changed same-obligation history", attempts[0].record.AttemptID)
			}
		})
	}
}

// full_only: false
func TestGeneratedRepeatedRetirementRequiresEveryOriginalConsumer(t *testing.T) {
	for _, change := range []string{"missing", "owner", "material", "context", "foreign result", "selected derivation"} {
		t.Run(change, func(t *testing.T) {
			s, attempts, duty := generatedRepeatedRetirementState(t, 1)
			g, err := s.selectedGeneratedWork(stdcontext.Background())
			if err != nil {
				t.Fatal(err)
			}
			var bodies [][]byte
			for i, a := range attempts {
				consumer := g.consumers[materialIdentity{3, a.material.Core.OperationMaterialID}][0]
				if i == 0 {
					switch change {
					case "missing":
						continue
					case "owner":
						consumer.OwnerID = generatedVectorID(94)
					case "material":
						consumer.MaterialID = attempts[1].material.Core.OperationMaterialID
					case "context":
						consumer.ContextDigest = generatedVectorID(94)
					case "foreign result":
						consumer.SubjectID = generatedVectorID(94)
					case "selected derivation":
						consumer.Purpose = 3
					}
				}
				body, err := contract.EncodeGeneratorConsumer(consumer)
				if err != nil {
					t.Fatal(err)
				}
				bodies = append(bodies, body)
			}
			slices.SortFunc(bodies, bytes.Compare)
			var carriers []contract.SupportRecord
			duty.Consumers, carriers = generatedVectorRows(t, 10, duty.DutyID, contract.GeneratorVectorConsumers, bodies)
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
			body, err := contract.EncodeGeneratedDutyRecord(duty)
			if err != nil {
				t.Fatal(err)
			}
			generatedReplaceRecord(t, s, 10, duty.DutyID, body)
			phase := *g.phase
			phase.Duties, err = contract.GeneratorRecordSetDescriptor(contract.GeneratorPhaseDuties, s.root.Domain,
				[]contract.SupportRecord{{Kind: 10, RecordID: duty.DutyID, Body: body}})
			if err != nil {
				t.Fatal(err)
			}
			body, err = contract.EncodeGeneratedPhaseRecord(phase)
			if err != nil {
				t.Fatal(err)
			}
			generatedReplaceRecord(t, s, 5, phase.OperationID, body)
			s.generatedWork = nil
			if _, err := s.selectedGeneratedWork(stdcontext.Background()); err == nil {
				t.Fatal("repeated history changed an original result consumer")
			}
		})
	}
}

// full_only: false
func TestGeneratedRepeatedRetirementRequiresEveryOriginalDependency(t *testing.T) {
	for _, missing := range []uint8{9, 1} {
		t.Run(fmt.Sprint(missing), func(t *testing.T) {
			s, attempts, _ := generatedRepeatedRetirementState(t, 1)
			old := attempts[0]
			id := old.record.AttemptID
			if missing == 1 {
				id = old.material.Core.OperationMaterialID
			}
			for i := range s.support {
				s.support[i].Records = slices.DeleteFunc(s.support[i].Records, func(row contract.SupportRecordView) bool {
					if row.Kind == missing && row.RecordID == id {
						return true
					}
					if missing != 9 || row.Kind != contract.GeneratorVectorSupportKind {
						return false
					}
					v, err := contract.InspectGeneratorVectorCarrier(row.Body)
					if err != nil {
						t.Fatal(err)
					}
					return v.OwnerKind == 9 && v.OwnerID == id
				})
			}
			if missing == 9 {
				s.root.Generated.Attempts--
			} else {
				s.root.Generated.Materials--
				s.access[0].Records = slices.DeleteFunc(s.access[0].Records, func(row contract.AccessRecord) bool { return row.MaterialID == id })
				s.root.AccessRecordCount--
				generatedCommitFixtureAccess(t, s)
				if !s.indexSelectedMaterials() {
					t.Fatal("remaining material index")
				}
			}
			s.generatedWork = nil
			if _, err := format.EncodeRoot(s.root); err != nil {
				t.Fatal("missing-dependency fixture Root must be valid", err)
			}
			if _, err := s.selectedGeneratedWork(stdcontext.Background()); err == nil {
				t.Fatal("later invocation replaced an unresolved original dependency")
			}
		})
	}
}

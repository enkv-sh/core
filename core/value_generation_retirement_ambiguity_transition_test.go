package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedRepeatedRetirementParkingPreservesEveryPriorInvocation(t *testing.T) {
	for _, previous := range []int{1, 60} {
		t.Run(fmt.Sprint(previous), func(t *testing.T) {
			s, attempts, duty := generatedRepeatedRetirementState(t, previous)
			before, err := s.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			current := attempts[len(attempts)-1]
			facts, err := contract.EncodeGeneratorSafeFacts(generatedRetirementFactsFixture(t, s, current, contract.GeneratorDispositionUnknown))
			if err != nil {
				t.Fatal(err)
			}
			priorHistory, err := before.vectors.resolve(10, duty.DutyID, contract.GeneratorVectorHistory, duty.History)
			if err != nil {
				t.Fatal(err)
			}
			closure, err := before.generatedRetirementAmbiguity(t.Context(), duty.DutyID, facts, false)
			if err != nil {
				t.Fatal("repeated authorized retirement cannot retain its ambiguity", err)
			}
			s.root.Generated.Slices = closure.slices
			s.root.Generated.ActiveOwner, s.root.Generated.ActivePhase, s.root.Generated.ActiveGraph = contract.ID{}, contract.ID{}, contract.ID{}
			generatedRefreshClosureCounts(&s.root.Generated, closure.rows)
			generatedRepackSupportAtLocations(t, s, closure.rows, before.bundles, closure.locations)
			after, err := s.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal("parked repeated history is not authenticated", err)
			}
			parked, err := contract.InspectGeneratedDutyRecord(after.records[generatedRecordKey{10, duty.DutyID}].Body)
			if err != nil || parked.Status != contract.GeneratedEffectUnknown || parked.Consumers != duty.Consumers || parked.Target != duty.Target ||
				parked.History.Count != duty.History.Count || len(after.attempts) != len(attempts) || s.root.Generated.Retiring != 1 || s.root.Generated.Hazards != 0 {
				t.Fatal("parking reset ownership, history, readers or the target", err)
			}
			nextHistory, err := after.vectors.resolve(10, duty.DutyID, contract.GeneratorVectorHistory, parked.History)
			if err != nil || len(nextHistory) != len(priorHistory) {
				t.Fatal("parking changed history length", err)
			}
			for i, old := range attempts[:previous] {
				key := materialIdentity{3, old.material.Core.OperationMaterialID}
				if !bytes.Equal(priorHistory[i], nextHistory[i]) || after.attempts[old.record.AttemptID].record != before.attempts[old.record.AttemptID].record ||
					!slices.Equal(after.consumers[key], before.consumers[key]) || !after.materials[key] {
					t.Fatal("parking changed a prior invocation or consumed right")
				}
			}
			if after.attempts[current.record.AttemptID].record.State != contract.GeneratedEffectUnknown ||
				after.attempts[current.record.AttemptID].record.Stage != contract.GeneratedStageTerminal {
				t.Fatal("parking did not record the current exact ambiguous invocation")
			}
		})
	}
}

// full_only: false
func TestGeneratedRepeatedRetirementResidueTransfersEveryOriginalReader(t *testing.T) {
	for _, previous := range []int{1, 60} {
		for _, parked := range []bool{false, true} {
			t.Run(fmt.Sprintf("previous=%d/parked=%t", previous, parked), func(t *testing.T) {
				s, attempts, duty := generatedRepeatedRetirementState(t, previous)
				g, err := s.selectedGeneratedWork(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				current := attempts[len(attempts)-1]
				facts, err := contract.EncodeGeneratorSafeFacts(generatedRetirementFactsFixture(t, s, current, contract.GeneratorDispositionUnknown))
				if err != nil {
					t.Fatal(err)
				}
				if parked {
					closure, err := g.generatedRetirementAmbiguity(t.Context(), duty.DutyID, facts, false)
					if err != nil {
						t.Fatal(err)
					}
					generatedInstallAmbiguityClosure(t, s, g, closure)
					g, err = s.selectedGeneratedWork(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					facts = nil
				}
				beforeDuty, err := contract.InspectGeneratedDutyRecord(g.records[generatedRecordKey{10, duty.DutyID}].Body)
				if err != nil {
					t.Fatal(err)
				}
				beforeHistory, err := g.vectors.resolve(10, duty.DutyID, contract.GeneratorVectorHistory, beforeDuty.History)
				if err != nil {
					t.Fatal(err)
				}
				closure, err := g.generatedRetirementResidueWithFactsFixture(t.Context(), duty.DutyID, facts)
				if err != nil {
					t.Fatal("residue cannot transfer the repeated retiring obligation", err)
				}
				generatedInstallAmbiguityClosure(t, s, g, closure)
				after, err := s.selectedGeneratedWork(context.Background())
				if err != nil {
					t.Fatal("repeated residue cannot cold-select its complete ownership", err)
				}
				h := closure.hazard
				if h.OriginalAttemptID != current.record.AttemptID || h.OriginalOperationID != current.record.OperationID || h.OwnerID != duty.DutyID ||
					h.History.Count != uint32(len(attempts)) || h.Consumers.Count != uint32(len(attempts)) ||
					s.root.Generated.Hazards != 1 || s.root.Generated.Duties != 0 || s.root.Generated.Retiring != 0 || len(after.attempts) != len(attempts) {
					t.Fatal("residue split the obligation, lost original coordinates or kept the retiring slot")
				}
				history, err := after.vectors.resolve(11, h.HazardID, contract.GeneratorVectorHistory, h.History)
				if err != nil || len(history) != len(beforeHistory) {
					t.Fatal("residue lost history", err)
				}
				for i, original := range attempts {
					a := after.attempts[original.record.AttemptID]
					key := materialIdentity{3, original.material.Core.OperationMaterialID}
					want := slices.Clone(g.consumers[key])
					for j := range want {
						want[j].OwnerID = h.HazardID
					}
					if !after.materials[key] || !slices.Equal(want, after.consumers[key]) || a.expected != original.expected {
						t.Fatal("residue changed an original result identity, context or reader")
					}
					if i < previous && (!bytes.Equal(history[i], beforeHistory[i]) || a.record != g.attempts[original.record.AttemptID].record) {
						t.Fatal("residue changed a prior unknown Attempt or fresh-invocation edge")
					}
				}
			})
		}
	}
}

func generatedInstallAmbiguityClosure(t testing.TB, s *StateSession, g *generatedSelection, closure generatedResidueClosure) {
	t.Helper()
	s.root.Generated.Slices = closure.slices
	s.root.Generated.ActiveOwner, s.root.Generated.ActivePhase, s.root.Generated.ActiveGraph = contract.ID{}, contract.ID{}, contract.ID{}
	generatedRefreshClosureCounts(&s.root.Generated, closure.rows)
	generatedRepackSupportAtLocations(t, s, closure.rows, g.bundles, closure.locations)
}

func generatedRepeatedRetirementHazardState(t testing.TB, previous int) (*StateSession, *generatedSelection, contract.GeneratedHazardRecord) {
	t.Helper()
	s, attempts, duty := generatedRepeatedRetirementState(t, previous)
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	current := attempts[len(attempts)-1]
	facts, err := contract.EncodeGeneratorSafeFacts(generatedRetirementFactsFixture(t, s, current, contract.GeneratorDispositionUnknown))
	if err != nil {
		t.Fatal(err)
	}
	closure, err := g.generatedRetirementResidueWithFactsFixture(t.Context(), duty.DutyID, facts)
	if err != nil {
		t.Fatal(err)
	}
	generatedInstallAmbiguityClosure(t, s, g, closure)
	g, err = s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return s, g, closure.hazard
}

// full_only: false
func TestGeneratedRepeatedRetirementResiduePreservesOriginalCreateSupport(t *testing.T) {
	s, attempts, duty := generatedRepeatedRetirementState(t, 2)
	bundles := generatedFixtureBundles(t, s)
	body, err := contract.EncodeGeneratorSupportBinding(contract.GeneratorSupportBinding{Schema: contract.GeneratorSupportBindingSchema, Role: 3,
		ContractID: generatedVectorID(110), ImplementationID: generatedVectorID(111), PublicBindingDigest: generatedVectorID(112)})
	if err != nil {
		t.Fatal(err)
	}
	var carriers []contract.SupportRecord
	duty.Support, carriers, err = generatedCarrierRows(s.root.Domain, 2, duty.OriginalOperationID, contract.GeneratorVectorSupport, [][]byte{body})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range carriers {
		s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
	}
	body, err = contract.EncodeGeneratedDutyRecord(duty)
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceRecord(t, s, 10, duty.DutyID, body)
	for _, row := range s.supportRecords() {
		if row.Kind != 5 {
			continue
		}
		phase, err := contract.InspectGeneratedPhaseRecord(row.Body)
		if err != nil {
			t.Fatal(err)
		}
		phase.Duties, err = contract.GeneratorRecordSetDescriptor(contract.GeneratorPhaseDuties, s.root.Domain,
			[]contract.SupportRecord{{Kind: 10, RecordID: duty.DutyID, Body: body}})
		if err != nil {
			t.Fatal(err)
		}
		phaseBody, err := contract.EncodeGeneratedPhaseRecord(phase)
		if err != nil {
			t.Fatal(err)
		}
		generatedReplaceRecord(t, s, 5, phase.OperationID, phaseBody)
	}
	generatedRefreshSupport(t, s, bundles...)
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal("original create support is not selected by its Duty", err)
	}
	current := attempts[len(attempts)-1]
	facts, err := contract.EncodeGeneratorSafeFacts(generatedRetirementFactsFixture(t, s, current, contract.GeneratorDispositionUnknown))
	if err != nil {
		t.Fatal(err)
	}
	closure, err := g.generatedRetirementResidueWithFactsFixture(t.Context(), duty.DutyID, facts)
	if err != nil || closure.hazard.Support != duty.Support {
		t.Fatal("residue discarded original obligation support", err)
	}
	generatedInstallAmbiguityClosure(t, s, g, closure)
	g, err = s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal("residue relabelled original create support as latest delete support", err)
	}
	original := g.attempts[attempts[0].record.AttemptID]
	packet := generatedRetirementResultFixture(t, s, original, contract.GeneratorDispositionRetirementAcknowledged)
	selection, ok, err := g.selectGeneratedCleanup(context.Background(), map[contract.ID][]byte{original.record.ResultID: packet})
	if err != nil || !ok || !selection.closeOwner {
		t.Fatal("original delete result selection", err)
	}
	reflected, err := g.generatedReflectLateDelete(t.Context(), selection, generatedVectorID(95))
	if err != nil {
		t.Fatal("shared resource closure with original create support", err)
	}
	for _, row := range reflected.rows {
		if row.Kind != contract.GeneratorVectorSupportKind {
			continue
		}
		carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil || carrier.VectorKind == contract.GeneratorVectorSupport && carrier.OwnerID == duty.OriginalOperationID {
			t.Fatal("closure retained obsolete original create support", err)
		}
	}
	generatedRepackSupportAtLocations(t, s, reflected.rows, g.bundles, reflected.locations)
	s.root.Generated.Slices = reflected.slices
	for _, page := range s.access {
		if page != nil {
			page.Records = slices.DeleteFunc(page.Records, func(row contract.AccessRecord) bool {
				return row.MaterialKind == 3 && slices.Contains(reflected.materials, row.MaterialID)
			})
		}
	}
	s.root.AccessRecordCount = 0
	generatedRefreshClosureCounts(&s.root.Generated, reflected.rows)
	s.recountChildren()
	generatedCommitFixtureAccess(t, s)
	if !s.indexSelectedMaterials() {
		t.Fatal("release-only material index")
	}
	if _, err := s.selectedGeneratedWork(context.Background()); err != nil {
		t.Fatal("release-only state cannot cold-select after public support pruning", err)
	}
}

// full_only: false
func TestGeneratedResidueSupportPruningKeepsSelectedSiblingSupport(t *testing.T) {
	s := generatedSelectedEntryState(t)
	entry := s.pages[0].Slots[0]
	body, err := contract.EncodeGeneratorSupportBinding(contract.GeneratorSupportBinding{Schema: contract.GeneratorSupportBindingSchema, Role: 3,
		ContractID: generatedVectorID(110), ImplementationID: generatedVectorID(111), PublicBindingDigest: generatedVectorID(112)})
	if err != nil {
		t.Fatal(err)
	}
	var carriers []contract.SupportRecord
	entry.Generated.RequiredSupport, carriers, err = generatedCarrierRows(s.root.Domain, 2, entry.Generated.OriginOperationID,
		contract.GeneratorVectorSupport, [][]byte{body})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range carriers {
		s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
	}
	generatedRefreshSupport(t, s)
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal("selected sibling public support", err)
	}
	obsoleteOwner := generatedVectorID(113)
	_, obsolete, err := generatedCarrierRows(s.root.Domain, 2, obsoleteOwner, contract.GeneratorVectorSupport, [][]byte{body})
	if err != nil {
		t.Fatal(err)
	}
	var rows []contract.SupportRecord
	for _, row := range s.supportRecords() {
		if row.Kind == contract.GeneratorVectorSupportKind {
			carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			if carrier.VectorKind == contract.GeneratorVectorSlices {
				continue
			}
		}
		rows = append(rows, row)
	}
	rows = append(rows, obsolete...)
	rows, locations, descriptor, err := g.generatedCloseContent(rows)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Kind != contract.GeneratorVectorSupportKind {
			continue
		}
		carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil || carrier.VectorKind == contract.GeneratorVectorSupport && carrier.OwnerID == obsoleteOwner {
			t.Fatal("unreferenced support survived root pruning", err)
		}
	}
	generatedRepackSupportAtLocations(t, s, rows, g.bundles, locations)
	s.root.Generated.Slices = descriptor
	generatedRefreshClosureCounts(&s.root.Generated, rows)
	if _, err := s.selectedGeneratedWork(context.Background()); err != nil {
		t.Fatal("pruning removed the selected sibling's public support", err)
	}
}

// full_only: false
func TestGeneratedCloseContentUsesAuthenticatedSliceSnapshot(t *testing.T) {
	s, _, duty := generatedParkedRetirementState(t)
	g, err := s.selectedGeneratedWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	backing := s.adminIndex.SliceSnapshot
	if backing.IsZero() || backing != s.root.Snapshot {
		t.Fatal("fixture has no authenticated Slice backing")
	}
	s.root.Snapshot = generatedVectorID(114)
	if s.root.Snapshot == backing {
		t.Fatal("fixture did not separate Root and Slice snapshots")
	}
	closure, err := g.generatedRetirementAmbiguity(t.Context(), duty.DutyID, nil, true)
	if err != nil {
		t.Fatal("retirement closure with retained Slice backing", err)
	}
	carriers := 0
	for _, row := range closure.rows {
		if row.Kind != contract.GeneratorVectorSupportKind {
			continue
		}
		carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			t.Fatal(err)
		}
		if carrier.VectorKind != contract.GeneratorVectorSlices {
			continue
		}
		carriers++
		id, err := contract.GeneratorVectorCarrierID(carrier)
		if err != nil || carrier.OwnerKind != contract.GeneratorSnapshotOwner || carrier.OwnerID != backing || row.RecordID != id {
			t.Fatal("closure changed authenticated Slice owner", err)
		}
	}
	if carriers == 0 || closure.slices.Count != uint32(carriers) {
		t.Fatal("retirement closure omitted Slice carriers", carriers, closure.slices.Count)
	}
}

// full_only: false
func TestGeneratedParkedRetirementResiduePreservesExactPossibleLiveHazard(t *testing.T) {
	s, original, duty := generatedParkedRetirementState(t)
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	closure, err := g.generatedRetirementResidueFixture(t.Context(), duty.DutyID)
	if err != nil {
		t.Fatal(err)
	}
	if closure.attempt.record.AttemptID != original.record.AttemptID ||
		closure.attempt.record.State != contract.GeneratedEffectClosedWithResidue ||
		closure.hazard.OwnerID != duty.DutyID || closure.hazard.OriginalAttemptID != original.record.AttemptID ||
		closure.hazard.Exposure != contract.GeneratedExposurePossibleLive || closure.hazard.Eligibility != contract.GeneratedExposurePossibleLive ||
		closure.hazard.Fenced != 1 || closure.hazard.CompletionClass != duty.CompletionClass {
		t.Fatal("residue closure changed the exact unknown retirement or its completion ceiling")
	}
	targets, err := generatedVectorBodies(closure.hazard.DomainID, closure.rows, 11, closure.hazard.HazardID, contract.GeneratorVectorTargets, closure.hazard.Target)
	if err != nil || len(targets) != 1 {
		t.Fatal("residue closure lost the exact target", err)
	}
	beforeTargets, err := g.vectors.resolve(10, duty.DutyID, contract.GeneratorVectorTargets, duty.Target)
	if err != nil || !bytes.Equal(targets[0], beforeTargets[0]) {
		t.Fatal("residue closure retargeted the resource", err)
	}

	generatedRepackSupport(t, s, closure.rows, g.bundles)
	s.root.Generated.Duties, s.root.Generated.Retiring, s.root.Generated.Hazards = 0, 0, 1
	s.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, []contract.ID{closure.hazard.HazardID})
	if err != nil {
		t.Fatal(err)
	}
	after, err := s.selectedGeneratedWork(context.Background())
	if err != nil || !after.hasRecord(generatedRecordKey{11, closure.hazard.HazardID}) ||
		after.attempts[original.record.AttemptID].record.State != contract.GeneratedEffectClosedWithResidue {
		t.Fatal("selected residue closure did not retain the exact Hazard", err)
	}
}

// full_only: false
func TestGeneratedRetirementResidueRefusesIneligibleWork(t *testing.T) {
	t.Run("not started", func(t *testing.T) {
		s, duty, _ := generatedDetachedRetirementState(t, "absent", 0)
		g, err := s.selectedGeneratedWork(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := g.generatedRetirementResidueFixture(t.Context(), duty.DutyID); err == nil {
			t.Fatal("residue closure accepted a retirement with no unknown delete")
		}
	})
	t.Run("active", func(t *testing.T) {
		s, _, duty, _ := generatedEnteredRetirementState(t, false)
		g, err := s.selectedGeneratedWork(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := g.generatedRetirementResidueFixture(t.Context(), duty.DutyID); err == nil {
			t.Fatal("parked residue path accepted an active transmitted delete")
		}
	})
	t.Run("contradiction", func(t *testing.T) {
		s, a, duty := generatedParkedRetirementState(t)
		g, err := s.selectedGeneratedWork(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		facts, err := contract.EncodeGeneratorSafeFacts(contract.GeneratorSafeFacts{Schema: contract.GeneratorSafeFactsSchema, Disposition: contract.GeneratorDispositionUnknown, Reason: 10,
			Action: a.expected.Template.Action, LifecycleMode: a.expected.Template.LifecycleMode, ResourceContractID: a.expected.Template.ResourceContractID, RequestDigest: a.record.RequestDigest, IntentDigest: a.expected.Template.IntentDigest,
			Target: []byte("fixture-target"), ResourceData: bytes.Repeat([]byte{96}, 32)})
		if err != nil {
			t.Fatal(err)
		}
		body, err := contract.EncodeGeneratorFactsRow(contract.GeneratorFactsRow{Schema: 1, ResultID: a.record.ResultID, Facts: facts})
		if err != nil {
			t.Fatal(err)
		}
		a.record.Facts, _ = generatedVectorRows(t, 9, a.record.AttemptID, contract.GeneratorVectorFacts, [][]byte{body})
		// This direct predicate check is sufficient: a conflicting identity is
		// never an eligible residue even if its carriers are otherwise selected.
		g.attempts[a.record.AttemptID] = a
		if _, err := g.generatedRetirementResidueFixture(t.Context(), duty.DutyID); err == nil {
			t.Fatal("residue closure hid a conflicting delete identity")
		}
	})
}

func generatedVectorBodies(domain contract.ID, rows []contract.SupportRecord, ownerKind uint8, owner contract.ID, vectorKind contract.GeneratorVectorKind,
	descriptor contract.GeneratorDescriptor) ([][]byte, error) {
	resolver, err := newGeneratedVectorSet(domain, rows)
	if err != nil {
		return nil, err
	}
	return resolver.resolve(ownerKind, owner, vectorKind, descriptor)
}

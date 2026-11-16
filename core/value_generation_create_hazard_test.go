package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestGeneratedDetachedCreateHazardRequiresEveryOwnedDeleteInHistory(t *testing.T) {
	for _, sameOwner := range []bool{true, false} {
		t.Run(fmt.Sprintf("same_owner=%t", sameOwner), func(t *testing.T) {
			state, hazard, _ := generatedDetachedHazardState(t, "absent", 0, contract.GeneratorDispositionCompleteCreate, 1)
			selected := mustSelectedGeneratedWork(t, state)
			facts := *selected
			facts.attempts = make(map[contract.ID]generatedAttempt)
			facts.consumers = make(map[materialIdentity][]contract.GeneratorConsumer)
			owner := hazard.OwnerID
			if !sameOwner {
				owner = generatedVectorID(249)
			}
			attempt := generatedVectorID(248)
			// The detached-Hazard boundary receives already selected Attempts.
			// Neither history nor consumers lists this selected delete.
			facts.attempts[attempt] = generatedAttempt{
				record:   contract.GeneratedAttemptRecord{AttemptID: attempt, OwnerID: owner},
				expected: contract.GeneratorResultExpectation{InputEncoding: contract.InputEncodingRaw, Template: contract.GeneratorAttemptTemplate{Action: contract.GeneratorActionDelete}},
			}
			content, err := newGeneratedContentValidation(t.Context(), state)
			if err != nil {
				t.Fatal("detached content", err)
			}
			builder := &generatedSelectionBuilder{facts: &facts, content: content,
				vectors: newGeneratedVectorValidation(&facts.vectors), claimed: make(map[generatedRecordKey]bool)}
			err = builder.resolveDetachedCreateHazards(state.supportRecords())
			if sameOwner && !errors.Is(err, contract.ErrRecord) {
				t.Fatal("detached Hazard accepted an omitted same-owner delete", err)
			}
			if !sameOwner && err != nil {
				t.Fatal("detached Hazard required another owner's delete history", err)
			}
		})
	}
}

func generatedCreateHazardState(t testing.TB, mode, disposition uint8) (*StateSession, generatedAttempt, contract.GeneratedHazardRecord) {
	t.Helper()
	s, original := generatedUnselectedCleanupState(t, mode)
	return generatedCreateHazardFromCleanup(t, s, original, disposition)
}

func generatedCreateHazardFromCleanup(t testing.TB, s *StateSession, original generatedAttempt, disposition uint8) (*StateSession, generatedAttempt, contract.GeneratedHazardRecord) {
	t.Helper()
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a := g.attempts[original.record.AttemptID]
	d, err := contract.InspectGeneratedDutyRecord(g.records[generatedRecordKey{10, a.record.OwnerID}].Body)
	if err != nil {
		t.Fatal(err)
	}
	empty := contract.EmptyGeneratorVector
	h := contract.GeneratedHazardRecord{Schema: contract.GeneratedHazardRecordSchema, DomainID: d.DomainID, HazardID: a.expected.Template.HazardID,
		OriginalOperationID: d.OriginalOperationID, OriginalAttemptID: d.OriginalAttemptID, OwnerID: d.OwnerID,
		ResourceID: d.ResourceID, ConfigContractID: d.ConfigContractID, ResourceContractID: d.ResourceContractID, ExecutorID: d.ExecutorID,
		CredentialRouteID: d.CredentialRouteID, DescriptorID: d.DescriptorID, ResultContractID: d.ResultContractID, CapacityReservation: d.CapacityReservation,
		Exposure: contract.GeneratedExposurePossibleLive, CompletionClass: d.CompletionClass, Fenced: 1,
		OriginalResults: contract.EmptyGeneratorRecordSet(contract.GeneratorHazardResults), Target: empty(contract.GeneratorVectorTargets),
		History: empty(contract.GeneratorVectorHistory), Support: d.Support}
	a.record.State, a.record.Stage = contract.GeneratedEffectClosedWithResidue, contract.GeneratedStageTerminal
	a.record.Facts, a.result = empty(contract.GeneratorVectorFacts), nil
	var added []contract.SupportRecord
	if disposition != 0 {
		a.result = generatedPublicResultFixture(t, a, disposition)
		result, err := contract.InspectGeneratedResultRecord(a.result)
		if err != nil {
			t.Fatal(err)
		}
		ownedFacts, err := result.SafeFacts.Own()
		if err != nil {
			t.Fatal(err)
		}
		factsBody, err := contract.EncodeGeneratorSafeFacts(ownedFacts)
		if err != nil {
			t.Fatal(err)
		}
		facts, err := contract.EncodeGeneratorFactsRow(contract.GeneratorFactsRow{Schema: 1, ResultID: a.record.ResultID, Facts: factsBody})
		if err != nil {
			t.Fatal(err)
		}
		descriptor, carriers := generatedVectorRows(t, 9, a.record.AttemptID, contract.GeneratorVectorFacts, [][]byte{facts})
		a.record.Facts = descriptor
		added = append(added, carriers...)
		resultRow := contract.SupportRecord{Kind: 4, RecordID: a.record.ResultID, Body: a.result}
		h.OriginalResults, err = contract.GeneratorRecordSetDescriptor(contract.GeneratorHazardResults, s.root.Domain, []contract.SupportRecord{resultRow})
		if err != nil {
			t.Fatal(err)
		}
		added = append(added, resultRow)
		h.Exposure, h.Eligibility = contract.GeneratedExposureLateEffect, contract.GeneratedExposureLateEffect
		targets, err := g.vectors.resolve(10, d.DutyID, contract.GeneratorVectorTargets, d.Target)
		if err != nil {
			t.Fatal(err)
		}
		h.Target, carriers = generatedVectorRows(t, 11, h.HazardID, contract.GeneratorVectorTargets, targets)
		added = append(added, carriers...)
	}
	consumers, err := g.vectors.resolve(10, d.DutyID, contract.GeneratorVectorConsumers, d.Consumers)
	if err != nil {
		t.Fatal(err)
	}
	var consumerBodies [][]byte
	for _, body := range consumers {
		consumer, err := contract.InspectGeneratorConsumer(body)
		if err != nil {
			t.Fatal(err)
		}
		consumer.OwnerID = h.HazardID
		body, err = contract.EncodeGeneratorConsumer(consumer)
		if err != nil {
			t.Fatal(err)
		}
		consumerBodies = append(consumerBodies, body)
	}
	var carriers []contract.SupportRecord
	h.Consumers, carriers = generatedVectorRows(t, 11, h.HazardID, contract.GeneratorVectorConsumers, consumerBodies)
	added = append(added, carriers...)
	body, err := contract.EncodeGeneratedHazardRecord(h)
	if err != nil {
		t.Fatal(err)
	}
	added = append(added, contract.SupportRecord{Kind: 11, RecordID: h.HazardID, Body: body})
	body, err = contract.EncodeGeneratedAttemptRecord(a.record)
	if err != nil {
		t.Fatal(err)
	}
	added = append(added, contract.SupportRecord{Kind: 9, RecordID: a.record.AttemptID, Body: body})
	for i := range s.support {
		s.support[i].Records = slices.DeleteFunc(s.support[i].Records, func(row contract.SupportRecordView) bool {
			if row.Kind == 4 || row.Kind == 9 || row.Kind == 10 {
				return true
			}
			if row.Kind == contract.GeneratorVectorSupportKind {
				v, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				return v.OwnerKind == 10 || v.OwnerKind == 9 && v.VectorKind == contract.GeneratorVectorFacts
			}
			return false
		})
	}
	for _, row := range added {
		s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
	}
	s.root.Generated.Duties, s.root.Generated.Hazards, s.root.Generated.Results = 0, 1, h.OriginalResults.Count
	s.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, []contract.ID{h.HazardID})
	if err != nil {
		t.Fatal(err)
	}
	generatedRepackSupport(t, s, s.supportRecords(), g.bundles)
	return s, a, h
}

// full_only: false
func TestGeneratedCreateHazardKeepsOriginalResultAndCurrentReaders(t *testing.T) {
	for mode := uint8(0); mode < 3; mode++ {
		for disposition := uint8(0); disposition < 3; disposition++ {
			t.Run(fmt.Sprintf("source%d/result%d", mode, disposition), func(t *testing.T) {
				s, original, h := generatedCreateHazardState(t, mode, disposition)
				g, err := s.selectedGeneratedWork(context.Background())
				if err != nil {
					t.Fatal("original create Hazard refused", err)
				}
				a := g.attempts[original.record.AttemptID]
				if g.parent != nil || g.phase != nil || len(g.attempts) != 1 || len(g.bundles) != 1 ||
					a.expected != original.expected || a.record != original.record || !bytes.Equal(a.result, original.result) ||
					!g.hasRecord(generatedRecordKey{11, h.HazardID}) || !g.materials[materialIdentity{3, a.material.Core.OperationMaterialID}] ||
					len(g.sources) != 0 || len(g.protected) != 0 {
					t.Fatal("Hazard changed original work or retained completed preparation")
				}
				if _, coverageErr := s.validateGeneratedCoverage(t.Context(), s.access[0].Records); coverageErr != nil {
					t.Fatal("Hazard changed original work or retained completed preparation")
				}
				consumers := g.consumers[materialIdentity{3, a.material.Core.OperationMaterialID}]
				if len(consumers) != 1 || consumers[0].OwnerID != h.HazardID || consumers[0].SubjectID != a.record.ResultID || consumers[0].Purpose != 4 {
					t.Fatal("Hazard lost original-result adoption or gained selected derivation")
				}
				if mode == 2 && len(g.canonical) != 1 {
					t.Fatal("Hazard lost its retained canonical reader union")
				}
				for id, original := range g.canonical {
					selection, err := g.canonicalConsumer(generatedRecordKey{11, h.HazardID}, id, original.record.Entry.Recipients[0])
					if err != nil || selection.Record.OriginalSlot != original.record.OriginalSlot ||
						selection.Selection.Core != original.core || selection.Owner.Kind != 11 || selection.Owner.RecordID != h.HazardID {
						t.Fatal("Hazard lost its exact retained canonical selection", err)
					}
				}
				coverage, err := s.replacementMaterialRows(t.Context(), 0, 1, contract.BindingTableRow{SubjectKind: 1, SubjectID: s.admission.recipient, Binding: generatedPublicBinding(t, 95)})
				if err != nil || len(coverage) != len(g.materials) {
					t.Fatal("key replacement omitted Hazard material")
				}
				used := make(map[contract.ID]bool)
				if s.retainGeneratedIdentities(t.Context(), used) != nil || !used[a.record.InboxID] || !used[a.record.ResultID] || !used[h.HazardID] {
					t.Fatal("Hazard released its absent or present original result coordinate")
				}
			})
		}
	}
}

// full_only: false
func TestGeneratedReservationPreservesCreateHazard(t *testing.T) {
	for _, disposition := range []uint8{0, 2} {
		t.Run(fmt.Sprint(disposition), func(t *testing.T) {
			before := generatedEmptyPredecessor(t)
			reserved, err := before.deriveGeneratedReservation(context.Background(), generatedReservationInputFixture(t, before))
			if err != nil {
				t.Fatal(err)
			}
			s, original := generatedUnselectedCleanupFromReservation(t, reserved.state)
			s, original, h := generatedCreateHazardFromCleanup(t, s, original, disposition)
			s.recountChildren()
			prior, err := s.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal("invalid Hazard predecessor", err)
			}
			if _, relationErr := s.validateRelationsMode(t.Context(), false); relationErr != nil {
				t.Fatal("invalid Hazard predecessor", err)
			}
			input := generatedReservationInputForOperation(t, s, generatedVectorID(98))
			reservation, err := s.deriveGeneratedReservation(context.Background(), input)
			if err != nil {
				t.Fatal("reservation lost an older Hazard", err)
			}
			g, err := reservation.state.selectedGeneratedWork(context.Background())
			if err != nil || g.parent == nil || g.parent.OperationID != input.graph.Header.OperationID ||
				len(g.attempts) != 2 || len(g.bundles) != 2 || len(g.materials) != 2 || g.phase.Attempts.Count != 1 ||
				g.phase.Duties.Count != 1 || g.phase.Hazards.Count != 0 || reservation.state.validateGeneratedSelection(t.Context(), nil) != nil {
				t.Fatal("reservation lost older work or adopted it into its active phase", err)
			}
			for _, key := range []generatedRecordKey{{1, original.material.Core.OperationMaterialID}, {9, original.record.AttemptID}, {11, h.HazardID}} {
				if !g.hasRecord(key) || !bytes.Equal(prior.records[key].Body, g.records[key].Body) {
					t.Fatal("reservation changed a Hazard dependency", key.kind)
				}
			}
			if !bytes.Equal(g.attempts[original.record.AttemptID].result, original.result) {
				t.Fatal("reservation changed the original result")
			}
		})
	}
}

// full_only: false
func TestGeneratedOwnedUnusableHazardKeepsTerminalFailureWithoutResidue(t *testing.T) {
	for _, mode := range []uint8{0, 2} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			s, a, h := generatedCreateHazardState(t, mode, 2)
			a.record.State, h.Fenced = contract.GeneratedEffectFailedTerminal, 0
			body, err := contract.EncodeGeneratedAttemptRecord(a.record)
			if err != nil {
				t.Fatal(err)
			}
			generatedReplaceRecord(t, s, 9, a.record.AttemptID, body)
			body, err = contract.EncodeGeneratedHazardRecord(h)
			if err != nil {
				t.Fatal(err)
			}
			generatedReplaceRecord(t, s, 11, h.HazardID, body)
			generatedRefreshSupport(t, s)
			g, err := s.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal("qualified owned-unusable result required an invented residue fence", err)
			}
			if g.attempts[a.record.AttemptID].record.State != contract.GeneratedEffectFailedTerminal {
				t.Fatal("owned-unusable Hazard changed its failed frontier or lost readers")
			}
			if _, coverageErr := s.validateGeneratedCoverage(t.Context(), s.access[0].Records); coverageErr != nil {
				t.Fatal("owned-unusable Hazard changed its failed frontier or lost readers")
			}
		})
	}
}

// full_only: false
func TestGeneratedCreateHazardRequiresLiveDependencies(t *testing.T) {
	for _, missing := range []uint8{1, 4, 6, 9, 11} {
		t.Run(fmt.Sprintf("record%d", missing), func(t *testing.T) {
			s, _, _ := generatedCreateHazardState(t, 2, 1)
			for i := range s.support {
				s.support[i].Records = slices.DeleteFunc(s.support[i].Records, func(row contract.SupportRecordView) bool { return row.Kind == missing })
			}
			s.generatedWork = nil
			if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
				t.Fatal("Hazard silently released a required dependency")
			}
		})
	}
	for _, disposition := range []uint8{0, 1} {
		t.Run(fmt.Sprintf("no seed/result%d", disposition), func(t *testing.T) {
			s, _, _ := generatedCreateHazardState(t, 0, disposition)
			s.access[0].Records, s.root.AccessRecordCount = nil, 0
			generatedCommitFixtureAccess(t, s)
			if !s.indexSelectedMaterials() {
				t.Fatal("material index")
			}
			if _, err := format.EncodeRoot(s.root); err != nil {
				t.Fatal("missing-seed Hazard fixture Root must be valid", err)
			}
			if _, coverageErr := s.validateGeneratedCoverage(t.Context(), s.generatedCoverageRecords()); coverageErr == nil {
				t.Fatal("Hazard released its original-result key")
			}
		})
	}
	for _, purpose := range []uint8{0, 3} {
		t.Run(fmt.Sprintf("result purpose%d", purpose), func(t *testing.T) {
			s, _, h := generatedCreateHazardState(t, 0, 0)
			var consumer contract.GeneratorConsumer
			for i := range s.support {
				s.support[i].Records = slices.DeleteFunc(s.support[i].Records, func(row contract.SupportRecordView) bool {
					if row.Kind != contract.GeneratorVectorSupportKind {
						return false
					}
					v, err := contract.InspectGeneratorVectorCarrier(row.Body)
					if err != nil {
						t.Fatal(err)
					}
					if v.OwnerKind != 11 || v.VectorKind != contract.GeneratorVectorConsumers {
						return false
					}
					consumer, err = contract.InspectGeneratorConsumer(v.Row)
					if err != nil {
						t.Fatal(err)
					}
					return true
				})
			}
			var bodies [][]byte
			if purpose != 0 {
				consumer.Purpose = purpose
				body, err := contract.EncodeGeneratorConsumer(consumer)
				if err != nil {
					t.Fatal(err)
				}
				bodies = append(bodies, body)
			}
			descriptor, carriers := generatedVectorRows(t, 11, h.HazardID, contract.GeneratorVectorConsumers, bodies)
			h.Consumers = descriptor
			body, err := contract.EncodeGeneratedHazardRecord(h)
			if err != nil {
				t.Fatal(err)
			}
			generatedReplaceRecord(t, s, 11, h.HazardID, body)
			for _, row := range carriers {
				s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
			}
			s.generatedWork = nil
			if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
				t.Fatal("Hazard dropped late adoption or restored selected derivation")
			}
		})
	}
}

// full_only: false
func TestGeneratedCreateHazardKeepsAmbiguityFactsOutsideTerminalInbox(t *testing.T) {
	for _, name := range []string{"transport", "identity conflict", "wrong result", "wrong request", "wrong intent", "wrong account", "invented success"} {
		t.Run(name, func(t *testing.T) {
			s, a, h := generatedCreateHazardState(t, 0, 0)
			bundles := generatedFixtureBundles(t, s)
			facts := contract.GeneratorSafeFacts{Schema: contract.GeneratorSafeFactsSchema, Disposition: contract.GeneratorDispositionUnknown, Reason: 8, Action: a.expected.Template.Action, LifecycleMode: a.expected.Template.LifecycleMode, ResourceContractID: a.expected.Template.ResourceContractID,
				RequestDigest: a.record.RequestDigest, IntentDigest: a.expected.Template.IntentDigest}
			id := a.record.ResultID
			switch name {
			case "identity conflict":
				facts.Reason = contract.GeneratorReasonIdentityConflict
				facts.Target, facts.ResourceData = []byte("fixture-target"), bytes.Repeat([]byte{99}, 32)
			case "wrong result":
				id = generatedVectorID(99)
			case "wrong request":
				facts.RequestDigest = generatedVectorID(99)
			case "wrong intent":
				facts.IntentDigest = generatedVectorID(99)
			case "wrong account":
				facts.ResourceContractID = generatedVectorID(99)
			case "invented success":
				facts.Disposition, facts.Reason = contract.GeneratorDispositionCompleteCreate, contract.GeneratorReasonNone
				facts.Target, facts.ResourceData = []byte("fixture-target"), bytes.Repeat([]byte{99}, 32)
			}
			body, err := contract.EncodeGeneratorSafeFacts(facts)
			if err != nil {
				t.Fatal(err)
			}
			body, err = contract.EncodeGeneratorFactsRow(contract.GeneratorFactsRow{Schema: 1, ResultID: id, Facts: body})
			if err != nil {
				t.Fatal(err)
			}
			descriptor, carriers := generatedVectorRows(t, 9, a.record.AttemptID, contract.GeneratorVectorFacts, [][]byte{body})
			a.record.Facts = descriptor
			body, err = contract.EncodeGeneratedAttemptRecord(a.record)
			if err != nil {
				t.Fatal(err)
			}
			generatedReplaceRecord(t, s, 9, a.record.AttemptID, body)
			for _, row := range carriers {
				s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
			}
			if name == "transport" || name == "identity conflict" {
				generatedRefreshSupport(t, s, bundles...)
			} else {
				// Malformed facts have no authenticated group owner. Keep this
				// negative unit case at the generated-work validation boundary.
				s.generatedWork = nil
			}
			g, err := s.selectedGeneratedWork(context.Background())
			if name != "transport" && name != "identity conflict" {
				if err == nil {
					t.Fatal("Hazard accepted wrong facts or invented a terminal result")
				}
				return
			}
			if err != nil {
				t.Fatal("Hazard discarded bounded ambiguity facts", err)
			}
			if len(g.attempts[a.record.AttemptID].result) != 0 || g.attempts[a.record.AttemptID].record.Facts != descriptor ||
				h.Eligibility != 0 || s.root.Generated.Results != 0 {
				t.Fatal("ambiguity became terminal evidence, cleanup eligibility, or loss of original-result access")
			}
			if _, coverageErr := s.validateGeneratedCoverage(t.Context(), s.access[0].Records); coverageErr != nil {
				t.Fatal("ambiguity became terminal evidence, cleanup eligibility, or loss of original-result access")
			}
		})
	}
}

// full_only: false
func TestGeneratedCreateHazardRejectsChangedOwnerAndAttempt(t *testing.T) {
	for name, change := range map[string]func(*contract.GeneratedHazardRecord, *contract.GeneratedAttemptRecord){
		"hazard": func(h *contract.GeneratedHazardRecord, _ *contract.GeneratedAttemptRecord) {
			h.HazardID = generatedVectorID(99)
		},
		"owner": func(h *contract.GeneratedHazardRecord, _ *contract.GeneratedAttemptRecord) { h.OwnerID = h.HazardID },
		"operation": func(h *contract.GeneratedHazardRecord, _ *contract.GeneratedAttemptRecord) {
			h.OriginalOperationID = generatedVectorID(99)
		},
		"attempt": func(h *contract.GeneratedHazardRecord, _ *contract.GeneratedAttemptRecord) {
			h.OriginalAttemptID = generatedVectorID(99)
		},
		"resource": func(h *contract.GeneratedHazardRecord, a *contract.GeneratedAttemptRecord) {
			h.ResourceID, a.ResourceID = generatedVectorID(99), generatedVectorID(99)
		},
		"profile": func(h *contract.GeneratedHazardRecord, a *contract.GeneratedAttemptRecord) {
			h.ConfigContractID, a.ConfigContractID = generatedVectorID(99), generatedVectorID(99)
		},
		"assumptions": func(h *contract.GeneratedHazardRecord, a *contract.GeneratedAttemptRecord) {
			h.ResourceContractID, a.ResourceContractID = generatedVectorID(99), generatedVectorID(99)
		},
		"executor": func(h *contract.GeneratedHazardRecord, a *contract.GeneratedAttemptRecord) {
			h.ExecutorID, a.ExecutorID = generatedVectorID(99), generatedVectorID(99)
		},
		"credential": func(h *contract.GeneratedHazardRecord, a *contract.GeneratedAttemptRecord) {
			h.CredentialRouteID, a.CredentialRouteID = generatedVectorID(99), generatedVectorID(99)
		},
		"permission": func(h *contract.GeneratedHazardRecord, a *contract.GeneratedAttemptRecord) {
			h.DescriptorID, a.DescriptorID = generatedVectorID(99), generatedVectorID(99)
		},
		"result contract": func(h *contract.GeneratedHazardRecord, a *contract.GeneratedAttemptRecord) {
			h.ResultContractID, a.ResultContractID = generatedVectorID(99), generatedVectorID(99)
		},
		"class": func(h *contract.GeneratedHazardRecord, a *contract.GeneratedAttemptRecord) {
			h.CompletionClass, a.CompletionClass = 2, 2
		},
		"unfenced": func(h *contract.GeneratedHazardRecord, _ *contract.GeneratedAttemptRecord) { h.Fenced = 0 },
		"unreflected": func(h *contract.GeneratedHazardRecord, _ *contract.GeneratedAttemptRecord) {
			h.Exposure, h.Eligibility = contract.GeneratedExposurePossibleLive, 0
		},
		"missing result set": func(h *contract.GeneratedHazardRecord, _ *contract.GeneratedAttemptRecord) {
			h.OriginalResults = contract.EmptyGeneratorRecordSet(contract.GeneratorHazardResults)
		},
		"missing target": func(h *contract.GeneratedHazardRecord, _ *contract.GeneratedAttemptRecord) {
			h.Target = contract.EmptyGeneratorVector(contract.GeneratorVectorTargets)
		},
		"inbox": func(_ *contract.GeneratedHazardRecord, a *contract.GeneratedAttemptRecord) {
			a.InboxID = generatedVectorID(99)
		},
		"transmission": func(_ *contract.GeneratedHazardRecord, a *contract.GeneratedAttemptRecord) {
			a.TransmissionID = generatedVectorID(99)
		},
		"request": func(_ *contract.GeneratedHazardRecord, a *contract.GeneratedAttemptRecord) {
			a.RequestDigest = generatedVectorID(99)
		},
		"predecessor": func(_ *contract.GeneratedHazardRecord, a *contract.GeneratedAttemptRecord) {
			a.PredecessorAttemptID = generatedVectorID(99)
		},
		"retry": func(_ *contract.GeneratedHazardRecord, a *contract.GeneratedAttemptRecord) { a.RetryUsed = 1 },
		"stage": func(_ *contract.GeneratedHazardRecord, a *contract.GeneratedAttemptRecord) {
			a.Stage = contract.GeneratedStageRetainedResult
		},
		"state": func(_ *contract.GeneratedHazardRecord, a *contract.GeneratedAttemptRecord) {
			a.State = contract.GeneratedEffectSucceeded
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, a, h := generatedCreateHazardState(t, 0, 1)
			id := h.HazardID
			change(&h, &a.record)
			body, err := contract.EncodeGeneratedHazardRecord(h)
			if err != nil {
				t.Fatal(err)
			}
			generatedReplaceRecord(t, s, 11, id, body)
			if h.HazardID != id {
				for i := range s.support {
					for j := range s.support[i].Records {
						row := &s.support[i].Records[j]
						if row.Kind == 11 && row.RecordID == id {
							row.RecordID = h.HazardID
						}
					}
				}
			}
			body, err = contract.EncodeGeneratedAttemptRecord(a.record)
			if err != nil {
				t.Fatal(err)
			}
			generatedReplaceRecord(t, s, 9, a.record.AttemptID, body)
			s.generatedWork = nil
			if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
				t.Fatal("repinned Hazard changed its original accepted relation")
			}
		})
	}
}

// full_only: false
func TestGeneratedCreateHazardRejectsRepinnedTarget(t *testing.T) {
	for name, change := range map[string]func(*contract.GeneratorTarget){
		"name":            func(v *contract.GeneratorTarget) { v.Name = "another" },
		"incarnation":     func(v *contract.GeneratorTarget) { v.IncarnationID = generatedVectorID(99) },
		"epoch":           func(v *contract.GeneratorTarget) { v.Epoch++ },
		"resource":        func(v *contract.GeneratorTarget) { v.ResourceID = generatedVectorID(99) },
		"account":         func(v *contract.GeneratorTarget) { v.ResourceContractID = generatedVectorID(99) },
		"token":           func(v *contract.GeneratorTarget) { v.ResourceDigest = generatedVectorID(99) },
		"profile":         func(v *contract.GeneratorTarget) { v.ConfigContractID = generatedVectorID(99) },
		"assumptions":     func(v *contract.GeneratorTarget) { v.ResourceContractID = generatedVectorID(99) },
		"operation":       func(v *contract.GeneratorTarget) { v.OriginalOperationID = generatedVectorID(99) },
		"attempt":         func(v *contract.GeneratorTarget) { v.OriginalAttemptID = generatedVectorID(99) },
		"result contract": func(v *contract.GeneratorTarget) { v.ResultContractID = generatedVectorID(99) },
		"class":           func(v *contract.GeneratorTarget) { v.CompletionClass = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			s, _, h := generatedCreateHazardState(t, 0, 1)
			g, err := s.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			rows, err := g.vectors.resolve(11, h.HazardID, contract.GeneratorVectorTargets, h.Target)
			if err != nil || len(rows) != 1 {
				t.Fatal("target", err)
			}
			target, err := contract.InspectGeneratorTarget(rows[0])
			if err != nil {
				t.Fatal(err)
			}
			change(&target)
			body, err := contract.EncodeGeneratorTarget(target)
			if err != nil {
				t.Fatal(err)
			}
			descriptor, carriers := generatedVectorRows(t, 11, h.HazardID, contract.GeneratorVectorTargets, [][]byte{body})
			h.Target = descriptor
			body, err = contract.EncodeGeneratedHazardRecord(h)
			if err != nil {
				t.Fatal(err)
			}
			generatedReplaceRecord(t, s, 11, h.HazardID, body)
			for i := range s.support {
				s.support[i].Records = slices.DeleteFunc(s.support[i].Records, func(row contract.SupportRecordView) bool {
					if row.Kind != contract.GeneratorVectorSupportKind {
						return false
					}
					v, err := contract.InspectGeneratorVectorCarrier(row.Body)
					if err != nil {
						t.Fatal(err)
					}
					return v.OwnerKind == 11 && v.OwnerID == h.HazardID && v.VectorKind == contract.GeneratorVectorTargets
				})
			}
			for _, row := range carriers {
				s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
			}
			s.generatedWork = nil
			if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
				t.Fatal("Hazard substituted a different create target")
			}
		})
	}
}

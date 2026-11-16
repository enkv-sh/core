package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func generatedDetachedHazardState(t testing.TB, current string, branch, disposition, fenced uint8) (*StateSession, contract.GeneratedHazardRecord, contract.GeneratorTarget) {
	t.Helper()
	profile := defaultGeneratedFixtureProfile()
	profile.ConfigContractID, profile.ResourceContractID = generatedVectorID(9), generatedVectorID(7)
	profile.ExecutorID, profile.DescriptorID, profile.CreateResultContractID = generatedVectorID(17), generatedVectorID(19), generatedVectorID(20)
	graph, _, _ := generatedEffectPlanForGenerationState(t, nil, generatedVectorID(11), []string{"generated"}, []byte("{}"), profile, 1,
		map[string]contract.ID{"generated": generatedVectorID(11)}, nil)
	originalTemplate := graph.Lineages[0].Templates[branch]
	s, duty, target := generatedDetachedRetirementState(t, current, branch)
	hazard, err := contract.GeneratorHazardID(duty.DomainID, duty.OriginalAttemptID)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := contract.GeneratorDutyID(duty.DomainID, duty.OriginalOperationID, duty.OriginalAttemptID, 1)
	if err != nil {
		t.Fatal(err)
	}
	h := contract.GeneratedHazardRecord{Schema: contract.GeneratedHazardRecordSchema, DomainID: duty.DomainID, HazardID: hazard, OriginalOperationID: duty.OriginalOperationID,
		OriginalAttemptID: duty.OriginalAttemptID, OwnerID: owner, ResourceID: duty.ResourceID, ConfigContractID: duty.ConfigContractID,
		ResourceContractID: duty.ResourceContractID, ExecutorID: generatedVectorID(17), CredentialRouteID: duty.CredentialRouteID,
		DescriptorID: duty.DescriptorID, ResultContractID: target.ResultContractID, CapacityReservation: duty.CapacityReservation,
		Exposure: contract.GeneratedExposureLateEffect, CompletionClass: duty.CompletionClass, Fenced: fenced, Eligibility: contract.GeneratedExposureLateEffect,
		History: contract.EmptyGeneratorVector(contract.GeneratorVectorHistory), Support: duty.Support,
		Consumers: contract.EmptyGeneratorVector(contract.GeneratorVectorConsumers)}
	var original contract.SupportRecord
	for i := range s.support {
		for j := range s.support[i].Records {
			row := &s.support[i].Records[j]
			if row.Kind != 13 {
				continue
			}
			evidence, err := contract.DecodeGeneratedCreateEvidence(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			core, err := contract.InspectGeneratedResultCore(evidence.ResultCore)
			if err != nil {
				t.Fatal(err)
			}
			if core.AttemptID != h.OriginalAttemptID {
				continue
			}
			if originalTemplate.AttemptID != core.AttemptID || originalTemplate.ResultID != core.ResultID ||
				originalTemplate.ExecutorID != core.ExecutorID || originalTemplate.DescriptorID != core.DescriptorID {
				t.Fatal("detached original template differs")
			}
			h.DescriptorID, h.CredentialRouteID = core.DescriptorID, originalTemplate.CredentialRouteID
			facts, err := contract.DecodeGeneratorSafeFacts(evidence.SafeFacts)
			if err != nil {
				t.Fatal(err)
			}
			facts.Disposition = disposition
			if disposition == 2 {
				facts.Reason = 1
			}
			evidence.SafeFacts, err = contract.EncodeGeneratorSafeFacts(facts)
			if err != nil {
				t.Fatal(err)
			}
			core.SafeFactsDigest, err = contract.GeneratorSafeFactsDigest(facts)
			if err != nil {
				t.Fatal(err)
			}
			evidence.ResultCore, err = contract.EncodeGeneratedResultCore(core)
			if err != nil {
				t.Fatal(err)
			}
			row.Body, err = contract.EncodeGeneratedCreateEvidence(evidence)
			if err != nil {
				t.Fatal(err)
			}
			original = contract.SupportRecord(*row)
		}
	}
	h.OriginalResults, err = contract.GeneratorRecordSetDescriptor(contract.GeneratorHazardResults, h.DomainID, []contract.SupportRecord{original})
	if err != nil {
		t.Fatal(err)
	}
	for i := range s.support {
		s.support[i].Records = slices.DeleteFunc(s.support[i].Records, func(row contract.SupportRecordView) bool {
			if row.Kind == 10 {
				return true
			}
			if row.Kind == contract.GeneratorVectorSupportKind {
				v, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				return v.OwnerKind == 10
			}
			return false
		})
	}
	if s.pages[0] != nil && s.pages[0].Slots[0].ValueSource == contract.Generated {
		s.pages[0].Slots[0].Generated.RetiringDutyPresent = 0
		s.pages[0].Slots[0].Generated.RetiringDutyID = contract.ID{}
	}
	s.root.Generated.Duties, s.root.Generated.Retiring, s.root.Generated.Hazards = 0, 0, 1
	h = generatedReplaceDetachedHazard(t, s, h, target)
	return s, h, target
}

func generatedReplaceDetachedHazard(t testing.TB, s *StateSession, h contract.GeneratedHazardRecord, target contract.GeneratorTarget, refresh ...bool) contract.GeneratedHazardRecord {
	t.Helper()
	body, err := contract.EncodeGeneratorTarget(target)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, carriers := generatedVectorRows(t, 11, h.HazardID, contract.GeneratorVectorTargets, [][]byte{body})
	h.Target = descriptor
	for i := range s.support {
		s.support[i].Records = slices.DeleteFunc(s.support[i].Records, func(row contract.SupportRecordView) bool {
			if row.Kind == 11 {
				return true
			}
			if row.Kind == contract.GeneratorVectorSupportKind {
				v, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				return v.OwnerKind == 11 && v.VectorKind == contract.GeneratorVectorTargets
			}
			return false
		})
	}
	body, err = contract.EncodeGeneratedHazardRecord(h)
	if err != nil {
		t.Fatal(err)
	}
	carriers = append(carriers, contract.SupportRecord{Kind: 11, RecordID: h.HazardID, Body: body})
	for _, row := range carriers {
		s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
	}
	s.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, []contract.ID{h.HazardID})
	if err != nil {
		t.Fatal(err)
	}
	if len(refresh) == 0 || refresh[0] {
		generatedRefreshSupport(t, s)
	} else {
		s.generatedWork = nil
	}
	return h
}

// full_only: false
func TestGeneratedDetachedHazardRetainsEvidenceWithoutResultAdoption(t *testing.T) {
	for _, current := range []string{"absent", "supplied", "generated"} {
		for _, outcome := range []struct{ disposition, fenced uint8 }{{1, 1}, {2, 1}, {2, 0}} {
			for _, branch := range []uint8{0, 2} {
				t.Run(fmt.Sprintf("%s/result%d/fenced%d/branch%d", current, outcome.disposition, outcome.fenced, branch), func(t *testing.T) {
					s, h, target := generatedDetachedHazardState(t, current, branch, outcome.disposition, outcome.fenced)
					g, err := s.selectedGeneratedWork(context.Background())
					if err != nil {
						t.Fatal("detached create evidence refused", err)
					}
					if g.parent != nil || g.phase != nil || len(g.attempts) != 0 || len(g.bundles) != 0 || len(g.consumers) != 0 ||
						len(g.sources) != 0 || len(g.protected) != 0 || !g.hasRecord(generatedRecordKey{11, h.HazardID}) {
						t.Fatal("detached Hazard restored original result adoption or private dependencies")
					}
					wantMaterials := 0
					if current == "generated" {
						wantMaterials = 1
					}
					if len(g.materials) != wantMaterials {
						t.Fatal("detached Hazard retained discarded seed or lost current value")
					}
					if _, ok := g.record(10, h.OwnerID); ok {
						t.Fatal("detached Hazard invented a succeeded Duty")
					}
					used := make(map[contract.ID]bool)
					if s.retainGeneratedIdentities(t.Context(), used) != nil {
						t.Fatal("detached Hazard identity inventory")
					}
					for _, id := range []contract.ID{h.HazardID, h.OwnerID, h.OriginalOperationID, h.OriginalAttemptID, h.ResourceID,
						h.ConfigContractID, h.ResourceContractID, h.ExecutorID, h.CredentialRouteID, h.DescriptorID, h.ResultContractID,
						target.IncarnationID, target.ResourceContractID, target.ResourceDigest} {
						if !used[id] {
							t.Fatal("detached Hazard made a retained identity reusable", id)
						}
					}
				})
			}
		}
	}
}

// full_only: false
func TestGeneratedDetachedHazardRejectsRepinnedOriginAndTarget(t *testing.T) {
	for name, damage := range map[string]func(*contract.GeneratedHazardRecord, *contract.GeneratorTarget){
		"hazard": func(h *contract.GeneratedHazardRecord, _ *contract.GeneratorTarget) {
			h.HazardID = generatedVectorID(99)
		},
		"owner": func(h *contract.GeneratedHazardRecord, _ *contract.GeneratorTarget) {
			h.OwnerID = generatedVectorID(99)
		},
		"executor": func(h *contract.GeneratedHazardRecord, _ *contract.GeneratorTarget) {
			h.ExecutorID = generatedVectorID(99)
		},
		"descriptor": func(h *contract.GeneratedHazardRecord, _ *contract.GeneratorTarget) {
			h.DescriptorID = generatedVectorID(99)
		},
		"route": func(h *contract.GeneratedHazardRecord, _ *contract.GeneratorTarget) {
			h.CredentialRouteID = generatedVectorID(99)
		},
		"operation": func(h *contract.GeneratedHazardRecord, v *contract.GeneratorTarget) {
			h.OriginalOperationID, v.OriginalOperationID = generatedVectorID(99), generatedVectorID(99)
		},
		"attempt": func(h *contract.GeneratedHazardRecord, v *contract.GeneratorTarget) {
			h.OriginalAttemptID, v.OriginalAttemptID = generatedVectorID(99), generatedVectorID(99)
		},
		"resource": func(h *contract.GeneratedHazardRecord, v *contract.GeneratorTarget) {
			h.ResourceID, v.ResourceID = generatedVectorID(99), generatedVectorID(99)
		},
		"profile": func(h *contract.GeneratedHazardRecord, v *contract.GeneratorTarget) {
			h.ConfigContractID, v.ConfigContractID = generatedVectorID(99), generatedVectorID(99)
		},
		"assumption": func(h *contract.GeneratedHazardRecord, v *contract.GeneratorTarget) {
			h.ResourceContractID, v.ResourceContractID = generatedVectorID(99), generatedVectorID(99)
		},
		"result contract": func(h *contract.GeneratedHazardRecord, v *contract.GeneratorTarget) {
			h.ResultContractID, v.ResultContractID = generatedVectorID(99), generatedVectorID(99)
		},
		"class": func(h *contract.GeneratedHazardRecord, v *contract.GeneratorTarget) {
			h.CompletionClass, v.CompletionClass = 2, 2
		},
		"name": func(_ *contract.GeneratedHazardRecord, v *contract.GeneratorTarget) { v.Name = "different" },
		"incarnation": func(_ *contract.GeneratedHazardRecord, v *contract.GeneratorTarget) {
			v.IncarnationID = generatedVectorID(99)
		},
		"epoch": func(_ *contract.GeneratedHazardRecord, v *contract.GeneratorTarget) { v.Epoch++ },
		"account": func(_ *contract.GeneratedHazardRecord, v *contract.GeneratorTarget) {
			v.ResourceContractID = generatedVectorID(99)
		},
		"token": func(_ *contract.GeneratedHazardRecord, v *contract.GeneratorTarget) {
			v.ResourceDigest = generatedVectorID(99)
		},
		"unfenced success": func(h *contract.GeneratedHazardRecord, _ *contract.GeneratorTarget) { h.Fenced = 0 },
		"original results": func(h *contract.GeneratedHazardRecord, _ *contract.GeneratorTarget) {
			h.OriginalResults.Digest = generatedVectorID(99)
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, h, target := generatedDetachedHazardState(t, "absent", 0, 1, 1)
			damage(&h, &target)
			generatedReplaceDetachedHazard(t, s, h, target, false)
			if name != "descriptor" && name != "route" && generatedIndexRejectsAlteredSupport(t, s) {
				return
			}
			generatedRefreshSupport(t, s)
			if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
				t.Fatal("detached Hazard accepted changed origin or target")
			}
		})
	}
}

// full_only: false
func TestGeneratedDetachedHazardRequiresEvidenceAndNoPrivateConsumer(t *testing.T) {
	for _, missing := range []uint8{11, 13} {
		t.Run(fmt.Sprintf("missing%d", missing), func(t *testing.T) {
			s, _, _ := generatedDetachedHazardState(t, "absent", 0, 1, 1)
			for i := range s.support {
				s.support[i].Records = slices.DeleteFunc(s.support[i].Records, func(row contract.SupportRecordView) bool { return row.Kind == missing })
			}
			// Remove an empty page without making a malformed physical directory.
			s.support = slices.DeleteFunc(s.support, func(p format.RequiredSupportPageView) bool { return len(p.Records) == 0 })
			for i := range s.support {
				s.support[i].Index = uint16(i)
			}
			if missing == 11 {
				s.root.Generated.Hazards = 0
				s.root.Generated.LiveOwners = contract.EmptyGeneratorIndexes()[1]
			}
			if generatedIndexRejectsAlteredSupport(t, s) {
				return
			}
			generatedRefreshSupport(t, s)
			if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
				t.Fatal("detached Hazard dropped evidence or retained an unowned dependency")
			}
		})
	}
	for _, purpose := range []uint8{3, 4} {
		t.Run(fmt.Sprintf("result consumer%d", purpose), func(t *testing.T) {
			s, h, _ := generatedDetachedHazardState(t, "absent", 0, 1, 1)
			consumer, err := contract.EncodeGeneratorConsumer(contract.GeneratorConsumer{Schema: 1, OwnerID: h.HazardID,
				MaterialID: generatedVectorID(90), ContextDigest: generatedVectorID(91), SubjectKind: 3, SubjectID: generatedVectorID(92), Purpose: purpose})
			if err != nil {
				t.Fatal(err)
			}
			descriptor, rows := generatedVectorRows(t, 11, h.HazardID, contract.GeneratorVectorConsumers, [][]byte{consumer})
			h.Consumers = descriptor
			body, err := contract.EncodeGeneratedHazardRecord(h)
			if err != nil {
				t.Fatal(err)
			}
			generatedReplaceRecord(t, s, 11, h.HazardID, body)
			for _, row := range rows {
				s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
			}
			generatedRefreshSupport(t, s)
			if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
				t.Fatal("detached evidence restored a private result consumer")
			}
		})
	}
}

// full_only: false
func TestGeneratedReservationPreservesDetachedHazard(t *testing.T) {
	for _, disposition := range []uint8{1, 2} {
		t.Run(fmt.Sprint(disposition), func(t *testing.T) {
			s := generatedEmptyPredecessor(t)
			old, h, _ := generatedDetachedHazardState(t, "absent", 0, disposition, 1)
			s.support, s.root.Generated = old.support, old.root.Generated
			generatedRefreshSupport(t, s)
			s.recountChildren()
			prior, err := s.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal("invalid detached Hazard predecessor", err)
			}
			if _, relationErr := s.validateRelationsMode(t.Context(), false); relationErr != nil {
				t.Fatal("invalid detached Hazard predecessor", err)
			}
			input := generatedReservationInputForProfileIntent(t, s, generatedVectorID(98), []string{"generated"},
				[]byte(`{"name":"independent"}`), defaultGeneratedFixtureProfile())
			reservation, err := s.deriveGeneratedReservation(context.Background(), input)
			if err != nil {
				t.Fatal("new reservation lost detached Hazard", err)
			}
			g, err := reservation.state.selectedGeneratedWork(context.Background())
			if err != nil || len(g.attempts) != 1 || len(g.bundles) != 1 || len(g.materials) != 1 ||
				g.phase.Hazards.Count != 0 || g.phase.Attempts.Count != 1 || reservation.state.validateGeneratedSelection(t.Context(), nil) != nil {
				t.Fatal("new reservation adopted detached Hazard", err)
			}
			for key, row := range prior.records {
				if key.kind == 11 || key.kind == 13 {
					if !g.hasRecord(key) || !bytes.Equal(row.Body, g.records[key].Body) {
						t.Fatal("new reservation changed detached evidence", key.kind)
					}
				}
			}
			if _, adopted := g.attempts[h.OriginalAttemptID]; adopted {
				t.Fatal("new reservation restored original result adoption")
			}
			for _, selecting := range []bool{true, false} {
				t.Run(fmt.Sprintf("final_selecting_%t", selecting), func(t *testing.T) {
					ctx := t.Context()
					oldIntents := make(map[contract.ID][]byte)
					for key, row := range prior.records {
						if key.kind != contract.GeneratedCreateEvidenceSupportKind {
							continue
						}
						evidence, err := contract.InspectGeneratedCreateEvidence(row.Body)
						if err != nil {
							t.Fatal("old detached evidence", err)
						}
						facts, err := contract.InspectGeneratorSafeFacts(evidence.SafeFacts)
						if err != nil {
							t.Fatal("old detached facts", err)
						}
						intent, err := prior.readSelectedSlice(ctx, contract.GeneratorContentIntent,
							facts.IntentDigest, contract.GeneratorIntentMaxLength)
						if err != nil {
							t.Fatal("old detached Intent", err)
						}
						oldIntents[facts.IntentDigest] = bytes.Clone(intent)
					}
					if len(oldIntents) != 1 {
						t.Fatal("detached fixture lacks its exclusive evidence Intent")
					}
					active := g.attempts[g.phase.FrontierAttemptID]
					if _, shared := oldIntents[active.expected.Template.IntentDigest]; shared {
						t.Fatal("independent operation reuses the detached Intent")
					}
					resultDisposition := uint8(contract.GeneratorDispositionCompleteCreate)
					if !selecting {
						resultDisposition = contract.GeneratorDispositionOwnedUnusableCreate
					}
					recordPlan, err := reservation.state.generatedRecordRequest(ctx, active.record.AttemptID,
						generatedPublicResultFixture(t, active, resultDisposition),
						generatedContinuationContext(t, reservation.state, 180, 181))
					if err != nil {
						t.Fatal("independent Record request", err)
					}
					recorded, err := reservation.state.deriveGeneratedRecord(ctx, recordPlan)
					if err != nil {
						t.Fatal("independent Record", err)
					}
					plan, err := recorded.state.generatedFinalRequest(ctx, generatedContinuationContext(t, recorded.state, 182, 183))
					if err != nil || plan.selecting != selecting {
						t.Fatal("independent Final request", err)
					}
					var prepared []contract.CryptoGeneratedValueEntryResult
					for _, entryPlan := range plan.entryPlans {
						prepared = append(prepared, generatedPreparedValueEntryFixture(t, recorded.state, entryPlan))
					}
					final, err := recorded.state.deriveGeneratedFinal(ctx, plan, prepared)
					if err != nil {
						t.Fatal("independent Final lost detached evidence closure", err)
					}
					closed, err := final.state.selectedGeneratedWork(ctx)
					if err != nil || final.state.validateGeneratedSelection(t.Context(), nil) != nil {
						t.Fatal("independent Final detached closure", err)
					}
					if _, adopted := closed.attempts[h.OriginalAttemptID]; adopted {
						t.Fatal("independent Final restored original result adoption")
					}
					for key, row := range prior.records {
						if key.kind == contract.GeneratedHazardSupportKind || key.kind == contract.GeneratedCreateEvidenceSupportKind {
							if !closed.hasRecord(key) || !bytes.Equal(row.Body, closed.records[key].Body) {
								t.Fatal("independent Final changed detached evidence", key.kind)
							}
						}
					}
					for id, want := range oldIntents {
						got, err := closed.readSelectedSlice(ctx, contract.GeneratorContentIntent, id, contract.GeneratorIntentMaxLength)
						if err != nil || !bytes.Equal(got, want) {
							t.Fatal("independent Final changed detached Intent", err)
						}
					}
				})
			}
		})
	}
}

func generatedHazardEvidenceHandoff(t testing.TB, s *StateSession, a generatedAttempt, h contract.GeneratedHazardRecord, releaseState uint8) *StateSession {
	return generatedHazardEvidenceHandoffAtSnapshot(t, s, a, h, releaseState, s.root.Snapshot)
}

func generatedHazardEvidenceHandoffAtSnapshot(t testing.TB, s *StateSession, a generatedAttempt, h contract.GeneratedHazardRecord,
	releaseState uint8, snapshot contract.ID) *StateSession {
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal("detached handoff selected work", err)
	}
	result, err := contract.DecodeGeneratedResultRecord(a.result)
	if err != nil {
		t.Fatal("detached handoff result", err)
	}
	core, err := contract.EncodeGeneratedResultCore(result.Core)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := contract.EncodeGeneratorSafeFacts(result.SafeFacts)
	if err != nil {
		t.Fatal(err)
	}
	var blobs []generatedContentFixtureBlob
	var locations []contract.GeneratorSliceLocation
	for _, key := range []generatedContentKey{{contract.GeneratorContentIntent, result.SafeFacts.IntentDigest}, {contract.GeneratorContentGraph, result.Core.PlanGraphID}} {
		if key.kind == contract.GeneratorContentGraph && releaseState == 0 {
			continue
		}
		location := g.content.locations[key]
		body, err := g.readSelectedSlice(t.Context(), key.kind, key.id, location.Length)
		if err != nil {
			t.Fatal(err)
		}
		location.BlobID, location.Offset = contract.Hash(body), 0
		locations = append(locations, location)
		blobs = append(blobs, generatedContentFixtureBlob{location.BlobID, body})
	}
	intent, err := contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{locations[0].Logical()})
	if err != nil {
		t.Fatal(err)
	}
	createEvidence := contract.GeneratedCreateEvidence{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratedCreateEvidenceSchema, OriginalResultID: a.record.ResultID,
		CredentialRouteID: a.expected.Template.CredentialRouteID, ResultCore: core, SafeFacts: facts, Intent: intent, CompletionClass: a.record.CompletionClass}
	switch a.expected.Template.ResultReaderIdentity() {
	case contract.GeneratorResultReaderID():
		createEvidence.Schema, createEvidence.LifecycleMode = contract.GeneratedCreateEvidenceSchema, a.expected.Template.SemanticLifecycleMode()
	default:
		t.Fatal("detached handoff original result reader is unsupported")
	}
	body, err := contract.EncodeGeneratedCreateEvidence(createEvidence)
	if err != nil {
		t.Fatal(err)
	}
	evidence := contract.SupportRecord{Kind: 13, RecordID: a.record.ResultID, Body: body}
	h.OriginalResults, err = contract.GeneratorRecordSetDescriptor(contract.GeneratorHazardResults, h.DomainID, []contract.SupportRecord{evidence})
	if err != nil {
		t.Fatal(err)
	}
	var retained, consumers []contract.SupportRecord
	var consumerBodies [][]byte
	for _, row := range s.supportRecords() {
		if row.Kind == 6 || row.Kind == 13 {
			retained = append(retained, row)
		}
		if row.Kind != contract.GeneratorVectorSupportKind {
			continue
		}
		v, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			t.Fatal(err)
		}
		ownedByHazard := v.OwnerKind == 11 && v.OwnerID == h.HazardID
		ownedSupport := v.OwnerKind == 2 && v.OwnerID == h.OriginalOperationID && v.VectorKind == contract.GeneratorVectorSupport
		if !ownedByHazard && !ownedSupport {
			continue
		}
		if ownedByHazard && v.VectorKind == contract.GeneratorVectorConsumers {
			consumer, err := contract.InspectGeneratorConsumer(v.Row)
			if err != nil {
				t.Fatal(err)
			}
			if consumer.SubjectKind == 2 {
				consumerBodies = append(consumerBodies, v.Row)
			}
		} else {
			retained = append(retained, row)
		}
	}
	h.Consumers, consumers = generatedVectorRowsForDomain(t, h.DomainID, 11, h.HazardID, contract.GeneratorVectorConsumers, consumerBodies)
	retained = append(retained, consumers...)
	retained = append(retained, evidence)
	body, err = contract.EncodeGeneratedHazardRecord(h)
	if err != nil {
		t.Fatal(err)
	}
	retained = append(retained, contract.SupportRecord{Kind: 11, RecordID: h.HazardID, Body: body})
	owners := []contract.ID{h.HazardID}
	content := generatedContentStateForDomainAtSnapshot(t, s.root.Domain, snapshot, blobs, locations)
	s.root.Snapshot = snapshot
	s.root.Generated = content.root.Generated
	s.root.Generated.Hazards = 1
	if releaseState != 0 {
		a.record.Facts = contract.EmptyGeneratorVector(contract.GeneratorVectorFacts)
		body, err = contract.EncodeGeneratedAttemptRecord(a.record)
		if err != nil {
			t.Fatal(err)
		}
		retained = append(retained, contract.SupportRecord{Kind: 9, RecordID: a.record.AttemptID, Body: body})
		body, err = contract.EncodePendingInboxReleaseRecord(contract.PendingInboxReleaseRecord{Schema: 1, DomainID: h.DomainID,
			InboxID: a.record.InboxID, OriginalResultID: a.record.ResultID, SelectedHandoffDigest: contract.Hash(a.result),
			HandoffRevisionID: generatedVectorID(96), CapacityReservation: h.CapacityReservation, ObjectLength: uint32(len(a.result)), State: releaseState})
		if err != nil {
			t.Fatal(err)
		}
		retained = append(retained, contract.SupportRecord{Kind: 12, RecordID: a.record.InboxID, Body: body})
		s.root.Generated.Attempts, s.root.Generated.PendingReleases = 1, 1
		s.root.Generated.Graphs, err = contract.GeneratorIndexDescriptor(contract.GeneratorGraphSet, []contract.ID{a.expected.Plan.PlanGraphID})
		if err != nil {
			t.Fatal(err)
		}
		owners = append(owners, a.record.InboxID)
	}
	slices.SortFunc(owners, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	s.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, owners)
	if err != nil {
		t.Fatal(err)
	}
	s.support = content.support
	page := format.RequiredSupportPageView{Domain: h.DomainID, Object: generatedVectorID(95), Index: uint16(len(s.support))}
	for _, row := range retained {
		page.Records = append(page.Records, contract.SupportRecordView(row))
	}
	s.support = append(s.support, page)
	generatedRepackSupportAtLocations(t, s, s.supportRecords(), g.bundles, locations)
	s.root.AccessRecordCount = 0
	for _, page := range s.access {
		if page != nil {
			page.Records = slices.DeleteFunc(page.Records, func(row contract.AccessRecord) bool { return row.MaterialKind == 3 })
			s.root.AccessRecordCount += uint32(len(page.Records))
		}
	}
	generatedCommitFixtureAccess(t, s)
	if !s.indexSelectedMaterials() {
		t.Fatal("detached Hazard access index")
	}
	return s
}

// full_only: false
func TestGeneratedDetachedHazardHandoffKeepsOnlyActualConsumers(t *testing.T) {
	for mode := uint8(0); mode < 3; mode++ {
		for _, release := range []uint8{0, contract.GeneratedReleaseUnknown} {
			for _, disposition := range []uint8{1, 2} {
				t.Run(fmt.Sprintf("source%d/release%d/result%d", mode, release, disposition), func(t *testing.T) {
					s, a, h := generatedCreateHazardState(t, mode, disposition)
					s = generatedHazardEvidenceHandoff(t, s, a, h, release)
					g, err := s.selectedGeneratedWork(context.Background())
					if err != nil {
						t.Fatal("qualified create-evidence handoff refused", err)
					}
					graphs, materials := 0, 0
					if release != 0 {
						graphs = 1
					}
					if mode == 2 {
						materials = 1
						if len(g.canonical) != 1 {
							t.Fatal("handoff dropped a live canonical consumer")
						}
					}
					if len(g.bundles) != graphs || len(g.materials) != materials || len(g.attempts) != 0 ||
						len(g.sources) != 0 || len(g.protected) != 0 {
						t.Fatal("handoff lost exact readers or restored completed private work")
					}
					if _, coverageErr := s.validateGeneratedCoverage(t.Context(), s.generatedCoverageRecords()); coverageErr != nil {
						t.Fatal("handoff lost exact readers or restored completed private work")
					}
					for _, consumers := range g.consumers {
						for _, consumer := range consumers {
							if consumer.OwnerID != h.HazardID || consumer.SubjectKind != 2 || consumer.Purpose != 2 {
								t.Fatal("handoff retained or restored original-result adoption")
							}
						}
					}
					coverage, err := s.replacementMaterialRows(t.Context(), 0, 1, contract.BindingTableRow{SubjectKind: 1, SubjectID: s.admission.recipient, Binding: generatedPublicBinding(t, 94)})
					if err != nil || len(coverage) != materials {
						t.Fatal("replacement lost a current consumer or retained a discarded seed")
					}
				})
			}
		}
	}
}

// full_only: false
func TestGeneratedDetachedHazardCannotRestoreOriginalCiphertext(t *testing.T) {
	s, a, h := generatedCreateHazardState(t, 0, 1)
	s = generatedHazardEvidenceHandoff(t, s, a, h, 0)
	s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records,
		contract.SupportRecordView{Kind: 4, RecordID: a.record.ResultID, Body: a.result})
	s.root.Generated.Results++
	// The duplicate has no authentic owner. Check the generated-work relation
	// directly, since the administrative index writer must also reject it.
	s.generatedWork = nil
	if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
		t.Fatal("detached evidence and original ciphertext represented the same result twice")
	}
}

// full_only: false
func TestGeneratedReservationPreservesHazardWithPendingRelease(t *testing.T) {
	before := generatedEmptyPredecessor(t)
	reserved, err := before.deriveGeneratedReservation(context.Background(), generatedReservationInputFixture(t, before))
	if err != nil {
		t.Fatal(err)
	}
	s, a := generatedUnselectedCleanupFromReservation(t, reserved.state)
	s, a, h := generatedCreateHazardFromCleanup(t, s, a, 1)
	s = generatedHazardEvidenceHandoff(t, s, a, h, contract.GeneratedReleaseUnknown)
	s.access = [contract.MaxChildPages]*format.AccessPage{}
	s.root.CurrentAccess.Core.AccessPageRefs = nil
	s.root.CurrentAccess.Core.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(s.root.Domain, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(s.root.CurrentAccess.Core)
	if err != nil {
		t.Fatal(err)
	}
	s.recountChildren()
	prior, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal("invalid Hazard/release predecessor", err)
	}
	if _, relationErr := s.validateRelationsMode(t.Context(), false); relationErr != nil {
		t.Fatal("invalid Hazard/release predecessor", err)
	}
	reservation, err := s.deriveGeneratedReservation(context.Background(), generatedReservationInputForOperation(t, s, generatedVectorID(98)))
	if err != nil {
		t.Fatal("new reservation lost Hazard/release dependencies", err)
	}
	g, err := reservation.state.selectedGeneratedWork(context.Background())
	if err != nil || len(g.attempts) != 1 || len(g.bundles) != 2 || len(g.materials) != 1 ||
		g.phase.Hazards.Count != 0 || g.phase.PendingReleases.Count != 0 || reservation.state.validateGeneratedSelection(t.Context(), nil) != nil {
		t.Fatal("new reservation restored old adoption or selected old work in its phase", err)
	}
	for _, key := range []generatedRecordKey{{9, a.record.AttemptID}, {11, h.HazardID}, {12, a.record.InboxID}, {13, a.record.ResultID}} {
		if !g.hasRecord(key) || !bytes.Equal(g.records[key].Body, prior.records[key].Body) {
			t.Fatal("new reservation changed original evidence or release", key.kind)
		}
	}
}

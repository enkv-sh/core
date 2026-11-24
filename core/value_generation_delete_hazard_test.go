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

func generatedDeleteHazardState(t testing.TB, resultKind uint8) (*StateSession, generatedAttempt, contract.GeneratedHazardRecord, contract.GeneratorTarget) {
	return generatedDeleteHazardForOperation(t, generatedVectorID(99), resultKind)
}

// full_only: false
func TestGeneratedHazardResultsDescriptorOrdersRecordedResults(t *testing.T) {
	s, attempts, _ := generatedRepeatedRetirementState(t, 1)
	results := make([]contract.SupportRecord, 0, len(attempts))
	for _, attempt := range attempts {
		results = append(results, contract.SupportRecord{Kind: 4, RecordID: attempt.record.ResultID,
			Body: generatedRetirementResultFixture(t, s, attempt, contract.GeneratorDispositionRetirementAcknowledged)})
	}
	slices.SortFunc(results, func(a, b contract.SupportRecord) int { return -bytes.Compare(a.RecordID[:], b.RecordID[:]) })
	descriptor, err := generatedHazardResultsDescriptor(s.root.Domain, results)
	if err != nil || bytes.Compare(results[0].RecordID[:], results[1].RecordID[:]) >= 0 {
		t.Fatal("hazard results did not acquire canonical RecordID order", err)
	}
	want, err := contract.GeneratorRecordSetDescriptor(contract.GeneratorHazardResults, s.root.Domain, results)
	if err != nil || descriptor != want {
		t.Fatal("hazard results descriptor differs after canonical ordering", err)
	}
}

// full_only: false
func TestGeneratedRepeatedDeleteHazardRefusesLostOrChangedOriginalRelations(t *testing.T) {
	for _, damage := range []string{"missing Attempt", "missing material", "missing consumer", "broken fresh edge", "linked own frontier", "changed class"} {
		t.Run(damage, func(t *testing.T) {
			s, g, h := generatedRepeatedRetirementHazardState(t, 2)
			bodies, err := g.vectors.resolve(11, h.HazardID, contract.GeneratorVectorHistory, h.History)
			if err != nil {
				t.Fatal(err)
			}
			var history []contract.GeneratorHistory
			for _, body := range bodies {
				row, err := contract.InspectGeneratorHistory(body)
				if err != nil {
					t.Fatal(err)
				}
				history = append(history, row)
			}
			original := g.attempts[history[0].PredecessorAttemptID]
			switch damage {
			case "broken fresh edge", "linked own frontier":
				kind, owner := uint8(11), h.HazardID
				changed := history[0]
				if damage == "broken fresh edge" {
					changed.NextAttemptID = h.OriginalAttemptID
				} else {
					kind, owner = 9, original.record.AttemptID
				}
				body, err := contract.EncodeGeneratorHistory(changed)
				if err != nil {
					t.Fatal(err)
				}
				for _, page := range s.support {
					for i, row := range page.Records {
						if row.Kind != contract.GeneratorVectorSupportKind {
							continue
						}
						carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
						if err != nil {
							t.Fatal(err)
						}
						if carrier.OwnerKind == kind && carrier.OwnerID == owner && carrier.VectorKind == contract.GeneratorVectorHistory && carrier.Ordinal == 0 {
							carrier.Row = body
							page.Records[i].Body, err = contract.EncodeGeneratorVectorCarrier(carrier)
							if err != nil {
								t.Fatal(err)
							}
						}
					}
				}
			case "changed class":
				original.record.CompletionClass = contract.GeneratedCompletionConfirmed
				body, err := contract.EncodeGeneratedAttemptRecord(original.record)
				if err != nil {
					t.Fatal(err)
				}
				generatedReplaceRecord(t, s, 9, original.record.AttemptID, body)
			default:
				for _, page := range s.support {
					page.Records = slices.DeleteFunc(page.Records, func(row contract.SupportRecordView) bool {
						if damage == "missing Attempt" {
							return row.Kind == 9 && row.RecordID == original.record.AttemptID
						}
						if damage == "missing material" {
							return row.Kind == 1 && row.RecordID == original.material.Core.OperationMaterialID
						}
						if row.Kind != contract.GeneratorVectorSupportKind {
							return false
						}
						carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
						if err != nil {
							t.Fatal(err)
						}
						if carrier.OwnerKind != 11 || carrier.OwnerID != h.HazardID || carrier.VectorKind != contract.GeneratorVectorConsumers {
							return false
						}
						consumer, err := contract.InspectGeneratorConsumer(carrier.Row)
						if err != nil {
							t.Fatal(err)
						}
						return consumer.SubjectID == original.record.ResultID
					})
				}
			}
			if _, err := s.selectedGeneratedWork(stdcontext.Background()); err == nil {
				t.Fatal("cold selection accepted damaged original ownership", damage)
			}
		})
	}
}

func generatedDeleteHazardForOperation(t testing.TB, operation contract.ID, resultKind uint8, completion ...uint8) (*StateSession, generatedAttempt, contract.GeneratedHazardRecord, contract.GeneratorTarget) {
	t.Helper()
	s, original, duty, target := generatedEnteredRetirementForOperation(t, operation, resultKind == 2, completion...)
	g, err := s.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	a := g.attempts[original.record.AttemptID]
	empty := contract.EmptyGeneratorVector
	h := contract.GeneratedHazardRecord{Schema: contract.GeneratedHazardRecordSchema, DomainID: a.record.DomainID, HazardID: a.expected.Template.HazardID,
		OriginalOperationID: a.record.OperationID, OriginalAttemptID: a.record.AttemptID, OwnerID: duty.DutyID,
		ResourceID: duty.ResourceID, ConfigContractID: duty.ConfigContractID, ResourceContractID: duty.ResourceContractID, ExecutorID: duty.ExecutorID,
		CredentialRouteID: duty.CredentialRouteID, DescriptorID: duty.DescriptorID, ResultContractID: duty.ResultContractID, CapacityReservation: duty.CapacityReservation,
		Exposure: contract.GeneratedExposurePossibleLive, CompletionClass: duty.CompletionClass, Fenced: 1,
		Eligibility: contract.GeneratedExposurePossibleLive, Support: duty.Support, History: empty(contract.GeneratorVectorHistory),
		OriginalResults: contract.EmptyGeneratorRecordSet(contract.GeneratorHazardResults)}
	a.record.State, a.record.Stage = contract.GeneratedEffectClosedWithResidue, contract.GeneratedStageTerminal
	var added []contract.SupportRecord
	var carriers []contract.SupportRecord
	targetBody, err := contract.EncodeGeneratorTarget(target)
	if err != nil {
		t.Fatal(err)
	}
	h.Target, carriers = generatedVectorRows(t, 11, h.HazardID, contract.GeneratorVectorTargets, [][]byte{targetBody})
	added = append(added, carriers...)
	context, err := contract.GeneratorResultUseDigest(a.expected.Use)
	if err != nil {
		t.Fatal(err)
	}
	body, err := contract.EncodeGeneratorConsumer(contract.GeneratorConsumer{Schema: 1, OwnerID: h.HazardID, MaterialID: a.material.Core.OperationMaterialID,
		ContextDigest: context, SubjectKind: 3, SubjectID: a.record.ResultID, Purpose: 4})
	if err != nil {
		t.Fatal(err)
	}
	h.Consumers, carriers = generatedVectorRows(t, 11, h.HazardID, contract.GeneratorVectorConsumers, [][]byte{body})
	added = append(added, carriers...)
	if resultKind == 1 {
		facts, err := contract.EncodeGeneratorSafeFacts(generatedRetirementFactsFixture(t, s, a, contract.GeneratorDispositionUnknown))
		if err != nil {
			t.Fatal(err)
		}
		body, err := contract.EncodeGeneratorFactsRow(contract.GeneratorFactsRow{Schema: 1, ResultID: a.record.ResultID, Facts: facts})
		if err != nil {
			t.Fatal(err)
		}
		a.record.Facts, carriers = generatedVectorRows(t, 9, a.record.AttemptID, contract.GeneratorVectorFacts, [][]byte{body})
		added = append(added, carriers...)
	}
	history := contract.GeneratorHistory{Schema: 1, PredecessorAttemptID: a.record.AttemptID, OwnerID: duty.DutyID, Outcome: a.record.State}
	if resultKind == 2 {
		h.OriginalResults, err = contract.GeneratorRecordSetDescriptor(contract.GeneratorHazardResults, s.root.Domain, []contract.SupportRecord{g.records[generatedRecordKey{4, a.record.ResultID}]})
		if err != nil {
			t.Fatal(err)
		}
		history.ResultID, history.ResultDigest = a.record.ResultID, contract.Hash(a.result)
	}
	body, err = contract.EncodeGeneratorHistory(history)
	if err != nil {
		t.Fatal(err)
	}
	a.record.History, carriers = generatedVectorRows(t, 9, a.record.AttemptID, contract.GeneratorVectorHistory, [][]byte{body})
	added = append(added, carriers...)
	h.History, carriers = generatedVectorRows(t, 11, h.HazardID, contract.GeneratorVectorHistory, [][]byte{body})
	added = append(added, carriers...)
	body, err = contract.EncodeGeneratedAttemptRecord(a.record)
	if err != nil {
		t.Fatal(err)
	}
	added = append(added, contract.SupportRecord{Kind: 9, RecordID: a.record.AttemptID, Body: body})
	body, err = contract.EncodeGeneratedHazardRecord(h)
	if err != nil {
		t.Fatal(err)
	}
	added = append(added, contract.SupportRecord{Kind: 11, RecordID: h.HazardID, Body: body})
	var locations []contract.GeneratorSliceLocation
	var blobs []generatedContentFixtureBlob
	for _, key := range []generatedContentKey{{contract.GeneratorContentGraph, g.parent.PlanGraphID}, {contract.GeneratorContentIntent, a.expected.Template.IntentDigest}} {
		location := g.content.locations[key]
		body, err := g.readSelectedSlice(t.Context(), key.kind, key.id, location.Length)
		if err != nil {
			t.Fatal(err)
		}
		location.BlobID, location.Offset = contract.Hash(body), 0
		locations = append(locations, location)
		blobs = append(blobs, generatedContentFixtureBlob{location.BlobID, body})
	}
	rows := s.supportRecords()
	content := generatedContentStateAtSnapshot(t, s.root.Snapshot, blobs, locations)
	s.support = content.support
	s.root.Generated.Fragments, s.root.Generated.Slices = content.root.Generated.Fragments, content.root.Generated.Slices
	s.root.Generated.ActiveOwner, s.root.Generated.ActivePhase, s.root.Generated.ActiveGraph = contract.ID{}, contract.ID{}, contract.ID{}
	s.root.Generated.Duties, s.root.Generated.Retiring, s.root.Generated.Hazards = 0, 0, 1
	s.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, []contract.ID{h.HazardID})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Kind == 2 || row.Kind == 3 || row.Kind == 5 || row.Kind == 9 || row.Kind == 10 {
			continue
		}
		if row.Kind == contract.GeneratorVectorSupportKind {
			v, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			if v.OwnerKind == 10 || v.OwnerKind == contract.GeneratorSnapshotOwner || v.OwnerKind == 9 && v.VectorKind == contract.GeneratorVectorHistory {
				continue
			}
		}
		added = append(added, row)
	}
	for _, row := range added {
		s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
	}
	generatedRepackSupport(t, s, s.supportRecords(), g.bundles)
	return s, a, h, target
}

// full_only: false
func TestGeneratedDeleteHazardKeepsOriginalDeleteAndCreateEvidence(t *testing.T) {
	for resultKind := uint8(0); resultKind < 3; resultKind++ {
		t.Run(fmt.Sprint(resultKind), func(t *testing.T) {
			s, a, h, target := generatedDeleteHazardState(t, resultKind)
			g, err := s.selectedGeneratedWork(stdcontext.Background())
			if err != nil {
				t.Fatal("exact delete Hazard refused", err)
			}
			actual := g.attempts[a.record.AttemptID]
			if g.parent != nil || g.phase != nil || len(g.attempts) != 1 || len(g.bundles) != 1 || actual.record != a.record ||
				actual.expected != a.expected || !bytes.Equal(actual.result, a.result) || !g.hasRecord(generatedRecordKey{11, h.HazardID}) ||
				h.OriginalAttemptID == target.OriginalAttemptID || h.ResultContractID == target.ResultContractID ||
				s.root.Generated.Retiring != 0 || s.root.Generated.Duties != 0 {
				t.Fatal("delete Hazard lost its exact original delete or adopted the create result")
			}
			if _, coverageErr := s.validateGeneratedCoverage(t.Context(), s.access[0].Records); coverageErr != nil {
				t.Fatal("delete Hazard lost its exact original delete or adopted the create result")
			}
			consumers := g.consumers[materialIdentity{3, a.material.Core.OperationMaterialID}]
			if len(consumers) != 1 || consumers[0].OwnerID != h.HazardID || consumers[0].SubjectID != a.record.ResultID || consumers[0].Purpose != 4 {
				t.Fatal("delete Hazard lost its late-result reader or acquired selection rights")
			}
			generatedRepackSupport(t, s, s.supportRecords(), g.bundles)
			if _, err := s.selectedGeneratedWork(stdcontext.Background()); err != nil {
				t.Fatal("packed delete Hazard lost required support", err)
			}
		})
	}
}

// full_only: false
func TestGeneratedDeleteHazardRejectsChangedOwnerAndTarget(t *testing.T) {
	for name, damage := range map[string]func(*contract.GeneratedHazardRecord, *contract.GeneratorTarget){
		"owner": func(h *contract.GeneratedHazardRecord, _ *contract.GeneratorTarget) {
			h.OwnerID = generatedVectorID(96)
		},
		"original operation": func(h *contract.GeneratedHazardRecord, _ *contract.GeneratorTarget) {
			h.OriginalOperationID = generatedVectorID(96)
		},
		"original attempt": func(h *contract.GeneratedHazardRecord, _ *contract.GeneratorTarget) {
			h.OriginalAttemptID = generatedVectorID(96)
		},
		"create contract substituted": func(h *contract.GeneratedHazardRecord, target *contract.GeneratorTarget) {
			h.ResultContractID = target.ResultContractID
		},
		"delete contract substituted": func(h *contract.GeneratedHazardRecord, target *contract.GeneratorTarget) {
			target.ResultContractID = h.ResultContractID
		},
		"create pair substituted": func(h *contract.GeneratedHazardRecord, target *contract.GeneratorTarget) {
			h.OriginalOperationID, h.OriginalAttemptID = target.OriginalOperationID, target.OriginalAttemptID
		},
		"delete pair substituted": func(h *contract.GeneratedHazardRecord, target *contract.GeneratorTarget) {
			target.OriginalOperationID, target.OriginalAttemptID = h.OriginalOperationID, h.OriginalAttemptID
		},
		"token": func(_ *contract.GeneratedHazardRecord, target *contract.GeneratorTarget) {
			target.ResourceDigest = generatedVectorID(96)
		},
		"resource": func(h *contract.GeneratedHazardRecord, target *contract.GeneratorTarget) {
			h.ResourceID, target.ResourceID = generatedVectorID(96), generatedVectorID(96)
		},
		"unfenced": func(h *contract.GeneratedHazardRecord, _ *contract.GeneratorTarget) { h.Fenced = 0 },
		"late effect": func(h *contract.GeneratedHazardRecord, _ *contract.GeneratorTarget) {
			h.Exposure, h.Eligibility = contract.GeneratedExposureLateEffect, contract.GeneratedExposureLateEffect
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, _, h, target := generatedDeleteHazardState(t, 0)
			damage(&h, &target)
			generatedReplaceDetachedHazard(t, s, h, target, false)
			if _, err := s.selectedGeneratedWork(stdcontext.Background()); err == nil {
				t.Fatal("delete Hazard changed its owner, exposure or original target")
			}
		})
	}
}

// full_only: false
func TestGeneratedDeleteHazardRequiresOriginalAttemptAndMaterial(t *testing.T) {
	for _, missing := range []uint8{9, 1} {
		t.Run(fmt.Sprint(missing), func(t *testing.T) {
			s, _, _, _ := generatedDeleteHazardState(t, 0)
			if _, err := s.selectedGeneratedWork(stdcontext.Background()); err != nil {
				t.Fatal("starting delete hazard fixture is invalid", err)
			}
			for i := range s.support {
				s.support[i].Records = slices.DeleteFunc(s.support[i].Records, func(row contract.SupportRecordView) bool { return row.Kind == missing })
			}
			s.root.RequiredSupportRecordCount = 0
			for _, page := range s.support {
				s.root.RequiredSupportRecordCount += uint32(len(page.Records))
			}
			if missing == 9 {
				s.root.Generated.Attempts = 0
			} else {
				s.root.Generated.Materials = 0
			}
			s.root.RequiredSupport = nil
			var pages []format.RequiredSupportPageView
			for _, page := range s.support {
				if len(page.Records) == 0 {
					continue
				}
				rows := make([]contract.SupportRecord, len(page.Records))
				for i, row := range page.Records {
					rows[i] = contract.SupportRecord(row)
				}
				body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: rows})
				if err != nil {
					t.Fatal("encode missing-dependency support", err)
				}
				ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
				if err != nil {
					t.Fatal(err)
				}
				s.root.RequiredSupport = append(s.root.RequiredSupport, ref)
				pages = append(pages, page)
			}
			s.support = pages
			s.recountChildren()
			generatedInstallFixtureSupportReader(t, s)
			s.generatedWork = nil
			if _, err := s.supportDescriptor(); err != nil {
				t.Fatal("missing original support fixture is structurally invalid", err)
			}
			if _, err := s.selectedGeneratedWork(stdcontext.Background()); err == nil {
				t.Fatal("create evidence replaced the still-adoptable delete result")
			}
		})
	}
}

// full_only: false
func TestGeneratedDeleteHazardDoesNotUseCreateEvidenceAsOriginalResult(t *testing.T) {
	s, _, h, target := generatedDeleteHazardState(t, 0)
	var evidence contract.SupportRecord
	for _, row := range s.supportRecords() {
		if row.Kind == 13 {
			evidence = row
		}
	}
	var err error
	h.OriginalResults, err = contract.GeneratorRecordSetDescriptor(contract.GeneratorHazardResults, s.root.Domain, []contract.SupportRecord{evidence})
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceDetachedHazard(t, s, h, target, false)
	if _, err := s.selectedGeneratedWork(stdcontext.Background()); err == nil {
		t.Fatal("create acknowledgement became delete closure evidence")
	}
}

// full_only: false
func TestGeneratedDeleteHazardRetainsContradictionWithoutCleanupEligibility(t *testing.T) {
	for _, conflict := range []string{"identity reason", "different token"} {
		t.Run(conflict, func(t *testing.T) {
			ctx := t.Context()
			s, original, h, target := generatedDeleteHazardState(t, 0)
			selected := mustSelectedGeneratedWork(t, s)
			source, err := contract.InspectGeneratedDeleteSource(selected.records[generatedRecordKey{contract.GeneratedHazardSupportKind, h.HazardID}])
			if err != nil {
				t.Fatal(err)
			}
			reservation, err := s.deriveGeneratedReservation(ctx, generatedOrdinaryCleanupReservationInput(t, s, source, generatedVectorID(178)))
			if err != nil {
				t.Fatal(err)
			}
			active := reservation.state
			work := mustSelectedGeneratedWork(t, active)
			attempt := work.attempts[work.phase.FrontierAttemptID]
			facts := generatedRetirementFactsFixture(t, active, attempt, contract.GeneratorDispositionUnknown)
			encode := contract.EncodeGeneratorSafeFacts
			if conflict == "identity reason" {
				facts.Reason = contract.GeneratorReasonIdentityConflict
			} else {
				facts.Target, facts.ResourceData = []byte("fixture-target"), bytes.Repeat([]byte{96}, 32)
				encode = contract.EncodeRejectedRetirement
			}
			body, err := encode(facts)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := active.generatedOrdinaryCleanupAmbiguityPlan(ctx, attempt.record.AttemptID, body, generatedLifecycleFixture(t, active))
			if err != nil {
				t.Fatal(err)
			}
			parked, err := active.deriveGeneratedOrdinaryCleanupAmbiguity(ctx, plan)
			if err != nil {
				t.Fatal(err)
			}
			state := parked.state
			closed := mustSelectedGeneratedWork(t, state)
			retained, err := contract.InspectGeneratedDeleteSource(closed.records[generatedRecordKey{contract.GeneratedHazardSupportKind, h.HazardID}])
			current := closed.attempts[attempt.record.AttemptID]
			if err != nil || retained.Hazard.Eligibility != 0 || retained.Hazard.Fenced != 1 ||
				closed.attempts[original.record.AttemptID].record.State != contract.GeneratedEffectClosedWithResidue ||
				current.record.State != contract.GeneratedEffectUnknown || current.record.Stage != contract.GeneratedStageTerminal || len(current.result) != 0 {
				t.Fatal("contradictory observation lost the original hazard or admitted cleanup", err)
			}
			rows, err := closed.vectors.resolve(contract.GeneratedAttemptSupportKind, attempt.record.AttemptID, contract.GeneratorVectorFacts, current.record.Facts)
			if err != nil || len(rows) != 1 {
				t.Fatal("missing contradiction facts", err)
			}
			row, err := contract.InspectGeneratorFactsRow(rows[0])
			if err != nil || row.ResultID != attempt.record.ResultID || !bytes.Equal(row.Facts, body) {
				t.Fatal("contradiction facts changed", err)
			}
			damaged := retained.Hazard
			damaged.Eligibility = contract.GeneratedExposurePossibleLive
			generatedReplaceDetachedHazard(t, state, damaged, target, false)
			if _, err := state.selectedGeneratedWork(ctx); err == nil {
				t.Fatal("changed hazard eligibility accepted")
			}
		})
	}
}

// full_only: false
func TestGeneratedCleanupRecordsAndParksContradictoryProbe(t *testing.T) {
	for _, deleteOrigin := range []bool{false, true} {
		for _, disposition := range []uint8{contract.GeneratorDispositionContinuedUsability, contract.GeneratorDispositionConflictingBinding} {
			t.Run(fmt.Sprintf("delete-origin=%t/disposition=%d", deleteOrigin, disposition), func(t *testing.T) {
				var s *StateSession
				var source contract.GeneratedDeleteSource
				if deleteOrigin {
					var hazard contract.GeneratedHazardRecord
					s, _, hazard, _ = generatedDeleteHazardForOperation(t, generatedVectorID(177), 1, contract.GeneratedCompletionConfirmed)
					selected := mustSelectedGeneratedWork(t, s)
					var err error
					source, err = contract.InspectGeneratedDeleteSource(selected.records[generatedRecordKey{contract.GeneratedHazardSupportKind, hazard.HazardID}])
					if err != nil {
						t.Fatal(err)
					}
				} else {
					s, source = generatedOrdinaryCleanupSourceState(t, contract.GeneratedCompletionConfirmed, true)
				}
				originalTarget, originalClass := source.Target, source.CompletionClass
				reserved, err := s.deriveGeneratedReservation(t.Context(), generatedOrdinaryCleanupReservationInput(t, s, source, generatedVectorID(178)))
				if err != nil {
					t.Fatal("reserve first cleanup acknowledgement", err)
				}
				s = reserved.state
				selected := mustSelectedGeneratedWork(t, s)
				ack := selected.attempts[selected.phase.FrontierAttemptID]
				ackPacket := generatedRetirementResultFixture(t, s, ack, contract.GeneratorDispositionRetirementAcknowledged)
				record, err := s.generatedRecordRequest(t.Context(), ack.record.AttemptID, ackPacket, generatedLifecycleFixture(t, s))
				if err != nil {
					t.Fatal("admit first cleanup acknowledgement", err)
				}
				recorded, err := s.deriveGeneratedRecord(t.Context(), record)
				if err != nil {
					t.Fatal("record first cleanup acknowledgement", err)
				}
				s = recorded.state
				closePlan, err := s.generatedOrdinaryCleanupClosePlan(t.Context(), ack.record.AttemptID, generatedLifecycleFixture(t, s))
				if err != nil {
					t.Fatal("plan unfinished acknowledgement parking", err)
				}
				parked, err := s.deriveGeneratedCleanupClose(t.Context(), closePlan)
				if err != nil {
					t.Fatal("park first acknowledgement", err)
				}
				s = parked.state
				selected = mustSelectedGeneratedWork(t, s)
				source, err = selected.generatedDeleteSource(source.OwnerID)
				if err != nil {
					t.Fatal(err)
				}
				input := generatedOrdinaryCleanupReservationInput(t, s, source, generatedVectorID(179))
				x := input.graph.Lineages[0].Templates[0]
				scope := contract.GeneratorControlledRetirementScope(x.DescriptorID, x.ConfigContractID, x.ResultContractID)
				request := contract.GeneratorControlledRetirementProbeDigest(s.root.Domain, source.ResourceID, ack.expected.TargetResourceDigest, scope, ack.record.ResultID, contract.Hash(ackPacket))
				input.requestBindings = generatedFixtureRequestBindings(input.graph, request)
				reserved, err = s.deriveGeneratedReservation(t.Context(), input)
				if err != nil {
					t.Fatal("reserve remaining exact scoped probe", err)
				}
				s = reserved.state
				selected = mustSelectedGeneratedWork(t, s)
				probe := selected.attempts[selected.phase.FrontierAttemptID]
				packet, err := contract.DecodeGeneratedResultRecord(generatedHistoricalAckConfirmationFixture(t, s, probe, ack.record.ResultID, contract.Hash(ackPacket)))
				if err != nil {
					t.Fatal(err)
				}
				packet.SafeFacts.Disposition = disposition
				if disposition == contract.GeneratorDispositionConflictingBinding {
					packet.SafeFacts.ObservedResourceDigest = generatedVectorID(176)
				}
				packet.Core, err = contract.ExpectedGeneratedResultCore(probe.expected, probe.material, packet.SafeFacts)
				if err != nil {
					t.Fatal(err)
				}
				packet.Transfer.Core.ResultCoreDigest, err = contract.GeneratedResultCoreDigest(packet.Core)
				if err != nil {
					t.Fatal(err)
				}
				probePacket, err := contract.EncodeGeneratedResultRecord(packet)
				if err != nil {
					t.Fatal(err)
				}
				beforeReceipts := generatedReceiptRows(s)
				record, err = s.generatedRecordRequest(t.Context(), probe.record.AttemptID, probePacket, generatedLifecycleFixture(t, s))
				if err != nil {
					t.Fatal("admit qualified contradictory observation", err)
				}
				recorded, err = s.deriveGeneratedRecord(t.Context(), record)
				if err != nil {
					t.Fatal("record qualified contradiction before parking", err)
				}
				s = recorded.state
				if err := s.validateGeneratedSelection(t.Context(), nil); err != nil {
					t.Fatal("contradictory record candidate is not a valid selected state", err)
				}
				s.generatedWork = nil
				selected = mustSelectedGeneratedWork(t, s)
				source, err = selected.generatedDeleteSource(source.OwnerID)
				if err != nil || source.Hazard.Eligibility != 0 || source.Target != originalTarget || source.CompletionClass != originalClass ||
					selected.attempts[probe.record.AttemptID].record.State != contract.GeneratedEffectFailedTerminal ||
					!bytes.Equal(selected.attempts[probe.record.AttemptID].result, probePacket) || !bytes.Equal(selected.attempts[ack.record.AttemptID].result, ackPacket) || len(selected.releases) != 0 {
					t.Fatal("record lost contradiction, fixed source or required acknowledgement", err)
				}
				closePlan, err = s.generatedOrdinaryCleanupClosePlan(t.Context(), probe.record.AttemptID, generatedLifecycleFixture(t, s))
				if err != nil {
					t.Fatal("plan effect-free contradictory cleanup parking", err)
				}
				parked, err = s.deriveGeneratedCleanupClose(t.Context(), closePlan)
				if err != nil {
					t.Fatal("park contradicted unfinished cleanup", err)
				}
				s = parked.state
				s.generatedWork = nil
				selected = mustSelectedGeneratedWork(t, s)
				source, err = selected.generatedDeleteSource(source.OwnerID)
				if err != nil || source.Hazard.Eligibility != 0 || source.Target != originalTarget || source.CompletionClass != originalClass ||
					!bytes.Equal(selected.attempts[probe.record.AttemptID].result, probePacket) || !bytes.Equal(selected.attempts[ack.record.AttemptID].result, ackPacket) {
					t.Fatal("cold parked cleanup lost its contradiction or exact source", err)
				}
				if selected.parent != nil || selected.phase != nil || len(selected.releases) != 0 || !slices.EqualFunc(generatedReceiptRows(s), beforeReceipts, func(a, b contract.SupportRecord) bool {
					return a.Kind == b.Kind && a.RecordID == b.RecordID && bytes.Equal(a.Body, b.Body)
				}) {
					t.Fatal("contradictory cleanup retained active ownership or created a terminal receipt/release")
				}
				progress, err := selected.controlledDeleteSourceProgress(source, nil, true)
				if err != nil || !progress.contradiction || len(progress.rows) != 1 {
					t.Fatal("parked contradiction became completed evidence", err)
				}
				selection, admitted, err := selected.selectGeneratedCleanup(t.Context(), nil)
				if err != nil && err != contract.ErrRecord || err == nil && admitted && selection.kind != generatedCleanupReflection {
					t.Fatal("parked contradictory source regained destructive cleanup eligibility or failed unrelated validation", err)
				}
				if _, admitted, err := s.generatedDeleteReservationSelection(t.Context(), input.graph, selected); err != nil || admitted {
					t.Fatal("noneligible source admitted a fresh destructive reservation", admitted, err)
				}
			})
		}
	}
}

// full_only: false
func TestGeneratedDeleteHazardCannotRetainCanonicalValueConsumer(t *testing.T) {
	s, _, h, _ := generatedDeleteHazardState(t, 0)
	g, err := s.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, retained := generatedCanonicalSource(t)
	retained.Entry.Recipients = []contract.ID{s.admission.recipient}
	body, err := contract.EncodeRetainedCanonicalRecord(retained)
	if err != nil {
		t.Fatal(err)
	}
	s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records,
		contract.SupportRecordView{Kind: 6, RecordID: retained.Entry.ValueState, Body: body})
	core, err := contract.ValueCoreForEntry(s.root.Domain, s.root.CurrentAccess.Core.CompatibilityID, retained.Entry)
	if err != nil {
		t.Fatal(err)
	}
	context, err := contract.ValueMaterialContextDigest(core)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := contract.DecodeCanonicalPayload(retained.Entry.ValueBytes)
	if err != nil {
		t.Fatal(err)
	}
	access := s.access[0].Records[0]
	access.MaterialKind, access.MaterialID, access.MaterialContextDigest, access.PackageCheck = 1, core.ValueStateID, context, payload.PackageCheck
	s.access[0].Records = append(s.access[0].Records, access)
	slices.SortFunc(s.access[0].Records, func(a, b contract.AccessRecord) int { return bytes.Compare(a.MaterialID[:], b.MaterialID[:]) })
	s.root.AccessRecordCount++
	generatedCommitFixtureAccess(t, s)
	if !s.indexSelectedMaterials() {
		t.Fatal("canonical material index")
	}
	if _, err := (&generatedSelectionBuilder{facts: &generatedSelection{session: s, image: s.selectedImage(), selectedMaterials: selectedMaterialFacts{accessLocations: s.accessLocations, valueReaders: s.valueReaders}}}).canonicalValue(retained); err != nil {
		t.Fatal("canonical fixture must be valid independently of its consumer", err)
	}
	consumers, err := g.vectors.resolve(11, h.HazardID, contract.GeneratorVectorConsumers, h.Consumers)
	if err != nil {
		t.Fatal(err)
	}
	body, err = contract.EncodeGeneratorConsumer(contract.GeneratorConsumer{Schema: 1, OwnerID: h.HazardID, MaterialID: core.ValueStateID,
		ContextDigest: context, SubjectKind: 2, SubjectID: core.ValueStateID, Purpose: 2})
	if err != nil {
		t.Fatal(err)
	}
	consumers = append(slices.Clone(consumers), body)
	slices.SortFunc(consumers, bytes.Compare)
	var carriers []contract.SupportRecord
	h.Consumers, carriers = generatedVectorRows(t, 11, h.HazardID, contract.GeneratorVectorConsumers, consumers)
	for i := range s.support {
		s.support[i].Records = slices.DeleteFunc(s.support[i].Records, func(row contract.SupportRecordView) bool {
			if row.Kind != contract.GeneratorVectorSupportKind {
				return false
			}
			v, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			return v.OwnerKind == 11 && v.OwnerID == h.HazardID && v.VectorKind == contract.GeneratorVectorConsumers
		})
	}
	for _, row := range carriers {
		s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
	}
	body, err = contract.EncodeGeneratedHazardRecord(h)
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceRecord(t, s, 11, h.HazardID, body)
	s.generatedWork = nil
	if _, err := format.EncodeRoot(s.root); err != nil {
		t.Fatal("forbidden-consumer fixture Root must be valid", err)
	}
	if _, err := s.selectedGeneratedWork(stdcontext.Background()); err == nil {
		t.Fatal("delete Hazard acquired an unrelated canonical-value consumer")
	}
}

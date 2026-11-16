package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func generatedOrdinaryCleanupSourceState(t testing.TB, class uint8, hazard bool) (*StateSession, contract.GeneratedDeleteSource) {
	t.Helper()
	base := generatedEmptyPredecessor(t)
	profile := defaultGeneratedFixtureProfile()
	profile.CompletionClass = class
	reserved, err := base.deriveGeneratedReservation(context.Background(), generatedReservationInputForProfile(t, base, generatedVectorID(170), []string{"generated"}, profile))
	if err != nil {
		t.Fatal(err)
	}
	s, original := generatedUnselectedCleanupFromReservation(t, reserved.state)
	if hazard {
		var h contract.GeneratedHazardRecord
		s, _, h = generatedCreateHazardFromCleanup(t, s, original, 1)
		g, err := s.selectedGeneratedWork(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		source, err := contract.InspectGeneratedDeleteSource(g.records[generatedRecordKey{kind: 11, id: h.HazardID}])
		if err != nil {
			t.Fatal(err)
		}
		return s, source
	}
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	source, err := contract.InspectGeneratedDeleteSource(g.records[generatedRecordKey{kind: 10, id: original.record.OwnerID}])
	if err != nil {
		t.Fatal(err)
	}
	return s, source
}

func generatedOrdinaryCleanupReservationInput(t testing.TB, s *StateSession, source contract.GeneratedDeleteSource, operation contract.ID) generatedReservationInput {
	t.Helper()
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	target, err := g.generatedCleanupTarget(source.Record.Kind, source.SourceID, source.Target)
	if err != nil {
		t.Fatal(err)
	}
	var resultContract contract.ID
	anchor, deleteOrigin := g.attempts[source.OriginalAttemptID]
	if source.Record.Kind == contract.GeneratedHazardSupportKind && deleteOrigin && anchor.expected.Template.Action == contract.GeneratorActionDelete {
		resultContract = source.ResultContractID
	} else {
		retained, err := g.retainedGraph(target.OriginalOperationID)
		if err != nil {
			t.Fatal(err)
		}
		for _, lineage := range retained.Lineages {
			for _, x := range lineage.Templates[:lineage.TemplateCount] {
				if lineage.Purpose == 3 && x.DutyID == source.OwnerID && x.ResourceIncarnationID == source.ResourceID {
					resultContract = x.ResultContractID
				}
			}
		}
	}
	if resultContract.IsZero() {
		t.Fatal("cleanup source has no retained delete contract")
	}

	input := generatedReservationInputForGenerations(t, s, operation, nil)
	input.graph.ValueEntryPlans = nil
	input.graph.Header.ValueEntryPlanCount = 0
	facts, err := g.createTargetEvidence(t.Context(), target)
	if err != nil {
		t.Fatal(err)
	}
	lineage := contract.GeneratorLineageTemplate{Schema: contract.GeneratorLineageTemplateSchema, Purpose: 3, DomainID: s.root.Domain, OperationID: operation,
		Name: target.Name, EntryIncarnationID: target.IncarnationID, Epoch: target.Epoch, IntentDigest: facts.IntentDigest,
		ResourceIncarnationID: target.ResourceID, TemplateCount: 1}
	lineage.LineageID, err = contract.GeneratorObligationLineageID(lineage.DomainID, operation, target.ResourceID, 3)
	if err != nil {
		t.Fatal(err)
	}
	x := contract.GeneratorAttemptTemplate{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratorAttemptTemplateSchema, ResultReaderID: contract.GeneratorResultReaderID(), ResourceDigest: target.ResourceDigest, Action: 2, LineageID: lineage.LineageID,
		ResourceIncarnationID: target.ResourceID, DutyID: source.OwnerID, ConfigContractID: source.ConfigContractID,
		ResourceContractID: source.ResourceContractID, ExecutorID: source.ExecutorID, CredentialRouteID: source.CredentialRouteID,
		DescriptorID: source.DescriptorID, ResultContractID: resultContract, IntentDigest: facts.IntentDigest, TargetKind: 3, CompletionClass: source.CompletionClass, RequiredAuthoritySet: 1}
	x.TargetSourceID, err = generatedCreateResultID(s.root.Domain, target.OriginalOperationID, target.OriginalAttemptID)
	if err != nil {
		t.Fatal(err)
	}
	x.AttemptID, err = contract.GeneratorAttemptID(x.LineageID, 0)
	if err != nil {
		t.Fatal(err)
	}
	x.PlannedValueSlotID, err = contract.GeneratorValueSlotID(s.root.Domain, operation, x.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	x.HazardID, err = contract.GeneratorHazardID(s.root.Domain, x.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	x.TransmissionID, err = contract.GeneratorTransmissionID(x.AttemptID, 2)
	if err != nil {
		t.Fatal(err)
	}
	x.ResultID, err = contract.GeneratorResultID(s.root.Domain, operation, x.AttemptID, x.TransmissionID, 2)
	if err != nil {
		t.Fatal(err)
	}
	x.InboxID, err = contract.GeneratorInboxID(s.root.Domain, operation, x.AttemptID, x.ResultID)
	if err != nil {
		t.Fatal(err)
	}
	x.RequestPlanDigest, err = contract.GeneratorRequestPlanDigest(x)
	if err != nil {
		t.Fatal(err)
	}
	lineage.Templates[0] = x
	input.graph.Lineages = []contract.GeneratorLineageTemplate{lineage}
	input.graph.Header.LineageCount, input.graph.Header.TemplateCount = 0, 1
	input.graph.Request.OperationKind = 31
	input.requestBindings = generatedFixtureRequestBindings(input.graph, generatedVectorID(61))
	input.graph.Header.RequestCoreDigest, err = contract.GeneratorRequestCoreDigest(input.graph.Request)
	if err != nil {
		t.Fatal(err)
	}
	join, err := contract.GeneratorCompleteJoinID(input.graph.Header.RequestCoreDigest)
	if err != nil {
		t.Fatal(err)
	}
	template, err := contract.GeneratorTemplateID(x)
	if err != nil {
		t.Fatal(err)
	}
	input.graph.Edges = nil
	for _, guard := range []uint8{3, 4} {
		input.graph.Edges = append(input.graph.Edges, contract.GeneratorEdge{Schema: 1, SourceTemplateID: template,
			DestinationTemplateID: join, Guard: guard, ResultSlotID: x.ResultID, RequiredAuthoritySet: 1})
	}
	use := contract.GeneratorResultUse{Schema: 1, AttemptID: x.AttemptID, ResultID: x.ResultID, InboxID: x.InboxID,
		ExecutorID: x.ExecutorID, ResultContractID: x.ResultContractID, PlannedValueSlotID: x.PlannedValueSlotID,
		MaterialID: input.graph.Header.MaterialID, Purpose: 1, MaxFacts: 4096}
	input.graph.ResultUses = []contract.GeneratorResultUse{use}
	input.graph.UsePlan.ResultUses, err = contract.GeneratorResultUsesDescriptor(input.graph.ResultUses)
	if err != nil {
		t.Fatal(err)
	}
	input.graph.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(input.graph.Header, input.graph.ValueEntryPlans, input.graph.Lineages, input.graph.Edges)
	if err != nil {
		t.Fatal(err)
	}
	input.parent.PlanGraphID, input.parent.TemplateCount, input.parent.LineageCount = input.graph.UsePlan.PlanGraphID, 1, 0
	input.parent.RequestCoreDigest, input.parent.ValueEntryPlanCount, input.parent.Declaration = input.graph.Header.RequestCoreDigest, 0, input.graph.Request.Declaration
	input.parent.IntendedEntryPlans, err = contract.GeneratorValueEntryPlansDescriptor(nil)
	if err != nil {
		t.Fatal(err)
	}
	input.parent.UsePlanDigest, err = contract.GeneratorUsePlanDigest(input.graph.UsePlan)
	if err != nil {
		t.Fatal(err)
	}
	input.parent.Graph, err = contract.GeneratorPlanBundleDescriptor(input.graph)
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
	if err := contract.ValidateGeneratorEffectGraph(input.graph); err != nil {
		t.Fatal(err)
	}
	return input
}

func generatedReceiptRows(s *StateSession) []contract.SupportRecord {
	var out []contract.SupportRecord
	for _, row := range s.supportRecords() {
		if row.Kind == 7 {
			out = append(out, row)
		}
	}
	return out
}

// full_only: false
func TestGeneratedOrdinaryCleanupAmbiguityPrivateAdmissionRefusesInvalidBoundary(t *testing.T) {
	s := &StateSession{}
	if permit, err := s.admitGeneratedOrdinaryCleanupUnknown(context.Background(), contract.ID{}, nil, contract.ApplyContext{}); err == nil || permit != nil {
		t.Fatal("invalid ordinary-cleanup ambiguity boundary admitted work")
	}
}

// full_only: false
func TestGeneratedOrdinaryCleanupRequiresEveryOwnedInvocation(t *testing.T) {
	for _, hazard := range []bool{false, true} {
		for _, damage := range []string{"complete", "missing consumer", "missing history"} {
			t.Run(fmt.Sprintf("hazard=%t/%s", hazard, damage), func(t *testing.T) {
				s, source := generatedOrdinaryCleanupSourceState(t, contract.GeneratedCompletionAcknowledged, hazard)
				for invocation := byte(0); invocation < 2; invocation++ {
					reserved, err := s.deriveGeneratedReservation(t.Context(), generatedOrdinaryCleanupReservationInput(t, s, source, generatedVectorID(180+invocation)))
					if err != nil {
						t.Fatal("reserve owned invocation", err)
					}
					s = reserved.state
					g := mustSelectedGeneratedWork(t, s)
					a := g.attempts[g.phase.FrontierAttemptID]
					facts, err := contract.EncodeGeneratorSafeFacts(generatedRetirementFactsFixture(t, s, a, contract.GeneratorDispositionUnknown))
					if err != nil {
						t.Fatal(err)
					}
					plan, err := s.generatedOrdinaryCleanupAmbiguityPlan(t.Context(), a.record.AttemptID, facts, generatedLifecycleFixture(t, s))
					if err != nil {
						t.Fatal("park owned invocation", err)
					}
					parked, err := s.deriveGeneratedOrdinaryCleanupAmbiguity(t.Context(), plan)
					if err != nil {
						t.Fatal("select parked invocation", err)
					}
					s = parked.state
					g = mustSelectedGeneratedWork(t, s)
					source, err = contract.InspectGeneratedDeleteSource(g.records[generatedRecordKey{source.Record.Kind, source.SourceID}])
					if err != nil {
						t.Fatal(err)
					}
				}
				g := mustSelectedGeneratedWork(t, s)
				if damage != "complete" {
					kind, descriptor := contract.GeneratorVectorConsumers, source.Consumers
					if damage == "missing history" {
						kind, descriptor = contract.GeneratorVectorHistory, source.History
					}
					bodies, err := g.vectors.resolve(source.Record.Kind, source.SourceID, kind, descriptor)
					if err != nil || len(bodies) < 2 {
						t.Fatal("complete source vector", err)
					}
					if kind == contract.GeneratorVectorConsumers {
						// Keep the original create use but omit one actual Delete use.
						for i, body := range bodies {
							consumer, err := contract.InspectGeneratorConsumer(body)
							if err != nil {
								t.Fatal(err)
							}
							for _, a := range g.attempts {
								if a.expected.Template.Action == contract.GeneratorActionDelete && a.record.ResultID == consumer.SubjectID {
									bodies = slices.Delete(slices.Clone(bodies), i, i+1)
									goto changed
								}
							}
						}
						t.Fatal("owned Delete consumer missing in fixture")
					} else {
						bodies = slices.Clone(bodies[:len(bodies)-1])
						last, err := contract.InspectGeneratorHistory(bodies[len(bodies)-1])
						if err != nil {
							t.Fatal(err)
						}
						last.Edge, last.NextAttemptID = 0, contract.ID{}
						bodies[len(bodies)-1], err = contract.EncodeGeneratorHistory(last)
						if err != nil {
							t.Fatal(err)
						}
					}
				changed:
					replacement, carriers, err := generatedCarrierRows(s.root.Domain, source.Record.Kind, source.SourceID, kind, bodies)
					if err != nil {
						t.Fatal(err)
					}
					rows := slices.DeleteFunc(slices.Clone(s.supportRecords()), func(row contract.SupportRecord) bool {
						if row.Kind != contract.GeneratorVectorSupportKind {
							return false
						}
						carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
						if err != nil {
							t.Fatal(err)
						}
						return carrier.OwnerKind == source.Record.Kind && carrier.OwnerID == source.SourceID && carrier.VectorKind == kind
					})
					for i, row := range rows {
						if row.Kind != source.Record.Kind || row.RecordID != source.SourceID {
							continue
						}
						if source.Record.Kind == contract.GeneratedDutySupportKind {
							d := source.Duty
							if kind == contract.GeneratorVectorConsumers {
								d.Consumers = replacement
							} else {
								d.History = replacement
							}
							rows[i].Body, err = contract.EncodeGeneratedDutyRecord(d)
						} else {
							h := source.Hazard
							if kind == contract.GeneratorVectorConsumers {
								h.Consumers = replacement
							} else {
								h.History = replacement
							}
							rows[i].Body, err = contract.EncodeGeneratedHazardRecord(h)
						}
						if err != nil {
							t.Fatal(err)
						}
					}
					rows = append(rows, carriers...)
					if kind == contract.GeneratorVectorConsumers || hazard && damage == "missing history" {
						page := format.RequiredSupportPageView{Domain: s.root.Domain, Index: 0}
						for _, row := range rows {
							page.Records = append(page.Records, contract.SupportRecordView(row))
						}
						s.support = []format.RequiredSupportPageView{page}
						if kind == contract.GeneratorVectorConsumers {
							indexChecked, err := generatedAlteredSupportIndexResult(t, s)
							if !indexChecked || !errors.Is(err, contract.ErrRecord) {
								t.Fatalf("cleanup with %s requires administrative index refusal: indexChecked=%t err=%v", damage, indexChecked, err)
							}
						} else if !generatedIndexRejectsAlteredSupport(t, s) {
							t.Fatalf("administrative ownership admitted cleanup with %s", damage)
						}
						return
					}
					generatedRepackSupport(t, s, rows, g.bundles)
				}
				s.generatedWork = nil
				_, err := s.selectedGeneratedWork(t.Context())
				if damage == "complete" && err != nil {
					t.Fatal("complete owned set refused", err)
				}
				if damage != "complete" && err == nil {
					t.Fatal("selected cleanup omitted an actual owned Delete invocation")
				}
			})
		}
	}
}

// full_only: false
func TestGeneratedOrdinaryCleanupAmbiguityIsReceiptFreeAndAllowsFreshInvocation(t *testing.T) {
	for _, class := range []uint8{contract.GeneratedCompletionAcknowledged, contract.GeneratedCompletionConfirmed} {
		for _, hazard := range []bool{false, true} {
			t.Run(fmt.Sprintf("class=%d/hazard=%t", class, hazard), func(t *testing.T) {
				s, source := generatedOrdinaryCleanupSourceState(t, class, hazard)
				for invocation := byte(0); invocation < 2; invocation++ {
					input := generatedOrdinaryCleanupReservationInput(t, s, source, generatedVectorID(180+invocation))
					reserved, err := s.deriveGeneratedReservation(context.Background(), input)
					if err != nil {
						t.Fatal("fresh ordinary cleanup reservation", err)
					}
					active := reserved.state
					ctx := generatedLifecycleFixture(t, active)
					before, err := active.selectedGeneratedWork(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					a := before.attempts[before.phase.FrontierAttemptID]
					facts, err := contract.EncodeGeneratorSafeFacts(generatedRetirementFactsFixture(t, active, a, contract.GeneratorDispositionUnknown))
					if err != nil {
						t.Fatal(err)
					}
					beforeSource := before.records[generatedRecordKey{kind: source.Record.Kind, id: source.SourceID}]
					beforeRows := generatedReceiptRows(active)
					beforeSuccess, beforeFailure, beforeOrder := active.root.Generated.SuccessWindow, active.root.Generated.FailureWindow, active.root.Generated.ReceiptOrder
					plan, err := active.generatedOrdinaryCleanupAmbiguityPlan(t.Context(), a.record.AttemptID, facts, ctx)
					if err != nil {
						t.Fatal("qualified ordinary ambiguity plan", err)
					}
					closed, err := active.deriveGeneratedOrdinaryCleanupAmbiguity(context.Background(), plan)
					if err != nil || closed.state.validateGeneratedSelection(t.Context(), nil) != nil {
						t.Fatal("qualified ordinary ambiguity transition", err)
					}
					after, err := closed.state.selectedGeneratedWork(context.Background())
					if err != nil || after.parent != nil || after.phase != nil {
						t.Fatal("ordinary ambiguity retained active owner", err)
					}
					parked := after.attempts[a.record.AttemptID]
					if parked.record.State != contract.GeneratedEffectUnknown || parked.record.Stage != contract.GeneratedStageTerminal ||
						len(parked.result) != 0 || parked.record.Facts.Count != 1 || parked.record.CompletionClass != class ||
						parked.record.Progress != a.record.Progress {
						t.Fatal("ordinary ambiguity changed its result-free terminal attempt")
					}
					afterSource, err := contract.InspectGeneratedDeleteSource(after.records[generatedRecordKey{kind: source.Record.Kind, id: source.SourceID}])
					if err != nil || afterSource.History.Count != source.History.Count+1 || afterSource.Consumers.Count != source.Consumers.Count+1 ||
						afterSource.CompletionClass != source.CompletionClass || afterSource.Target != source.Target ||
						source.Record.Kind == 10 && afterSource.Duty.Progress != source.Duty.Progress {
						t.Fatal("ordinary ambiguity lost source history, consumers, progress, class, or target", err)
					}
					if closed.state.root.Generated.SuccessWindow != beforeSuccess || closed.state.root.Generated.FailureWindow != beforeFailure || closed.state.root.Generated.ReceiptOrder != beforeOrder ||
						!reflect.DeepEqual(generatedReceiptRows(closed.state), beforeRows) {
						t.Fatal("ordinary ambiguity created or changed a compact receipt")
					}
					if bytes.Equal(beforeSource.Body, after.records[generatedRecordKey{kind: source.Record.Kind, id: source.SourceID}].Body) {
						t.Fatal("ordinary ambiguity did not record its own source history")
					}
					s, source = closed.state, afterSource
					generatedLifecycleFixture(t, s)
				}
			})
		}
	}
}

// full_only: false
func TestGeneratedOrdinaryCleanupAmbiguityRefusesContradictionWithoutStateChange(t *testing.T) {
	for _, damage := range []string{"alive", "unequal", "reason10"} {
		t.Run(damage, func(t *testing.T) {
			s, source := generatedOrdinaryCleanupSourceState(t, contract.GeneratedCompletionAcknowledged, false)
			reserved, err := s.deriveGeneratedReservation(context.Background(), generatedOrdinaryCleanupReservationInput(t, s, source, generatedVectorID(190)))
			if err != nil {
				t.Fatal(err)
			}
			active := reserved.state
			ctx := generatedLifecycleFixture(t, active)
			g, err := active.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			a := g.attempts[g.phase.FrontierAttemptID]
			facts := generatedRetirementFactsFixture(t, active, a, contract.GeneratorDispositionUnknown)
			switch damage {
			case "alive":
				facts = generatedRetirementFactsFixture(t, active, a, contract.GeneratorDispositionRetirementAcknowledged)
				facts.Disposition = contract.GeneratorDispositionContinuedUsability
				facts.ScopeID, facts.PrecedingResultID, facts.PrecedingResultBodyDigest = generatedVectorID(191), generatedVectorID(192), generatedVectorID(193)
				facts.ObservedResourceID, facts.ObservedResourceDigest, facts.ObservedScopeID = a.record.ResourceID, a.expected.TargetResourceDigest, generatedVectorID(194)
			case "unequal":
				facts.Target, facts.ResourceData = []byte("fixture-target"), bytes.Repeat([]byte{199}, 32)
			case "reason10":
				facts.Reason = 10
			}
			body, err := contract.EncodeGeneratorSafeFacts(facts)
			if err != nil {
				t.Fatal(err)
			}
			before := slices.Clone(active.supportRecords())
			if plan, err := active.generatedOrdinaryCleanupAmbiguityPlan(t.Context(), a.record.AttemptID, body, ctx); err == nil || plan != nil {
				t.Fatal("contradictory ordinary cleanup ambiguity admitted")
			}
			if !reflect.DeepEqual(before, active.supportRecords()) || g.parent == nil || g.phase == nil ||
				g.attempts[a.record.AttemptID].record.State != contract.GeneratedEffectTransmitted {
				t.Fatal("refused ordinary cleanup ambiguity changed selected state")
			}
		})
	}
}

// full_only: false
func TestGeneratedOrdinaryCleanupAmbiguityPlanBindsSourceTargetAndFacts(t *testing.T) {
	s, source := generatedOrdinaryCleanupSourceState(t, contract.GeneratedCompletionAcknowledged, false)
	reserved, err := s.deriveGeneratedReservation(context.Background(), generatedOrdinaryCleanupReservationInput(t, s, source, generatedVectorID(195)))
	if err != nil {
		t.Fatal(err)
	}
	active := reserved.state
	ctx := generatedLifecycleFixture(t, active)
	g, err := active.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a := g.attempts[g.phase.FrontierAttemptID]
	ambiguity := generatedRetirementFactsFixture(t, active, a, contract.GeneratorDispositionRetirementAcknowledged)
	ambiguity.Disposition, ambiguity.Reason = contract.GeneratorDispositionUnknown, contract.GeneratorReasonTransport
	facts, err := contract.EncodeGeneratorSafeFacts(ambiguity)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := active.generatedOrdinaryCleanupAmbiguityPlan(t.Context(), a.record.AttemptID, facts, ctx)
	if err != nil || plan.owner != source.SourceID || plan.target != a.expected.TargetResourceDigest || plan.evidence.IsZero() ||
		plan.kind != generatedLifecycleOrdinaryCleanupUnknown || !bytes.Equal(plan.result, facts) {
		t.Fatal("ordinary-cleanup ambiguity plan lost its exact source, target, or facts", err)
	}
	for name, damage := range map[string]func(*generatedLifecyclePlan){
		"owner":    func(v *generatedLifecyclePlan) { v.owner = generatedVectorID(196) },
		"target":   func(v *generatedLifecyclePlan) { v.target = generatedVectorID(196) },
		"evidence": func(v *generatedLifecyclePlan) { v.evidence = generatedVectorID(196) },
		"facts":    func(v *generatedLifecyclePlan) { v.result = bytes.Clone(v.result); v.result[len(v.result)-1] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := *plan
			damage(&changed)
			if derived, err := active.deriveGeneratedOrdinaryCleanupAmbiguity(t.Context(), &changed); err == nil || derived != nil {
				t.Fatal("changed ordinary-cleanup ambiguity plan was accepted")
			}
		})
	}
}

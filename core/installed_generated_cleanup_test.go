package core

import (
	"context"
	"fmt"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// full_only: false
func TestGeneratedCleanupObservationKeepsExplicitColdRefusal(t *testing.T) {
	for _, hazard := range []bool{false, true} {
		for _, reason := range []Reason{NoReason, InvalidRelation, CapacityExceeded, AdmissionInvalid} {
			t.Run(fmt.Sprintf("hazard=%v/reason=%d", hazard, reason), func(t *testing.T) {
				state, attempt := installedGeneratedUnknownCleanupFixture(t, contract.GeneratedCompletionAcknowledged, hazard)
				work := mustSelectedGeneratedWork(t, state)
				result := refused(reason)
				if reason == NoReason {
					result = Result{}
				}
				out := PublicApplyResult{RequestID: generatedVectorID(241), DomainID: state.root.Domain, OperationID: attempt.record.OperationID, Result: result}
				got := preserveInstalledGeneratedCleanupObserved(t.Context(), out, state, work, &generatedSelectionCheckpoint{})
				if reason == NoReason {
					if got.Result.Outcome != ObservedCurrent || got.Result.Evidence != AuthenticatedClosure || got.Result.ObservedRevision != state.head.Core.Revision {
						t.Fatal("explicit initial observation did not establish current evidence", got.Result)
					}
				} else if got.Result != result {
					t.Fatal("cold refusal was replaced by observation", result, got.Result)
				}
				if got.Generated == nil || got.Generated.EffectSummary != contract.ReceiptEffectUnknown || len(got.Generated.Effects) != 1 || got.Generated.Effects[0].Record.AttemptID != attempt.record.AttemptID || got.Cleanup == nil {
					t.Fatal("cold refusal lost retained exact unknown cleanup work")
				}
			})
		}
	}
}

// full_only: false
func TestInstalledGeneratedCleanupRefusalCompletesClosedTelemetry(t *testing.T) {
	for _, continuation := range []bool{false, true} {
		t.Run(fmt.Sprint(continuation), func(t *testing.T) {
			var engine *InstalledApply
			recorder := telemetry.NewRecorder()
			ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
			request := generatedVectorID(11)
			var result PublicApplyResult
			if continuation {
				result = engine.ContinueGeneratedCleanup(ctx, request, GeneratedCleanupContinuationRequest{OperationID: generatedVectorID(12)})
			} else {
				result = engine.CleanupGenerated(ctx, request)
			}
			if result.RequestID != request || result.Result != refused(AdmissionInvalid) || result.Generated != nil || len(result.Receipt) != 0 {
				t.Fatal("invalid cleanup installed authority admitted work", result)
			}
			records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 3))
			if len(records) != 3 || records[0].Event != telemetry.DiagnosticStart || records[1].Event != telemetry.DiagnosticCheckpoint ||
				records[2].Event != telemetry.DiagnosticReturn || records[2].Operation != telemetry.OpCoreGeneratedCleanup || records[2].Result != telemetry.ResultAdmissionRefused {
				t.Fatal("cleanup refusal lost its closed operation", records)
			}
			for _, record := range records {
				if err := record.Validate(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func installedGeneratedUnknownCleanupFixture(t *testing.T, class uint8, hazard bool) (*StateSession, generatedAttempt) {
	t.Helper()
	s, source := generatedOrdinaryCleanupSourceState(t, class, hazard)
	reservation, err := s.deriveGeneratedReservation(t.Context(), generatedOrdinaryCleanupReservationInput(t, s, source, generatedVectorID(180)))
	if err != nil {
		t.Fatal(err)
	}
	s = reservation.state
	work := mustSelectedGeneratedWork(t, s)
	a := work.attempts[work.phase.FrontierAttemptID]
	facts, err := contract.EncodeGeneratorSafeFacts(generatedRetirementFactsFixture(t, s, a, contract.GeneratorDispositionUnknown))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := s.generatedOrdinaryCleanupAmbiguityPlan(t.Context(), a.record.AttemptID, facts, generatedLifecycleFixture(t, s))
	if err != nil {
		t.Fatal(err)
	}
	parked, err := s.deriveGeneratedOrdinaryCleanupAmbiguity(t.Context(), plan)
	if err != nil {
		t.Fatal(err)
	}
	s = parked.state
	return s, mustSelectedGeneratedWork(t, s).attempts[a.record.AttemptID]
}

// full_only: false
func TestInstalledGeneratedCleanupReflectionCapturesExactOriginalBeforeOwnerEnds(t *testing.T) {
	for _, hazard := range []bool{false, true} {
		t.Run(fmt.Sprint(hazard), func(t *testing.T) {
			s, original := installedGeneratedUnknownCleanupFixture(t, contract.GeneratedCompletionAcknowledged, hazard)
			packet := generatedRetirementResultFixture(t, s, original, contract.GeneratorDispositionRetirementAcknowledged)
			plan, err := s.generatedReflectionPlan(t.Context(), original.record.ResultID, packet, generatedLifecycleFixture(t, s))
			if err != nil || plan.kind != generatedLifecycleCleanupClose {
				t.Fatal("qualified original did not derive exact closure", err)
			}
			proposal, err := s.deriveGeneratedLifecycle(t.Context(), plan, nil)
			if err != nil {
				t.Fatal(err)
			}
			work := mustSelectedGeneratedWork(t, s)
			capture, err := captureInstalledGeneratedCleanupResult(t.Context(), s, work, plan, proposal, nil)
			if err != nil {
				t.Fatal("capture original before cleanup owner ends", err)
			}
			work.records, work.attempts, work.bundles, work.image = nil, nil, nil, nil
			canceled, cancel := context.WithCancel(t.Context())
			cancel()
			actual := Result{Outcome: ObservedCurrent, Evidence: AuthenticatedClosure, RequestedRevision: proposal.state.head.Core.Revision, ObservedRevision: proposal.state.head.Core.Revision}
			result, err := capture.observe(canceled, proposal.state, actual)
			if err != nil || result.OperationKind != contract.OperationCleanOwnedFailureResidue || result.StateResult != "success" ||
				result.ReceiptObservation || result.AcknowledgedCount != 1 || result.ConfirmedCount != 0 || len(result.Effects) != 1 || len(result.Duties) != 0 || len(result.Hazards) != 0 {
				t.Fatal("cleanup closure lost exact receipt-free original result", result, err)
			}
			effect := result.Effects[0]
			if effect.Record.AttemptID != original.record.AttemptID || effect.Record.OperationID != original.record.OperationID ||
				effect.SummaryClass != contract.ReceiptSummarySuccessCount || effect.Target == nil || effect.Target.ResourceDigest != original.expected.TargetResourceDigest ||
				!effect.Warnings.InvalidationNotConfirmed || result.CanonicalOutcome != contract.ReceiptCanonicalNotSelected {
				t.Fatal("cleanup synthesized an Attempt, target or stronger completion", effect)
			}
			out := PublicApplyResult{DomainID: original.record.DomainID, OperationID: plan.identity.operation, RequestIdentity: plan.requestIdentity, RequestID: generatedVectorID(249), Result: actual, Generated: result}
			capture.attach(&out)
			if out.Cleanup == nil || out.Cleanup.RemainingWorkBasis.HeadRevisionID != actual.ObservedRevision || !containsCleanupID(out.Cleanup.RemainingInboxIDs, original.record.InboxID) || capture.backingBytes <= capture.generatedInvocationResultCapture.backingBytes {
				t.Fatal("capture lost owned cleanup payload or backing account")
			}
			if err := RefreshGeneratedCleanupResult(&out); err != nil || out.Cleanup.SiblingResults.Count != 1 {
				t.Fatal("exact reflected Product row failed pure validation", err)
			}
			out.Generated.Effects[0].Name += "changed"
			if _, err := GeneratedCleanupSiblingResults(out); err == nil {
				t.Fatal("effect name contradicting exact target accepted")
			}

		})
	}
}

// full_only: false
func TestInstalledGeneratedCleanupReflectionPreservesBeforeEvidenceOnContention(t *testing.T) {
	s, original := installedGeneratedUnknownCleanupFixture(t, contract.GeneratedCompletionAcknowledged, false)
	packet := generatedRetirementResultFixture(t, s, original, contract.GeneratorDispositionRetirementAcknowledged)
	plan, err := s.generatedReflectionPlan(t.Context(), original.record.ResultID, packet, generatedLifecycleFixture(t, s))
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := s.deriveGeneratedLifecycle(t.Context(), plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	work := mustSelectedGeneratedWork(t, s)
	capture, err := captureInstalledGeneratedCleanupResult(t.Context(), s, work, plan, proposal, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := capture.observe(t.Context(), proposal.state, Result{Outcome: Contention})
	if err != nil || result.StateResult != "contention" || len(result.Effects) != 1 || result.Effects[0].Record != original.record ||
		result.Effects[0].SummaryClass != contract.ReceiptSummaryUnknownCount || result.AcknowledgedCount != 0 || result.ConfirmedCount != 0 {
		t.Fatal("unselected reflection promoted original evidence", result, err)
	}
}

// full_only: false
func TestInstalledGeneratedCleanupVerificationProjectsActualDetachedOperation(t *testing.T) {
	s, original := installedGeneratedUnknownCleanupFixture(t, contract.GeneratedCompletionAcknowledged, true)
	packet := generatedRetirementResultFixture(t, s, original, contract.GeneratorDispositionRetirementAcknowledged)
	plan, err := s.generatedReflectionPlan(t.Context(), original.record.ResultID, packet, generatedLifecycleFixture(t, s))
	if err != nil {
		t.Fatal(err)
	}
	q, _, err := s.generatedOriginalVerificationRequest(t.Context(), plan)
	if err != nil {
		t.Fatal(err)
	}
	work := mustSelectedGeneratedWork(t, s)
	input, err := s.installedGeneratedVerificationInput(t.Context(), work, plan, q)
	if err != nil {
		t.Fatal("project actual original verification", err)
	}
	graph, err := contract.DecodeGeneratorPlanBundle(input.Session.Graph)
	if err != nil || work.parent != nil || graph.Header.OperationID != original.record.OperationID || input.Material != original.material ||
		input.Result.Expected != original.expected || input.Result.Reference != q.OriginalResult || input.Target == nil ||
		input.Target.ResourceDigest != original.expected.TargetResourceDigest || input.Owner.Kind != contract.GeneratedHazardSupportKind || len(input.SeedAccess) == 0 {
		t.Fatal("verification invented an active parent or changed original facts", err)
	}
	wrong := q
	wrong.OriginalOwnerID = generatedVectorID(250)
	if _, err := s.installedGeneratedVerificationInput(t.Context(), work, plan, wrong); err == nil {
		t.Fatal("changed original owner admitted for verification")
	}
}

// full_only: false
func TestInstalledGeneratedCleanupClosedResidueObservationRemainsUnknown(t *testing.T) {
	base := generatedEmptyPredecessor(t)
	reserved, err := base.deriveGeneratedReservation(t.Context(), generatedReservationInputFixture(t, base))
	if err != nil {
		t.Fatal(err)
	}
	work := mustSelectedGeneratedWork(t, reserved.state)
	originalID := work.phase.FrontierAttemptID
	s := generatedRetainedClosureResidue(t, reserved.state, 230)
	s = generatedReservePlannedSuccessor(t, s, 232)
	s = generatedRetainedClosureResidue(t, s, 234)
	finalPlan, err := s.generatedFinalRequest(t.Context(), generatedContinuationContext(t, s, 236, 237))
	if err != nil || finalPlan.selecting {
		t.Fatal("exhausted nonselecting original prerequisite", err)
	}
	final, err := s.deriveGeneratedFinal(t.Context(), finalPlan, nil)
	if err != nil {
		t.Fatal(err)
	}
	s = final.state
	work = mustSelectedGeneratedWork(t, s)
	original := work.attempts[originalID]
	if work.parent != nil || work.phase != nil || original.record.State != contract.GeneratedEffectClosedWithResidue || len(original.result) != 0 {
		t.Fatal("expected actual detached sole cleanup original", original.record.State)
	}
	packet := generatedPublicResultFixture(t, original, contract.GeneratorDispositionCompleteCreate)
	plan, err := s.generatedReflectionPlan(t.Context(), original.record.ResultID, packet, generatedContinuationContext(t, s, 238, 239))
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := s.deriveGeneratedLifecycle(t.Context(), plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	capture, err := captureInstalledGeneratedCleanupResult(t.Context(), s, work, plan, proposal, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := PublicApplyResult{DomainID: s.root.Domain, OperationID: plan.identity.operation, RequestIdentity: plan.requestIdentity, RequestID: generatedVectorID(240)}
	if err := capture.prevalidate(out, ApplyInstallation{}); err != nil {
		t.Fatal("exact unknown original and qualified learned target refused prevalidation", err)
	}
	got, err := capture.observe(t.Context(), proposal.state, Result{Outcome: Contention})
	if err != nil || got == nil || len(got.Effects) != 1 || got.Effects[0].Record != original.record || len(got.Hazards) != 1 || got.Hazards[0].Record.HazardID != original.expected.Template.HazardID {
		t.Fatal("before-only original observation was not retained", got, err)
	}
	if got.Effects[0].SummaryClass != contract.ReceiptSummaryUnknownCount || got.SummaryCounts[contract.ReceiptSummaryUnknownCount] != 1 || got.SummaryCounts[contract.ReceiptPreservedResidueCount] != 0 || got.UnknownCount != 1 || got.EffectSummary != contract.ReceiptEffectUnknown {
		t.Fatal("sole required closed-residue original lost its uncertainty", got)
	}
	out.Result, out.Generated = Result{Outcome: Contention}, got
	capture.attach(&out)
	if _, err := GeneratedCleanupSiblingResults(out); err != nil {
		t.Fatal("exact unknown CREATE reflection shape was refused", err)
	}
	if out.Cleanup.Basis.Target == nil {
		t.Fatal("late-effect reflection did not bind the learned target")
	}
	for name, change := range map[string]func(*PublicApplyResult){
		"delete":       func(r *PublicApplyResult) { r.Generated.Effects[0].Action = contract.GeneratorActionDelete },
		"known create": func(r *PublicApplyResult) { r.Generated.Effects[0].Record.State = contract.GeneratedEffectSucceeded },
		"ordinary cleanup": func(r *PublicApplyResult) {
			r.Cleanup.Basis.Kind, r.Cleanup.Basis.OriginalResult = GeneratedCleanupOwnedTarget, nil
		},
		"invented observed target": func(r *PublicApplyResult) { r.Generated.Effects[0].Target = r.Cleanup.Basis.Target },
		"wrong source":             func(r *PublicApplyResult) { r.Cleanup.Basis.SourceID = generatedVectorID(250) },
		"unfenced source": func(r *PublicApplyResult) {
			r.Generated.Hazards[0].Record.Fenced, r.Generated.Hazards[0].Record.Eligibility = 0, 0
		},
		"wrong original":                    func(r *PublicApplyResult) { r.Generated.Hazards[0].Record.OriginalAttemptID = generatedVectorID(249) },
		"learned-target-name":               func(r *PublicApplyResult) { r.Cleanup.Basis.Target.Name += "changed" },
		"learned-target-incarnation":        func(r *PublicApplyResult) { r.Cleanup.Basis.Target.IncarnationID = generatedVectorID(248) },
		"learned-target-epoch":              func(r *PublicApplyResult) { r.Cleanup.Basis.Target.Epoch++ },
		"learned-target-original-operation": func(r *PublicApplyResult) { r.Cleanup.Basis.Target.OriginalOperationID = generatedVectorID(247) },
		"learned-target-original-attempt":   func(r *PublicApplyResult) { r.Cleanup.Basis.Target.OriginalAttemptID = generatedVectorID(246) },
		"learned-target-resource":           func(r *PublicApplyResult) { r.Cleanup.Basis.Target.ResourceID = generatedVectorID(245) },
		"learned-target-config-contract":    func(r *PublicApplyResult) { r.Cleanup.Basis.Target.ConfigContractID = generatedVectorID(244) },
		"learned-target-resource-contract":  func(r *PublicApplyResult) { r.Cleanup.Basis.Target.ResourceContractID = generatedVectorID(243) },
		"learned-target-result-contract":    func(r *PublicApplyResult) { r.Cleanup.Basis.Target.ResultContractID = generatedVectorID(242) },
		"learned-target-completion-class": func(r *PublicApplyResult) {
			r.Cleanup.Basis.Target.CompletionClass = contract.GeneratedCompletionConfirmed
		},
		"hazard-completion-class": func(r *PublicApplyResult) {
			r.Generated.Hazards[0].Record.CompletionClass = contract.GeneratedCompletionConfirmed
		},
		"attempt-completion-class": func(r *PublicApplyResult) {
			r.Generated.Effects[0].Record.CompletionClass = contract.GeneratedCompletionConfirmed
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := out
			facts, payload := *out.Generated, *out.Cleanup
			facts.Effects = append([]GeneratedEffectFact(nil), facts.Effects...)
			facts.Hazards = append([]GeneratedHazardFact(nil), facts.Hazards...)
			target := *payload.Basis.Target
			payload.Basis.Target = &target
			changed.Generated, changed.Cleanup = &facts, &payload
			change(&changed)
			for _, set := range []struct {
				kind contract.MutationResultRecordKind
				row  contract.SupportRecord
				desc **contract.GeneratorDescriptor
			}{
				{contract.MutationResultEffects, contract.SupportRecord{Kind: contract.GeneratedAttemptSupportKind, RecordID: facts.Effects[0].Record.AttemptID}, &facts.EffectsCommitment},
				{contract.MutationResultHazards, contract.SupportRecord{Kind: contract.GeneratedHazardSupportKind, RecordID: facts.Hazards[0].Record.HazardID}, &facts.RelatedHazardsCommitment},
			} {
				var err error
				if set.row.Kind == contract.GeneratedAttemptSupportKind {
					set.row.Body, err = contract.EncodeGeneratedAttemptRecord(facts.Effects[0].Record)
				} else {
					set.row.Body, err = contract.EncodeGeneratedHazardRecord(facts.Hazards[0].Record)
				}
				if err != nil {
					t.Fatal("damaged semantic fixture must remain encodable", err)
				}
				descriptor, err := contract.MutationResultRecordDescriptor(set.kind, changed.DomainID, []contract.SupportRecord{set.row})
				if err != nil {
					t.Fatal(err)
				}
				*set.desc = &descriptor
			}
			if _, err := GeneratedCleanupSiblingResults(changed); err == nil {
				t.Fatal("unknown CREATE exception admitted a different effect or source")
			}
		})
	}
}

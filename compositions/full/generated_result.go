package compositionfull

import (
	"encoding/hex"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func RenderGeneratedMutationJSON(r core.PublicApplyResult, operation uint16) ([]byte, error) {
	return renderGeneratedMutation(r, operation, false)
}
func RenderGeneratedMutationHuman(r core.PublicApplyResult, operation uint16) ([]byte, error) {
	return renderGeneratedMutation(r, operation, true)
}

func renderGeneratedMutation(r core.PublicApplyResult, operation uint16, human bool, locations ...*resultStoreLocation) ([]byte, error) {
	var location *resultStoreLocation
	if len(locations) != 0 {
		location = locations[0]
	}
	if location != nil && (r.Generated == nil || !location.validAuthenticatedDomain(r.DomainID, r.Result)) {
		return nil, errApplyResult
	}
	if r.Generated == nil {
		if r.Payload != nil || r.Cleanup != nil || len(r.Receipt) != 0 || r.Result.Outcome == core.ObservedCurrent || r.Result.Outcome == core.Unchanged {
			return nil, errApplyResult
		}
		v, err := transitionResultProjection(r, operation)
		if err != nil {
			return nil, err
		}
		if human {
			return renderTransitionHuman(r, v)
		}
		return renderTransitionResultJSON(v)
	}
	if err := validateGeneratedInvocation(r, operation); err != nil {
		return nil, err
	}
	preparation, err := applyPreparationProjection(r.Preparation)
	if err != nil {
		return nil, err
	}
	g := r.Generated
	if human {
		return renderGeneratedMutationHuman(r, operation, location)
	}
	return renderReadableGeneratedResult(func(w *generatedResultWriter) {
		d := newGeneratedResultDocument(w, false)
		d.field("schema", "ProductResult/v1")
		d.field("operation_kind", generatedOperationName(operation))
		if location != nil {
			d.field("store_location", location.fields())
		}
		d.field("state_result", g.StateResult)
		d.field("effect_summary", generatedEffectSummary(g.EffectSummary))
		d.field("output_summary", "not-applicable")
		d.field("request_id", readerID(r.RequestID))
		d.field("operation_id", readerID(r.OperationID))
		d.field("request_identity", readerID(r.RequestIdentity))
		replay := readerID(r.RequestIdentity)
		if g.StateResult == "no-op" {
			replay = "none"
		}
		d.field("replay_identity", replay)
		d.field("domain_id", readerID(r.DomainID))
		d.field("canonical_outcome", map[uint8]string{contract.ReceiptCanonicalSelected: "selected", contract.ReceiptCanonicalNotSelected: "not-selected"}[g.CanonicalOutcome])
		d.field("requested_revision_id", generatedID(r.Result.RequestedRevision))
		d.field("observed_revision_id", generatedID(r.Result.ObservedRevision))
		d.field("commit_may_have_occurred", r.Result.CommitMayHaveOccurred)
		d.field("evidence_ceiling", generatedEvidence(g.EvidenceCeiling))
		d.field("current_domain_warning_bits", r.WarningBits)
		d.field("effect_warnings", generatedWarnings(g.Warnings))
		d.field("receipt_observation", g.ReceiptObservation)
		if preparation != nil {
			d.field("preparation", preparation)
		}
		if p := r.Payload; p != nil {
			d.field("transition", map[string]any{"schema": "TransitionPayload/v1", "predecessor_revision_id": readerID(p.PredecessorRevisionID), "requested_revision_id": readerID(p.RequestedRevisionID), "observed_revision_id": generatedID(p.ObservedRevisionID), "changed_subject_commitment": map[string]any{"count": p.ChangedSubjects.Count, "identity_root_digest": readerID(p.ChangedSubjects.IdentityRootDigest)}})
			if !g.ReceiptObservation {
				writeGeneratedIDs(d, "current_domain_duty_ids", p.LiveDutyIDs)
				writeGeneratedIDs(d, "current_domain_hazard_ids", p.LiveHazardIDs)
			}
		} else {
			d.field("transition", nil)
		}
		if r.Cleanup != nil {
			d.key("cleanup")
			writeGeneratedCleanup(w, r.Cleanup)
			d.endField()
		} else {
			d.field("cleanup", nil)
		}
		d.field("effects_available", g.EffectsAvailable)
		d.field("effects_commitment", generatedDescriptor(g.EffectsCommitment))
		if g.EffectsAvailable {
			d.array("effects", len(g.Effects), func(i int) { writeGeneratedEffect(w, g.Effects[i]) })
		} else {
			d.field("effects", nil)
		}
		d.field("summary_counts_available", g.SummaryCountsAvailable)
		if g.SummaryCountsAvailable {
			writeGeneratedCounts(d, g.SummaryCounts)
			d.field("deletion_acknowledged_count", g.AcknowledgedCount)
			d.field("invalidation_confirmed_count", g.ConfirmedCount)
			d.field("unknown_count", g.UnknownCount)
		} else {
			d.field("summary_counts", nil)
			d.field("deletion_acknowledged_count", nil)
			d.field("invalidation_confirmed_count", nil)
			d.field("unknown_count", nil)
		}
		d.field("related_work_available", g.RelatedWorkAvailable)
		d.field("related_duties_commitment", generatedDescriptor(g.RelatedDutiesCommitment))
		d.field("related_hazards_commitment", generatedDescriptor(g.RelatedHazardsCommitment))
		if g.RelatedWorkAvailable {
			writeGeneratedIDs(d, "related_duty_ids", g.RelatedDutyIDs)
			writeGeneratedIDs(d, "related_hazard_ids", g.RelatedHazardIDs)
			d.array("duties", len(g.Duties), func(i int) { writeGeneratedDuty(w, g.Duties[i]) })
			d.array("hazards", len(g.Hazards), func(i int) { writeGeneratedHazard(w, g.Hazards[i]) })
		} else {
			d.field("related_duty_ids", nil)
			d.field("related_hazard_ids", nil)
			d.field("duties", nil)
			d.field("hazards", nil)
		}
		d.array("diagnostics", len(r.Diagnostics), func(i int) { v, _ := readerDiagnostic(r.Diagnostics[i]); w.value(v) })
		if len(r.Receipt) != 0 {
			row, _ := contract.InspectCompactMutationReceipt(r.Receipt)
			d.field("receipt_warning_bits", row.WarningBits)
			d.field("receipt_hex", hex.EncodeToString(r.Receipt))
		} else {
			d.field("receipt_hex", nil)
		}
		d.finish()
	})
}

func RenderGeneratedListJSON(r core.PublicGeneratedListResult) ([]byte, error) {
	return renderGeneratedList(r, false, nil, "", nil)
}
func RenderGeneratedListHuman(r core.PublicGeneratedListResult) ([]byte, error) {
	return renderGeneratedList(r, true, nil, "", nil)
}
func renderGeneratedList(r core.PublicGeneratedListResult, human bool, sourceFailure *ConfigurationSourceFailure, sourceStage string, storeLocation *resultStoreLocation) ([]byte, error) {
	if !validGeneratedListSourceFailure(r, sourceFailure, sourceStage) {
		return nil, errApplyResult
	}
	if !storeLocation.valid(r.Context.ExpectedDomain, r.Result) || storeLocation != nil && r.View == nil {
		return nil, errApplyResult
	}
	if err := validateGeneratedList(r); err != nil {
		return nil, err
	}
	if human {
		return renderGeneratedListHuman(r, sourceFailure, storeLocation)
	}
	return renderReadableGeneratedResult(func(w *generatedResultWriter) {
		d := newGeneratedResultDocument(w, false)
		d.field("schema", "ProductResult/v1")
		d.field("operation_kind", "generated-list")
		if storeLocation != nil {
			d.field("store_location", storeLocation.fields())
		}
		if sourceFailure != nil {
			d.field("source_failure", sourceFailure)
		}
		d.field("state_result", r.StateResult)
		d.field("effect_summary", "not-applicable")
		d.field("output_summary", "not-applicable")
		d.field("request_id", readerID(r.Context.RequestID))
		d.field("operation_id", generatedID(r.Context.OperationID))
		d.field("domain_id", generatedID(r.Context.ExpectedDomain))
		d.field("failure_reason", r.FailureReason)
		v := r.View
		if v == nil {
			d.field("view", nil)
			d.finish()
			return
		}
		d.field("observed_revision_id", readerID(v.RevisionID))
		d.field("snapshot_id", readerID(v.SnapshotID))
		d.field("evidence_ceiling", "canonical")
		d.field("current_domain_warning_bits", v.DomainWarningBits)
		d.field("effect_warnings", generatedWarnings(v.Warnings))
		d.field("possible_garbage", v.PossibleGarbage)
		d.array("current_generations", len(v.CurrentGenerations), func(i int) {
			w.value(generatedCurrentGeneration(v.CurrentGenerations[i]))
		})
		if p := v.ActiveOperation; p != nil {
			d.field("active_operation", map[string]any{"operation_id": readerID(p.OperationID), "operation_kind": generatedOperationName(p.OperationKind), "phase_id": readerID(p.PhaseID), "phase": p.Phase, "stage": p.Stage, "frontier_attempt_id": generatedID(p.FrontierAttemptID)})
		} else {
			d.field("active_operation", nil)
		}
		d.array("attempts", len(v.Effects), func(i int) { writeGeneratedEffect(w, v.Effects[i]) })
		d.array("duties", len(v.Duties), func(i int) { writeGeneratedDuty(w, v.Duties[i]) })
		d.array("hazards", len(v.Hazards), func(i int) { writeGeneratedHazard(w, v.Hazards[i]) })
		d.array("pending_releases", len(v.PendingReleases), func(i int) {
			p := v.PendingReleases[i]
			var completion any
			if p.CompletionClass != 0 {
				completion = generatedCompletion(p.CompletionClass)
			}
			w.value(map[string]any{"inbox_id": readerID(p.InboxID), "original_result_id": readerID(p.OriginalResultID), "selected_handoff_digest": readerID(p.SelectedHandoffDigest), "handoff_revision_id": readerID(p.HandoffRevisionID), "state": map[uint8]string{contract.GeneratedReleasePending: "pending", contract.GeneratedReleaseUnknown: "unknown", contract.GeneratedReleaseUnobserved: "unobserved"}[p.State], "object_length": p.ObjectLength, "original_operation_id": readerID(p.OriginalOperationID), "original_attempt_id": readerID(p.OriginalAttemptID), "action": map[uint8]string{contract.GeneratorActionCreate: "create", contract.GeneratorActionDelete: "delete"}[p.Action], "effect_state": generatedEffectState(p.EffectState), "completion_class": completion})
		})
		d.array("next_actions", len(v.NextActions), func(i int) {
			p := v.NextActions[i]
			w.value(map[string]any{"command": p.Command, "operation_id": generatedID(p.OperationID), "duty_id": generatedID(p.DutyID), "attempt_id": generatedID(p.AttemptID)})
		})
		d.finish()
	})
}

func validateGeneratedList(r core.PublicGeneratedListResult) error {
	if r.Context.Operation != core.GeneratedListOperation || !validReaderState(r.StateResult) || r.Context.RequestID.IsZero() {
		return errApplyResult
	}
	if r.StateResult != contract.ReaderSuccess {
		if r.View != nil || r.Result.Outcome == core.ObservedCurrent {
			return errApplyResult
		}
		return nil
	}
	v := r.View
	if v == nil || v.DomainID != r.Context.ExpectedDomain || v.DomainID.IsZero() || v.RevisionID.IsZero() || v.SnapshotID.IsZero() || r.Result.Outcome != core.ObservedCurrent || r.Result.Evidence != core.AuthenticatedClosure || r.Result.CommitMayHaveOccurred || r.Result.ObservedRevision != v.RevisionID || r.Result.ObservedSnapshotID != v.SnapshotID || v.DomainWarningBits & ^uint8(31) != 0 || len(v.CurrentGenerations) > contract.GeneratedCurrentEntryLimit || !validGeneratedFactRows(v.DomainID, v.Effects, v.Duties, v.Hazards) || uint64(len(v.PendingReleases)) > core.GeneratedResultAttemptLimit || uint64(len(v.NextActions)) > 2*core.GeneratedResultWorkLimit+2 {
		return errApplyResult
	}
	for i, p := range v.CurrentGenerations {
		if !boundedReaderText(p.Name, contract.CryptoMaxName) || i > 0 && v.CurrentGenerations[i-1].Name >= p.Name || p.EntryIncarnationID.IsZero() || p.GenerationID.IsZero() || p.OriginOperationID.IsZero() || p.OriginAttemptID.IsZero() || p.ResourceID.IsZero() || p.ConfigContractID.IsZero() {
			return errApplyResult
		}
		switch p.LifecycleMode {
		case contract.GeneratorLifecycleNone:
			if !p.ResourceContractID.IsZero() || !p.ResourceDigest.IsZero() || p.CompletionClass != 0 || p.RetirementMode != 0 {
				return errApplyResult
			}
		case contract.GeneratorLifecycleManaged:
			if p.ResourceContractID.IsZero() || p.ResourceDigest.IsZero() || generatedCompletion(p.CompletionClass) == "" || generatedPlanningPolicy(p.RetirementMode) == nil {
				return errApplyResult
			}
		default:
			return errApplyResult
		}
	}
	if p := v.ActiveOperation; p != nil {
		if p.OperationID.IsZero() || p.PhaseID.IsZero() || generatedOperationName(p.OperationKind) == "" || p.Stage < contract.GeneratedStageRetainedResult || p.Stage > contract.GeneratedStageTerminal {
			return errApplyResult
		}
	}
	if core.ValidateGeneratedPendingResultCleanup(v.DomainID, v.PendingReleases, v.Effects) != nil {
		return errApplyResult
	}
	for _, p := range v.NextActions {
		switch p.Command {
		case "apply":
			if p.OperationID.IsZero() || !p.DutyID.IsZero() || !p.AttemptID.IsZero() {
				return errApplyResult
			}
		case "generated retire":
			if p.OperationID.IsZero() == p.DutyID.IsZero() || !p.AttemptID.IsZero() {
				return errApplyResult
			}
		case "generated cleanup":
			if !p.DutyID.IsZero() || !p.AttemptID.IsZero() {
				return errApplyResult
			}
		case "generated accept-retirement-risk":
			if !p.OperationID.IsZero() || p.DutyID.IsZero() || p.AttemptID.IsZero() {
				return errApplyResult
			}
		default:
			return errApplyResult
		}
	}
	return nil
}

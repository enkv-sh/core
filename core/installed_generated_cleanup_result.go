package core

import (
	"context"
	"fmt"

	"enkv.sh/core/contract"
)

func captureInstalledGeneratedCleanupResult(ctx context.Context, before *StateSession, work *generatedSelection, plan *generatedLifecyclePlan, proposal *generatedReservation, checkpoint *generatedSelectionCheckpoint) (*generatedCleanupResultCapture, error) {
	if before == nil || work == nil || plan == nil || proposal == nil || proposal.state == nil {
		return nil, contract.ErrRecord
	}
	selected, err := proposal.state.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, fmt.Errorf("capture cleanup selected closure: %w", err)
	}
	var attempt generatedAttempt
	var source generatedRecordKey
	scope := generatedInvocationResultScope{OperationKind: contract.OperationCleanOwnedFailureResidue,
		receiptFree: true, EffectClasses: map[contract.ID]int{}, observedEffectClasses: map[contract.ID]int{}}
	switch plan.kind {
	case generatedLifecycleReflection, generatedLifecycleCleanupClose:
		result, err := contract.InspectGeneratedResultRecord(plan.result)
		if err != nil {
			return nil, err
		}
		original, present, err := work.selectGeneratedCleanup(ctx, map[contract.ID][]byte{result.Core.ResultID: plan.result})
		if err != nil || !present || original.kind != generatedCleanupReflection || original.sourceKey().id != plan.owner {
			return nil, contract.ErrRecord
		}
		attempt, source = original.attempt, original.sourceKey()
		scope.OperationID, scope.RequestIdentity = plan.identity.operation, plan.requestIdentity
		scope.OriginalPredecessorRevisionID, scope.effectOperationID = before.head.Core.Revision, attempt.record.OperationID
		if plan.kind == generatedLifecycleCleanupClose {
			scope.EffectClasses[attempt.record.AttemptID], scope.receiptFreeState = contract.ReceiptSummarySuccessCount, "success"
			if attempt.expected.Template.Action == contract.GeneratorActionDelete {
				scope.CompletionClasses = map[contract.ID]uint8{attempt.record.AttemptID: attempt.record.CompletionClass}
			}
		} else if attempt.expected.Template.Action == contract.GeneratorActionCreate {
			scope.EffectClasses[attempt.record.AttemptID], scope.receiptFreeState = contract.ReceiptSummaryFailureCount, "effect-terminal-failure"
		} else {
			scope.EffectClasses[attempt.record.AttemptID], scope.receiptFreeState = contract.ReceiptSummaryPendingCount, "effect-pending"
		}
	case generatedLifecycleOrdinaryCleanupClose, generatedLifecycleOrdinaryCleanupUnknown:
		if work.parent == nil || work.phase == nil || len(work.bundles) == 0 || !installedGeneratedCleanupGraph(work.bundles[0]) ||
			work.phase.FrontierAttemptID != plan.source.AttemptID {
			return nil, contract.ErrRecord
		}
		var present bool
		attempt, present = work.attempts[plan.source.AttemptID]
		if !present {
			return nil, contract.ErrRecord
		}
		owner, err := work.generatedDeleteSource(attempt.record.OwnerID)
		if err != nil || owner.SourceID != plan.owner {
			return nil, contract.ErrRecord
		}
		source = generatedRecordKey{owner.Record.Kind, owner.SourceID}
		scope.OperationID, scope.RequestIdentity = work.parent.OperationID, work.parent.RequestIdentityDigest
		scope.OriginalPredecessorRevisionID = work.bundles[0].Request.PredecessorRevisionID
		class, state := contract.ReceiptSummaryUnknownCount, "effect-unknown"
		if plan.kind == generatedLifecycleOrdinaryCleanupClose {
			if selected.hasRecord(source) {
				class, state = contract.ReceiptSummaryPendingCount, "effect-pending"
				if attempt.record.State == contract.GeneratedEffectFailedTerminal {
					class, state = contract.ReceiptSummaryFailureCount, "effect-terminal-failure"
				}
			} else {
				class, state = contract.ReceiptSummarySuccessCount, "success"
				scope.CompletionClasses = map[contract.ID]uint8{attempt.record.AttemptID: attempt.record.CompletionClass}
			}
		}
		scope.EffectClasses[attempt.record.AttemptID], scope.receiptFreeState = class, state
	default:
		return nil, contract.ErrRecord
	}
	key := generatedRecordKey{contract.GeneratedAttemptSupportKind, attempt.record.AttemptID}
	original, present := work.records[key]
	if !present {
		return nil, contract.ErrRecord
	}
	row, present := selected.records[key]
	if !present {
		return nil, contract.ErrRecord
	}
	scope.observedEffects, scope.Effects = []contract.SupportRecord{original}, []contract.SupportRecord{row}
	scope.observedEffectClasses[attempt.record.AttemptID] = installedGeneratedCleanupObservedClass(attempt.record)
	if source.kind == contract.GeneratedDutySupportKind {
		scope.RelatedDutyIDs = []contract.ID{source.id}
		if row, present := selected.records[source]; present {
			scope.Duties = []contract.SupportRecord{row}
		}
	} else {
		scope.RelatedHazardIDs = []contract.ID{source.id}
		if row, present := selected.records[source]; present {
			scope.Hazards = []contract.SupportRecord{row}
		}
	}
	if checkpoint != nil && checkpoint.valid {
		scope.borrowedObserved = checkpoint.ownedBefore(before, scope.OperationKind, scope.OperationID)
		if scope.borrowedObserved == nil {
			return nil, contract.ErrRecord
		}
	}
	common, err := captureGeneratedInvocationResult(ctx, before, work, scope, proposal)
	if err != nil {
		return nil, fmt.Errorf("capture cleanup Product facts: %w", err)
	}
	kind, reflected := GeneratedCleanupOwnedTarget, []byte(nil)
	if plan.kind == generatedLifecycleReflection || plan.kind == generatedLifecycleCleanupClose {
		kind, reflected = GeneratedCleanupReflection, plan.result
	}
	effect := common.observed.Effects[0]
	if common.selected.Effects[0].Target != nil {
		effect.Target = common.selected.Effects[0].Target
	}
	basis, err := generatedCleanupBasisForEffect(work, kind, source, effect, reflected)
	if err != nil {
		return nil, fmt.Errorf("capture cleanup reflection basis: %w", err)
	}
	capture, err := newGeneratedCleanupResultCapture(ctx, before, work, common, basis, scope.OriginalPredecessorRevisionID, proposal, checkpoint)
	if err != nil {
		return nil, fmt.Errorf("capture cleanup remaining work: %w", err)
	}
	return capture, nil
}

func installedGeneratedCleanupObservedClass(record contract.GeneratedAttemptRecord) int {
	switch record.State {
	case contract.GeneratedEffectSucceeded:
		return contract.ReceiptSummaryPendingCount
	case contract.GeneratedEffectFailedTerminal, contract.GeneratedEffectConfirmedNoEffect:
		return contract.ReceiptSummaryFailureCount
	case contract.GeneratedEffectClosedWithResidue:
		// This invocation reports the exact required original, with no
		// accepted successor frontier that can exclude its uncertainty.
		return contract.ReceiptSummaryUnknownCount
	default:
		return contract.ReceiptSummaryUnknownCount
	}
}

func installedGeneratedCleanupObserved(ctx context.Context, out PublicApplyResult, s *StateSession, work *generatedSelection) PublicApplyResult {
	initialObservation := out.Result.Outcome == 0
	if initialObservation {
		out.Result = refused(AdmissionInvalid)
	}
	graph, err := work.retainedGraph(out.OperationID)
	if err != nil || !installedGeneratedCleanupGraph(graph) {
		out.Result = failure(EvidenceUnavailable, MissingSelectedObject)
		return out
	}
	x := graph.Lineages[0].Templates[0]
	row, present := work.records[generatedRecordKey{contract.GeneratedAttemptSupportKind, x.AttemptID}]
	if !present {
		out.Result = failure(EvidenceUnavailable, MissingSelectedObject)
		return out
	}
	record, err := contract.InspectGeneratedAttemptRecord(row.Body)
	if err != nil || record.OperationID != out.OperationID || record.AttemptID != x.AttemptID {
		return out
	}
	identity, err := contract.GeneratorDeleteReservationRequestID(graph.Header.RequestCoreDigest)
	if err != nil {
		return out
	}
	out.RequestIdentity = identity
	scope := generatedInvocationResultScope{OperationKind: contract.OperationCleanOwnedFailureResidue,
		OperationID: out.OperationID, RequestIdentity: identity, OriginalPredecessorRevisionID: graph.Request.PredecessorRevisionID,
		Effects: []contract.SupportRecord{row}, EffectClasses: map[contract.ID]int{record.AttemptID: installedGeneratedCleanupObservedClass(record)}}
	source, err := work.generatedDeleteSource(record.OwnerID)
	if err != nil {
		out.Result = failure(EvidenceUnavailable, MissingSelectedObject)
		return out
	}
	if source.Record.Kind == contract.GeneratedDutySupportKind {
		scope.RelatedDutyIDs = []contract.ID{source.SourceID}
	} else {
		scope.RelatedHazardIDs = []contract.ID{source.SourceID}
	}
	common, err := captureGeneratedInvocationResult(ctx, s, work, scope, nil)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	basis, err := generatedCleanupBasisForEffect(work, GeneratedCleanupOwnedTarget, generatedRecordKey{source.Record.Kind, source.SourceID}, common.observed.Effects[0], nil)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	capture, err := newGeneratedCleanupResultCapture(ctx, s, work, common, basis, graph.Request.PredecessorRevisionID, nil, nil)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	if initialObservation {
		out.Result = Result{Outcome: ObservedCurrent, Evidence: AuthenticatedClosure, ObservedRevision: s.head.Core.Revision}
	}
	out.Generated, err = capture.observe(ctx, s, out.Result)
	if err != nil {
		out.Generated = nil
	}
	if err == nil {
		capture.attach(&out)
	}
	return out
}

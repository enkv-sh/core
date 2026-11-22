package core

import (
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// ReleaseGeneratedInbox reopens one selected temporary-result obligation.
// The resolution is receipt-free and uses only the Store and normal Trust.
func (e *InstalledApply) ReleaseGeneratedInbox(ctx context.Context, requestID, inboxID contract.ID) PublicApplyResult {
	ctx, preparation := beginApplyPreparation(ctx)
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreGeneratedCleanup)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	var inv installedGeneratedMutation
	out := PublicApplyResult{RequestID: requestID, Result: refused(AdmissionInvalid)}
	if !inboxID.IsZero() {
		callctx := telemetry.CallContext(ctx, call)
		var ready bool
		inv, ready = e.beginInstalledGeneratedMutation(callctx, requestID, contract.OperationCleanOwnedFailureResidue)
		defer inv.close()
		out = inv.out
		if ready {
			out = inv.releaseInbox(callctx, inboxID, call)
		}
	}
	appendApplyInterruptionDiagnostic(ctx, &out)
	finishInstalledGeneratedCleanup(inv.installation, &out)
	preparation.attach(&out)
	finishCore(call, out.Result)
	return out
}

func (inv *installedGeneratedMutation) releaseInbox(ctx context.Context, inboxID contract.ID, call *telemetry.Call) PublicApplyResult {
	s, out := inv.state, inv.out
	if !s.root.Generated.ActiveOwner.IsZero() {
		out.Result = refused(InvalidRelation)
		return out
	}
	admitted, err := installedGeneratedContext(s, inv.deadline)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	var capture *generatedCleanupResultCapture
	var unknownCandidate Candidate
	var unknownBasis GeneratedCleanupWorkBasis
	var unknownWarnings uint8
	clean, unknown, err := s.prepareInboxReleasePlans(ctx, inboxID, admitted, func(work *generatedSelection, plan *generatedLifecyclePlan, proposal *generatedReservation) error {
		qualified, err := inv.captureInboxRelease(ctx, work, plan, proposal)
		if err != nil {
			return err
		}
		if plan.kind == generatedLifecycleInboxRelease {
			capture = qualified
			return nil
		}
		// Unknown changes the release state and revision, but keeps every
		// remaining ID. Verify that invariant before retaining only its
		// candidate identity and the fields that differ from the predecessor.
		before, after := qualified.observedPayload, qualified.selectedPayload
		if !slices.Equal(before.RemainingInboxIDs, after.RemainingInboxIDs) || !slices.Equal(before.RemainingDutyIDs, after.RemainingDutyIDs) || !slices.Equal(before.RemainingHazardIDs, after.RemainingHazardIDs) {
			return contract.ErrRecord
		}
		unknownCandidate, unknownBasis, unknownWarnings = qualified.candidate, after.RemainingWorkBasis, qualified.selectedWarnings
		return nil
	})
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	plan, err := s.observeInboxReleasePlan(ctx, clean, unknown, true)
	var actual *StateSession
	var result Result
	if err != nil {
		// No candidate was selected. Only the authenticated predecessor can
		// supply remaining work for this observation.
		plan, result = clean, installedApplyPreparationFailure(err)
	} else {
		if plan == unknown {
			*capture.selectedPayload = *capture.observedPayload
			capture.selectedPayload.RemainingWorkBasis = unknownBasis
			capture.selected.StateResult = "effect-unknown"
			capture.candidate, capture.selectedWarnings = unknownCandidate, unknownWarnings
		}
		var permit *admittedGeneratedLifecycle
		permit, err = s.admitGeneratedLifecyclePlan(ctx, plan)
		if err != nil {
			result = installedApplyPreparationFailure(err)
		} else {
			var candidate *Candidate
			candidate, result = s.PrepareGeneratedLifecycle(ctx, permit, inv.installation.Trust)
			if candidate != nil {
				call.Checkpoint(telemetry.DiagnosticCommitObservation, telemetry.DiagnosticReasonNone)
				actual, result = s.selectObserved(ctx, candidate)
			}
		}
	}
	out.OperationID, out.RequestIdentity = plan.identity.operation, plan.requestIdentity
	recordInstalledGeneratedCleanupSelection(ctx, &out, actual, result, capture, &generatedSelectionCheckpoint{})
	if plan == unknown && result.Outcome != ObservedCurrent {
		out.Diagnostics = append(out.Diagnostics, contract.Diagnostic{
			Subject: contract.DiagnosticSubject{Kind: contract.SubjectStore}, Path: []contract.DiagnosticField{contract.FieldPresence},
			Outcome: contract.DiagnosticUnable, Reason: contract.ReasonEvidenceUnavailable,
		})
	}
	return out
}

func (inv *installedGeneratedMutation) captureInboxRelease(ctx context.Context, work *generatedSelection, plan *generatedLifecyclePlan, proposal *generatedReservation) (*generatedCleanupResultCapture, error) {
	r, ok := work.releases[plan.source.AttemptID]
	if !ok || r.release.InboxID != plan.owner || r.release.OriginalResultID != plan.target || r.release.SelectedHandoffDigest != plan.evidence {
		return nil, contract.ErrRecord
	}
	scope := generatedInvocationResultScope{OperationKind: contract.OperationCleanOwnedFailureResidue, OperationID: plan.identity.operation, RequestIdentity: plan.requestIdentity,
		OriginalPredecessorRevisionID: plan.predecessorRevision, CanonicalSuccessor: true, receiptFree: true, receiptFreeState: "success"}
	if plan.kind == generatedLifecycleInboxReleaseUnknown {
		scope.receiptFreeState = "effect-unknown"
	}
	common, err := captureGeneratedInvocationResult(ctx, inv.state, work, scope, proposal)
	if err != nil {
		return nil, err
	}
	common.observed.StateResult, common.observed.CanonicalOutcome = "unavailable", contract.ReceiptCanonicalNotSelected
	graph, err := work.retainedGraph(r.attempt.OperationID)
	if err != nil {
		return nil, err
	}
	basis := GeneratedCleanupBasis{Kind: GeneratedCleanupInboxRelease, SourceKind: contract.PendingInboxReleaseSupportKind, SourceID: plan.owner, PlanGraphID: graph.UsePlan.PlanGraphID,
		OriginalOwnerID: r.attempt.OwnerID, OriginalOperationID: r.attempt.OperationID, OriginalAttemptID: r.attempt.AttemptID,
		OriginalResult: &contract.GeneratorResultReference{Schema: 1, ResultID: plan.target, ResultBodyDigest: plan.evidence, ResultLength: r.release.ObjectLength}}
	capture, err := newGeneratedCleanupResultCapture(ctx, inv.state, work, common, basis, plan.predecessorRevision, proposal, nil)
	if err != nil {
		return nil, err
	}
	out := inv.out
	out.OperationID, out.RequestIdentity = scope.OperationID, scope.RequestIdentity
	return capture, capture.prevalidate(out, inv.installation)
}

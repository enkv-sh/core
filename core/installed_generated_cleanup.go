package core

import (
	"context"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

type GeneratedCleanupContinuationRequest struct{ OperationID contract.ID }

func (e *InstalledApply) CleanupGenerated(ctx context.Context, requestID contract.ID) PublicApplyResult {
	ctx, preparation := beginApplyPreparation(ctx)
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreGeneratedCleanup)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	callctx := telemetry.CallContext(ctx, call)
	inv, ready := e.beginInstalledGeneratedMutation(callctx, requestID, contract.OperationCleanOwnedFailureResidue)
	defer inv.close()
	out := inv.out
	if ready {
		out = e.cleanupGenerated(callctx, call, inv)
	}
	appendApplyInterruptionDiagnostic(ctx, &out)
	finishInstalledGeneratedCleanup(inv.installation, &out)
	preparation.attach(&out)
	finishCore(call, out.Result)
	return out
}

func (e *InstalledApply) cleanupGenerated(ctx context.Context, call *telemetry.Call, inv installedGeneratedMutation) PublicApplyResult {
	s, i, out := inv.state, inv.installation, inv.out
	var checkpoint generatedSelectionCheckpoint
	selected, present, err := s.readGeneratedCleanup(ctx)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	work, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	if !present {
		return installedGeneratedCleanupNoOp(ctx, out, s)
	}
	if selected.kind == generatedCleanupReflection {
		return reflectInstalledGeneratedCleanup(ctx, out, s, work, selected, i, inv.deadline, call, &checkpoint)
	}
	plan, err := s.installedGeneratedCleanupPlan(ctx, i, work, selected, inv.deadline)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	out.OperationID = plan.input.graph.Header.OperationID
	var capture *generatedCleanupResultCapture
	p, owner, result := s.prepareInstalledGeneratedDelete(ctx, i, plan, inv.deadline, func(reservation *generatedReservation, attemptID contract.ID) error {
		out.RequestIdentity = reservation.identity.RequestIdentityDigest
		var err error
		capture, err = captureInstalledGeneratedCleanupReservation(ctx, s, work, reservation, attemptID, selected.sourceKey(), selected.target)
		if err != nil {
			return err
		}
		return capture.prevalidate(out, i)
	})
	defer func() {
		if owner != nil {
			owner.Close()
		}
	}()
	if p == nil {
		out.Result = result
		return out
	}
	handoff := p.bindInstalledDelete(owner, &out)
	if handoff == nil {
		return out
	}
	call.Checkpoint(telemetry.DiagnosticCommitObservation, telemetry.DiagnosticReasonNone)
	next, result := s.selectCandidate(ctx, p.reservation.candidate)
	owner.Close()
	owner = nil
	recordInstalledGeneratedCleanupSelection(ctx, &out, next, result, capture, &checkpoint)
	if out.stopForResultPersistence(ctx, handoff.persistence) {
		return out
	}
	if next == nil || result.Outcome != ObservedCurrent {
		return out
	}
	return e.driveInstalledGeneratedCleanup(ctx, out, next, i, inv.deadline, handoff.ambiguity, call, &checkpoint)
}

func (e *InstalledApply) ContinueGeneratedCleanup(ctx context.Context, requestID contract.ID, request GeneratedCleanupContinuationRequest) PublicApplyResult {
	ctx, preparation := beginApplyPreparation(ctx)
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreGeneratedCleanup)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	var inv installedGeneratedMutation
	out := PublicApplyResult{RequestID: requestID, Result: refused(AdmissionInvalid)}
	if !request.OperationID.IsZero() {
		callctx := telemetry.CallContext(ctx, call)
		var ready bool
		inv, ready = e.beginInstalledGeneratedMutation(callctx, requestID, contract.OperationCleanOwnedFailureResidue)
		defer inv.close()
		inv.out.OperationID = request.OperationID
		out = inv.out
		if ready {
			out = e.continueGeneratedCleanup(callctx, request, call, inv)
		}
	}
	appendApplyInterruptionDiagnostic(ctx, &out)
	finishInstalledGeneratedCleanup(inv.installation, &out)
	preparation.attach(&out)
	finishCore(call, out.Result)
	return out
}

func (e *InstalledApply) continueGeneratedCleanup(ctx context.Context, request GeneratedCleanupContinuationRequest, call *telemetry.Call, inv installedGeneratedMutation) PublicApplyResult {
	out := inv.out
	s := inv.state
	work, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	if work.parent == nil {
		// Terminal cleanup has no receipt. Retained original support may still
		// prove an observation; absence never authorizes another target or send.
		out.Result = Result{}
		return installedGeneratedCleanupObserved(ctx, out, s, work)
	}
	if work.parent.OperationID != request.OperationID || len(work.bundles) == 0 || !installedGeneratedCleanupGraph(work.bundles[0]) {
		return out
	}
	out.RequestIdentity = work.parent.RequestIdentityDigest
	out.Result = Result{}
	return e.driveInstalledGeneratedCleanup(ctx, out, s, inv.installation, inv.deadline, nil, call, &generatedSelectionCheckpoint{})
}

func installedGeneratedCleanupGraph(graph contract.GeneratorPlanBundle) bool {
	return graph.Request.OperationKind == contract.OperationCleanOwnedFailureResidue && len(graph.Lineages) == 1 &&
		graph.Lineages[0].Purpose == contract.GeneratorLineageCleanup && graph.Lineages[0].TemplateCount == 1 &&
		graph.Lineages[0].Templates[0].Action == contract.GeneratorActionDelete && graph.Header.TemplateCount == 1
}

func installedGeneratedCleanupNoOp(ctx context.Context, out PublicApplyResult, s *StateSession) PublicApplyResult {
	operation, identity, err := s.installedGeneratedCleanupNoWorkIdentity(ctx)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	empty := contract.EmptyMutationResultDescriptors()
	out.OperationID, out.RequestIdentity = operation, identity
	out.Result = Result{Outcome: Unchanged, Evidence: AuthenticatedClosure, ObservedRevision: s.head.Core.Revision}
	out.Generated = &GeneratedInvocationResult{OperationKind: contract.OperationCleanOwnedFailureResidue,
		StateResult: "no-op", CanonicalOutcome: contract.ReceiptCanonicalNotSelected, EffectSummary: contract.ReceiptEffectNoChange,
		EvidenceCeiling: contract.ReceiptEvidenceCanonical, SummaryCountsAvailable: true, EffectsAvailable: true, RelatedWorkAvailable: true,
		EffectsCommitment: &empty[1], RelatedDutiesCommitment: &empty[3], RelatedHazardsCommitment: &empty[4]}
	work, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	out.Cleanup, err = captureGeneratedCleanupPayload(s, work, GeneratedCleanupBasis{Kind: GeneratedCleanupNoWork}, contract.ID{})
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	out.WarningBits = s.root.WarningBits
	return out
}

package core

import (
	"context"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

type GeneratedRetirementRequest struct{ DutyID contract.ID }
type GeneratedRetirementContinuationRequest struct{ OperationID contract.ID }
type GeneratedRetirementRiskRequest struct{ DutyID, AttemptID contract.ID }

type installedGeneratedMutation struct {
	state        *StateSession
	installation ApplyInstallation
	deadline     time.Time
	out          PublicApplyResult
	finish       func()
}

func (inv *installedGeneratedMutation) close() {
	if inv.finish != nil {
		inv.finish()
		inv.finish = nil
	}
}

// Each operation opens fresh current authority. The installed proposal is not
// compared or replayed for exact retained work.
func (e *InstalledApply) beginInstalledGeneratedMutation(ctx context.Context, requestID contract.ID, kind uint16) (installedGeneratedMutation, bool) {
	inv := installedGeneratedMutation{out: PublicApplyResult{RequestID: requestID, Result: refused(AdmissionInvalid)}}
	if e == nil || ctx == nil || ctx.Err() != nil || requestID.IsZero() || kind != contract.OperationRetireGeneratedGeneration &&
		kind != contract.OperationAcceptGeneratedRetirementResidue && kind != contract.OperationCleanOwnedFailureResidue {
		return inv, false
	}
	deadline, finite := ctx.Deadline()
	if !finite || !validPrivateDeadline(deadline) {
		return inv, false
	}
	e.mu.Lock()
	if e.used || e.closed || e.activeDone != nil {
		e.mu.Unlock()
		return inv, false
	}
	e.used = true
	i := e.installation
	e.installation.PublicConfiguration = contract.PublicConfiguration{}
	done := make(chan struct{})
	e.activeDone = done
	e.mu.Unlock()
	inv.finish = func() { e.mu.Lock(); e.activeDone = nil; close(done); e.mu.Unlock() }
	inv.installation, inv.deadline, inv.out.DomainID = i, deadline, i.ExpectedDomain
	admitted, result := admitBorrowedPublicNormal(ctx, i.ExpectedDomain, i.ExpectedStore, i.PublicBasis, i.Store, i.CompositionID, i.ConfigurationValidator.interpret)
	if result.Outcome != ObservedCurrent {
		inv.out.Result = result
		return inv, false
	}
	inv.state, result = Open(ctx, admitted, i.Store)
	if inv.state == nil {
		inv.out.Result = result
		return inv, false
	}
	inv.out.WarningBits = inv.state.root.WarningBits
	return inv, true
}

func (e *InstalledApply) RetireGenerated(ctx context.Context, requestID contract.ID, request GeneratedRetirementRequest) PublicApplyResult {
	ctx, preparation := beginApplyPreparation(ctx)
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreGeneratedRetire)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	out := e.retireGenerated(telemetry.CallContext(ctx, call), requestID, request, call)
	preparation.attach(&out)
	appendApplyInterruptionDiagnostic(ctx, &out)
	finishCore(call, out.Result)
	return out
}

func (e *InstalledApply) retireGenerated(ctx context.Context, requestID contract.ID, request GeneratedRetirementRequest, call *telemetry.Call) (returned PublicApplyResult) {
	if request.DutyID.IsZero() {
		return PublicApplyResult{RequestID: requestID, Result: refused(AdmissionInvalid)}
	}
	inv, ready := e.beginInstalledGeneratedMutation(ctx, requestID, contract.OperationRetireGeneratedGeneration)
	defer inv.close()
	if !ready {
		return inv.out
	}
	s, i, out := inv.state, inv.installation, inv.out
	defer func() { qualifyGeneratedInvocationResult(i, &returned) }()
	work, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	if i.Generated == nil || i.Generated.NewRetirementReturnProof == nil {
		return out
	}
	proof, err := i.Generated.NewRetirementReturnProof()
	if proof != nil {
		defer proof.Close()
	}
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	if proof == nil || proof.Commitment().IsZero() {
		out.Result = refused(ConstructionMismatch)
		return out
	}
	i.retirementReturn = proof
	plan, err := s.installedGeneratedRetirementPlan(ctx, i, work, request.DutyID, proof.Commitment(), inv.deadline)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	out.OperationID = plan.input.graph.Header.OperationID
	var checkpoint generatedSelectionCheckpoint
	var capture *generatedInvocationResultCapture
	p, owner, result := s.prepareInstalledGeneratedDelete(ctx, i, plan, inv.deadline, func(reservation *generatedReservation, _ contract.ID) error {
		var err error
		capture, err = captureGeneratedSelectionStep(ctx, s, work, reservation, &checkpoint)
		return err
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
	out.RequestIdentity = p.reservation.identity.RequestIdentityDigest
	handoff := p.bindInstalledDelete(owner, &out)
	if handoff == nil {
		return out
	}
	call.Checkpoint(telemetry.DiagnosticCommitObservation, telemetry.DiagnosticReasonNone)
	next, result := s.selectObserved(ctx, p.reservation.candidate)
	owner.Close()
	owner = nil
	recordGeneratedSelection(ctx, &out, next, result, capture, &checkpoint)
	if len(handoff.ambiguity) == 0 || handoff.persistence.Outcome == IntegrityFailure {
		if out.stopForResultPersistence(ctx, handoff.persistence) {
			return out
		}
	}
	if next == nil || result.Outcome != ObservedCurrent {
		return out
	}
	// An unavailable independent record does not prevent the ordinary signed
	// parking transition from preserving the same live, qualified return.
	priorDiagnostics := len(out.Diagnostics)
	out = e.driveInstalledGeneratedRetirement(ctx, out, next, i, inv.deadline, handoff.ambiguity, call, &checkpoint)
	if len(out.Diagnostics) == priorDiagnostics {
		out.stopForResultPersistence(ctx, handoff.persistence)
	}
	return out
}

func (e *InstalledApply) ContinueGeneratedRetirement(ctx context.Context, requestID contract.ID, request GeneratedRetirementContinuationRequest) PublicApplyResult {
	ctx, preparation := beginApplyPreparation(ctx)
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreGeneratedRetire)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	out := e.continueGeneratedRetirement(telemetry.CallContext(ctx, call), requestID, request, call)
	preparation.attach(&out)
	appendApplyInterruptionDiagnostic(ctx, &out)
	finishCore(call, out.Result)
	return out
}

func (e *InstalledApply) continueGeneratedRetirement(ctx context.Context, requestID contract.ID, request GeneratedRetirementContinuationRequest, call *telemetry.Call) (returned PublicApplyResult) {
	if request.OperationID.IsZero() {
		return PublicApplyResult{RequestID: requestID, Result: refused(AdmissionInvalid)}
	}
	inv, ready := e.beginInstalledGeneratedMutation(ctx, requestID, contract.OperationRetireGeneratedGeneration)
	defer inv.close()
	out := inv.out
	out.OperationID = request.OperationID
	if !ready {
		return out
	}
	defer func() { qualifyGeneratedInvocationResult(inv.installation, &returned) }()
	s := inv.state
	row, raw, found, err := s.retainedMutationReceipt(request.OperationID)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	if found {
		if row.OperationKind != contract.OperationRetireGeneratedGeneration {
			return out
		}
		return installedGeneratedReceiptObservation(out, s, row, raw)
	}
	work, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	if work.parent == nil || work.parent.OperationID != request.OperationID || len(work.bundles) == 0 ||
		work.bundles[0].Request.OperationKind != contract.OperationRetireGeneratedGeneration {
		return out
	}
	out.RequestIdentity = work.parent.RequestIdentityDigest
	out.Result = s.observed(ObservedCurrent)
	var checkpoint generatedSelectionCheckpoint
	return e.driveInstalledGeneratedRetirement(ctx, out, s, inv.installation, inv.deadline, nil, call, &checkpoint)
}

package core

import (
	"context"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// AcceptGeneratedRetirementRisk fences one exact retirement using retained
// qualified ambiguity. It constructs no producer or provider request.
func (e *InstalledApply) AcceptGeneratedRetirementRisk(ctx context.Context, requestID contract.ID, request GeneratedRetirementRiskRequest) PublicApplyResult {
	ctx, preparation := beginApplyPreparation(ctx)
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreGeneratedAcceptRetirementRisk)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	out := e.acceptGeneratedRetirementRisk(telemetry.CallContext(ctx, call), requestID, request, call)
	preparation.attach(&out)
	appendApplyInterruptionDiagnostic(ctx, &out)
	finishCore(call, out.Result)
	return out
}

func (e *InstalledApply) acceptGeneratedRetirementRisk(ctx context.Context, requestID contract.ID, request GeneratedRetirementRiskRequest, call *telemetry.Call) (returned PublicApplyResult) {
	if request.DutyID.IsZero() || request.AttemptID.IsZero() {
		return PublicApplyResult{RequestID: requestID, Result: refused(AdmissionInvalid)}
	}
	inv, ready := e.beginInstalledGeneratedMutation(ctx, requestID, contract.OperationAcceptGeneratedRetirementResidue)
	defer inv.close()
	if !ready {
		return inv.out
	}
	s, out := inv.state, inv.out
	defer func() { qualifyGeneratedInvocationResult(inv.installation, &returned) }()
	work, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	row, present := work.records[generatedRecordKey{contract.GeneratedDutySupportKind, request.DutyID}]
	if !present {
		return out
	}
	duty, err := contract.InspectGeneratedDutyRecord(row.Body)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	reader := retirementEvidenceReader{s.admission.store.Prefix, s.storeRead}
	attempt, ambiguity, err := reader.riskAttempt(ctx, work, duty, request.AttemptID)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	if attempt.IsZero() || attempt != request.AttemptID {
		return out
	}
	c, err := installedGeneratedContext(s, inv.deadline)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	plan, err := s.generatedRetirementAmbiguityPlan(ctx, request.DutyID, ambiguity, c, true)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	out.OperationID, out.RequestIdentity = plan.identity.operation, plan.requestIdentity
	var checkpoint generatedSelectionCheckpoint
	return selectInstalledGeneratedRetirementLifecycle(ctx, out, s, work, plan, inv.installation, call, &checkpoint)
}

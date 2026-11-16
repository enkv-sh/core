package core

import (
	"context"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

func (e *InstalledApply) driveInstalledGeneratedCleanup(ctx context.Context, out PublicApplyResult, s *StateSession, i ApplyInstallation, deadline time.Time, ambiguity []byte, call *telemetry.Call, checkpoint *generatedSelectionCheckpoint) PublicApplyResult {
	// One fixed target can adopt its original and then close or park. Each
	// selection has independent owned facts and replaces the invocation checkpoint.
	for stage := 0; stage < 2; stage++ {
		work, err := s.selectedGeneratedWork(ctx)
		if err != nil {
			return cleanupPreparationFailure(ctx, checkpoint, out, err)
		}
		if work.parent == nil || work.phase == nil || work.parent.OperationID != out.OperationID || len(work.bundles) == 0 || !installedGeneratedCleanupGraph(work.bundles[0]) {
			return checkpoint.preparationFailure(ctx, out, refused(InvalidRelation))
		}
		a, found := work.attempts[work.phase.FrontierAttemptID]
		if !found || a.expected.Template.AttemptID != work.bundles[0].Lineages[0].Templates[0].AttemptID {
			return checkpoint.preparationFailure(ctx, out, refused(InvalidRelation))
		}
		out.RequestIdentity = work.parent.RequestIdentityDigest
		c, err := installedGeneratedContext(s, deadline)
		if err != nil {
			return cleanupPreparationFailure(ctx, checkpoint, out, err)
		}
		if a.record.State == contract.GeneratedEffectTransmitted {
			body, present, result := s.ReadGeneratedResult(ctx, a.record.AttemptID)
			if result.Outcome != 0 {
				out = checkpoint.preparationFailure(ctx, out, result)
				return preserveInstalledGeneratedCleanupObserved(ctx, out, s, work, checkpoint)
			}
			if present {
				call.Checkpoint(telemetry.DiagnosticCommitObservation, telemetry.DiagnosticReasonNone)
				next, adopted := s.recordInstalledGeneratedCleanupResult(ctx, i, work, a.record.AttemptID, body, deadline, out, checkpoint)
				out = adopted
				if next == nil || out.Result.Outcome != ObservedCurrent {
					return out
				}
				s = next
				continue
			}
			if len(ambiguity) == 0 {
				return preserveInstalledGeneratedCleanupObserved(ctx, out, s, work, checkpoint)
			}
			plan, err := s.generatedOrdinaryCleanupAmbiguityPlan(ctx, a.record.AttemptID, ambiguity, c)
			if err != nil {
				out = cleanupPreparationFailure(ctx, checkpoint, out, err)
				return preserveInstalledGeneratedCleanupObserved(ctx, out, s, work, checkpoint)
			}
			return selectInstalledGeneratedCleanupLifecycle(ctx, out, s, work, plan, nil, i, call, checkpoint)
		}
		if a.record.State != contract.GeneratedEffectSucceeded && a.record.State != contract.GeneratedEffectFailedTerminal {
			return preserveInstalledGeneratedCleanupObserved(ctx, out, s, work, checkpoint)
		}
		plan, err := s.generatedOrdinaryCleanupClosePlan(ctx, a.record.AttemptID, c)
		if err != nil {
			out = cleanupPreparationFailure(ctx, checkpoint, out, err)
			return preserveInstalledGeneratedCleanupObserved(ctx, out, s, work, checkpoint)
		}
		return selectInstalledGeneratedCleanupLifecycle(ctx, out, s, work, plan, nil, i, call, checkpoint)
	}
	return checkpoint.preparationFailure(ctx, out, refused(CapacityExceeded))
}

func selectInstalledGeneratedCleanupLifecycle(ctx context.Context, out PublicApplyResult, s *StateSession, work *generatedSelection, plan *generatedLifecyclePlan, permit *admittedGeneratedLifecycle, i ApplyInstallation, call *telemetry.Call, checkpoint *generatedSelectionCheckpoint) PublicApplyResult {
	proposal, err := s.deriveGeneratedLifecycle(ctx, plan, nil)
	if err != nil {
		return cleanupPreparationFailure(ctx, checkpoint, out, err)
	}
	capture, err := captureInstalledGeneratedCleanupResult(ctx, s, work, plan, proposal, checkpoint)
	if err != nil {
		return cleanupPreparationFailure(ctx, checkpoint, out, err)
	}
	if err := capture.prevalidate(out, i); err != nil {
		return cleanupPreparationFailure(ctx, checkpoint, out, err)
	}
	if permit == nil {
		permit, err = s.admitGeneratedLifecyclePlan(ctx, plan)
		if err != nil {
			return cleanupPreparationFailure(ctx, checkpoint, out, err)
		}
	}
	candidate, result := s.PrepareGeneratedLifecycle(ctx, permit, i.Trust)
	if candidate == nil {
		if checkpoint.valid {
			return checkpoint.preparationFailure(ctx, out, result)
		}
		out.Result = result
		out.Generated, err = capture.observe(ctx, s, result)
		if err != nil {
			cleanupDeliveryDefect(&out)
			return out
		}
		capture.attach(&out)
		return out
	}
	call.Checkpoint(telemetry.DiagnosticCommitObservation, telemetry.DiagnosticReasonNone)
	next, result := s.selectObserved(ctx, candidate)
	recordInstalledGeneratedCleanupSelection(ctx, &out, next, result, capture, checkpoint)
	return out
}

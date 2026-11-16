package core

import (
	"context"
	"encoding/hex"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

func (s *StateSession) planPublication(ctx context.Context, input publicationInput, private publicationPrivate) (*publicationPlan, Result) {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCorePublicationPlan)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	plan, result := s.preparePublicationPlan(telemetry.CallContext(ctx, call), input, private)
	finishCore(call, result)
	return plan, result
}

func publicationTelemetryDetails(plan *publicationPlan, attempt contract.ID) telemetry.DiagnosticDetails {
	details := telemetry.DiagnosticDetails{}
	if plan != nil && !plan.operation.IsZero() {
		details = details.WithCommandID(hex.EncodeToString(plan.operation[:]))
	}
	if !attempt.IsZero() {
		details = details.WithAttemptID(hex.EncodeToString(attempt[:]))
	}
	return details
}

func (plan *publicationPlan) reserveCandidate(ctx context.Context, s *StateSession, target publicationTargetPlan, action uint8, private publicationPrivate) (*Candidate, *publicationPreparation, Result) {
	var attempt contract.ID
	if index := slices.Index(target.actions, action); index >= 0 && index < len(target.attempts) {
		attempt = target.attempts[index]
	}
	call := telemetry.StartWithDetails(ctx, telemetry.ProviderCore, telemetry.OpCorePublicationPrepareReservation, publicationTelemetryDetails(plan, attempt))
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	candidate, preparation, result := plan.preparePublicationReservation(telemetry.CallContext(ctx, call), s, target, action, private)
	finishCore(call, result)
	return candidate, preparation, result
}

func (plan *publicationPlan) closeCandidate(ctx context.Context, s *StateSession, preparation *publicationPreparation, wire contract.PublicationResult) (*Candidate, Result) {
	var attempt contract.ID
	if preparation != nil {
		attempt = preparation.original.marker.AttemptID
	}
	call := telemetry.StartWithDetails(ctx, telemetry.ProviderCore, telemetry.OpCorePublicationPrepareClose, publicationTelemetryDetails(plan, attempt))
	call.Checkpoint(telemetry.DiagnosticCommitObservation, telemetry.DiagnosticReasonNone)
	candidate, result := plan.preparePublicationClose(telemetry.CallContext(ctx, call), s, preparation, wire)
	finishCore(call, result)
	return candidate, result
}

func (plan *publicationPlan) execute(ctx context.Context, private publicationPrivate, current publicationCurrent) publicationOperationResult {
	call := telemetry.StartWithDetails(ctx, telemetry.ProviderCore, telemetry.OpCorePublicationExecute, publicationTelemetryDetails(plan, contract.ID{}))
	call.Checkpoint(telemetry.DiagnosticCommitObservation, telemetry.DiagnosticReasonNone)
	result := plan.executePublication(telemetry.CallContext(ctx, call), private, current)
	finishPublication(call, result)
	return result
}

func finishPublication(call *telemetry.Call, result publicationOperationResult) {
	if result.state.Reason == CustodyUnavailable {
		call.FinishReason(telemetry.ResultFailure, telemetry.DiagnosticReasonCustodyUnavailable)
		return
	}
	// A current selected state can contain an unresolved publication. Its vector,
	// rather than the successful state observation, owns the effect outcome.
	if result.summary == contract.PublicationSummaryUnknown {
		reason := coreDiagnosticReason(result.state.Reason)
		if reason == telemetry.DiagnosticReasonNone {
			reason = telemetry.DiagnosticReasonUncertain
		}
		call.FinishReason(telemetry.ResultUnknown, reason)
		return
	}
	terminalFailure := result.summary == contract.PublicationSummaryMixedTerminal
	if result.summary == contract.PublicationSummaryFailed {
		for _, entry := range result.output.Entries {
			for _, action := range entry.Actions {
				terminalFailure = terminalFailure || action.Disposition == contract.PublicationOutcomeQualifiedNoEffect
			}
		}
	}
	// Mixed results and qualified no-effect results are operation failures even
	// when the last Core action refused admission. Entirely not-sent work retains
	// its expected Core admission refusal.
	if terminalFailure {
		call.FinishReason(telemetry.ResultFailure, coreDiagnosticReason(result.state.Reason))
		return
	}
	if result.state.Outcome != ObservedCurrent && result.state.Outcome != Unchanged {
		finishCore(call, result.state)
		return
	}
	switch result.summary {
	case contract.PublicationSummaryNoChange:
		call.Finish(telemetry.ResultUnchanged)
	case contract.PublicationSummaryComplete:
		call.Finish(telemetry.ResultWriteAcknowledged)
	case contract.PublicationSummaryMixedTerminal, contract.PublicationSummaryFailed:
		call.Finish(telemetry.ResultFailure)
	default:
		call.FinishReason(telemetry.ResultInvalid, telemetry.DiagnosticReasonInvalidRelation)
	}
}

package core

import (
	"context"
	"encoding/hex"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

func startGeneratedCore(ctx context.Context, operation telemetry.Operation, stage telemetry.DiagnosticStage) (context.Context, *telemetry.Call) {
	return startGeneratedCoreDetails(ctx, operation, stage, telemetry.DiagnosticDetails{})
}

func startGeneratedCoreDetails(ctx context.Context, operation telemetry.Operation, stage telemetry.DiagnosticStage, details telemetry.DiagnosticDetails) (context.Context, *telemetry.Call) {
	call := telemetry.StartWithDetails(ctx, telemetry.ProviderCore, operation, details)
	call.Checkpoint(stage, telemetry.DiagnosticReasonNone)
	if ctx != nil {
		ctx = telemetry.CallContext(ctx, call)
	}
	return ctx, call
}

func generatedAttemptDetails(id contract.ID) telemetry.DiagnosticDetails {
	if id.IsZero() {
		return telemetry.DiagnosticDetails{}
	}
	return (telemetry.DiagnosticDetails{}).WithAttemptID(hex.EncodeToString(id[:]))
}

// PrepareGeneratedPlan uses an opaque private admission to prepare a generated plan.
func (s *StateSession) PrepareGeneratedPlan(ctx context.Context, permit *admittedGeneratedPlan) (*generatedPreparation, Result) {
	ctx, call := startGeneratedCore(ctx, telemetry.OpCoreGeneratedPreparePlan, telemetry.DiagnosticAdmission)
	preparation, result := s.prepareGeneratedPlan(ctx, permit)
	finishCore(call, result)
	return preparation, result
}

// PrepareGeneratedProducer prepares one selected generated attempt.
func (s *StateSession) PrepareGeneratedProducer(ctx context.Context, permit *admittedGeneratedProducer) (*generatedPreparation, Result) {
	details := telemetry.DiagnosticDetails{}
	if permit != nil {
		details = generatedAttemptDetails(permit.attempt)
	}
	ctx, call := startGeneratedCoreDetails(ctx, telemetry.OpCoreGeneratedPrepareProducer, telemetry.DiagnosticAdmission, details)
	preparation, result := s.prepareGeneratedProducer(ctx, permit)
	finishCore(call, result)
	return preparation, result
}

// PrepareGeneratedOriginalProducer prepares one independent original Attempt.
func (s *StateSession) PrepareGeneratedOriginalProducer(ctx context.Context, permit *admittedGeneratedProducer) (*generatedPreparation, Result) {
	details := telemetry.DiagnosticDetails{}
	if permit != nil {
		details = generatedAttemptDetails(permit.attempt)
	}
	ctx, call := startGeneratedCoreDetails(ctx, telemetry.OpCoreGeneratedPrepareProducer, telemetry.DiagnosticAdmission, details)
	preparation, result := s.prepareGeneratedOriginalProducer(ctx, permit)
	finishCore(call, result)
	return preparation, result
}

// PrepareGeneratedRecord adopts one sealed generated result.
func (s *StateSession) PrepareGeneratedRecord(ctx context.Context, permit *admittedGeneratedRecord) (*generatedPreparation, Result) {
	details := telemetry.DiagnosticDetails{}
	if permit != nil && permit.plan != nil {
		details = generatedAttemptDetails(permit.plan.expected.Template.AttemptID)
	}
	ctx, call := startGeneratedCoreDetails(ctx, telemetry.OpCoreGeneratedPrepareRecord, telemetry.DiagnosticAdmission, details)
	preparation, result := s.prepareGeneratedRecord(ctx, permit)
	finishCore(call, result)
	return preparation, result
}

// PrepareGeneratedFinal prepares the final candidate from generated outputs.
func (s *StateSession) PrepareGeneratedFinal(ctx context.Context, permit *admittedGeneratedFinal) (*generatedPreparation, Result) {
	ctx, call := startGeneratedCore(ctx, telemetry.OpCoreGeneratedPrepareFinal, telemetry.DiagnosticAdmission)
	preparation, result := s.prepareGeneratedFinal(ctx, permit)
	finishCore(call, result)
	return preparation, result
}

// PrepareGeneratedCreateResidue binds a residue fence to current authority.
func (s *StateSession) PrepareGeneratedCreateResidue(ctx context.Context, permit *admittedGeneratedCreateResidue, trust contract.Trust) (*Candidate, Result) {
	ctx, call := startGeneratedCore(ctx, telemetry.OpCoreGeneratedPrepareCreateResidue, telemetry.DiagnosticAdmission)
	candidate, result := s.prepareGeneratedCreateResidue(ctx, permit, trust)
	finishCore(call, result)
	return candidate, result
}

// PrepareGeneratedLifecycle prepares one effect-free lifecycle candidate.
func (s *StateSession) PrepareGeneratedLifecycle(ctx context.Context, permit *admittedGeneratedLifecycle, trust contract.Trust) (*Candidate, Result) {
	ctx, call := startGeneratedCore(ctx, telemetry.OpCoreGeneratedPrepareLifecycle, telemetry.DiagnosticAdmission)
	candidate, result := s.prepareGeneratedLifecycle(ctx, permit, trust)
	finishCore(call, result)
	return candidate, result
}

// PrepareGeneratedSuccessorReservation fixes a successor to selected state.
func (s *StateSession) PrepareGeneratedSuccessorReservation(ctx context.Context, permit *admittedGeneratedSuccessorReservation) (*generatedPreparation, Result) {
	ctx, call := startGeneratedCore(ctx, telemetry.OpCoreGeneratedPrepareSuccessorReservation, telemetry.DiagnosticAdmission)
	preparation, result := s.prepareGeneratedSuccessorReservation(ctx, permit)
	finishCore(call, result)
	return preparation, result
}

// ClaimGeneratedPreparation attaches a privately prepared candidate.
func (s *StateSession) ClaimGeneratedPreparation(ctx context.Context, candidate *Candidate, trust contract.Trust) (*Candidate, Result) {
	ctx, call := startGeneratedCore(ctx, telemetry.OpCoreGeneratedClaimPreparation, telemetry.DiagnosticAdmission)
	claimed, result := s.claimGeneratedPreparationAttached(ctx, candidate, trust)
	finishCore(call, result)
	return claimed, result
}

// ClaimGeneratedOriginalProducer claims one independent original producer.
func (s *StateSession) ClaimGeneratedOriginalProducer(ctx context.Context, preparation *generatedPreparation) (*Candidate, Result) {
	ctx, call := startGeneratedCore(ctx, telemetry.OpCoreGeneratedClaimDetachedProducer, telemetry.DiagnosticAdmission)
	candidate, result := s.claimGeneratedOriginalProducer(ctx, preparation)
	finishCore(call, result)
	return candidate, result
}

// ClaimGeneratedOriginalSet attaches the complete set of original producers.
func (s *StateSession) ClaimGeneratedOriginalSet(ctx context.Context, producers []*generatedPreparation, trust contract.Trust) (*Candidate, Result) {
	ctx, call := startGeneratedCore(ctx, telemetry.OpCoreGeneratedClaimOriginalSet, telemetry.DiagnosticAdmission)
	candidate, result := s.claimGeneratedOriginalSet(ctx, producers, trust)
	finishCore(call, result)
	return candidate, result
}

// ReadGeneratedResult reads one selected attempt's fixed result inbox.
func (s *StateSession) ReadGeneratedResult(ctx context.Context, attempt contract.ID) ([]byte, bool, Result) {
	ctx, call := startGeneratedCoreDetails(ctx, telemetry.OpCoreGeneratedReadResult, telemetry.DiagnosticStateLoading, generatedAttemptDetails(attempt))
	body, found, result := s.readGeneratedResult(ctx, attempt)
	call.OutputBytes(int64(len(body)))
	if result.Outcome != 0 {
		finishCore(call, result)
	} else if found {
		call.Finish(telemetry.ResultReadOK)
	} else {
		call.Finish(telemetry.ResultReadMissing)
	}
	return body, found, result
}

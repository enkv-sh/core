package core

import (
	"context"
	"time"

	"enkv.sh/core/contract"
)

func (s *StateSession) admitGeneratedLifecyclePlan(ctx context.Context, plan *generatedLifecyclePlan) (*admittedGeneratedLifecycle, error) {
	if s == nil || plan == nil || s.prepared || !s.admission.valid(s.store) || plan.context.Expiry > uint64(1<<63-1) {
		return nil, contract.ErrRecord
	}
	deadline := time.Unix(0, int64(plan.context.Expiry))
	if !validPrivateDeadline(deadline) {
		return nil, contract.ErrRecord
	}
	if plan.kind == generatedLifecycleReflection || plan.kind == generatedLifecycleCleanupClose {
		if ctx == nil {
			return nil, contract.ErrRecord
		}
		ctx, cancel := context.WithDeadline(ctx, deadline)
		defer cancel()
		first, err := s.generatedReflectionIsFirst(ctx, plan)
		if err != nil {
			return nil, err
		}
		if !first {
			return nil, contract.ErrRecord
		}
	}
	reservation, err := s.deriveGeneratedLifecycle(ctx, plan, nil)
	if err != nil {
		return nil, err
	}
	// Admission derives the complete selected image before any private Crypto
	// call. Guard its exact Root, including all index shards and receipt pages.
	if reservation == nil || !ordinaryCandidateCapacity(reservation.candidate) {
		return nil, contract.ErrRecordCapacity
	}
	return &admittedGeneratedLifecycle{session: s, plan: plan, trust: s.admission.trust,
		family: s.admission.store.Family, deadline: deadline}, nil
}

func (s *StateSession) admitGeneratedOrdinaryCleanupClose(ctx context.Context, attemptID contract.ID, admitted contract.ApplyContext) (*admittedGeneratedLifecycle, error) {
	plan, err := s.generatedOrdinaryCleanupClosePlan(ctx, attemptID, admitted)
	if err != nil {
		return nil, err
	}
	return s.admitGeneratedLifecyclePlan(ctx, plan)
}

func (s *StateSession) admitGeneratedOrdinaryCleanupUnknown(ctx context.Context, attemptID contract.ID, ambiguity []byte,
	admitted contract.ApplyContext) (*admittedGeneratedLifecycle, error) {
	plan, err := s.generatedOrdinaryCleanupAmbiguityPlan(ctx, attemptID, ambiguity, admitted)
	if err != nil {
		return nil, err
	}
	return s.admitGeneratedLifecyclePlan(ctx, plan)
}

func (s *StateSession) admitGeneratedActiveRetirementResidue(ctx context.Context, dutyID contract.ID, ambiguity []byte,
	admitted contract.ApplyContext) (*admittedGeneratedLifecycle, error) {
	plan, err := s.generatedRetirementAmbiguityPlan(ctx, dutyID, ambiguity, admitted, true)
	if err != nil {
		return nil, err
	}
	return s.admitGeneratedLifecyclePlan(ctx, plan)
}

func (s *StateSession) admitGeneratedRetirementUnknown(ctx context.Context, dutyID contract.ID, ambiguity []byte,
	admitted contract.ApplyContext) (*admittedGeneratedLifecycle, error) {
	plan, err := s.generatedRetirementAmbiguityPlan(ctx, dutyID, ambiguity, admitted, false)
	if err != nil {
		return nil, err
	}
	return s.admitGeneratedLifecyclePlan(ctx, plan)
}

func (s *StateSession) admitGeneratedReflection(ctx context.Context, resultID contract.ID, result []byte,
	admitted contract.ApplyContext, crypto contract.Crypto) (*admittedGeneratedLifecycle, error) {
	plan, err := s.generatedReflectionPlan(ctx, resultID, result, admitted)
	if err != nil {
		return nil, err
	}
	permit, err := s.admitGeneratedLifecyclePlan(ctx, plan)
	if err != nil {
		return nil, err
	}
	if crypto == nil || crypto.InstanceID().IsZero() {
		return nil, contract.ErrRecord
	}
	q, _, err := s.generatedOriginalVerificationRequest(ctx, plan)
	if err != nil {
		return nil, err
	}
	permit.crypto, permit.instance, permit.verification = crypto, crypto.InstanceID(), q
	return permit, nil
}

func (s *StateSession) admitGeneratedRetirementClose(ctx context.Context, attemptID contract.ID,
	admitted contract.ApplyContext) (*admittedGeneratedLifecycle, error) {
	plan, err := s.generatedRetirementClosePlan(ctx, attemptID, admitted)
	if err != nil {
		return nil, err
	}
	return s.admitGeneratedLifecyclePlan(ctx, plan)
}

func (s *StateSession) admitGeneratedInboxRelease(ctx context.Context, inboxID contract.ID,
	admitted contract.ApplyContext) (*admittedGeneratedLifecycle, error) {
	if s == nil || !s.admission.valid(s.store) {
		return nil, contract.ErrRecord
	}
	plan, err := s.generatedInboxReleasePlan(ctx, inboxID, admitted)
	if err != nil {
		return nil, err
	}
	return s.admitGeneratedLifecyclePlan(ctx, plan)
}

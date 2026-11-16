package crypto

import (
	"context"
	"sync"
	"time"

	"enkv.sh/core/contract"
)

// This state owns fixed public bindings, the original authority guard and the
// joined failure category.
// It retains no admission, Runtime, producer, seed, process or input backing.
type generatedLocalFailureBinding struct {
	domain, operation, request, graph, usePlan, material, resultUse, attempt contract.ID
}

type generatedLocalFailureOutcome struct {
	mu                           sync.Mutex
	binding                      generatedLocalFailureBinding
	reason                       uint8
	guard                        generatedLocalFailureGuard
	joined, recorded, busy, used bool
}

type generatedLocalFailureGuard struct {
	callerDone <-chan struct{}
	deadline   time.Time
}

func (g generatedLocalFailureGuard) live() bool {
	if !time.Now().Before(g.deadline) {
		return false
	}
	select {
	case <-g.callerDone:
		return false
	default:
		return true
	}
}

// enter is called only after the original return owner is registered.
func (s *generatedLocalFailureOutcome) enter(callerDone <-chan struct{}, deadline time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.guard = generatedLocalFailureGuard{callerDone: callerDone, deadline: deadline}
	s.mu.Unlock()
}

type generatedLocalFailureAdmission struct {
	guard               generatedLocalFailureGuard
	attempt             contract.GeneratedAttemptRecord
	beforePhase         contract.GeneratedPhaseRecord
	beforeSliceSnapshot contract.ID
	prepared            bool
}

func newGeneratedLocalFailureOutcome(a *generatedAdmission) *generatedLocalFailureOutcome {
	if a == nil || a.purpose.producer == nil || a.purpose.producer.producer == nil {
		return nil
	}
	p := a.purpose.producer.producer
	x, v := p.expected.Template, p.attempt
	if x.Schema != contract.GeneratorAttemptTemplateSchema || x.LifecycleMode != contract.GeneratorLifecycleNone ||
		x.Action != contract.GeneratorActionCreate || x.Branch != contract.GeneratorBranchInitial ||
		v.Schema != contract.GeneratedAttemptRecordSchema || v.LifecycleMode != contract.GeneratorLifecycleNone ||
		v.State != contract.GeneratedEffectTransmitted || v.Stage != contract.GeneratedStageRetainedResult || v.FailureReason != 0 || !v.PredecessorAttemptID.IsZero() {
		return nil
	}
	body, err := contract.EncodeGeneratedAttemptRecord(v)
	if err != nil {
		return nil
	}
	material, err := contract.OperationMaterialContextDigest(a.material.Core)
	if err != nil {
		return nil
	}
	use, err := contract.GeneratorResultUseDigest(p.expected.Use)
	if err != nil {
		return nil
	}
	return &generatedLocalFailureOutcome{binding: generatedLocalFailureBinding{
		domain: v.DomainID, operation: v.OperationID, request: a.request.Parent.RequestIdentityDigest,
		graph: p.expected.Plan.PlanGraphID, usePlan: a.request.UsePlanDigest, material: material, resultUse: use, attempt: contract.Hash(body)}}
}

func generatedLocalFailureReason(category generatedFailureCategory) uint8 {
	switch category {
	case generatedFailureInvalid:
		return contract.GeneratorFailureInvalid
	case generatedFailureUnavailable:
		return contract.GeneratorFailureUnavailable
	case generatedFailureCancelled:
		return contract.GeneratorFailureCancelled
	case generatedFailureExpired:
		return contract.GeneratorFailureExpired
	case generatedFailureProtocol:
		return contract.GeneratorFailureProtocol
	default:
		return 0
	}
}

func (s *generatedLocalFailureOutcome) record(out generatedProducerOutput, settled bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.recorded {
		return
	}
	s.recorded = true
	if settled && out.code != contract.CryptoSuccess && len(out.Record) == 0 {
		s.reason = generatedLocalFailureReason(out.category)
	}
}

func (s *generatedLocalFailureOutcome) closeJoined() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.joined = true
	s.mu.Unlock()
}

func (s *generatedLocalFailureOutcome) failureReason() uint8 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.joined || s.used || !s.guard.live() {
		return 0
	}
	return s.reason
}

// GeneratedLocalFailureAdmitter is a receiver-bound private capability. Its
// public arguments do not prove producer entry, joining or publication state.
type GeneratedLocalFailureAdmitter func(context.Context, *Runtime, contract.CryptoGeneratedCompareRequest, contract.ControlCore, GeneratedCustodyConstruction, contract.GeneratedLocalFailureInput, time.Time) (*GeneratedCustody, error)

func (c *GeneratedCustody) LocalFailureAdmission() (func() uint8, GeneratedLocalFailureAdmitter) {
	if c == nil || c.localFailure == nil {
		return nil, nil
	}
	s := c.localFailure
	return s.failureReason, s.admit
}

func (s *generatedLocalFailureOutcome) admit(ctx context.Context, r *Runtime, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, construction GeneratedCustodyConstruction, input contract.GeneratedLocalFailureInput, deadline time.Time) (*GeneratedCustody, error) {
	if ctx == nil || ctx.Err() != nil || r == nil || s.failureReason() == 0 {
		return nil, ErrAdmission
	}
	if input.Session.SelectionPhase == nil {
		return nil, ErrAdmission
	}
	beforePhase := *input.Session.SelectionPhase
	session, err := r.generatedInstalledSession(q, control, construction, input.Session, input.Plan)
	if err != nil {
		return nil, err
	}
	private := generatedAdoptionAdmissionInput{Session: session, Plan: generatedInstalledPlan(input.Plan), Phase: input.Phase,
		Material: input.Custody.Material, SeedAccess: input.Custody.SeedAccess, SourceProtections: input.Custody.SourceProtections}
	return s.admitOwned(ctx, r, q, private, input.Attempt, beforePhase, input.BeforeSliceSnapshot, deadline)
}

func generatedLocalTerminalAttempt(v contract.GeneratedAttemptRecord) bool {
	n, err := contract.GeneratedAttemptRecordLength(v)
	return err == nil && n == contract.GeneratedAttemptRecordFixedLength && v.Schema == contract.GeneratedAttemptRecordSchema && v.LifecycleMode == contract.GeneratorLifecycleNone &&
		v.State == contract.GeneratedEffectFailedTerminal && v.Stage == contract.GeneratedStageTerminal && v.RetryUsed == 0 && v.PredecessorAttemptID.IsZero() &&
		v.FailureReason >= contract.GeneratorFailureInvalid && v.FailureReason <= contract.GeneratorFailureProtocol && v.Facts == contract.EmptyGeneratorVector(contract.GeneratorVectorFacts)
}

func (b generatedLocalFailureBinding) matches(q contract.CryptoGeneratedCompareRequest, input generatedAdoptionAdmissionInput, attempt contract.GeneratedAttemptRecord) bool {
	if !generatedLocalTerminalAttempt(attempt) || q.Purpose != contract.CryptoGeneratedAdoptionPurpose || input.ControlledPredecessor != nil || input.Target != nil ||
		input.Result != (generatedResultAdmission{}) || q.Context.DomainID != b.domain || q.Parent.DomainID != b.domain || q.Parent.OperationID != b.operation ||
		q.Parent.RequestIdentityDigest != b.request || q.Parent.PlanGraphID != b.graph || q.UsePlanDigest != b.usePlan ||
		input.Phase.TransitionKind != contract.GeneratorAuthorityFailedTerminal {
		return false
	}
	material, err := contract.OperationMaterialContextDigest(input.Material.Core)
	if err != nil || material != b.material {
		return false
	}
	body, err := contract.EncodeGeneratedAttemptRecord(attempt)
	if err != nil || input.Phase.Evidence != (contract.GeneratorDescriptor{Digest: contract.Hash(body), Length: contract.GeneratedAttemptRecordFixedLength, Count: 1}) {
		return false
	}
	attempt.State, attempt.Stage, attempt.FailureReason = contract.GeneratedEffectTransmitted, contract.GeneratedStageRetainedResult, 0
	original, err := contract.EncodeGeneratedAttemptRecord(attempt)
	return err == nil && contract.Hash(original) == b.attempt
}

func (s *generatedLocalFailureOutcome) admitOwned(ctx context.Context, r *Runtime, q contract.CryptoGeneratedCompareRequest, input generatedAdoptionAdmissionInput, attempt contract.GeneratedAttemptRecord, beforePhase contract.GeneratedPhaseRecord, beforeSliceSnapshot contract.ID, deadline time.Time) (owner *GeneratedCustody, err error) {
	if s == nil || r == nil || ctx == nil || ctx.Err() != nil || beforeSliceSnapshot.IsZero() {
		return nil, ErrAdmission
	}
	s.mu.Lock()
	if !s.joined || !s.guard.live() || deadline.After(s.guard.deadline) || q.Context.Expiry > uint64(s.guard.deadline.UnixNano()) || s.reason == 0 || s.reason != attempt.FailureReason || s.used || s.busy || !s.binding.matches(q, input, attempt) {
		s.mu.Unlock()
		return nil, ErrAdmission
	}
	s.busy = true
	binding, guard := s.binding, s.guard
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.busy = false
		if err == nil && owner != nil {
			s.used = true
		}
		s.mu.Unlock()
	}()
	failure := &generatedLocalFailureAdmission{guard: guard, attempt: attempt, beforePhase: beforePhase, beforeSliceSnapshot: beforeSliceSnapshot}
	owner, err = newGeneratedCustody(r, func() (*generatedAdmission, error) {
		return r.admitGeneratedAdoptionState(q, input, failure, &binding, deadline)
	})
	if err == nil && (ctx.Err() != nil || !guard.live()) {
		owner.Close()
		return nil, ErrAdmission
	}
	return owner, err
}

func generatedFailureSupportFact(a *generatedAdmission, kind uint8, id contract.ID) (contract.SupportRecordDigest, bool) {
	if a.purpose.output == nil {
		return contract.SupportRecordDigest{}, false
	}
	var found contract.SupportRecordDigest
	count := 0
	for _, fact := range a.purpose.output.Rows.Facts {
		if fact.Kind() == kind && fact.RecordID() == id {
			found = fact
			count++
		}
	}
	return found, count == 1
}

func (f *generatedLocalFailureAdmission) matchesAdmission(a *generatedAdmission, b generatedLocalFailureBinding) bool {
	v := f.attempt
	phase := &f.beforePhase
	if phase.Phase != a.purpose.adoption.phase.BeforePhase || phase.DomainID != v.DomainID || phase.OperationID != v.OperationID ||
		phase.PlanGraphID != b.graph || phase.UsePlanDigest != b.usePlan || phase.FrontierAttemptID != v.AttemptID || phase.Stage != contract.GeneratedStageRetainedResult ||
		!phase.AcceptedResultID.IsZero() || !phase.ResultDigest.IsZero() || phase.Branch != contract.GeneratorBranchInitial || phase.NoEffectUsed != 0 || phase.ResidueUsed != 0 ||
		int(phase.LineageIndex) >= len(a.graph.Lineages) || a.graph.Lineages[phase.LineageIndex].LineageID != v.LineageID {
		return false
	}
	phaseBody, err := contract.EncodeGeneratedPhaseRecord(*phase)
	if err != nil {
		return false
	}
	phaseFact, ok := generatedFailureSupportFact(a, contract.GeneratedPhaseSupportKind, v.OperationID)
	if !ok || phaseFact.BodyLength() != uint32(len(phaseBody)) || phaseFact.BodyDigest() != contract.Hash(phaseBody) {
		return false
	}
	attemptFact, ok := generatedFailureSupportFact(a, contract.GeneratedAttemptSupportKind, v.AttemptID)
	if !ok || attemptFact.BodyLength() != contract.GeneratedAttemptRecordFixedLength || attemptFact.BodyDigest() != b.attempt {
		return false
	}
	if _, present := generatedFailureSupportFact(a, contract.GeneratedResultSupportKind, v.ResultID); present {
		return false
	}
	duty, ok := generatedFailureSupportFact(a, contract.GeneratedDutySupportKind, v.OwnerID)
	if !ok || duty.BodyLength() != contract.GeneratedDutyRecordFixedLength {
		return false
	}
	for _, lineage := range a.graph.Lineages {
		if lineage.Purpose != contract.GeneratorLineageCreate || lineage.TemplateCount != 1 {
			continue
		}
		x := lineage.Templates[0]
		if x.AttemptID != v.AttemptID {
			continue
		}
		if x.Schema != contract.GeneratorAttemptTemplateSchema || x.LifecycleMode != contract.GeneratorLifecycleNone || x.Branch != 0 || x.Action != contract.GeneratorActionCreate ||
			!generatedUncertainAttemptMatches(v, x, a.graph.Header.DomainID, a.graph.Header.OperationID) {
			return false
		}
		for _, use := range a.graph.ResultUses {
			if use.AttemptID == v.AttemptID {
				digest, err := contract.GeneratorResultUseDigest(use)
				return err == nil && digest == b.resultUse
			}
		}
	}
	return false
}

func (a *generatedAdmission) prepareLocalFailure(q contract.CryptoGeneratedLocalFailureRequest, out *contract.CryptoResponse) contract.CryptoResultCode {
	state := a.purpose.adoption
	if state == nil || state.localFailure == nil || state.localFailure.prepared || q.AttemptID != state.localFailure.attempt.AttemptID || q.Reason != state.localFailure.attempt.FailureReason {
		return contract.CryptoInvalidAdmission
	}
	state.localFailure.prepared = true
	out.Body = []byte{byte(contract.CryptoGeneratedPrepareLocalFailure)}
	a.stage = contract.CryptoFreeze
	return contract.CryptoSuccess
}

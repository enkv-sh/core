package core

import (
	"bytes"
	"context"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type admittedGeneratedRecord struct {
	observation *operationObservation
	session     *StateSession
	plan        *generatedRecordPlan
	crypto      contract.Crypto
	instance    contract.ID
	deadline    time.Time
	used        bool
}

type generatedResultWrite struct {
	attempt contract.ID
	body    []byte
}

// PrepareGeneratedRecord uses an opaque private admission to adopt one sealed
// generated result into the selected closure.
func (s *StateSession) prepareGeneratedRecord(ctx context.Context, permit *admittedGeneratedRecord) (*generatedPreparation, Result) {
	if s == nil || ctx == nil || s.prepared || !s.admission.valid(s.store) || permit == nil || permit.used || permit.session != s || permit.plan == nil ||
		permit.crypto == nil || permit.instance.IsZero() || permit.crypto.InstanceID() != permit.instance || !validPrivateDeadline(permit.deadline) ||
		permit.plan.request.Context.Expiry != uint64(permit.deadline.UnixNano()) {
		return nil, refused(AdmissionInvalid)
	}
	permit.used = true
	if ctx.Err() != nil {
		return nil, refused(AdmissionInvalid)
	}
	reservation, err := s.deriveGeneratedRecord(ctx, permit.plan)
	if err != nil {
		if result, ok := selectedReadResult(err); ok {
			return nil, result
		}
		return nil, refused(InvalidRelation)
	}
	bindingWork, bindingErr := s.selectedGeneratedWork(ctx)
	if bindingErr != nil {
		return nil, installedApplyPreparationFailure(bindingErr)
	}
	bindings, err := s.generatedBindings(bindingWork)
	if err != nil {
		return nil, refused(InvalidRelation)
	}
	q := permit.plan.request
	body, err := contract.EncodeCryptoGeneratedCompareRequest(q)
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	selected, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		if result, ok := selectedReadResult(err); ok {
			return nil, result
		}
		return nil, refused(InvalidRelation)
	}
	currentOpens, err := selected.continuationCurrentOpens(ctx)
	if err != nil {
		if result, ok := selectedReadResult(err); ok {
			return nil, result
		}
		return nil, refused(InvalidRelation)
	}
	s.prepared = true
	source := generatedExchangeSource(q)
	source.PhaseID, source.AttemptID = mustGeneratedPhaseID(permit.plan.phase), permit.plan.expected.Template.AttemptID
	p := &generatedPreparation{reservation: reservation,
		producerPhase: new(contract.GeneratorPhaseIdentity),
		operation: &cryptoOperation{observation: permit.observation, source: source, adapter: permit.crypto, instance: permit.instance, context: q.Context, deadline: permit.deadline,
			authority: s.admission.recipient, bindings: bindings, sourceCount: 1 + currentOpens}}
	if permit.plan.failureReason == 0 {
		p.results = []contract.GeneratorResultReference{permit.plan.reference}
		p.resultWrites = []generatedResultWrite{{attempt: permit.plan.expected.Template.AttemptID, body: bytes.Clone(permit.plan.result)}}
	}
	*p.producerPhase = permit.plan.phase
	if permit.plan.expected.Template.CompletionClass == contract.GeneratedCompletionConfirmed && permit.plan.expected.Template.Action == contract.GeneratorActionDelete {
		g, err := s.selectedGeneratedWork(ctx)
		if err != nil {
			if result, ok := selectedReadResult(err); ok {
				return nil, result
			}
			return nil, refused(AdmissionInvalid)
		}
		source, err := g.generatedDeleteSource(permit.plan.expected.Template.DutyID)
		if err != nil {
			return nil, refused(AdmissionInvalid)
		}
		progress, err := g.controlledDeleteSourceProgress(source, nil, true)
		if err != nil {
			return nil, refused(AdmissionInvalid)
		}
		if len(progress.rows) != 0 {
			p.operation.sourceCount++
		}
	}
	// Recording a completed result or failure has no pending-key reads.
	reply, res := p.exchange(ctx, contract.CryptoCompare, body)
	if res.Outcome != 0 {
		return nil, res
	}
	compared, err := contract.InspectCryptoGeneratedCompareResult(reply.Body)
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	p.operation.operationRef, p.operation.sourceCount = compared.OperationRef, 0
	if permit.plan.failureReason != 0 {
		body, err = contract.EncodeCryptoGeneratedLocalFailureRequest(contract.CryptoGeneratedLocalFailureRequest{OperationRef: compared.OperationRef, Context: q.Context, AttemptID: permit.plan.expected.Template.AttemptID, Reason: permit.plan.failureReason})
	} else {
		body, err = contract.EncodeCryptoGeneratedAdoptRequest(contract.CryptoGeneratedAdoptRequest{OperationRef: compared.OperationRef, Context: q.Context, Result: permit.plan.result, ExpectedResult: permit.plan.phase.Evidence})
	}
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	reply, res = p.exchange(ctx, contract.CryptoPrepare, body)
	if res.Outcome != 0 {
		return nil, res
	}
	if permit.plan.failureReason != 0 {
		if !bytes.Equal(reply.Body, []byte{9}) {
			return nil, refused(AdmissionInvalid)
		}
	} else {
		adopted, err := contract.InspectCryptoGeneratedAdoptResult(reply.Body)
		if err != nil || !bytes.Equal(adopted.Result, permit.plan.result) {
			return nil, refused(AdmissionInvalid)
		}
	}
	reservation.candidate.bindObservation(permit.observation, source)
	reservation.candidate.generated = &generatedCandidateFacts{reservation: reservation}
	reservation.candidate.producer = p
	return p, s.observed(ObservedCurrent)
}

func (s *StateSession) generatedResultCoordinate(ctx context.Context, attempt contract.ID) (string, generatedAttempt, error) {
	if s == nil || !s.admission.valid(s.store) {
		return "", generatedAttempt{}, contract.ErrRecord
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return "", generatedAttempt{}, err
	}
	a, ok := g.attempts[attempt]
	if !ok {
		return "", generatedAttempt{}, contract.ErrRecord
	}
	key, err := format.GeneratedResultKey(s.admission.store.Prefix, s.root.Domain, a.record.InboxID)
	return key, a, err
}

// ReadGeneratedResult reads the fixed result inbox for one selected Attempt.
// Missing and unavailable are distinct. Neither creates evidence of no effect
// or removes the selected inbox root.
func (s *StateSession) readGeneratedResult(ctx context.Context, attempt contract.ID) ([]byte, bool, Result) {
	if ctx == nil {
		return nil, false, refused(AdmissionInvalid)
	}
	key, a, err := s.generatedResultCoordinate(ctx, attempt)
	if err != nil {
		if result, ok := selectedReadResult(err); ok {
			return nil, false, result
		}
		return nil, false, refused(AdmissionInvalid)
	}
	if ctx.Err() != nil {
		return nil, false, failure(EvidenceUnavailable, ReadUnavailable)
	}
	read := s.storeRead(ctx, key, uint32(contract.GeneratedResultRecordMaxLength))
	if read.Status == contract.ReadMissing {
		return nil, false, Result{}
	}
	if read.Status == contract.ReadInvalid {
		return nil, false, failure(IntegrityFailure, InvalidFormat)
	}
	if read.Status != contract.ReadOK {
		return nil, false, unavailableStoreRead(read)
	}
	result, err := contract.DecodeGeneratedResultRecord(read.Body)
	if err != nil || contract.ValidateGeneratedResult(a.expected, a.material, result) != nil || len(a.result) != 0 && !bytes.Equal(a.result, read.Body) {
		return nil, false, failure(IntegrityFailure, InvalidRelation)
	}
	return read.Body, true, Result{}
}

func (s *StateSession) persistGeneratedResult(ctx context.Context, result generatedResultWrite) Result {
	if ctx == nil {
		return refused(AdmissionInvalid)
	}
	key, a, err := s.generatedResultCoordinate(ctx, result.attempt)
	if err != nil {
		if result, ok := selectedReadResult(err); ok {
			return result
		}
		return refused(AdmissionInvalid)
	}
	r, err := contract.DecodeGeneratedResultRecord(result.body)
	if err != nil || contract.ValidateGeneratedResult(a.expected, a.material, r) != nil {
		return refused(InvalidRelation)
	}
	if ctx.Err() != nil {
		return failure(EvidenceUnavailable, ReadUnavailable)
	}
	frozen := bytes.Clone(result.body)
	return s.persistImmutable(ctx, key, frozen, uint32(contract.GeneratedResultRecordMaxLength))
}

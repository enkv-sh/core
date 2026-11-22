package core

import (
	"bytes"
	"context"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func retirementAmbiguityKey(prefix string, a generatedAttempt) (string, error) {
	id, err := contract.GeneratorRetirementAmbiguityID(a.record.InboxID)
	if err != nil {
		return "", err
	}
	return format.GeneratedResultKey(prefix, a.record.DomainID, id)
}

func (g *generatedSelection) retirementAmbiguityFacts(a generatedAttempt, body []byte) ([]byte, error) {
	if g == nil || g.parent == nil || g.phase == nil || len(g.bundles) == 0 || g.phase.FrontierAttemptID != a.record.AttemptID || a.record.OperationID != g.parent.OperationID || a.record.State != contract.GeneratedEffectTransmitted || a.record.Stage != contract.GeneratedStageRetainedResult || len(a.result) != 0 {
		return nil, contract.ErrRecord
	}
	graph := g.bundles[0]
	if graph.Request.OperationKind != contract.OperationRetireGeneratedGeneration || graph.Header.OperationID != a.record.OperationID {
		return nil, contract.ErrRecord
	}
	v, err := contract.InspectRetirementAmbiguity(body)
	if err != nil || !v.Verify(graph.Request.CallerNonce, a.record.DomainID, a.record.OperationID, a.record.AttemptID, a.record.InboxID, a.expected.Plan.PlanGraphID) {
		return nil, contract.ErrRecord
	}
	facts, err := inspectRetirementAttemptFacts(v.Facts, a)
	if err != nil || facts.RetirementRejected {
		return nil, contract.ErrRecord
	}
	return v.Facts, nil
}

func (s *StateSession) persistRetirementAmbiguity(ctx context.Context, attempt contract.ID, returned contract.GeneratedProducerResult) Result {
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return installedApplyPreparationFailure(err)
	}
	a := g.attempts[attempt]
	facts, err := g.retirementAmbiguityFacts(a, returned.RetirementAmbiguity)
	original, encodeErr := contract.EncodeGeneratorSafeFacts(returned.Facts)
	if err != nil || encodeErr != nil || !bytes.Equal(facts, original) {
		return failure(IntegrityFailure, InvalidRelation)
	}
	key, err := retirementAmbiguityKey(s.admission.store.Prefix, a)
	if err != nil {
		return refused(InvalidRelation)
	}
	return s.persistImmutable(ctx, key, returned.RetirementAmbiguity, contract.RetirementAmbiguityMaxLength)
}

type retirementEvidenceReader struct {
	prefix string
	read   func(context.Context, string, uint32) contract.ReadResult
}

func (r retirementEvidenceReader) load(ctx context.Context, g *generatedSelection, a generatedAttempt) ([]byte, error) {
	if r.read == nil {
		return nil, contract.ErrRecord
	}
	key, err := retirementAmbiguityKey(r.prefix, a)
	if err != nil {
		return nil, err
	}
	read := r.read(ctx, key, contract.RetirementAmbiguityMaxLength)
	switch read.Status {
	case contract.ReadMissing:
		return nil, nil
	case contract.ReadOK:
		facts, err := g.retirementAmbiguityFacts(a, read.Body)
		if err != nil {
			return nil, selectedReadFailure(failure(IntegrityFailure, InvalidRelation))
		}
		return bytes.Clone(facts), nil
	case contract.ReadInvalid:
		return nil, selectedReadFailure(failure(IntegrityFailure, InvalidFormat))
	default:
		return nil, selectedReadFailure(unavailableStoreRead(read))
	}
}

// A terminal packet takes precedence over separate Unknown evidence. Even a
// malformed terminal packet prevents accepting risk from the independent note.
func (r retirementEvidenceReader) activeRiskFacts(ctx context.Context, g *generatedSelection, a generatedAttempt) ([]byte, error) {
	body, err := r.load(ctx, g, a)
	if err != nil || len(body) == 0 {
		return nil, err
	}
	facts, err := contract.InspectGeneratorSafeFacts(body)
	if err != nil {
		return nil, err
	}
	if facts.Reason == contract.GeneratorReasonIdentityConflict || !generatedResourceFactsMatch(facts.GeneratorSafeFacts, a.expected.TargetResourceDigest) {
		return nil, nil
	}
	key, err := format.GeneratedResultKey(r.prefix, a.record.DomainID, a.record.InboxID)
	if err != nil {
		return nil, err
	}
	read := r.read(ctx, key, uint32(contract.GeneratedResultRecordMaxLength))
	switch read.Status {
	case contract.ReadMissing:
		return body, nil
	case contract.ReadOK:
		v, err := contract.DecodeGeneratedResultRecord(read.Body)
		if err != nil || contract.ValidateGeneratedResult(a.expected, a.material, v) != nil {
			return nil, selectedReadFailure(failure(IntegrityFailure, InvalidRelation))
		}
		return nil, nil
	case contract.ReadInvalid:
		return nil, selectedReadFailure(failure(IntegrityFailure, InvalidFormat))
	default:
		return nil, selectedReadFailure(unavailableStoreRead(read))
	}
}

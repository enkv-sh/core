package core

import (
	"context"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

func Initialize(ctx context.Context, admitted InitContext, store contract.Store, normal, recovery contract.QualifyingTrust, crypto contract.Crypto) (*StateSession, Result) {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreInitialize)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	if ctx == nil || ctx.Err() != nil {
		result := refused(AdmissionInvalid)
		finishCore(call, result)
		return nil, result
	}
	ctx = telemetry.CallContext(ctx, call)
	session, result := initialize(ctx, admitted, store, normal, recovery, crypto)
	finishCore(call, result)
	return session, result
}

func Open(ctx context.Context, admitted OpenContext, store contract.Store) (*StateSession, Result) {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreOpen)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	if ctx == nil || ctx.Err() != nil {
		result := refused(AdmissionInvalid)
		finishCore(call, result)
		return nil, result
	}
	ctx = telemetry.CallContext(ctx, call)
	session, result := open(ctx, admitted, store)
	finishCore(call, result)
	return session, result
}

func (s *StateSession) Compare(ctx context.Context, input []ApplyEntryInput, parent *AdmittedParentComparison) (*Comparison, Result) {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreCompare)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	if ctx == nil || ctx.Err() != nil {
		result := refused(AdmissionInvalid)
		finishCore(call, result)
		return nil, result
	}
	ctx = telemetry.CallContext(ctx, call)
	if call != nil {
		for _, value := range input {
			call.InputBytes(int64(len(value.InputBytes)))
		}
	}
	comparison, result := s.compare(ctx, input, parent)
	finishCore(call, result)
	return comparison, result
}

func (s *StateSession) Prepare(ctx context.Context, c *Comparison, permit *AdmittedParentTransition, trust contract.Trust) (*Candidate, Result) {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCorePrepare)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	if ctx == nil || ctx.Err() != nil {
		result := refused(AdmissionInvalid)
		finishCore(call, result)
		return nil, result
	}
	ctx = telemetry.CallContext(ctx, call)
	candidate, result := s.prepare(ctx, c, permit, trust)
	finishCore(call, result)
	return candidate, result
}

func (s *StateSession) Select(ctx context.Context, candidate *Candidate) Result {
	_, result := s.selectObserved(ctx, candidate)
	return result
}

func (s *StateSession) selectObserved(ctx context.Context, candidate *Candidate) (*StateSession, Result) {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreSelect)
	call.Checkpoint(telemetry.DiagnosticCommitObservation, telemetry.DiagnosticReasonNone)
	if ctx == nil || ctx.Err() != nil {
		result := refused(AdmissionInvalid)
		if s.candidateObservationReady(candidate) {
			candidate.offerSelection(ctx, result)
		}
		finishCore(call, result)
		return nil, result
	}
	ctx = telemetry.CallContext(ctx, call)
	selected, result := s.selectCandidate(ctx, candidate)
	finishCore(call, result)
	return selected, result
}

func finishCore(call *telemetry.Call, result Result) {
	if call == nil {
		return
	}
	label := telemetry.ResultUnknown
	switch result.Outcome {
	case Unchanged:
		label = telemetry.ResultUnchanged
	case ObservedCurrent:
		label = telemetry.ResultObservedCurrent
	case Contention:
		label = telemetry.ResultContention
	case UnresolvedCommit:
		label = telemetry.ResultUnresolvedCommit
	case IntegrityFailure:
		label = telemetry.ResultIntegrityFailure
	case EvidenceUnavailable:
		label = telemetry.ResultEvidenceUnavailable
	case RootLossUnsupported:
		label = telemetry.ResultRootLossUnsupported
	case AdmissionRefused:
		label = telemetry.ResultAdmissionRefused
	}
	call.FinishReason(label, coreDiagnosticReason(result.Reason))
}

func coreDiagnosticReason(reason Reason) telemetry.DiagnosticReason {
	switch reason {
	case NoReason:
		return telemetry.DiagnosticReasonNone
	case AdmissionInvalid:
		return telemetry.DiagnosticReasonAdmissionInvalid
	case ConstructionMismatch:
		return telemetry.DiagnosticReasonConstructionMismatch
	case InvalidFormat:
		return telemetry.DiagnosticReasonInvalidFormat
	case InvalidProof:
		return telemetry.DiagnosticReasonInvalidProof
	case InvalidReference:
		return telemetry.DiagnosticReasonInvalidReference
	case InvalidRelation:
		return telemetry.DiagnosticReasonInvalidRelation
	case MissingSelectedObject:
		return telemetry.DiagnosticReasonMissingSelectedObject
	case ReadUnavailable:
		return telemetry.DiagnosticReasonReadUnavailable
	case ImmutableConflict:
		return telemetry.DiagnosticReasonImmutableConflict
	case CapacityExceeded:
		return telemetry.DiagnosticReasonCapacityExceeded
	case InvalidIntent, StaleGeneratedEpoch, GeneratedIntentConflict:
		return telemetry.DiagnosticReasonInvalidIntent
	case SigningUnavailable:
		return telemetry.DiagnosticReasonSigningUnavailable
	case WriteUncertain:
		return telemetry.DiagnosticReasonWriteUncertain
	case StalePrecondition:
		return telemetry.DiagnosticReasonStalePrecondition
	case DifferentSelection:
		return telemetry.DiagnosticReasonDifferentSelection
	case AlreadyUsed:
		return telemetry.DiagnosticReasonAlreadyUsed
	case CustodyUnavailable:
		return telemetry.DiagnosticReasonCustodyUnavailable
	default:
		return telemetry.DiagnosticReasonInvalid
	}
}

// These helpers observe the actual Store/Trust calls, including exact readbacks.
// Cache hits do not become Store reads. Construction or resource identities do
// not enter labels; provider work has its own distinct operation names.
func (s *StateSession) storeReadOnce(ctx context.Context, key string, limit uint32) contract.ReadResult {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreStoreRead)
	ctx = telemetry.CallContext(ctx, call)
	call.Checkpoint(telemetry.DiagnosticStateLoading, telemetry.DiagnosticReasonNone)
	result := s.store.Read(ctx, key, limit)
	if call != nil {
		call.OutputBytes(int64(len(result.Body)))
		label := telemetry.ResultUnknown
		switch result.Status {
		case contract.ReadOK:
			label = telemetry.ResultReadOK
		case contract.ReadMissing:
			label = telemetry.ResultReadMissing
		case contract.ReadUnavailable:
			label = telemetry.ResultReadUnavailable
		case contract.ReadInvalid:
			label = telemetry.ResultReadInvalid
		}
		call.Finish(label)
	}
	return result
}

func (s *StateSession) storeCreate(ctx context.Context, key string, body []byte) contract.WriteResult {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreStoreCreate)
	ctx = telemetry.CallContext(ctx, call)
	call.Checkpoint(telemetry.DiagnosticCandidatePersistence, telemetry.DiagnosticReasonNone)
	result := s.store.Create(ctx, key, body)
	if result.Status == contract.WritePrecondition {
		call.InputBytes(int64(len(body)))
		call.Finish(telemetry.ResultVerificationPending)
	} else {
		finishWrite(call, len(body), result)
	}
	return result
}

func (s *StateSession) storeCreateHead(ctx context.Context, request contract.HeadCreateRequest) contract.WriteResult {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreStoreCreateHead)
	ctx = telemetry.CallContext(ctx, call)
	call.Checkpoint(telemetry.DiagnosticCandidatePersistence, telemetry.DiagnosticReasonNone)
	result := s.store.CreateHead(ctx, request)
	finishWrite(call, int(request.Length()), result)
	return result
}

func (s *StateSession) storeCompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreStoreCompareAndSwap)
	ctx = telemetry.CallContext(ctx, call)
	call.Checkpoint(telemetry.DiagnosticCommitObservation, telemetry.DiagnosticReasonNone)
	result := s.store.CompareAndSwap(ctx, key, token, body)
	finishWrite(call, len(body), result)
	return result
}

func finishWrite(call *telemetry.Call, bytes int, result contract.WriteResult) {
	if call == nil {
		return
	}
	call.InputBytes(int64(bytes))
	label := telemetry.ResultUnknown
	switch result.Status {
	case contract.WriteAcknowledged:
		label = telemetry.ResultWriteAcknowledged
	case contract.WritePrecondition:
		label = telemetry.ResultWritePrecondition
	case contract.WriteConflict:
		label = telemetry.ResultWriteConflict
	case contract.WriteUnknown:
		label = telemetry.ResultWriteUnknown
	case contract.WriteRefused:
		label = telemetry.ResultWriteRefused
	}
	call.Finish(label)
}

func (s *StateSession) trustSign(ctx context.Context, trust contract.Trust, request contract.SignRequest) contract.SignResult {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreTrustSign)
	ctx = telemetry.CallContext(ctx, call)
	call.Checkpoint(telemetry.DiagnosticProviderCall, telemetry.DiagnosticReasonNone)
	result := trust.Sign(ctx, request)
	if call != nil {
		call.InputBytes(int64(len(request.Digest())))
		call.OutputBytes(int64(len(result.Signature)))
		label := telemetry.ResultSignUnavailable
		if result.Reason == contract.ReasonNone && len(result.Signature) != 0 {
			label = telemetry.ResultSignOK
		}
		if result.Reason == contract.ReasonProof || result.Reason == contract.ReasonMalformed {
			label = telemetry.ResultSignInvalid
		}
		call.Finish(label)
	}
	return result
}

package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/telemetry"
)

func (s *StateSession) signSuccession(ctx context.Context, trust contract.Trust, binding contract.PublicSigningBinding, q contract.SignRequest) ([]byte, Result) {
	if ctx == nil || ctx.Err() != nil || !s.admission.valid(s.store) || trust == nil || trust.Family() != binding.Provider || trust.Identity() != binding.Binding.Trust {
		return nil, refused(AdmissionInvalid)
	}
	key, ok := publicKey(binding.SPKI)
	if !ok || !q.Valid() {
		return nil, refused(InvalidProof)
	}
	result := s.trustSign(ctx, trust, q)
	if ctx.Err() != nil {
		return nil, failure(EvidenceUnavailable, SigningUnavailable)
	}
	if result.Reason == contract.ReasonProof || result.Reason == contract.ReasonMalformed || result.Reason == contract.ReasonNone && !verify(key, q, result.Signature) {
		return nil, failure(IntegrityFailure, InvalidProof)
	}
	if result.Reason != contract.ReasonNone {
		return nil, failure(EvidenceUnavailable, SigningUnavailable)
	}
	return bytes.Clone(result.Signature), Result{}
}

func (s *StateSession) qualifySuccessionSigner(ctx context.Context, request contract.SuccessionRequestCore, row contract.SuccessionReplacementRow, trust contract.QualifyingTrust, used map[contract.ID]bool) (contract.SuccessorEvidenceRow, Result) {
	var evidence contract.SuccessorEvidenceRow
	binding := row.AfterSigning
	if ctx.Err() != nil || !s.admission.valid(s.store) || trust == nil || trust.Family() != binding.Provider || trust.Identity() != binding.Binding.Trust {
		return evidence, refused(AdmissionInvalid)
	}
	digest, err := contract.SigningBindingDigest(binding)
	if err != nil {
		return evidence, refused(InvalidProof)
	}
	qualified := trust.QualifySigningBinding(ctx, binding)
	if ctx.Err() != nil || qualified.Qualified == 0 && (qualified.Reason == contract.ReasonAccess || qualified.Reason == contract.ReasonTransport || qualified.Reason == contract.ReasonLimit) {
		return evidence, failure(EvidenceUnavailable, SigningUnavailable)
	}
	if qualified.Qualified != 1 || qualified.Reason != contract.ReasonNone || qualified.TargetRole != row.TargetRole || qualified.SigningBindingDigest != digest || qualified.Provider != binding.Provider {
		return evidence, failure(IntegrityFailure, InvalidProof)
	}
	entropy := s.admission.entropy
	if entropy == nil {
		entropy = rand.Reader
	}
	var attempt contract.ID
	if _, err := io.ReadFull(entropy, attempt[:]); err != nil || attempt.IsZero() || used[attempt] {
		return evidence, refused(AdmissionInvalid)
	}
	used[attempt] = true
	requestDescriptor, err := contract.SuccessionRequestDescriptor(request)
	if err != nil {
		return evidence, refused(AdmissionInvalid)
	}
	probe, err := contract.NewSuccessorSignerProbeRequest(contract.SuccessorProbeCore{Schema: 1, EvidenceKind: contract.SuccessorSignerEvidence, TargetRole: row.TargetRole, DomainID: request.DomainID, CoordinateID: request.CoordinateID, AdmissionID: request.AdmissionID, PredecessorFullHEADDigest: request.PredecessorFullHEADDigest, RequestCoreDigest: requestDescriptor.Digest, SuccessorBindingDigest: digest, ProbeAttemptID: attempt})
	if err != nil {
		return evidence, refused(InvalidProof)
	}
	proof, res := s.signSuccession(ctx, trust, binding, probe)
	if res.Outcome != 0 {
		return evidence, res
	}
	return contract.SuccessorEvidenceRow{TargetRole: row.TargetRole, EvidenceKind: contract.SuccessorSignerEvidence, Trust: contract.SuccessorTrustEvidence{SuccessorSignerFields: contract.SuccessorSignerFields{ProbeAttemptID: attempt, SigningBindingDigest: digest}, Signature: proof}}, Result{}
}

func (s *StateSession) PrepareSuccession(ctx context.Context, permit *AdmittedSuccession, signers SuccessionSigners) (*Candidate, Result) {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCorePrepareSuccession)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	candidate, result := s.prepareSuccession(ctx, permit, signers, call)
	finishCore(call, result)
	return candidate, result
}

func (s *StateSession) prepareSuccession(ctx context.Context, permit *AdmittedSuccession, signers SuccessionSigners, call *telemetry.Call) (*Candidate, Result) {
	if ctx == nil || ctx.Err() != nil {
		return nil, refused(AdmissionInvalid)
	}
	ctx = telemetry.CallContext(ctx, call)
	if s == nil || permit == nil || permit.used || permit.session != s || ctx == nil || ctx.Err() != nil {
		return nil, refused(AdmissionInvalid)
	}
	if permit.goal != nil {
		if !permit.goal.deadline.Equal(permit.deadline) {
			return nil, refused(AdmissionInvalid)
		}
		changed, observation := s.compareAuthorityGoal(ctx, permit.goal)
		if permit.observation.enabled() && (observation.Outcome == ObservedCurrent || observation.Outcome == Unchanged) {
			permit.observation.offerChange(ctx, changeObservation{Source: observationSource{Stage: observationComparison}, Result: observation})
		}
		if observation.Outcome != ObservedCurrent {
			if observation.Outcome == Unchanged {
				permit.used = true
			}
			return nil, observation
		}
		g := permit.goal.goal
		if changed != permit.request.ChangeMask || g.ApprovalRole != permit.request.ApprovalRole || g.Signing != nil && !signingGoalMatches(*g.Signing, permit.request.ProposedAfterControl.NormalSigning, g, s.admission.store.Family) || g.KMS != nil && !kmsGoalMatches(*g.KMS, permit.request.ProposedAfterControl.AuthorityKMSBinding, s.admission.store.Family) {
			return nil, refused(AdmissionInvalid)
		}
	}
	if !validPrivateDeadline(permit.deadline) {
		return nil, refused(AdmissionInvalid)
	}
	preparationContext, cancel := context.WithDeadline(ctx, permit.deadline)
	defer cancel()
	if err := s.successionRequestValid(preparationContext, permit.request, permit.plan); err != nil {
		if result, ok := selectedReadResult(err); ok {
			return nil, result
		}
		return nil, refused(AdmissionInvalid)
	}
	request := permit.request
	descriptor, err := contract.SuccessionRequestDescriptor(request)
	if err != nil || descriptor != permit.descriptor {
		return nil, refused(AdmissionInvalid)
	}
	subjects, err := contract.SuccessionChangedSubjectDescriptor(request)
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	projected, err := s.projectedSuccessionRoot(preparationContext, request, permit.plan, subjects)
	if errors.Is(err, contract.ErrRecordCapacity) {
		return nil, refused(CapacityExceeded)
	}
	if err != nil {
		if result, ok := selectedReadResult(err); ok {
			return nil, result
		}
		return nil, refused(AdmissionInvalid)
	}
	if _, err := format.EncodeRoot(projected); err != nil {
		return nil, refused(CapacityExceeded)
	}
	if permit.observation.enabled() {
		detail, err := successionObservation(request)
		if err != nil {
			permit.observation.reject(ctx)
		} else {
			detail.Source.Stage = observationComparison
			permit.observation.offerChange(ctx, detail)
		}
	}
	q, rows, err := s.successionAccessRequest(preparationContext, request, permit.plan, permit.context, permit.source)
	if err != nil {
		if result, ok := selectedReadResult(err); ok {
			return nil, result
		}
		return nil, refused(AdmissionInvalid)
	}
	if q.Context != permit.context || permit.context.Expiry != uint64(permit.deadline.UnixNano()) {
		return nil, refused(AdmissionInvalid)
	}
	authorizer := request.BeforeControl.NormalSigning
	if request.ApprovalRole == contract.RecoverySigningRole {
		if request.BeforeControl.Recovery == nil {
			return nil, refused(AdmissionInvalid)
		}
		authorizer = request.BeforeControl.Recovery.Signing
	}
	if signers.Authorizer == nil || signers.Authorizer.Identity() != authorizer.Binding.Trust || signers.Authorizer.Family() != authorizer.Provider {
		return nil, refused(AdmissionInvalid)
	}
	target, _, rewrap := successionTarget(request)
	used, err := s.closureIDsMode(preparationContext, signerOnlyRecovery(request))
	if err != nil {
		if result, ok := selectedReadResult(err); ok {
			return nil, result
		}
		return nil, refused(AdmissionInvalid)
	}
	for _, id := range []contract.ID{request.OperationID, request.AdmissionID, request.IdentityPlan.Snapshot, request.IdentityPlan.Revision, request.IdentityPlan.Transition} {
		used[id] = true
	}
	for _, page := range request.IdentityPlan.Pages {
		used[page.Object] = true
	}
	for _, row := range request.ReplacementPlan.Rows {
		used[row.AfterKMS.BindingID] = true
		used[row.AfterSigning.BindingID] = true
	}
	if rewrap {
		probe := permit.probe
		digest, err := contract.PublicBindingDigest(target.Binding)
		if err != nil || probe.Context != q.Context || probe.SubjectKind != target.SubjectKind || probe.SubjectID != target.SubjectID || probe.SuccessorBindingDigest != digest || used[probe.ProbeID] || permit.crypto == nil || permit.crypto.InstanceID() != permit.instance {
			return nil, refused(AdmissionInvalid)
		}
		if _, err := contract.EncodeSuccessorKEKProbeCore(probe); err != nil {
			return nil, refused(AdmissionInvalid)
		}
		used[probe.ProbeID] = true
	}
	permit.used = true
	var evidence []contract.SuccessorEvidenceRow
	k1, k3 := bytes.Clone(s.head.K1), bytes.Clone(s.head.K3)
	for _, row := range request.ReplacementPlan.Rows {
		if row.TargetRole != contract.SuccessorNormalSigner && row.TargetRole != contract.SuccessorRecoverySigner {
			continue
		}
		route := signers.NormalSuccessor
		if row.TargetRole == contract.SuccessorRecoverySigner {
			route = signers.RecoverySuccessor
		}
		proof, res := s.qualifySuccessionSigner(preparationContext, request, row, route, used)
		if res.Outcome != 0 {
			return nil, res
		}
		evidence = append(evidence, proof)
		if row.TargetRole == contract.SuccessorNormalSigner {
			bindingRequest, err := contract.NewBindingRequest(row.AfterSigning.Binding)
			if err != nil {
				return nil, refused(InvalidProof)
			}
			k1, res = s.signSuccession(preparationContext, route, row.AfterSigning, bindingRequest)
			if res.Outcome != 0 {
				return nil, res
			}
		} else {
			basisRequest, err := contract.NewK3BasisRequest(row.AfterSigning)
			if err != nil {
				return nil, refused(InvalidProof)
			}
			k3, res = s.signSuccession(preparationContext, route, row.AfterSigning, basisRequest)
			if res.Outcome != 0 {
				return nil, res
			}
		}
	}
	var prepared *preparedReplacement
	if rewrap {
		source := exchangeSource(q.Context)
		source.OperationID = request.OperationID
		op := &cryptoOperation{observation: permit.observation, source: source, adapter: permit.crypto, instance: permit.instance, context: q.Context, deadline: permit.deadline, bindings: q.BindingTable, authority: request.BeforeControl.AuthorityRecipientID, accessSource: &permit.source, probeBinding: target.Binding.BindingID, wrapCounts: map[contract.ID]uint32{target.Binding.BindingID: 1}}
		body, err := contract.EncodeCryptoAccessReplaceRequest(q)
		if err != nil {
			return nil, refused(AdmissionInvalid)
		}
		reply, res := op.exchange(preparationContext, contract.CryptoAccessReplace, body)
		if res.Outcome != 0 {
			return nil, res
		}
		started, err := contract.DecodeCryptoAccessReplaceResult(reply.Body)
		if err != nil || len(started.Qualified) != 1 || started.Qualified[0].BindingIndex != q.Replacements[0].SuccessorBindingIndex || started.Qualified[0].Qualification.ProbeID != permit.probe.ProbeID || contract.ValidateAccessReplaceResult(q, started) != nil {
			return nil, refused(InvalidProof)
		}
		op.operationRef = started.OperationRef
		role := uint8(contract.SuccessorAuthorityKEK)
		if target.SubjectKind == contract.RecoveryWrapSubject {
			role = contract.SuccessorRecoveryKEK
		}
		evidence = append(evidence, contract.SuccessorEvidenceRow{TargetRole: role, EvidenceKind: contract.SuccessorKEKEvidence, KEK: started.Qualified[0].Qualification})
		prepared, res = prepareReplacementRows(preparationContext, op, q, rows, target)
		if res.Outcome != 0 {
			return nil, res
		}
	} else {
		projection, err := replacementProjection(q, 0)
		if err != nil {
			return nil, refused(AdmissionInvalid)
		}
		prepared = &preparedReplacement{projection: projection}
	}
	candidate, next, res := s.encodeSuccession(preparationContext, request, permit.plan, q, prepared, evidence, k1, k3)
	if candidate == nil {
		return nil, res
	}
	candidate.bindObservation(permit.observation, observationSource{DomainID: request.DomainID, AdmissionID: request.AdmissionID, OperationID: request.OperationID})
	if permit.observation.enabled() {
		detail, err := successionObservation(request)
		if err != nil {
			permit.observation.reject(ctx)
		} else {
			detail.Source.Stage = observationCandidate
			detail.Candidate = candidateObservationIdentity(candidate)
			permit.observation.offerChange(ctx, detail)
		}
	}
	candidate.succession = &successionPreparation{request: descriptor, qualified: true, requiresCrypto: rewrap}
	if rewrap {
		if res := s.freezeSuccessionAccess(preparationContext, request, next, prepared); res.Outcome != 0 {
			return nil, res
		}
		candidate.succession.claimed = true
	}
	if preparationContext.Err() != nil || !validPrivateDeadline(permit.deadline) {
		return nil, refused(AdmissionInvalid)
	}
	candidate.succession.frozen = true
	s.prepared = true
	return s.persistSuccession(preparationContext, candidate, request, next, signers)
}

func (s *StateSession) freezeSuccessionAccess(ctx context.Context, request contract.SuccessionRequestCore, next *StateSession, prepared *preparedReplacement) Result {
	identity, err := contract.IdentityPlanDescriptor(request.IdentityPlan)
	if err != nil {
		return refused(AdmissionInvalid)
	}
	public, err := next.publicProjection()
	if err != nil {
		return refused(AdmissionInvalid)
	}
	publicDescriptor, err := contract.PublicStateDescriptor(public)
	if err != nil {
		return refused(AdmissionInvalid)
	}
	coverage, outputs, unchanged, err := prepared.projection.Descriptors()
	if err != nil {
		return refused(AdmissionInvalid)
	}
	op := prepared.op
	frozen := contract.CryptoAccessFreezeRequest{OperationRef: op.operationRef, Context: op.context, IdentityPlanDescriptor: identity, ExpectedCoverageDescriptor: coverage, AfterAccessRowsDescriptor: outputs, CandidatePublicStateDescriptor: publicDescriptor, CandidateAccessRoot: next.root.CurrentAccess.AccessRoot, UnchangedMaterialDescriptor: unchanged, FinalTranscriptDigest: prepared.transcript}
	body, err := contract.EncodeCryptoAccessFreezeRequest(frozen)
	if err != nil {
		return refused(AdmissionInvalid)
	}
	s.prepared = true
	reply, res := op.exchange(ctx, contract.CryptoFreeze, body)
	if res.Outcome != 0 {
		return res
	}
	fact, err := contract.DecodeCryptoFreezeResult(reply.Body)
	if err != nil {
		return refused(AdmissionInvalid)
	}
	expected, err := contract.CryptoAccessFactDigest(op.instance, frozen)
	if err != nil || fact.FactDigest != expected {
		return refused(AdmissionInvalid)
	}
	body, err = contract.EncodeCryptoAccessClaimRequest(contract.CryptoAccessClaimRequest{CryptoAccessFreezeRequest: frozen, FactDigest: expected})
	if err != nil {
		return refused(AdmissionInvalid)
	}
	_, res = op.exchange(ctx, contract.CryptoClaim, body)
	return res
}

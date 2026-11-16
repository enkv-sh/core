package core

import (
	"context"
	"errors"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func (s *StateSession) encodeSuccession(ctx context.Context, request contract.SuccessionRequestCore, p transitionPlan, q contract.CryptoAccessReplaceRequest, prepared *preparedReplacement, evidence []contract.SuccessorEvidenceRow, k1, k3 []byte) (*Candidate, *StateSession, Result) {
	fail := func() (*Candidate, *StateSession, Result) {
		return nil, nil, refused(InvalidRelation)
	}
	readOrFail := func(err error) (*Candidate, *StateSession, Result) {
		if result, ok := selectedReadResult(err); ok {
			return nil, nil, result
		}
		if errors.Is(err, contract.ErrRecordCapacity) {
			return nil, nil, refused(CapacityExceeded)
		}
		return fail()
	}
	next, objects, err := s.deriveSuccession(ctx, request, p, prepared.after)
	if err != nil {
		return readOrFail(err)
	}
	coverage, outputs, unchanged, err := prepared.projection.Descriptors()
	if err != nil || len(q.Replacements) != 0 && coverage != q.ExpectedCoverageDescriptor {
		return fail()
	}
	identity, err := contract.IdentityPlanDescriptor(request.IdentityPlan)
	if err != nil {
		return fail()
	}
	requestDescriptor, err := contract.SuccessionRequestDescriptor(request)
	if err != nil {
		return fail()
	}
	beforeControl, err := contract.ControlCoreDigest(request.BeforeControl)
	if err != nil {
		return fail()
	}
	afterControl, err := contract.ControlCoreDigest(request.ProposedAfterControl)
	if err != nil {
		return fail()
	}
	preserved, err := s.preservedState(ctx, request.ChangeMask, signerOnlyRecovery(request))
	if err != nil {
		return readOrFail(err)
	}
	replacement, err := contract.SuccessionReplacementPlanDescriptor(request.ReplacementPlan)
	if err != nil {
		return fail()
	}
	evidencePlan, err := contract.PlanSuccessorEvidence(evidence)
	if err != nil {
		return fail()
	}
	evidencePlanDigest, err := contract.EvidencePlanDigest(evidencePlan)
	if err != nil {
		return fail()
	}
	beforeWindows := contract.MutationReceiptWindows{DomainID: request.DomainID}
	if !signerOnlyRecovery(request) {
		beforeWindows, err = s.receiptWindows(ctx)
		if err != nil {
			return readOrFail(err)
		}
	}
	publicOperation := successionPublicOperation(request.OperationKind)
	deltaPlan := contract.MutationReceiptDeltaPlan{DomainID: request.DomainID, OperationKind: publicOperation, Before: beforeWindows}
	if request.OperationKind != contract.SuccessionReplaceAuthority {
		subjects, err := contract.SuccessionChangedSubjectDescriptor(request)
		if err != nil {
			return fail()
		}
		var changes []contract.AccessChangeRow
		for _, before := range s.accessRecords() {
			if after, ok := prepared.after[materialIdentity{before.MaterialKind, before.MaterialID}]; ok {
				changes = append(changes, contract.AccessChangeRow{Before: before, After: after})
			}
		}
		access, err := contract.AccessChangeDescriptor(request.DomainID, changes)
		if err != nil {
			return fail()
		}
		row := contract.CompactMutationReceiptPlan{Schema: contract.MutationReceiptSchema, OperationKind: publicOperation, DomainID: request.DomainID,
			OperationID:           request.OperationID,
			PredecessorRevisionID: request.PredecessorHeadRevisionID, RequestedRevisionID: p.revision, ObservedRevisionID: p.revision,
			StateResult: contract.ReceiptStateSuccess, EvidenceCeiling: contract.ReceiptEvidenceCanonical, CanonicalOutcome: contract.ReceiptCanonicalSelected, ChangedSubjects: subjects}
		row.WarningBits, err = contract.EncodeReceiptWarningBits(publicOperation, s.root.WarningBits, 0)
		if err != nil {
			return fail()
		}
		row.SummaryCounts[contract.ReceiptChangedAccessCount] = access.Count
		empty := contract.EmptyMutationResultDescriptors()
		row.CompleteResult, err = contract.CompleteMutationResultDescriptor(contract.MutationResultProjection{Receipt: row,
			RequestCoreDigest: requestDescriptor.Digest, ChangedAccess: access, Effects: empty[1], Outputs: empty[2], Duties: empty[3], Hazards: empty[4]})
		if err != nil {
			return fail()
		}
		deltaPlan.AddedCount = 1
		deltaPlan.NewReceipt = row
		storage, err := s.encodeMutationReceiptSupport(ctx, p, deltaPlan, contract.ID{})
		if err != nil {
			return readOrFail(err)
		}
		storage.install(next)
		if err := s.installAdministrativeIndex(ctx, next, &Candidate{session: s}, &row); err != nil {
			return readOrFail(err)
		}
	}
	next.recountChildren()
	snapshotPlan, err := format.EncodeRoot(next.root)
	if err != nil {
		return fail()
	}
	h := s.successorCore(p)
	h.Epoch = request.ProposedAfterControl.NormalSigning.Binding.Epoch
	h.Trust = request.ProposedAfterControl.NormalSigning.Binding.Trust
	h.Root = contract.Ref{Kind: format.RootKind, Format: format.Version, Domain: request.DomainID, Object: p.snapshot, Length: uint32(len(snapshotPlan)), Index: 0}
	headPlan, err := format.EncodeHeadPlan(format.HeadPlan(h))
	if err != nil {
		return fail()
	}
	conditionPlan := format.ConditionalRequestPlan{Family: s.token.Family, Store: h.Store, Coordinate: h.Coordinate, NonBody: h.NonBody, Condition: matchedCondition(s.token), HeadCoreLength: uint32(len(headPlan))}
	receiptPlanDigest, err := contract.MutationReceiptDeltaPlanDigest(deltaPlan)
	if err != nil {
		return fail()
	}
	subject := contract.SuccessionSubject{Schema: contract.CanonicalSchema, MaterialSourceRole: request.MaterialSourceRole, OperationKind: request.OperationKind, ApprovalRole: request.ApprovalRole, OperationID: request.OperationID, AdmissionID: request.AdmissionID,
		RequestCoreDigest: requestDescriptor.Digest, IdentityPlanDigest: identity.Digest, BeforeControlDigest: beforeControl, AfterControlDigest: afterControl, BeforeAccessRoot: request.BeforeAccessRoot, AfterAccessRoot: next.root.CurrentAccess.AccessRoot,
		PreservedStateDigest: preserved.Digest, CoverageDigest: coverage.Digest, ReplacementPlanDigest: replacement.Digest, SuccessorEvidenceDigest: evidencePlanDigest, ReceiptDeltaDigest: receiptPlanDigest,
		IdentityPlanLength: uint32(identity.Length), HeadCoreLength: uint32(len(headPlan)), CoverageCount: coverage.Count, ReplacementCount: uint16(replacement.Count), SuccessorEvidenceCount: uint8(len(evidence)), ReceiptDeltaCount: deltaPlan.AddedCount, ChangeMask: request.ChangeMask}
	authorizer := request.BeforeControl.NormalSigning
	if request.ApprovalRole == contract.RecoverySigningRole {
		authorizer = request.BeforeControl.Recovery.Signing
	}
	graph, err := format.DeriveSuccessionIdentity(format.SuccessionIdentityPlan{Request: request, Snapshot: next.root, Head: format.HeadPlan(h), Conditional: conditionPlan, Authorization: contract.SuccessionAuthorizationPlan{Subject: contract.SuccessionAuthorizationSubject(subject), Authorizer: authorizer}, Evidence: evidencePlan, AccessPlan: q.Plan(), Coverage: coverage, Unchanged: unchanged, AfterAccess: outputs})
	if err != nil {
		return fail()
	}
	subject.RequestIdentityDigest = graph.RequestIdentityDigest
	afterWindows := beforeWindows
	if deltaPlan.AddedCount == 1 {
		storage, err := s.encodeMutationReceiptSupport(ctx, p, deltaPlan, graph.RequestIdentityDigest)
		if err != nil {
			return readOrFail(err)
		}
		storage.install(next)
		objects = append(objects, storage.objects...)
		indexCandidate := &Candidate{session: s}
		if err := s.installAdministrativeIndex(ctx, next, indexCandidate); err != nil {
			return readOrFail(err)
		}
		if s.fragmentFacts != nil {
			if err := s.bindReceiptSuccessorSlices(next); err != nil {
				return readOrFail(err)
			}
		}
		objects = append(objects, indexCandidate.objects...)
		afterWindows, err = next.receiptWindows(ctx)
		if err != nil {
			return readOrFail(err)
		}
	}
	subject.ReceiptDeltaDigest, err = contract.MutationReceiptDeltaDigest(contract.MutationReceiptDelta{DomainID: request.DomainID,
		OperationKind: publicOperation, AddedCount: deltaPlan.AddedCount, Before: beforeWindows, After: afterWindows})
	if err != nil {
		return fail()
	}
	subject.SuccessorEvidenceDigest, err = contract.SuccessorEvidenceDigest(evidence)
	if err != nil {
		return fail()
	}
	if !successionRegistryPreserved(s, next, request.ProposedAfterControl) {
		return fail()
	}
	if _, err := next.validateRelationsAgainst(ctx, request.ProposedAfterControl, signerOnlyRecovery(request)); err != nil {
		return readOrFail(err)
	}
	root, err := format.EncodeRoot(next.root)
	if err != nil || len(root) != len(snapshotPlan) {
		return fail()
	}
	h.Root, err = format.Reference(format.RootKind, request.DomainID, p.snapshot, 0, root)
	if err != nil {
		return fail()
	}
	objects = append(objects, objectImage{ref: h.Root, body: root})
	core, err := format.EncodeHeadCore(h)
	if err != nil || len(core) != len(headPlan) {
		return fail()
	}
	subject.HeadCoreDigest = contract.Hash(core)
	condition, err := format.EncodeConditionalPlan(conditional(h, core))
	if err != nil {
		return fail()
	}
	subject.ConditionalPlanDigest = contract.Hash(condition)
	if _, err := contract.EncodeSuccessionSubject(subject); err != nil {
		return fail()
	}
	candidate := &Candidate{session: s, requestIdentity: graph.RequestIdentityDigest, replacementState: next, objects: objects, head: format.Head{Core: h, K1: k1, K3: k3, AuthKind: format.SuccessionAuth, Succession: &format.SuccessionProof{Subject: subject, Authorizer: authorizer, Evidence: evidence}}}
	next.head = candidate.head
	if !ordinaryCandidateCapacity(candidate) {
		return nil, nil, refused(CapacityExceeded)
	}
	if !currentSigningProofs(candidate.head, request.ProposedAfterControl) || !successorEvidenceValid(candidate.head, request.ProposedAfterControl) {
		return fail()
	}
	return candidate, next, Result{}
}

func (s *StateSession) persistSuccession(ctx context.Context, candidate *Candidate, request contract.SuccessionRequestCore, next *StateSession, signers SuccessionSigners) (*Candidate, Result) {
	if !ordinaryCandidateCapacity(candidate) {
		return nil, refused(CapacityExceeded)
	}
	for i, object := range candidate.objects {
		if ctx.Err() != nil || !s.admission.valid(s.store) {
			return nil, refused(AdmissionInvalid)
		}
		key, err := format.Key(s.admission.store.Prefix, object.ref)
		if err != nil {
			return nil, refused(InvalidReference)
		}
		if res := s.persistImmutable(ctx, key, object.body, object.ref.Length); res.Outcome != 0 {
			return nil, res
		}
		if format.CheckReference(object.ref, object.body) != nil {
			return nil, failure(IntegrityFailure, ImmutableConflict)
		}
		s.cacheVerifiedObject(object.ref, object.body)
		if s.replacementRead && object.ref.Kind == contract.AdministrativeIndexKind {
			candidate.objects[i].body = nil
		}
	}
	if err := s.cacheCandidateAdministrativeIndex(candidate); err != nil {
		return nil, failure(IntegrityFailure, InvalidRelation)
	}
	candidate.succession.readback = true
	subject := candidate.head.Succession.Subject
	q, err := contract.NewK2SuccessionRequest(subject)
	if subject.ApprovalRole == contract.RecoverySigningRole {
		q, err = contract.NewK3SuccessionRequest(subject)
	}
	if err != nil {
		return nil, refused(InvalidProof)
	}
	proof, res := s.signSuccession(ctx, signers.Authorizer, candidate.head.Succession.Authorizer, q)
	if res.Outcome != 0 {
		return nil, res
	}
	candidate.head.AuthorizationSignature = proof
	core, err := format.EncodeHeadCore(candidate.head.Core)
	if err != nil {
		return nil, failure(IntegrityFailure, InvalidFormat)
	}
	for _, evidence := range candidate.head.Succession.Evidence {
		if evidence.EvidenceKind != contract.SuccessorSignerEvidence {
			continue
		}
		binding := next.root.CurrentAccess.Core.NormalSigning
		accepting := signers.NormalSuccessor
		role := uint8(contract.NormalSigningRole)
		if evidence.TargetRole == contract.SuccessorRecoverySigner {
			if next.root.CurrentAccess.Core.Recovery == nil {
				return nil, refused(InvalidProof)
			}
			binding = next.root.CurrentAccess.Core.Recovery.Signing
			accepting = signers.RecoverySuccessor
			role = contract.RecoverySigningRole
		}
		digest, err := contract.SigningBindingDigest(binding)
		if err != nil || digest != evidence.Trust.SigningBindingDigest {
			return nil, refused(InvalidProof)
		}
		acceptance, err := contract.NewSelectionAcceptanceRequest(contract.SelectionAcceptance{HeadCore: core,
			CurrentAccess: next.root.CurrentAccess, AccessRoot: next.root.CurrentAccess.AccessRoot,
			Succession: subject, Authorizer: candidate.head.Succession.Authorizer,
			Evidence: candidate.head.Succession.Evidence, Accepting: binding, Role: role, Epoch: binding.Binding.Epoch})
		if err != nil {
			return nil, refused(InvalidProof)
		}
		signature, result := s.signSuccession(ctx, accepting, binding, acceptance)
		if result.Outcome != 0 {
			return nil, result
		}
		candidate.head.Succession.Acceptances = append(candidate.head.Succession.Acceptances, format.SelectionAcceptanceProof{Role: role,
			BindingDigest: digest, Epoch: binding.Binding.Epoch, Signature: signature})
	}
	if !selectionAcceptanceValid(candidate.head, next.root) {
		return nil, refused(InvalidProof)
	}
	next.head = candidate.head
	candidate.body, err = format.EncodeHead(candidate.head)
	if err != nil {
		return nil, failure(IntegrityFailure, InvalidFormat)
	}
	basis, err := qualifyCurrentBasis(ctx, s, candidate, request, next)
	if err != nil {
		if result, ok := selectedReadResult(err); ok {
			return nil, result
		}
		return nil, refused(InvalidProof)
	}
	candidate.succession.basis = basis
	res = s.observed(ObservedCurrent)
	res.RequestedRevision = candidate.head.Core.Revision
	return candidate, res
}

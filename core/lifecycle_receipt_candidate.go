package core

import (
	"context"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type lifecycleReceiptCandidate struct {
	candidate *Candidate
	authority lifecycleAuthority
	identity  contract.ID
	receipt   []byte
	after     contract.MutationReceiptWindows
}

func deriveLifecycleReceiptIdentity(operation uint16, p format.SuppliedApplyIdentityPlan) (contract.ID, error) {
	switch operation {
	case contract.OperationApplyDeclaration:
		return format.DeriveSuppliedApplyIdentity(p)
	case contract.OperationRetireRecipientIdentity:
		return format.DeriveRecipientRetirementIdentity(p)
	case contract.OperationEnvelopeRekey:
		return format.DeriveEnvelopeRekeyIdentity(p)
	case contract.OperationRotateRecipientKeyBinding:
		return format.DeriveRecipientReplacementIdentity(format.RecipientReplacementIdentityPlan(p))
	default:
		return contract.ID{}, contract.ErrRecord
	}
}

func (s *StateSession) encodeLifecycleReceiptCandidate(ctx context.Context, c *Comparison, next *StateSession, p transitionPlan, request contract.RequestCore, delta contract.MutationReceiptDeltaPlan) (*lifecycleReceiptCandidate, Result) {
	fail := func(err error) (*lifecycleReceiptCandidate, Result) {
		return nil, installedApplyPreparationFailure(err)
	}
	planned, err := s.encodeLifecycleReceiptSupport(ctx, c, p, delta, contract.ID{})
	if err != nil {
		return fail(err)
	}
	planned.install(next)
	if err := s.bindNormalReceiptSlicePlan(c, next, p); err != nil {
		return fail(err)
	}
	defer func() { next.normalReceiptSlices = nil }()
	children, result := s.encodeSuccessorChildren(next, p, c)
	if children == nil {
		return nil, result
	}
	if err := s.installAdministrativeIndex(ctx, next, children, &delta.NewReceipt); err != nil {
		return fail(err)
	}
	support, err := s.receiptSupportPlanDescriptor(planned, delta.NewReceipt)
	if err != nil {
		return fail(err)
	}
	public, err := next.publicStateWithSupport(support)
	if err != nil {
		return fail(err)
	}
	descriptor, err := contract.PublicStateDescriptor(public)
	if err != nil {
		return fail(err)
	}
	authority, err := s.authorityWithPublicState(next, c, p, contract.DigestLength{Digest: descriptor.Digest, Length: descriptor.Length})
	if err != nil {
		return fail(err)
	}
	root, err := format.EncodeRoot(next.root)
	if err != nil {
		return fail(err)
	}
	h := s.successorCore(p)
	if len(children.head.GrantWraps) != 0 {
		h.GrantDigest = contract.Hash(children.head.GrantWraps)
	}
	h.Root = contract.Ref{Kind: format.RootKind, Format: format.Version, Domain: s.root.Domain, Object: p.snapshot, Index: 0, Length: uint32(len(root))}
	head, err := format.EncodeHeadPlan(format.HeadPlan(h))
	if err != nil {
		return fail(err)
	}
	subject := authority.subject()
	subject.HeadCoreLength = uint32(len(head))
	conditional := format.ConditionalRequestPlan{Family: s.token.Family, Store: h.Store, Coordinate: h.Coordinate, NonBody: h.NonBody, Condition: matchedCondition(s.token), HeadCoreLength: uint32(len(head))}
	identity, err := deriveLifecycleReceiptIdentity(delta.OperationKind, format.SuppliedApplyIdentityPlan{Request: request, Identity: identityPlan(c, p), Snapshot: next.root, Head: format.HeadPlan(h), Conditional: conditional, Authorization: contract.LifecycleAuthorizationPlan(subject), PublicState: public, Receipt: delta})
	if err != nil {
		return fail(err)
	}
	actual, err := s.encodeLifecycleReceiptSupport(ctx, c, p, delta, identity)
	if err != nil {
		return fail(err)
	}
	actual.install(next)
	index := &Candidate{session: s}
	if err := s.installAdministrativeIndex(ctx, next, index); err != nil {
		return fail(err)
	}
	if s.fragmentFacts != nil {
		if err := s.bindReceiptSuccessorSlices(next); err != nil {
			return fail(err)
		}
	}
	authority, err = s.authorityFrom(next, c, p)
	if err != nil {
		return fail(err)
	}
	candidate, result := s.encodeSuccessor(ctx, next, p, authority, c, actual.objects)
	if candidate == nil {
		return nil, result
	}
	if !ordinaryCandidateCapacity(candidate) {
		return fail(contract.ErrRecordCapacity)
	}
	// Lifecycle envelopes are bounded by the actual core/subject and three
	// existing P-256 proof slots, each admitted by the closed HEAD grammar.
	core, err := format.EncodeHeadCore(candidate.head.Core)
	if err != nil || len(core)+contract.LifecycleSubjectLength+3*(4+72)+32 > contract.MaxHeadLength {
		return fail(contract.ErrRecordCapacity)
	}
	receipt := contract.CompactMutationReceipt(delta.NewReceipt)
	receipt.RequestIdentityDigest = identity
	body, err := contract.EncodeCompactMutationReceipt(receipt)
	if err != nil {
		return fail(err)
	}
	after, err := contract.AppendMutationReceipt(delta.Before, receipt)
	if err != nil {
		return fail(err)
	}
	return &lifecycleReceiptCandidate{candidate: candidate, authority: authority, identity: identity, receipt: body, after: after}, Result{}
}

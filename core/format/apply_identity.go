package format

import "enkv.sh/core/contract"

// SuppliedApplyIdentityPlan is the complete proof-free supplied successor.
// Its receipt plan has one request-identity hole; Head and Conditional use
// their existing named digest holes. Stored readers accept none of them.
type SuppliedApplyIdentityPlan struct {
	Request       contract.RequestCore
	Identity      contract.IdentityPlan
	Snapshot      Root
	Head          HeadPlan
	Conditional   ConditionalRequestPlan
	Authorization contract.LifecycleAuthorizationPlan
	PublicState   contract.PublicState
	Receipt       contract.MutationReceiptDeltaPlan
}

func DeriveSuppliedApplyIdentity(p SuppliedApplyIdentityPlan) (ID, error) {
	return deriveLifecycleReceiptIdentity(p, contract.OperationApplyDeclaration, "supplied-transition-graph-v1")
}

func DeriveEnvelopeRekeyIdentity(p SuppliedApplyIdentityPlan) (ID, error) {
	if len(p.Identity.Rows) != 1 || p.Receipt.NewReceipt.EffectSummary != contract.ReceiptEffectNotApplicable {
		return ID{}, ErrFormat
	}
	return deriveLifecycleReceiptIdentity(p, contract.OperationEnvelopeRekey, "envelope-rekey-transition-graph-v1")
}

func DeriveRecipientRetirementIdentity(p SuppliedApplyIdentityPlan) (ID, error) {
	if len(p.Identity.Rows) > min(int(p.Authorization.Normal.Changed), int(p.Authorization.AfterSecretCount)) || p.Receipt.NewReceipt.EffectSummary != contract.ReceiptEffectNotApplicable {
		return ID{}, ErrFormat
	}
	expectedPages, plannedPages := 0, 0
	for _, ref := range p.Snapshot.Recipients {
		if ref != nil {
			expectedPages++
		}
	}
	for _, page := range p.Identity.Pages {
		if page.Kind == RecipientKind {
			plannedPages++
		}
	}
	if expectedPages == 0 || plannedPages != expectedPages {
		return ID{}, ErrFormat
	}
	return deriveLifecycleReceiptIdentity(p, contract.OperationRetireRecipientIdentity, "recipient-retirement-transition-graph-v1")
}

func deriveLifecycleReceiptIdentity(p SuppliedApplyIdentityPlan, operation uint16, label string) (ID, error) {
	request, err := contract.EncodeRequestCore(p.Request)
	if err != nil {
		return ID{}, err
	}
	identity, err := contract.EncodeIdentityPlan(p.Identity)
	if err != nil {
		return ID{}, err
	}
	root, err := EncodeRoot(p.Snapshot)
	if err != nil {
		return ID{}, err
	}
	head, err := EncodeHeadPlan(p.Head)
	if err != nil {
		return ID{}, err
	}
	condition, err := EncodeConditionalRequestPlan(p.Conditional)
	if err != nil {
		return ID{}, err
	}
	authorization, err := contract.EncodeLifecycleAuthorizationPlan(p.Authorization)
	if err != nil {
		return ID{}, err
	}
	receipt, err := contract.MutationReceiptDeltaPlanDigest(p.Receipt)
	if err != nil {
		return ID{}, err
	}
	public, err := contract.PublicStateDescriptor(p.PublicState)
	if err != nil {
		return ID{}, err
	}
	q, h, c, a := p.Request, HeadCore(p.Head), ConditionalPlan(p.Conditional), contract.LifecycleSubject(p.Authorization)
	if a.OperationKind != operation || q.IdentityPlan != (contract.DigestLength{Digest: contract.Hash(identity), Length: uint64(len(identity))}) || a.Request != contract.Hash(request) || a.Operation != p.Identity.Operation || a.IdentityPlan != q.IdentityPlan || a.Normal.Intent != q.Intent || a.Normal.PublicState != (contract.DigestLength{Digest: public.Digest, Length: public.Length}) || a.AfterAccessRoot != p.PublicState.AccessRoot || p.PublicState.AccessRoot != p.Snapshot.CurrentAccess.AccessRoot || p.PublicState.Domain != q.Domain || len(p.PublicState.Rows) != len(p.Snapshot.Names) ||
		p.Snapshot.Domain != q.Domain || p.Snapshot.Snapshot != p.Identity.Snapshot || p.Snapshot.Transition != p.Identity.Transition || h.Root.Object != p.Identity.Snapshot || h.Root.Length != uint32(len(root)) || h.Domain != q.Domain || h.Revision != p.Identity.Revision || h.PreviousRevision != q.PreviousRevision || h.PreviousDigest != q.PreviousDigest || h.PreviousToken != q.PreviousToken || h.Store != q.Store || h.Trust != q.Trust || h.Coordinate != q.Coordinate || h.NonBody != q.NonBody || h.Interpretation != q.Interpretation || h.Epoch != q.Epoch || a.HeadCoreLength != uint32(len(head)) ||
		c.Family != q.PreviousToken.Family || c.Store != h.Store || c.Coordinate != h.Coordinate || c.NonBody != h.NonBody || c.HeadCoreLength != uint32(len(head)) ||
		p.Receipt.AddedCount != 1 || p.Receipt.OperationKind != operation || p.Receipt.DomainID != q.Domain || p.Receipt.NewReceipt.OperationID != p.Identity.Operation || p.Receipt.NewReceipt.PredecessorRevisionID != q.PreviousRevision || p.Receipt.NewReceipt.RequestedRevisionID != p.Identity.Revision || p.Receipt.NewReceipt.ObservedRevisionID != p.Identity.Revision {
		return ID{}, ErrFormat
	}
	token, ok := c.Condition.Token()
	if !ok || token != q.PreviousToken {
		return ID{}, ErrFormat
	}
	for i, row := range p.PublicState.Rows {
		if row.Name != p.Snapshot.Names[i].Name || row.Slot != p.Snapshot.Names[i].Slot {
			return ID{}, ErrFormat
		}
	}
	for _, page := range p.Identity.Pages {
		var ref *Ref
		switch page.Kind {
		case ValueEntryPageKind:
			if int(page.Index) < len(p.Snapshot.ValueEntryPages) {
				ref = p.Snapshot.ValueEntryPages[page.Index]
			}
		case RecipientKind:
			if (operation == contract.OperationApplyDeclaration || operation == contract.OperationRotateRecipientKeyBinding || operation == contract.OperationRetireRecipientIdentity) && int(page.Index) < len(p.Snapshot.Recipients) {
				ref = p.Snapshot.Recipients[page.Index]
			}
		case AccessKind:
			for i := range p.Snapshot.CurrentAccess.Core.AccessPageRefs {
				if p.Snapshot.CurrentAccess.Core.AccessPageRefs[i].Index == page.Index {
					ref = &p.Snapshot.CurrentAccess.Core.AccessPageRefs[i]
				}
			}
		case contract.RequiredSupportKind:
			for i := range p.Snapshot.RequiredSupport {
				if p.Snapshot.RequiredSupport[i].Index == page.Index {
					ref = &p.Snapshot.RequiredSupport[i]
				}
			}
		}
		if ref == nil || ref.Object != page.Object || ref.Kind != page.Kind {
			return ID{}, ErrFormat
		}
	}
	graph := newSuccessionIdentityHash(label)
	for _, part := range [][]byte{request, identity, root, head, condition, authorization} {
		graph.blob(part)
	}
	graph.id(receipt)
	result := newSuccessionIdentityHash("mutation-request-identity-v1")
	result.id(contract.Hash(request))
	result.write([]byte{0, 0, 0, 0})
	result.id(p.Identity.Revision)
	result.id(graph.descriptor().Digest)
	return result.descriptor().Digest, nil
}

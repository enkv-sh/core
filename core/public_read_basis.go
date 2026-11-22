package core

import (
	"bytes"
	"context"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// A read basis retains the owned public anchor and exact-ref read reach only.
// It is not an ordinary OpenContext or a private reconstruction selection.
type publicReadBasis struct {
	anchor anchoredPublicCandidate
	reader selectedObjectReader
}

// The normal provider Store must reproduce the selected construction identity
// and reread the same HEAD before any selected child is requested. On AWS that
// Store applies the authenticated owner guard to every request.
func bindPublicReadBasis(ctx context.Context, anchor anchoredPublicCandidate, source PublicSelectedReader) (publicReadBasis, Result) {
	var empty publicReadBasis
	if ctx == nil || source == nil {
		return empty, refused(AdmissionInvalid)
	}
	if !publicReadInvocationCurrent(ctx, anchor) {
		return empty, failure(EvidenceUnavailable, ReadUnavailable)
	}
	d := source.Descriptor()
	config := anchor.configuration
	h, root := anchor.head, anchor.root
	configID, err := contract.StoreConfigurationID(config)
	if err != nil || !d.Valid() || source.StoreConfiguration() != config ||
		configID != h.Core.Store || h.Core.Domain != config.DomainID || root.Domain != config.DomainID ||
		root.CurrentAccess.Core.DomainID != config.DomainID ||
		d.Family != config.Provider || d.Identity != configID || d.Coordinate != h.Core.Coordinate ||
		d.NonBody != h.Core.NonBody || d.Prefix != config.PrefixBeforeHEAD ||
		root.CurrentAccess.Core.Provider != d.Family || root.CurrentAccess.Core.StoreID != d.Identity ||
		root.CurrentAccess.Core.CoordinateID != d.Coordinate || root.CurrentAccess.Core.NonBodyID != d.NonBody {
		return empty, failure(IntegrityFailure, ConstructionMismatch)
	}
	headBody, err := format.EncodeHead(h)
	if err != nil || format.CheckReference(h.Core.Root, anchor.rootBody) != nil || !bytes.Equal(anchor.headBody, headBody) {
		return empty, failure(IntegrityFailure, InvalidReference)
	}
	binding, ok := candidateSelectionSignature(h, root, anchor.anchor.role)
	if !ok || !signingBindingEqual(binding, anchor.anchor.binding) {
		return empty, failure(IntegrityFailure, InvalidProof)
	}
	read := source.Read(ctx, d.HeadKey, contract.MaxHeadLength)
	if !publicReadInvocationCurrent(ctx, anchor) {
		return empty, unavailableStoreRead(contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit})
	}
	checked := ownCandidateRead(read, contract.MaxHeadLength, nil, 0)
	if checked.Status != contract.ReadOK {
		return empty, candidateReadFailure(checked, false)
	}
	if checked.Token.Family != d.Family || checked.Token != anchor.headToken || !bytes.Equal(checked.Body, anchor.headBody) {
		return empty, failure(Contention, DifferentSelection)
	}
	sources, err := root.GrantSources(h)
	if err != nil {
		return empty, failure(IntegrityFailure, InvalidReference)
	}
	return publicReadBasis{anchor: anchor, reader: selectedObjectReader{
		domain: config.DomainID, descriptor: d, source: source, grantSources: sources,
	}}, Result{}
}

func publicReadInvocationCurrent(ctx context.Context, anchor anchoredPublicCandidate) bool {
	if ctx == nil || ctx.Err() != nil || ctx.Done() != anchor.done {
		return false
	}
	if !anchor.deadline.IsZero() {
		deadline, ok := ctx.Deadline()
		if !ok || deadline.After(anchor.deadline) || !validPrivateDeadline(anchor.deadline) || !validPrivateDeadline(deadline) {
			return false
		}
	}
	select {
	case <-anchor.done:
		return false
	default:
		return true
	}
}

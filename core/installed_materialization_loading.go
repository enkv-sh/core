package core

import (
	"bytes"
	"context"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/telemetry"
)

func (i *readerInvocation) loadMaterializationSelection(ctx context.Context, request contract.ID, call *telemetry.Call) (publicSelection, readerFailure) {
	basis, failed := i.loadPublicReadBasis(ctx, contract.MaterializationOperation, request)
	if failed.Outcome != 0 {
		return publicSelection{}, failed
	}
	const imageAttempts = 3
	var selected publicSelection
	for attempt := 0; attempt < imageAttempts; attempt++ {
		if reason := i.admission.failure(ctx, contract.MaterializationOperation, request); reason != "" {
			return publicSelection{}, readerRefusal(reason)
		}
		var result Result
		selected, result = completePublicSelection(ctx, basis, nil)
		if reason := i.admission.failure(ctx, contract.MaterializationOperation, request); reason != "" {
			return publicSelection{}, readerRefusal(reason)
		}
		if result.Outcome == 0 {
			break
		}
		if result.Outcome != EvidenceUnavailable || result.Reason != MissingSelectedObject {
			return publicSelection{}, readerSelectionFailure(result)
		}
		call.Checkpoint(telemetry.DiagnosticStateLoading, telemetry.DiagnosticReasonMissingSelectedObject)
		next, failed := i.refreshMaterializationBasis(ctx, basis)
		if failed.Outcome != 0 {
			return publicSelection{}, failed
		}
		current, observed := basis.anchor, next.anchor
		if observed.headToken == current.headToken || observed.head.Core.Revision == current.head.Core.Revision || bytes.Equal(observed.headBody, current.headBody) {
			return publicSelection{}, readerSelectionFailure(result)
		}
		if attempt+1 == imageAttempts {
			return publicSelection{}, readerSelectionFailure(failure(Contention, DifferentSelection))
		}
		basis = next
	}

	return i.finishPublicSelection(ctx, contract.MaterializationOperation, request, selected)
}

func (i *readerInvocation) refreshMaterializationBasis(ctx context.Context, previous publicReadBasis) (publicReadBasis, readerFailure) {
	var empty publicReadBasis
	if reason := i.admission.failure(ctx, contract.MaterializationOperation, i.admission.request); reason != "" {
		return empty, readerRefusal(reason)
	}
	if i.source == nil || i.source.Descriptor() != i.admission.store || i.source.StoreConfiguration() != previous.anchor.configuration {
		return empty, readerRefusal(contract.ReasonStoreBasisInvalid)
	}
	read := ownCandidateRead(i.source.Read(ctx, i.admission.store.HeadKey, contract.MaxHeadLength), contract.MaxHeadLength, nil, 0)
	if reason := i.admission.failure(ctx, contract.MaterializationOperation, i.admission.request); reason != "" {
		return empty, readerRefusal(reason)
	}
	if read.Status != contract.ReadOK {
		return empty, readerSelectionFailure(candidateReadFailure(read, true))
	}
	if read.Token.Family != i.admission.store.Family || read.Token == previous.anchor.headToken && !bytes.Equal(read.Body, previous.anchor.headBody) {
		return empty, readerSelectionFailure(failure(IntegrityFailure, InvalidFormat))
	}
	head, err := format.DecodeHead(read.Body)
	if err != nil {
		return empty, readerSelectionFailure(failure(IntegrityFailure, InvalidFormat))
	}
	if head.Core.Domain != i.admission.domain || head.Core.Store != i.admission.store.Identity || head.Core.Coordinate != i.admission.store.Coordinate || head.Core.NonBody != i.admission.store.NonBody || head.Core.Root.Domain != i.admission.domain {
		return empty, readerSelectionFailure(failure(IntegrityFailure, ConstructionMismatch))
	}
	rootBody, result := previous.reader.readOwned(ctx, head.Core.Root)
	if result.Outcome != 0 {
		return empty, readerSelectionFailure(result)
	}
	root, err := format.DecodeRoot(rootBody)
	if err != nil || root.Domain != head.Core.Domain || root.Snapshot != head.Core.Root.Object {
		return empty, readerSelectionFailure(failure(IntegrityFailure, InvalidReference))
	}
	basis := i.admission.basis
	normal := readerSigningQualifier{binding: basis.control.NormalSigning}
	var recovery candidateSigningQualifier
	if basis.control.Recovery != nil {
		recovery = readerSigningQualifier{binding: basis.control.Recovery.Signing}
	}
	qualified, result := qualifyCandidateSelection(ctx, head, root, normal, recovery)
	if reason := i.admission.failure(ctx, contract.MaterializationOperation, i.admission.request); reason != "" {
		return empty, readerRefusal(reason)
	}
	if result.Outcome != 0 {
		return empty, readerSelectionFailure(result)
	}
	if head.AuthKind == format.SuccessionAuth && !basis.successionSelected(head) {
		return empty, readerSelectionFailure(failure(EvidenceUnavailable, SigningUnavailable))
	}
	anchor := previous.anchor
	anchor.head, anchor.headBody, anchor.headToken = head, read.Body, read.Token
	anchor.root, anchor.rootBody, anchor.anchor = root, rootBody, qualified
	return publicReadBasis{anchor: anchor, reader: previous.reader}, readerFailure{}
}

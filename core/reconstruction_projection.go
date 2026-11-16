package core

import (
	"context"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// A projection is provisional until its consumer commits after every selected
// part, every current secret, and the final identical HEAD observation.
type reconstructionProjectionKind uint8

const (
	reconstructionConfigurationPart reconstructionProjectionKind = iota + 1
	reconstructionHEADPart
	reconstructionRootPart
	reconstructionValuePagePart
	reconstructionRecipientPagePart
	reconstructionAccessPagePart
	reconstructionIndexPagePart
	reconstructionSupportRowPart
)

// Body is borrowed for the duration of Accept only. Ref is zero for the
// configuration and HEAD; physicalOrdinal applies only to selected support.
type reconstructionProjectionPart struct {
	kind            reconstructionProjectionKind
	ref             format.Ref
	physicalOrdinal uint16
	supportKind     contract.SupportRecordKind
	recordID        contract.ID
	body            []byte
}

// Core creates one private consumer per full attempt. Abort discards that
// attempt; Commit transfers the complete result atomically.
type reconstructionProjectionConsumer interface {
	Accept(context.Context, reconstructionProjectionPart) Result
	Commit(context.Context, Result) Result
	Abort()
}

type reconstructionProjectionProvenance struct {
	domain, revision, snapshot contract.ID
	headDigest                 contract.ID
	headToken                  contract.Token
}

type reconstructionProjectionProgress struct {
	parts uint32
	bytes uint64
}

func acceptReconstructionPart(ctx context.Context, anchor anchoredPublicCandidate,
	consumer reconstructionProjectionConsumer, progress *reconstructionProjectionProgress,
	maxBytes uint64, part reconstructionProjectionPart) Result {
	if consumer == nil || progress == nil || !reconstructionInvocationCurrent(ctx, anchor) {
		return failure(EvidenceUnavailable, ReadUnavailable)
	}
	if len(part.body) == 0 || progress.bytes > maxBytes ||
		uint64(len(part.body)) > maxBytes-progress.bytes || progress.parts == ^uint32(0) {
		return failure(IntegrityFailure, InvalidRelation)
	}
	result := consumer.Accept(ctx, part)
	if result != (Result{}) {
		if result.Outcome == 0 || result.Outcome == ObservedCurrent || result.Outcome == Unchanged {
			return refused(AdmissionInvalid)
		}
		return result
	}
	if !reconstructionInvocationCurrent(ctx, anchor) {
		return failure(EvidenceUnavailable, ReadUnavailable)
	}
	progress.parts++
	progress.bytes += uint64(len(part.body))
	return Result{}
}

// emitReconstructionFixedParts emits the fixed selected objects in root order.
// It neither emits support rows nor grants completeness or calls Commit. The
// support-row stage must use exact selected physical ordinals, not whole pages.
func emitReconstructionFixedParts(ctx context.Context, selected *publicSelection,
	consumer reconstructionProjectionConsumer) (reconstructionProjectionProgress, Result) {
	var progress reconstructionProjectionProgress
	if selected == nil || !selected.complete || consumer == nil || selected.basis.reader.source == nil ||
		selected.image.root.Domain != selected.basis.reader.domain {
		return progress, refused(AdmissionInvalid)
	}
	anchor := selected.basis.anchor
	if !reconstructionInvocationCurrent(ctx, anchor) {
		return progress, failure(EvidenceUnavailable, ReadUnavailable)
	}
	root := selected.image.root
	if len(anchor.configBody) == 0 || len(anchor.configBody) > contract.MaxStoreConfigurationLength ||
		len(anchor.headBody) == 0 || len(anchor.headBody) > contract.MaxHeadLength ||
		len(anchor.rootBody) == 0 || len(anchor.rootBody) > contract.MaxRootLength ||
		format.CheckReference(anchor.head.Core.Root, anchor.rootBody) != nil {
		return progress, failure(IntegrityFailure, InvalidReference)
	}
	maxBytes := root.ChildEncodedBytes + uint64(len(anchor.configBody)+len(anchor.headBody)+len(anchor.rootBody))
	for _, part := range []reconstructionProjectionPart{
		{kind: reconstructionConfigurationPart, body: anchor.configBody},
		{kind: reconstructionHEADPart, body: anchor.headBody},
		{kind: reconstructionRootPart, ref: anchor.head.Core.Root, body: anchor.rootBody},
	} {
		if result := acceptReconstructionPart(ctx, anchor, consumer, &progress, maxBytes, part); result.Outcome != 0 {
			return progress, result
		}
	}
	read := func(kind reconstructionProjectionKind, ref format.Ref) Result {
		if !reconstructionInvocationCurrent(ctx, anchor) {
			return failure(EvidenceUnavailable, ReadUnavailable)
		}
		body, _, result := selected.basis.reader.readBorrowed(ctx, ref)
		if result.Outcome != 0 {
			return result
		}
		return acceptReconstructionPart(ctx, anchor, consumer, &progress, maxBytes,
			reconstructionProjectionPart{kind: kind, ref: ref, body: body})
	}
	for _, ref := range root.ValueEntryPages {
		if ref != nil {
			if result := read(reconstructionValuePagePart, *ref); result.Outcome != 0 {
				return progress, result
			}
		}
	}
	for _, ref := range root.Recipients {
		if ref != nil {
			if result := read(reconstructionRecipientPagePart, *ref); result.Outcome != 0 {
				return progress, result
			}
		}
	}
	for _, ref := range root.CurrentAccess.Core.AccessPageRefs {
		if result := read(reconstructionAccessPagePart, ref); result.Outcome != 0 {
			return progress, result
		}
	}
	if result := read(reconstructionIndexPagePart, root.AdministrativeIndex); result.Outcome != 0 {
		return progress, result
	}
	for _, ref := range root.AdministrativeIndexShards {
		if result := read(reconstructionIndexPagePart, ref); result.Outcome != 0 {
			return progress, result
		}
	}
	return progress, Result{}
}

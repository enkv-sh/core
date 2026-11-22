package core

import (
	"context"

	"enkv.sh/core/contract"
)

// These dependencies are installed by the static composition. Candidate
// records cannot choose the reader's location, signing resource, key route or
// verifier. This private owner never receives a mutable Store or plaintext sink.
type reconstructionReaderFactory func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result)

type reconstructionInputs struct {
	candidate        candidateReadSource
	normal, recovery candidateSigningQualifier
	construct        reconstructionReaderFactory
	verifier         reconstructionVerifierFactory
	expectedDomain   contract.ID
}

// Complete selection has already consumed support bodies for its relations,
// generated proof and receipt windows. The material indexes retain positions
// and recipient IDs, not these bodies. Projection rereads exact selected rows
// from authenticated page facts, so it must not keep a second support tree.
func releasePublicSupportBodies(selected *publicSelection) {
	for i := range selected.image.support {
		selected.image.support[i].Records = nil
	}
	selected.image.cache = nil
}

func reconstructOneProjection(ctx context.Context, input reconstructionInputs) (*ReconstructionProjection, Result) {
	public, result := anchorPublicCandidate(ctx, input.candidate, input.expectedDomain, input.normal, input.recovery)
	if result.Outcome != 0 {
		return nil, result
	}
	if !reconstructionInvocationCurrent(ctx, public) {
		return nil, failure(EvidenceUnavailable, ReadUnavailable)
	}
	reader, result := input.construct(ctx, public.configuration)
	if reader != nil {
		defer reader.Close()
	}
	if !reconstructionInvocationCurrent(ctx, public) {
		return nil, failure(EvidenceUnavailable, ReadUnavailable)
	}
	if result != (Result{}) || reader == nil {
		if result.Outcome == 0 || result.Outcome == Unchanged || result.Outcome == ObservedCurrent {
			result = refused(AdmissionInvalid)
		}
		return nil, result
	}
	basis, result := bindPublicReadBasis(ctx, public, reader)
	if result.Outcome != 0 {
		return nil, result
	}
	var pendingRegistry contract.ID
	complete, result := completePublicSelection(ctx, basis, func(_ context.Context, work *generatedSelection) error {
		if work.registry != nil && len(work.registry.InitiallyAbsent) != 0 && !generatedSelectionAnchored(work) {
			pendingRegistry = work.registry.OperationID
		}
		return nil
	})
	if result.Outcome != 0 {
		return nil, result
	}
	// The complete reader has already checked every support body, relation and
	// family proof. Later work uses only selected facts and exact-ref rereads.
	// Drop its loaded support tree before the owned projection grows.
	releasePublicSupportBodies(&complete)
	owner, result := beginReconstructionProjection(&complete)
	if result != (Result{}) {
		return nil, result
	}
	defer owner.Abort()
	progress, result := emitReconstructionFixedParts(ctx, &complete, owner)
	if result != (Result{}) {
		return nil, result
	}
	progress, result = emitReconstructionSupportRows(ctx, &complete, owner, progress)
	if result != (Result{}) {
		return nil, result
	}
	if progress.parts != owner.partLimit || uint64(len(owner.parts)) != uint64(owner.partLimit) ||
		progress.bytes != owner.bytes {
		return nil, failure(IntegrityFailure, InvalidRelation)
	}
	observed := verifyReconstructionSelection(ctx, &complete, input.verifier)
	if observed.Outcome != ObservedCurrent {
		return nil, observed
	}
	if result := owner.Commit(ctx, observed); result != (Result{}) {
		return nil, result
	}
	projection := owner.takeCommitted()
	if projection == nil {
		return nil, refused(AdmissionInvalid)
	}
	projection.pendingRegistry = pendingRegistry
	return projection, observed
}

// reconstructOwnedCurrent restarts the entire independent read and private
// verification at most twice when HEAD changes. Only the final attempt can
// return an owned projection; failed attempt backing is discarded first.
func reconstructOwnedCurrent(ctx context.Context, input reconstructionInputs) (*ReconstructionProjection, Result) {
	if ctx == nil || input.candidate == nil || input.construct == nil || input.verifier == nil ||
		input.normal == nil && input.recovery == nil {
		return nil, refused(AdmissionInvalid)
	}
	deadline, ok := ctx.Deadline()
	if !ok || ctx.Err() != nil || !validPrivateDeadline(deadline) {
		return nil, failure(EvidenceUnavailable, ReadUnavailable)
	}
	for restarts := 0; restarts <= 2; restarts++ {
		projection, result := reconstructOneProjection(ctx, input)
		if result.Outcome == ObservedCurrent {
			return projection, result
		}
		if result.Outcome != Contention || result.Reason != DifferentSelection || restarts == 2 {
			return nil, result
		}
		if ctx.Err() != nil || !validPrivateDeadline(deadline) {
			return nil, failure(EvidenceUnavailable, ReadUnavailable)
		}
	}
	return nil, failure(Contention, DifferentSelection)
}

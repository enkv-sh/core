package core

import (
	"context"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func successionPublicOperation(kind uint8) uint16 {
	switch kind {
	case contract.SuccessionReplaceRecoveryBasis:
		return contract.OperationReplaceRecoveryKeysAndRoot
	default:
		return contract.OperationReplaceAuthorityKeys
	}
}

// projectedSuccessionRoot runs the same support layout and index sharder as
// the final writer. The receipt's only unknown fields are fixed-width digests
// and counts, so its request-identity hole has the final encoded length.

func (s *StateSession) projectedSuccessionRoot(ctx context.Context, q contract.SuccessionRequestCore, p transitionPlan, subjects contract.GeneratorDescriptor) (format.Root, error) {
	next := *s
	next.root.Snapshot, next.root.Transition = p.snapshot, p.transition
	if signerOnlyRecovery(q) {
		// The signer-only path preserves every support and index commitment.
		next.recountChildren()
		if next.root.ChildCount > contract.MaxChildPages {
			return format.Root{}, contract.ErrRecordCapacity
		}
		return next.root, nil
	}
	var projectedReceipt *contract.CompactMutationReceiptPlan
	if q.OperationKind == contract.SuccessionReplaceAuthority {
		if _, err := s.rebindGeneratedSnapshot(ctx, &next, p); err != nil {
			return format.Root{}, err
		}
		if err := s.installSuccessionSnapshotIndex(ctx, &next, &Candidate{session: s}); err != nil {
			return format.Root{}, err
		}
		return next.root, nil
	} else {
		before, err := s.receiptWindows(ctx)
		if err != nil {
			return format.Root{}, err
		}
		row := contract.CompactMutationReceiptPlan{Schema: contract.MutationReceiptSchema,
			OperationKind: successionPublicOperation(q.OperationKind), DomainID: q.DomainID,
			OperationID:           q.OperationID,
			PredecessorRevisionID: q.PredecessorHeadRevisionID, RequestedRevisionID: p.revision,
			ObservedRevisionID: p.revision, StateResult: contract.ReceiptStateSuccess,
			EvidenceCeiling: contract.ReceiptEvidenceCanonical, CanonicalOutcome: contract.ReceiptCanonicalSelected,
			ChangedSubjects: subjects,
			CompleteResult: contract.GeneratorDescriptor{Digest: contract.Hash([]byte("ENKV/succession-capacity-projection/v1")),
				Length: 8 + contract.MutationResultProjectionLength, Count: 1}}
		row.WarningBits, err = contract.EncodeReceiptWarningBits(row.OperationKind, s.root.WarningBits, 0)
		if err != nil {
			return format.Root{}, err
		}
		projectedReceipt = &row
		if q.ChangeMask&(contract.SuccessionChangeAuthorityKEK|contract.SuccessionChangeRecoveryKEK) != 0 {
			row.SummaryCounts[contract.ReceiptChangedAccessCount] = s.root.AccessRecordCount
		}
		delta := contract.MutationReceiptDeltaPlan{DomainID: q.DomainID, OperationKind: row.OperationKind,
			AddedCount: 1, Before: before, NewReceipt: row}
		storage, err := s.encodeMutationReceiptSupport(ctx, p, delta, contract.ID{})
		if err != nil {
			return format.Root{}, err
		}
		storage.install(&next)
	}
	if err := s.installAdministrativeIndex(ctx, &next, &Candidate{session: s}, projectedReceipt); err != nil {
		return format.Root{}, err
	}
	return next.root, nil
}

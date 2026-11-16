package core

import "enkv.sh/core/contract"

func validatePublicQueryResult(out PublicQueryResult) error {
	r := out.Result
	if q := out.PreAdmission; q != nil {
		if !out.RequestIdentity.IsZero() || out.OperationID.IsZero() || q.RequestNonce != out.RequestID || q.Stage == "" || q.Code == "" || q.SourceSchema == "" || q.SourceProfile == "" {
			return contract.ErrRecord
		}
	}
	if r.CommitMayHaveOccurred || !r.RequestedRevision.IsZero() || r.StoreReason > contract.ReasonProof || out.StateResult != publicQueryState(r, out.FailureReason) {
		return contract.ErrRecord
	}
	if r.Outcome == ObservedCurrent {
		if r.Reason != NoReason || r.StoreReason != contract.ReasonNone || r.Evidence != AuthenticatedClosure || r.ObservedRevision.IsZero() || r.ObservedSnapshotID.IsZero() || out.FailureReason != "" {
			return contract.ErrRecord
		}
		return nil
	}
	if r.Evidence != NoEvidence || !r.ObservedRevision.IsZero() || !r.ObservedSnapshotID.IsZero() {
		return contract.ErrRecord
	}
	switch r.Reason {
	case AdmissionInvalid, ConstructionMismatch, InvalidFormat, InvalidProof, InvalidReference, InvalidRelation, MissingSelectedObject, ReadUnavailable, CapacityExceeded, SigningUnavailable, DifferentSelection:
	default:
		return contract.ErrRecord
	}
	switch out.FailureReason {
	case contract.ReasonInvalidInput, contract.ReasonExpired, contract.ReasonCancelled, contract.ReasonUnsupportedProfile, contract.ReasonUnsupportedSchema, contract.ReasonLimitExceeded, contract.ReasonTargetAbsent, contract.ReasonLocatorUnusable:
		if r.Outcome != AdmissionRefused {
			return contract.ErrRecord
		}
	case contract.ReasonTrustBasisInvalid, contract.ReasonDomainBasisInvalid, contract.ReasonStoreBasisInvalid, contract.ReasonProofInvalid, contract.ReasonSelectedObjectInvalid, contract.ReasonSelectedRelationInvalid:
		if r.Outcome != AdmissionRefused && r.Outcome != IntegrityFailure {
			return contract.ErrRecord
		}
	case contract.ReasonHeadInvalid:
		if r.Outcome != IntegrityFailure {
			return contract.ErrRecord
		}
	case contract.ReasonEvidenceUnavailable, contract.ReasonSelectedObjectUnavailable, contract.ReasonPublicFactUnavailable:
		if r.Outcome != EvidenceUnavailable && r.Outcome != RootLossUnsupported {
			return contract.ErrRecord
		}
	case contract.ReasonReadContention:
		if r.Outcome != Contention {
			return contract.ErrRecord
		}
	default:
		return contract.ErrRecord
	}
	return nil
}

func validatePublicQueryBinding(out PublicQueryResult, q PublicQueryBasis, digest, selector contract.ID) error {
	if err := validatePublicQueryResult(out); err != nil {
		return err
	}
	computed, ok := q.digest(selector)
	if !ok || computed != digest || digest != out.RequestIdentity || out.OperationID != publicQueryOperationID(digest) || out.RequestID != q.RequestNonce || out.DomainID != q.ExpectedDomain || out.Operation != q.Operation {
		return contract.ErrRecord
	}
	if out.StateResult == PublicQuerySuccess && (q.Observation == nil || q.Observation.HeadRevisionID != out.Result.ObservedRevision || q.Observation.SnapshotID != out.Result.ObservedSnapshotID) {
		return contract.ErrRecord
	}
	return nil
}

func (q ReceiptListQueryIdentity) Validate() error {
	digest, ok := q.digest(contract.ID{})
	if !ok || q.Operation != ReceiptListOperation || q.Digest != digest {
		return contract.ErrRecord
	}
	return nil
}

func (q ReceiptDetailQueryIdentity) Validate() error {
	digest, ok := q.digest(q.RequestedOperationID)
	if !ok || q.Operation != ReceiptDetailOperation || q.Digest != digest {
		return contract.ErrRecord
	}
	return nil
}

func validateUnboundPublicQuery(out PublicQueryResult) error {
	if err := validatePublicQueryResult(out); err != nil {
		return err
	}
	if out.StateResult == PublicQueryProfileBlocked {
		if !out.RequestIdentity.IsZero() || out.Result != refused(AdmissionInvalid) {
			return contract.ErrRecord
		}
		return nil
	}
	if !out.RequestIdentity.IsZero() || out.StateResult != PublicQueryRefused &&
		(out.StateResult != PublicQueryUnavailable || out.Result.Outcome != EvidenceUnavailable || out.Result.Reason != ReadUnavailable || out.FailureReason != contract.ReasonEvidenceUnavailable) {
		return contract.ErrRecord
	}
	return nil
}

func validReceiptCurrent(observation PublicObservation, bits uint8, warnings PublicDomainWarnings, q *PublicObservation) bool {
	return q != nil && observation == *q && bits & ^uint8(31) == 0 && warnings == publicDomainWarnings(bits)
}

func (r PublicReceiptListResult) Validate() error {
	if r.Operation != ReceiptListOperation {
		return contract.ErrRecord
	}
	if r.Query == nil {
		if r.Payload != nil {
			return contract.ErrRecord
		}
		return validateUnboundPublicQuery(r.PublicQueryResult)
	}
	if err := r.Query.Validate(); err != nil {
		return err
	}
	if err := validatePublicQueryBinding(r.PublicQueryResult, r.Query.PublicQueryBasis, r.Query.Digest, contract.ID{}); err != nil {
		return err
	}
	if r.StateResult != PublicQuerySuccess {
		if r.Payload != nil {
			return contract.ErrRecord
		}
		return nil
	}
	p := r.Payload
	if p == nil || !validReceiptCurrent(p.Observation, p.CurrentDomainWarningBits, p.CurrentWarnings, r.Query.Observation) || p.Receipts == nil || len(p.Receipts) > 2*contract.MutationReceiptWindowLimit {
		return contract.ErrRecord
	}
	seen := make(map[contract.ID]bool, len(p.Receipts))
	var classes [2]int
	for _, row := range p.Receipts {
		if row.OperationID.IsZero() || row.ObservedRevisionID.IsZero() || row.RequestedRevisionID.IsZero() || seen[row.OperationID] ||
			!contract.CompactMutationReceiptSummaryValid(row.OperationKind, row.StateResult, row.EvidenceCeiling, row.CanonicalOutcome, row.WarningBits) ||
			(row.CanonicalOutcome == contract.ReceiptCanonicalSelected) != (row.RequestedRevisionID == row.ObservedRevisionID) {
			return contract.ErrRecord
		}
		seen[row.OperationID] = true
		classes[row.CanonicalOutcome-1]++
		if classes[row.CanonicalOutcome-1] > contract.MutationReceiptWindowLimit {
			return contract.ErrRecord
		}
	}
	return nil
}

func (r PublicReceiptDetailResult) Validate() error {
	if r.Operation != ReceiptDetailOperation {
		return contract.ErrRecord
	}
	if r.Query == nil {
		if r.Payload != nil {
			return contract.ErrRecord
		}
		return validateUnboundPublicQuery(r.PublicQueryResult)
	}
	if err := r.Query.Validate(); err != nil {
		return err
	}
	if err := validatePublicQueryBinding(r.PublicQueryResult, r.Query.PublicQueryBasis, r.Query.Digest, r.Query.RequestedOperationID); err != nil {
		return err
	}
	if r.StateResult != PublicQuerySuccess {
		if r.Payload != nil {
			return contract.ErrRecord
		}
		return nil
	}
	p := r.Payload
	if p == nil || !validReceiptCurrent(p.Observation, p.CurrentDomainWarningBits, p.CurrentWarnings, r.Query.Observation) || p.Receipt.DomainID != r.DomainID || p.Receipt.OperationID != r.Query.RequestedOperationID || p.Authenticity != "authenticated-retained" || p.Retention != "retained" {
		return contract.ErrRecord
	}
	stored, err := contract.InspectCompactMutationReceipt(p.EncodedReceipt)
	if err != nil || stored != p.Receipt {
		return contract.ErrRecord
	}
	return nil
}

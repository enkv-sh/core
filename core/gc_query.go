package core

import (
	"encoding/binary"

	"enkv.sh/core/contract"
)

type CapacityInspectionQueryIdentity struct {
	PublicQueryBasis
	Cursor                                string
	MarkDigest, EnumerationDigest, Digest contract.ID
}

type GCPreviewQueryIdentity struct {
	PublicQueryBasis
	Cursor                                string
	ProposedOperationID                   contract.ID
	MarkDigest, EnumerationDigest, Digest contract.ID
}

func gcQueryDigest(q PublicQueryBasis, cursor string, operation, mark, enumeration contract.ID) (contract.ID, bool) {
	if q.Operation != InspectCapacityOperation && q.Operation != GCPlanOperation ||
		q.Operation == InspectCapacityOperation && !operation.IsZero() || q.Operation == GCPlanOperation && operation.IsZero() ||
		(q.Observation == nil) != (mark.IsZero() && enumeration.IsZero()) || mark.IsZero() != enumeration.IsZero() {
		return contract.ID{}, false
	}
	fields, err := decodeGCCursorFields(cursor)
	if err != nil || cursor != "" && (fields.domain != q.ExpectedDomain || fields.store != q.StoreDescriptorDigest) {
		return contract.ID{}, false
	}
	body, ok := q.identityBytes(operation)
	if !ok {
		return contract.ID{}, false
	}
	body = binary.BigEndian.AppendUint32(body, uint32(len(cursor)))
	body = append(body, cursor...)
	body = append(body, mark[:]...)
	body = append(body, enumeration[:]...)
	return contract.Hash(body), true
}

func gcSourcePinsDigest(pins AdministrativeSourcePins) (contract.ID, error) {
	if !pins.Valid() {
		return contract.ID{}, contract.ErrRecord
	}
	body := []byte("ENKV/GC-SOURCE-PINS/v1\x00")
	for _, id := range []contract.ID{pins.FileID, pins.EditableDigest, pins.GeneratedDigest} {
		body = append(body, id[:]...)
	}
	body = append(body, pins.Format)
	body = binary.BigEndian.AppendUint64(body, pins.EditableLength)
	body = binary.BigEndian.AppendUint64(body, pins.GeneratedLength)
	if pins.HasGenerated {
		body = append(body, 1)
	} else {
		body = append(body, 0)
	}
	return contract.Hash(body), nil
}

// ValidateGCPlanScope rejects an untrusted artifact before provider construction.
// Current selected ownership, target bytes and the predecessor still require GETs.
func ValidateGCPlanScope(plan contract.GCPlan, domain contract.ID, store contract.Descriptor, basis PublicBasis, pins AdministrativeSourcePins) error {
	qualified, reason := qualifyBorrowedReaderPublicBasis(basis, domain, store)
	if reason != "" || plan.DomainID != domain || plan.PredecessorToken.Family != store.Family || !gcValidateTargetMapping(plan, store) {
		return contract.ErrRecord
	}
	source, err := gcSourcePinsDigest(pins)
	if err != nil || plan.SourcePinsDigest != source || plan.PublicBasisDigest != qualified.digest {
		return contract.ErrRecord
	}
	return nil
}

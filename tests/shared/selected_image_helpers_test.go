package core

import (
	"context"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func (s *StateSession) validateGeneratedFinalReceipt(ctx context.Context, subject contract.GeneratorAuthoritySubject, selected bool) error {
	if s == nil {
		return contract.ErrRecord
	}
	return (&selectedGeneratedProof{selectedImage: s.selectedImage(), head: s.head}).validateGeneratedFinalReceipt(ctx, subject, selected)
}

func (s *StateSession) generatedInitialIdentity(g *generatedSelection) (format.GeneratorInitialIdentity, error) {
	if s == nil {
		return format.GeneratorInitialIdentity{}, contract.ErrRecord
	}
	return (&selectedGeneratedProof{selectedImage: s.selectedImage(), head: s.head}).generatedInitialIdentity(g)
}

func selectedPublicationFilterProof(image *selectedImage) (*selectedPublicationProof, error) {
	rows, err := publicationSelectedRowProofs(image)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		for _, group := range image.adminIndex.Groups {
			if group.OwnerKind == format.AdministrativePublicationCoordinate ||
				group.OwnerKind == format.AdministrativePublicationMarker {
				return nil, contract.ErrRecord
			}
		}
		return nil, nil
	}
	if image.publicationProof == nil || !image.publicationProof.validFor(image) {
		return nil, contract.ErrRecord
	}
	return image.publicationProof, nil
}

func (s *StateSession) verifySelectedGeneratedSlices(ctx context.Context) Result {
	if ctx == nil || ctx.Err() != nil {
		return failure(EvidenceUnavailable, ReadUnavailable)
	}
	if s == nil || len(s.supportFacts) != len(s.root.RequiredSupport) {
		return failure(IntegrityFailure, InvalidRelation)
	}
	if rootDigest, ok := s.generatedSelectionRoot(); ok && !s.generatedSlicesRoot.IsZero() && s.generatedSlicesRoot == rootDigest {
		return Result{}
	}
	image := s.selectedImage()
	result := verifySelectedGeneratedSlices(ctx, image, s.selectedObjectReader())
	if result.Outcome != 0 {
		return result
	}
	rootDigest, ok := s.generatedSelectionRoot()
	if !ok {
		return failure(IntegrityFailure, InvalidRelation)
	}
	s.generatedSliceLocations, s.generatedSlicesRoot = image.generatedSliceLocations, rootDigest
	return Result{}
}

func (s *StateSession) selectedObservationExtraReads() (uint64, error) {
	return selectedObservationExtraReads(s.selectedImage(), selectedComplete)
}

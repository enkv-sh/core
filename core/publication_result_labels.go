package core

import (
	"bytes"
	"strings"
	"unicode/utf8"

	"enkv.sh/core/contract"
)

const (
	PublicationTargetCurrent uint8 = iota + 1
	PublicationTargetRetainedDeletion
)

// PublicationTargetDescription owns the safe labels captured from the admitted
// selection. It is result metadata, separate from stored outcome evidence.
type PublicationTargetDescription struct {
	CoordinateID      contract.ID
	Origin            uint8
	EntryName         *string
	DestinationID     *string
	ServiceContractID string
	CanonicalTarget   string
}

// ValidPublicationDescriptions checks the complete result-only relation before
// either public projection uses labels. It obtains no new state or authority.
func ValidPublicationDescriptions(domain contract.ID, output *contract.PublicationOutcomeVector, descriptions []PublicationTargetDescription) bool {
	if cap(descriptions) != len(descriptions) {
		return false
	}
	if output == nil {
		return len(descriptions) == 0
	}
	if domain.IsZero() || output.DomainID != domain || len(descriptions) != len(output.Entries) || len(descriptions) > contract.MaxPublicationCoordinates {
		return false
	}
	text := func(value string, maximum int, empty bool) bool {
		return (empty || len(value) != 0) && len(value) <= maximum && utf8.ValidString(value)
	}
	for i, row := range descriptions {
		if row.CoordinateID != output.Entries[i].CoordinateID || i > 0 && bytes.Compare(descriptions[i-1].CoordinateID[:], row.CoordinateID[:]) >= 0 || !text(row.ServiceContractID, 256, false) || !text(row.CanonicalTarget, 1024, false) ||
			row.EntryName != nil && !text(*row.EntryName, 256, true) || row.DestinationID != nil && !text(*row.DestinationID, 256, false) {
			return false
		}
		switch row.Origin {
		case PublicationTargetCurrent:
			if row.EntryName == nil || row.DestinationID == nil {
				return false
			}
		case PublicationTargetRetainedDeletion:
			if row.EntryName != nil {
				return false
			}
		default:
			return false
		}
		coordinate, err := contract.PublicationCoordinateID(domain, row.ServiceContractID, row.CanonicalTarget)
		if err != nil || coordinate != row.CoordinateID {
			return false
		}
	}
	return true
}

func (plan *publicationPlan) captureDescriptions() ([]PublicationTargetDescription, error) {
	if plan == nil || len(plan.targets) != len(plan.vector.Entries) || len(plan.targets) > contract.MaxPublicationCoordinates {
		return nil, contract.ErrRecord
	}
	descriptions := make([]PublicationTargetDescription, len(plan.targets))
	for i, target := range plan.targets {
		row := PublicationTargetDescription{CoordinateID: target.coordinate, Origin: PublicationTargetCurrent,
			ServiceContractID: strings.Clone(target.target.ServiceContractID), CanonicalTarget: strings.Clone(target.target.CanonicalTarget)}
		if target.deletion {
			row.Origin = PublicationTargetRetainedDeletion
			if target.retained.DeletionDestinationID != "" {
				destination := strings.Clone(target.retained.DeletionDestinationID)
				row.DestinationID = &destination
			}
		} else {
			if target.selection == nil || target.selection.DomainID != plan.vector.DomainID || target.selection.Entry.Incarnation != target.target.EntryIncarnationID || target.valueBasis.EntryIncarnationID != target.target.EntryIncarnationID {
				return nil, contract.ErrRecord
			}
			name, destination := strings.Clone(target.selection.Entry.Name), strings.Clone(target.destination)
			row.EntryName, row.DestinationID = &name, &destination
		}
		descriptions[i] = row
	}
	if !ValidPublicationDescriptions(plan.vector.DomainID, &plan.vector, descriptions) {
		return nil, contract.ErrRecord
	}
	return descriptions, nil
}

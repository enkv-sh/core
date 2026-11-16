package core

import (
	"enkv.sh/core/contract"
)

// Publication facts own their decoded fields. The digest still identifies the
// exact canonical record whose selected page was authenticated.
type selectedPublicationRecord struct {
	digest     contract.SupportRecordDigest
	coordinate *contract.PublicationCoordinate
	marker     *contract.PublicationMarker
}

func publicationSupportKind(kind uint8) bool {
	return kind == contract.PublicationCoordinateSupportKind || kind == contract.PublicationMarkerSupportKind
}

func inspectSelectedPublicationRecord(domain contract.ID, row contract.SupportRecord) (selectedPublicationRecord, error) {
	fact, err := contract.InspectSupportRecordDigest(domain, row)
	if err != nil {
		return selectedPublicationRecord{}, err
	}
	out := selectedPublicationRecord{digest: fact}
	switch row.Kind {
	case contract.PublicationCoordinateSupportKind:
		v, err := contract.InspectPublicationCoordinate(row.Body)
		if err != nil {
			return selectedPublicationRecord{}, err
		}
		out.coordinate = &v
	case contract.PublicationMarkerSupportKind:
		v, err := contract.InspectPublicationMarker(row.Body)
		if err != nil {
			return selectedPublicationRecord{}, err
		}
		out.marker = &v
	default:
		return selectedPublicationRecord{}, contract.ErrRecord
	}
	return out, nil
}

func (s *selectedImage) publicationRecord(row contract.SupportRecord) (selectedPublicationRecord, error) {
	if s == nil || !publicationSupportKind(row.Kind) {
		return selectedPublicationRecord{}, contract.ErrRecord
	}
	key := generatedRecordKey{row.Kind, row.RecordID}
	fact, present := s.publicationFacts[key]
	if row.Body != nil {
		if present && fact.digest.BodyLength() == uint32(len(row.Body)) && fact.digest.BodyDigest() == contract.Hash(row.Body) {
			return fact, nil
		}
		return inspectSelectedPublicationRecord(s.root.Domain, row)
	}
	if !present {
		return selectedPublicationRecord{}, contract.ErrRecord
	}
	// The typed fact alone does not select a row. Its digest must occur in the
	// current image's authenticated physical-row facts.
	for _, page := range s.supportFacts {
		for _, selected := range page.rows {
			if selected == fact.digest {
				return fact, nil
			}
		}
	}
	return selectedPublicationRecord{}, contract.ErrRecord
}

func (s *StateSession) publicationRecord(row contract.SupportRecord) (selectedPublicationRecord, error) {
	return s.selectedImage().publicationRecord(row)
}

func (r selectedPublicationRecord) body() ([]byte, error) {
	var body []byte
	var err error
	switch {
	case r.coordinate != nil && r.marker == nil:
		body, err = contract.EncodePublicationCoordinate(*r.coordinate)
	case r.marker != nil && r.coordinate == nil:
		body, err = contract.EncodePublicationMarker(*r.marker)
	default:
		return nil, contract.ErrRecord
	}
	if err != nil || uint32(len(body)) != r.digest.BodyLength() || contract.Hash(body) != r.digest.BodyDigest() {
		return nil, contract.ErrRecord
	}
	return body, nil
}

func (s *selectedImage) publicationRows(rows []contract.SupportRecord) (selectedPublication, error) {
	return s.publicationRowsForDomain(s.root.Domain, rows)
}

func (s *selectedImage) publicationRowsForDomain(domain contract.ID, rows []contract.SupportRecord) (selectedPublication, error) {
	selected := selectedPublication{coordinates: make(map[contract.ID]contract.PublicationCoordinate), markers: make(map[contract.ID]contract.PublicationMarker)}
	for _, row := range rows {
		if !publicationSupportKind(row.Kind) {
			continue
		}
		var fact selectedPublicationRecord
		var err error
		if row.Body != nil {
			fact, err = inspectSelectedPublicationRecord(domain, row)
		} else if domain == s.root.Domain {
			fact, err = s.publicationRecord(row)
		} else {
			err = contract.ErrRecord
		}
		if err != nil {
			return selectedPublication{}, err
		}
		if fact.coordinate != nil {
			if _, duplicate := selected.coordinates[row.RecordID]; duplicate {
				return selectedPublication{}, contract.ErrRecord
			}
			selected.coordinates[row.RecordID] = *fact.coordinate
		} else {
			if _, duplicate := selected.markers[row.RecordID]; duplicate {
				return selectedPublication{}, contract.ErrRecord
			}
			selected.markers[row.RecordID] = *fact.marker
		}
	}
	return selected, nil
}

func releaseSelectedPublicationPageBodies(image *selectedImage, i int) {
	page := image.support[i]
	hasPublication := false
	for _, row := range page.Records {
		hasPublication = hasPublication || publicationSupportKind(row.Kind)
	}
	if !hasPublication {
		return
	}
	for j, row := range page.Records {
		if publicationSupportKind(row.Kind) {
			image.support[i].Records[j].Body = nil
		}
	}
	delete(image.cache, image.root.RequiredSupport[i])
}

func publicationRecordWithFacts(domain contract.ID, row contract.SupportRecord, facts map[generatedRecordKey]selectedPublicationRecord) (selectedPublicationRecord, error) {
	if row.Body != nil {
		return inspectSelectedPublicationRecord(domain, row)
	}
	fact, present := facts[generatedRecordKey{row.Kind, row.RecordID}]
	if !present || fact.digest.Kind() != row.Kind || fact.digest.RecordID() != row.RecordID {
		return selectedPublicationRecord{}, contract.ErrRecord
	}
	return fact, nil
}

package core

import (
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// Scalar limits precede decoding and all row maps. Mixed selected images may
// contain other support families; publication rewrites contain only these two.
func publicationRowBounds(rows []contract.SupportRecord, exclusive bool) error {
	var coordinates, markers int
	for _, row := range rows {
		switch row.Kind {
		case contract.PublicationCoordinateSupportKind:
			coordinates++
			if coordinates > contract.MaxPublicationCoordinates || len(row.Body) > contract.MaxPublicationCoordinateRecordBytes-contract.SupportRecordOverhead {
				return contract.ErrRecordCapacity
			}
		case contract.PublicationMarkerSupportKind:
			markers++
			if markers > contract.MaxPublicationMarkers || len(row.Body) > contract.MaxPublicationMarkerRecordBytes-contract.SupportRecordOverhead {
				return contract.ErrRecordCapacity
			}
		default:
			if exclusive {
				return contract.ErrRecord
			}
		}
	}
	return nil
}

func publicationSupportBounds(pages []format.RequiredSupportPageView) error {
	var coordinates, markers int
	for _, page := range pages {
		for _, row := range page.Records {
			switch row.Kind {
			case contract.PublicationCoordinateSupportKind:
				coordinates++
				if coordinates > contract.MaxPublicationCoordinates || len(row.Body) > contract.MaxPublicationCoordinateRecordBytes-contract.SupportRecordOverhead {
					return contract.ErrRecordCapacity
				}
			case contract.PublicationMarkerSupportKind:
				markers++
				if markers > contract.MaxPublicationMarkers || len(row.Body) > contract.MaxPublicationMarkerRecordBytes-contract.SupportRecordOverhead {
					return contract.ErrRecordCapacity
				}
			}
		}
	}
	return nil
}

func publicationOwnedPageBounds(pages []format.RequiredSupportPage) error {
	var coordinates, markers int
	for _, page := range pages {
		for _, row := range page.Records {
			switch row.Kind {
			case contract.PublicationCoordinateSupportKind:
				coordinates++
				if coordinates > contract.MaxPublicationCoordinates || len(row.Body) > contract.MaxPublicationCoordinateRecordBytes-contract.SupportRecordOverhead {
					return contract.ErrRecordCapacity
				}
			case contract.PublicationMarkerSupportKind:
				markers++
				if markers > contract.MaxPublicationMarkers || len(row.Body) > contract.MaxPublicationMarkerRecordBytes-contract.SupportRecordOverhead {
					return contract.ErrRecordCapacity
				}
			}
		}
	}
	return nil
}

package core

import (
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// Current values, publication history, configuration and receipt windows can
// remain selected without any generated operation or GC owner. Work rows in
// that image must be claimed by those current owners, not by an absent graph.
func selectedCurrentOnlyRoot(root format.Root) bool {
	g := root.Generated
	return root.ActiveGC.IsZero() && root.GCPlans.Count == 0 &&
		g.ActiveOwner.IsZero() && g.ActivePhase.IsZero() && g.ActiveGraph.IsZero() &&
		g.Graphs.Count == 0 && g.LiveOwners.Count == 0 && g.Retiring == 0 &&
		g.Attempts == 0 && g.Duties == 0 && g.Hazards == 0 && g.Results == 0 && g.Materials == 0 && g.PendingReleases == 0
}

func selectedIndexOwnerBounds(root format.Root, index format.AdministrativeIndex, complete, currentSupport bool, currentEvidence map[contract.ID]bool) bool {
	var coordinates, markers, fragments, receipts, evidence, slices, configuration uint32
	currentOnly := selectedCurrentOnlyRoot(root)
	seenEvidence := make(map[contract.ID]bool)
	for _, group := range index.Groups {
		if currentOnly && group.OwnerKind != format.AdministrativePublicationCoordinate && group.OwnerKind != format.AdministrativePublicationMarker {
			return false
		}
	}
	for _, page := range index.Pages {
		if page.ReadRequired {
			for _, span := range page.Spans {
				slices += uint32(span.Count)
			}
			continue
		}
		logical := 0
		for _, span := range page.Spans {
			for _, row := range page.Rows[logical : logical+int(span.Count)] {
				switch row.Kind {
				case contract.PublicationCoordinateSupportKind:
					coordinates++
				case contract.PublicationMarkerSupportKind:
					markers++
				case contract.GeneratedFragmentSupportKind:
					fragments++
				case contract.MutationReceiptSupportKind:
					receipts++
				case contract.GeneratedCreateEvidenceSupportKind:
					evidence++
					if currentOnly {
						if !span.Mandatory || !currentEvidence[row.RecordID] || seenEvidence[row.RecordID] {
							return false
						}
						seenEvidence[row.RecordID] = true
					}
				case contract.OutputConfigurationSliceSupportKind:
					configuration++
				case contract.GeneratorVectorSupportKind:
					if currentOnly && complete && !currentSupport {
						return false
					}
				default:
					if currentOnly && complete {
						return false
					}
				}
			}
			logical += int(span.Count)
		}
	}
	if coordinates > contract.MaxPublicationCoordinates || markers > contract.MaxPublicationMarkers || fragments > uint32(len(root.Generated.Fragments)) {
		return false
	}
	if currentOnly && len(seenEvidence) != len(currentEvidence) {
		return false
	}
	if currentOnly && complete {
		// Receipt indexes have their own blob owner; output configuration
		// slices are separate kind-17 rows. The scanner binds current Slice
		// keys to decoded entries before reading these selected spans.
		return evidence <= root.Generated.GeneratedCurrent &&
			receipts <= root.Generated.SuccessWindow.Count+root.Generated.FailureWindow.Count &&
			slices <= root.Generated.Slices.Count &&
			configuration <= uint32(root.OutputConfiguration.SliceCount)
	}
	return true
}

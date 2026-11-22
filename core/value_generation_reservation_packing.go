package core

import (
	"bytes"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func generatedUniqueLocations(rows []contract.GeneratorSliceLocation) ([]contract.GeneratorSliceLocation, error) {
	slices.SortStableFunc(rows, func(a, b contract.GeneratorSliceLocation) int {
		if a.ContentKind != b.ContentKind {
			return int(a.ContentKind) - int(b.ContentKind)
		}
		return bytes.Compare(a.ContentID[:], b.ContentID[:])
	})
	out := rows[:0]
	for _, row := range rows {
		if len(out) != 0 {
			last := out[len(out)-1]
			if last.ContentKind == row.ContentKind && last.ContentID == row.ContentID {
				if last.Logical() != row.Logical() {
					return nil, contract.ErrRecord
				}
				continue
			}
		}
		out = append(out, row)
	}
	return out, nil
}

func generatedReservationGroups(rows []contract.SupportRecord, locations []contract.GeneratorSliceLocation, bundles []contract.GeneratorPlanBundle) ([]format.RequiredSupportGroup, error) {
	return generatedReservationGroupsWithFacts(rows, locations, bundles, nil)
}

// generatedReservationGroupsWithFacts uses authenticated selected fragment
// headers when a complete reader has released their payload backing. Other
// rows still require their complete typed bodies.
func generatedReservationGroupsWithFacts(rows []contract.SupportRecord, locations []contract.GeneratorSliceLocation,
	bundles []contract.GeneratorPlanBundle, fragments map[contract.ID]selectedFragmentFact) ([]format.RequiredSupportGroup, error) {
	type key struct {
		class format.SupportStorageGroup
		owner contract.ID
	}
	inboxes := make(map[contract.ID]contract.ID)
	retained := make(map[contract.ID]contract.GeneratedAttemptRecord)
	for _, row := range rows {
		if row.Kind != contract.GeneratedAttemptSupportKind {
			continue
		}
		a, err := contract.InspectGeneratedAttemptRecord(row.Body)
		if err != nil || row.RecordID != a.AttemptID || !inboxes[a.InboxID].IsZero() {
			return nil, contract.ErrRecord
		}
		if _, exists := retained[a.AttemptID]; exists {
			return nil, contract.ErrRecord
		}
		inboxes[a.InboxID], retained[a.AttemptID] = a.AttemptID, a
	}
	attempts := make(map[contract.ID]key)
	lineages := make(map[contract.ID]contract.GeneratorLineageTemplate)
	firstEntered := make(map[contract.ID]key)
	for _, bundle := range bundles {
		if err := contract.ValidateGeneratorEffectGraph(bundle); err != nil {
			return nil, err
		}
		operation := bundle.Header.OperationID
		if _, exists := firstEntered[operation]; exists {
			return nil, contract.ErrRecord
		}
		firstEntered[operation] = key{}
		for _, lineage := range bundle.Lineages {
			if _, exists := lineages[lineage.LineageID]; exists {
				return nil, contract.ErrRecord
			}
			lineages[lineage.LineageID] = lineage
			for _, x := range lineage.Templates[:lineage.TemplateCount] {
				if _, exists := attempts[x.AttemptID]; exists {
					return nil, contract.ErrRecord
				}
				k := key{class: format.CreateContinuationSupport, owner: x.AttemptID}
				if x.Action == contract.GeneratorActionDelete {
					k.class = format.DeleteContinuationSupport
				}
				attempts[x.AttemptID] = k
				if a, exists := retained[x.AttemptID]; exists {
					if a.DomainID != bundle.Header.DomainID || a.OperationID != operation || !generatedAttemptMatches(a, x) {
						return nil, contract.ErrRecord
					}
					if firstEntered[operation].class == 0 {
						firstEntered[operation] = k
					}
					delete(retained, x.AttemptID)
				}
			}
		}
	}
	if len(retained) != 0 {
		return nil, contract.ErrRecord
	}
	blobs := make(map[contract.ID]format.SupportStorageGroup)
	for _, location := range locations {
		class := format.AuxiliaryFragmentSupport
		switch location.ContentKind {
		case contract.GeneratorContentGraph:
			class = format.GraphFragmentSupport
		case contract.GeneratorContentIntent, contract.GeneratorContentDeclaration, contract.GeneratorContentSource:
			class = format.IntentFragmentSupport
		}
		if old, exists := blobs[location.BlobID]; exists && old != class {
			return nil, contract.ErrRecord
		}
		blobs[location.BlobID] = class
	}
	groups := make(map[key][]contract.SupportRecord)
	for _, row := range rows {
		k := key{owner: row.RecordID}
		switch row.Kind {
		case contract.GCPlanSupportKind:
			k = key{class: format.GCPlanSupport, owner: row.RecordID}
		case contract.OperationMaterialSupportKind:
			material, err := contract.InspectOperationMaterialRecord(row.Body)
			if err != nil {
				return nil, err
			}
			k.class, k.owner = format.MaterialSupport, material.Core.OperationID
		case contract.GeneratedParentSupportKind:
			k.class = format.MaterialSupport
		case contract.GeneratedFragmentSupportKind:
			var blob contract.ID
			if row.Body == nil {
				fact, ok := fragments[row.RecordID]
				if !ok || fact.row.Kind() != row.Kind || fact.row.RecordID() != row.RecordID || fact.blob.IsZero() {
					return nil, contract.ErrRecord
				}
				blob = fact.blob
			} else {
				fragment, err := contract.InspectGeneratedFragment(row.Body)
				if err != nil {
					return nil, err
				}
				blob = fragment.BlobID
			}
			k.owner, k.class = blob, blobs[blob]
			if k.class == 0 { // Receipt index is checked by its own closed projection.
				k.class = format.AuxiliaryFragmentSupport
			}
		case contract.OutputConfigurationSliceSupportKind:
			k.class = format.OutputConfigurationSupport
			if row.Body == nil {
				fact, ok := fragments[row.RecordID]
				if !ok || fact.row.Kind() != row.Kind || fact.blob.IsZero() {
					return nil, contract.ErrRecord
				}
				k.owner = fact.blob
			} else {
				configuration, err := contract.InspectOutputConfigurationSlice(row.Body)
				if err != nil {
					return nil, err
				}
				k.owner = configuration.ConfigurationDigest
			}
		case contract.PublicationCoordinateSupportKind, contract.PublicationMarkerSupportKind:
			k.class = format.OwnerSupport
		case contract.GeneratedResultSupportKind:
			result, err := contract.InspectGeneratedResultRecord(row.Body)
			if err != nil || row.RecordID != result.Core.ResultID {
				return nil, contract.ErrRecord
			}
			continuation := attempts[result.Core.AttemptID]
			if continuation.class == 0 {
				return nil, contract.ErrRecord
			}
			k.class = format.ResultSupport
			if continuation.class == format.DeleteContinuationSupport {
				k = continuation
			}
		case contract.GeneratedFinalPreparationSupportKind:
			preparation, err := contract.InspectGeneratedFinalPreparationRecord(row.Body)
			if err != nil || row.RecordID != preparation.OperationID {
				return nil, contract.ErrRecord
			}
			k = firstEntered[preparation.OperationID]
		case contract.GeneratedPhaseSupportKind:
			phase, err := contract.InspectGeneratedPhaseRecord(row.Body)
			if err != nil {
				return nil, err
			}
			k = firstEntered[phase.OperationID]
		case contract.GeneratedAttemptSupportKind:
			k = attempts[row.RecordID]
		case contract.GeneratedLineageSupportKind:
			v, err := contract.InspectGeneratedLineageRecord(row.Body)
			lineage, ok := lineages[row.RecordID]
			if err != nil || !ok || lineage.Purpose != contract.GeneratorLineageCreate || v.DomainID != lineage.DomainID || v.OperationID != lineage.OperationID ||
				v.LineageID != lineage.LineageID || v.Branch >= lineage.TemplateCount {
				return nil, contract.ErrRecord
			}
			k = attempts[lineage.Templates[v.Branch].AttemptID]
		case contract.RetainedCanonicalSupportKind, contract.GeneratedCreateEvidenceSupportKind:
			k.class = format.OldValueSupport
		case contract.MutationReceiptSupportKind:
			k.class = format.ReceiptSupport
		case contract.GeneratedDutySupportKind, contract.GeneratedHazardSupportKind:
			k.class = format.OwnerSupport
		case contract.PendingInboxReleaseSupportKind:
			r, err := contract.InspectPendingInboxReleaseRecord(row.Body)
			if err != nil || inboxes[r.InboxID].IsZero() {
				return nil, contract.ErrRecord
			}
			k = attempts[inboxes[r.InboxID]]
		case contract.GeneratorVectorSupportKind:
			v, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				return nil, err
			}
			k.owner = v.OwnerID
			switch v.VectorKind {
			case contract.GeneratorVectorSlices:
				// Slice rows are independent page-sized index groups.
				k.class, k.owner = format.GraphIndexSupport, row.RecordID
			case contract.GeneratorVectorConsumers, contract.GeneratorVectorSupport:
				k.class, k.owner = format.AuxiliaryIndexSupport, row.RecordID
			case contract.GeneratorVectorFacts:
				k = attempts[v.OwnerID]
			case contract.GeneratorVectorProgress:
				progress, err := contract.InspectGeneratorProgress(v.Row)
				if err != nil {
					return nil, err
				}
				k = attempts[progress.AttemptID]
			case contract.GeneratorVectorHistory:
				history, err := contract.InspectGeneratorHistory(v.Row)
				if err != nil {
					return nil, err
				}
				k = attempts[history.PredecessorAttemptID]
			case contract.GeneratorVectorProofs:
				proof, err := contract.InspectGeneratorProof(v.Row)
				if err != nil {
					return nil, err
				}
				subject, err := contract.DecodeGeneratorAuthoritySubject(proof.Subject)
				if err != nil {
					return nil, err
				}
				k = attempts[subject.AttemptID]
				if subject.AttemptID.IsZero() {
					k = firstEntered[subject.OperationID]
				}
			case contract.GeneratorVectorTargets:
				k.class = format.OwnerSupport
			default:
				return nil, contract.ErrRecord
			}
		default:
			return nil, contract.ErrRecord
		}
		if k.class == 0 {
			return nil, contract.ErrRecord
		}
		groups[k] = append(groups[k], row)
	}
	out := make([]format.RequiredSupportGroup, 0, len(groups))
	for k, rows := range groups {
		out = append(out, format.RequiredSupportGroup{Class: k.class, Owner: k.owner, Records: rows})
	}
	return out, nil
}

func generatedFragmentDirectory(pages []format.RequiredSupportPage) ([]format.FragmentLocation, error) {
	return generatedFragmentDirectoryWithSelectedFacts(pages, nil)
}

func generatedFragmentDirectoryWithSelectedFacts(pages []format.RequiredSupportPage,
	facts map[contract.ID]selectedFragmentFact) ([]format.FragmentLocation, error) {
	var directory []format.FragmentLocation
	for _, page := range pages {
		for i, row := range page.Records {
			if row.Kind != contract.GeneratedFragmentSupportKind {
				continue
			}
			if row.Body == nil {
				fact, ok := facts[row.RecordID]
				if !ok || i > 255 || fact.row.Kind() != row.Kind || fact.row.RecordID() != row.RecordID ||
					fact.ref.Index != page.Index || fact.ref.Domain != page.Domain ||
					fact.ref.Object != page.Object || int(fact.logical) != i {
					return nil, contract.ErrRecord
				}
				directory = append(directory, format.FragmentLocation{BlobID: fact.blob, FragmentIndex: fact.index,
					SupportPageIndex: page.Index, RowSlot: uint8(i)})
				continue
			}
			fragment, err := contract.InspectGeneratedFragment(row.Body)
			if err != nil || i > 255 {
				return nil, contract.ErrRecord
			}
			directory = append(directory, format.FragmentLocation{BlobID: fragment.BlobID, FragmentIndex: fragment.Index, SupportPageIndex: page.Index, RowSlot: uint8(i)})
		}
	}
	slices.SortFunc(directory, func(a, b format.FragmentLocation) int {
		if order := bytes.Compare(a.BlobID[:], b.BlobID[:]); order != 0 {
			return order
		}
		return int(a.FragmentIndex) - int(b.FragmentIndex)
	})
	return directory, nil
}

func (s *StateSession) packGeneratedAccess(rows []contract.AccessRecord, request contract.ID, candidate *Candidate) ([]format.AccessPage, error) {
	return s.packGeneratedAccessWithPageID(rows, request, candidate, func(kind contract.Kind, index uint16) (contract.ID, error) {
		return contract.GeneratorInitialPageID(request, kind, index)
	})
}

func (s *StateSession) packGeneratedAccessWithPageID(rows []contract.AccessRecord, seed contract.ID, candidate *Candidate,
	pageID func(contract.Kind, uint16) (contract.ID, error)) ([]format.AccessPage, error) {
	slices.SortFunc(rows, func(a, b contract.AccessRecord) int {
		if a.MaterialKind != b.MaterialKind {
			return int(a.MaterialKind) - int(b.MaterialKind)
		}
		return bytes.Compare(a.MaterialID[:], b.MaterialID[:])
	})
	descriptor, err := contract.AccessRecordsDescriptor(s.root.Domain, rows)
	if err != nil {
		return nil, err
	}
	var pages []format.AccessPage
	page := format.AccessPage{Domain: s.root.Domain}
	length := contract.AccessPageHeaderLength
	flush := func() error {
		if len(page.Records) == 0 {
			return nil
		}
		if len(pages) == contract.MaxChildPages {
			return contract.ErrRecordCapacity
		}
		page.Index = uint16(len(pages))
		var err error
		page.Object, err = pageID(format.AccessKind, page.Index)
		if err != nil {
			return err
		}
		pages = append(pages, page)
		page, length = format.AccessPage{Domain: s.root.Domain}, contract.AccessPageHeaderLength
		return nil
	}
	for _, row := range rows {
		size, err := contract.AccessRecordLength(row)
		if err != nil {
			return nil, err
		}
		if length+size > contract.MaxAccessPageLength || len(page.Records) == contract.AccessPageRecordLimit {
			if err := flush(); err != nil {
				return nil, err
			}
		}
		page.Records, length = append(page.Records, row), length+size
	}
	if err := flush(); err != nil {
		return nil, err
	}
	s.root.CurrentAccess.Core.AccessPageRefs, s.access = nil, [contract.MaxChildPages]*format.AccessPage{}
	for i := range pages {
		page := &pages[i]
		body, err := format.EncodeAccessPage(*page)
		if err != nil {
			return nil, err
		}
		ref, err := format.Reference(format.AccessKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			return nil, err
		}
		s.access[i] = page
		s.root.CurrentAccess.Core.AccessPageRefs = append(s.root.CurrentAccess.Core.AccessPageRefs, ref)
		candidate.objects = append(candidate.objects, objectImage{ref: ref, body: body})
	}
	s.root.AccessRecordCount = uint32(len(rows))
	s.root.CurrentAccess.Core.AccessRecordsDescriptor = descriptor
	if err := contract.AdvanceAccessGeneration(&s.root.CurrentAccess.Core, seed); err != nil {
		return nil, err
	}
	s.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(s.root.CurrentAccess.Core)
	return pages, err
}

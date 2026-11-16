package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// generatedSupportPages keeps a body's absence distinct from an empty body.
// Only a previously authenticated fragment may have nil Body. It plans the
// same class/mandatory boundaries as the canonical support packer without
// retaining old fragment payloads.
func generatedSupportPages(domain contract.ID, groups []format.RequiredSupportGroup, otherChildren uint32,
	fragments map[contract.ID]selectedFragmentFact) ([][]contract.SupportRecord, error) {
	return generatedSupportPagesWithParent(domain, groups, otherChildren, fragments, nil)
}

func generatedSupportPagesWithParent(domain contract.ID, groups []format.RequiredSupportGroup, otherChildren uint32,
	fragments map[contract.ID]selectedFragmentFact, parent *contract.GeneratedParentPlan) ([][]contract.SupportRecord, error) {
	if domain.IsZero() || otherChildren > contract.MaxChildPages {
		return nil, contract.ErrRecord
	}
	var ordinary, fragmentGroups []format.RequiredSupportGroup
	for _, group := range groups {
		if group.Class >= format.IntentFragmentSupport && group.Class <= format.OutputConfigurationSupport {
			fragmentGroups = append(fragmentGroups, group)
		} else {
			ordinary = append(ordinary, group)
		}
	}
	var pages [][]contract.SupportRecord
	var err error
	if parent == nil {
		pages, err = format.PackRequiredSupportRows(domain, ordinary, otherChildren)
	} else {
		pages, err = format.PackRequiredSupportParentPlan(domain, ordinary, otherChildren, *parent)
	}
	if err != nil {
		return nil, err
	}
	slices.SortFunc(fragmentGroups, func(a, b format.RequiredSupportGroup) int {
		if a.Class != b.Class {
			return int(a.Class) - int(b.Class)
		}
		if a.Mandatory != b.Mandatory {
			if a.Mandatory {
				return -1
			}
			return 1
		}
		return bytes.Compare(a.Owner[:], b.Owner[:])
	})
	seen := make(map[generatedRecordKey]bool)
	for _, page := range pages {
		for _, row := range page {
			seen[generatedRecordKey{row.Kind, row.RecordID}] = true
		}
	}
	var page []contract.SupportRecord
	pageLength := contract.RequiredSupportPageHeaderLength
	flush := func() error {
		if len(page) == 0 {
			return nil
		}
		if uint32(len(pages))+otherChildren >= contract.MaxChildPages {
			return contract.ErrRecordCapacity
		}
		pages = append(pages, page)
		page, pageLength = nil, contract.RequiredSupportPageHeaderLength
		return nil
	}
	for i, group := range fragmentGroups {
		if group.Owner.IsZero() || len(group.Records) == 0 || group.Class > format.OutputConfigurationSupport ||
			i > 0 && fragmentGroups[i-1].Class == group.Class && fragmentGroups[i-1].Mandatory == group.Mandatory &&
				fragmentGroups[i-1].Owner == group.Owner {
			return nil, contract.ErrRecord
		}
		if i > 0 && (fragmentGroups[i-1].Class != group.Class || fragmentGroups[i-1].Mandatory != group.Mandatory) {
			if err := flush(); err != nil {
				return nil, err
			}
		}
		rows := slices.Clone(group.Records)
		slices.SortFunc(rows, func(a, b contract.SupportRecord) int {
			if a.Kind != b.Kind {
				return int(a.Kind) - int(b.Kind)
			}
			return bytes.Compare(a.RecordID[:], b.RecordID[:])
		})
		for _, row := range rows {
			key := generatedRecordKey{row.Kind, row.RecordID}
			if !opaqueSupportKind(row.Kind) || row.RecordID.IsZero() || seen[key] {
				return nil, contract.ErrRecord
			}
			seen[key] = true
			if (row.Kind == contract.OutputConfigurationSliceSupportKind) != (group.Class == format.OutputConfigurationSupport) {
				return nil, contract.ErrRecord
			}
			length := len(row.Body)
			if row.Body == nil {
				fact, ok := fragments[row.RecordID]
				if !ok || fact.blob != group.Owner || fact.row.Kind() != row.Kind || fact.row.RecordID() != row.RecordID {
					return nil, contract.ErrRecord
				}
				length = int(fact.row.BodyLength())
			} else if row.Kind == contract.OutputConfigurationSliceSupportKind {
				configuration, err := contract.InspectOutputConfigurationSlice(row.Body)
				if err != nil || group.Class != format.OutputConfigurationSupport || configuration.ConfigurationDigest != group.Owner {
					return nil, contract.ErrRecord
				}
			} else {
				if group.Class == format.OutputConfigurationSupport {
					return nil, contract.ErrRecord
				}
				fragment, err := contract.InspectGeneratedFragment(row.Body)
				if err != nil || fragment.BlobID != group.Owner {
					return nil, contract.ErrRecord
				}
			}
			minimum := contract.GeneratedFragmentHeaderLength
			if row.Kind == contract.OutputConfigurationSliceSupportKind {
				minimum = contract.OutputConfigurationSliceBodyOverhead
			}
			framed := contract.SupportRecordOverhead + length
			if length < minimum || framed > format.MaxRequiredSupportPage-contract.RequiredSupportPageHeaderLength {
				return nil, contract.ErrRecordCapacity
			}
			if len(page) == 2 || pageLength+framed > format.MaxRequiredSupportPage {
				if err := flush(); err != nil {
					return nil, err
				}
			}
			page, pageLength = append(page, row), pageLength+framed
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return pages, nil
}

type generatedMaterializedPage struct {
	object    objectImage
	view      format.RequiredSupportPageView
	page      format.RequiredSupportPage
	fragments []format.FragmentLocation
	parent    bool
}

func (s *StateSession) selectedFragmentLocationsByRecord() (map[contract.ID]format.FragmentLocation, error) {
	byID := make(map[contract.ID]format.FragmentLocation, len(s.fragmentFacts))
	for location, fact := range s.fragmentFacts {
		id := fact.row.RecordID()
		if _, duplicate := byID[id]; duplicate {
			return nil, fmt.Errorf("materialize support duplicate fragment fact: %w", contract.ErrRecord)
		}
		byID[id] = location
	}
	return byID, nil
}

// materializeGeneratedSupportPageAt borrows old fragments one at a time and
// encodes only this changed page. physicalIndex is the final Ref.Index; it is
// independent of the page's compact position in a selected Root.
func (s *StateSession) materializeGeneratedSupportPageAt(ctx context.Context, planned []contract.SupportRecord,
	pageID contract.ID, physicalIndex uint16, parent *contract.GeneratedParentPlan,
	byID map[contract.ID]format.FragmentLocation) (generatedMaterializedPage, error) {
	if s == nil || ctx == nil || pageID.IsZero() || len(planned) == 0 {
		return generatedMaterializedPage{}, fmt.Errorf("materialize support page identity: %w", contract.ErrRecord)
	}
	rows := slices.Clone(planned)
	var err error
	for j, row := range rows {
		if row.Kind == contract.OutputConfigurationSliceSupportKind && row.Body == nil {
			rows[j].Body, err = s.readSelectedOutputSupportRow(ctx, row.RecordID)
			if err != nil {
				return generatedMaterializedPage{}, err
			}
			continue
		}
		if row.Kind != contract.GeneratedFragmentSupportKind || row.Body != nil {
			continue
		}
		location, ok := byID[row.RecordID]
		if !ok {
			return generatedMaterializedPage{}, fmt.Errorf("materialize support selected fragment identity: %w", contract.ErrRecord)
		}
		fact := s.fragmentFacts[location]
		result, err := s.withSelectedFragment(ctx, location, func(payload []byte) error {
			body, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: contract.GeneratorRecordSchema,
				BlobID: fact.blob, Index: fact.index, Count: fact.count, TotalLength: fact.total,
				WholeDigest: fact.whole, Offset: fact.offset, Payload: payload})
			if err != nil || uint32(len(body)) != fact.row.BodyLength() || contract.Hash(body) != fact.row.BodyDigest() {
				return contract.ErrRecord
			}
			rows[j].Body = body
			return nil
		})
		if result.Outcome != 0 {
			return generatedMaterializedPage{}, selectedReadFailure(result)
		}
		if err != nil {
			return generatedMaterializedPage{}, err
		}
	}
	page := format.RequiredSupportPage{Domain: s.root.Domain, Object: pageID, Index: physicalIndex, Records: rows}
	plannedParent := false
	if parent != nil {
		for _, row := range rows {
			if row.Kind == contract.GeneratedParentSupportKind && row.RecordID == parent.OperationID {
				plannedParent = true
			}
		}
	}
	var body []byte
	if plannedParent {
		body, err = format.EncodeRequiredSupportParentPlan(page, *parent)
	} else {
		body, err = format.EncodeRequiredSupportPage(page)
	}
	if err != nil {
		return generatedMaterializedPage{}, fmt.Errorf("materialize support encode page: %w", err)
	}
	ref := format.Ref{Kind: contract.RequiredSupportKind, Format: format.Version, Domain: page.Domain,
		Object: page.Object, Index: page.Index, Digest: contract.Hash(body), Length: uint32(len(body))}
	if !plannedParent {
		ref, err = format.Reference(contract.RequiredSupportKind, s.root.Domain, page.Object, page.Index, body)
		if err != nil {
			return generatedMaterializedPage{}, err
		}
	}
	var view format.RequiredSupportPageView
	if !plannedParent {
		view, err = format.InspectRequiredSupportPage(body)
		if err != nil {
			return generatedMaterializedPage{}, err
		}
		for slot := range rows {
			rows[slot].Body = view.Records[slot].Body
		}
	}
	out := generatedMaterializedPage{object: objectImage{ref: ref, body: body}, view: view,
		page: page, parent: plannedParent}
	for slot, row := range view.Records {
		if row.Kind != contract.GeneratedFragmentSupportKind {
			continue
		}
		fragment, err := contract.InspectGeneratedFragment(row.Body)
		if err != nil || slot > 255 {
			return generatedMaterializedPage{}, contract.ErrRecord
		}
		out.fragments = append(out.fragments, format.FragmentLocation{BlobID: fragment.BlobID,
			FragmentIndex: fragment.Index, SupportPageIndex: physicalIndex, RowSlot: uint8(slot)})
	}
	return out, nil
}

func (s *StateSession) materializeGeneratedSupportPages(ctx context.Context, packed [][]contract.SupportRecord,
	pageIDs []contract.ID) (generatedRequiredSupportMaterialization, error) {
	return s.materializeGeneratedSupportPagesWithParent(ctx, packed, pageIDs, nil)
}

func (s *StateSession) materializeGeneratedSupportPagesWithParent(ctx context.Context, packed [][]contract.SupportRecord,
	pageIDs []contract.ID, parent *contract.GeneratedParentPlan) (generatedRequiredSupportMaterialization, error) {
	if s == nil || ctx == nil || len(packed) != len(pageIDs) {
		return generatedRequiredSupportMaterialization{}, fmt.Errorf("materialize support input: %w", contract.ErrRecord)
	}
	byID, err := s.selectedFragmentLocationsByRecord()
	if err != nil {
		return generatedRequiredSupportMaterialization{}, err
	}
	out := generatedRequiredSupportMaterialization{objects: make([]objectImage, 0, len(packed)),
		references: make([]format.Ref, 0, len(packed)), views: make([]format.RequiredSupportPageView, 0, len(packed)),
		pages:         make([]format.RequiredSupportPage, 0, len(packed)),
		identityPages: make([]contract.IdentityPage, 0, len(packed))}
	indexes, err := s.generatedSupportPhysicalIndexes(packed)
	if err != nil {
		return generatedRequiredSupportMaterialization{}, err
	}
	parentPages := 0
	for i, planned := range packed {
		if retained, ok := s.retainedOutputPage(planned); ok {
			position := slices.Index(s.root.RequiredSupport, retained.ref)
			if position < 0 {
				return generatedRequiredSupportMaterialization{}, contract.ErrRecord
			}
			view := s.support[position]
			records := make([]contract.SupportRecord, len(view.Records))
			for j, row := range view.Records {
				records[j] = contract.SupportRecord(row)
			}
			out.references = append(out.references, retained.ref)
			out.views = append(out.views, view)
			out.pages = append(out.pages, format.RequiredSupportPage{Domain: view.Domain, Object: view.Object, Index: view.Index, Records: records})
			out.identityPages = append(out.identityPages, contract.IdentityPage{Kind: retained.ref.Kind, Index: retained.ref.Index, Object: retained.ref.Object})
			out.recordCount += uint32(len(records))
			continue
		}
		materialized, err := s.materializeGeneratedSupportPageAt(ctx, planned, pageIDs[i], indexes[i], parent, byID)
		if err != nil {
			return generatedRequiredSupportMaterialization{}, err
		}
		if materialized.parent {
			parentPages++
		}
		out.fragments = append(out.fragments, materialized.fragments...)
		out.objects = append(out.objects, materialized.object)
		out.references = append(out.references, materialized.object.ref)
		out.views = append(out.views, materialized.view)
		out.pages = append(out.pages, materialized.page)
		out.identityPages = append(out.identityPages, contract.IdentityPage{Kind: contract.RequiredSupportKind,
			Index: indexes[i], Object: materialized.page.Object})
		out.recordCount += uint32(len(materialized.page.Records))
	}
	slices.SortFunc(out.identityPages, func(a, b contract.IdentityPage) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return int(a.Index) - int(b.Index)
	})
	type orderedPage struct {
		ref  format.Ref
		view format.RequiredSupportPageView
		page format.RequiredSupportPage
	}
	ordered := make([]orderedPage, len(out.references))
	for i := range ordered {
		ordered[i] = orderedPage{out.references[i], out.views[i], out.pages[i]}
	}
	slices.SortFunc(ordered, func(a, b orderedPage) int { return int(a.ref.Index) - int(b.ref.Index) })
	for i, page := range ordered {
		out.references[i], out.views[i], out.pages[i] = page.ref, page.view, page.page
	}
	if parent != nil && parentPages != 1 {
		return generatedRequiredSupportMaterialization{}, fmt.Errorf("materialize support parent page count: %w", contract.ErrRecord)
	}
	slices.SortFunc(out.fragments, func(a, b format.FragmentLocation) int {
		if n := bytes.Compare(a.BlobID[:], b.BlobID[:]); n != 0 {
			return n
		}
		return int(a.FragmentIndex) - int(b.FragmentIndex)
	})
	return out, nil
}

func (s *StateSession) generatedSupportPhysicalIndexes(packed [][]contract.SupportRecord) ([]uint16, error) {
	if s == nil || len(packed) > contract.MaxChildPages {
		return nil, contract.ErrRecord
	}
	indexes := make([]uint16, len(packed))
	used := make(map[uint16]bool)
	retained := make([]bool, len(packed))
	for i, rows := range packed {
		if page, ok := s.retainedOutputPage(rows); ok {
			if used[page.ref.Index] {
				return nil, contract.ErrRecord
			}
			indexes[i], retained[i], used[page.ref.Index] = page.ref.Index, true, true
		}
	}
	var next uint16
	for i := range packed {
		if retained[i] {
			continue
		}
		for used[next] {
			next++
		}
		if next >= contract.MaxChildPages {
			return nil, contract.ErrRecordCapacity
		}
		indexes[i], used[next] = next, true
	}
	return indexes, nil
}

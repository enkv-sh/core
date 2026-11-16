package core

import (
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type generatedRequiredSupportMaterialization struct {
	objects       []objectImage
	references    []format.Ref
	views         []format.RequiredSupportPageView
	pages         []format.RequiredSupportPage
	recordCount   uint32
	identityPages []contract.IdentityPage
	fragments     []format.FragmentLocation
}

func materializeGeneratedRequiredSupport(domain contract.ID, packed [][]contract.SupportRecord,
	pageIDs []contract.ID) (generatedRequiredSupportMaterialization, error) {
	if domain.IsZero() || len(packed) != len(pageIDs) || len(packed) > contract.MaxChildPages {
		return generatedRequiredSupportMaterialization{}, contract.ErrRecord
	}
	if len(packed) == 0 {
		return generatedRequiredSupportMaterialization{}, nil
	}
	seen := make(map[contract.ID]struct{}, len(pageIDs))
	var recordCount uint64
	for i, id := range pageIDs {
		if id.IsZero() {
			return generatedRequiredSupportMaterialization{}, contract.ErrRecord
		}
		if _, ok := seen[id]; ok {
			return generatedRequiredSupportMaterialization{}, contract.ErrRecord
		}
		seen[id] = struct{}{}
		recordCount += uint64(len(packed[i]))
		if recordCount > uint64(^uint32(0)) {
			return generatedRequiredSupportMaterialization{}, contract.ErrRecordCapacity
		}
	}

	out := generatedRequiredSupportMaterialization{
		objects:       make([]objectImage, 0, len(packed)),
		references:    make([]format.Ref, 0, len(packed)),
		views:         make([]format.RequiredSupportPageView, 0, len(packed)),
		recordCount:   uint32(recordCount),
		identityPages: make([]contract.IdentityPage, 0, len(packed)),
	}
	pages := make([]format.RequiredSupportPage, len(packed))
	for i, records := range packed {
		page := format.RequiredSupportPage{Domain: domain, Object: pageIDs[i], Index: uint16(i), Records: records}
		body, err := format.EncodeRequiredSupportPage(page)
		if err != nil {
			return generatedRequiredSupportMaterialization{}, err
		}
		ref, err := format.Reference(contract.RequiredSupportKind, domain, page.Object, page.Index, body)
		if err != nil {
			return generatedRequiredSupportMaterialization{}, err
		}
		view, err := format.InspectRequiredSupportPage(body)
		if err != nil {
			return generatedRequiredSupportMaterialization{}, err
		}
		pages[i] = page
		out.objects = append(out.objects, objectImage{ref: ref, body: body})
		out.references = append(out.references, ref)
		out.views = append(out.views, view)
		out.identityPages = append(out.identityPages, contract.IdentityPage{Kind: contract.RequiredSupportKind, Index: uint16(i), Object: page.Object})
	}
	var err error
	out.fragments, err = generatedFragmentDirectory(pages)
	if err != nil {
		return generatedRequiredSupportMaterialization{}, err
	}
	return out, nil
}

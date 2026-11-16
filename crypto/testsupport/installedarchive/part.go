package installedarchive

import (
	"bytes"
	"fmt"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// Part records independently selected public or encrypted archive bytes.
type Part struct {
	Kind            string
	Ref             format.Ref
	PhysicalOrdinal uint16
	SupportKind     contract.SupportRecordKind
	RecordID        contract.ID
	Body            []byte
}

// SelectedParts derives the expected projection from the archive's fixed
// signed HEAD, its selected Root and that Root's administrative spans. Other
// objects in the archive are not part of this selection.
func (a Archive) SelectedParts() ([]Part, error) {
	headObject, ok := a.Object(a.Location.PrefixBeforeHEAD + "/HEAD")
	if !ok || contract.Hash(headObject.Body) != a.HeadDigest {
		return nil, fmt.Errorf("selected HEAD unavailable")
	}
	head, err := format.DecodeHead(headObject.Body)
	if err != nil || head.Core.Domain != a.Domain {
		return nil, fmt.Errorf("selected HEAD invalid")
	}
	rootObject, err := a.selectedObject(head.Core.Root)
	if err != nil {
		return nil, err
	}
	root, err := format.DecodeRoot(rootObject.Body)
	if err != nil || root.Domain != a.Domain || root.Snapshot != head.Core.Root.Object {
		return nil, fmt.Errorf("selected Root invalid")
	}
	configKey, err := contract.StoreConfigurationKeyForID(a.Family, a.Location.PrefixBeforeHEAD, a.Domain, head.Core.Store)
	if err != nil {
		return nil, err
	}
	configuration, ok := a.Object(configKey)
	if !ok {
		return nil, fmt.Errorf("selected configuration unavailable")
	}
	decoded, err := contract.DecodeStoreConfiguration(configuration.Body)
	if err != nil {
		return nil, err
	}
	configID, err := contract.StoreConfigurationID(decoded)
	if err != nil || configID != head.Core.Store {
		return nil, fmt.Errorf("selected configuration identity invalid")
	}
	parts := []Part{
		{Kind: "configuration", Body: bytes.Clone(configuration.Body)},
		{Kind: "HEAD", Body: bytes.Clone(headObject.Body)},
		{Kind: "root", Ref: head.Core.Root, Body: bytes.Clone(rootObject.Body)},
	}
	addRef := func(kind string, ref format.Ref) error {
		item, err := a.selectedObject(ref)
		if err != nil {
			return err
		}
		parts = append(parts, Part{Kind: kind, Ref: ref, Body: bytes.Clone(item.Body)})
		return nil
	}
	for _, ref := range root.ValueEntryPages {
		if ref != nil {
			if err := addRef("value page", *ref); err != nil {
				return nil, err
			}
		}
	}
	for _, ref := range root.Recipients {
		if ref != nil {
			if err := addRef("recipient page", *ref); err != nil {
				return nil, err
			}
		}
	}
	for _, ref := range root.CurrentAccess.Core.AccessPageRefs {
		if err := addRef("access page", ref); err != nil {
			return nil, err
		}
	}
	indexRefs := append([]format.Ref{root.AdministrativeIndex}, root.AdministrativeIndexShards...)
	indexPages := make([]format.AdministrativeIndexPage, 0, len(indexRefs))
	for _, ref := range indexRefs {
		item, err := a.selectedObject(ref)
		if err != nil {
			return nil, err
		}
		parts = append(parts, Part{Kind: "index page", Ref: ref, Body: bytes.Clone(item.Body)})
		indexPages = append(indexPages, format.AdministrativeIndexPage{Ref: ref, Body: item.Body})
	}
	index, err := format.DecodeAdministrativeIndexPages(indexPages)
	if err != nil || index.Domain != a.Domain || len(index.Pages) != len(root.RequiredSupport) {
		return nil, fmt.Errorf("selected administrative index invalid")
	}
	var selectedRows uint32
	for i, ref := range root.RequiredSupport {
		if index.Pages[i].Ref != ref {
			return nil, fmt.Errorf("selected support reference differs")
		}
		item, err := a.selectedObject(ref)
		if err != nil {
			return nil, err
		}
		page, err := format.InspectRequiredSupportPage(item.Body)
		if err != nil || page.Domain != a.Domain || page.Object != ref.Object || page.Index != ref.Index {
			return nil, fmt.Errorf("selected support page invalid")
		}
		for _, span := range index.Pages[i].Spans {
			end := uint32(span.First) + uint32(span.Count)
			if end > uint32(len(page.Records)) {
				return nil, fmt.Errorf("selected support span invalid")
			}
			for physical := uint32(span.First); physical < end; physical++ {
				row := page.Records[physical]
				parts = append(parts, Part{Kind: "support row", Ref: ref,
					PhysicalOrdinal: uint16(physical), SupportKind: row.Kind, RecordID: row.RecordID, Body: bytes.Clone(row.Body)})
				selectedRows++
			}
		}
	}
	if selectedRows != root.RequiredSupportRecordCount {
		return nil, fmt.Errorf("selected support count differs")
	}
	return parts, nil
}

func (a Archive) selectedObject(ref format.Ref) (Object, error) {
	key, err := format.Key(a.Location.PrefixBeforeHEAD, ref)
	if err != nil {
		return Object{}, err
	}
	item, ok := a.Object(key)
	if !ok || format.CheckReference(ref, item.Body) != nil {
		return Object{}, fmt.Errorf("selected object unavailable or invalid: %s", key)
	}
	return item, nil
}

package core

import (
	"slices"
	"sort"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// selectedCompleteRelations checks the complete selected support and value
// image after the caller has authenticated every referenced page and its
// configuration stream. It does not issue an ordinary admission or authority.
func selectedCompleteRelations(head format.Head, image *selectedImage, authorityID contract.ID, materials selectedMaterialFacts) ([]contract.AccessRecord, bool) {
	if image == nil || !image.selectedOutputComplete() {
		return nil, false
	}
	support, err := image.supportDescriptor()
	if err != nil || support.Count != image.root.RequiredSupportRecordCount ||
		(len(image.support) == 0) != (len(image.root.RequiredSupport) == 0) {
		return nil, false
	}
	return selectedValueRelations(head, image, authorityID, materials)
}

// selectedValueRelations checks the selected registry, values and access rows
// against one authenticated image. authorityID comes from the qualified
// current signer; this function grants no ordinary enrollment or operation.
func selectedValueRelations(head format.Head, image *selectedImage, authorityID contract.ID, materials selectedMaterialFacts) ([]contract.AccessRecord, bool) {
	if image == nil || authorityID.IsZero() || authorityID != image.root.CurrentAccess.Core.AuthorityRecipientID ||
		len(image.support) != len(image.root.RequiredSupport) {
		return nil, false
	}
	if _, ok := selectedControlFrom(image.root, &image.recipients, authorityID); !ok {
		return nil, false
	}
	ids := make(map[contract.ID]bool)
	add := func(id contract.ID) bool {
		if id.IsZero() || ids[id] {
			return false
		}
		ids[id] = true
		return true
	}
	for _, id := range []contract.ID{image.root.Snapshot, image.root.Transition, head.Core.Revision} {
		if !add(id) {
			return nil, false
		}
	}
	for i, page := range image.support {
		if page.Domain != image.root.Domain || page.Object != image.root.RequiredSupport[i].Object ||
			page.Index != image.root.RequiredSupport[i].Index || !add(page.Object) {
			return nil, false
		}
		for _, record := range page.Records {
			if record.Kind == contract.MutationReceiptSupportKind && !add(record.RecordID) {
				return nil, false
			}
		}
	}
	if !selectedRegistryIdentities(image.root, &image.recipients, add) {
		return nil, false
	}

	var names []format.NameEntry
	var raw uint64
	var memberships, secrets, wraps uint32
	for i, page := range image.pages {
		if page == nil {
			continue
		}
		if !add(page.Object) {
			return nil, false
		}
		for j, value := range page.Slots {
			if value == nil {
				continue
			}
			if !add(value.Incarnation) || !add(value.ValueState) || value.OriginSnapshot.IsZero() ||
				value.OriginTransition.IsZero() || value.ValueSource != contract.Supplied && value.ValueSource != contract.Generated ||
				(value.OriginSnapshot == image.root.Snapshot) != (value.OriginTransition == image.root.Transition) ||
				!slices.Contains(value.Recipients, authorityID) {
				return nil, false
			}
			for _, id := range value.Recipients {
				if selectedRecipientRecord(&image.recipients, id) == nil {
					return nil, false
				}
			}
			memberships += uint32(len(value.Recipients))
			if value.ConfidentialityClass == format.Secret {
				core, payload, _, ok := selectedValueFrom(image.root.Domain, image.root, &image.pages,
					&image.recipients, &image.access, materials.accessLocations, materials.valueReaders,
					uint16(i*format.PageSlots+j))
				if !ok || !add(core.DataKeyID) || !add(core.CommitmentKeyID) {
					return nil, false
				}
				raw += uint64(payload.ContentLength)
				secrets++
				wraps += uint32(len(value.Recipients))
			} else {
				raw += uint64(value.ContentLength)
			}
			names = append(names, format.NameEntry{Name: value.Name, Slot: uint16(i*format.PageSlots + j)})
		}
	}
	records := make([]contract.AccessRecord, 0, image.root.AccessRecordCount)
	for _, page := range image.access {
		if page == nil {
			continue
		}
		if !add(page.Object) {
			return nil, false
		}
		records = append(records, page.Records...)
	}
	slices.SortFunc(records, func(a, b contract.AccessRecord) int {
		return compareMaterial(a.MaterialKind, a.MaterialID, b.MaterialKind, b.MaterialID)
	})
	descriptor, err := contract.AccessRecordsDescriptor(image.root.Domain, records)
	if err != nil || descriptor != image.root.CurrentAccess.Core.AccessRecordsDescriptor ||
		len(records) != int(image.root.AccessRecordCount) {
		return nil, false
	}
	sort.Slice(names, func(i, j int) bool { return names[i].Name < names[j].Name })
	if uint32(len(names)) != image.root.ValueEntryCount || raw != image.root.RawBytes ||
		memberships != image.root.MembershipCount || secrets != image.root.SecretCount ||
		wraps != image.root.SecretOrdinaryWrapCount || !slices.Equal(names, image.root.Names) {
		return nil, false
	}
	for i := 1; i < len(names); i++ {
		if names[i].Name == names[i-1].Name {
			return nil, false
		}
	}
	return records, true
}

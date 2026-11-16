package core

import (
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// These facts come from the selected recipient pages. The caller supplies the
// independently verified authority ID; this reader does not issue admission.
func selectedRecipientRecord(pages *[contract.MaxRecipientPages]*format.RecipientPage, id contract.ID) *contract.RecipientRecord {
	if pages == nil {
		return nil
	}
	for _, page := range pages {
		if page == nil {
			continue
		}
		for _, row := range page.Slots {
			if row != nil && row.RecipientID == id {
				return row
			}
		}
	}
	return nil
}

func selectedRecipientRegistry(pages *[contract.MaxRecipientPages]*format.RecipientPage, count uint16) []contract.RecipientRecord {
	rows := make([]contract.RecipientRecord, 0, count)
	if pages == nil {
		return rows
	}
	for _, page := range pages {
		if page == nil {
			continue
		}
		for _, row := range page.Slots {
			if row != nil {
				rows = append(rows, *row)
			}
		}
	}
	return rows
}

func selectedControlFrom(root format.Root, pages *[contract.MaxRecipientPages]*format.RecipientPage, authorityID contract.ID) (contract.ControlCore, bool) {
	if authorityID.IsZero() || authorityID != root.CurrentAccess.Core.AuthorityRecipientID {
		return contract.ControlCore{}, false
	}
	authority := selectedRecipientRecord(pages, authorityID)
	if authority == nil || authority.CurrentBinding == nil {
		return contract.ControlCore{}, false
	}
	control := contract.ControlCore{CurrentControl: root.CurrentAccess.Core.CurrentControl, AuthorityKMSBinding: *authority.CurrentBinding}
	_, err := contract.ControlCoreLength(control)
	return control, err == nil
}

func selectedRegistryIdentities(root format.Root, pages *[contract.MaxRecipientPages]*format.RecipientPage, add func(contract.ID) bool) bool {
	count := 0
	for _, page := range pages {
		if page == nil {
			continue
		}
		if !add(page.Object) {
			return false
		}
		for _, row := range page.Slots {
			if row == nil {
				continue
			}
			count++
			if row.CurrentBinding == nil || row.CurrentBinding.Provider != root.CurrentAccess.Core.Provider || !add(row.RecipientID) || !add(row.CurrentBinding.BindingID) {
				return false
			}
		}
	}
	return count == int(root.RecipientCount)
}

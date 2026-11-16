package format

import (
	"bytes"

	"enkv.sh/core/contract"
)

// ApplyRecipientPages packs one complete changed registry. Returned pages own
// their row structs; nested public binding data borrows rows unchanged.
func ApplyRecipientPages(domain contract.ID, rows []contract.RecipientRecord, plan contract.IdentityPlan) ([]RecipientPage, []contract.Ref, error) {
	if domain.IsZero() || len(rows) == 0 || len(rows) > contract.CryptoMaxRecipients {
		return nil, nil, ErrFormat
	}
	if _, err := contract.IdentityPlanDescriptor(plan); err != nil {
		return nil, nil, ErrFormat
	}
	records := 0
	for i, row := range rows {
		length, err := contract.RecipientRecordLength(row)
		if err != nil || row.Status != contract.CurrentRecipient || i > 0 && bytes.Compare(rows[i-1].RecipientID[:], row.RecipientID[:]) >= 0 {
			return nil, nil, ErrFormat
		}
		records += length
		if records > contract.MaxPublicRegistryBytes {
			return nil, nil, ErrFormat
		}
	}
	count := (len(rows) + RecipientSlots - 1) / RecipientSlots
	var identities [contract.MaxRecipientPages]contract.IdentityPage
	found := 0
	for _, page := range plan.Pages {
		if page.Kind != contract.RecipientKind {
			continue
		}
		if found >= count || page.Index != uint16(found) {
			return nil, nil, ErrFormat
		}
		for _, prior := range identities[:found] {
			if prior.Object == page.Object {
				return nil, nil, ErrFormat
			}
		}
		identities[found] = page
		found++
	}
	if found != count {
		return nil, nil, ErrFormat
	}
	pages := make([]RecipientPage, count)
	refs := make([]contract.Ref, count)
	for i := range pages {
		pages[i] = RecipientPage{Domain: domain, Object: identities[i].Object, Index: uint16(i)}
		for slot := 0; slot < RecipientSlots && i*RecipientSlots+slot < len(rows); slot++ {
			row := rows[i*RecipientSlots+slot]
			pages[i].Slots[slot] = &row
		}
		body, err := EncodeRecipientPage(pages[i])
		if err != nil {
			return nil, nil, err
		}
		refs[i], err = Reference(RecipientKind, domain, pages[i].Object, pages[i].Index, body)
		if err != nil {
			return nil, nil, err
		}
	}
	return pages, refs, nil
}

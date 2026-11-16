package core

import (
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type admittedConsumerSelection struct {
	recipient contract.ID
	slots     []uint16
}

// The private parent fixes the complete selection before admitting any sink or
// private consumer. The authenticated session supplies membership and bindings.
func (s *StateSession) admitConsumerSelection(ctx context.Context, names []string, acting contract.ID) (*admittedConsumerSelection, Result) {
	if s == nil || ctx == nil || ctx.Err() != nil || !s.admission.valid(s.store) {
		return nil, refused(AdmissionInvalid)
	}
	if len(names) > contract.CryptoMaxValueEntries {
		return nil, refused(CapacityExceeded)
	}
	if acting.IsZero() {
		acting = s.root.CurrentAccess.Core.AuthorityRecipientID
	}
	image := selectedImage{root: s.root, pages: s.pages, recipients: s.recipients}
	slots, result, _ := consumerMembershipSlots(&image, names, acting)
	if result.Outcome != 0 {
		return nil, result
	}
	return &admittedConsumerSelection{recipient: acting, slots: slots}, s.observed(ObservedCurrent)
}

// This pure check reads immutable selected facts. Private admission and the
// implicit Authority choice remain in the consumer's enclosing parent.
func consumerMembershipSlots(image *selectedImage, names []string, acting contract.ID) ([]uint16, Result, contract.DiagnosticReason) {
	if image == nil {
		return nil, refused(AdmissionInvalid), contract.ReasonSelectedRelationInvalid
	}
	if len(names) > contract.CryptoMaxValueEntries {
		return nil, refused(CapacityExceeded), contract.ReasonLimitExceeded
	}
	r := image.recipientRecord(acting)
	if r == nil || r.Status != format.Current || r.CurrentBinding == nil {
		return nil, refused(AdmissionInvalid), contract.ReasonTargetAbsent
	}
	if _, err := contract.RecipientRecordLength(*r); err != nil {
		return nil, refused(AdmissionInvalid), contract.ReasonSelectedRelationInvalid
	}
	var slots [contract.CryptoMaxValueEntries]uint16
	var seen [contract.CryptoMaxValueEntries]bool
	for i, name := range names {
		index := slices.IndexFunc(image.root.Names, func(row format.NameEntry) bool { return row.Name == name })
		if index < 0 {
			return nil, refused(InvalidIntent), contract.ReasonEntryAbsent
		}
		slot := image.root.Names[index].Slot
		if slot >= contract.CryptoMaxValueEntries {
			return nil, refused(InvalidIntent), contract.ReasonSelectedRelationInvalid
		}
		if seen[slot] {
			return nil, refused(InvalidIntent), contract.ReasonDuplicateEntry
		}
		m := image.valueEntry(slot)
		if m == nil || !slices.Contains(m.Recipients, acting) {
			return nil, refused(AdmissionInvalid), contract.ReasonTargetNotAuthorized
		}
		for _, id := range m.Recipients {
			row := image.recipientRecord(id)
			if row == nil || row.Status != format.Current || row.CurrentBinding == nil {
				return nil, refused(AdmissionInvalid), contract.ReasonSelectedRelationInvalid
			}
			if _, err := contract.RecipientRecordLength(*row); err != nil {
				return nil, refused(AdmissionInvalid), contract.ReasonSelectedRelationInvalid
			}
		}
		slots[i], seen[slot] = slot, true
	}
	return slices.Clone(slots[:len(names)]), Result{}, ""
}

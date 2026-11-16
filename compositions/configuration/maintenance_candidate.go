package configuration

import (
	"slices"
	"unicode/utf8"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func (m *MaintenanceMetadata) materialCapacity() bool {
	if len(m.SignedCandidate) > contract.MaxHeadLength || len(m.PredecessorHead) > contract.MaxHeadLength || len(m.CandidateRoot) > contract.MaxRootLength || len(m.PredecessorRoot) > contract.MaxRootLength || len(m.CandidatePages) > contract.MaxValueEntryPages || len(m.PredecessorPages) > contract.MaxValueEntryPages || len(m.PinDeltas) > contract.CryptoMaxValueEntries || len(m.OutputPath) > 4096 || len(m.Request.Name) > contract.CryptoMaxName || len(m.Request.RecipientReference) > 256 {
		return false
	}
	const limit = uint64(MaxPairBytes)
	var total uint64
	add := func(n uint64) bool {
		if n > limit-total {
			return false
		}
		total += n
		return true
	}
	base64 := func(n int) bool { return add(4 * ((uint64(n) + 2) / 3)) }
	if !add(m.Source.Editable.Length) || !add(m.Source.Generated.Length) || !add(8192+6*(uint64(len(m.OutputPath))+256)) || !base64(len(m.SignedCandidate)) || !base64(len(m.PredecessorHead)) || !base64(len(m.PredecessorRoot)) || !base64(len(m.CandidateRoot)) {
		return false
	}
	for _, delta := range m.PinDeltas {
		if len(delta.Name) > contract.CryptoMaxName || !utf8.ValidString(delta.Name) || !add(512+6*uint64(len(delta.Name))) {
			return false
		}
	}
	if m.RekeyTarget != nil && !add(12*uint64(len(m.Request.Name))) {
		return false
	}
	for _, rows := range [][]MaintenanceValuePage{m.PredecessorPages, m.CandidatePages} {
		for _, row := range rows {
			if len(row.Body) > contract.MaxValueEntryPageLength || !base64(len(row.Body)) || !add(128) {
				return false
			}
		}
	}
	return true
}

func (m *MaintenanceMetadata) materialRecords(head format.Head, rootBody []byte, pages []MaintenanceValuePage) (format.Root, [contract.CryptoMaxValueEntries]*contract.ValueEntry, error) {
	var slots [contract.CryptoMaxValueEntries]*contract.ValueEntry
	if len(rootBody) == 0 || len(rootBody) > contract.MaxRootLength || len(pages) == 0 || len(pages) > contract.MaxValueEntryPages || format.CheckReference(head.Core.Root, rootBody) != nil {
		return format.Root{}, slots, ErrEdit
	}
	root, err := format.DecodeRoot(rootBody)
	if err != nil || root.Domain != head.Core.Domain || root.Snapshot != head.Core.Root.Object {
		return format.Root{}, slots, ErrEdit
	}
	var names [contract.CryptoMaxValueEntries]string
	var occupied [contract.CryptoMaxValueEntries]bool
	for _, row := range root.Names {
		names[row.Slot] = row.Name
		occupied[row.Slot] = true
	}
	var required [contract.MaxValueEntryPages]bool
	for _, delta := range m.PinDeltas {
		slot, found := maintenanceCandidateSlot(root, delta.Name)
		if !found {
			return format.Root{}, slots, ErrEdit
		}
		required[slot/format.PageSlots] = true
	}
	if target := m.RekeyTarget; target != nil {
		if target.Slot >= contract.CryptoMaxValueEntries || !occupied[target.Slot] || names[target.Slot] != target.Name {
			return format.Root{}, slots, ErrEdit
		}
		required[target.Slot/format.PageSlots] = true
	}
	var seen [contract.MaxValueEntryPages]bool
	for i, page := range pages {
		if page.Index >= contract.MaxValueEntryPages || len(page.Body) == 0 || len(page.Body) > contract.MaxValueEntryPageLength || i > 0 && pages[i-1].Index >= page.Index || !required[page.Index] {
			return format.Root{}, slots, ErrEdit
		}
		ref := root.ValueEntryPages[page.Index]
		if ref == nil || format.CheckReference(*ref, page.Body) != nil {
			return format.Root{}, slots, ErrEdit
		}
		decoded, err := format.DecodeValueEntryPage(page.Body)
		if err != nil || decoded.Domain != root.Domain || decoded.Index != page.Index || decoded.Object != ref.Object {
			return format.Root{}, slots, ErrEdit
		}
		for i, entry := range decoded.Slots {
			slot := int(page.Index)*format.PageSlots + i
			if entry == nil && occupied[slot] || entry != nil && (!occupied[slot] || entry.Name != names[slot]) {
				return format.Root{}, slots, ErrEdit
			}
			slots[slot] = entry
		}
		seen[page.Index] = true
	}
	if seen != required {
		return format.Root{}, slots, ErrEdit
	}
	return root, slots, nil
}

func (m *MaintenanceMetadata) checkCandidateMaterial(head format.Head) error {
	needed := len(m.PinDeltas) > 0 || m.Request.OperationKind == contract.OperationEnvelopeRekey
	if !needed {
		if len(m.PredecessorHead) != 0 || len(m.PredecessorRoot) != 0 || len(m.PredecessorPages) != 0 || len(m.CandidateRoot) != 0 || len(m.CandidatePages) != 0 || !m.BeforeGeneration.IsZero() || !m.AfterGeneration.IsZero() {
			return ErrEdit
		}
		return nil
	}
	if len(m.PredecessorHead) == 0 || len(m.PredecessorHead) > contract.MaxHeadLength || contract.Hash(m.PredecessorHead) != head.Core.PreviousDigest {
		return ErrEdit
	}
	beforeHead, err := format.DecodeHead(m.PredecessorHead)
	if err != nil || beforeHead.Core.Revision != head.Core.PreviousRevision || beforeHead.Core.Domain != head.Core.Domain || beforeHead.Core.Store != head.Core.Store || beforeHead.Core.Coordinate != head.Core.Coordinate || beforeHead.Core.NonBody != head.Core.NonBody || beforeHead.Core.Trust != head.Core.Trust || beforeHead.Core.Interpretation != head.Core.Interpretation || beforeHead.Core.Epoch != head.Core.Epoch {
		return ErrEdit
	}
	beforeRoot, before, err := m.materialRecords(beforeHead, m.PredecessorRoot, m.PredecessorPages)
	if err != nil || beforeRoot.CurrentAccess.AccessRoot != head.Subject.BeforeAccessRoot {
		return ErrEdit
	}
	root, after, err := m.materialRecords(head, m.CandidateRoot, m.CandidatePages)
	if err != nil || root.CurrentAccess.AccessRoot != head.Subject.AfterAccessRoot {
		return ErrEdit
	}
	for _, delta := range m.PinDeltas {
		beforeSlot, beforeFound := maintenanceCandidateSlot(beforeRoot, delta.Name)
		afterSlot, afterFound := maintenanceCandidateSlot(root, delta.Name)
		if !beforeFound || !afterFound || beforeSlot != afterSlot {
			return ErrEdit
		}
		a, b := before[beforeSlot], after[afterSlot]
		if a == nil || b == nil || a.Name != delta.Name || b.Name != delta.Name || a.ValueSource != contract.Supplied || b.ValueSource != contract.Supplied || a.ConfidentialityClass != contract.Secret || b.ConfidentialityClass != contract.Secret || a.Incarnation != delta.Before.Incarnation || a.ValueState != delta.Before.Material || b.Incarnation != delta.After.Incarnation || b.ValueState != delta.After.Material || m.Retirement != nil && slices.Contains(b.Recipients, m.Request.RecipientID) {
			return ErrEdit
		}
	}
	if target := m.RekeyTarget; target != nil {
		a, b := before[target.Slot], after[target.Slot]
		if a == nil || b == nil || a.Name != target.Name || b.Name != target.Name || a.ConfidentialityClass != contract.Secret || b.ConfidentialityClass != contract.Secret || a.Incarnation != target.Incarnation || b.Incarnation != target.Incarnation || a.ValueState != target.Material || b.ValueState == target.Material || a.ValueSource != b.ValueSource {
			return ErrEdit
		}
		digest, err := contract.PublicValueEntryDigest(head.Core.Domain, target.Slot, *a)
		if err != nil || digest != target.BeforePublicEntryDigest {
			return ErrEdit
		}
		if b.ValueSource == contract.Generated {
			if len(m.PinDeltas) != 0 || m.BeforeGeneration.IsZero() || m.BeforeGeneration != a.Generated.GenerationID || m.BeforeGeneration != target.Material || m.AfterGeneration.IsZero() || m.AfterGeneration != b.Generated.GenerationID || m.BeforeGeneration == m.AfterGeneration {
				return ErrEdit
			}
		} else if b.ValueSource != contract.Supplied || !m.BeforeGeneration.IsZero() || !m.AfterGeneration.IsZero() || len(m.PinDeltas) != 1 || m.PinDeltas[0].Name != target.Name || m.PinDeltas[0].Before != (contract.RetainedSecretInput{Incarnation: target.Incarnation, Material: target.Material}) {
			return ErrEdit
		}
	} else if !m.BeforeGeneration.IsZero() || !m.AfterGeneration.IsZero() {
		return ErrEdit
	}
	return nil
}

func maintenanceCandidateSlot(root format.Root, name string) (uint16, bool) {
	for _, row := range root.Names {
		if row.Name == name {
			return row.Slot, true
		}
	}
	return 0, false
}

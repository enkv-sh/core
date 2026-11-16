package core

import (
	"bytes"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func maintenanceMaterialRecords(c MaintenanceSuccessor, head format.Head, rootBody []byte, rows []MaintenanceValuePage) (format.Root, [contract.MaxValueEntryPages]*format.ValueEntryPage, bool) {
	var pages [contract.MaxValueEntryPages]*format.ValueEntryPage
	if len(rootBody) == 0 || len(rootBody) > contract.MaxRootLength || len(rows) == 0 || len(rows) > contract.MaxValueEntryPages || format.CheckReference(head.Core.Root, rootBody) != nil {
		return format.Root{}, pages, false
	}
	root, err := format.DecodeRoot(rootBody)
	if err != nil || root.Domain != head.Core.Domain || root.Snapshot != head.Core.Root.Object {
		return format.Root{}, pages, false
	}
	var required [contract.MaxValueEntryPages]bool
	for _, delta := range c.PinDeltas {
		index := slices.IndexFunc(root.Names, func(row format.NameEntry) bool { return row.Name == delta.Name })
		if index < 0 {
			return format.Root{}, pages, false
		}
		required[root.Names[index].Slot/format.PageSlots] = true
	}
	if target := c.RekeyTarget; target != nil {
		if target.Slot >= contract.CryptoMaxValueEntries || !slices.Contains(root.Names, format.NameEntry{Name: target.Name, Slot: target.Slot}) {
			return format.Root{}, pages, false
		}
		required[target.Slot/format.PageSlots] = true
	}
	for i, row := range rows {
		if row.Index >= contract.MaxValueEntryPages || i > 0 && rows[i-1].Index >= row.Index || !required[row.Index] || len(row.Body) == 0 || len(row.Body) > contract.MaxValueEntryPageLength {
			return format.Root{}, pages, false
		}
		ref := root.ValueEntryPages[row.Index]
		if ref == nil || format.CheckReference(*ref, row.Body) != nil {
			return format.Root{}, pages, false
		}
		page, err := format.DecodeValueEntryPage(row.Body)
		if err != nil || page.Domain != root.Domain || page.Object != ref.Object || page.Index != row.Index {
			return format.Root{}, pages, false
		}
		for at, entry := range page.Slots {
			slot := row.Index*format.PageSlots + uint16(at)
			index := slices.IndexFunc(root.Names, func(named format.NameEntry) bool { return named.Slot == slot })
			if entry == nil && index >= 0 || entry != nil && (index < 0 || entry.Name != root.Names[index].Name) {
				return format.Root{}, pages, false
			}
		}
		pages[row.Index] = &page
	}
	for index, needed := range required {
		if needed != (pages[index] != nil) {
			return format.Root{}, pages, false
		}
	}
	return root, pages, true
}

func maintenanceMaterial(c MaintenanceSuccessor, head format.Head) (format.Root, [contract.MaxValueEntryPages]*format.ValueEntryPage, bool) {
	var empty [contract.MaxValueEntryPages]*format.ValueEntryPage
	needed := len(c.PinDeltas) != 0 || c.RekeyTarget != nil
	if !needed {
		return format.Root{}, empty, len(c.PredecessorHead) == 0 && len(c.PredecessorRoot) == 0 && len(c.PredecessorPages) == 0 && len(c.CandidateRoot) == 0 && len(c.CandidatePages) == 0 && c.BeforeGeneration.IsZero() && c.AfterGeneration.IsZero()
	}
	if len(c.PredecessorHead) == 0 || len(c.PredecessorHead) > contract.MaxHeadLength || contract.Hash(c.PredecessorHead) != head.Core.PreviousDigest {
		return format.Root{}, empty, false
	}
	beforeHead, err := format.DecodeHead(c.PredecessorHead)
	if err != nil || beforeHead.Core.Revision != head.Core.PreviousRevision || beforeHead.Core.Domain != head.Core.Domain || beforeHead.Core.Store != head.Core.Store || beforeHead.Core.Coordinate != head.Core.Coordinate || beforeHead.Core.NonBody != head.Core.NonBody || beforeHead.Core.Trust != head.Core.Trust || beforeHead.Core.Interpretation != head.Core.Interpretation || beforeHead.Core.Epoch != head.Core.Epoch {
		return format.Root{}, empty, false
	}
	beforeRoot, beforePages, valid := maintenanceMaterialRecords(c, beforeHead, c.PredecessorRoot, c.PredecessorPages)
	if !valid || beforeRoot.CurrentAccess.AccessRoot != head.Subject.BeforeAccessRoot {
		return format.Root{}, empty, false
	}
	root, pages, valid := maintenanceMaterialRecords(c, head, c.CandidateRoot, c.CandidatePages)
	if !valid || root.CurrentAccess.AccessRoot != head.Subject.AfterAccessRoot {
		return format.Root{}, empty, false
	}
	for _, delta := range c.PinDeltas {
		beforeIndex := slices.IndexFunc(beforeRoot.Names, func(row format.NameEntry) bool { return row.Name == delta.Name })
		afterIndex := slices.IndexFunc(root.Names, func(row format.NameEntry) bool { return row.Name == delta.Name })
		beforeSlot, afterSlot := beforeRoot.Names[beforeIndex].Slot, root.Names[afterIndex].Slot
		before := beforePages[beforeSlot/format.PageSlots].Slots[beforeSlot%format.PageSlots]
		after := pages[afterSlot/format.PageSlots].Slots[afterSlot%format.PageSlots]
		if beforeSlot != afterSlot || before == nil || after == nil || before.Name != delta.Name || after.Name != delta.Name || before.ValueSource != contract.Supplied || after.ValueSource != contract.Supplied || before.ConfidentialityClass != contract.Secret || after.ConfidentialityClass != contract.Secret || before.Incarnation != delta.Before.Incarnation || before.ValueState != delta.Before.Material || after.Incarnation != delta.After.Incarnation || after.ValueState != delta.After.Material || c.Retirement != nil && slices.Contains(after.Recipients, c.Recipient.RecipientID) {
			return format.Root{}, empty, false
		}
	}
	if target := c.RekeyTarget; target != nil {
		before := beforePages[target.Slot/format.PageSlots].Slots[target.Slot%format.PageSlots]
		after := pages[target.Slot/format.PageSlots].Slots[target.Slot%format.PageSlots]
		if before == nil || after == nil || before.Name != target.Name || after.Name != target.Name || before.Incarnation != target.Incarnation || after.Incarnation != target.Incarnation || before.ConfidentialityClass != contract.Secret || after.ConfidentialityClass != contract.Secret || before.ValueState != target.Material || after.ValueState == target.Material || before.ValueSource != after.ValueSource {
			return format.Root{}, empty, false
		}
		digest, err := contract.PublicValueEntryDigest(head.Core.Domain, target.Slot, *before)
		if err != nil || digest != target.BeforePublicEntryDigest {
			return format.Root{}, empty, false
		}
		if after.ValueSource == contract.Supplied {
			if !c.BeforeGeneration.IsZero() || !c.AfterGeneration.IsZero() || len(c.PinDeltas) != 1 || c.PinDeltas[0].Name != target.Name || c.PinDeltas[0].Before != (contract.RetainedSecretInput{Incarnation: target.Incarnation, Material: target.Material}) {
				return format.Root{}, empty, false
			}
		} else if after.ValueSource != contract.Generated || len(c.PinDeltas) != 0 || c.BeforeGeneration.IsZero() || c.BeforeGeneration != target.Material || c.BeforeGeneration != before.Generated.GenerationID || c.AfterGeneration.IsZero() || c.BeforeGeneration == c.AfterGeneration || c.AfterGeneration != after.Generated.GenerationID {
			return format.Root{}, empty, false
		}
	} else if !c.BeforeGeneration.IsZero() || !c.AfterGeneration.IsZero() {
		return format.Root{}, empty, false
	}
	return root, pages, true
}

func (s *StateSession) prepareMaintenanceMaterial(c *Comparison, candidate *Candidate, correlation *MaintenanceSuccessor, bounds maintenanceMaterialBounds) bool {
	if len(correlation.PinDeltas) == 0 && correlation.RekeyTarget == nil {
		return true
	}
	if candidate.head.Core.PreviousRevision != s.head.Core.Revision || candidate.head.Core.PreviousDigest != contract.Hash(s.body) || candidate.head.Core.PreviousToken != s.token || len(s.body) > contract.MaxHeadLength {
		return false
	}
	correlation.PredecessorHead = bytes.Clone(s.body)
	beforeRoot, err := format.EncodeRoot(s.root)
	if err != nil || format.CheckReference(s.head.Core.Root, beforeRoot) != nil {
		return false
	}
	correlation.PredecessorRoot = beforeRoot
	for _, object := range candidate.objects {
		if object.ref == candidate.head.Core.Root {
			correlation.CandidateRoot = bytes.Clone(object.body)
			break
		}
	}
	root, err := format.DecodeRoot(correlation.CandidateRoot)
	if err != nil || len(correlation.CandidateRoot) > contract.MaxRootLength {
		return false
	}
	var required [contract.MaxValueEntryPages]bool
	for _, delta := range correlation.PinDeltas {
		index := slices.IndexFunc(root.Names, func(row format.NameEntry) bool { return row.Name == delta.Name })
		if index < 0 {
			return false
		}
		required[root.Names[index].Slot/format.PageSlots] = true
	}
	if target := correlation.RekeyTarget; target != nil {
		required[target.Slot/format.PageSlots] = true
		before := s.valueEntry(target.Slot)
		if before == nil {
			return false
		}
		if before.ValueSource == contract.Generated {
			correlation.BeforeGeneration = before.Generated.GenerationID
		}
	}
	for index, needed := range required {
		if !needed {
			continue
		}
		ref := root.ValueEntryPages[index]
		if ref == nil || bounds.pages[index] == 0 {
			return false
		}
		beforeRef := s.root.ValueEntryPages[index]
		if beforeRef == nil || s.pages[index] == nil {
			return false
		}
		beforeBody, err := format.EncodeValueEntryPage(*s.pages[index])
		if err != nil || format.CheckReference(*beforeRef, beforeBody) != nil || uint64(len(beforeBody)) != uint64(bounds.pages[index]) {
			return false
		}
		correlation.PredecessorPages = append(correlation.PredecessorPages, MaintenanceValuePage{Index: uint16(index), Body: beforeBody})
		var body []byte
		for _, object := range candidate.objects {
			if object.ref == *ref {
				body = object.body
				break
			}
		}
		// Maintenance preserves names, payload ContentLength and fixed-width
		// identities. Retirement may remove memberships; no page may grow.
		if len(body) == 0 || uint64(len(body)) > uint64(bounds.pages[index]) {
			return false
		}
		correlation.CandidatePages = append(correlation.CandidatePages, MaintenanceValuePage{Index: uint16(index), Body: bytes.Clone(body)})
		if target := correlation.RekeyTarget; target != nil && int(target.Slot/format.PageSlots) == index && !correlation.BeforeGeneration.IsZero() {
			page, err := format.DecodeValueEntryPage(body)
			if err != nil || page.Slots[target.Slot%format.PageSlots] == nil {
				return false
			}
			correlation.AfterGeneration = page.Slots[target.Slot%format.PageSlots].Generated.GenerationID
		}
	}
	_, _, valid := maintenanceMaterial(*correlation, candidate.head)
	return valid
}

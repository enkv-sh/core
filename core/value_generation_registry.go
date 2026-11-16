package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// The immutable image owns display metadata and creation evidence. Existing
// recipients take their bindings from the authenticated current selection.
func effectiveGeneratedRecipients(root format.Root, current []contract.RecipientRecord, image contract.GeneratedRecipientRegistryImage, selected ...bool) ([]contract.RecipientRecord, error) {
	if image.DomainID != root.Domain || image.OperationID.IsZero() {
		return nil, contract.ErrRecord
	}
	remaining := make(map[contract.ID]contract.RecipientRecord, len(current))
	for _, row := range current {
		remaining[row.RecipientID] = row
	}
	out := make([]contract.RecipientRecord, len(image.Recipients))
	for i, input := range image.Recipients {
		row := input.Recipient
		if row.Status != contract.CurrentRecipient || row.CurrentBinding == nil || row.CurrentBinding.Provider != root.CurrentAccess.Core.Provider {
			return nil, contract.ErrRecord
		}
		old, present := remaining[row.RecipientID]
		if slices.Contains(image.InitiallyAbsent, row.RecipientID) && (len(selected) != 1 || !selected[0]) {
			if present || input.Creation == nil || input.Creation.Snapshot != image.OriginalPredecessorSnapshotID {
				return nil, contract.ErrRecord
			}
			id, err := contract.RecipientCreationID(root.Domain, input.Creation.Snapshot, input.Creation.Nonce)
			if err != nil || id != row.RecipientID {
				return nil, contract.ErrRecord
			}
			binding, incarnation, err := contract.RecipientInitialBindingIDs(root.Domain, id)
			if err != nil || row.CurrentBinding.BindingID != binding || row.CurrentBinding.BindingIncarnationID != incarnation || row.CurrentBinding.BindingSerial != 1 {
				return nil, contract.ErrRecord
			}
		} else {
			if !present || old.Status != contract.CurrentRecipient || old.CurrentBinding == nil {
				return nil, contract.ErrRecord
			}
			row.CurrentBinding = old.CurrentBinding
			delete(remaining, row.RecipientID)
		}
		out[i] = row
	}
	if len(remaining) != 0 {
		return nil, contract.ErrRecord
	}
	return out, nil
}

func (s *StateSession) admitGeneratedRegistry(ctx context.Context, body []byte, q contract.GeneratorRequestCore, initial bool) (*contract.GeneratedRecipientRegistryImage, error) {
	if q.Schema == contract.GeneratorRequestCoreSchema {
		if len(body) != 0 {
			return nil, contract.ErrRecord
		}
		return nil, nil
	}
	image, err := contract.DecodeGeneratedRecipientRegistryImage(body)
	descriptor, descriptorErr := contract.GeneratedRecipientRegistryDescriptor(body)
	if err != nil || descriptorErr != nil || (q.Schema != contract.GeneratorPublicRequestCoreSchema && q.Schema != contract.GeneratorApplyRequestCoreSchema) || image.DomainID != s.root.Domain || image.OperationID != q.OperationID || descriptor != q.Registry {
		return nil, contract.ErrRecord
	}
	if _, err = effectiveGeneratedRecipients(s.root, s.registry(), image); err != nil {
		return nil, err
	}
	if initial {
		if image.OriginalPredecessorSnapshotID != s.root.Snapshot {
			return nil, contract.ErrRecord
		}
		proposal, err := s.admitApplyRecipients(ctx, image.Recipients)
		if err != nil {
			return nil, err
		}
		used, err := s.closureIDsMode(ctx, false)
		if err != nil {
			return nil, err
		}
		absent := make([]contract.ID, 0, len(proposal.changed))
		for _, row := range image.Recipients {
			if s.recipientRecord(row.Recipient.RecipientID) == nil {
				absent = append(absent, row.Recipient.RecipientID)
				for _, id := range []contract.ID{row.Recipient.RecipientID, row.Recipient.CurrentBinding.BindingID, row.Recipient.CurrentBinding.BindingIncarnationID} {
					if id.IsZero() || used[id] {
						return nil, contract.ErrRecord
					}
					used[id] = true
				}
			}
		}
		if !slices.Equal(absent, image.InitiallyAbsent) {
			return nil, contract.ErrRecord
		}
	}
	return &image, nil
}

func (b *generatedSelectionBuilder) resolveGeneratedRegistry() error {
	g := b.facts
	if g.parent == nil {
		return nil
	}
	q := g.bundles[0].Request
	if q.Schema == contract.GeneratorRequestCoreSchema {
		return nil
	}
	body, err := b.content.read(contract.GeneratorContentRecipientRegistry, q.OperationID, contract.GeneratedRecipientRegistryMaxLength)
	if err != nil {
		return err
	}
	image, err := contract.DecodeGeneratedRecipientRegistryImage(body)
	descriptor, descriptorErr := contract.GeneratedRecipientRegistryDescriptor(body)
	if err != nil || descriptorErr != nil || (q.Schema != contract.GeneratorPublicRequestCoreSchema && q.Schema != contract.GeneratorApplyRequestCoreSchema) || image.DomainID != g.image.root.Domain || image.OperationID != q.OperationID || descriptor != q.Registry {
		return contract.ErrRecord
	}
	current := selectedRecipientRegistry(&g.image.recipients, g.image.root.RecipientCount)
	if _, err = effectiveGeneratedRecipients(g.image.root, current, image, generatedSelectionAnchored(g)); err != nil {
		return err
	}
	g.registry, g.registryBody = &image, body
	return nil
}

func (s *StateSession) generatedEffectiveRecipients(g *generatedSelection) ([]contract.RecipientRecord, error) {
	return s.selectedImage().generatedEffectiveRecipients(g)
}
func (s *selectedImage) generatedEffectiveRecipients(g *generatedSelection) ([]contract.RecipientRecord, error) {
	current := selectedRecipientRegistry(&s.recipients, s.root.RecipientCount)
	if g == nil || g.registry == nil {
		return current, nil
	}
	return effectiveGeneratedRecipients(s.root, current, *g.registry, generatedSelectionAnchored(g))
}

func generatedRecipientBindings(root format.Root, records []contract.RecipientRecord) ([]contract.BindingTableRow, error) {
	rows := make([]contract.BindingTableRow, 0, len(records)+1)
	for _, row := range records {
		if row.CurrentBinding == nil {
			return nil, contract.ErrRecord
		}
		rows = append(rows, contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: row.RecipientID, Binding: *row.CurrentBinding})
	}
	if recovery := root.CurrentAccess.Core.Recovery; recovery != nil {
		rows = append(rows, contract.BindingTableRow{SubjectKind: contract.RecoveryWrapSubject, SubjectID: recovery.RoleID, Binding: recovery.KMS})
	}
	orderBindings(rows)
	_, err := contract.BindingTableLength(rows)
	return rows, err
}
func (s *StateSession) generatedBindings(g *generatedSelection) ([]contract.BindingTableRow, error) {
	return s.selectedImage().generatedBindings(g)
}
func (s *selectedImage) generatedBindings(g *generatedSelection) ([]contract.BindingTableRow, error) {
	records, err := s.generatedEffectiveRecipients(g)
	if err != nil {
		return nil, err
	}
	return generatedRecipientBindings(s.root, records)
}
func (s *StateSession) generatedPlanBindings(plan *generatedPlan) ([]contract.BindingTableRow, error) {
	if plan == nil {
		return nil, contract.ErrRecord
	}
	image, err := s.admitGeneratedRegistry(context.Background(), plan.input.registryImage, plan.input.graph.Request, false)
	if err != nil {
		return nil, err
	}
	if image == nil {
		return s.currentBindings()
	}
	rows, err := effectiveGeneratedRecipients(s.root, s.registry(), *image)
	if err != nil {
		return nil, err
	}
	return generatedRecipientBindings(s.root, rows)
}

func generatedRegistryPages(root format.Root, records []contract.RecipientRecord, phase contract.ID, operation contract.ID) ([]format.RecipientPage, []contract.Ref, error) {
	revision, err := contract.GeneratorPhaseRevisionID(phase)
	if err != nil {
		return nil, nil, err
	}
	plan := contract.IdentityPlan{Operation: operation, Snapshot: root.Snapshot, Transition: root.Transition, Revision: revision}
	count := (len(records) + format.RecipientSlots - 1) / format.RecipientSlots
	for i := 0; i < count; i++ {
		id, err := contract.GeneratorPhasePageID(phase, contract.RecipientKind, uint16(i))
		if err != nil {
			return nil, nil, err
		}
		plan.Pages = append(plan.Pages, contract.IdentityPage{Kind: contract.RecipientKind, Index: uint16(i), Object: id})
	}
	return format.ApplyRecipientPages(root.Domain, records, plan)
}
func (next *StateSession) installGeneratedRegistry(before *StateSession, g *generatedSelection, phase contract.ID, candidate *Candidate) error {
	if g.registry == nil {
		return nil
	}
	records, err := before.generatedEffectiveRecipients(g)
	if err != nil {
		return err
	}
	equal := len(records) == len(before.registry())
	if equal {
		for at, row := range records {
			a, e := contract.EncodeRecipientRecord(row)
			if e != nil {
				return e
			}
			b, e := contract.EncodeRecipientRecord(before.registry()[at])
			if e != nil {
				return e
			}
			if !bytes.Equal(a, b) {
				equal = false
				break
			}
		}
	}
	if equal {
		return nil
	}
	pages, refs, err := generatedRegistryPages(next.root, records, phase, g.parent.OperationID)
	if err != nil {
		return err
	}
	next.root.Recipients = [contract.MaxRecipientPages]*contract.Ref{}
	next.recipients = [contract.MaxRecipientPages]*format.RecipientPage{}
	for i := range pages {
		page := &pages[i]
		ref := refs[i]
		next.recipients[page.Index] = page
		next.root.Recipients[ref.Index] = &ref
		body, err := format.EncodeRecipientPage(*page)
		if err != nil {
			return err
		}
		candidate.objects = append(candidate.objects, objectImage{ref: ref, body: body})
	}
	next.root.RecipientCount = uint16(len(records))
	if len(pages) > 0 {
		next.recipient = pages[0]
	}
	next.root.CurrentAccess.Core.RecipientRefsDescriptor, err = recipientRefsDescriptor(next.root)
	return err
}

func (s *selectedImage) generatedFinalValueAccess(g *generatedSelection, core contract.ValueCore, payload contract.CanonicalPayload, access contract.AccessRecord, readers []contract.ID) bool {
	if g.registry == nil {
		return selectedValueAccess(s.root, &s.recipients, core, payload, access, readers)
	}
	records, err := s.generatedEffectiveRecipients(g)
	if err != nil {
		return false
	}
	// A validation projection has no store, admission, or execution capability.
	var pages [contract.MaxRecipientPages]*format.RecipientPage
	for i := range records {
		index, slot := i/format.RecipientSlots, i%format.RecipientSlots
		if pages[index] == nil {
			pages[index] = &format.RecipientPage{}
		}
		pages[index].Slots[slot] = &records[i]
	}
	return selectedValueAccess(s.root, &pages, core, payload, access, readers)
}

func generatedRegistryChangedSubjects(before, after *StateSession) ([]contract.ChangedSubjectIdentity, error) {
	var out []contract.ChangedSubjectIdentity
	for _, row := range after.registry() {
		old := before.recipientRecord(row.RecipientID)
		kind := uint8(contract.ChangedSubjectAdded)
		if old != nil {
			a, err := contract.EncodeRecipientRecord(*old)
			if err != nil {
				return nil, err
			}
			b, err := contract.EncodeRecipientRecord(row)
			if err != nil {
				return nil, err
			}
			if bytes.Equal(a, b) {
				continue
			}
			kind = contract.ChangedSubjectUpdated
		}
		id, err := contract.ChangedSubjectIdentityID(before.root.Domain, contract.ChangedSubjectRecipient, row.RecipientID, contract.ID{})
		if err != nil {
			return nil, err
		}
		out = append(out, contract.ChangedSubjectIdentity{Kind: contract.ChangedSubjectRecipient, Change: kind, Identity: id})
	}
	return out, nil
}

func (s *StateSession) generatedQualificationCounts(bindings []contract.BindingTableRow) map[contract.ID]uint32 {
	counts := make(map[contract.ID]uint32)
	for _, row := range bindings {
		if row.SubjectKind == contract.OrdinaryWrapSubject && s.recipientRecord(row.SubjectID) == nil {
			counts[row.Binding.BindingID] = contract.PublicKeyQualificationUseCount(row.Binding.Provider)
		}
	}
	return counts
}

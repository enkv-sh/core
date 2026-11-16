package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
)

func (s *StateSession) generatedConsumerSelection(ctx context.Context, kind uint8, owner, value, acting contract.ID) (contract.GeneratedCanonicalSelection, Result) {
	if s == nil || ctx == nil || ctx.Err() != nil || !s.admission.valid(s.store) || acting.IsZero() {
		return contract.GeneratedCanonicalSelection{}, refused(AdmissionInvalid)
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		if result, ok := selectedReadResult(err); ok {
			return contract.GeneratedCanonicalSelection{}, result
		}
		return contract.GeneratedCanonicalSelection{}, refused(InvalidRelation)
	}
	selection, err := g.canonicalConsumer(generatedRecordKey{kind, owner}, value, acting)
	if err != nil {
		return contract.GeneratedCanonicalSelection{}, refused(AdmissionInvalid)
	}
	return selection, s.observed(ObservedCurrent)
}

func (g *generatedSelection) canonicalConsumer(key generatedRecordKey, value, acting contract.ID) (contract.GeneratedCanonicalSelection, error) {
	owned, err := g.canonicalConsumerView(key, value, acting)
	if err != nil {
		return contract.GeneratedCanonicalSelection{}, err
	}
	owned.Record.Entry.ValueBytes = bytes.Clone(owned.Record.Entry.ValueBytes)
	owned.Record.Entry.Recipients = slices.Clone(owned.Record.Entry.Recipients)
	owned.Selection.Entry = owned.Record.Entry
	owned.Selection.Payload.Ciphertext = bytes.Clone(owned.Selection.Payload.Ciphertext)
	owned.Selection.Access.Wraps = slices.Clone(owned.Selection.Access.Wraps)
	for i := range owned.Selection.Access.Wraps {
		owned.Selection.Access.Wraps[i].RSACiphertext = bytes.Clone(owned.Selection.Access.Wraps[i].RSACiphertext)
	}
	owned.Selection.Binding.Binding.SPKI = bytes.Clone(owned.Selection.Binding.Binding.SPKI)
	owned.Owner.Body = bytes.Clone(owned.Owner.Body)
	owned.Consumers = slices.Clone(owned.Consumers)
	for i := range owned.Consumers {
		owned.Consumers[i] = bytes.Clone(owned.Consumers[i])
	}
	return owned, nil
}

// canonicalConsumerView lends the exact immutable selected input only through
// the installed constructor call. Public returns use canonicalConsumer's copy.
func (g *generatedSelection) canonicalConsumerView(key generatedRecordKey, value, acting contract.ID) (contract.GeneratedCanonicalSelection, error) {
	owner, owned := g.records[key]
	if !owned {
		return contract.GeneratedCanonicalSelection{}, contract.ErrRecord
	}
	reader := g.image.recipientRecord(acting)
	if reader == nil || reader.Status != contract.CurrentRecipient || reader.CurrentBinding == nil {
		return contract.GeneratedCanonicalSelection{}, contract.ErrRecord
	}
	var descriptor contract.GeneratorDescriptor
	switch key.kind {
	case contract.GeneratedDutySupportKind:
		row, err := contract.InspectGeneratedDutyRecord(owner.Body)
		if err != nil {
			return contract.GeneratedCanonicalSelection{}, err
		}
		descriptor = row.Consumers
	case contract.GeneratedHazardSupportKind:
		row, err := contract.InspectGeneratedHazardRecord(owner.Body)
		if err != nil {
			return contract.GeneratedCanonicalSelection{}, err
		}
		descriptor = row.Consumers
	default:
		return contract.GeneratedCanonicalSelection{}, contract.ErrRecord
	}
	consumers, err := g.vectors.borrow(key.kind, key.id, contract.GeneratorVectorConsumers, descriptor)
	if err != nil {
		return contract.GeneratedCanonicalSelection{}, err
	}
	var source generatedCanonical
	found := false
	for _, body := range consumers {
		row, err := contract.InspectGeneratorConsumer(body)
		if err != nil {
			return contract.GeneratedCanonicalSelection{}, err
		}
		if row.MaterialID != value || row.SubjectKind != contract.GeneratorConsumerRetainedCanonicalValue {
			continue
		}
		var ok bool
		source, ok = g.canonical[row.SubjectID]
		materialContext, err := contract.ValueMaterialContextDigest(source.core)
		if found || !ok || err != nil || row.OwnerID != key.id || row.Purpose != contract.GeneratorConsumerUseRetainedCanonical ||
			source.record.Entry.ValueState != value || row.ContextDigest != materialContext {
			return contract.GeneratedCanonicalSelection{}, contract.ErrRecord
		}
		found = true
	}
	if !found || !slices.Contains(source.record.Entry.Recipients, acting) {
		return contract.GeneratedCanonicalSelection{}, contract.ErrRecord
	}
	s := g.session
	record := source.record
	digest, err := contract.PublicValueEntryDigest(s.admission.domain, record.OriginalSlot, record.Entry)
	if err != nil {
		return contract.GeneratedCanonicalSelection{}, err
	}
	payload, access, binding := source.payload, source.access, *reader.CurrentBinding
	selection := contract.ConsumerSelection{DomainID: s.admission.domain,
		SnapshotID: s.root.Snapshot, HEADDigest: contract.Hash(s.body), AccessRoot: s.root.CurrentAccess.AccessRoot, EntryDigest: digest,
		Root: s.head.Core.Root, HEADRevision: s.head.Core.Revision, HEADToken: s.token, Slot: record.OriginalSlot,
		Entry: record.Entry, Core: source.core, Payload: payload, Access: access,
		Binding: contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: acting, Binding: binding}}
	return contract.GeneratedCanonicalSelection{Selection: selection, Record: record, Owner: owner, Consumers: consumers}, nil
}

type generatedCanonical struct {
	record  contract.RetainedCanonicalRecord
	core    contract.ValueCore
	payload contract.CanonicalPayload
	access  contract.AccessRecord
}

func (b *generatedSelectionBuilder) resolveActiveCanonicals() error {
	if b == nil || b.facts == nil {
		return contract.ErrRecord
	}
	g := b.facts
	if g.phase != nil && !g.phase.SelectionPhaseID.IsZero() {
		return nil
	}
	if g.parent == nil || len(g.bundles) == 0 || g.bundles[0].UsePlan.PlanGraphID != g.parent.PlanGraphID {
		return contract.ErrRecord
	}
	operation := g.bundles[0].Request.OperationKind
	currentOnly := operation == contract.OperationCleanOwnedFailureResidue || operation == contract.OperationRetireGeneratedGeneration
	body, err := b.content.read(contract.GeneratorContentDeclaration, g.parent.OperationID, contract.GeneratorDeclarationMaxLength)
	if err != nil {
		return err
	}
	declaration, err := contract.InspectGeneratorDeclaration(body)
	if err != nil {
		return err
	}
	g.declaredCanonicals = make(map[contract.ID]bool)
	for i := 0; i < declaration.EntryCount(); i++ {
		entry, _, err := declaration.Entry(i)
		if err != nil {
			return err
		}
		if entry.Kind != contract.GeneratorDeclarationRetained {
			continue
		}
		r, err := contract.DecodeRetainedCanonicalRecord(entry.Payload)
		if err != nil {
			return err
		}
		if currentOnly {
			// Delete declarations repeat current values for their membership
			// projection. Only real retained consumers can claim work support.
			named := false
			for _, entry := range g.image.root.Names {
				if entry.Name == r.Entry.Name && entry.Slot == r.OriginalSlot {
					named = true
					break
				}
			}
			current := g.image.valueEntry(r.OriginalSlot)
			if !named || current == nil {
				return contract.ErrRecord
			}
			body, err := contract.EncodeRetainedCanonicalRecord(contract.RetainedCanonicalRecord{OriginalSlot: r.OriginalSlot, Entry: *current})
			if err != nil || !bytes.Equal(body, entry.Payload) {
				return contract.ErrRecord
			}
			if _, err := b.canonicalValue(r); err != nil {
				return err
			}
			continue
		}
		sourceID, err := contract.AdmissionEntryDigest(r)
		if err != nil {
			return err
		}
		found := false
		for _, id := range []contract.ID{sourceID, r.Entry.ValueState} {
			row, ok := g.records[generatedRecordKey{contract.RetainedCanonicalSupportKind, id}]
			if !ok || !bytes.Equal(row.Body, entry.Payload) {
				continue
			}
			selected, err := b.canonicalValue(r)
			if err != nil {
				return err
			}
			if _, ok := b.claimRecord(contract.RetainedCanonicalSupportKind, id); !ok {
				return contract.ErrRecord
			}
			g.canonical[id] = selected
			g.declaredCanonicals[id] = true
			if g.retainedOwners == nil {
				g.retainedOwners = make(map[contract.ID][]generatedRecordKey)
			}
			g.retainedOwners[id] = append(g.retainedOwners[id], generatedRecordKey{contract.GeneratedParentSupportKind, g.parent.OperationID})
			found = true
		}
		if !found {
			return contract.ErrRecord
		}
	}
	return nil
}

func (b *generatedSelectionBuilder) canonicalValue(r contract.RetainedCanonicalRecord) (generatedCanonical, error) {
	if b == nil || b.facts == nil {
		return generatedCanonical{}, contract.ErrRecord
	}
	g := b.facts
	core, payload, err := g.image.canonicalValueMeaning(r, g.canonical)
	if err != nil {
		return generatedCanonical{}, err
	}
	access, ok := g.materialAccess(contract.ValueMaterialKind, core.ValueStateID)
	if !ok || !g.validateValueAccess(core, payload, access, g.selectedMaterials.valueReaders[core.ValueStateID]) {
		return generatedCanonical{}, contract.ErrRecord
	}
	return generatedCanonical{record: r, core: core, payload: payload, access: access}, nil
}

func (s *selectedImage) canonicalValueMeaning(r contract.RetainedCanonicalRecord, others map[contract.ID]generatedCanonical) (contract.ValueCore, contract.CanonicalPayload, error) {
	control := s.root.CurrentAccess.Core
	core, err := contract.ValueCoreForEntry(s.root.Domain, control.CompatibilityID, r.Entry)
	if err != nil || core.CryptoSupportID != control.CryptoSupportID || !slices.Contains(r.Entry.Recipients, control.AuthorityRecipientID) {
		return contract.ValueCore{}, contract.CanonicalPayload{}, contract.ErrRecord
	}
	payload, err := contract.DecodeCanonicalPayload(r.Entry.ValueBytes)
	if err != nil {
		return contract.ValueCore{}, contract.CanonicalPayload{}, err
	}
	for _, entry := range s.root.Names {
		current := s.valueEntry(entry.Slot)
		if current != nil && current.ValueState == core.ValueStateID && !sameRetainedEntryValue(*current, r.Entry) {
			return contract.ValueCore{}, contract.CanonicalPayload{}, contract.ErrRecord
		}
	}
	for _, other := range others {
		if other.record.Entry.ValueState == r.Entry.ValueState && !sameRetainedEntryValue(other.record.Entry, r.Entry) {
			return contract.ValueCore{}, contract.CanonicalPayload{}, contract.ErrRecord
		}
	}
	return core, payload, nil
}

func (b *generatedSelectionBuilder) claimCanonicalConsumer(ownerKind uint8, owner contract.ID, declared bool, consumer contract.GeneratorConsumer) error {
	if b == nil || b.facts == nil {
		return contract.ErrRecord
	}
	g := b.facts
	if consumer.OwnerID != owner || consumer.SubjectKind != contract.GeneratorConsumerRetainedCanonicalValue || consumer.Purpose != contract.GeneratorConsumerUseRetainedCanonical ||
		declared && !g.declaredCanonicals[consumer.SubjectID] {
		return contract.ErrRecord
	}
	selected, ok := g.canonical[consumer.SubjectID]
	if !ok {
		row, present := b.claimRecord(contract.RetainedCanonicalSupportKind, consumer.SubjectID)
		if !present {
			return contract.ErrRecord
		}
		r, err := contract.DecodeRetainedCanonicalRecord(row.Body)
		if err != nil || r.Entry.ValueState != consumer.MaterialID {
			return contract.ErrRecord
		}
		selected, err = b.canonicalValue(r)
		if err != nil {
			return err
		}
		if r.Entry.ValueSource == contract.Generated {
			if err := b.validateValueEntry(g.image.root.Domain, r.Entry); err != nil {
				return err
			}
		}
		g.canonical[consumer.SubjectID] = selected
	}
	context, err := contract.ValueMaterialContextDigest(selected.core)
	if err != nil || consumer.ContextDigest != context || selected.record.Entry.ValueState != consumer.MaterialID {
		return contract.ErrRecord
	}
	key := materialIdentity{contract.ValueMaterialKind, consumer.MaterialID}
	if !b.claimMaterial(key) {
		return contract.ErrRecord
	}
	for _, other := range g.consumers[key] {
		if other.OwnerID == owner && other.SubjectKind == consumer.SubjectKind && other.SubjectID != consumer.SubjectID {
			return contract.ErrRecord
		}
	}
	g.consumers[key] = append(g.consumers[key], consumer)
	if g.retainedOwners == nil {
		g.retainedOwners = make(map[contract.ID][]generatedRecordKey)
	}
	g.retainedOwners[consumer.SubjectID] = append(g.retainedOwners[consumer.SubjectID], generatedRecordKey{ownerKind, owner})
	return nil
}

func (g *generatedSelection) retainedReaders(value contract.ID) []contract.ID {
	var readers []contract.ID
	for _, source := range g.canonical {
		if source.record.Entry.ValueState == value {
			readers = append(readers, source.record.Entry.Recipients...)
		}
	}
	slices.SortFunc(readers, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	return slices.Compact(readers)
}

package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
)

type generatedFinalRows struct {
	declaration     contract.GeneratorDeclarationView
	generated       map[uint16]contract.CryptoGeneratedValueEntryResult
	supplied        map[uint16]generatedFinalSuppliedEntry
	legacyExclusion bool
}

// Historical exclusion recognition is allowed only while qualifying a selected
// immutable image. New checkpoints and actual Final always use the strict gate.
func (s *StateSession) validateGeneratedFinalRows(ctx context.Context, g *generatedSelection, plan *generatedFinalPlan,
	prepared []contract.CryptoGeneratedValueEntryResult, preparedSupplied []contract.CryptoPreparedSecret, historical bool) (generatedFinalRows, error) {
	if s == nil || plan == nil || plan.request.Context.DomainID != s.root.Domain || plan.request.Context.CompatibilityID != s.root.CurrentAccess.Core.CompatibilityID {
		return generatedFinalRows{}, contract.ErrRecord
	}
	return s.selectedImage().validateGeneratedFinalRows(ctx, g, &plan.generatedFinalProjection, plan.materialization != nil, prepared, preparedSupplied, historical)
}

func (s *selectedImage) validateGeneratedFinalRows(ctx context.Context, g *generatedSelection, plan *generatedFinalProjection, materialized bool,
	prepared []contract.CryptoGeneratedValueEntryResult, preparedSupplied []contract.CryptoPreparedSecret, historical bool) (generatedFinalRows, error) {
	if s == nil || g == nil || g.parent == nil || plan == nil || len(prepared) != len(plan.entryPlans) {
		return generatedFinalRows{}, contract.ErrRecord
	}
	var err error
	legacyExclusion := false
	bySlot := make(map[uint16]contract.CryptoGeneratedValueEntryResult, len(prepared))
	for i, row := range prepared {
		input := plan.entryPlans[i]
		if row.Slot != input.Slot || row.ResultID != input.Generated.CreateResultID || row.ResultDigest != contract.Hash(input.Result) ||
			row.ValueCore != input.ValueCore || row.Entry.OutputEncoding != input.OutputEncoding || row.Entry.Name != input.ValueCore.Name || row.Entry.Generated != input.Generated ||
			row.Access.MaterialKind != contract.ValueMaterialKind || row.Access.MaterialID != input.ValueCore.ValueStateID {
			return generatedFinalRows{}, contract.ErrRecord
		}
		core, coreErr := contract.ValueCoreForEntry(s.root.Domain, s.root.CurrentAccess.Core.CompatibilityID, row.Entry)
		payload, payloadErr := contract.InspectCanonicalPayload(row.Entry.ValueBytes)
		if coreErr != nil || payloadErr != nil || core != row.ValueCore || row.Entry.ValueSource != contract.Generated ||
			row.Entry.ConfidentialityClass != contract.Secret || !slices.Equal(row.Entry.Recipients, input.Recipients) ||
			!s.generatedFinalValueAccess(g, core, contract.CanonicalPayload(payload), row.Access, input.Recipients) {
			return generatedFinalRows{}, contract.ErrRecord
		}
		if current := s.generatedFinalPredecessor(row.Slot, row.Entry.Name); current != nil && current.ConfidentialityClass == contract.Secret &&
			generatedFinalExcludesReader(*current, input.Recipients) && !generatedFinalChangedProtection(*current, row.Entry) {
			return generatedFinalRows{}, contract.ErrRecord
		}
		if _, duplicate := bySlot[row.Slot]; duplicate {
			return generatedFinalRows{}, contract.ErrRecord
		}
		bySlot[row.Slot] = row
	}
	suppliedBySlot := make(map[uint16]generatedFinalSuppliedEntry, len(plan.supplied.Rows))
	transferred := false
	var pendingEntry []byte
	var pendingAccess contract.AccessRecord
	defer func() {
		if transferred {
			return
		}
		clear(pendingEntry[:cap(pendingEntry)])
		for _, wrap := range pendingAccess.Wraps {
			clear(wrap.RSACiphertext[:cap(wrap.RSACiphertext)])
		}
		owned := generatedFinalRows{supplied: suppliedBySlot}
		owned.clearOwnedSupplied()
	}()
	for _, valueEntry := range plan.plain {
		identityIndex := slices.IndexFunc(plan.supplied.Rows, func(row contract.IdentityRow) bool { return row.Name == valueEntry.Name })
		if identityIndex < 0 || plan.supplied.Rows[identityIndex].Slot >= contract.CryptoMaxValueEntries {
			return generatedFinalRows{}, contract.ErrRecord
		}
		suppliedBySlot[plan.supplied.Rows[identityIndex].Slot] = generatedFinalSuppliedEntry{entry: valueEntry}
	}
	var declarationBody []byte
	if len(s.fragmentFacts) != 0 {
		declarationBody, err = g.readSelectedSlice(ctx, contract.GeneratorContentDeclaration, g.parent.OperationID, contract.GeneratorDeclarationMaxLength)
	} else {
		declarationBody, err = g.content.read(contract.GeneratorContentDeclaration, g.parent.OperationID, contract.GeneratorDeclarationMaxLength)
	}
	if err != nil {
		return generatedFinalRows{}, err
	}
	declaration, err := contract.InspectGeneratorDeclaration(declarationBody)
	if err != nil {
		return generatedFinalRows{}, contract.ErrRecord
	}
	wantPrepared := 0
	for _, identity := range plan.supplied.Rows {
		entryPlanIndex := slices.IndexFunc(g.bundles[0].ValueEntryPlans, func(entryPlan contract.GeneratorValueEntryPlan) bool {
			return entryPlan.Name == identity.Name && entryPlan.Slot == identity.Slot
		})
		if entryPlanIndex < 0 {
			return generatedFinalRows{}, contract.ErrRecord
		}
		entry, _, entryErr := declaration.Entry(entryPlanIndex)
		if entryErr != nil {
			return generatedFinalRows{}, contract.ErrRecord
		}
		if entry.ConfidentialityClass() == contract.Secret {
			wantPrepared++
		}
	}
	if len(preparedSupplied) != wantPrepared {
		return generatedFinalRows{}, contract.ErrRecord
	}
	for _, row := range preparedSupplied {
		identityIndex := slices.IndexFunc(plan.supplied.Rows, func(value contract.IdentityRow) bool { return value.Name == row.Name })
		if identityIndex < 0 {
			return generatedFinalRows{}, contract.ErrRecord
		}
		identity := plan.supplied.Rows[identityIndex]
		entryPlanIndex := slices.IndexFunc(g.bundles[0].ValueEntryPlans, func(entryPlan contract.GeneratorValueEntryPlan) bool {
			return entryPlan.Name == identity.Name && entryPlan.Slot == identity.Slot
		})
		if entryPlanIndex < 0 || row.Slot != identity.Slot {
			return generatedFinalRows{}, contract.ErrRecord
		}
		entry, _, entryErr := declaration.Entry(entryPlanIndex)
		if entryErr != nil || entry.ConfidentialityClass() != contract.Secret {
			return generatedFinalRows{}, contract.ErrRecord
		}
		valueEntry, err := contract.DecodeValueEntry(row.EntryBytes)
		pendingEntry = valueEntry.ValueBytes
		if err != nil || valueEntry.Name != identity.Name || valueEntry.Incarnation != identity.Incarnation ||
			valueEntry.InputEncoding != entry.InputEncoding || valueEntry.OutputEncoding != entry.OutputEncoding || valueEntry.ValueSource != entry.ValueSource() || valueEntry.ConfidentialityClass != contract.Secret {
			return generatedFinalRows{}, contract.ErrRecord
		}
		access, err := contract.DecodeAccessRecord(row.AccessRecord)
		pendingAccess = access
		if err != nil || access.MaterialKind != contract.ValueMaterialKind || access.MaterialID != valueEntry.ValueState {
			return generatedFinalRows{}, contract.ErrRecord
		}
		core, err := contract.ValueCoreForEntry(s.root.Domain, s.root.CurrentAccess.Core.CompatibilityID, valueEntry)
		payload, payloadErr := contract.InspectCanonicalPayload(valueEntry.ValueBytes)
		recipients := make([]contract.ID, len(entry.RecipientIDs)/32)
		for i := range recipients {
			recipients[i] = contract.ID(entry.RecipientIDs[i*32 : (i+1)*32])
		}
		if !slices.Equal(valueEntry.Recipients, recipients) {
			return generatedFinalRows{}, contract.ErrRecord
		}
		current := s.generatedFinalPredecessor(identity.Slot, identity.Name)
		exclusion := current != nil && current.ConfidentialityClass == contract.Secret && generatedFinalExcludesReader(*current, recipients)
		readers := valueEntry.Recipients
		preservedSource := g.bundles[0].ValueEntryPlans[entryPlanIndex].ChangeMask&contract.GeneratorValueChangeContent == 0 || entry.Kind == contract.GeneratorDeclarationRetained
		legacy := false
		if exclusion {
			if !generatedFinalFreshProtection(*current, valueEntry) {
				if !historical || !preservedSource || !sameRetainedEntryValue(*current, valueEntry) {
					return generatedFinalRows{}, contract.ErrRecord
				}
				legacy, legacyExclusion = true, true
				identity.ValueState, identity.OriginSnapshot, identity.OriginTransition = current.ValueState, current.OriginSnapshot, current.OriginTransition
			}
		}
		if !exclusion || legacy {
			if preservedSource {
				if current == nil || current.Generated != valueEntry.Generated || !sameRetainedEntryValue(*current, valueEntry) {
					return generatedFinalRows{}, contract.ErrRecord
				}
				if retained := g.retainedReaders(valueEntry.ValueState); len(retained) != 0 {
					readers = append(slices.Clone(readers), retained...)
					slices.SortFunc(readers, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
					readers = slices.Compact(readers)
				}
			}
		}
		if valueEntry.ValueState != identity.ValueState || valueEntry.OriginSnapshot != identity.OriginSnapshot || valueEntry.OriginTransition != identity.OriginTransition {
			return generatedFinalRows{}, contract.ErrRecord
		}
		currentOnlyReplay := (!exclusion || legacy) && materialized && entry.Kind == contract.GeneratorDeclarationRetained &&
			g.bundles[0].ValueEntryPlans[entryPlanIndex].ChangeMask&contract.GeneratorValueChangeContent != 0 &&
			len(readers) > len(valueEntry.Recipients) && s.generatedFinalValueAccess(g, core, contract.CanonicalPayload(payload), access, valueEntry.Recipients)
		if currentOnlyReplay {
			readers = valueEntry.Recipients
		}
		if err != nil || core.EntryIncarnationID != identity.Incarnation || core.ValueStateID != identity.ValueState ||
			core.OriginSnapshotID != identity.OriginSnapshot || core.OriginTransitionID != identity.OriginTransition ||
			payloadErr != nil || !s.generatedFinalValueAccess(g, core, contract.CanonicalPayload(payload), access, readers) {
			return generatedFinalRows{}, contract.ErrRecord
		}
		if entry.Kind == contract.GeneratorDeclarationRetained {
			record, recordErr := contract.DecodeRetainedCanonicalRecord(entry.Payload)
			matches := recordErr == nil && current != nil && sameRetainedEntryValue(*current, record.Entry) &&
				(exclusion && !legacy || sameRetainedEntryValue(valueEntry, record.Entry))
			clear(record.Entry.ValueBytes[:cap(record.Entry.ValueBytes)])
			if !matches {
				return generatedFinalRows{}, contract.ErrRecord
			}
		}
		if _, duplicate := suppliedBySlot[row.Slot]; duplicate {
			return generatedFinalRows{}, contract.ErrRecord
		}
		accessCopy := access
		suppliedBySlot[row.Slot] = generatedFinalSuppliedEntry{entry: valueEntry, access: &accessCopy, currentOnlyReplay: currentOnlyReplay}
		pendingEntry, pendingAccess = nil, contract.AccessRecord{}
	}
	if len(suppliedBySlot) != len(plan.supplied.Rows) {
		return generatedFinalRows{}, contract.ErrRecord
	}
	transferred = true
	return generatedFinalRows{declaration: declaration, generated: bySlot, supplied: suppliedBySlot, legacyExclusion: legacyExclusion}, nil
}

// Finish qualification before rebuilding a replacement request. Image rows and
// decoded supplied copies must not overlap the next complete request's inputs.
func (s *StateSession) generatedFinalPreparationNeedsReplacement(ctx context.Context, g *generatedSelection, plan *generatedFinalPlan) (bool, error) {
	image, err := s.generatedFinalPreparationImage(ctx, g)
	if err != nil {
		return false, err
	}
	defer image.Clear()
	rows, err := s.validateGeneratedFinalRows(ctx, g, plan, image.Generated, image.Supplied, true)
	if err != nil {
		return false, err
	}
	defer rows.clearOwnedSupplied()
	return rows.legacyExclusion, nil
}

// Generated map rows borrow the image; plain map rows borrow plan inputs.
// Only decoded secret entries and access packets are owned by this result.
func (v *generatedFinalRows) clearOwnedSupplied() {
	for slot, row := range v.supplied {
		if row.access != nil {
			clear(row.entry.ValueBytes[:cap(row.entry.ValueBytes)])
			for i := range row.access.Wraps {
				clear(row.access.Wraps[i].RSACiphertext[:cap(row.access.Wraps[i].RSACiphertext)])
			}
			row.access.Wraps = nil
		}
		delete(v.supplied, slot)
	}
	v.generated, v.supplied = nil, nil
	v.declaration = contract.GeneratorDeclarationView{}
}

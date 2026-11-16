package crypto

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

func (a *generatedAdmission) admitCurrentValues(input []contract.ConsumerSelection, declarationBody []byte) bool {
	plan := a.purpose.plan()
	if plan == nil || len(input) > contract.CryptoMaxValueEntries {
		return false
	}
	declaration, err := contract.InspectGeneratorDeclaration(declarationBody)
	if err != nil {
		return false
	}
	required := 0
	for i, entryPlan := range a.graph.ValueEntryPlans {
		changed := entryPlan.ChangeMask&contract.GeneratorValueChangeContent != 0
		if !changed && entryPlan.ValueSource != contract.Supplied {
			continue
		}
		entry, _, entryErr := declaration.Entry(i)
		if entryErr != nil {
			return false
		}
		before := slices.IndexFunc(a.before.Rows, func(row contract.PublicStateRow) bool {
			return row.Slot == entryPlan.Slot && row.Name == entryPlan.Name
		})
		if before < 0 {
			if changed {
				continue
			}
			return false
		}
		if a.purpose.output == nil || before >= len(a.purpose.output.EntryBodies) {
			return false
		}
		current, err := contract.InspectValueEntry(a.purpose.output.EntryBodies[before])
		if err != nil {
			return false
		}
		readers := make([]contract.ID, current.RecipientCount())
		for j := range readers {
			id, present := current.RecipientID(j)
			if !present {
				return false
			}
			readers[j] = id
		}
		removal := current.ConfidentialityClass == contract.Secret && slices.ContainsFunc(readers, func(id contract.ID) bool {
			return !slices.Contains(plan.recipients[i], id)
		})
		if changed {
			// Changed content keeps its own semantic source. The authenticated
			// old current packet is needed separately to reject old key reuse.
			if entryPlan.ConfidentialityClass != contract.Secret || !removal || entry.Kind == contract.GeneratorDeclarationRetained {
				continue
			}
		} else {
			if current.ValueSource != contract.Supplied || current.InputEncoding != entryPlan.InputEncoding || current.ConfidentialityClass != entryPlan.ConfidentialityClass || current.Incarnation != entryPlan.EntryIncarnationID {
				return false
			}
			membership, err := contract.GeneratorIntendedMembershipDescriptor(readers)
			if err != nil || membership != entryPlan.IntendedMembership && entryPlan.ChangeMask&contract.GeneratorValueChangeMembership == 0 {
				return false
			}
			if current.ConfidentialityClass == contract.Plain {
				if entry.Kind != contract.GeneratorDeclarationPlain || !bytes.Equal(current.ValueBytes, entry.Payload) {
					return false
				}
				continue
			}
			if entry.Kind == contract.GeneratorDeclarationRetained {
				continue
			}
			if entry.Kind != contract.GeneratorDeclarationSealed {
				return false
			}
		}
		index := slices.IndexFunc(input, func(row contract.ConsumerSelection) bool { return row.Slot == entryPlan.Slot })
		if index < 0 {
			return false
		}
		s := input[index]
		if index > 0 && input[index-1].Slot >= s.Slot {
			return false
		}
		if _, _, ok := checkConsumerSelection(s, a.control.Provider); !ok {
			return false
		}
		c := a.request.Context
		root, err := contract.DecodeRef(c.PredecessorRootRef[:], contract.CanonicalSchema)
		if err != nil || s.Root != root || s.DomainID != c.DomainID || s.HEADDigest != c.PredecessorHEADDigest || s.AccessRoot != c.CurrentAccessRoot ||
			s.Binding.SubjectID != a.control.AuthorityRecipientID || !sameGeneratedBinding(s.Binding.Binding, a.control.AuthorityKMSBinding) || !a.accessBindingsValid(s.Access) ||
			a.before.Rows[before] != (contract.PublicStateRow{Slot: s.Slot, Name: s.Entry.Name, EntryDigest: s.EntryDigest}) {
			return false
		}
		condition, err := contract.MatchHeadCondition(s.HEADToken)
		if err != nil {
			return false
		}
		digest, err := contract.CryptoConditionDigest(condition)
		body, bodyErr := contract.EncodeValueEntry(s.Entry)
		if err != nil || bodyErr != nil || digest != c.OriginalConditionDigest || !bytes.Equal(body, a.purpose.output.EntryBodies[before]) {
			return false
		}
		// The selected output image owns the current payload. Keep one owned
		// copy for the private comparison and clear it with this admission.
		s.Entry, err = contract.DecodeValueEntry(body)
		if err != nil {
			return false
		}
		payload, err := contract.InspectCanonicalPayload(s.Entry.ValueBytes)
		if err != nil {
			return false
		}
		s.Payload = contract.CanonicalPayload(payload)
		s.Access.Wraps = slices.Clone(s.Access.Wraps)
		for j := range s.Access.Wraps {
			s.Access.Wraps[j].RSACiphertext = bytes.Clone(s.Access.Wraps[j].RSACiphertext)
		}
		plan.currentValues = append(plan.currentValues, s)
		required++
	}
	return required == len(input)
}

func (a *generatedAdmission) originalSealedCurrentSubset(index int) bool {
	plan := a.purpose.plan()
	if plan == nil || index < 0 || index >= len(a.graph.ValueEntryPlans) || index >= len(plan.recipients) || a.purpose.output == nil {
		return false
	}
	entryPlan := a.graph.ValueEntryPlans[index]
	if entryPlan.ValueSource != contract.Supplied || entryPlan.ConfidentialityClass != contract.Secret || entryPlan.ChangeMask&contract.GeneratorValueChangeContent != 0 {
		return false
	}
	before := slices.IndexFunc(a.before.Rows, func(row contract.PublicStateRow) bool {
		return row.Slot == entryPlan.Slot && row.Name == entryPlan.Name
	})
	if before < 0 || before >= len(a.purpose.output.EntryBodies) {
		return false
	}
	current, err := contract.InspectValueEntry(a.purpose.output.EntryBodies[before])
	if err != nil || current.ValueSource != contract.Supplied || current.ConfidentialityClass != contract.Secret || current.Incarnation != entryPlan.EntryIncarnationID {
		return false
	}
	for _, desired := range plan.recipients[index] {
		present := false
		for at := 0; at < current.RecipientCount(); at++ {
			id, ok := current.RecipientID(at)
			if !ok {
				return false
			}
			present = present || id == desired
		}
		if !present {
			return false
		}
	}
	return true
}

func (a *generatedAdmission) compareSuppliedCurrent(ctx context.Context, route KeyAccess, name string, plain []byte, out *contract.CryptoResponse) contract.CryptoResultCode {
	plan := a.purpose.plan()
	if plan == nil {
		return contract.CryptoInvalidAdmission
	}
	entryPlan := slices.IndexFunc(a.graph.ValueEntryPlans, func(row contract.GeneratorValueEntryPlan) bool { return row.Name == name })
	if entryPlan < 0 {
		return contract.CryptoInvalidAdmission
	}
	if a.graph.ValueEntryPlans[entryPlan].ChangeMask&contract.GeneratorValueChangeContent != 0 {
		return contract.CryptoSuccess
	}
	index := slices.IndexFunc(plan.currentValues, func(row contract.ConsumerSelection) bool {
		return row.Entry.Name == name && row.Slot == a.graph.ValueEntryPlans[entryPlan].Slot
	})
	if index < 0 {
		return contract.CryptoInvalidAdmission
	}
	s := plan.currentValues[index]
	keys, code := a.openCurrentValue(ctx, route, s, out)
	if keys != nil {
		defer clear(keys[:cap(keys)])
	}
	if code != contract.CryptoSuccess {
		return code
	}
	current, err := custody.OpenValue(s.Core, s.Payload, keys)
	if current != nil {
		defer clear(current[:cap(current)])
	}
	if err != nil {
		return contract.CryptoStoredAuthenticationFailed
	}
	if ctx.Err() != nil {
		return contract.CryptoCancelled
	}
	equal, err := custody.EqualValue(s.Core, s.Payload, keys, plain)
	if err != nil {
		return contract.CryptoStoredAuthenticationFailed
	}
	if !equal {
		return contract.CryptoInvalidAdmission
	}
	return contract.CryptoSuccess
}

func (a *generatedAdmission) openCurrentValue(ctx context.Context, route KeyAccess, selected contract.ConsumerSelection, out *contract.CryptoResponse) ([]byte, contract.CryptoResultCode) {
	index := applyBindingIndex(a.bindings, a.control.AuthorityRecipientID)
	if index < 0 {
		return nil, contract.CryptoInvalidAdmission
	}
	binding := a.bindings[index]
	core, err := custody.ValueWrapCore(selected.Core, binding)
	wrap := slices.IndexFunc(selected.Access.Wraps, func(row contract.WrapRow) bool {
		return generatedWrapRowIdentity(row) == generatedBindingIdentity(binding, a.bindingDigests[index])
	})
	if err != nil || wrap < 0 {
		return nil, contract.CryptoInvalidAdmission
	}
	return openMaterialPacket(ctx, route, binding, core, selected.Access.Wraps[wrap], contract.CryptoStoredAuthenticationFailed, out)
}

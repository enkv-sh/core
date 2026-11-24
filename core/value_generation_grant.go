package core

import (
	"slices"
	"strings"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// Reserve all proposed additions before consulting a generator. Only an
// already usable wrap for material known to survive can reduce this bound.
func (s *StateSession) checkGeneratedGrantCapacity(input []ApplyEntryInput) error {
	if s == nil {
		return contract.ErrRecord
	}
	count := 0
	for _, after := range input {
		if after.ConfidentialityClass != contract.Secret {
			continue
		}
		i, ok := slices.BinarySearchFunc(s.root.Names, after.Name, func(row format.NameEntry, name string) int {
			return strings.Compare(row.Name, name)
		})
		if !ok {
			continue
		}
		before := s.valueEntry(s.root.Names[i].Slot)
		if before == nil || before.Name != after.Name {
			return contract.ErrRecord
		}
		if before.ConfidentialityClass != contract.Secret {
			continue
		}
		preserved := before.ValueSource == after.ValueSource && !generatedFinalExcludesReader(*before, after.Recipients) &&
			(after.Retained != nil && after.Retained.Material == before.ValueState ||
				after.ValueSource == contract.Generated && after.Generated != nil && before.Generated.Epoch == after.Generated.Epoch)
		count += newGeneratedGrants(before, after.Recipients, preserved, s.valueReaders[before.ValueState])
	}
	return s.checkGeneratedGrantCount(count)
}

func (s *StateSession) checkGeneratedGrantCount(count int) error {
	k3 := 0
	if s.root.CurrentAccess.Core.Recovery != nil {
		k3 = contract.MaxSignature
	}
	if count != 0 && !format.GrantHeadFits(count, contract.TokenValueLimit(s.token.Family), contract.MaxSignature, k3, true) {
		return contract.ErrRecordCapacity
	}
	return nil
}

func newGeneratedGrants(before *contract.ValueEntry, intended []contract.ID, preserved bool, retained []contract.ID) int {
	if before == nil || before.ConfidentialityClass != contract.Secret {
		return 0
	}
	count := 0
	for _, id := range intended {
		if slices.Contains(before.Recipients, id) || preserved && slices.Contains(retained, id) {
			continue
		}
		count++
	}
	return count
}

// A declaration can credit an older reader only if its material is already
// fixed before preparation. Equality of fresh sealed input is still unknown.
func generatedDeclarationGrantCount(before *contract.ValueEntry, plan contract.GeneratorValueEntryPlan, entry contract.GeneratorDeclarationEntryView, intended []contract.ID, selected *generatedSelection) (uint64, error) {
	if before == nil || before.ConfidentialityClass != contract.Secret || plan.ConfidentialityClass != contract.Secret {
		return 0, nil
	}
	preserved := false
	if plan.ValueSource == before.ValueSource && !generatedFinalExcludesReader(*before, intended) {
		switch entry.Kind {
		case contract.GeneratorDeclarationRetained:
			retained, err := contract.DecodeRetainedCanonicalRecord(entry.Payload)
			if err != nil {
				return 0, err
			}
			preserved = retained.Entry.ValueState == before.ValueState
		case contract.GeneratorDeclarationGenerated, contract.GeneratorDeclarationGeneratedReference:
			preserved = plan.ChangeMask&contract.GeneratorValueChangeContent == 0
		}
	}
	var retained []contract.ID
	if preserved {
		retained = selected.retainedReaders(before.ValueState)
	}
	return uint64(newGeneratedGrants(before, intended, preserved, retained)), nil
}

// Project the exact slots that become usable for the first time. The caller
// supplies prepared rows, while previous membership and retained access come
// from the selected image, independently of the preparer's seal list.
func (s *selectedImage) generatedGrantRows(image *contract.GeneratedFinalPreparationImage) (map[contract.ID][]contract.ID, []contract.GeneratedGrantSeal, error) {
	grants := make(map[contract.ID][]contract.ID)
	var slots []contract.GeneratedGrantSeal
	previous := make(map[contract.ID]contract.AccessRecord)
	for _, page := range s.access {
		if page != nil {
			for _, row := range page.Records {
				if row.MaterialKind == contract.ValueMaterialKind {
					previous[row.MaterialID] = row
				}
			}
		}
	}
	collect := func(slot uint16, name string, material contract.ID, recipients []contract.ID, wraps int, wrapAt func(int) (contract.WrapRowView, bool)) error {
		before := s.generatedFinalPredecessor(slot, name)
		if before == nil || before.ConfidentialityClass != contract.Secret {
			return nil
		}
		for _, id := range recipients {
			if slices.Contains(before.Recipients, id) {
				continue
			}
			if before.ValueState == material && slices.ContainsFunc(previous[material].Wraps, func(w contract.WrapRow) bool {
				return w.SubjectKind == contract.OrdinaryWrapSubject && w.SubjectID == id
			}) {
				continue
			}
			i := 0
			for ; i < wraps; i++ {
				w, ok := wrapAt(i)
				if !ok {
					return contract.ErrRecord
				}
				if w.SubjectKind == contract.OrdinaryWrapSubject && w.SubjectID == id {
					break
				}
			}
			if i == wraps || len(slots) >= contract.MaxSelectedGrantRows {
				return contract.ErrRecord
			}
			slots = append(slots, contract.GeneratedGrantSeal{Slot: slot, Wrap: uint16(i)})
			grants[material] = append(grants[material], id)
		}
		return nil
	}
	for _, row := range image.Generated {
		if err := collect(row.Slot, row.Entry.Name, row.Access.MaterialID, row.Entry.Recipients, len(row.Access.Wraps), func(i int) (contract.WrapRowView, bool) { return contract.WrapRowView(row.Access.Wraps[i]), true }); err != nil {
			return nil, nil, err
		}
	}
	for _, row := range image.Supplied {
		e, err := contract.InspectValueEntry(row.EntryBytes)
		if err != nil {
			return nil, nil, err
		}
		a, err := contract.InspectAccessRecord(row.AccessRecord)
		if err != nil {
			return nil, nil, err
		}
		var ids []contract.ID
		for i := 0; i < e.RecipientCount(); i++ {
			id, ok := e.RecipientID(i)
			if !ok {
				return nil, nil, contract.ErrRecord
			}
			ids = append(ids, id)
		}
		if err := collect(row.Slot, row.Name, a.MaterialID, ids, a.WrapCount(), a.Wrap); err != nil {
			return nil, nil, err
		}
	}
	slices.SortFunc(slots, contract.CompareGeneratedGrantSeals)
	return grants, slots, nil
}

func (s *selectedImage) checkGeneratedGrantSeals(image *contract.GeneratedFinalPreparationImage) error {
	_, expected, err := s.generatedGrantRows(image)
	if err != nil || !slices.EqualFunc(expected, image.GrantSeals, func(a, b contract.GeneratedGrantSeal) bool { return a.Slot == b.Slot && a.Wrap == b.Wrap }) {
		return contract.ErrRecord
	}
	return nil
}

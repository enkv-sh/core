package core

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestGeneratedGrantCapacityBeforeReservation(t *testing.T) {
	s := &StateSession{valueReaders: map[contract.ID][]contract.ID{}}
	s.pages[0] = &format.ValueEntryPage{}
	s.token.Family = contract.AWS
	var input []ApplyEntryInput
	for slot, added := range []int{63, 63, 3} {
		name := fmt.Sprintf("value%d", slot)
		before := &contract.ValueEntry{Name: name, ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret,
			ValueState: contract.ID{byte(slot + 1)}, Recipients: []contract.ID{{1}}}
		s.pages[0].Slots[slot] = before
		s.root.Names = append(s.root.Names, format.NameEntry{Name: name, Slot: uint16(slot)})
		recipients := []contract.ID{{1}}
		for n := 0; n < added; n++ {
			recipients = append(recipients, contract.ID{byte(n + 2)})
		}
		input = append(input, ApplyEntryInput{Name: name, ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret,
			Recipients: recipients, Retained: &contract.RetainedSecretInput{Material: before.ValueState}})
	}
	// A generated Final with 129 grants and maximum AWS ETag cannot fit.
	// No generator is installed. Capacity must be decided before calling it.
	if _, err := s.installedGeneratedPlan(t.Context(), ApplyInstallation{}, input, nil, time.Now().Add(time.Minute)); !errors.Is(err, contract.ErrRecordCapacity) {
		t.Fatalf("expected capacity refusal before reservation, got %v", err)
	}
	s.token.Family = contract.GCP
	if err := s.checkGeneratedGrantCapacity(input); err != nil {
		t.Fatal("19-byte generation should fit", err)
	}
	s.token.Family = contract.AWS
	s.valueReaders[contract.ID{1}] = []contract.ID{{2}}
	if err := s.checkGeneratedGrantCapacity(input); err != nil {
		t.Fatal("existing access to retained material counted twice", err)
	}
	input[0].Retained = nil
	if !errors.Is(s.checkGeneratedGrantCapacity(input), contract.ErrRecordCapacity) {
		t.Fatal("new material inherited a past grant")
	}
}

// full_only: false
func TestGeneratedGrantPositionsRespectRetainedMaterial(t *testing.T) {
	authority, oldReader, newReader := contract.ID{1}, contract.ID{2}, contract.ID{3}
	material := contract.ID{7}
	image := &selectedImage{}
	image.pages[0] = &format.ValueEntryPage{}
	image.pages[0].Slots[1] = &contract.ValueEntry{Name: "service", ConfidentialityClass: contract.Secret, ValueState: material, Recipients: []contract.ID{authority}}
	wrap := func(id contract.ID) contract.WrapRow {
		return contract.WrapRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: id}
	}
	image.access[0] = &format.AccessPage{Records: []contract.AccessRecord{{MaterialKind: contract.ValueMaterialKind, MaterialID: material, Wraps: []contract.WrapRow{wrap(authority), wrap(oldReader)}}}}
	for _, tc := range []struct {
		name    string
		value   contract.ID
		wanted  []contract.ID
		indices []uint16
	}{
		{"retained", material, []contract.ID{newReader}, []uint16{2}},
		{"rotated", contract.ID{8}, []contract.ID{oldReader, newReader}, []uint16{1, 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := contract.CryptoGeneratedValueEntryResult{Slot: 1, Entry: contract.ValueEntry{Name: "service", Recipients: []contract.ID{authority, oldReader, newReader}},
				Access: contract.AccessRecord{MaterialKind: contract.ValueMaterialKind, MaterialID: tc.value, Wraps: []contract.WrapRow{wrap(authority), wrap(oldReader), wrap(newReader)}}}
			prepared := contract.GeneratedFinalPreparationImage{Generated: []contract.CryptoGeneratedValueEntryResult{row}}
			grants, slots, err := image.generatedGrantRows(&prepared)
			if err != nil || !slices.Equal(grants[tc.value], tc.wanted) || len(slots) != len(tc.indices) {
				t.Fatal("wrong retained grant count", err)
			}
			for i, index := range tc.indices {
				if slots[i].Slot != 1 || slots[i].Wrap != index {
					t.Fatal("wrong checkpoint position", i)
				}
			}
			prepared.GrantSeals = slots
			if err := image.checkGeneratedGrantSeals(&prepared); err != nil {
				t.Fatal(err)
			}
			prepared.GrantSeals = prepared.GrantSeals[1:]
			if err := image.checkGeneratedGrantSeals(&prepared); err == nil {
				t.Fatal("partial directory accepted")
			}
		})
	}
}

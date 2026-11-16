package core

import (
	"slices"
	"testing"

	"enkv.sh/core/format"
)

// full_only: false
func TestAdministrativeSelectedKeysRejectsDuplicateOpaqueSummaries(t *testing.T) {
	s := generatedReservationState(t)
	if !administrativeSelectedKeysUnique(s.adminIndex, s.support) {
		t.Fatal("valid selected keys refused")
	}
	index := s.adminIndex
	index.Pages = slices.Clone(index.Pages)
	first := format.AdministrativeRowSummary{}
	mutated := false
	for i := range index.Pages {
		if index.Pages[i].ReadRequired || len(index.Pages[i].Rows) == 0 {
			continue
		}
		index.Pages[i].Rows = slices.Clone(index.Pages[i].Rows)
		for j := range index.Pages[i].Rows {
			if first.RecordID.IsZero() {
				first = index.Pages[i].Rows[j]
				continue
			}
			index.Pages[i].Rows[j] = first
			mutated = true
			break
		}
		if mutated {
			break
		}
	}
	if !mutated || !index.Valid() {
		t.Fatal("fixture has no second valid opaque summary")
	}
	if administrativeSelectedKeysUnique(index, s.support) {
		t.Fatal("duplicate authenticated selected row identity accepted")
	}
}

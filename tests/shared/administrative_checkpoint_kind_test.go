package core

import (
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestAdministrativeProjectionRetainsKnownPreparationKind(t *testing.T) {
	checkpoint, _ := selectCheckpointOnly(t, newFinalizationCheckpointFixture(t))
	preparationPage, preparationRow := -1, -1
	for i, page := range checkpoint.adminIndex.Pages {
		for j, row := range page.Rows {
			if row.Kind == 18 {
				if preparationPage >= 0 || page.ReadRequired {
					t.Fatal("fixture preparation must be one optional indexed row")
				}
				preparationPage, preparationRow = i, j
			}
		}
	}
	if preparationPage < 0 || !checkpoint.adminIndex.Valid() {
		t.Fatal("fixture lacks valid selected kind18 preparation evidence")
	}
	projected, selected, err := checkpoint.administrativeGeneratedProjection(checkpoint.adminIndex)
	if err != nil || selected != checkpoint.root.RequiredSupportRecordCount || !reflect.DeepEqual(projected, checkpoint.root.Generated) {
		t.Fatal("known preparation row changed administrative projection", selected, err)
	}
	for _, unknown := range []uint8{0, 20, 255} {
		index := checkpoint.adminIndex
		index.Pages = slices.Clone(index.Pages)
		index.Pages[preparationPage].Rows = slices.Clone(index.Pages[preparationPage].Rows)
		index.Pages[preparationPage].Rows[preparationRow].Kind = unknown
		if index.Valid() {
			t.Fatal("unknown support kind passed index grammar", unknown)
		}
		projection, count, err := checkpoint.administrativeGeneratedProjection(index)
		if err == nil || count != 0 || !reflect.DeepEqual(projection, format.GeneratedClosure{}) {
			t.Fatal("unknown support kind escaped administrative refusal", unknown, count, err)
		}
	}
}

// full_only: false
func TestGeneratedAdministrativeRowEnvelopeIncludesReachablePreparation(t *testing.T) {
	shape := generatedCapacityShape{ValueEntryCount: 1, ValueEntryPageCount: 1, Recipients: 1, Secrets: 1, Memberships: 1,
		SecretMemberships: 1, Generated: 1, Creates: 1, ValueEntryPlanCount: 1, DeclarationBytes: 100}
	for _, selecting := range []bool{true, false} {
		v := shape
		if !selecting {
			v.Creates, v.Retirements, v.OldGenerated = 0, 1, 1
		}
		rows, _, _, err := generatedAdministrativeRowEnvelope(v)
		if err != nil || len(rows) != 19 {
			t.Fatal("closed support-kind envelope does not include kind18", selecting, len(rows), err)
		}
		want := uint64(0)
		if selecting {
			want = 1 // One active parent retains one Final preparation descriptor.
		}
		preparationKind := 18
		if rows[preparationKind] != want {
			t.Fatal("wrong selecting versus delete-only preparation row allowance", selecting, rows[preparationKind], want)
		}
		if contract.GeneratedFinalPreparationSupportKind != 18 || contract.GeneratedFinalPreparationRecordLength+contract.SupportRecordOverhead != 355 {
			t.Fatal("preparation kind or physical descriptor framing changed")
		}
	}
}

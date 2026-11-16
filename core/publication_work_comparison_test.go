package core

import (
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestPublicationWorkComparisonPreservesExactRepresentation(t *testing.T) {
	base := format.AdministrativeIndex{Domain: publicationRelationID(1), Object: publicationRelationID(2), SliceSnapshot: publicationRelationID(3),
		Groups: []format.AdministrativeGroup{{GroupID: publicationRelationID(4), OwnerID: publicationRelationID(5), TargetID: publicationRelationID(6),
			Affected:            contract.GeneratorDescriptor{Digest: publicationRelationID(7), Length: 8, Count: 9},
			Dependencies:        contract.GeneratorDescriptor{Digest: publicationRelationID(10), Length: 11, Count: 12},
			Disposable:          contract.GeneratorDescriptor{Digest: publicationRelationID(13), Length: 14, Count: 15},
			RelatedGroupIndexes: []uint16{1, 2}, PublicationIncarnationID: publicationRelationID(16), AdmissionOrdinal: 17}},
		Pages: []format.AdministrativePage{{Ref: format.Ref{Kind: contract.RequiredSupportKind, Domain: publicationRelationID(1), Object: publicationRelationID(18), Digest: publicationRelationID(19), Format: format.Version, Length: 20, Index: 1},
			Rows:  []format.AdministrativeRowSummary{{Kind: contract.PublicationCoordinateSupportKind, RecordID: publicationRelationID(21), BodyLength: 22, MaterialID: publicationRelationID(23)}, {Kind: contract.PublicationMarkerSupportKind, RecordID: publicationRelationID(24), BodyLength: 25}},
			Spans: []format.AdministrativeSpan{{First: 1, Count: 2, Mandatory: true, GroupIndexes: []uint16{1, 2}}, {First: 3, Count: 1}}}},
		PublicationOrder: []format.PublicationCoordinateOrder{{CoordinateID: publicationRelationID(26), Incarnations: []contract.ID{publicationRelationID(27), publicationRelationID(28)}}, {CoordinateID: publicationRelationID(29), Incarnations: []contract.ID{publicationRelationID(30)}}}}
	secondGroup, secondPage := base.Groups[0], base.Pages[0]
	secondGroup.GroupID, secondPage.Ref.Object = publicationRelationID(31), publicationRelationID(32)
	base.Groups, base.Pages = append(base.Groups, secondGroup), append(base.Pages, secondPage)
	check := func(t *testing.T, a, b format.AdministrativeIndex, want bool) {
		t.Helper()
		if samePublicationWork(a, b) != want || samePublicationWork(b, a) != want {
			t.Fatal("complete work comparison changed exact equality", want)
		}
	}
	t.Run("equal_detached", func(t *testing.T) { check(t, base, clonePublicationWork(base), true) })
	t.Run("equal_zero", func(t *testing.T) { check(t, format.AdministrativeIndex{}, format.AdministrativeIndex{}, true) })
	t.Run("capacity_ignored", func(t *testing.T) {
		a, b := base, base
		a.Groups, b.Groups = base.Groups[:1:1], base.Groups[:1:2]
		check(t, a, b, true)
	})
	for _, test := range []struct {
		name   string
		change func(*format.AdministrativeIndex)
	}{
		{"domain", func(v *format.AdministrativeIndex) { v.Domain[0]++ }},
		{"object", func(v *format.AdministrativeIndex) { v.Object[0]++ }},
		{"slice_snapshot", func(v *format.AdministrativeIndex) { v.SliceSnapshot[0]++ }},
		{"group_GroupID", func(v *format.AdministrativeIndex) { v.Groups[0].GroupID[0]++ }},
		{"group_OwnerID", func(v *format.AdministrativeIndex) { v.Groups[0].OwnerID[0]++ }},
		{"group_TargetID", func(v *format.AdministrativeIndex) { v.Groups[0].TargetID[0]++ }},
		{"group_PublicationIncarnationID", func(v *format.AdministrativeIndex) { v.Groups[0].PublicationIncarnationID[0]++ }},
		{"group_OwnerKind", func(v *format.AdministrativeIndex) { v.Groups[0].OwnerKind++ }},
		{"group_DutyKind", func(v *format.AdministrativeIndex) { v.Groups[0].DutyKind++ }},
		{"group_EffectEntryCeiling", func(v *format.AdministrativeIndex) { v.Groups[0].EffectEntryCeiling++ }},
		{"group_SelectedEvidenceSummary", func(v *format.AdministrativeIndex) { v.Groups[0].SelectedEvidenceSummary++ }},
		{"group_DestructiveEffect", func(v *format.AdministrativeIndex) { v.Groups[0].DestructiveEffect++ }},
		{"group_UncertainCreateProof", func(v *format.AdministrativeIndex) { v.Groups[0].UncertainCreateProof++ }},
		{"group_ChargedPages", func(v *format.AdministrativeIndex) { v.Groups[0].ChargedPages++ }},
		{"group_ChargedBytes", func(v *format.AdministrativeIndex) { v.Groups[0].ChargedBytes++ }},
		{"group_AdmissionOrdinal", func(v *format.AdministrativeIndex) { v.Groups[0].AdmissionOrdinal++ }},
		{"group_Affected_Digest", func(v *format.AdministrativeIndex) { v.Groups[0].Affected.Digest[0]++ }},
		{"group_Dependencies_Digest", func(v *format.AdministrativeIndex) { v.Groups[0].Dependencies.Digest[0]++ }},
		{"group_Disposable_Digest", func(v *format.AdministrativeIndex) { v.Groups[0].Disposable.Digest[0]++ }},
		{"page_ref_Object", func(v *format.AdministrativeIndex) { v.Pages[0].Ref.Object[0]++ }},
		{"page_ref_Index", func(v *format.AdministrativeIndex) { v.Pages[0].Ref.Index++ }},
		{"page_read_required", func(v *format.AdministrativeIndex) { v.Pages[0].ReadRequired = !v.Pages[0].ReadRequired }},
		{"span_mandatory", func(v *format.AdministrativeIndex) { v.Pages[0].Spans[0].Mandatory = !v.Pages[0].Spans[0].Mandatory }},
		{"row_BodyLength", func(v *format.AdministrativeIndex) { v.Pages[0].Rows[0].BodyLength++ }},
		{"row_MaterialID", func(v *format.AdministrativeIndex) { v.Pages[0].Rows[0].MaterialID[0]++ }},
		{"order_coordinate", func(v *format.AdministrativeIndex) { v.PublicationOrder[0].CoordinateID[0]++ }},
		{"incarnation_value", func(v *format.AdministrativeIndex) { v.PublicationOrder[0].Incarnations[0][0]++ }},
		{"Groups_length", func(v *format.AdministrativeIndex) { v.Groups = v.Groups[:1] }},
		{"Groups_order", func(v *format.AdministrativeIndex) { v.Groups[0], v.Groups[1] = v.Groups[1], v.Groups[0] }},
		{"Pages_length", func(v *format.AdministrativeIndex) { v.Pages = v.Pages[:1] }},
		{"Pages_order", func(v *format.AdministrativeIndex) { v.Pages[0], v.Pages[1] = v.Pages[1], v.Pages[0] }},
		{"PublicationOrder_length", func(v *format.AdministrativeIndex) { v.PublicationOrder = v.PublicationOrder[:1] }},
		{"PublicationOrder_order", func(v *format.AdministrativeIndex) {
			v.PublicationOrder[0], v.PublicationOrder[1] = v.PublicationOrder[1], v.PublicationOrder[0]
		}},
		{"Groups[0].RelatedGroupIndexes_length", func(v *format.AdministrativeIndex) {
			v.Groups[0].RelatedGroupIndexes = v.Groups[0].RelatedGroupIndexes[:1]
		}},
		{"Groups[0].RelatedGroupIndexes_order", func(v *format.AdministrativeIndex) {
			v.Groups[0].RelatedGroupIndexes[0], v.Groups[0].RelatedGroupIndexes[1] = v.Groups[0].RelatedGroupIndexes[1], v.Groups[0].RelatedGroupIndexes[0]
		}},
		{"Pages[0].Rows_length", func(v *format.AdministrativeIndex) { v.Pages[0].Rows = v.Pages[0].Rows[:1] }},
		{"Pages[0].Rows_order", func(v *format.AdministrativeIndex) {
			v.Pages[0].Rows[0], v.Pages[0].Rows[1] = v.Pages[0].Rows[1], v.Pages[0].Rows[0]
		}},
		{"Pages[0].Spans_length", func(v *format.AdministrativeIndex) { v.Pages[0].Spans = v.Pages[0].Spans[:1] }},
		{"Pages[0].Spans_order", func(v *format.AdministrativeIndex) {
			v.Pages[0].Spans[0], v.Pages[0].Spans[1] = v.Pages[0].Spans[1], v.Pages[0].Spans[0]
		}},
		{"Pages[0].Spans[0].GroupIndexes_length", func(v *format.AdministrativeIndex) {
			v.Pages[0].Spans[0].GroupIndexes = v.Pages[0].Spans[0].GroupIndexes[:1]
		}},
		{"Pages[0].Spans[0].GroupIndexes_order", func(v *format.AdministrativeIndex) {
			v.Pages[0].Spans[0].GroupIndexes[0], v.Pages[0].Spans[0].GroupIndexes[1] = v.Pages[0].Spans[0].GroupIndexes[1], v.Pages[0].Spans[0].GroupIndexes[0]
		}},
		{"PublicationOrder[0].Incarnations_length", func(v *format.AdministrativeIndex) {
			v.PublicationOrder[0].Incarnations = v.PublicationOrder[0].Incarnations[:1]
		}},
		{"PublicationOrder[0].Incarnations_order", func(v *format.AdministrativeIndex) {
			v.PublicationOrder[0].Incarnations[0], v.PublicationOrder[0].Incarnations[1] = v.PublicationOrder[0].Incarnations[1], v.PublicationOrder[0].Incarnations[0]
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, b := clonePublicationWork(base), clonePublicationWork(base)
			test.change(&b)
			check(t, a, b, false)
		})
	}
	for _, test := range []struct {
		name   string
		change func(*format.AdministrativeIndex, *format.AdministrativeIndex)
	}{
		{"Groups_nil_empty", func(a, b *format.AdministrativeIndex) { a.Groups = nil; b.Groups = []format.AdministrativeGroup{} }},
		{"Pages_nil_empty", func(a, b *format.AdministrativeIndex) { a.Pages = nil; b.Pages = []format.AdministrativePage{} }},
		{"PublicationOrder_nil_empty", func(a, b *format.AdministrativeIndex) {
			a.PublicationOrder = nil
			b.PublicationOrder = []format.PublicationCoordinateOrder{}
		}},
		{"Groups[0].RelatedGroupIndexes_nil_empty", func(a, b *format.AdministrativeIndex) {
			a.Groups[0].RelatedGroupIndexes = nil
			b.Groups[0].RelatedGroupIndexes = []uint16{}
		}},
		{"Pages[0].Rows_nil_empty", func(a, b *format.AdministrativeIndex) {
			a.Pages[0].Rows = nil
			b.Pages[0].Rows = []format.AdministrativeRowSummary{}
		}},
		{"Pages[0].Spans_nil_empty", func(a, b *format.AdministrativeIndex) {
			a.Pages[0].Spans = nil
			b.Pages[0].Spans = []format.AdministrativeSpan{}
		}},
		{"Pages[0].Spans[0].GroupIndexes_nil_empty", func(a, b *format.AdministrativeIndex) {
			a.Pages[0].Spans[0].GroupIndexes = nil
			b.Pages[0].Spans[0].GroupIndexes = []uint16{}
		}},
		{"PublicationOrder[0].Incarnations_nil_empty", func(a, b *format.AdministrativeIndex) {
			a.PublicationOrder[0].Incarnations = nil
			b.PublicationOrder[0].Incarnations = []contract.ID{}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, b := clonePublicationWork(base), clonePublicationWork(base)
			test.change(&a, &b)
			check(t, a, b, false)
			check(t, a, clonePublicationWork(a), true)
			check(t, b, clonePublicationWork(b), true)
		})
	}
}

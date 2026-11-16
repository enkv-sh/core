package core

import (
	"bytes"
	"slices"
	"strconv"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestGCPlanPackingAndNormalCapacityKeepWholeRows(t *testing.T) {
	s, _, _ := observationSelectedPredecessor(t)
	plan := gcTestPlan(t, s, "packing")
	body, err := contract.EncodeGCPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	gcRow := contract.SupportRecord{Kind: contract.GCPlanSupportKind, RecordID: plan.OperationID, Body: body}
	blob := gcTestID("true-auxiliary-fragment")
	fragment := generatedMaterializerFragment(t, blob, []byte("immutable selected fragment"))
	fact, err := contract.InspectSupportRecordDigest(s.root.Domain, fragment)
	if err != nil {
		t.Fatal(err)
	}
	for _, cold := range []bool{false, true} {
		t.Run("fragment-cold="+strconv.FormatBool(cold), func(t *testing.T) {
			row := fragment
			var facts map[contract.ID]selectedFragmentFact
			if cold {
				row.Body = nil
				facts = map[contract.ID]selectedFragmentFact{row.RecordID: {blob: blob, row: fact}}
			}
			groups := []format.RequiredSupportGroup{{Class: format.GCPlanSupport, Owner: gcRow.RecordID, Records: []contract.SupportRecord{gcRow}}, {Class: format.AuxiliaryFragmentSupport, Owner: blob, Records: []contract.SupportRecord{row}}}
			pages, err := generatedSupportPages(s.root.Domain, groups, 2, facts)
			if err != nil || len(pages) != 2 {
				t.Fatal("whole GC row entered the fragment stream", err)
			}
			// The closed class order places complete GC rows before fragments.
			// These expected typed rows do not use another packing helper.
			expected := [][]contract.SupportRecord{{gcRow}, {row}}
			for i := range expected {
				if !slices.EqualFunc(pages[i], expected[i], func(a, b contract.SupportRecord) bool {
					return a.Kind == b.Kind && a.RecordID == b.RecordID && bytes.Equal(a.Body, b.Body) && (a.Body == nil) == (b.Body == nil)
				}) {
					t.Fatal("closed GC/fragment page order or bytes changed", i)
				}
			}
			if !cold {
				canonical, err := format.PackRequiredSupportRows(s.root.Domain, groups, 2)
				if err != nil || len(canonical) != len(pages) {
					t.Fatal("canonical mixed packing", err)
				}
				for i := range pages {
					if !slices.EqualFunc(pages[i], canonical[i], func(a, b contract.SupportRecord) bool {
						return a.Kind == b.Kind && a.RecordID == b.RecordID && bytes.Equal(a.Body, b.Body)
					}) {
						t.Fatal("stream page order differs from canonical whole-row packing", i)
					}
				}
			}
			seenGC, seenFragment := false, false
			for _, page := range pages {
				if len(page) != 1 {
					t.Fatal("GC and fragment classes shared a physical page")
				}
				switch page[0].Kind {
				case contract.GCPlanSupportKind:
					seenGC = page[0].RecordID == plan.OperationID && bytes.Equal(page[0].Body, body)
				case contract.GeneratedFragmentSupportKind:
					seenFragment = page[0].RecordID == fragment.RecordID && (cold && page[0].Body == nil || !cold && bytes.Equal(page[0].Body, fragment.Body))
				}
			}
			if !seenGC || !seenFragment {
				t.Fatal("packing changed typed row bytes or opaque fragment ownership")
			}
		})
	}
	t.Run("closed classes", func(t *testing.T) {
		for _, group := range []format.RequiredSupportGroup{
			{Class: format.AuxiliaryFragmentSupport, Owner: gcRow.RecordID, Records: []contract.SupportRecord{gcRow}},
			{Class: format.GCPlanSupport, Owner: blob, Records: []contract.SupportRecord{fragment}},
			{Class: format.OutputConfigurationSupport + 1, Owner: gcRow.RecordID, Records: []contract.SupportRecord{gcRow}},
		} {
			if _, err := generatedSupportPages(s.root.Domain, []format.RequiredSupportGroup{group}, 2, nil); err == nil {
				t.Fatal("unrecognized or cross-kind class acquired fragment rules", group.Class)
			}
		}
	})
	t.Run("exact normal charge", func(t *testing.T) {
		comparison, result := s.compareEntryInputs([]ApplyEntryInput{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "plain", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{s.admission.recipient}, InputBytes: []byte("changed")}})
		if comparison == nil || result.Outcome != ObservedCurrent {
			t.Fatal("normal capacity intent", result)
		}
		witness, err := s.generatedSupportTransition(t.Context(), comparison, nil)
		if err != nil || witness == nil {
			t.Fatal("normal capacity predecessor", err)
		}
		generated, err := s.selectedGeneratedWork(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		withRows := *witness
		withRows.Records = append(slices.Clone(witness.Records), gcRow, fragment)
		slices.SortFunc(withRows.Records, func(a, b contract.SupportRecord) int {
			if a.Kind != b.Kind {
				return int(a.Kind) - int(b.Kind)
			}
			return bytes.Compare(a.RecordID[:], b.RecordID[:])
		})
		withRows.RecordFacts = slices.Clone(witness.RecordFacts)
		for _, row := range []contract.SupportRecord{gcRow, fragment} {
			fact, err := contract.InspectSupportRecordDigest(s.root.Domain, row)
			if err != nil {
				t.Fatal(err)
			}
			withRows.RecordFacts = append(withRows.RecordFacts, fact)
		}
		slices.SortFunc(withRows.RecordFacts, func(a, b contract.SupportRecordDigest) int {
			if a.Kind() != b.Kind() {
				return int(a.Kind()) - int(b.Kind())
			}
			left, right := a.RecordID(), b.RecordID()
			return bytes.Compare(left[:], right[:])
		})
		withRows.BeforeSupport, err = contract.RequiredSupportDescriptorFromDigests(s.root.Domain, withRows.RecordFacts)
		if err != nil {
			t.Fatal(err)
		}
		if err := withRows.IntentError(comparison.intent); err != nil {
			t.Fatal("normal capacity fixture witness", err)
		}
		groups, err := s.generatedNormalGroups(t.Context(), comparison, generated, &withRows)
		if err != nil {
			t.Fatal("normal capacity rejected typed GC row beside fragment", err)
		}
		before, after := witness.Groups[contract.GeneratorCapacityAuxiliary], groups[contract.GeneratorCapacityAuxiliary]
		framed := uint64(2*contract.SupportRecordOverhead + len(body) + len(fragment.Body))
		if after.MaxCount != before.MaxCount+2 || after.MaxFramedBytes != before.MaxFramedBytes+framed || after.MaxPages != before.MaxPages+2 {
			t.Fatal("GC acquired fragment counting or full-page width charge", before, after, framed)
		}
	})
}

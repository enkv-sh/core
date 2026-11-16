package core

import (
	"encoding/binary"
	"runtime"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestAdministrativeInspectionBoundsRelatedGroupAllocation(t *testing.T) {
	const groupCount = 512
	s := administrativeHistoryFixture(t)
	// The authenticated-state projection keeps optional duty summaries without
	// opening their bodies; this fixture tests that projection and ownership.
	seed := s.adminIndex.Groups[2]
	s.adminIndex.Groups = make([]format.AdministrativeGroup, groupCount)
	s.root.Generated.ActiveOwner = contract.ID{}
	page := &s.adminIndex.Pages[2]
	page.Ref.Length = 75 + groupCount*(37+contract.GeneratedDutyRecordBodyLength)
	page.Spans, page.Rows = nil, nil
	for i := range s.adminIndex.Groups {
		group := seed
		group.GroupID = contract.ID{1}
		binary.BigEndian.PutUint16(group.GroupID[30:], uint16(i+1))
		group.OwnerID = group.GroupID
		group.RelatedGroupIndexes = make([]uint16, i)
		for j := range group.RelatedGroupIndexes {
			group.RelatedGroupIndexes[j] = uint16(j)
		}
		summary := format.AdministrativeRowSummary{Kind: contract.GeneratedDutySupportKind, RecordID: group.GroupID, BodyLength: contract.GeneratedDutyRecordBodyLength}
		group.Disposable = administrativeDescriptor("selected-disposable", administrativeSummaryBytes(summary))
		group.ChargedPages, group.ChargedBytes = 1, 37+contract.GeneratedDutyRecordBodyLength
		page.Rows = append(page.Rows, summary)
		page.Spans = append(page.Spans, format.AdministrativeSpan{First: uint16(i), Count: 1, GroupIndexes: []uint16{uint16(i)}})
		s.adminIndex.Groups[i] = group
	}
	if !s.adminIndex.Valid() {
		t.Fatal("dense acyclic administrative index is invalid")
	}
	s.root.RequiredSupport[2] = page.Ref
	projected, selected, err := s.administrativeGeneratedProjection(s.adminIndex)
	if err != nil || projected.Duties != groupCount || selected != groupCount+5 {
		t.Fatal("dense administrative ownership projection failed", selected, err)
	}
	s.root.Generated, s.root.RequiredSupportRecordCount = projected, selected
	session := &AuthoritySession{state: s, mode: LocalAuthorityInspect}
	if warm, result := session.Inspect(t.Context()); result.Outcome != ObservedCurrent || len(warm.Groups) != groupCount {
		t.Fatal("administrative inspection warm-up failed", result)
	}

	// 130,816 edges need 261,632 compact bytes; expanded IDs alone need
	// 4,186,112. This separates the representations without a maximum fixture.
	var results [4]AuthorityInspection
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := range results {
		view, result := session.Inspect(t.Context())
		if result.Outcome != ObservedCurrent {
			t.Fatal("dense administrative inspection failed", result)
		}
		results[i] = view
	}
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(results)
	allocated := (after.TotalAlloc - before.TotalAlloc) / uint64(len(results))
	t.Logf("administrative inspection allocation: groups=%d edges=%d bytes_per_result=%d limit=%d", groupCount, groupCount*(groupCount-1)/2, allocated, 2<<20)
	for _, view := range results {
		if len(view.Groups) != groupCount || len(view.Abandonments) != 3 {
			t.Fatal("inspection omitted groups or retained abandonments")
		}
		for i, row := range view.Groups {
			if row.GroupID != s.adminIndex.Groups[i].GroupID || len(row.RelatedGroupIndexes) != i {
				t.Fatal("inspection changed complete group or relation count", i)
			}
			for j, related := range row.RelatedGroupIndexes {
				if related != uint16(j) || view.Groups[related].GroupID != s.adminIndex.Groups[j].GroupID {
					t.Fatal("inspection changed a related group or its order", i, j)
				}
			}
		}
	}
	results[0].Groups[groupCount-1].RelatedGroupIndexes[0] = 1
	results[0].Groups[0].GroupID[0] ^= 1
	if results[1].Groups[groupCount-1].RelatedGroupIndexes[0] != 0 || results[1].Groups[0].GroupID != s.adminIndex.Groups[0].GroupID || s.adminIndex.Groups[groupCount-1].RelatedGroupIndexes[0] != 0 {
		t.Fatal("inspection relations borrow another result or authenticated state")
	}
	if allocated > 2<<20 {
		t.Fatalf("administrative inspection expands relation storage: %d bytes per result exceeds %d", allocated, 2<<20)
	}
}

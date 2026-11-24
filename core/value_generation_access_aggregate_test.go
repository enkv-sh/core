package core

import (
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestGeneratedRetainedReaderUnionDoesNotRequireAnotherMaterial(t *testing.T) {
	root := format.Root{ValueEntryCount: 1, SecretCount: 1, MembershipCount: 1, SecretOrdinaryWrapCount: 1,
		AccessRecordCount: 1, Names: []format.NameEntry{{Name: "value"}}}
	root.ValueEntryPages[0] = &format.Ref{Length: uint32(75 + contract.ValueEntryFixedLength + len("value") + 32 + 215)}
	root.CurrentAccess.Core.AccessPageRefs = []contract.Ref{{Length: 75 + 102 + 489}}
	if !validAggregate(root) {
		t.Fatal("current-only material refused")
	}
	root.CurrentAccess.Core.AccessPageRefs[0].Length += 489
	if validAggregate(root) {
		t.Fatal("unowned extra wrap accepted")
	}
	for _, hazard := range []bool{false, true} {
		root.Generated.Duties, root.Generated.Hazards = 1, 0
		if hazard {
			root.Generated.Duties, root.Generated.Hazards = 0, 1
		}
		if !validAggregate(root) {
			t.Fatal("retained original readers need wraps, not a duplicate material")
		}
		root.CurrentAccess.Core.AccessPageRefs[0].Length = 75 + 102 + 488
		if validAggregate(root) {
			t.Fatal("live owner weakened current access lower bound")
		}
		root.CurrentAccess.Core.AccessPageRefs[0].Length = contract.MaxAccessPageLength + 1
		if validAggregate(root) {
			t.Fatal("live owner weakened access page limit")
		}
		root.CurrentAccess.Core.AccessPageRefs[0].Length = 75 + 102 + 2*489
	}
	root.AccessRecordCount = 0
	if validAggregate(root) {
		t.Fatal("current secret without material accepted")
	}
}

// full_only: false
func TestGeneratedAggregateIncludesEveryClosedMetadataWidth(t *testing.T) {
	root := format.Root{ValueEntryCount: 1, SecretCount: 1, MembershipCount: 1, SecretOrdinaryWrapCount: 1, AccessRecordCount: 1, Names: []format.NameEntry{{Name: "value"}}}
	root.Generated.GeneratedCurrent = 1
	root.CurrentAccess.Core.AccessPageRefs = []contract.Ref{{Length: 75 + 102 + 489}}
	base := uint32(contract.ValueEntryPageFixedLength + contract.ValueEntryFixedLength + len("value") + 32 + contract.CanonicalPayloadOverhead)
	for _, width := range []uint32{390, 422, 460} {
		t.Run(map[uint32]string{390: "generic", 422: "generic with older duty", 460: "coarse upper bound"}[width], func(t *testing.T) {
			root.ValueEntryPages[0] = &format.Ref{Length: base + width}
			if !validAggregate(root) {
				t.Fatal("closed generated metadata width refused", width)
			}
		})
	}
	for _, width := range []uint32{389, 461} {
		root.ValueEntryPages[0] = &format.Ref{Length: base + width}
		if validAggregate(root) {
			t.Fatal("generated metadata outside closed bounds admitted", width)
		}
	}
	root.Generated.GeneratedCurrent = 0
	root.ValueEntryPages[0] = &format.Ref{Length: base}
	if !validAggregate(root) {
		t.Fatal("supplied aggregate exact size changed")
	}
	root.ValueEntryPages[0].Length--
	if validAggregate(root) {
		t.Fatal("non-generated entry accepted a short aggregate")
	}
	root.ValueEntryPages[0].Length = base + 1
	if validAggregate(root) {
		t.Fatal("non-generated entry acquired metadata allowance")
	}
	root.ValueEntryCount, root.SecretCount, root.MembershipCount, root.SecretOrdinaryWrapCount, root.AccessRecordCount = 3, 3, 3, 3, 3
	root.Generated.GeneratedCurrent = 3
	root.Names = []format.NameEntry{{Name: "a"}, {Name: "b"}, {Name: "c"}}
	root.CurrentAccess.Core.AccessPageRefs = []contract.Ref{{Length: 75 + 3*(102+489)}}
	mixedBase := uint32(contract.ValueEntryPageFixedLength + 3*(contract.ValueEntryFixedLength+32+contract.CanonicalPayloadOverhead) + 3)
	for _, width := range []uint32{390 + 390 + 422, 390 + 422 + 460} {
		root.ValueEntryPages[0] = &format.Ref{Length: mixedBase + width}
		if !validAggregate(root) {
			t.Fatal("mixed closed metadata aggregate refused", width)
		}
	}
	for _, width := range []uint32{3*390 - 1, 3*460 + 1} {
		root.ValueEntryPages[0] = &format.Ref{Length: mixedBase + width}
		if validAggregate(root) {
			t.Fatal("mixed metadata outside bounds admitted", width)
		}
	}
}

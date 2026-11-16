package core

import (
	"encoding/hex"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestUnionCommitmentGolden(t *testing.T) {
	id := func(n byte) contract.ID {
		var value contract.ID
		for i := range value {
			value[i] = n
		}
		return value
	}
	// Fixed public projection inputs do not depend on genesis entropy. No ready
	// domain is fabricated: these sessions only supply rows to the projection.
	before := &StateSession{admission: openAdmission{domain: id(1)}}
	after := &StateSession{admission: before.admission}
	for _, row := range []struct {
		name                            string
		slot                            uint16
		incarnation, oldValue, newValue byte
	}{{"a", 0, 3, 4, 5}, {"é/β", 17, 6, 7, 8}} {
		old := &format.ValueEntry{Name: row.name, Incarnation: id(row.incarnation), ValueState: id(row.oldValue), OriginSnapshot: id(9), OriginTransition: id(10), Recipients: []contract.ID{id(2)}, ValueSource: 1, ConfidentialityClass: 1, ValueBytes: []byte("old"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len([]byte("old"))), RetainedLength: uint32(len([]byte("old")))}
		next := *old
		next.ValueState, next.OriginSnapshot, next.OriginTransition, next.ValueBytes = id(row.newValue), id(11), id(12), []byte("new")
		entry := format.NameEntry{Name: row.name, Slot: row.slot}
		before.root.Names = append(before.root.Names, entry)
		after.root.Names = append(after.root.Names, entry)
		before.pages[row.slot/format.PageSlots] = &format.ValueEntryPage{}
		after.pages[row.slot/format.PageSlots] = &format.ValueEntryPage{}
		before.pages[row.slot/format.PageSlots].Slots[row.slot%format.PageSlots] = old
		after.pages[row.slot/format.PageSlots].Slots[row.slot%format.PageSlots] = &next
	}
	union, grants, exclusions, changed := before.lifecycleVectors(after)
	// Independently packed v6 vector: 70-byte header, two (6+name)-byte
	// row headers, and four 100-byte sides. Each side contains a v6 public
	// member digest, itself derived from the fixed ValueEntry fields above.
	if union.Length != 488 || union.Count != 2 || changed != 2 || len(grants) != 0 || len(exclusions) != 0 || hex.EncodeToString(union.Digest[:]) != "dae130c91cfbec6f24825542b3740cb61f206fba2a6bc34272313d72f4280ccc" {
		t.Fatalf("union commitment changed: %+v changed=%d", union, changed)
	}
}

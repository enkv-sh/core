package format

import (
	"encoding/binary"
	"errors"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestValueEntryPageRejectsRawDuplicateFields(t *testing.T) {
	first := *valueEntryPageFixture().Slots[0]
	second := first
	second.Name, second.Incarnation, second.ValueState = "other", fid(33), fid(44)
	for _, row := range []struct {
		name   string
		change func(*ValueEntry)
	}{
		{"valid", func(*ValueEntry) {}},
		{"name", func(v *ValueEntry) { v.Name = first.Name }},
		{"incarnation", func(v *ValueEntry) { v.Incarnation = first.Incarnation }},
		{"value-state", func(v *ValueEntry) { v.ValueState = first.ValueState }},
	} {
		t.Run(row.name, func(t *testing.T) {
			other := second
			row.change(&other)
			// Only the valid child records use their codec. The page frame is
			// ENKV, value-page kind 1, schema 11, two IDs, index 3, mask 3.
			body := []byte{'E', 'N', 'K', 'V', 1, 0, 11}
			domain, object := fid(1), fid(2)
			body = append(body, domain[:]...)
			body = append(body, object[:]...)
			body = binary.BigEndian.AppendUint16(body, 3)
			body = binary.BigEndian.AppendUint16(body, 3)
			for _, entry := range []ValueEntry{first, other} {
				encoded, err := contract.EncodeValueEntry(entry)
				if err != nil {
					t.Fatal("invalid child fixture", err)
				}
				body = append(body, encoded...)
			}
			page, err := DecodeValueEntryPage(body)
			if row.name != "valid" {
				if !errors.Is(err, ErrFormat) {
					t.Fatal("raw duplicate page was not refused by its owner", err)
				}
				return
			}
			if err != nil || page.Domain != domain || page.Object != object || page.Index != 3 || page.Slots[0] == nil || page.Slots[1] == nil ||
				page.Slots[0].Name != first.Name || page.Slots[1].Name != second.Name || page.Slots[1].Incarnation != second.Incarnation || page.Slots[1].ValueState != second.ValueState {
				t.Fatal("valid raw page lost its complete entries", err)
			}
			for _, entry := range page.Slots[2:] {
				if entry != nil {
					t.Fatal("raw page invented an unoccupied slot")
				}
			}
		})
	}
}

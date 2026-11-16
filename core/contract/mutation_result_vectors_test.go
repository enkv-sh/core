package contract

import (
	"fmt"
	"testing"
)

// full_only: false
func TestMutationResultRecordDescriptorsPreserveExactOrderAndType(t *testing.T) {
	domain := generatedRecordID(1)
	first := generatedRecordAttempt()
	first.State, first.Stage = GeneratedEffectSucceeded, GeneratedStageTerminal
	second := first
	second.AttemptID, second.LineageID, second.TransmissionID, second.ResultID, second.InboxID =
		generatedRecordID(31), generatedRecordID(32), generatedRecordID(33), generatedRecordID(34), generatedRecordID(35)
	firstBody, err := EncodeGeneratedAttemptRecord(first)
	if err != nil {
		t.Fatal(err)
	}
	secondBody, err := EncodeGeneratedAttemptRecord(second)
	if err != nil {
		t.Fatal(err)
	}
	rows := []SupportRecord{{Kind: 9, RecordID: first.AttemptID, Body: firstBody}, {Kind: 9, RecordID: second.AttemptID, Body: secondBody}}
	got, err := MutationResultRecordDescriptor(MutationResultEffects, domain, rows)
	// Independent Node Buffer construction used the documented Attempt and
	// SupportRecord fields plus the effect-results domain label for this hash.
	if err != nil || got.Count != 2 || got.Length != 1606 ||
		fmt.Sprintf("%x", got.Digest) != "8099e61d393999cfbb6bcb888f740525e73dd007f5b38df30c18c1e819d28408" {
		t.Fatal("effect descriptor differs from the independent vector", got, err)
	}
	reversed, err := MutationResultRecordDescriptor(MutationResultEffects, domain, []SupportRecord{rows[1], rows[0]})
	if err != nil || reversed == got {
		t.Fatal("ordered effect vector was sorted or collapsed", err)
	}
	for _, tc := range []struct {
		name    string
		kind    MutationResultRecordKind
		support uint8
		length  uint64
		digest  string
		body    func(ID) ([]byte, error)
	}{
		{"duties", MutationResultDuties, GeneratedDutySupportKind, 1396, "90cfad64031f4ffa9d32be87074a806db47056b9e4a54e6c5b1b91a410e1b321", func(id ID) ([]byte, error) {
			row := generatedRecordDuty()
			row.DutyID = id
			return EncodeGeneratedDutyRecord(row)
		}},
		{"hazards", MutationResultHazards, GeneratedHazardSupportKind, 1394, "8c367ed3dd93ef615d522250d320de8b38ee56b11381c804d36d3466de7db92b", func(id ID) ([]byte, error) {
			row := generatedRecordHazard()
			row.HazardID = id
			return EncodeGeneratedHazardRecord(row)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rows []SupportRecord
			for _, id := range []ID{generatedRecordID(2), generatedRecordID(31)} {
				body, err := tc.body(id)
				if err != nil {
					t.Fatal(err)
				}
				rows = append(rows, SupportRecord{Kind: tc.support, RecordID: id, Body: body})
			}
			// Independent Python struct packing: schema u16, IDs1..12 repeated32
			// (second row ID2 becomes ID31), Duty tags 0201010103 or Hazard
			// tags 01010101, descriptors13..18 = ID32+u64(4)+u32(0).
			// The family prefix, u32 length/count and each exact typed row are hashed.
			got, err := MutationResultRecordDescriptor(tc.kind, domain, rows)
			if err != nil || got.Count != 2 || got.Length != tc.length || fmt.Sprintf("%x", got.Digest) != tc.digest {
				t.Fatal("related descriptor differs from independent framing", got, err)
			}
			reversed, err := MutationResultRecordDescriptor(tc.kind, domain, []SupportRecord{rows[1], rows[0]})
			if err != nil || reversed == got {
				t.Fatal("related descriptor discarded Product order", err)
			}
			rows[0].Body = append(rows[0].Body, 0)
			if _, err := MutationResultRecordDescriptor(tc.kind, domain, rows); err == nil {
				t.Fatal("changed related body accepted")
			}
		})
	}
	empty := EmptyMutationResultDescriptors()
	for _, tc := range []struct {
		kind MutationResultRecordKind
		want GeneratorDescriptor
	}{{MutationResultEffects, empty[1]}, {MutationResultDuties, empty[3]}, {MutationResultHazards, empty[4]}} {
		actual, err := MutationResultRecordDescriptor(tc.kind, domain, nil)
		if err != nil || actual != tc.want {
			t.Fatal("empty result family differs", tc.kind, actual, err)
		}
	}
	for name, bad := range map[string]func([]SupportRecord) []SupportRecord{
		"wrong kind":     func(v []SupportRecord) []SupportRecord { v[0].Kind = 10; return v },
		"wrong identity": func(v []SupportRecord) []SupportRecord { v[0].RecordID[0] ^= 1; return v },
		"duplicate":      func(v []SupportRecord) []SupportRecord { return append(v, v[0]) },
		"changed body":   func(v []SupportRecord) []SupportRecord { v[0].Body = append(v[0].Body, 0); return v },
	} {
		t.Run(name, func(t *testing.T) {
			copy := append([]SupportRecord(nil), rows...)
			if _, err := MutationResultRecordDescriptor(MutationResultEffects, domain, bad(copy)); err == nil {
				t.Fatal("invalid result row accepted")
			}
		})
	}
}

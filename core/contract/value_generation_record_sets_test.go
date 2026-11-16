package contract

import (
	"bytes"
	"fmt"
	"testing"
)

// full_only: false
func TestGeneratorRecordSetsIndependentDescriptors(t *testing.T) {
	// Node SHA-256 over ENKV/GENERATOR/v1/<label> NUL, uint32be(4),
	// uint32be(0). No production encoder supplied these expected digests.
	for i, want := range []string{
		"34732f80776ab6c7021fca04ef4cab10239cd5d263c497faaa9ca24092c81e45",
		"4c05f106df77129217610c4346ce7eb37303531a96473b2a522d5223d6caf5bb",
		"1c168a0a84829e85965d19dfa031d5ec6d0659b60c04858b1abfe6f5f14787e6",
		"a7b3bb7cf556cc1369fa3e3d8bc63a4fda9b51a4fceac4dcdd930608dbcf9899",
		"19525031213e57ac0293fca97b35638c385ed34e8038321d315ad6a71888cd06",
		"6b8ab25924f8b6dddcd2d81e190af3cbc9022f27da5527bddd16aace65149318",
	} {
		kind := GeneratorRecordSetKind(i + 1)
		d, err := GeneratorRecordSetDescriptor(kind, generatedRecordID(1), nil)
		if err != nil || d != EmptyGeneratorRecordSet(kind) || d.Length != 4 || d.Count != 0 || fmt.Sprintf("%x", d.Digest) != want ||
			!GeneratorRecordSetShapeValid(kind, d) {
			t.Fatal("independent empty set", kind, d, err)
		}
		for other := GeneratorRecordSetKind(1); other <= GeneratorHazardResults; other++ {
			if other != kind && GeneratorRecordSetShapeValid(other, d) {
				t.Fatal("empty descriptor changed family", kind, other)
			}
		}
	}
	// Independently concatenated release body: u16(1), repeated-byte IDs1..5,
	// descriptor6, u32(1024), u8(1). Support row: u8(12), ID2, B(body).
	// Set: u32(1), B(support row). D("phase-releases", set) is over 256 bytes.
	body, err := EncodePendingInboxReleaseRecord(generatedRecordRelease())
	if err != nil {
		t.Fatal(err)
	}
	d, err := GeneratorRecordSetDescriptor(GeneratorPhaseReleases, generatedRecordID(1), []SupportRecord{{Kind: 12, RecordID: generatedRecordID(2), Body: body}})
	if err != nil || d.Length != 256 || d.Count != 1 || fmt.Sprintf("%x", d.Digest) != "b5b48800ac69d97d281c5b68dc5d419388ad193c5eedc838fd3f6242aecc2c7c" ||
		!GeneratorRecordSetShapeValid(GeneratorPhaseReleases, d) {
		t.Fatal("independent release set", d, err)
	}
}

// full_only: false
func TestGeneratorRecordSetsRequireExactTypedRows(t *testing.T) {
	expected, _, result := generatedResultFixture(t, 1)
	resultBody, err := EncodeGeneratedResultRecord(result)
	if err != nil {
		t.Fatal(err)
	}
	coreBody, err := EncodeGeneratedResultCore(result.Core)
	if err != nil {
		t.Fatal(err)
	}
	factsBody, err := EncodeGeneratorSafeFacts(result.SafeFacts)
	if err != nil {
		t.Fatal(err)
	}
	evidenceBody, err := EncodeGeneratedCreateEvidence(GeneratedCreateEvidence{
		Schema:            GeneratedCreateEvidenceSchema,
		OriginalResultID:  result.Core.ResultID,
		CredentialRouteID: expected.Template.CredentialRouteID,
		ResultCore:        coreBody,
		SafeFacts:         factsBody,
		Intent:            generatedRecordDescriptor(8),
		CompletionClass:   expected.Template.CompletionClass,
		LifecycleMode:     GeneratorLifecycleManaged,
	})
	if err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		kind GeneratorRecordSetKind
		row  SupportRecord
	}{
		{GeneratorPhaseResults, SupportRecord{Kind: 4, RecordID: result.Core.ResultID, Body: resultBody}},
		{GeneratorHazardResults, SupportRecord{Kind: 4, RecordID: result.Core.ResultID, Body: resultBody}},
		{GeneratorHazardResults, SupportRecord{Kind: 13, RecordID: result.Core.ResultID, Body: evidenceBody}},
	}
	for _, tc := range []struct {
		kind   GeneratorRecordSetKind
		tag    uint8
		id     ID
		encode func() ([]byte, error)
	}{
		{GeneratorPhaseAttempts, 9, generatedRecordAttempt().AttemptID, func() ([]byte, error) { return EncodeGeneratedAttemptRecord(generatedRecordAttempt()) }},
		{GeneratorPhaseDuties, 10, generatedRecordDuty().DutyID, func() ([]byte, error) { return EncodeGeneratedDutyRecord(generatedRecordDuty()) }},
		{GeneratorPhaseHazards, 11, generatedRecordHazard().HazardID, func() ([]byte, error) { return EncodeGeneratedHazardRecord(generatedRecordHazard()) }},
		{GeneratorPhaseReleases, 12, generatedRecordRelease().InboxID, func() ([]byte, error) { return EncodePendingInboxReleaseRecord(generatedRecordRelease()) }},
	} {
		b, err := tc.encode()
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, struct {
			kind GeneratorRecordSetKind
			row  SupportRecord
		}{tc.kind, SupportRecord{Kind: tc.tag, RecordID: tc.id, Body: b}})
	}
	for _, tc := range rows {
		t.Run(fmt.Sprintf("%d/%d", tc.kind, tc.row.Kind), func(t *testing.T) {
			domain, err := SupportRecordDomain(tc.row)
			if err != nil {
				t.Fatal(err)
			}
			d, err := GeneratorRecordSetDescriptor(tc.kind, domain, []SupportRecord{tc.row})
			if err != nil || !GeneratorRecordSetShapeValid(tc.kind, d) || d.Length != uint64(41+len(tc.row.Body)+4) || d.Count != 1 {
				t.Fatal("typed set", d, err)
			}
			for _, mutate := range []func(*SupportRecord){
				func(v *SupportRecord) { v.Kind = 5 },
				func(v *SupportRecord) { v.RecordID[0] ^= 1 },
				func(v *SupportRecord) { v.Body = append(bytes.Clone(v.Body), 0) },
				func(v *SupportRecord) { v.Body = bytes.Clone(v.Body); v.Body[1]++ },
			} {
				bad := tc.row
				mutate(&bad)
				if _, err := GeneratorRecordSetDescriptor(tc.kind, domain, []SupportRecord{bad}); err == nil {
					t.Fatal("invalid row accepted")
				}
			}
			for _, badDomain := range []ID{{}, generatedRecordID(99)} {
				if _, err := GeneratorRecordSetDescriptor(tc.kind, badDomain, []SupportRecord{tc.row}); err == nil {
					t.Fatal("wrong selected domain accepted")
				}
			}
			if _, err := GeneratorRecordSetDescriptor(tc.kind, domain, []SupportRecord{tc.row, tc.row}); err == nil {
				t.Fatal("duplicate row accepted")
			}
			for _, damage := range []func(*GeneratorDescriptor){
				func(v *GeneratorDescriptor) { v.Length = 0 },
				func(v *GeneratorDescriptor) { v.Count = ^uint32(0) },
				func(v *GeneratorDescriptor) { v.Digest = ID{} },
			} {
				bad := d
				damage(&bad)
				if GeneratorRecordSetShapeValid(tc.kind, bad) {
					t.Fatal("bad shape accepted")
				}
			}
		})
	}
	if _, err := GeneratorRecordSetDescriptor(GeneratorHazardResults, result.Core.DomainID, []SupportRecord{rows[1].row, rows[2].row}); err == nil {
		t.Fatal("two representations of one result accepted")
	}
	for _, kind := range []GeneratorRecordSetKind{0, 7, 255} {
		if _, err := GeneratorRecordSetDescriptor(kind, generatedRecordID(1), nil); err == nil || EmptyGeneratorRecordSet(kind).Valid() ||
			GeneratorRecordSetShapeValid(kind, EmptyGeneratorRecordSet(GeneratorPhaseResults)) {
			t.Fatal("unknown family accepted")
		}
	}
}

// full_only: false
func TestGeneratorRecordSetsRequireSortedCompleteRows(t *testing.T) {
	first := generatedRecordRelease()
	second := first
	second.InboxID = generatedRecordID(3)
	a, _ := EncodePendingInboxReleaseRecord(first)
	b, _ := EncodePendingInboxReleaseRecord(second)
	rows := []SupportRecord{{Kind: 12, RecordID: first.InboxID, Body: a}, {Kind: 12, RecordID: second.InboxID, Body: b}}
	before, err := GeneratorRecordSetDescriptor(GeneratorPhaseReleases, first.DomainID, rows)
	if err != nil {
		t.Fatal(err)
	}
	rows[0], rows[1] = rows[1], rows[0]
	if _, err := GeneratorRecordSetDescriptor(GeneratorPhaseReleases, first.DomainID, rows); err == nil {
		t.Fatal("unordered rows accepted")
	}
	rows[0], rows[1] = rows[1], rows[0]
	second.State = GeneratedReleaseUnknown
	rows[1].Body, err = EncodePendingInboxReleaseRecord(second)
	if err != nil {
		t.Fatal(err)
	}
	after, err := GeneratorRecordSetDescriptor(GeneratorPhaseReleases, first.DomainID, rows)
	if err != nil || after.Digest == before.Digest || after.Length != before.Length || after.Count != before.Count {
		t.Fatal("complete row body not bound", err)
	}
}

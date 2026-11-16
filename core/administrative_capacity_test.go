package core

import (
	"encoding/binary"
	"fmt"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestGeneratedAdministrativeRowEnvelopeSeparatesOldValueKinds(t *testing.T) {
	shape := generatedCapacityShape{ValueEntryCount: 2, ValueEntryPageCount: 1, Recipients: 1,
		Secrets: 2, Memberships: 2, SecretMemberships: 2, Generated: 1, OldGenerated: 1,
		ValueEntryPlanCount: 1, RetainedSources: 1, DeclarationBytes: 512}
	groups, err := generatedCleanCapacity(shape)
	if err != nil || groups[contract.GeneratorCapacityOldValues].MaxCount != 2 {
		t.Fatal("combined old-value physical charge", err)
	}
	rows, _, _, err := generatedAdministrativeRowEnvelope(shape)
	if err != nil || rows[contract.RetainedCanonicalSupportKind] != 1 ||
		rows[contract.GeneratedCreateEvidenceSupportKind] != 1 {
		t.Fatal("distinct selected kind 6 and kind 13 rows were double charged", err, rows)
	}
}

// full_only: false
func TestGeneratedAdministrativeControlledEnvelopeFitsReservedShards(t *testing.T) {
	shape := generatedCapacityShape{ValueEntryCount: 512, ValueEntryPageCount: 32, Recipients: 256, Secrets: 512,
		Memberships: 4096, SecretMemberships: 4096, Generated: 128, OldGenerated: 128, Creates: 128,
		Retirements: 128, ControlledRetirements: 128, ValueEntryPlanCount: 512, RetainedSources: 384,
		DeclarationBytes: 32 << 20, OldIntentBytes: 48 << 20, Recovery: true}
	rows, direct, owners, err := generatedAdministrativeRowEnvelope(shape)
	var total uint64
	for _, count := range rows {
		total += count
	}
	// Index positions are the closed SupportRecord kind set (1 through 18).
	// A new writer category must revise the row envelope and this test.
	// The image charge is 13,681,913 + (384*256-4096)*489 = 59,749,625.
	// With 6,197,248 prior Auxiliary bytes, 1,048,320-byte fragments
	// require 63 rows; marker four adds 384*32 material-association bytes.
	wantRows := generatedAdministrativeRowCounts{0, 1024, 1, 104, 640, 1, 384, 512, 384, 640, 1280, 0, 640, 512, 8711, 0, 0, 0, 1}
	if err != nil || rows != wantRows || total != 14834 || direct != 1280 || owners != 1281 {
		t.Fatalf("closed support-row tally: %v want %v; total %d direct %d groups %d: %v", rows, wantRows, total, direct, owners, err)
	}
	domain := generatedVectorID(1)
	// Full prior receipt windows plus current provenance can leave many
	// mandatory rows before the new plan. One coalesced physical span still
	// contributes 512 row references to the successor growth projection.
	index := format.AdministrativeIndex{Domain: domain, Object: generatedVectorID(202), SliceSnapshot: generatedVectorID(203),
		Pages: []format.AdministrativePage{{Ref: format.Ref{Kind: contract.RequiredSupportKind, Format: format.Version,
			Domain: domain, Object: generatedVectorID(204), Digest: generatedVectorID(205),
			Length: contract.RequiredSupportPageHeaderLength + 512*contract.SupportRecordMinLength},
			Spans: []format.AdministrativeSpan{{First: 0, Count: 512, Mandatory: true}}}}}
	index.Pages[0].Rows = make([]format.AdministrativeRowSummary, 512)
	for i := range index.Pages[0].Rows {
		var id contract.ID
		binary.BigEndian.PutUint32(id[28:], uint32(i+1))
		index.Pages[0].Rows[i] = format.AdministrativeRowSummary{Kind: contract.MutationReceiptSupportKind, RecordID: id, BodyLength: 87}
	}
	s := &StateSession{adminIndex: index}
	reservedIndexBytes, err := s.generatedAdministrativeReservedLength(shape)
	if err != nil {
		t.Fatal(err)
	}
	shards, err := s.generatedAdministrativeShardReserve(shape)
	if err != nil || shards > 19 {
		t.Fatalf("controlled index reserve: %d shards: %v", shards, err)
	}
	if _, err := generatedCleanCapacity(shape); err != contract.ErrRecordCapacity {
		t.Fatal("clean helper accepted old intents without selected physical blobs", err)
	}
	clean := shape
	clean.OldIntentBytes = 0
	groups, err := generatedCleanCapacity(clean)
	if err != nil {
		t.Fatal(err)
	}
	physical := uint32(3) // mandatory/optional split at each possible changed class
	for _, group := range groups {
		physical += group.MaxPages
	}
	if physical != 208 || reservedIndexBytes != 37_074_011 || shards != 18 || physical+shards > ordinaryChildPageLimit {
		t.Fatalf("clean continuation lost four-slot exit margin: %d physical + %d index (%d bytes)", physical, shards, reservedIndexBytes)
	}
	exitShards, err := s.generatedAdministrativeFirstExitShardReserve(shape)
	if err != nil || exitShards != 18 || physical+2+exitShards > contract.MaxChildPages {
		t.Fatalf("clean continuation cannot fit its first exit: %d physical + 2 receipt + %d index: %v", physical, exitShards, err)
	}
	t.Logf("clean reserved envelope: physical=%d index-bytes=%d index-shards=%d first-exit-index-bytes=%d first-exit-shards=%d first-exit-children=%d",
		physical, reservedIndexBytes, shards, reservedIndexBytes+endWorkMaximumReceiptIndexBytes, exitShards, physical+2+exitShards)
	backlog, selected, oldPages := capacityWithIndependentOldIntentsFixture(t, shape, groups)
	fullPhysical := uint32(0)
	for _, group := range backlog {
		fullPhysical += group.MaxPages
	}
	// The existing receipt page remains. Add exact page framing and each
	// selected row summary for the 128 independent old blobs.
	for i, rows := range oldPages {
		object := contract.Hash([]byte(fmt.Sprintf("capacity-old-intent-page-%d", i)))
		page := format.RequiredSupportPage{Domain: selected.session.root.Domain, Object: object, Index: uint16(i + 1), Records: rows}
		body, err := format.EncodeRequiredSupportPage(page)
		if err != nil {
			t.Fatal("physical old intent page", err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, domain, object, page.Index, body)
		if err != nil {
			t.Fatal("physical old intent Ref", err)
		}
		indexed := format.AdministrativePage{Ref: ref,
			Spans: []format.AdministrativeSpan{{First: 0, Count: uint16(len(rows)), Mandatory: true}}}
		for _, row := range rows {
			indexed.Rows = append(indexed.Rows, format.AdministrativeRowSummary{Kind: row.Kind, RecordID: row.RecordID, BodyLength: uint32(len(row.Body))})
		}
		s.adminIndex.Pages = append(s.adminIndex.Pages, indexed)
	}
	fullIndexBytes, err := s.generatedAdministrativeReservedLength(shape)
	if err != nil {
		t.Fatal("independent old blob index reserve", err)
	}
	fullShards, err := s.generatedAdministrativeShardReserve(shape)
	if err != nil {
		t.Fatal("independent old blob shards", err)
	}
	fullExitShards, err := s.generatedAdministrativeFirstExitShardReserve(shape)
	if err != nil || fullPhysical != 273 || fullIndexBytes != 37_414_939 || fullShards != 18 || fullExitShards != 18 ||
		fullPhysical+fullShards != 291 || fullPhysical+fullShards <= ordinaryChildPageLimit ||
		fullPhysical+2+fullExitShards != 293 || fullPhysical+2+fullExitShards <= contract.MaxChildPages {
		t.Fatalf("full independent old-blob shape must remain refused: physical=%d index=%d bytes=%d first-exit-index=%d: %v", fullPhysical, fullShards, fullIndexBytes, fullExitShards, err)
	}
	t.Logf("independent old-blob reserved shape exceeds admission: %d children > %d; first exit %d > %d; signed maximum reachability is not established",
		fullPhysical+fullShards, ordinaryChildPageLimit, fullPhysical+2+fullExitShards, contract.MaxChildPages)
}

// full_only: false
func TestEndWorkFirstExitIndexBoundUsesEncodedReceiptAndSplitSpans(t *testing.T) {
	domain := generatedVectorID(216)
	index := format.AdministrativeIndex{Domain: domain, Object: generatedVectorID(217), SliceSnapshot: generatedVectorID(218)}
	before, err := format.AdministrativeIndexEncodedLength(index)
	if err != nil {
		t.Fatal(err)
	}
	receipts := format.AdministrativePage{Ref: format.Ref{Kind: contract.RequiredSupportKind, Format: format.Version,
		Domain: domain, Object: generatedVectorID(219), Digest: generatedVectorID(220), Index: 0,
		Length: contract.RequiredSupportPageHeaderLength + 512*contract.SupportRecordMinLength},
		Spans: []format.AdministrativeSpan{{First: 0, Count: 512, Mandatory: true}}}
	for i := 0; i < 512; i++ {
		var id contract.ID
		binary.BigEndian.PutUint32(id[28:], uint32(i+1))
		receipts.Rows = append(receipts.Rows, format.AdministrativeRowSummary{
			Kind: contract.MutationReceiptSupportKind, RecordID: id, BodyLength: 87})
	}
	fragment := format.AdministrativePage{Ref: format.Ref{Kind: contract.RequiredSupportKind, Format: format.Version,
		Domain: domain, Object: generatedVectorID(221), Digest: generatedVectorID(222), Index: 1,
		Length: contract.RequiredSupportPageHeaderLength + contract.SupportRecordMinLength},
		Spans: []format.AdministrativeSpan{{First: 0, Count: 1, Mandatory: true}},
		Rows: []format.AdministrativeRowSummary{{Kind: contract.GeneratedFragmentSupportKind,
			RecordID: generatedVectorID(223), BodyLength: 87}}}
	index.Pages = []format.AdministrativePage{receipts, fragment}
	after, err := format.AdministrativeIndexEncodedLength(index)
	if err != nil || after-before != 19211 || endWorkMaximumReceiptIndexBytes != 19211 {
		t.Fatalf("full receipt and fragment index allowance: %d + %d = %d: %v", before, endWorkMaximumReceiptIndexBytes, after, err)
	}

	descriptor := contract.GeneratorDescriptor{Digest: generatedVectorID(224), Length: 4}
	index = format.AdministrativeIndex{Domain: domain, Object: generatedVectorID(217), SliceSnapshot: generatedVectorID(218)}
	for i := byte(0); i < 2; i++ {
		id := generatedVectorID(225 + i)
		index.Groups = append(index.Groups, format.AdministrativeGroup{GroupID: id, OwnerID: id, TargetID: id,
			OwnerKind: format.AdministrativeGeneratedDuty, DutyKind: contract.GeneratedDutyCreate,
			SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing,
			Affected:                descriptor, Dependencies: descriptor, Disposable: descriptor})
	}
	index.Pages = []format.AdministrativePage{{Ref: format.Ref{Kind: contract.RequiredSupportKind,
		Format: format.Version, Domain: domain, Object: generatedVectorID(227), Digest: generatedVectorID(228),
		Length: contract.RequiredSupportPageHeaderLength + 3*contract.SupportRecordMinLength}, ReadRequired: true,
		Spans: []format.AdministrativeSpan{{First: 0, Count: 3, Mandatory: true, GroupIndexes: []uint16{0, 1}}}}}
	coalesced, err := format.AdministrativeIndexEncodedLength(index)
	if err != nil {
		t.Fatal(err)
	}
	if got := endWorkSliceSpanExpansion(index); got != 22 {
		t.Fatalf("three owned Slice rows must allow two new spans with both owners: %d", got)
	}
	index.Pages[0].Spans = []format.AdministrativeSpan{
		{First: 0, Count: 1, Mandatory: true, GroupIndexes: []uint16{0, 1}},
		{First: 1, Count: 1, Mandatory: true, GroupIndexes: []uint16{0, 1}},
		{First: 2, Count: 1, Mandatory: true, GroupIndexes: []uint16{0, 1}},
	}
	split, err := format.AdministrativeIndexEncodedLength(index)
	if err != nil || split-coalesced != 22 {
		t.Fatalf("independent one-row encoded span allowance: %d -> %d: %v", coalesced, split, err)
	}
	// A retained old intent blob can lose current-mandatory status for one
	// physical fragment while an adjacent fragment keeps another owner. The
	// absolute shortcut must cover this non-Slice split too; the per-target
	// fallback uses the actual post-disposition span list.
	fragments := format.AdministrativePage{Ref: format.Ref{Kind: contract.RequiredSupportKind,
		Format: format.Version, Domain: domain, Object: generatedVectorID(229), Digest: generatedVectorID(230),
		Index: 1, Length: contract.RequiredSupportPageHeaderLength + 3*contract.SupportRecordMinLength},
		Spans: []format.AdministrativeSpan{{First: 0, Count: 3, Mandatory: true, GroupIndexes: []uint16{0, 1}}}}
	for i := byte(0); i < 3; i++ {
		fragments.Rows = append(fragments.Rows, format.AdministrativeRowSummary{Kind: contract.GeneratedFragmentSupportKind,
			RecordID: generatedVectorID(231 + i), BodyLength: 87})
	}
	index.Pages = append(index.Pages, fragments)
	beforeDemotion, err := format.AdministrativeIndexEncodedLength(index)
	if err != nil || endWorkSliceSpanExpansion(index) != 0 || endWorkSelectedSpanExpansion(index) != 22 {
		t.Fatal("absolute bound omitted the non-Slice fragment span", err)
	}
	index.Pages[1].Spans = []format.AdministrativeSpan{
		{First: 0, Count: 1, GroupIndexes: []uint16{1}},
		{First: 1, Count: 2, Mandatory: true, GroupIndexes: []uint16{0, 1}},
	}
	afterDemotion, err := format.AdministrativeIndexEncodedLength(index)
	if err != nil || afterDemotion-beforeDemotion != 9 ||
		afterDemotion-beforeDemotion > endWorkSelectedSpanExpansion(format.AdministrativeIndex{Pages: []format.AdministrativePage{fragments}}) {
		t.Fatalf("retained fragment demotion split exceeds absolute span bound: %d -> %d: %v", beforeDemotion, afterDemotion, err)
	}
}

// full_only: false
func TestGeneratedAdministrativeShardGrowthRefusesFullOrdinaryBudget(t *testing.T) {
	const oldGroups = 7156
	domain := generatedVectorID(210)
	descriptor := contract.GeneratorDescriptor{Digest: generatedVectorID(211), Length: 4}
	index := format.AdministrativeIndex{Domain: domain, Object: generatedVectorID(212), SliceSnapshot: generatedVectorID(213)}
	spans := make([]format.AdministrativeSpan, 0, oldGroups)
	for i := 0; i < oldGroups; i++ {
		var id contract.ID
		binary.BigEndian.PutUint32(id[28:], uint32(i+1))
		index.Groups = append(index.Groups, format.AdministrativeGroup{GroupID: id, OwnerID: id, TargetID: id,
			OwnerKind: format.AdministrativeGeneratedDuty, DutyKind: contract.GeneratedDutyCreate,
			SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing,
			Affected:                descriptor, Dependencies: descriptor, Disposable: descriptor})
		spans = append(spans, format.AdministrativeSpan{First: uint16(i), Count: 1, GroupIndexes: []uint16{uint16(i)}})
	}
	index.Pages = []format.AdministrativePage{{Ref: format.Ref{Kind: contract.RequiredSupportKind, Format: format.Version,
		Domain: domain, Object: generatedVectorID(214), Digest: generatedVectorID(215),
		Length: contract.RequiredSupportPageHeaderLength + oldGroups*contract.SupportRecordMinLength}, Spans: spans}}
	index.Pages[0].Rows = make([]format.AdministrativeRowSummary, oldGroups)
	for i := range index.Pages[0].Rows {
		index.Pages[0].Rows[i] = format.AdministrativeRowSummary{Kind: contract.GeneratedDutySupportKind,
			RecordID: index.Groups[i].GroupID, BodyLength: 87}
	}
	before, err := format.AdministrativeIndexEncodedLength(index)
	if err != nil || before >= contract.MaxRequiredSupportPageLength {
		t.Fatalf("predecessor must fit one shard: %d: %v", before, err)
	}
	shape := generatedCapacityShape{ValueEntryCount: 1, ValueEntryPageCount: 1, Recipients: 1,
		Memberships: 1, Creates: 1, ValueEntryPlanCount: 1, DeclarationBytes: 512}
	shards, err := (&StateSession{adminIndex: index}).generatedAdministrativeShardReserve(shape)
	if err != nil || shards < 2 || 251+shards <= ordinaryChildPageLimit {
		t.Fatalf("projected index growth did not consume the next child: %d: %v", shards, err)
	}
}

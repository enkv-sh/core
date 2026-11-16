package core

import (
	"bytes"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestAdministrativeInspectionPreservesOtherGroupWhenSharedAuxiliaryPageIsMissing(t *testing.T) {
	domain := generatedVectorID(1)
	first := generatedVectorID(2)
	second := generatedVectorID(3)
	shared := format.Ref{
		Kind: contract.RequiredSupportKind, Format: format.Version,
		Domain: domain, Object: generatedVectorID(4), Digest: generatedVectorID(5),
		Length: 1024,
	}
	descriptor := contract.GeneratorDescriptor{Digest: generatedVectorID(6), Length: 4}
	s := &StateSession{
		admission: openAdmission{domain: domain},
		root:      format.Root{Domain: domain, AdministrativeIndex: format.Ref{Object: generatedVectorID(7)}, RequiredSupport: []format.Ref{shared}},
		adminIndex: format.AdministrativeIndex{
			Domain: domain, Object: generatedVectorID(7), SliceSnapshot: generatedVectorID(8),
			Groups: []format.AdministrativeGroup{
				{GroupID: first, OwnerID: first, TargetID: first, OwnerKind: format.AdministrativeGeneratedParent,
					SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing,
					Affected:                descriptor, Dependencies: descriptor, Disposable: descriptor},
				{GroupID: second, OwnerID: second, TargetID: second, OwnerKind: format.AdministrativeGeneratedDuty, DutyKind: contract.GeneratedDutyCreate,
					SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing,
					Affected:                descriptor, Dependencies: descriptor, Disposable: descriptor},
			},
			Pages: []format.AdministrativePage{{Ref: shared, Spans: []format.AdministrativeSpan{
				{First: 0, Count: 1, GroupIndexes: []uint16{0}},
				{First: 1, Count: 1, GroupIndexes: []uint16{1}},
			}, Rows: []format.AdministrativeRowSummary{
				{Kind: contract.GeneratedParentSupportKind, RecordID: first, BodyLength: 87},
				{Kind: contract.GeneratedDutySupportKind, RecordID: second, BodyLength: 87},
			}}},
		},
	}
	// There is no decoded support page: the selected object is unavailable.
	if _, err := s.supportDescriptor(); err == nil {
		t.Fatal("ordinary complete reader accepted missing selected support")
	}
	beforeBytes, err := format.AdministrativeIndexEncodedLength(s.adminIndex)
	if err != nil {
		t.Fatal(err)
	}
	next, err := s.administrativeWorkDisposition(first)
	if err != nil {
		t.Fatal("administrative reader required damaged auxiliary bytes", err)
	}
	if len(next.Groups) != 1 || next.Groups[0].GroupID != second ||
		len(next.Pages) != 1 || next.Pages[0].Ref != shared ||
		len(next.Pages[0].Spans) != 1 || next.Pages[0].Spans[0].First != 1 ||
		len(next.Pages[0].Spans[0].GroupIndexes) != 1 || next.Pages[0].Spans[0].GroupIndexes[0] != 0 {
		t.Fatal("unrelated group commitment or shared page changed", next)
	}
	if slot, ok := administrativeSelectedRowSlot(next.Pages[0], 1); !ok || slot != 0 {
		t.Fatal("retained physical row did not become logical slot zero", slot, ok)
	}
	afterBytes, err := format.AdministrativeIndexEncodedLength(next)
	if err != nil || afterBytes >= beforeBytes {
		t.Fatal("small zero-page exit increased retained index bytes", beforeBytes, afterBytes, err)
	}
	withReceipt := next
	withReceipt.Pages = slices.Clone(next.Pages)
	for i := uint16(1); i <= 2; i++ {
		withReceipt.Pages = append(withReceipt.Pages, format.AdministrativePage{Ref: format.Ref{
			Kind: contract.RequiredSupportKind, Format: format.Version, Domain: domain,
			Object: generatedVectorID(uint8(8 + i)), Digest: generatedVectorID(uint8(10 + i)), Index: i,
			Length: contract.RequiredSupportPageHeaderLength + contract.SupportRecordMinLength},
			Spans: []format.AdministrativeSpan{{First: 0, Count: 1, Mandatory: true}},
			Rows:  []format.AdministrativeRowSummary{{Kind: contract.MutationReceiptSupportKind, RecordID: generatedVectorID(uint8(20 + i)), BodyLength: 87}}})
	}
	receiptBytes, err := format.AdministrativeIndexEncodedLength(withReceipt)
	if err != nil || receiptBytes-afterBytes != 304 {
		t.Fatal("first receipt and ordered-index pages have wrong index cost", receiptBytes, afterBytes, err)
	}
	priorShards, err := format.AdministrativeIndexShardCount(afterBytes)
	if err != nil {
		t.Fatal(err)
	}
	receiptShards, err := format.AdministrativeIndexShardCount(receiptBytes)
	if err != nil || receiptShards > priorShards+1 {
		t.Fatal("bounded receipt page required more than one new index shard", priorShards, receiptShards, err)
	}
	if _, ok := administrativeSelectedRowSlot(next.Pages[0], 0); ok {
		t.Fatal("ended row retained a logical slot")
	}
	s.adminIndex = next
	s.support = []format.RequiredSupportPageView{{Domain: domain, Object: shared.Object, Index: shared.Index}}
	owners, err := s.priorAdministrativeRows()
	if err != nil || len(owners) != 1 || len(s.priorAdministrativeOwnership(owners[generatedRecordKey{contract.GeneratedDutySupportKind, second}]).groups) != 1 ||
		s.priorAdministrativeOwnership(owners[generatedRecordKey{contract.GeneratedDutySupportKind, second}]).groups[0] != second {
		t.Fatal("opaque selected row lost authenticated group ownership", err)
	}
	s.support = []format.RequiredSupportPageView{{Domain: domain, Object: shared.Object, Index: shared.Index,
		Records: []contract.SupportRecordView{{Kind: contract.GeneratedDutySupportKind, RecordID: second}}}}
	owners, err = s.priorAdministrativeRows()
	if err != nil || len(owners) != 1 || len(s.priorAdministrativeOwnership(owners[generatedRecordKey{contract.GeneratedDutySupportKind, second}]).groups) != 1 ||
		s.priorAdministrativeOwnership(owners[generatedRecordKey{contract.GeneratedDutySupportKind, second}]).groups[0] != second {
		t.Fatal("sparse selected row lost independent group ownership", err)
	}
	afterSecond, err := s.administrativeWorkDisposition(second)
	if err != nil || len(afterSecond.Pages) != 0 || len(afterSecond.Groups) != 0 {
		t.Fatal("last group did not release the shared page", err)
	}
	s.adminIndex.Pages[0].Spans = []format.AdministrativeSpan{{First: 0, Count: 1, GroupIndexes: []uint16{0}},
		{First: 1, Count: 1, GroupIndexes: []uint16{0}}}
	s.adminIndex.Pages[0].Rows = []format.AdministrativeRowSummary{
		{Kind: contract.GeneratedParentSupportKind, RecordID: first, BodyLength: 87},
		{Kind: contract.GeneratedDutySupportKind, RecordID: second, BodyLength: 87},
	}
	s.adminIndex.Groups = []format.AdministrativeGroup{
		{GroupID: first, OwnerID: first, TargetID: first, OwnerKind: format.AdministrativeGeneratedParent,
			SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing,
			Affected:                descriptor, Dependencies: descriptor, Disposable: descriptor},
		{GroupID: second, OwnerID: second, TargetID: second, OwnerKind: format.AdministrativeGeneratedDuty, DutyKind: contract.GeneratedDutyCreate,
			SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing,
			Affected:                descriptor, Dependencies: descriptor, Disposable: descriptor, RelatedGroupIndexes: []uint16{0}},
	}
	if _, err := s.administrativeWorkDisposition(first); err == nil {
		t.Fatal("selected dependent group lost its mandatory parent")
	}
	closed, scope, err := s.administrativeWorkClosure(first)
	if err != nil || len(scope) != 2 || len(closed.Groups) != 0 || len(closed.Pages) != 0 {
		t.Fatal("parent exit did not close its selected dependent scope", len(scope), err)
	}
}

// full_only: false
func TestEndWorkWarnsForDiscardedInboxMappingOnSharedPage(t *testing.T) {
	domain, parent, release, survivor := generatedVectorID(225), generatedVectorID(226), generatedVectorID(227), generatedVectorID(228)
	object, snapshot := generatedVectorID(229), generatedVectorID(230)
	descriptor := contract.GeneratorDescriptor{Digest: generatedVectorID(231), Length: 4}
	ref := format.Ref{Kind: contract.RequiredSupportKind, Format: format.Version, Domain: domain,
		Object: object, Digest: generatedVectorID(232), Length: 1024}
	before := format.AdministrativeIndex{Domain: domain, Object: generatedVectorID(233), SliceSnapshot: snapshot,
		Groups: []format.AdministrativeGroup{
			{GroupID: parent, OwnerID: parent, TargetID: parent, OwnerKind: format.AdministrativeGeneratedParent,
				SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing,
				Affected:                descriptor, Dependencies: descriptor, Disposable: descriptor},
			{GroupID: release, OwnerID: release, TargetID: release, OwnerKind: format.AdministrativeInboxRelease,
				SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing,
				Affected:                descriptor, Dependencies: descriptor, Disposable: descriptor, RelatedGroupIndexes: []uint16{0}},
			{GroupID: survivor, OwnerID: survivor, TargetID: survivor, OwnerKind: format.AdministrativeGeneratedDuty,
				DutyKind: contract.GeneratedDutyCreate, SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing,
				Affected: descriptor, Dependencies: descriptor, Disposable: descriptor},
		},
		Pages: []format.AdministrativePage{{Ref: ref,
			Spans: []format.AdministrativeSpan{
				{First: 0, Count: 1, GroupIndexes: []uint16{0}},
				{First: 1, Count: 1, GroupIndexes: []uint16{1}},
				{First: 2, Count: 1, GroupIndexes: []uint16{2}},
			},
			Rows: []format.AdministrativeRowSummary{
				{Kind: contract.GeneratedAttemptSupportKind, RecordID: parent, BodyLength: 87},
				{Kind: contract.PendingInboxReleaseSupportKind, RecordID: release, BodyLength: 87},
				{Kind: contract.GeneratedDutySupportKind, RecordID: survivor, BodyLength: 87},
			},
		}}}
	s := &StateSession{root: format.Root{Domain: domain, AdministrativeIndex: format.Ref{Object: before.Object}, RequiredSupport: []format.Ref{ref}}, adminIndex: before}
	after, scope, err := s.administrativeWorkClosure(parent)
	if err != nil || len(scope) != 2 || len(after.Groups) != 1 || len(after.Pages) != 1 || after.Pages[0].Ref != ref ||
		len(after.Pages[0].Spans) != 1 || after.Pages[0].Spans[0].First != 2 {
		t.Fatal("parent exit did not retain only the independent physical row", err)
	}
	if endWorkReplacedSupport(before, after) {
		t.Fatal("fixture unexpectedly replaced the shared support page")
	}
	wantWarning := WarningOrphanGeneratedEffect | WarningDiscardedExactEvidence | WarningPossibleStoreGarbage
	if got := endWorkWarningBits(0, scope, endWorkPossibleStoreGarbage(before, after)); got != wantWarning {
		t.Fatal("discarded selected inbox mapping has wrong warning bits", got, wantWarning)
	}
	t.Run("active_release_requires_parent", func(t *testing.T) {
		active := *s
		active.root.Generated.ActiveOwner = parent
		if _, _, err := active.administrativeWorkClosure(release); err == nil {
			t.Fatal("active parent-owned release was independently disposable")
		}
		retained, ended, err := active.administrativeWorkClosure(parent)
		if err != nil || len(ended) != 2 || ended[0].GroupID != parent || ended[1].GroupID != release || len(retained.Groups) != 1 || retained.Groups[0].GroupID != survivor {
			t.Fatal("complete parent exit changed exact release scope", err)
		}
	})
	releaseOnly, releaseScope, err := s.administrativeWorkClosure(release)
	if err != nil || len(releaseScope) != 1 || len(releaseOnly.Pages) != 1 || releaseOnly.Pages[0].Ref != ref ||
		!endWorkPossibleStoreGarbage(before, releaseOnly) ||
		endWorkWarningBits(0, releaseScope, endWorkPossibleStoreGarbage(before, releaseOnly)) != wantWarning {
		t.Fatal("independent release exit lost shared-page inbox warning", err)
	}
	attemptOnly := before
	attemptOnly.Groups = []format.AdministrativeGroup{before.Groups[0], before.Groups[2]}
	attemptOnly.Pages = []format.AdministrativePage{{Ref: ref,
		Spans: []format.AdministrativeSpan{
			{First: 0, Count: 1, GroupIndexes: []uint16{0}},
			{First: 2, Count: 1, GroupIndexes: []uint16{1}},
		},
		Rows: []format.AdministrativeRowSummary{before.Pages[0].Rows[0], before.Pages[0].Rows[2]},
	}}
	s.adminIndex = attemptOnly
	attemptExit, attemptScope, err := s.administrativeWorkClosure(parent)
	if err != nil || len(attemptScope) != 1 || len(attemptExit.Pages) != 1 || attemptExit.Pages[0].Ref != ref ||
		!endWorkPossibleStoreGarbage(attemptOnly, attemptExit) ||
		endWorkWarningBits(0, attemptScope, endWorkPossibleStoreGarbage(attemptOnly, attemptExit)) != wantWarning {
		t.Fatal("independent Attempt exit lost shared-page inbox warning", err)
	}
	t.Run("transitive_incoming_scope", func(t *testing.T) {
		chain := before
		chain.Groups = slices.Clone(before.Groups)
		chain.Groups[2].RelatedGroupIndexes = []uint16{1}
		s.adminIndex = chain
		for _, test := range []struct {
			target      contract.ID
			ended, kept []contract.ID
		}{
			{parent, []contract.ID{parent, release, survivor}, nil},
			{release, []contract.ID{release, survivor}, []contract.ID{parent}},
			{survivor, []contract.ID{survivor}, []contract.ID{parent, release}},
		} {
			retained, scope, err := s.administrativeWorkClosure(test.target)
			if err != nil || len(scope) != len(test.ended) || len(retained.Groups) != len(test.kept) {
				t.Fatal("directed transitive exit scope", err)
			}
			for i, want := range test.ended {
				if scope[i].GroupID != want {
					t.Fatal("exit followed the dependency in the wrong direction")
				}
			}
			for i, want := range test.kept {
				if retained.Groups[i].GroupID != want {
					t.Fatal("exit removed a prerequisite outside the incoming scope")
				}
			}
		}
	})

}

// full_only: false
func TestEndWorkReboundSlicesCoalesceEqualAdjacentOwners(t *testing.T) {
	s := generatedReservationState(t)
	position := -1
	var retained []format.AdministrativeSpan
	graphCount, intentCount := 0, 0
	for i, page := range s.adminIndex.Pages {
		if !page.ReadRequired {
			continue
		}
		view, err := s.administrativeSelectedSupportPage(page)
		if err != nil {
			t.Fatal("authenticated Slice page", err)
		}
		logical := 0
		for _, span := range page.Spans {
			for physical := span.First; physical < span.First+span.Count; physical++ {
				carrier, match, err := snapshotSliceRecord(contract.SupportRecord(view.Records[logical]),
					s.root.Domain, s.adminIndex.SliceSnapshot)
				logical++
				if err != nil {
					t.Fatal("authenticated Slice carrier", err)
				}
				if !match {
					continue
				}
				location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
				if err != nil {
					t.Fatal("authenticated Slice location", err)
				}
				switch location.ContentKind {
				case contract.GeneratorContentGraph:
					graphCount++
				case contract.GeneratorContentIntent:
					intentCount++
				default:
					continue
				}
				if position >= 0 && position != i {
					t.Fatal("Graph and Intent do not share one physical page")
				}
				position = i
				retained = append(retained, format.AdministrativeSpan{First: physical, Count: 1,
					Mandatory: span.Mandatory, GroupIndexes: slices.Clone(span.GroupIndexes)})
			}
		}
	}
	if position < 0 || graphCount != 1 || intentCount != 1 || len(retained) != 2 {
		t.Fatal("fixture lacks exact Graph and Intent Slice locations")
	}
	old := retained[0]
	if retained[1].Mandatory != old.Mandatory || !slices.Equal(retained[1].GroupIndexes, old.GroupIndexes) {
		t.Fatal("Graph and Intent have different authenticated owner sets")
	}
	work := s.adminIndex
	work.Pages = slices.Clone(work.Pages)
	work.Pages[position].Spans = retained
	selected, err := s.administrativeSelectedSupportPage(work.Pages[position])
	if err != nil || len(selected.Records) != 2 {
		t.Fatal("retained two-row Slice selection", err)
	}
	locations := make([]contract.GeneratorSliceLocation, 0, 2)
	for _, row := range selected.Records {
		carrier, match, err := snapshotSliceRecord(contract.SupportRecord(row), s.root.Domain, s.adminIndex.SliceSnapshot)
		if err != nil || !match {
			t.Fatal("retained Slice carrier", err)
		}
		location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
		if err != nil {
			t.Fatal("retained Slice location", err)
		}
		locations = append(locations, location)
	}
	slices.SortFunc(locations, func(a, b contract.GeneratorSliceLocation) int {
		if a.ContentKind != b.ContentKind {
			return int(a.ContentKind) - int(b.ContentKind)
		}
		return bytes.Compare(a.ContentID[:], b.ContentID[:])
	})
	var vectorRows [][]byte
	for _, location := range locations {
		row, err := contract.EncodeGeneratorSliceLocation(location)
		if err != nil {
			t.Fatal(err)
		}
		vectorRows = append(vectorRows, row)
	}
	want, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorSlices, vectorRows)
	if err != nil {
		t.Fatal(err)
	}
	images, views, err := s.rebindEndWorkSlices(&work, generatedVectorID(220), generatedVectorID(221), want)
	if err != nil || len(images) != 1 || len(views) != 1 {
		t.Fatal("two-row Slice rebind", err)
	}
	spans := work.Pages[position].Spans
	if len(spans) != 1 || spans[0].First != 0 || spans[0].Count != 2 ||
		spans[0].Mandatory != old.Mandatory || !slices.Equal(spans[0].GroupIndexes, old.GroupIndexes) {
		t.Fatal("equal adjacent owners consumed separate index spans", spans)
	}
	if len(old.GroupIndexes) == 0 ||
		(&spans[0].GroupIndexes[0] != &retained[0].GroupIndexes[0] &&
			&spans[0].GroupIndexes[0] != &retained[1].GroupIndexes[0]) {
		t.Fatal("rebound Slice owners duplicate owned selected span backing")
	}
}

// full_only: false
func TestSparseFragmentUsesPhysicalAdministrativeSpanAndLogicalDirectorySlot(t *testing.T) {
	domain, object := generatedVectorID(41), generatedVectorID(42)
	rows := make([]contract.SupportRecord, 2)
	for i := range rows {
		payload := []byte{byte(50 + i)}
		blob := generatedVectorID(uint8(43 + i))
		body, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: 1, BlobID: blob,
			Count: 1, TotalLength: 1, WholeDigest: contract.Hash(payload), Payload: payload})
		if err != nil {
			t.Fatal(err)
		}
		id, err := contract.GeneratorFragmentID(blob, 0)
		if err != nil {
			t.Fatal(err)
		}
		rows[i] = contract.SupportRecord{Kind: contract.GeneratedFragmentSupportKind, RecordID: id, Body: body}
	}
	wire, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: domain, Object: object, Index: 7, Records: rows})
	if err != nil {
		t.Fatal(err)
	}
	physical, err := format.InspectRequiredSupportPage(wire)
	if err != nil || len(physical.Records) != 2 {
		t.Fatal("physical two-row fragment page is invalid", err)
	}
	selected := physical
	selected.Records = physical.Records[1:]
	indexed := format.AdministrativePage{Spans: []format.AdministrativeSpan{{First: 1, Count: 1}}}
	if slot, ok := administrativeSelectedRowSlot(indexed, 1); !ok || slot != 0 {
		t.Fatal("physical ordinal one did not map to selected slot zero", slot, ok)
	}
	directory := []format.FragmentLocation{{BlobID: generatedVectorID(44), SupportPageIndex: 7, RowSlot: 0}}
	if err := format.ValidateFragmentDirectory(directory, []format.RequiredSupportPageView{selected}); err != nil {
		t.Fatal("logical selected fragment slot zero was refused", err)
	}
	directory[0].RowSlot = 1
	if format.ValidateFragmentDirectory(directory, []format.RequiredSupportPageView{selected}) == nil {
		t.Fatal("fragment directory used physical ordinal as logical slot")
	}
}

// full_only: false
func TestAdministrativeDutyDispositionOrdersPreserveExactPageAccount(t *testing.T) {
	domain, exclusiveOwner, sharedOwner, survivor := generatedVectorID(1), generatedVectorID(2), generatedVectorID(3), generatedVectorID(4)
	exclusive := format.Ref{Kind: contract.RequiredSupportKind, Format: format.Version, Domain: domain,
		Object: generatedVectorID(5), Digest: generatedVectorID(6), Length: 199}
	shared := format.Ref{Kind: contract.RequiredSupportKind, Format: format.Version, Domain: domain,
		Object: generatedVectorID(7), Digest: generatedVectorID(8), Index: 1, Length: 323}
	descriptor := contract.GeneratorDescriptor{Digest: generatedVectorID(9), Length: 4}
	// Independent frame account: base 115; group 247; page 108;
	// one-owner span 9; row summary 37. Physical pages are 75+n*(37+87).
	for _, cell := range []struct {
		name        string
		order       [2]contract.ID
		indexBytes  [2]uint64
		refs        [2][]format.Ref
		groups      [2][]contract.ID
		sharedRows  [2][]contract.ID
		sharedFirst [2]uint16
	}{
		{"exclusive-first", [2]contract.ID{exclusiveOwner, sharedOwner}, [2]uint64{809, 516},
			[2][]format.Ref{{shared}, {shared}}, [2][]contract.ID{{sharedOwner, survivor}, {survivor}},
			[2][]contract.ID{{sharedOwner, survivor}, {survivor}}, [2]uint16{0, 1}},
		{"shared-first", [2]contract.ID{sharedOwner, exclusiveOwner}, [2]uint64{917, 516},
			[2][]format.Ref{{exclusive, shared}, {shared}}, [2][]contract.ID{{exclusiveOwner, survivor}, {survivor}},
			[2][]contract.ID{{survivor}, {survivor}}, [2]uint16{1, 1}},
	} {
		t.Run(cell.name, func(t *testing.T) {
			index := format.AdministrativeIndex{Domain: domain, Object: generatedVectorID(10), SliceSnapshot: generatedVectorID(11),
				Pages: []format.AdministrativePage{
					{Ref: exclusive, Spans: []format.AdministrativeSpan{{Count: 1, GroupIndexes: []uint16{0}}},
						Rows: []format.AdministrativeRowSummary{{Kind: contract.GeneratedDutySupportKind, RecordID: exclusiveOwner, BodyLength: 87}}},
					{Ref: shared, Spans: []format.AdministrativeSpan{{Count: 1, GroupIndexes: []uint16{1}}, {First: 1, Count: 1, GroupIndexes: []uint16{2}}},
						Rows: []format.AdministrativeRowSummary{{Kind: contract.GeneratedDutySupportKind, RecordID: sharedOwner, BodyLength: 87}, {Kind: contract.GeneratedDutySupportKind, RecordID: survivor, BodyLength: 87}}},
				}}
			for _, id := range []contract.ID{exclusiveOwner, sharedOwner, survivor} {
				index.Groups = append(index.Groups, format.AdministrativeGroup{GroupID: id, OwnerID: id, TargetID: id,
					OwnerKind: format.AdministrativeGeneratedDuty, DutyKind: contract.GeneratedDutyUnselectedCleanup,
					SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing,
					Affected:                descriptor, Dependencies: descriptor, Disposable: descriptor})
			}
			beforeBytes, err := format.AdministrativeIndexEncodedLength(index)
			if err != nil || beforeBytes != 1210 {
				t.Fatal("fixed ownership fixture lost its exact index frame", beforeBytes, err)
			}
			s := &StateSession{root: format.Root{Domain: domain, AdministrativeIndex: format.Ref{Object: index.Object}, RequiredSupport: []format.Ref{exclusive, shared}}, adminIndex: index}
			for step, target := range cell.order {
				next, scope, err := s.administrativeWorkClosure(target)
				if err != nil || len(scope) != 1 || scope[0].GroupID != target {
					t.Fatal("independent Duty exit changed its selected scope", step, len(scope), err)
				}
				var gotRefs []format.Ref
				var gotGroups []contract.ID
				for _, page := range next.Pages {
					gotRefs = append(gotRefs, page.Ref)
				}
				for _, group := range next.Groups {
					gotGroups = append(gotGroups, group.GroupID)
				}
				length, err := format.AdministrativeIndexEncodedLength(next)
				if err != nil || length != cell.indexBytes[step] || !slices.Equal(gotRefs, cell.refs[step]) || !slices.Equal(gotGroups, cell.groups[step]) {
					t.Fatalf("Duty exit lost exact page ownership: step=%d index-bytes=%d expected=%d pages=%d expected-pages=%d error=%v", step, length, cell.indexBytes[step], len(gotRefs), len(cell.refs[step]), err)
				}
				page := next.Pages[len(next.Pages)-1]
				var gotRows []contract.ID
				for _, row := range page.Rows {
					gotRows = append(gotRows, row.RecordID)
				}
				if page.Ref != shared || page.Spans[0].First != cell.sharedFirst[step] || !slices.Equal(gotRows, cell.sharedRows[step]) {
					t.Fatal("Duty exit changed the surviving immutable shared page or its physical rows", step)
				}
				for i, span := range page.Spans {
					owner := slices.Index(gotGroups, gotRows[i])
					if span.Count != 1 || len(span.GroupIndexes) != 1 || span.GroupIndexes[0] != uint16(owner) {
						t.Fatal("Duty exit changed the surviving row owner", step, i)
					}
				}
				s.adminIndex, s.root.RequiredSupport = next, gotRefs
			}
		})
	}
}

// full_only: false
func TestEndWorkRetainedSpansCoalesceOnlyEqualContiguousOwners(t *testing.T) {
	for _, cell := range []struct {
		name             string
		second           uint16
		extra, mandatory bool
		want             int
	}{
		{"newly equal neighbors", 4, false, false, 1},
		{"physical gap", 5, false, false, 2},
		{"different surviving owners", 4, true, false, 2},
		{"different mandatory flags", 4, false, true, 2},
	} {
		t.Run(cell.name, func(t *testing.T) {
			domain := generatedVectorID(1)
			descriptor := contract.GeneratorDescriptor{Digest: generatedVectorID(8), Length: 4}
			ref := format.Ref{Kind: contract.RequiredSupportKind, Format: format.Version, Domain: domain, Object: generatedVectorID(4), Digest: generatedVectorID(5), Length: 1024}
			index := format.AdministrativeIndex{Domain: domain, Object: generatedVectorID(6), SliceSnapshot: generatedVectorID(7)}
			for i := uint8(2); i <= 4; i++ {
				id := generatedVectorID(i)
				index.Groups = append(index.Groups, format.AdministrativeGroup{GroupID: id, OwnerID: id, TargetID: id, OwnerKind: format.AdministrativeGeneratedDuty, DutyKind: contract.GeneratedDutyCreate, SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing, Affected: descriptor, Dependencies: descriptor, Disposable: descriptor})
			}
			secondOwners := []uint16{1}
			if cell.extra {
				secondOwners = append(secondOwners, 2)
			}
			rows := []format.AdministrativeRowSummary{{Kind: contract.GeneratedDutySupportKind, RecordID: generatedVectorID(21), BodyLength: 87}, {Kind: contract.GeneratedDutySupportKind, RecordID: generatedVectorID(22), BodyLength: 91}}
			index.Pages = []format.AdministrativePage{{Ref: ref, Spans: []format.AdministrativeSpan{{First: 3, Count: 1, GroupIndexes: []uint16{0, 1}}, {First: cell.second, Count: 1, Mandatory: cell.mandatory, GroupIndexes: secondOwners}}, Rows: rows}}
			s := &StateSession{root: format.Root{Domain: domain, AdministrativeIndex: format.Ref{Object: index.Object}, RequiredSupport: []format.Ref{ref}}, adminIndex: index}
			if cell.mandatory {
				s.support = []format.RequiredSupportPageView{{Domain: domain, Object: ref.Object, Index: ref.Index}}
			}
			before, err := format.EncodeAdministrativeIndex(index)
			if err != nil {
				t.Fatal(err)
			}
			next, err := s.administrativeWorkDisposition(index.Groups[0].GroupID)
			if err != nil {
				t.Fatal(err)
			}
			page := next.Pages[0]
			if page.Ref != ref || page.ReadRequired || !slices.Equal(page.Rows, rows) || len(page.Spans) != cell.want {
				t.Fatal("retained page changed physical rows or maximal partition", page)
			}
			if page.Spans[0].First != 3 || page.Spans[0].Count != uint16(3-cell.want) || page.Spans[0].Mandatory || !slices.Equal(page.Spans[0].GroupIndexes, []uint16{0}) {
				t.Fatal("wrong retained physical coverage", page.Spans)
			}
			if cell.want == 2 && (page.Spans[1].First != cell.second || page.Spans[1].Mandatory != cell.mandatory) {
				t.Fatal("physical gap or mandatory flag changed")
			}
			after, err := format.EncodeAdministrativeIndex(s.adminIndex)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("disposition mutated selected backing", err)
			}
		})
	}
}

// full_only: false
func TestEndWorkSlicePackingStableAcrossCandidateIdentities(t *testing.T) {
	base := generatedEmptyPredecessor(t)
	input := generatedReservationInputForMembershipStateIntents(t, base, generatedVectorID(10), []contract.ID{base.admission.recipient},
		[]string{"first", "second", "third", "fourth", "fifth", "sixth"}, func(name string) []byte { return []byte(`{"name":"` + name + `"}`) },
		defaultGeneratedFixtureProfile(), 0, nil, nil)
	reservation, err := base.deriveGeneratedReservation(t.Context(), input)
	if err != nil {
		t.Fatal("distinct retained Slice fixture", err)
	}
	s := reservation.state
	work := clonePublicationWork(s.adminIndex)
	var locations []contract.GeneratorSliceLocation
	ownerByContent := make(map[generatedContentKey][]uint16)
	ordinal := 0
	for i, page := range work.Pages {
		if !page.ReadRequired {
			continue
		}
		view, err := s.administrativeSelectedSupportPage(page)
		if err != nil {
			t.Fatal(err)
		}
		work.Pages[i].Spans = nil
		for physical, row := range view.Records {
			carrier, match, err := snapshotSliceRecord(contract.SupportRecord(row), s.root.Domain, s.adminIndex.SliceSnapshot)
			if err != nil || !match {
				t.Fatal("Slice fixture", err)
			}
			location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
			if err != nil {
				t.Fatal(err)
			}
			locations = append(locations, location)
			owners := []uint16{uint16(ordinal % 2)}
			ordinal++
			ownerByContent[generatedContentKey{kind: location.ContentKind, id: location.ContentID}] = owners
			work.Pages[i].Spans = append(work.Pages[i].Spans, format.AdministrativeSpan{First: uint16(physical), Count: 1, GroupIndexes: owners})
		}
	}
	if len(locations) < 6 || len(work.Groups) < 2 {
		t.Fatal("fixture lacks alternating repeated owners")
	}
	slices.SortFunc(locations, func(a, b contract.GeneratorSliceLocation) int {
		if a.ContentKind != b.ContentKind {
			return int(a.ContentKind) - int(b.ContentKind)
		}
		return bytes.Compare(a.ContentID[:], b.ContentID[:])
	})
	var rows [][]byte
	for _, location := range locations {
		row, err := contract.EncodeGeneratorSliceLocation(location)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, row)
	}
	descriptor, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorSlices, rows)
	if err != nil {
		t.Fatal(err)
	}
	var wantSize, minimumSize, maximumSize uint64
	var wantOwners []string
	packingChanged := false
	for candidate := uint8(120); candidate < 152; candidate++ {
		next := clonePublicationWork(work)
		_, views, err := s.rebindEndWorkSlices(&next, generatedVectorID(candidate), generatedVectorID(candidate+40), descriptor)
		if err != nil {
			t.Fatal(err)
		}
		size, err := format.AdministrativeIndexEncodedLength(next)
		if err != nil {
			t.Fatal(err)
		}
		var owners []string
		for _, page := range next.Pages {
			if !page.ReadRequired {
				continue
			}
			offset := 0
			for _, span := range page.Spans {
				owners = append(owners, fmt.Sprint(span.First, "/", span.Count, "/", span.Mandatory, "/", span.GroupIndexes))
				for n := 0; n < int(span.Count); n++ {
					carrier, match, err := snapshotSliceRecord(contract.SupportRecord(views[page.Ref].Records[offset]), s.root.Domain, next.SliceSnapshot)
					offset++
					if err != nil || !match {
						t.Fatal("rebound Slice", err)
					}
					location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
					if err != nil || !slices.Equal(span.GroupIndexes, ownerByContent[generatedContentKey{kind: location.ContentKind, id: location.ContentID}]) {
						t.Fatal("candidate changed semantic owner", err)
					}
				}
			}
		}
		if candidate == 120 {
			wantSize, minimumSize, maximumSize, wantOwners = size, size, size, owners
		} else {
			minimumSize, maximumSize = min(minimumSize, size), max(maximumSize, size)
			packingChanged = packingChanged || size != wantSize || !slices.Equal(owners, wantOwners)
		}
	}
	if packingChanged {
		t.Fatalf("fresh candidate changed semantic owner packing; index bytes range from %d to %d", minimumSize, maximumSize)
	}
}

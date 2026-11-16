package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// Receipt replacement adds one physical page to this selected shape. The
// projection must count that page before signer or Crypto work begins.
// full_only: false
func TestSuccessionCapacityProjectionCountsReceiptAndIndexPages(t *testing.T) {
	for _, extra := range []int{246, 247, 248} {
		s := successionReceiptCapacityFixture(t)
		s.root.Snapshot = contract.ID{91}
		for n := 0; n < extra; n++ {
			var scalar [4]byte
			binary.BigEndian.PutUint32(scalar[:], uint32(n))
			blob := contract.Hash(append([]byte("succession-capacity-blob"), scalar[:]...))
			body, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: 1, BlobID: blob, Count: 1,
				TotalLength: 1, WholeDigest: contract.Hash([]byte{1}), Payload: []byte{1}})
			if err != nil {
				t.Fatal(err)
			}
			fragmentID, err := contract.GeneratorFragmentID(blob, 0)
			if err != nil {
				t.Fatal(err)
			}
			index := uint16(len(s.support))
			object := contract.Hash(append([]byte("succession-capacity-page"), scalar[:]...))
			pageBody, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: s.admission.domain,
				Object: object, Index: index, Records: []contract.SupportRecord{{Kind: contract.GeneratedFragmentSupportKind, RecordID: fragmentID, Body: body}}})
			if err != nil {
				t.Fatal(err)
			}
			view, err := format.InspectRequiredSupportPage(pageBody)
			if err != nil {
				t.Fatal(err)
			}
			ref, err := format.Reference(contract.RequiredSupportKind, s.admission.domain, object, index, pageBody)
			if err != nil {
				t.Fatal(err)
			}
			s.support = append(s.support, view)
			s.root.RequiredSupport = append(s.root.RequiredSupport, ref)
			s.root.RequiredSupportRecordCount++
			s.root.Generated.Fragments = append(s.root.Generated.Fragments,
				format.FragmentLocation{BlobID: blob, SupportPageIndex: index, RowSlot: 0})
		}
		slices.SortFunc(s.root.Generated.Fragments, func(a, b format.FragmentLocation) int {
			return bytes.Compare(a.BlobID[:], b.BlobID[:])
		})
		index := format.AdministrativeIndex{Domain: s.admission.domain, Object: contract.ID{92}, SliceSnapshot: s.root.Snapshot}
		for i, page := range s.support {
			indexed := format.AdministrativePage{Ref: s.root.RequiredSupport[i]}
			for slot := range page.Records {
				indexed.Spans = append(indexed.Spans, format.AdministrativeSpan{First: uint16(slot), Count: 1, Mandatory: true})
				indexed.Rows = append(indexed.Rows, format.AdministrativeRowSummary{Kind: page.Records[slot].Kind,
					RecordID: page.Records[slot].RecordID, BodyLength: uint32(len(page.Records[slot].Body))})
			}
			index.Pages = append(index.Pages, indexed)
		}
		shards, err := format.EncodeAdministrativeIndexPages(index)
		if err != nil || len(shards) != 1 {
			t.Fatalf("selected index: %v, %d shards", err, len(shards))
		}
		s.adminIndex = index
		s.root.AdministrativeIndex = shards[0].Ref
		s.recountChildren()
		if !s.selectedOutputComplete() {
			t.Fatal("capacity predecessor configuration invalid")
		}
		generatedInstallFixtureSupportReader(t, s)
		generatedVerifySelectedFixtureSlices(t, s)
		var plan transitionPlan
		plan.snapshot, plan.transition, plan.revision = contract.ID{93}, contract.ID{101}, contract.ID{94}
		indexes, err := s.mutationReceiptPageIndexes(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, index := range indexes {
			plan.supportPages[index] = contract.ID{95, byte(index)}
		}
		request := contract.SuccessionRequestCore{OperationKind: contract.SuccessionReplaceRecoveryBasis,
			DomainID: s.admission.domain, OperationID: contract.ID{96},
			PredecessorHeadRevisionID: contract.ID{99}}
		subjects := contract.GeneratorDescriptor{Digest: contract.ID{100}, Length: 4}
		projected, err := s.projectedSuccessionRoot(t.Context(), request, plan, subjects)
		if extra == 246 && (err != nil || projected.ChildCount != ordinaryChildPageLimit) ||
			extra >= 247 && !errors.Is(err, contract.ErrRecordCapacity) {
			t.Fatalf("%d additional pages: projected children %d, error %v", extra, projected.ChildCount, err)
		}
		if extra == 248 {
			request.OperationKind = contract.SuccessionReplaceAuthority
			request.ChangeMask = contract.SuccessionChangeNormalSigner
			request.ApprovalRole = contract.RecoverySigningRole
			preserved, err := s.projectedSuccessionRoot(t.Context(), request, plan, subjects)
			if err != nil || preserved.ChildCount != 253 {
				t.Fatalf("signer restoration at 253 children: %d, %v", preserved.ChildCount, err)
			}
		}
	}
}

// full_only: false
func TestSignerOnlyCandidatePreserves253ChildClosure(t *testing.T) {
	s := generatedEmptyPredecessor(t)
	for i := 0; i < 250; i++ {
		var scalar [4]byte
		binary.BigEndian.PutUint32(scalar[:], uint32(i))
		blob := contract.Hash(append([]byte("signer-capacity-blob"), scalar[:]...))
		fragment, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: 1, BlobID: blob, Count: 1,
			TotalLength: 1, WholeDigest: contract.Hash([]byte{1}), Payload: []byte{1}})
		if err != nil {
			t.Fatal(err)
		}
		fragmentID, err := contract.GeneratorFragmentID(blob, 0)
		if err != nil {
			t.Fatal(err)
		}
		physical := generatedFixtureFreeSupportIndex(t, s)
		object := contract.Hash(append([]byte("signer-capacity-page"), scalar[:]...))
		page, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: s.root.Domain, Object: object,
			Index: physical, Records: []contract.SupportRecord{{Kind: contract.GeneratedFragmentSupportKind, RecordID: fragmentID, Body: fragment}}})
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, s.root.Domain, object, physical, page)
		if err != nil {
			t.Fatal(err)
		}
		s.root.RequiredSupport = append(s.root.RequiredSupport, ref)
		s.root.RequiredSupportRecordCount++
	}
	s.recountChildren()
	if s.root.ChildCount != 253 {
		t.Fatal("boundary fixture has wrong selected child count")
	}
	root := s.root
	root.Snapshot = contract.Hash([]byte("signer-only successor snapshot"))
	root.Transition = contract.Hash([]byte("signer-only successor transition"))
	body, err := format.EncodeRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(format.RootKind, s.root.Domain, root.Snapshot, 0, body)
	if err != nil {
		t.Fatal(err)
	}
	candidate := &Candidate{session: s, head: format.Head{Core: format.HeadCore{Root: ref}, AuthKind: format.SuccessionAuth,
		Succession: &format.SuccessionProof{Subject: contract.SuccessionSubject{OperationKind: contract.SuccessionReplaceAuthority,
			ChangeMask: contract.SuccessionChangeNormalSigner, ApprovalRole: contract.RecoverySigningRole}}},
		objects: []objectImage{{ref: ref, body: body}}}
	if !ordinaryCandidateCapacity(candidate) {
		t.Fatal("signer-only candidate lost unchanged 253-child closure")
	}
	candidate.head.Succession.Subject.ChangeMask = contract.SuccessionChangeNormalSigner | contract.SuccessionChangeAuthorityKEK
	if ordinaryCandidateCapacity(candidate) {
		t.Fatal("receipt-writing succession used signer-only capacity allowance")
	}
}

// full_only: false
func TestSuccessionCapacityProjectionUsesExactIndexSizeNearShardBoundary(t *testing.T) {
	// Each release contributes 247 owner bytes, a 37-byte row summary,
	// and a 9-byte one-owner span. The 29 release pages are unchanged.
	for _, groups := range []int{7143, 7144} {
		s := successionReceiptCapacityFixture(t)
		s.root.Snapshot = contract.ID{111}
		descriptor := contract.GeneratorDescriptor{Digest: contract.ID{112}, Length: 4}
		for first := 0; first < groups; first += 255 {
			var rows []contract.SupportRecord
			for n := first; n < min(first+255, groups); n++ {
				var inbox contract.ID
				binary.BigEndian.PutUint32(inbox[28:], uint32(n+1))
				release := contract.PendingInboxReleaseRecord{Schema: contract.GeneratorRecordSchema,
					DomainID: s.admission.domain, InboxID: inbox, OriginalResultID: contract.ID{113},
					SelectedHandoffDigest: contract.ID{114}, HandoffRevisionID: contract.ID{115},
					CapacityReservation: descriptor, ObjectLength: 1, State: contract.GeneratedReleasePending}
				body, err := contract.EncodePendingInboxReleaseRecord(release)
				if err != nil {
					t.Fatal(err)
				}
				rows = append(rows, contract.SupportRecord{Kind: contract.PendingInboxReleaseSupportKind, RecordID: inbox, Body: body})
			}
			pageIndex := uint16(len(s.support))
			var scalar [2]byte
			binary.BigEndian.PutUint16(scalar[:], pageIndex)
			object := contract.Hash(append([]byte("succession-shard-boundary-page"), scalar[:]...))
			pageBody, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: s.admission.domain,
				Object: object, Index: pageIndex, Records: rows})
			if err != nil {
				t.Fatal(err)
			}
			page, err := format.InspectRequiredSupportPage(pageBody)
			if err != nil {
				t.Fatal(err)
			}
			ref, err := format.Reference(contract.RequiredSupportKind, s.admission.domain, object, pageIndex, pageBody)
			if err != nil {
				t.Fatal(err)
			}
			s.support = append(s.support, page)
			s.root.RequiredSupport = append(s.root.RequiredSupport, ref)
			s.root.RequiredSupportRecordCount += uint32(len(rows))
		}
		seed := *s
		seed.support = nil
		seed.root.RequiredSupport = nil
		seed.adminIndex = format.AdministrativeIndex{}
		pages := make([]format.RequiredSupportPage, len(s.support))
		for i, view := range s.support {
			pages[i] = format.RequiredSupportPage{Domain: view.Domain, Object: view.Object, Index: view.Index}
			for _, row := range view.Records {
				pages[i].Records = append(pages[i].Records, contract.SupportRecord(row))
			}
		}
		index, err := seed.buildAdministrativeIndex(context.Background(), s.root, pages, nil, nil, s)
		if err != nil {
			t.Fatal(err)
		}
		// Keep this predecessor just below one shard after the authenticated
		// row summaries and Duty kind are charged. The directed dependencies
		// make the index boundary exact without adding a physical page.
		index.Groups[0].RelatedGroupIndexes = make([]uint16, 24)
		for i := range index.Groups[0].RelatedGroupIndexes {
			index.Groups[0].RelatedGroupIndexes[i] = uint16(i + 1)
		}
		before, err := format.EncodeAdministrativeIndex(index)
		// Three source support pages have four rows and three spans.
		wantBefore := 115 + groups*293 + 29*108 + 3*108 + 4*37 + 3*7 + 24*2
		if err != nil || len(before) != wantBefore {
			t.Fatalf("predecessor index: %d bytes, %v", len(before), err)
		}
		shards, err := format.EncodeAdministrativeIndexPages(index)
		if err != nil || len(shards) != 1 {
			t.Fatalf("predecessor index shards: %d, %v", len(shards), err)
		}
		s.adminIndex = index
		s.root.AdministrativeIndex = shards[0].Ref
		s.recountChildren()
		if !s.selectedOutputComplete() {
			t.Fatal("capacity predecessor configuration invalid")
		}
		generatedInstallFixtureSupportReader(t, s)
		generatedVerifySelectedFixtureSlices(t, s)
		var plan transitionPlan
		plan.snapshot, plan.transition, plan.revision = contract.ID{116}, contract.ID{123}, contract.ID{117}
		changed, err := s.mutationReceiptPageIndexes(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, page := range changed {
			plan.supportPages[page] = contract.ID{118, byte(page)}
		}
		request := contract.SuccessionRequestCore{OperationKind: contract.SuccessionReplaceRecoveryBasis,
			DomainID: s.admission.domain, OperationID: contract.ID{119},
			PredecessorHeadRevisionID: contract.ID{122}}
		root, err := s.projectedSuccessionRoot(t.Context(), request, plan, descriptor)
		// The receipt rewrite separates the old mixed fragment page into two
		// pages. The added receipt makes five rows across four fixed pages.
		// Rebuilt groups discard the 24 synthetic predecessor-only edges.
		wantAfter := 115 + groups*293 + 29*108 + 4*108 + 5*37 + 4*7
		const shardHeader = 116
		const shardPayload = 2097152 - shardHeader
		wantShards := (wantAfter + shardPayload - 1) / shardPayload
		if err != nil || 1+len(root.AdministrativeIndexShards) != wantShards {
			t.Fatalf("%d groups: projected %d total shards, want %d: %v", groups, 1+len(root.AdministrativeIndexShards), wantShards, err)
		}
		refs := append([]format.Ref{root.AdministrativeIndex}, root.AdministrativeIndexShards...)
		for i, ref := range refs {
			wantLength := shardHeader + min(shardPayload, wantAfter-i*shardPayload)
			if int(ref.Length) != wantLength {
				t.Fatalf("%d groups: shard %d length %d, want %d", groups, i, ref.Length, wantLength)
			}
		}
	}
}

func successionReceiptCapacityFixture(t testing.TB) *StateSession {
	t.Helper()
	s := generatedEmptyPredecessor(t)
	receipts, _, _ := receiptStateFixtureForDomain(t, s.root.Domain)
	s.root.Generated = receipts.root.Generated
	s.root.Generated.Fragments = slices.Clone(receipts.root.Generated.Fragments)
	physical := make(map[uint16]uint16)
	for _, old := range receipts.support {
		page := old
		page.Index = generatedFixtureFreeSupportIndex(t, s)
		physical[old.Index] = page.Index
		s.support = append(s.support, page)
	}
	for i := range s.root.Generated.Fragments {
		s.root.Generated.Fragments[i].SupportPageIndex = physical[s.root.Generated.Fragments[i].SupportPageIndex]
	}
	generatedRefreshSupport(t, s)
	generatedVerifySelectedFixtureSlices(t, s)
	return s
}

// full_only: false
func TestSuccessionReceiptPlanCannotPublishCompleteSelection(t *testing.T) {
	s := successionReceiptCapacityFixture(t)
	before, err := s.receiptWindows(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	row := contract.CompactMutationReceiptPlan(before.Successes[0])
	row.OperationID = contract.ID{130}
	row.RequestIdentityDigest = contract.ID{}
	row.RequestedRevisionID, row.ObservedRevisionID = contract.ID{131}, contract.ID{131}
	delta := contract.MutationReceiptDeltaPlan{DomainID: s.root.Domain, OperationKind: row.OperationKind,
		AddedCount: 1, Before: before, NewReceipt: row}
	plan := transitionPlan{snapshot: contract.ID{132}, transition: contract.ID{133}, revision: contract.ID{131}}
	indexes, err := s.mutationReceiptPageIndexes(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range indexes {
		plan.supportPages[index] = contract.ID{134, byte(index)}
	}
	storage, err := s.encodeMutationReceiptSupport(t.Context(), plan, delta, contract.ID{})
	if err != nil {
		t.Fatal(err)
	}
	next := *s
	next.root.Snapshot, next.root.Transition = plan.snapshot, plan.transition
	storage.install(&next)
	if err := s.installAdministrativeIndex(t.Context(), &next, &Candidate{session: s}, &row); err != nil {
		t.Fatal("valid receipt plan refused", err)
	}
	if next.publicationProof != nil || !next.outputConfigurationRoot.IsZero() {
		t.Fatal("unsealed receipt plan published complete facts")
	}
	for _, page := range next.supportFacts {
		for _, fact := range page.rows {
			if fact.RecordID() == row.OperationID {
				t.Fatal("unsealed receipt acquired complete row fact")
			}
		}
	}
	unsealed := next
	if err := s.installAdministrativeIndex(t.Context(), &unsealed, &Candidate{session: s}); err == nil || unsealed.publicationProof != nil {
		t.Fatal("unsealed receipt plan qualified as a complete successor")
	}
	storage, err = s.encodeMutationReceiptSupport(t.Context(), plan, delta, contract.ID{135})
	if err != nil {
		t.Fatal(err)
	}
	storage.install(&next)
	if err := s.installAdministrativeIndex(t.Context(), &next, &Candidate{session: s}); err != nil {
		t.Fatal("sealed receipt successor refused", err)
	}
	if next.publicationProof == nil || !next.publicationProof.validFor(next.selectedImage()) || !next.selectedOutputComplete() {
		t.Fatal("sealed receipt successor lacks complete proof")
	}
	generatedInstallFixtureSupportReader(t, &next)
	generatedVerifySelectedFixtureSlices(t, &next)
	windows, err := next.receiptWindows(t.Context())
	if err != nil || len(windows.Successes) != 2 || windows.Successes[1].RequestIdentityDigest != (contract.ID{135}) {
		t.Fatal("sealed receipt identity was not selected", err)
	}
}

package core

import (
	"bytes"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func receiptStateFixture(t testing.TB) (*StateSession, contract.CompactMutationReceipt, contract.ID) {
	return receiptStateFixtureForDomain(t, contract.ID{1})
}

func receiptStateFixtureForDomain(t testing.TB, domain contract.ID) (*StateSession, contract.CompactMutationReceipt, contract.ID) {
	t.Helper()
	id := func(v byte) contract.ID { return contract.ID{v} }
	row := contract.CompactMutationReceipt{Schema: contract.MutationReceiptSchema, OperationKind: 36, StateResult: 1, EvidenceCeiling: 1,
		DomainID: domain, OperationID: id(2), RequestIdentityDigest: id(5),
		PredecessorRevisionID: id(6), RequestedRevisionID: id(7), ObservedRevisionID: id(7), CanonicalOutcome: 1,
		ChangedSubjects: contract.GeneratorDescriptor{Digest: id(8), Length: 80, Count: 2},
		CompleteResult:  contract.GeneratorDescriptor{Digest: id(9), Length: 8 + contract.MutationResultProjectionLength, Count: 1}}
	windows := contract.MutationReceiptWindows{DomainID: row.DomainID, Successes: []contract.CompactMutationReceipt{row}, Order: []contract.ID{row.OperationID}}
	indexes, err := windows.Indexes()
	if err != nil {
		t.Fatal(err)
	}
	successes, failures, order, err := indexes.Descriptors()
	if err != nil {
		t.Fatal(err)
	}
	indexID, err := contract.MutationReceiptIndexBlobID(row.DomainID, successes, failures, order)
	if err != nil {
		t.Fatal(err)
	}
	indexBody, err := contract.EncodeMutationReceiptIndexes(indexes)
	if err != nil {
		t.Fatal(err)
	}
	receipts, err := windows.SupportRecords()
	if err != nil {
		t.Fatal(err)
	}
	fragment := func(blob contract.ID, body []byte) contract.SupportRecord {
		b, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: 1, BlobID: blob, Count: 1, TotalLength: uint64(len(body)), WholeDigest: contract.Hash(body), Payload: body})
		if err != nil {
			t.Fatal(err)
		}
		record, err := contract.GeneratorFragmentID(blob, 0)
		if err != nil {
			t.Fatal(err)
		}
		return contract.SupportRecord{Kind: 3, RecordID: record, Body: b}
	}
	otherBlob := id(30)
	fragments := []contract.SupportRecord{fragment(indexID, indexBody), fragment(otherBlob, []byte("retained source bytes"))}
	s := &StateSession{admission: openAdmission{domain: row.DomainID}, root: format.Root{Domain: row.DomainID, Snapshot: id(32), Generated: format.EmptyGeneratedClosure(), GCPlans: contract.EmptyGCOwnersDescriptor()}}
	s.root.Generated.SuccessWindow, s.root.Generated.FailureWindow, s.root.Generated.ReceiptOrder = successes, failures, order
	for i, rows := range [][]contract.SupportRecord{receipts, fragments} {
		body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: row.DomainID, Object: id(byte(40 + i)), Index: uint16(i), Records: rows})
		if err != nil {
			t.Fatal(err)
		}
		page, err := format.InspectRequiredSupportPage(body)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, row.DomainID, page.Object, uint16(i), body)
		if err != nil {
			t.Fatal(err)
		}
		s.root.RequiredSupport = append(s.root.RequiredSupport, ref)
		s.root.RequiredSupportRecordCount += uint32(len(rows))
		s.support = append(s.support, page)
	}
	for i, row := range fragments {
		v, err := contract.InspectGeneratedFragment(row.Body)
		if err != nil {
			t.Fatal(err)
		}
		s.root.Generated.Fragments = append(s.root.Generated.Fragments, format.FragmentLocation{BlobID: v.BlobID, SupportPageIndex: 1, RowSlot: uint8(i)})
	}
	slices.SortFunc(s.root.Generated.Fragments, func(a, b format.FragmentLocation) int { return bytes.Compare(a.BlobID[:], b.BlobID[:]) })
	index := format.AdministrativeIndex{Domain: row.DomainID, Object: id(31), SliceSnapshot: s.root.Snapshot}
	for i, page := range s.support {
		indexed := format.AdministrativePage{Ref: s.root.RequiredSupport[i],
			Spans: []format.AdministrativeSpan{{First: 0, Count: uint16(len(page.Records)), Mandatory: true}}}
		for _, record := range page.Records {
			indexed.Rows = append(indexed.Rows, format.AdministrativeRowSummary{Kind: record.Kind,
				RecordID: record.RecordID, BodyLength: uint32(len(record.Body))})
		}
		index.Pages = append(index.Pages, indexed)
	}
	shards, err := format.EncodeAdministrativeIndexPages(index)
	if err != nil || len(shards) != 1 {
		t.Fatal("receipt fixture administrative index", err)
	}
	s.adminIndex, s.root.AdministrativeIndex = index, shards[0].Ref
	s.recountChildren()
	return s, row, otherBlob
}

// full_only: false
func TestSelectedMutationReceiptsResolveExactIndexesWithoutRecoveryGate(t *testing.T) {
	s, want, otherBlob := receiptStateFixture(t)
	windows, err := s.receiptWindows(t.Context())
	if err != nil || len(windows.Successes) != 1 || len(windows.Failures) != 0 || windows.Successes[0] != want || !slices.Equal(windows.Order, []contract.ID{want.OperationID}) {
		t.Fatalf("selected receipt: %v", err)
	}
	work, err := s.workSupportRecords(t.Context())
	if err != nil || len(work) != 1 || work[0].Kind != 3 {
		t.Fatalf("preserved live support: %v", err)
	}
	fragment, err := contract.InspectGeneratedFragment(work[0].Body)
	if err != nil || fragment.BlobID != otherBlob || string(fragment.Payload) != "retained source bytes" {
		t.Fatalf("receipt exclusion lost unrelated source bytes: %v", err)
	}
}

// full_only: false
func TestSelectedMutationReceiptsRejectIndexAndRecordDamage(t *testing.T) {
	for name, damage := range map[string]func(*StateSession){
		"missing index": func(s *StateSession) { s.support = s.support[:1] },
		"unindexed receipt": func(s *StateSession) {
			empty := contract.EmptyGeneratorIndexes()
			s.root.Generated.SuccessWindow = empty[2]
		},
		"missing order":        func(s *StateSession) { s.root.Generated.ReceiptOrder = contract.GeneratorDescriptor{} },
		"empty order":          func(s *StateSession) { s.root.Generated.ReceiptOrder = contract.EmptyGeneratorIndexes()[4] },
		"wrong order digest":   func(s *StateSession) { s.root.Generated.ReceiptOrder.Digest[0] ^= 0xff },
		"wrong index digest":   func(s *StateSession) { s.root.Generated.SuccessWindow.Digest[0] ^= 0xff },
		"wrong directory slot": func(s *StateSession) { s.root.Generated.Fragments[0].RowSlot = 2 },
		"missing receipt":      func(s *StateSession) { s.support[0].Records = nil },
		"duplicate receipt": func(s *StateSession) {
			s.support[0].Records = append(s.support[0].Records, s.support[0].Records[0])
			s.root.RequiredSupportRecordCount++
		},
		"wrong receipt identity": func(s *StateSession) { s.support[0].Records[0].RecordID[0] ^= 0xff },
		"changed fragment": func(s *StateSession) {
			b := bytes.Clone(s.support[1].Records[0].Body)
			b[len(b)-1] ^= 1
			s.support[1].Records[0].Body = b
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, _, _ := receiptStateFixture(t)
			damage(s)
			if _, err := s.receiptWindows(t.Context()); err == nil {
				t.Fatal("accepted invalid selected receipt relation")
			}
			if _, err := s.workSupportRecords(t.Context()); err == nil {
				t.Fatal("accepted invalid receipt exclusion")
			}
		})
	}
}

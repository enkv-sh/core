package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestRecipientReplacementProjectsExactOrdinaryChildMargin(t *testing.T) {
	for _, extra := range []int{247, 248} {
		s := generatedEmptyPredecessor(t)
		for n := 0; n < extra; n++ {
			var scalar [4]byte
			binary.BigEndian.PutUint32(scalar[:], uint32(n))
			blob := sha256.Sum256(append([]byte("replacement-capacity-blob"), scalar[:]...))
			body, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: 1, BlobID: blob, Count: 1,
				TotalLength: 1, WholeDigest: contract.Hash([]byte{1}), Payload: []byte{1}})
			if err != nil {
				t.Fatal(err)
			}
			fragmentID, err := contract.GeneratorFragmentID(blob, 0)
			if err != nil {
				t.Fatal(err)
			}
			physical := generatedFixtureFreeSupportIndex(t, s)
			object := sha256.Sum256(append([]byte("replacement-capacity-page"), scalar[:]...))
			pageBody, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: s.root.Domain,
				Object: object, Index: physical, Records: []contract.SupportRecord{{Kind: contract.GeneratedFragmentSupportKind, RecordID: fragmentID, Body: body}}})
			if err != nil {
				t.Fatal(err)
			}
			view, err := format.InspectRequiredSupportPage(pageBody)
			if err != nil {
				t.Fatal(err)
			}
			ref, err := format.Reference(contract.RequiredSupportKind, s.root.Domain, object, physical, pageBody)
			if err != nil {
				t.Fatal(err)
			}
			s.support = append(s.support, view)
			s.root.RequiredSupport = append(s.root.RequiredSupport, ref)
			s.root.RequiredSupportRecordCount++
			s.root.Generated.Fragments = append(s.root.Generated.Fragments,
				format.FragmentLocation{BlobID: blob, SupportPageIndex: physical, RowSlot: 0})
		}
		slices.SortFunc(s.root.Generated.Fragments, func(a, b format.FragmentLocation) int {
			return bytes.Compare(a.BlobID[:], b.BlobID[:])
		})
		index := format.AdministrativeIndex{Domain: s.root.Domain, Object: contract.Hash([]byte("replacement-capacity-index")), SliceSnapshot: s.root.Snapshot}
		for i := range s.support {
			index.Pages = append(index.Pages, format.AdministrativePage{Ref: s.root.RequiredSupport[i],
				Spans: []format.AdministrativeSpan{{First: 0, Count: 1, Mandatory: true}},
				Rows: []format.AdministrativeRowSummary{{Kind: s.support[i].Records[0].Kind,
					RecordID: s.support[i].Records[0].RecordID, BodyLength: uint32(len(s.support[i].Records[0].Body))}}})
		}
		shards, err := format.EncodeAdministrativeIndexPages(index)
		if err != nil || len(shards) != 1 {
			t.Fatalf("index for %d support pages: %d shards, %v", extra, len(shards), err)
		}
		s.adminIndex = index
		s.root.AdministrativeIndex = shards[0].Ref
		s.recountChildren()
		var p transitionPlan
		p.snapshot, p.transition = contract.Hash([]byte("replacement next snapshot")), contract.Hash([]byte("replacement next transition"))
		p.operation, p.revision = contract.Hash([]byte("replacement capacity operation")), contract.Hash([]byte("replacement capacity revision"))
		receiptPages, err := s.mutationReceiptPageIndexes(t.Context())
		if err != nil || len(receiptPages) != 2 {
			t.Fatal("receipt/index reservation", receiptPages, err)
		}
		for _, index := range receiptPages {
			p.supportPages[index] = sha256.Sum256(binary.BigEndian.AppendUint16([]byte("replacement receipt page"), index))
		}
		subject, err := contract.ChangedSubjectIdentityID(s.root.Domain, contract.ChangedSubjectRecipient, generatedVectorID(12), contract.ID{})
		if err != nil {
			t.Fatal(err)
		}
		subjects, err := contract.ChangedSubjectDescriptor([]contract.ChangedSubjectIdentity{{Kind: contract.ChangedSubjectRecipient, Change: contract.ChangedSubjectUpdated, Identity: subject}})
		if err != nil {
			t.Fatal(err)
		}
		projected, err := s.projectedRecipientReplacementRoot(context.Background(), p, subjects, contract.Hash([]byte("replacement capacity request")))
		if extra == 247 && (err != nil || projected.ChildCount != ordinaryChildPageLimit ||
			len(projected.RequiredSupport) != extra+3 || len(projected.AdministrativeIndexShards) != 0 ||
			projected.Generated.SuccessWindow.Count != 1 || projected.Generated.FailureWindow.Count != 0) ||
			extra == 248 && !errors.Is(err, contract.ErrRecordCapacity) {
			t.Fatalf("%d support pages: projected children %d, error %v", extra, projected.ChildCount, err)
		}
	}
}

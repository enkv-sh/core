package core

import (
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestAdministrativeReceiptReadKeepsOptionalFragmentOpaque(t *testing.T) {
	s, receipt, _ := receiptStateFixture(t)
	other := contract.SupportRecord(s.support[1].Records[1])
	mandatory := contract.SupportRecord(s.support[1].Records[0])
	write := func(object contract.ID, index uint16, rows []contract.SupportRecord) (format.Ref, format.RequiredSupportPageView) {
		t.Helper()
		body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: s.root.Domain, Object: object, Index: index, Records: rows})
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, s.root.Domain, object, index, body)
		if err != nil {
			t.Fatal(err)
		}
		view, err := format.InspectRequiredSupportPage(body)
		if err != nil {
			t.Fatal(err)
		}
		return ref, view
	}
	mandatoryRef, mandatoryPage := write(contract.ID{51}, 1, []contract.SupportRecord{mandatory})
	optionalRef, _ := write(contract.ID{52}, 2, []contract.SupportRecord{other})
	s.root.RequiredSupport[1] = mandatoryRef
	s.root.RequiredSupport = append(s.root.RequiredSupport, optionalRef)
	s.support[1] = mandatoryPage
	s.support = append(s.support, format.RequiredSupportPageView{Domain: s.root.Domain, Object: optionalRef.Object, Index: 2})
	otherFragment, err := contract.InspectGeneratedFragment(other.Body)
	if err != nil {
		t.Fatal(err)
	}
	for i := range s.root.Generated.Fragments {
		if s.root.Generated.Fragments[i].BlobID == otherFragment.BlobID {
			s.root.Generated.Fragments[i].SupportPageIndex = 2
			s.root.Generated.Fragments[i].RowSlot = 0
		}
	}
	s.adminIndex.Pages[1].Ref = mandatoryRef
	s.adminIndex.Pages[1].Spans[0].Count = 1
	s.adminIndex.Pages[1].Rows = s.adminIndex.Pages[1].Rows[:1]
	empty := contract.GeneratorDescriptor{Digest: contract.ID{53}, Length: 4}
	s.adminIndex.Groups = []format.AdministrativeGroup{{GroupID: contract.ID{54}, OwnerID: contract.ID{55}, TargetID: contract.ID{56},
		OwnerKind: format.AdministrativeGeneratedParent, SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing,
		Affected: empty, Dependencies: empty, Disposable: empty}}
	s.adminIndex.Pages = append(s.adminIndex.Pages, format.AdministrativePage{Ref: optionalRef,
		Spans: []format.AdministrativeSpan{{First: 0, Count: 1, GroupIndexes: []uint16{0}}},
		Rows:  []format.AdministrativeRowSummary{{Kind: other.Kind, RecordID: other.RecordID, BodyLength: uint32(len(other.Body))}}})
	if !s.adminIndex.Valid() {
		t.Fatal("optional summary is invalid")
	}
	if _, err := s.receiptWindowsFromValidatedSupport(); err == nil {
		t.Fatal("complete reader accepted unreadable optional fragment")
	}
	windows, err := s.receiptWindowsFromAdministrativeSupport()
	if err != nil || len(windows.Successes) != 1 || windows.Successes[0] != receipt {
		t.Fatal("administrative receipt reader lost mandatory receipt", err)
	}
	s.adminIndex.Pages[1].Spans[0].Mandatory = false
	if _, err := s.receiptWindowsFromAdministrativeSupport(); err == nil {
		t.Fatal("optional receipt index fragment was admitted")
	}
}

// full_only: false
func TestAdministrativeConfigurationSelectionKeepsOpaqueFacts(t *testing.T) {
	for _, shape := range []string{"pure", "mixed", "sparse"} {
		t.Run(shape, func(t *testing.T) {
			makeState := func() *StateSession {
				t.Helper()
				base := generatedEmptyPredecessor(t)
				next := *base
				configuration := contract.SupportRecord(base.support[0].Records[0])
				rows := []contract.SupportRecord{configuration}
				if shape != "pure" {
					receipt, _, _ := receiptStateFixtureForDomain(t, base.root.Domain)
					rows = []contract.SupportRecord{contract.SupportRecord(receipt.support[0].Records[0]), configuration}
				}
				body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: base.root.Domain, Object: generatedVectorID(97), Index: 7, Records: rows})
				if err != nil {
					t.Fatal(err)
				}
				ref, err := format.Reference(contract.RequiredSupportKind, base.root.Domain, generatedVectorID(97), 7, body)
				if err != nil {
					t.Fatal(err)
				}
				view, err := format.InspectRequiredSupportPage(body)
				if err != nil {
					t.Fatal(err)
				}
				next.root.RequiredSupport = []format.Ref{ref}
				next.root.RequiredSupportRecordCount = uint32(len(rows))
				next.support = []format.RequiredSupportPageView{view}
				next.adminIndex = base.adminIndex
				page := format.AdministrativePage{Ref: ref, Spans: []format.AdministrativeSpan{{First: 0, Count: uint16(len(rows)), Mandatory: true}}}
				for _, row := range rows {
					page.Rows = append(page.Rows, format.AdministrativeRowSummary{Kind: row.Kind, RecordID: row.RecordID, BodyLength: uint32(len(row.Body))})
				}
				next.adminIndex.Pages = []format.AdministrativePage{page}
				bind := func(prior *StateSession) {
					shards, err := format.EncodeAdministrativeIndexPages(next.adminIndex)
					if err != nil || len(shards) != 1 {
						t.Fatal("configuration index", err)
					}
					next.root.AdministrativeIndex = shards[0].Ref
					next.recountChildren()
					if err := prior.bindPreservedOutputConfiguration(&next); err != nil {
						t.Fatal("configuration facts", err)
					}
				}
				bind(base)
				if shape == "sparse" {
					prior := next
					next.support = []format.RequiredSupportPageView{{Domain: view.Domain, Object: view.Object, Index: view.Index, Records: []contract.SupportRecordView{view.Records[1]}}}
					next.adminIndex.Pages = []format.AdministrativePage{{Ref: ref, Spans: []format.AdministrativeSpan{{First: 1, Count: 1, Mandatory: true}}, Rows: slices.Clone(page.Rows[1:])}}
					next.root.RequiredSupportRecordCount = 1
					bind(&prior)
				}
				return &next
			}
			backed := makeState()
			want, err := backed.administrativeSelectedRows(backed.adminIndex.Pages[0])
			if err != nil {
				t.Fatal("body-backed configuration", err)
			}
			opaque := makeState()
			for i := range opaque.support[0].Records {
				if opaque.support[0].Records[i].Kind == contract.OutputConfigurationSliceSupportKind {
					opaque.support[0].Records[i].Body = nil
				}
			}
			got, err := opaque.administrativeSelectedRows(opaque.adminIndex.Pages[0])
			if err != nil || !slices.Equal(got, want) {
				t.Fatal("opaque configuration lost exact selected rows", got, want, err)
			}
			kept, err := opaque.administrativeWorkWithoutOldReceipts(opaque.adminIndex)
			ordinal := uint16(0)
			if shape != "pure" {
				ordinal = 1
			}
			if err != nil || len(kept.Pages) != 1 || kept.Pages[0].Ref != opaque.root.RequiredSupport[0] || len(kept.Pages[0].Rows) != 1 || kept.Pages[0].Rows[0].Kind != contract.OutputConfigurationSliceSupportKind || len(kept.Pages[0].Spans) != 1 || kept.Pages[0].Spans[0].First != ordinal || !opaque.selectedOutputComplete() {
				t.Fatal("receipt removal changed configuration identity or physical ordinal", kept, err)
			}
			for _, damage := range []string{"missing-facts", "fact-ref", "row-id", "row-kind", "ordinal", "proof", "optional", "owner", "body"} {
				t.Run(damage, func(t *testing.T) {
					bad := makeState()
					logical := len(bad.support[0].Records) - 1
					bad.support[0].Records[logical].Body = nil
					switch damage {
					case "missing-facts":
						bad.supportFacts = nil
					case "fact-ref":
						bad.supportFacts[0].ref.Digest[0] ^= 1
					case "row-id":
						bad.support[0].Records[logical].RecordID[0] ^= 1
					case "row-kind":
						bad.support[0].Records[logical].Kind = contract.MutationReceiptSupportKind
					case "ordinal":
						bad.supportFacts[0].ordinals[logical]++
					case "proof":
						bad.outputConfigurationRoot = contract.ID{}
					case "optional":
						bad.adminIndex.Pages[0].Spans[0].Mandatory = false
					case "owner":
						bad.adminIndex.Pages[0].Spans[0].GroupIndexes = []uint16{0}
					case "body":
						bad.support[0].Records[logical].Body = []byte("different body")
					}
					if _, err := bad.administrativeSelectedRows(bad.adminIndex.Pages[0]); err == nil {
						t.Fatal("damaged selected configuration accepted")
					}
				})
			}
		})
	}
}

package core

import (
	"bytes"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func workDescriptorFixture(t *testing.T) (*StateSession, []contract.SupportRecord) {
	t.Helper()
	domain := contract.Hash([]byte("work descriptor domain"))
	id := func(label string) contract.ID { return contract.Hash([]byte(label)) }
	receipt := contract.CompactMutationReceipt{Schema: contract.MutationReceiptSchema, OperationKind: 36, StateResult: 1, EvidenceCeiling: 1,
		DomainID: domain, OperationID: id("operation"),
		RequestIdentityDigest: id("request"), PredecessorRevisionID: id("before"), RequestedRevisionID: id("after"), ObservedRevisionID: id("after"),
		CanonicalOutcome: 1, ChangedSubjects: contract.GeneratorDescriptor{Digest: id("changed"), Length: 80, Count: 2},
		CompleteResult: contract.GeneratorDescriptor{Digest: id("complete"), Length: 655, Count: 1}}
	receipt.SummaryCounts[4] = 1
	windows := contract.MutationReceiptWindows{DomainID: domain, Successes: []contract.CompactMutationReceipt{receipt}, Order: []contract.ID{receipt.OperationID}}
	receipts, err := windows.SupportRecords()
	if err != nil {
		t.Fatal(err)
	}
	indexes, err := windows.Indexes()
	if err != nil {
		t.Fatal(err)
	}
	successes, failures, order, err := indexes.Descriptors()
	if err != nil {
		t.Fatal(err)
	}
	index, err := contract.MutationReceiptIndexBlobID(domain, successes, failures, order)
	if err != nil {
		t.Fatal(err)
	}
	indexBody, err := contract.EncodeMutationReceiptIndexes(indexes)
	if err != nil {
		t.Fatal(err)
	}
	fragment := func(blob contract.ID, payload []byte) contract.SupportRecord {
		body, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: 1, BlobID: blob, Count: 1,
			TotalLength: uint64(len(payload)), WholeDigest: contract.Hash(payload), Payload: payload})
		if err != nil {
			t.Fatal(err)
		}
		record, err := contract.GeneratorFragmentID(blob, 0)
		if err != nil {
			t.Fatal(err)
		}
		return contract.SupportRecord{Kind: contract.GeneratedFragmentSupportKind, RecordID: record, Body: body}
	}
	image, err := contract.EncodeOutputConfiguration(contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: domain})
	if err != nil {
		t.Fatal(err)
	}
	descriptor, parts, err := contract.SplitOutputConfiguration(domain, image)
	if err != nil {
		t.Fatal(err)
	}
	configBody, err := contract.EncodeOutputConfigurationSlice(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	configID, err := contract.OutputConfigurationSliceID(domain, descriptor.ConfigurationDigest, 0)
	if err != nil {
		t.Fatal(err)
	}
	work := []contract.SupportRecord{fragment(id("work blob"), []byte("live work")),
		{Kind: contract.OutputConfigurationSliceSupportKind, RecordID: configID, Body: configBody}}
	s := &StateSession{}
	s.root.Domain, s.admission.domain = domain, domain
	s.root.Generated = format.EmptyGeneratedClosure()
	s.root.Generated.SuccessWindow, s.root.Generated.FailureWindow, s.root.Generated.ReceiptOrder = successes, failures, order
	s.fragmentFacts = make(map[format.FragmentLocation]selectedFragmentFact)
	pages := [][]contract.SupportRecord{{work[0], fragment(index, indexBody)}, append(slices.Clone(receipts), work[1])}
	for p, rows := range pages {
		slices.SortFunc(rows, func(a, b contract.SupportRecord) int {
			if a.Kind < b.Kind {
				return -1
			}
			if a.Kind > b.Kind {
				return 1
			}
			return bytes.Compare(a.RecordID[:], b.RecordID[:])
		})
		physical := uint16(7 + 2*p)
		object := contract.Hash([]byte{byte(physical)})
		body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: domain, Object: object, Index: physical, Records: rows})
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, domain, object, physical, body)
		if err != nil {
			t.Fatal(err)
		}
		view, err := format.InspectRequiredSupportPage(body)
		if err != nil {
			t.Fatal(err)
		}
		s.root.RequiredSupport = append(s.root.RequiredSupport, ref)
		s.support = append(s.support, view)
		page := selectedSupportPageFacts{ref: ref}
		for i, row := range rows {
			fact, err := contract.InspectSupportRecordDigest(domain, row)
			if err != nil {
				t.Fatal(err)
			}
			page.rows = append(page.rows, fact)
			page.ordinals = append(page.ordinals, uint16(i))
			if row.Kind == contract.GeneratedFragmentSupportKind {
				v, err := contract.InspectGeneratedFragment(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				location := format.FragmentLocation{BlobID: v.BlobID, FragmentIndex: v.Index, SupportPageIndex: physical, RowSlot: uint8(i)}
				s.fragmentFacts[location] = selectedFragmentFact{ref: ref, row: fact, physical: uint16(i), logical: uint16(i), blob: v.BlobID, index: v.Index}
			}
		}
		s.supportFacts = append(s.supportFacts, page)
	}
	return s, work
}

// full_only: false
func TestWorkSupportDescriptorRetainsCompletePageFactsWithoutFragmentDirectory(t *testing.T) {
	for _, mode := range []string{"body-backed", "opaque-configuration", "opaque-fragments"} {
		t.Run(mode, func(t *testing.T) {
			s, work := workDescriptorFixture(t)
			want, err := contract.GeneratorAuthorityWorkDescriptor(s.root.Domain, work)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "body-backed" {
				s.supportFacts, s.fragmentFacts = nil, nil
			}
			if mode == "opaque-configuration" {
				s.fragmentFacts = nil
				for p := range s.support {
					for i := range s.support[p].Records {
						if s.support[p].Records[i].Kind == contract.OutputConfigurationSliceSupportKind {
							s.support[p].Records[i].Body = nil
						}
					}
				}
			}
			if mode == "opaque-fragments" {
				for p := range s.support {
					for i := range s.support[p].Records {
						s.support[p].Records[i].Body = nil
					}
				}
			}
			rows := make([]contract.SupportRecord, len(work))
			copy(rows, work)
			if mode != "body-backed" {
				for i := range rows {
					rows[i].Body = nil
				}
			}
			got, err := s.workSupportDescriptor(rows)
			if err != nil || got != want {
				t.Fatal("complete authenticated work descriptor", got, want, err)
			}
		})
	}
}

// full_only: false
func TestWorkSupportDescriptorRefusesDamagedRetainedFacts(t *testing.T) {
	cases := map[string]func(*StateSession){
		"missing-root-ref":          func(s *StateSession) { s.root.RequiredSupport = nil },
		"partial-page-facts":        func(s *StateSession) { s.supportFacts = s.supportFacts[:1] },
		"missing-all-facts":         func(s *StateSession) { s.supportFacts, s.fragmentFacts = nil, nil },
		"uninspected-row-fact":      func(s *StateSession) { s.supportFacts[0].rows[0] = contract.SupportRecordDigest{} },
		"missing-page-facts":        func(s *StateSession) { s.supportFacts = nil },
		"missing-row-fact":          func(s *StateSession) { s.supportFacts[0].rows = s.supportFacts[0].rows[1:] },
		"missing-ordinal":           func(s *StateSession) { s.supportFacts[0].ordinals = nil },
		"changed-page-ref":          func(s *StateSession) { s.supportFacts[0].ref.Digest = contract.Hash([]byte("wrong ref")) },
		"changed-row-id":            func(s *StateSession) { s.support[0].Records[0].RecordID = contract.Hash([]byte("wrong row")) },
		"changed-row-kind":          func(s *StateSession) { s.support[0].Records[0].Kind = contract.OutputConfigurationSliceSupportKind },
		"missing-fragment-identity": func(s *StateSession) { s.fragmentFacts = nil },
		"changed-fragment-ref": func(s *StateSession) {
			for location, fact := range s.fragmentFacts {
				fact.ref.Digest = contract.Hash([]byte("wrong fragment ref"))
				s.fragmentFacts[location] = fact
			}
		},
		"changed-fragment-ordinal": func(s *StateSession) {
			for location, fact := range s.fragmentFacts {
				fact.physical++
				s.fragmentFacts[location] = fact
			}
		},
	}
	for name, damage := range cases {
		t.Run(name, func(t *testing.T) {
			s, rows := workDescriptorFixture(t)
			for p := range s.support {
				for i := range s.support[p].Records {
					s.support[p].Records[i].Body = nil
				}
			}
			damage(s)
			if got, err := s.workSupportDescriptor(rows); err != contract.ErrRecord || got != (contract.GeneratorDescriptor{}) {
				t.Fatal("damaged facts accepted", got, err)
			}
		})
	}
}

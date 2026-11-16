package core

import (
	"slices"
	"strconv"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestNormalSupportPhysicalIndexesPreserveSparseRefsAndMakeRoom(t *testing.T) {
	domain := contract.Hash([]byte("normal support physical domain"))
	fragment := func(label string) (contract.SupportRecord, contract.GeneratedFragmentView) {
		blob := contract.Hash([]byte(label))
		payload := []byte(label)
		body, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: contract.GeneratorRecordSchema,
			BlobID: blob, Index: 0, Count: 1, TotalLength: uint64(len(payload)), WholeDigest: contract.Hash(payload), Payload: payload})
		if err != nil {
			t.Fatal(err)
		}
		id, err := contract.GeneratorFragmentID(blob, 0)
		if err != nil {
			t.Fatal(err)
		}
		view, err := contract.InspectGeneratedFragment(body)
		if err != nil {
			t.Fatal(err)
		}
		return contract.SupportRecord{Kind: contract.GeneratedFragmentSupportKind, RecordID: id, Body: body}, view
	}
	state := &StateSession{}
	state.root.Domain = domain
	state.fragmentFacts = make(map[format.FragmentLocation]selectedFragmentFact)
	fragments := make(map[contract.ID]selectedFragmentFact)
	var old []contract.SupportRecord
	for i, index := range []uint16{7, 9} {
		row, decoded := fragment([]string{"first", "second"}[i])
		old = append(old, contract.SupportRecord{Kind: row.Kind, RecordID: row.RecordID})
		fact, err := contract.InspectSupportRecordDigest(domain, row)
		if err != nil {
			t.Fatal(err)
		}
		physical := uint16(i % 2)
		physicalRows := []contract.SupportRecord{row}
		if physical == 1 {
			filler, _ := fragment("unselected filler")
			physicalRows = []contract.SupportRecord{filler, row}
		}
		object := contract.Hash([]byte{byte(index + 1)})
		body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{
			Domain: domain, Object: object, Index: index, Records: physicalRows})
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, domain, object, index, body)
		if err != nil {
			t.Fatal(err)
		}
		view, err := format.InspectRequiredSupportPage(body)
		if err != nil {
			t.Fatal(err)
		}
		view.Records = view.Records[physical : physical+1]
		view.Records[0].Body = nil
		state.root.RequiredSupport = append(state.root.RequiredSupport, ref)
		state.support = append(state.support, view)
		state.supportFacts = append(state.supportFacts, selectedSupportPageFacts{ref: ref,
			rows: []contract.SupportRecordDigest{fact}, ordinals: []uint16{physical}})
		location := format.FragmentLocation{BlobID: decoded.BlobID, FragmentIndex: decoded.Index,
			SupportPageIndex: index, RowSlot: 0}
		state.root.Generated.Fragments = append(state.root.Generated.Fragments, location)
		selected := selectedFragmentFact{ref: ref, row: fact, physical: physical, logical: 0,
			blob: decoded.BlobID, index: decoded.Index, count: decoded.Count, total: decoded.TotalLength,
			whole: decoded.WholeDigest, offset: decoded.Offset, payloadLength: uint32(len(decoded.Payload))}
		state.fragmentFacts[location] = selected
		fragments[row.RecordID] = selected
	}
	newRow, _ := fragment("new owner before fragments")
	newFact, err := contract.InspectSupportRecordDigest(domain, newRow)
	if err != nil {
		t.Fatal(err)
	}
	packed := [][]contract.SupportRecord{{newRow}, {old[0]}, {old[1]}}
	facts := [][]contract.SupportRecordDigest{{newFact}, {fragments[old[0].RecordID].row}, {fragments[old[1].RecordID].row}}
	plan, err := normalSupportPhysicalPages(state, packed, facts, fragments)
	if err != nil || len(plan) != 3 {
		t.Fatal("normal page plan", err)
	}
	if !slices.Equal([]uint16{plan[0].index, plan[1].index, plan[2].index}, []uint16{0, 7, 9}) ||
		!plan[0].retained.ref.Object.IsZero() || plan[1].retained.ref != state.root.RequiredSupport[0] ||
		plan[2].retained.ref != state.root.RequiredSupport[1] || plan[1].retained.ordinals[0] != 0 ||
		plan[2].retained.ordinals[0] != 1 {
		t.Fatal("inserted owner copied a sparse fragment page or lost its physical row", plan)
	}
}

// full_only: false
func TestNormalSupportFragmentFactsBindNewRefAndPhysicalOrdinal(t *testing.T) {
	domain := contract.Hash([]byte("normal changed fragment domain"))
	blob := contract.Hash([]byte("normal changed fragment blob"))
	payload := []byte("exact payload")
	body, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: contract.GeneratorRecordSchema,
		BlobID: blob, Index: 0, Count: 1, TotalLength: uint64(len(payload)), WholeDigest: contract.Hash(payload), Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	id, err := contract.GeneratorFragmentID(blob, 0)
	if err != nil {
		t.Fatal(err)
	}
	filler := contract.SupportRecord{Kind: contract.GeneratedFragmentSupportKind, RecordID: id, Body: body}
	// The fragment occupies physical row one in a newly encoded page. Its
	// Root directory row slot is one as well; neither is a compact Root slot.
	rows := []contract.SupportRecord{{Kind: contract.GeneratedFragmentSupportKind, RecordID: contract.Hash([]byte("other fragment")), Body: body}, filler}
	// The unrelated row needs its own valid fragment identity.
	otherBlob := contract.Hash([]byte("other blob"))
	rows[0].Body, err = contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: contract.GeneratorRecordSchema,
		BlobID: otherBlob, Index: 0, Count: 1, TotalLength: uint64(len(payload)), WholeDigest: contract.Hash(payload), Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	rows[0].RecordID, err = contract.GeneratorFragmentID(otherBlob, 0)
	if err != nil {
		t.Fatal(err)
	}
	object := contract.Hash([]byte("normal changed fragment page"))
	encoded, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{
		Domain: domain, Object: object, Index: 11, Records: rows})
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(contract.RequiredSupportKind, domain, object, 11, encoded)
	if err != nil {
		t.Fatal(err)
	}
	view, err := format.InspectRequiredSupportPage(encoded)
	if err != nil {
		t.Fatal(err)
	}
	page := selectedSupportPageFacts{ref: ref, rows: make([]contract.SupportRecordDigest, len(rows)),
		ordinals: []uint16{0, 1}}
	for i, row := range rows {
		page.rows[i], err = contract.InspectSupportRecordDigest(domain, row)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !normalSupportPageMatchesFacts(domain, view, page.rows) {
		t.Fatal("new page facts do not bind encoded bytes")
	}
	next := &StateSession{support: []format.RequiredSupportPageView{view},
		supportFacts: []selectedSupportPageFacts{page}}
	next.root.Domain = domain
	next.root.RequiredSupport = []format.Ref{ref}
	location := format.FragmentLocation{BlobID: blob, FragmentIndex: 0, SupportPageIndex: 11, RowSlot: 1}
	next.root.Generated.Fragments = []format.FragmentLocation{location}
	if !next.bindNormalGeneratedFragmentFacts(nil) {
		t.Fatal("new fragment facts not bound")
	}
	fact := next.fragmentFacts[location]
	if fact.ref != ref || fact.row != page.rows[1] || fact.physical != 1 || fact.logical != 1 ||
		fact.blob != blob || fact.index != 0 || fact.payloadLength != uint32(len(payload)) {
		t.Fatal("new fragment fact lost Ref, physical row, or body identity")
	}
}

// full_only: false
func TestNormalHandoffCapacityUsesSuccessorRecipientCount(t *testing.T) {
	s, _, _ := observationSelectedPredecessor(t)
	input := []ApplyEntryInput{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "plain", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain,
		Recipients: []contract.ID{s.admission.recipient}, InputBytes: []byte("changed")}}
	for _, count := range []int{7, 8, 9, 16, 17} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			comparison, result := s.compareEntryInputs(input)
			if comparison == nil || result.Outcome != ObservedCurrent {
				t.Fatal("normal comparison", result)
			}
			// Comparison owns the admitted successor registry. The formula
			// must not use the predecessor's recipient population.
			comparison.recipients = make([]contract.ApplyRecipientInput, count)
			witness, err := s.generatedSupportTransition(t.Context(), comparison, nil)
			if err != nil || witness == nil {
				t.Fatal("normal capacity witness", err)
			}
			want := contract.GeneratorCapacityGroup{MaxCount: uint64(count), MaxPages: uint32((count + 7) / 8), MaxFramedBytes: uint64(count) * 1855}
			if got := witness.Groups[contract.GeneratorCapacityCurrentRecipients]; got != want {
				t.Fatal("normal handoff bound does not cover complete successor registry", got, want)
			}
		})
	}
}

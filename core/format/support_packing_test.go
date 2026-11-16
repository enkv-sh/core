package format

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedSliceCarriersFitGraphAllocation(t *testing.T) {
	const count = 4*1408 + 512
	rows := make([][]byte, count)
	for i := range rows {
		id := ID{}
		binary.BigEndian.PutUint32(id[28:], uint32(i+1))
		var err error
		rows[i], err = contract.EncodeGeneratorSliceLocation(contract.GeneratorSliceLocation{Schema: 1,
			ContentKind: 1, ContentID: id, BlobID: fid(2), Length: 1, Digest: fid(3)})
		if err != nil {
			t.Fatal(err)
		}
	}
	d, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorSlices, rows)
	if err != nil {
		t.Fatal(err)
	}
	carriers := make([]contract.SupportRecord, len(rows))
	for i, row := range rows {
		c := contract.GeneratorVectorCarrier{Schema: 1, DomainID: fid(1), OwnerKind: contract.GeneratorSnapshotOwner,
			OwnerID: fid(4), VectorKind: contract.GeneratorVectorSlices, Ordinal: uint32(i), Vector: d, Row: row}
		body, err := contract.EncodeGeneratorVectorCarrier(c)
		if err != nil {
			t.Fatal(err)
		}
		id, err := contract.GeneratorVectorCarrierID(c)
		if err != nil {
			t.Fatal(err)
		}
		carriers[i] = contract.SupportRecord{Kind: 14, RecordID: id, Body: body}
	}
	groups := []RequiredSupportGroup{
		{Class: GraphIndexSupport, Owner: fid(4), Records: carriers},
		{Class: GraphFragmentSupport, Owner: fid(5), Records: packedFragments(t, fid(5), 5_431_424)},
	}
	pages, err := PackRequiredSupportRows(fid(1), groups, 252)
	if err != nil || len(pages) != 4 {
		t.Fatal("graph and direct indexes must fit four pages", len(pages), err)
	}
	for i, rows := range pages {
		b, err := EncodeRequiredSupportPage(RequiredSupportPage{Domain: fid(1), Object: fid(byte(10 + i)), Index: uint16(i), Records: rows})
		if err != nil {
			t.Fatal(err)
		}
		// 75-byte page framing and 157+111 bytes per independently bounded
		// carrier; this expectation does not use encoded lengths as input.
		if i == 0 && len(b) != 75+count*268 {
			t.Fatal("index page exceeds its exact charge", len(b))
		}
		if _, err := InspectRequiredSupportPage(b); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := PackRequiredSupportRows(fid(1), groups, 253); err == nil {
		t.Fatal("accepted child 257")
	}
	for _, class := range []SupportStorageGroup{ReceiptSupport, MaterialSupport, CreateContinuationSupport, OwnerSupport, AuxiliaryIndexSupport} {
		if _, err := PackRequiredSupportRows(fid(1), []RequiredSupportGroup{{Class: class, Owner: fid(4), Records: carriers[:1]}}, 0); err == nil {
			t.Fatal("location carrier accepted in a different allocation", class)
		}
	}
}

func packedReceipt(t testing.TB, id ID) (contract.CompactMutationReceipt, contract.SupportRecord) {
	t.Helper()
	v := contract.CompactMutationReceipt{Schema: contract.MutationReceiptSchema, OperationKind: 36, StateResult: 1, EvidenceCeiling: 1,
		DomainID: fid(1), OperationID: id, RequestIdentityDigest: fid(5),
		PredecessorRevisionID: fid(6), RequestedRevisionID: fid(7), ObservedRevisionID: fid(7), CanonicalOutcome: 1,
		ChangedSubjects: contract.GeneratorDescriptor{Digest: fid(8), Length: 80, Count: 2},
		CompleteResult:  contract.GeneratorDescriptor{Digest: fid(9), Length: 655, Count: 1}}
	body, err := contract.EncodeCompactMutationReceipt(v)
	if err != nil {
		t.Fatal(err)
	}
	return v, contract.SupportRecord{Kind: 7, RecordID: id, Body: body}
}

func packedFragments(t testing.TB, blob ID, length int) []contract.SupportRecord {
	t.Helper()
	data := bytes.Repeat([]byte{13}, length)
	count := (length + contract.GeneratedFragmentMaxPayload - 1) / contract.GeneratedFragmentMaxPayload
	rows := make([]contract.SupportRecord, count)
	for i := range rows {
		offset := i * contract.GeneratedFragmentMaxPayload
		fragment := contract.GeneratedFragment{Schema: 1, BlobID: blob, Index: uint16(i), Count: uint16(count),
			TotalLength: uint64(length), WholeDigest: contract.Hash(data), Offset: uint32(offset), Payload: data[offset:min(length, offset+contract.GeneratedFragmentMaxPayload)]}
		body, err := contract.EncodeGeneratedFragment(fragment)
		if err != nil {
			t.Fatal(err)
		}
		id, err := contract.GeneratorFragmentID(blob, uint16(i))
		if err != nil {
			t.Fatal(err)
		}
		rows[i] = contract.SupportRecord{Kind: 3, RecordID: id, Body: body}
	}
	return rows
}

// full_only: false
func TestRequiredSupportPackingReservesWholeGroupsAndChildLimit(t *testing.T) {
	_, first := packedReceipt(t, fid(20))
	_, second := packedReceipt(t, fid(21))
	fragments := packedFragments(t, fid(22), 2*contract.GeneratedFragmentMaxPayload+1)
	groups := []RequiredSupportGroup{
		{Class: AuxiliaryFragmentSupport, Owner: fid(22), Records: fragments},
		{Class: ReceiptSupport, Owner: fid(21), Records: []contract.SupportRecord{second}},
		{Class: ReceiptSupport, Owner: fid(20), Records: []contract.SupportRecord{first}},
	}
	pages, err := PackRequiredSupportRows(fid(1), groups, 253)
	if err != nil || len(pages) != 3 || len(pages[0]) != 2 || pages[0][0].RecordID != first.RecordID {
		t.Fatalf("pack: %v", err)
	}
	if groups[0].Class != AuxiliaryFragmentSupport || groups[0].Records[0].RecordID != fragments[0].RecordID {
		t.Fatal("packer changed caller ordering")
	}
	for i, rows := range pages {
		body, err := EncodeRequiredSupportPage(RequiredSupportPage{Domain: fid(1), Object: fid(byte(30 + i)), Index: uint16(i), Records: rows})
		if err != nil || len(body) > MaxRequiredSupportPage {
			t.Fatalf("page %d: %v", i, err)
		}
		if _, err := InspectRequiredSupportPage(body); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := PackRequiredSupportRows(fid(1), groups, 254); err == nil {
		t.Fatal("accepted child 257")
	}
	duplicate := append(slices.Clone(groups), groups[0])
	if _, err := PackRequiredSupportRows(fid(1), duplicate, 0); err == nil {
		t.Fatal("accepted duplicate owner group")
	}
	wrong := slices.Clone(groups)
	wrong[1].Records = []contract.SupportRecord{first}
	if _, err := PackRequiredSupportRows(fid(1), wrong, 0); err == nil {
		t.Fatal("accepted duplicate logical row across groups")
	}
	wrong = slices.Clone(groups)
	wrong[0].Class = ReceiptSupport
	if _, err := PackRequiredSupportRows(fid(1), wrong, 0); err == nil {
		t.Fatal("accepted fragment in receipt storage group")
	}
}

// full_only: false
func TestRequiredSupportPackingSeparatesMandatoryRowsWithinClass(t *testing.T) {
	_, current := packedReceipt(t, fid(31))
	_, disposable := packedReceipt(t, fid(32))
	groups := []RequiredSupportGroup{
		{Class: ReceiptSupport, Owner: current.RecordID, Mandatory: true, Records: []contract.SupportRecord{current}},
		{Class: ReceiptSupport, Owner: disposable.RecordID, Records: []contract.SupportRecord{disposable}},
	}
	pages, err := PackRequiredSupportRows(fid(1), groups, 254)
	if err != nil || len(pages) != 2 || len(pages[0]) != 1 || len(pages[1]) != 1 || pages[0][0].RecordID != current.RecordID {
		t.Fatalf("mandatory and optional rows shared a page: %d, %v", len(pages), err)
	}
	if _, err := PackRequiredSupportRows(fid(1), groups, 255); err == nil {
		t.Fatal("mandatory partition crossed the child limit")
	}
}

// full_only: false
func TestRequiredSupportReceiptPlanHasOneExactHole(t *testing.T) {
	first, _ := packedReceipt(t, fid(20))
	next, _ := packedReceipt(t, fid(21))
	plan := contract.CompactMutationReceiptPlan(next)
	plan.RequestIdentityDigest = ID{}
	delta := contract.MutationReceiptDeltaPlan{DomainID: fid(1), OperationKind: 36, AddedCount: 1,
		Before: contract.MutationReceiptWindows{DomainID: fid(1), Successes: []contract.CompactMutationReceipt{first}, Order: []contract.ID{first.OperationID}}, NewReceipt: plan}
	rows, err := delta.AfterSupportRecords()
	if err != nil {
		t.Fatal(err)
	}
	groups := make([]RequiredSupportGroup, len(rows))
	for i, row := range rows {
		groups[i] = RequiredSupportGroup{Class: ReceiptSupport, Owner: row.RecordID, Records: []contract.SupportRecord{row}}
	}
	if _, err := PackRequiredSupportRows(fid(1), groups, 0); err == nil {
		t.Fatal("actual packer accepted a receipt plan")
	}
	pages, err := PackRequiredSupportReceiptPlan(fid(1), groups, 0, plan)
	if err != nil || len(pages) != 1 {
		t.Fatalf("plan pack: %v", err)
	}
	p := RequiredSupportPage{Domain: fid(1), Object: fid(30), Records: pages[0]}
	body, err := EncodeRequiredSupportReceiptPlan(p, plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InspectRequiredSupportPage(body); err == nil {
		t.Fatal("stored page accepted a request-identity hole")
	}
	plan.CompleteResult.Digest = fid(99)
	if _, err := EncodeRequiredSupportReceiptPlan(p, plan); err == nil {
		t.Fatal("page accepted an unequal named plan")
	}
	if _, err := PackRequiredSupportReceiptPlan(fid(1), groups, 0, plan); err == nil {
		t.Fatal("packer accepted an unequal named plan")
	}
}

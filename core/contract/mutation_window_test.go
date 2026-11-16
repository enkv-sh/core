package contract

import (
	"bytes"
	"encoding/hex"
	"slices"
	"testing"
)

// full_only: true
// Proves both independent 256-receipt limits and the complete 512-ID order.
func TestMutationReceiptWindowsHaveIndependentOrderedEviction(t *testing.T) {
	windows := MutationReceiptWindows{DomainID: generatedRecordID(1)}
	for i := 0; i < 256; i++ {
		row := mutationReceiptFixture()
		row.OperationID = ID{byte(i), 1}
		var err error
		windows, err = AppendMutationReceipt(windows, row)
		if err != nil {
			t.Fatalf("append success %d: %v", i, err)
		}
	}
	for i := 0; i < 256; i++ {
		row := mutationReceiptFixture()
		row.OperationID = ID{byte(i), 2}
		row.OperationKind, row.StateResult, row.EffectSummary, row.EvidenceCeiling = 2, 11, 7, 2
		row.CanonicalOutcome, row.ObservedRevisionID = 2, row.PredecessorRevisionID
		row.SummaryCounts[0], row.SummaryCounts[6] = 1, 1
		var err error
		windows, err = AppendMutationReceipt(windows, row)
		if err != nil {
			t.Fatalf("append failure %d: %v", i, err)
		}
	}
	if _, err := AppendMutationReceipt(windows, windows.Successes[0]); err == nil {
		t.Fatal("reused operation about to be evicted")
	}
	row := mutationReceiptFixture()
	row.OperationID = ID{1, 3}
	after, err := AppendMutationReceipt(windows, row)
	if err != nil || len(after.Successes) != 256 || len(after.Failures) != 256 || after.Successes[0] != windows.Successes[1] || after.Successes[255] != row || !slices.Equal(after.Successes, append(slices.Clone(windows.Successes[1:]), row)) {
		t.Fatalf("success eviction: %v", err)
	}
	for i := range windows.Failures {
		if after.Failures[i] != windows.Failures[i] {
			t.Fatal("success append changed the failure window")
		}
	}
	wantOrder := make([]ID, 0, 512)
	for _, rows := range [][]CompactMutationReceipt{windows.Successes, windows.Failures} {
		for _, retained := range rows {
			wantOrder = append(wantOrder, retained.OperationID)
		}
	}
	if !slices.Equal(windows.Order, wantOrder) {
		t.Fatal("full order differs from selected append sequence")
	}
	wantSuccessOrder := append(slices.Clone(wantOrder[1:]), row.OperationID)
	if !slices.Equal(after.Order, wantSuccessOrder) || cap(after.Order) != 512 {
		t.Fatal("success eviction changed another relative position")
	}
	failure := windows.Failures[0]
	failure.OperationID = ID{2, 3}
	failedAfter, err := AppendMutationReceipt(windows, failure)
	wantFailureOrder := append(slices.Clone(wantOrder[:256]), wantOrder[257:]...)
	wantFailureOrder = append(wantFailureOrder, failure.OperationID)
	if err != nil || !slices.Equal(failedAfter.Successes, windows.Successes) || !slices.Equal(failedAfter.Failures, append(slices.Clone(windows.Failures[1:]), failure)) || !slices.Equal(failedAfter.Order, wantFailureOrder) || cap(failedAfter.Order) != 512 {
		t.Fatal("failure eviction changed another retained receipt or relative position", err)
	}
	indexes, err := windows.Indexes()
	if err != nil {
		t.Fatal(err)
	}
	body, err := EncodeMutationReceiptIndexes(indexes)
	if err != nil || len(body) != 36890 {
		t.Fatalf("maximum index body: %d %v", len(body), err)
	}
	decoded, err := InspectMutationReceiptIndexes(body)
	if err != nil || len(decoded.Successes) != 256 || len(decoded.Failures) != 256 {
		t.Fatalf("decode indexes: %v", err)
	}
	encoded, err := EncodeMutationReceiptIndexes(decoded)
	if err != nil || !bytes.Equal(encoded, body) {
		t.Fatal("index order changed")
	}
	decoded.Successes[0] = decoded.Failures[0]
	if _, err := EncodeMutationReceiptIndexes(decoded); err == nil {
		t.Fatal("cross-window duplicate accepted")
	}

}

// full_only: false
func TestMutationReceiptWindowDescriptorsBindOrderAndBodies(t *testing.T) {
	a, b := mutationReceiptFixture(), mutationReceiptFixture()
	b.OperationID = generatedRecordID(33)
	w := MutationReceiptWindows{DomainID: a.DomainID, Successes: []CompactMutationReceipt{a, b}, Order: []ID{a.OperationID, b.OperationID}}
	before, err := w.Descriptors()
	if err != nil {
		t.Fatal(err)
	}
	w.Successes[0], w.Successes[1] = w.Successes[1], w.Successes[0]
	w.Order[0], w.Order[1] = w.Order[1], w.Order[0]
	after, err := w.Descriptors()
	if err != nil || before.Successes == after.Successes || before.Receipts != after.Receipts || before.Failures != after.Failures {
		t.Fatalf("order/set commitments: %v", err)
	}
	w.Successes[0].CompleteResult.Digest = generatedRecordID(99)
	changed, err := w.Descriptors()
	if err != nil || changed.Successes != after.Successes || changed.Receipts == after.Receipts {
		t.Fatalf("receipt body commitment: %v", err)
	}
	w.Successes = append(w.Successes, w.Successes[0])
	if _, err := w.Descriptors(); err == nil {
		t.Fatal("duplicate receipt accepted")
	}
}

// full_only: false
func TestMutationReceiptIndexesRejectCountVersionAndBorrowedChanges(t *testing.T) {
	v := MutationReceiptIndexes{Successes: []ID{generatedRecordID(2)}, Failures: []ID{generatedRecordID(3)}, Order: []ID{generatedRecordID(2), generatedRecordID(3)}}
	body, err := EncodeMutationReceiptIndexes(v)
	if err != nil {
		t.Fatal(err)
	}
	// Explicit Python struct fields and SHA-256; derive-receipt-order.py records the derivation.
	want, err := hex.DecodeString("0002000000280000000100000020020202020202020202020202020202020202020202020202020202020202020200000028000000010000002003030303030303030303030303030303030303030303030303030303030303030000004c00000002000000200202020202020202020202020202020202020202020202020202020202020202000000200303030303030303030303030303030303030303030303030303030303030303")
	if err != nil || !bytes.Equal(body, want) {
		t.Fatalf("index vector: %v", err)
	}
	successes, failures, order, err := v.Descriptors()
	if err != nil {
		t.Fatal(err)
	}
	id, err := MutationReceiptIndexBlobID(generatedRecordID(1), successes, failures, order)
	if err != nil || hex.EncodeToString(id[:]) != "24062206d33c19414572350759bd452f7cd23e75ad52fc112991c67c90742ad3" {
		t.Fatalf("index identity: %x %v", id, err)
	}
	for _, offset := range []int{0, 1, 2, 5, 6, 9, 10, 13, 46, 49, 50, 53, 54, 57, 90, 93, 94, 97, 98, 101, 134, 137} {
		bad := bytes.Clone(body)
		bad[offset] ^= 0xff
		if _, err := InspectMutationReceiptIndexes(bad); err == nil {
			t.Fatalf("accepted damaged framing at %d", offset)
		}
	}
	decoded, err := InspectMutationReceiptIndexes(body)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < len(body); n++ {
		if _, err := InspectMutationReceiptIndexes(body[:n]); err == nil {
			t.Fatalf("accepted truncation %d", n)
		}
	}
	old := bytes.Clone(body[:90])
	old[1] = 1
	for _, bad := range [][]byte{old, append(bytes.Clone(old), body[90:]...), body[:90], append(bytes.Clone(body), 0)} {
		if _, err := InspectMutationReceiptIndexes(bad); err == nil {
			t.Fatal("accepted old, incomplete or trailing index")
		}
	}
	clear(body)
	if decoded.Successes[0] != v.Successes[0] || decoded.Failures[0] != v.Failures[0] || !slices.Equal(decoded.Order, v.Order) {
		t.Fatal("decoded scalar IDs borrowed input")
	}
	if _, err := MutationReceiptIndexBlobID(ID{}, successes, failures, order); err == nil {
		t.Fatal("zero domain accepted")
	}
}

// full_only: false
func TestMutationReceiptAppendOwnsReturnedWindows(t *testing.T) {
	for _, outcome := range []uint8{ReceiptCanonicalSelected, ReceiptCanonicalNotSelected} {
		t.Run(map[uint8]string{ReceiptCanonicalSelected: "success", ReceiptCanonicalNotSelected: "failure"}[outcome], func(t *testing.T) {
			success := mutationReceiptFixture()
			failure := success
			failure.OperationID = generatedRecordID(33)
			failure.OperationKind, failure.StateResult, failure.EffectSummary, failure.EvidenceCeiling = 2, 11, 7, 2
			failure.CanonicalOutcome, failure.ObservedRevisionID = ReceiptCanonicalNotSelected, failure.PredecessorRevisionID
			failure.SummaryCounts[0], failure.SummaryCounts[6] = 1, 1
			before := MutationReceiptWindows{DomainID: success.DomainID, Successes: []CompactMutationReceipt{success}, Failures: []CompactMutationReceipt{failure}, Order: []ID{success.OperationID, failure.OperationID}}
			next := success
			if outcome == ReceiptCanonicalNotSelected {
				next = failure
			}
			next.OperationID = generatedRecordID(34)
			after, err := AppendMutationReceipt(before, next)
			if err != nil {
				t.Fatal(err)
			}
			after.Successes[0].CompleteResult.Digest = generatedRecordID(98)
			after.Failures[0].CompleteResult.Digest = generatedRecordID(99)
			if before.Successes[0] != success || before.Failures[0] != failure {
				t.Fatal("returned receipt windows share predecessor storage")
			}
		})
	}
}

// full_only: false
func TestMutationReceiptCommonOrderRequiresExactClassSubsequences(t *testing.T) {
	a, b, c := generatedRecordID(2), generatedRecordID(3), generatedRecordID(4)
	valid := MutationReceiptIndexes{Successes: []ID{a, c}, Failures: []ID{b}, Order: []ID{a, b, c}}
	for name, order := range map[string][]ID{
		"missing": {a, b}, "extra": {a, b, c, generatedRecordID(5)}, "duplicate": {a, b, a},
		"zero": {a, ID{}, c}, "foreign": {a, generatedRecordID(5), c}, "wrong subsequence": {c, b, a},
	} {
		t.Run(name, func(t *testing.T) {
			bad := valid
			bad.Order = order
			if _, _, _, err := bad.Descriptors(); err == nil {
				t.Fatal("accepted invalid common order")
			}
			if _, err := EncodeMutationReceiptIndexes(bad); err == nil {
				t.Fatal("encoded invalid common order")
			}
		})
	}
	body, err := EncodeMutationReceiptIndexes(valid)
	if err != nil {
		t.Fatal(err)
	}
	// Index fields: schema2, framed two-success vector76, one-failure vector40,
	// then common count3 and three framed IDs. Damage only common ID bytes.
	for name, positions := range map[string][2]int{"duplicate": {138, 174}, "wrong subsequence": {138, 210}} {
		t.Run("decoded "+name, func(t *testing.T) {
			bad := bytes.Clone(body)
			first, second := positions[0], positions[1]
			if name == "duplicate" {
				copy(bad[second:second+32], bad[first:first+32])
			} else {
				tmp := bytes.Clone(bad[first : first+32])
				copy(bad[first:first+32], bad[second:second+32])
				copy(bad[second:second+32], tmp)
			}
			if _, err := InspectMutationReceiptIndexes(bad); err == nil {
				t.Fatal("decoded invalid common order")
			}
		})
	}
	firstSuccess, firstFailure, firstOrder, err := valid.Descriptors()
	if err != nil {
		t.Fatal(err)
	}
	firstID, err := MutationReceiptIndexBlobID(generatedRecordID(1), firstSuccess, firstFailure, firstOrder)
	if err != nil {
		t.Fatal(err)
	}
	valid.Order = []ID{b, a, c}
	success, failure, order, err := valid.Descriptors()
	if err != nil || success != firstSuccess || failure != firstFailure || order == firstOrder {
		t.Fatal("valid interleaving changed a class or failed to change order", err)
	}
	secondID, err := MutationReceiptIndexBlobID(generatedRecordID(1), success, failure, order)
	if err != nil || secondID == firstID {
		t.Fatal("index identity did not bind common order", err)
	}
}

// full_only: false
func TestMutationReceiptIndexesEmptyAndDescriptorBounds(t *testing.T) {
	empty := MutationReceiptIndexes{}
	body, err := EncodeMutationReceiptIndexes(empty)
	want, _ := hex.DecodeString("0002000000040000000000000004000000000000000400000000")
	if err != nil || !bytes.Equal(body, want) {
		t.Fatal("noncanonical empty index", err)
	}
	success, failure, order, err := empty.Descriptors()
	if err != nil || success != EmptyGeneratorIndexes()[2] || failure != EmptyGeneratorIndexes()[3] || order != EmptyGeneratorIndexes()[4] {
		t.Fatal("noncanonical empty descriptors", err)
	}
	if _, err := InspectMutationReceiptIndexes(want); err != nil {
		t.Fatal(err)
	}
	for _, old := range [][]byte{append([]byte{0, 1}, want[2:18]...), append([]byte{0, 1}, want[2:]...)} {
		if _, err := InspectMutationReceiptIndexes(old); err == nil {
			t.Fatal("accepted old empty index")
		}
	}
	for name, change := range map[string]func(*GeneratorDescriptor){
		"empty digest": func(d *GeneratorDescriptor) { d.Digest = generatedRecordID(99) },
		"length":       func(d *GeneratorDescriptor) { d.Length++ },
		"count":        func(d *GeneratorDescriptor) { d.Count++ },
	} {
		t.Run(name, func(t *testing.T) {
			bad := order
			change(&bad)
			if GeneratorIndexShapeValid(GeneratorReceiptOrder, bad) {
				t.Fatal("accepted invalid order descriptor")
			}
			if _, err := MutationReceiptIndexBlobID(generatedRecordID(1), success, failure, bad); err == nil {
				t.Fatal("accepted invalid index identity descriptor")
			}
		})
	}
	if _, _, _, err := (MutationReceiptIndexes{Order: make([]ID, 513)}).Descriptors(); err != ErrRecordCapacity {
		t.Fatal("order limit not enforced", err)
	}
}

// full_only: false
func TestMutationReceiptIndexesAndAppendOwnCommonOrder(t *testing.T) {
	first := mutationReceiptFixture()
	before := MutationReceiptWindows{DomainID: first.DomainID, Successes: []CompactMutationReceipt{first}, Order: []ID{first.OperationID}}
	next := first
	next.OperationID = generatedRecordID(33)
	after, err := AppendMutationReceipt(before, next)
	if err != nil || !slices.Equal(after.Order, []ID{first.OperationID, next.OperationID}) {
		t.Fatal("append order", err)
	}
	after.Order[0] = generatedRecordID(99)
	if before.Order[0] != first.OperationID {
		t.Fatal("append borrowed predecessor order")
	}
	indexes, err := before.Indexes()
	if err != nil {
		t.Fatal(err)
	}
	indexes.Order[0], indexes.Successes[0] = generatedRecordID(98), generatedRecordID(99)
	if before.Order[0] != first.OperationID || before.Successes[0] != first {
		t.Fatal("indexes borrowed selected windows")
	}
}

// full_only: false
func TestMutationReceiptWindowsRejectForeignDomainAndWrongClass(t *testing.T) {
	row := mutationReceiptFixture()
	for name, windows := range map[string]MutationReceiptWindows{
		"foreign domain": {DomainID: generatedRecordID(99), Successes: []CompactMutationReceipt{row}, Order: []ID{row.OperationID}},
		"wrong class":    {DomainID: row.DomainID, Failures: []CompactMutationReceipt{row}, Order: []ID{row.OperationID}},
		"missing order":  {DomainID: row.DomainID, Successes: []CompactMutationReceipt{row}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := windows.Descriptors(); err == nil {
				t.Fatal("accepted invalid selected receipt windows")
			}
			if _, err := windows.Indexes(); err == nil {
				t.Fatal("exposed invalid selected receipt indexes")
			}
		})
	}
}

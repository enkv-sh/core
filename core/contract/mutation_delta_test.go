package contract

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// full_only: false
func TestMutationReceiptDeltaPreservesRowsAndOnlyNewIdentityHole(t *testing.T) {
	first := mutationReceiptFixture()
	before := MutationReceiptWindows{DomainID: first.DomainID, Successes: []CompactMutationReceipt{first}, Order: []ID{first.OperationID}}
	next := first
	next.OperationID, next.RequestIdentityDigest = generatedRecordID(42), generatedRecordID(43)
	after, err := AppendMutationReceipt(before, next)
	if err != nil {
		t.Fatal(err)
	}
	actual := MutationReceiptDelta{DomainID: first.DomainID, OperationKind: next.OperationKind, AddedCount: 1, Before: before, After: after}
	digest, err := MutationReceiptDeltaDigest(actual)
	// Independent Python integers, repeated-byte IDs, count/B vectors
	// and standard SHA-256 derive the 389-byte delta body and these literals,
	// including operation 36 in each nested 471-byte receipt.
	if err != nil || hex.EncodeToString(digest[:]) != "4bd8a3b004e383f1fb151bf21ab84514fcdabfdee15d54c8d33cba1e2fd45374" {
		t.Fatalf("actual delta: %v", err)
	}
	p := CompactMutationReceiptPlan(next)
	p.RequestIdentityDigest = ID{}
	plan := MutationReceiptDeltaPlan{DomainID: first.DomainID, OperationKind: next.OperationKind, AddedCount: 1, Before: before, NewReceipt: p}
	planned, err := MutationReceiptDeltaPlanDigest(plan)
	if err != nil || hex.EncodeToString(planned[:]) != "39c6a08c187416b90c18f817495496f4f17fa9bb000d230fafd76609840e6bc2" {
		t.Fatalf("planned delta: %v", err)
	}
	rows, err := plan.AfterSupportRecords()
	if err != nil || len(rows) != 2 {
		t.Fatalf("planned records: %v", err)
	}
	for _, row := range rows {
		switch row.RecordID {
		case first.OperationID:
			want, _ := EncodeCompactMutationReceipt(first)
			if !bytes.Equal(row.Body, want) {
				t.Fatal("retained receipt changed")
			}
		case next.OperationID:
			want, _ := AppendCompactMutationReceiptPlan(nil, p)
			if !bytes.Equal(row.Body, want) {
				t.Fatal("new receipt plan differs")
			}
			if _, err := SupportRecordLength(row); err == nil {
				t.Fatal("actual support accepted the plan")
			}
		default:
			t.Fatal("unexpected receipt")
		}
	}
	indexes, err := plan.AfterIndexes()
	if err != nil || len(indexes.Successes) != 2 || indexes.Successes[0] != first.OperationID || indexes.Successes[1] != next.OperationID {
		t.Fatalf("planned order: %v", err)
	}
	after.Successes[0].CompleteResult.Digest = generatedRecordID(99)
	actual.After = after
	if _, err := MutationReceiptDeltaDigest(actual); err == nil {
		t.Fatal("retained receipt body rewrite accepted")
	}
	plan.NewReceipt.RequestIdentityDigest = next.RequestIdentityDigest
	if _, err := MutationReceiptDeltaPlanDigest(plan); err == nil {
		t.Fatal("plan accepted an actual new receipt")
	}
}

// full_only: false
func TestMutationReceiptDeltaReceiptFreePreservesBothWindows(t *testing.T) {
	row := mutationReceiptFixture()
	before := MutationReceiptWindows{DomainID: row.DomainID, Successes: []CompactMutationReceipt{row}, Order: []ID{row.OperationID}}
	actual := MutationReceiptDelta{DomainID: row.DomainID, OperationKind: 25, Before: before, After: before}
	digest, err := MutationReceiptDeltaDigest(actual)
	// The same independent count/B traversal retains the operation-36 receipt
	// in both windows; only the outer receipt-free operation is 25.
	if err != nil || hex.EncodeToString(digest[:]) != "84a007843a24d2bea16745f523a3c037a5c4561f90808ff4003a5ba986aea093" {
		t.Fatal(err)
	}
	plan := MutationReceiptDeltaPlan{DomainID: row.DomainID, OperationKind: 25, Before: before}
	planned, err := MutationReceiptDeltaPlanDigest(plan)
	if err != nil || planned != digest {
		t.Fatalf("receipt-free plan: %v", err)
	}
	actual.After = MutationReceiptWindows{DomainID: row.DomainID}
	if _, err := MutationReceiptDeltaDigest(actual); err == nil {
		t.Fatal("receipt-free operation discarded a receipt")
	}
	plan.AddedCount = 1
	if _, err := MutationReceiptDeltaPlanDigest(plan); err == nil {
		t.Fatal("receipt-free operation appended a receipt")
	}
}

// full_only: false
func TestMutationReceiptDeltaRechecksMutatedPredecessor(t *testing.T) {
	first := mutationReceiptFixture()
	second := first
	second.OperationID = generatedRecordID(42)
	before := MutationReceiptWindows{DomainID: first.DomainID, Successes: []CompactMutationReceipt{first, second}, Order: []ID{first.OperationID, second.OperationID}}
	if _, err := before.Descriptors(); err != nil {
		t.Fatal(err)
	}
	before.Successes[1] = first
	if _, err := before.Descriptors(); err == nil {
		t.Fatal("accepted predecessor changed to duplicate rows")
	}
	if _, err := MutationReceiptDeltaDigest(MutationReceiptDelta{DomainID: first.DomainID, OperationKind: 25, Before: before, After: before}); err == nil {
		t.Fatal("hashed an invalid mutated predecessor")
	}
}

// full_only: false
func TestReceiptFreeCleanupIsNotAnAuthorityReplacementDelta(t *testing.T) {
	row := mutationReceiptFixture()
	windows := MutationReceiptWindows{DomainID: row.DomainID, Successes: []CompactMutationReceipt{row}, Order: []ID{row.OperationID}}
	delta := MutationReceiptDelta{DomainID: row.DomainID, OperationKind: 31, Before: windows, After: windows}
	if _, err := MutationReceiptDeltaDigest(delta); err == nil {
		t.Fatal("cleanup admitted the authority-replacement-only zero-addition delta")
	}
}

// full_only: false
func TestMutationReceiptDeltaBindsOnlyCommonOrderChanges(t *testing.T) {
	first := mutationReceiptFixture()
	failure := first
	failure.OperationID = generatedRecordID(33)
	failure.OperationKind, failure.StateResult, failure.EffectSummary, failure.EvidenceCeiling = 2, 11, 7, 2
	failure.CanonicalOutcome, failure.ObservedRevisionID = ReceiptCanonicalNotSelected, failure.PredecessorRevisionID
	failure.SummaryCounts[0], failure.SummaryCounts[6] = 1, 1
	before := MutationReceiptWindows{DomainID: first.DomainID, Successes: []CompactMutationReceipt{first}, Failures: []CompactMutationReceipt{failure}, Order: []ID{first.OperationID, failure.OperationID}}
	other := before
	other.Order = []ID{failure.OperationID, first.OperationID}
	left, err := MutationReceiptDeltaDigest(MutationReceiptDelta{DomainID: first.DomainID, OperationKind: OperationReplaceAuthorityKeys, Before: before, After: before})
	if err != nil {
		t.Fatal(err)
	}
	right, err := MutationReceiptDeltaDigest(MutationReceiptDelta{DomainID: first.DomainID, OperationKind: OperationReplaceAuthorityKeys, Before: other, After: other})
	if err != nil || right == left {
		t.Fatal("delta did not commit common interleaving", err)
	}
	if _, err := MutationReceiptDeltaDigest(MutationReceiptDelta{DomainID: first.DomainID, OperationKind: OperationReplaceAuthorityKeys, Before: before, After: other}); err == nil {
		t.Fatal("receipt-free delta changed common order")
	}
	next := first
	next.OperationID = generatedRecordID(34)
	after, err := AppendMutationReceipt(before, next)
	if err != nil {
		t.Fatal(err)
	}
	after.Order = []ID{failure.OperationID, first.OperationID, next.OperationID}
	if _, err := MutationReceiptDeltaDigest(MutationReceiptDelta{DomainID: first.DomainID, OperationKind: next.OperationKind, AddedCount: 1, Before: before, After: after}); err == nil {
		t.Fatal("append delta changed retained common order")
	}
}

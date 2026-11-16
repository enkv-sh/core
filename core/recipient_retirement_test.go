package core

import (
	"bytes"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestRecipientRetirementChecksExactSparseSlotAndEncodedBeforeRow(t *testing.T) {
	s, rows := applyRecipientCreationFixture(t)
	old := rows[0].Recipient
	s.recipients = [contract.MaxRecipientPages]*format.RecipientPage{}
	s.recipients[4] = &format.RecipientPage{Domain: s.root.Domain, Index: 4, Slots: [format.RecipientSlots]*contract.RecipientRecord{2: &old}}
	slot, record := s.selectedRecipientSlot(old.RecipientID)
	body, err := contract.EncodeRecipientRecord(old)
	if err != nil || slot != 34 || record != &old {
		t.Fatal("actual sparse predecessor slot lost", err, slot)
	}
	row := contract.RecipientRetirementRow{Slot: 34, RecipientID: old.RecipientID, BeforeRecordDigest: contract.Hash(body), BeforeRecordLength: uint32(len(body))}
	if !s.authenticatedRecipientRetirement(row) {
		t.Fatal("exact independently encoded sparse row refused")
	}
	for _, damage := range []func(*contract.RecipientRetirementRow){func(row *contract.RecipientRetirementRow) { row.Slot = 0 }, func(row *contract.RecipientRetirementRow) { row.BeforeRecordDigest[0] ^= 1 }, func(row *contract.RecipientRetirementRow) { row.BeforeRecordLength++ }, func(row *contract.RecipientRetirementRow) { row.RecipientID[0] ^= 1 }} {
		bad := row
		damage(&bad)
		if s.authenticatedRecipientRetirement(bad) {
			t.Fatal("fabricated retirement before row admitted")
		}
	}
}

// full_only: false
func TestRecipientRetirementBlockerPrefixKeepsCompleteUniqueTotalAndLateErrors(t *testing.T) {
	recipient := contract.ID{1}
	g := &generatedSelection{canonical: make(map[contract.ID]generatedCanonical), retainedOwners: make(map[contract.ID][]generatedRecordKey), records: make(map[generatedRecordKey]contract.SupportRecord)}
	var want []RecipientRetirementBlocker
	for i := 1; i <= 70; i++ {
		id := contract.ID{byte(i)}
		owner := generatedRecordKey{contract.GeneratedHazardSupportKind, contract.ID{byte(100 + i)}}
		g.canonical[id] = generatedCanonical{record: contract.RetainedCanonicalRecord{Entry: contract.ValueEntry{ValueState: id, Recipients: []contract.ID{recipient}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}}}
		g.retainedOwners[id] = []generatedRecordKey{owner, owner}
		g.records[owner] = contract.SupportRecord{Kind: owner.kind, RecordID: owner.id}
		want = append(want, RecipientRetirementBlocker{MaterialID: id, OwnerKind: owner.kind, OwnerID: owner.id})
	}
	slices.SortFunc(want, func(a, b RecipientRetirementBlocker) int { return bytes.Compare(a.MaterialID[:], b.MaterialID[:]) })
	got, err := g.recipientRetirementBlockers(recipient)
	if err != nil || got == nil || got.Total != 70 || len(got.Rows) != 64 || cap(got.Rows) != 64 || !slices.Equal(got.Rows, want[:64]) {
		t.Fatal("bounded exact blocker prefix/complete unique total differs", err)
	}
	g.retainedOwners[contract.ID{70}] = []generatedRecordKey{{contract.GeneratedAttemptSupportKind, contract.ID{240}}}
	if got, err := g.recipientRetirementBlockers(recipient); err == nil || got != nil {
		t.Fatal("invalid closure beyond visible prefix yielded complete blocker facts")
	}
}

// full_only: false
func TestSelectedAccessMutationRequiresItsExactSuccessReceipt(t *testing.T) {
	operation := contract.ID{9}
	for _, kind := range []uint16{contract.OperationRemoveSecretValueEntryAccess, contract.OperationRetireRecipientIdentity, contract.OperationEnvelopeRekey} {
		head := format.Head{AuthKind: format.LifecycleAuth, Subject: contract.LifecycleSubject{Operation: operation, OperationKind: kind}}
		row := contract.CompactMutationReceipt{OperationID: operation, OperationKind: kind}
		if selectedLifecycleReceiptKind(head, contract.MutationReceiptWindows{}) || selectedLifecycleReceiptKind(head, contract.MutationReceiptWindows{Failures: []contract.CompactMutationReceipt{row}}) {
			t.Fatal("new access mutation accepted absent/non-success own receipt", kind)
		}
		if !selectedLifecycleReceiptKind(head, contract.MutationReceiptWindows{Successes: []contract.CompactMutationReceipt{row}}) {
			t.Fatal("matching own success receipt refused", kind)
		}
		row.OperationKind = contract.OperationApplyDeclaration
		if selectedLifecycleReceiptKind(head, contract.MutationReceiptWindows{Successes: []contract.CompactMutationReceipt{row}}) {
			t.Fatal("mismatched receipt kind admitted", kind)
		}
	}
	head := format.Head{AuthKind: format.LifecycleAuth, Subject: contract.LifecycleSubject{Operation: operation, OperationKind: contract.OperationApplyDeclaration}}
	if !selectedLifecycleReceiptKind(head, contract.MutationReceiptWindows{}) {
		t.Fatal("receipt-free older ordinary transition refused")
	}
}

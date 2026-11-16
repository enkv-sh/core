package core

import (
	"bytes"
	"context"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

func generatedRegistryFixture(t testing.TB) (*StateSession, contract.GeneratedRecipientRegistryImage) {
	t.Helper()
	s := generatedEmptyPredecessor(t)
	rows := currentApplyRecipients(s.registry())
	nonce := generatedVectorID(192)
	id, err := contract.RecipientCreationID(s.root.Domain, s.root.Snapshot, nonce)
	if err != nil {
		t.Fatal(err)
	}
	binding, incarnation, err := contract.RecipientInitialBindingIDs(s.root.Domain, id)
	if err != nil {
		t.Fatal(err)
	}
	key := *rows[0].Recipient.CurrentBinding
	key.BindingID, key.BindingIncarnationID, key.BindingSerial = binding, incarnation, 1
	rows = append(rows, contract.ApplyRecipientInput{Recipient: contract.RecipientRecord{RecipientID: id, Status: contract.CurrentRecipient, DisplayName: "accepted new reader", CurrentBinding: &key}, Creation: &contract.RecipientCreationProof{Snapshot: s.root.Snapshot, Nonce: nonce}})
	slices.SortFunc(rows, func(a, b contract.ApplyRecipientInput) int {
		return bytes.Compare(a.Recipient.RecipientID[:], b.Recipient.RecipientID[:])
	})
	return s, contract.GeneratedRecipientRegistryImage{Schema: 1, DomainID: s.root.Domain, OperationID: generatedVectorID(193), OriginalPredecessorSnapshotID: s.root.Snapshot, Recipients: rows, InitiallyAbsent: []contract.ID{id}}
}

// full_only: false
func TestGeneratedRegistryReplayKeepsProposalAndUsesCurrentExistingBinding(t *testing.T) {
	s, image := generatedRegistryFixture(t)
	before := s.registry()
	rows, err := effectiveGeneratedRecipients(s.root, before, image)
	if err != nil || len(rows) != len(before)+1 {
		t.Fatal("initial effective registry", err)
	}
	root := s.root
	root.Snapshot = generatedVectorID(194)
	current := slices.Clone(before)
	key := *current[0].CurrentBinding
	key.BindingID = generatedVectorID(195)
	key.BindingSerial++
	current[0].CurrentBinding = &key
	current[0].DisplayName = "later local display"
	effective, err := effectiveGeneratedRecipients(root, current, image)
	if err != nil {
		t.Fatal("phase restart rejected original predecessor proof", err)
	}
	old := slices.IndexFunc(effective, func(row contract.RecipientRecord) bool { return row.RecipientID == current[0].RecipientID })
	original := slices.IndexFunc(image.Recipients, func(row contract.ApplyRecipientInput) bool {
		return row.Recipient.RecipientID == current[0].RecipientID
	})
	if old < 0 || effective[old].CurrentBinding.BindingID != key.BindingID || effective[old].DisplayName != image.Recipients[original].Recipient.DisplayName || image.Recipients[original].Recipient.CurrentBinding.BindingID == key.BindingID {
		t.Fatal("replay lost accepted display, changed original image, or rebound old key")
	}
	pending := slices.IndexFunc(effective, func(row contract.RecipientRecord) bool { return row.RecipientID == image.InitiallyAbsent[0] })
	if pending < 0 || effective[pending].CurrentBinding.BindingSerial != 1 {
		t.Fatal("pending first binding changed")
	}
	if _, err := effectiveGeneratedRecipients(root, append(slices.Clone(current), effective[pending]), image); err == nil {
		t.Fatal("active accepted pending ID was already current")
	}
	image.Recipients[pending].Creation.Nonce[0] ^= 1
	if _, err := effectiveGeneratedRecipients(root, current, image); err == nil {
		t.Fatal("restart accepted altered original creation proof")
	}
}

// full_only: false
func TestGeneratedRegistrySchemaThreeCannotFallBackToCurrentRegistry(t *testing.T) {
	s, image := generatedRegistryFixture(t)
	body, err := contract.EncodeGeneratedRecipientRegistryImage(image)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := contract.GeneratedRecipientRegistryDescriptor(body)
	if err != nil {
		t.Fatal(err)
	}
	q := contract.GeneratorRequestCore{Schema: contract.GeneratorPublicRequestCoreSchema, DomainID: s.root.Domain, OperationID: image.OperationID, Registry: descriptor}
	if _, err := s.admitGeneratedRegistry(context.Background(), nil, q, false); err == nil {
		t.Fatal("schema3 missing image fell back to current registry")
	}
	if _, err := s.admitGeneratedRegistry(context.Background(), body, q, false); err != nil {
		t.Fatal("exact complete retained image refused", err)
	}
	q.Schema = contract.GeneratorRequestCoreSchema
	if _, err := s.admitGeneratedRegistry(context.Background(), body, q, false); err == nil {
		t.Fatal("selected-old schema2 gained schema3 registry semantics")
	}
	if image, err := s.admitGeneratedRegistry(context.Background(), nil, q, false); err != nil || image != nil {
		t.Fatal("exact old schema2 no-image semantics lost", err)
	}
}

// full_only: false
func TestGeneratedRegistryCapacityChargesSeparateBlobAndSlice(t *testing.T) {
	shape := generatedCapacityShape{ValueEntryCount: 1, ValueEntryPageCount: 1, Recipients: 1, Secrets: 1, Memberships: 1, SecretMemberships: 1, Generated: 1, Creates: 1, ValueEntryPlanCount: 1, DeclarationBytes: 512}
	before, err := generatedCleanCapacity(shape)
	if err != nil {
		t.Fatal(err)
	}
	shape.RegistryBytes = uint64(contract.GeneratedRecipientRegistryMaxLength)
	after, err := generatedCleanCapacity(shape)
	if err != nil {
		t.Fatal(err)
	}
	auxiliaryBefore, auxiliaryAfter := before[contract.GeneratorCapacityAuxiliary], after[contract.GeneratorCapacityAuxiliary]
	if auxiliaryAfter.MaxFramedBytes < auxiliaryBefore.MaxFramedBytes+shape.RegistryBytes || auxiliaryAfter.MaxPages <= auxiliaryBefore.MaxPages || after[contract.GeneratorCapacityGraph].MaxFramedBytes <= before[contract.GeneratorCapacityGraph].MaxFramedBytes {
		t.Fatal("accepted registry image did not reserve independent blob/carrier packing")
	}
	shape.RegistryBytes++
	if _, err := generatedCleanCapacity(shape); err == nil {
		t.Fatal("over-bound registry image reached capacity reservation")
	}
}

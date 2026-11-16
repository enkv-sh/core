package core

import (
	"bytes"
	"encoding/hex"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func applyRecipientCreationFixture(t *testing.T) (*StateSession, []contract.ApplyRecipientInput) {
	t.Helper()
	domain, snapshot, nonce := contract.ID(bytes.Repeat([]byte{1}, 32)), contract.ID(bytes.Repeat([]byte{2}, 32)), contract.ID(bytes.Repeat([]byte{3}, 32))
	literal := func(value string) contract.ID {
		b, err := hex.DecodeString(value)
		if err != nil || len(b) != 32 {
			t.Fatal("invalid independent creation literal")
		}
		return contract.ID(b)
	}
	recipient := literal("1e0f632de874daa81aee1329862f853523752d968f470b92a94f56f45033f601")
	public := publicConfigurationFixture(t).Recipients.Value[0].Encryption
	binding := contract.KMSBinding{BindingID: literal("1335f7894345cceb330d579a02243aeae81ae5d6025d02304861ebf6a9bf34c6"), BindingIncarnationID: literal("1e34b1961d9a9f318d85f0c4357dbae41ce1cde49a340899d4e7660b45e1d581"), BindingSerial: 1, Provider: public.Provider.Value, WrapProfile: public.WrapProfile.Value, ProtectionClass: public.ProtectionClass.Value, KeySelector: public.Selector.Value, SPKI: public.PublicKey.Value, Fingerprint: public.Fingerprint.Value}
	currentBinding := binding
	currentBinding.BindingID = contract.Hash([]byte("existing binding"))
	currentBinding.BindingIncarnationID = contract.Hash([]byte("existing binding incarnation"))
	current := contract.RecipientRecord{RecipientID: contract.ID{4}, Status: contract.CurrentRecipient, DisplayName: "current", CurrentBinding: &currentBinding}
	created := contract.RecipientRecord{RecipientID: recipient, Status: contract.CurrentRecipient, DisplayName: "unassigned", CurrentBinding: &binding}
	s := &StateSession{}
	s.root.Domain, s.root.Snapshot, s.root.RecipientCount = domain, snapshot, 1
	s.root.CurrentAccess.Core.Provider = public.Provider.Value
	s.recipients[0] = &format.RecipientPage{Domain: domain, Index: 0, Slots: [format.RecipientSlots]*contract.RecipientRecord{0: &current}}
	rows := []contract.ApplyRecipientInput{{Recipient: current}, {Recipient: created, Creation: &contract.RecipientCreationProof{Snapshot: snapshot, Nonce: nonce}}}
	slices.SortFunc(rows, func(a, b contract.ApplyRecipientInput) int {
		return bytes.Compare(a.Recipient.RecipientID[:], b.Recipient.RecipientID[:])
	})
	return s, rows
}

// full_only: false
func TestApplyRecipientCreationAdmitsIndependentInitialIdentityAndBinding(t *testing.T) {
	s, rows := applyRecipientCreationFixture(t)
	proposal, err := s.admitApplyRecipients(t.Context(), rows)
	if err != nil || proposal == nil || len(proposal.records) != 2 || len(proposal.changed) != 1 || proposal.changed[0] != rows[1].Recipient.RecipientID {
		t.Fatal("valid unassigned creation refused", err)
	}
	if len(s.registry()) != 1 || s.root.RecipientCount != 1 {
		t.Fatal("proposal mutated authenticated current registry")
	}
}

// full_only: false
func TestApplyRecipientCreationRefusesStaleOrInconsistentProofAndBinding(t *testing.T) {
	for _, name := range []string{"stale snapshot", "nonce", "recipient identity", "binding identity", "binding incarnation", "binding serial", "missing proof", "current binding change", "current row omission"} {
		t.Run(name, func(t *testing.T) {
			s, rows := applyRecipientCreationFixture(t)
			created := &rows[1]
			switch name {
			case "stale snapshot":
				created.Creation.Snapshot[0] ^= 1
			case "nonce":
				created.Creation.Nonce[0] ^= 1
			case "recipient identity":
				created.Recipient.RecipientID[0] ^= 1
			case "binding identity":
				created.Recipient.CurrentBinding.BindingID[0] ^= 1
			case "binding incarnation":
				created.Recipient.CurrentBinding.BindingIncarnationID[0] ^= 1
			case "binding serial":
				created.Recipient.CurrentBinding.BindingSerial = 2
			case "missing proof":
				created.Creation = nil
			case "current binding change":
				copy := *rows[0].Recipient.CurrentBinding
				copy.BindingID[0] ^= 1
				rows[0].Recipient.CurrentBinding = &copy
			case "current row omission":
				rows = rows[1:]
			}
			if _, err := s.admitApplyRecipients(t.Context(), rows); err == nil {
				t.Fatal("inconsistent recipient proposal admitted")
			}
			if len(s.registry()) != 1 {
				t.Fatal("refused proposal changed authenticated registry")
			}
		})
	}
}

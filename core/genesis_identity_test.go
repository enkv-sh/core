package core

import (
	"bytes"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGenesisIdentityAllocationIsSinglePass(t *testing.T) {
	var input []byte
	for _, n := range []byte{1, 2, 3, 4} {
		input = append(input, bytes.Repeat([]byte{n}, 32)...)
	}
	r := bytes.NewReader(input)
	ids, err := allocateGenesisIDs(r)
	if err != nil || r.Len() != 0 || ids.Init != contract.ID(input[:32]) || ids.Domain != contract.ID(input[32:64]) || ids.DescriptorArtifact != contract.ID(input[64:96]) || ids.ManifestArtifact != contract.ID(input[96:]) {
		t.Fatalf("genesis identity allocation: %+v %v bytes=%d", ids, err, r.Len())
	}
	for _, input := range [][]byte{make([]byte, 128), bytes.Repeat([]byte{1}, 128), bytes.Repeat([]byte{1}, 31)} {
		if _, err := allocateGenesisIDs(bytes.NewReader(input)); err == nil {
			t.Fatal("invalid or incomplete entropy was accepted")
		}
	}
}

// full_only: false
func TestGenesisPlanRejectsInvalidAdmissionBeforeEntropy(t *testing.T) {
	for _, descriptor := range [][]byte{nil, {1, 2, 3}} {
		entropy := bytes.NewReader(bytes.Repeat([]byte{1}, 512))
		plan, err := planGenesis(openAdmission{descriptor: descriptor, entropy: entropy})
		if plan != nil || err != contract.ErrSubject || entropy.Len() != 512 {
			t.Fatal("invalid genesis admission consumed entropy or produced a plan", err)
		}
	}
}

// full_only: false
func TestInitializationAllocationOwnsAllRoleAndRecipientIDs(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		count := 15
		if recovery {
			count = 20
		}
		var input []byte
		for i := 1; i <= count; i++ {
			input = append(input, bytes.Repeat([]byte{byte(i)}, 32)...)
		}
		reader := bytes.NewReader(input)
		allocation, err := allocateInitialization(reader, 2, recovery)
		if err != nil || reader.Len() != 0 {
			t.Fatal("initialization did not allocate the exact role set", err)
		}
		ids := allocation.Identities()
		if len(ids.Recipients) != 2 || (ids.Recovery != nil) != recovery || ids.NormalSigning.BindingID != contract.ID(bytes.Repeat([]byte{5}, 32)) ||
			ids.Authority.Encryption.BindingIncarnationID != contract.ID(bytes.Repeat([]byte{9}, 32)) {
			t.Fatal("initialization role allocation changed")
		}
		ids.Recipients[0].RecipientID = contract.ID{}
		if ids.Recovery != nil {
			ids.Recovery.RoleID = contract.ID{}
		}
		owned := allocation.Identities()
		if owned.Recipients[0].RecipientID.IsZero() || recovery && owned.Recovery.RoleID.IsZero() {
			t.Fatal("public allocation copy mutated its owner")
		}
		if _, err := allocateInitialization(bytes.NewReader(input[:len(input)-1]), 2, recovery); err == nil {
			t.Fatal("incomplete entropy admitted")
		}
	}
	if _, err := AllocateInitialization(contract.CryptoMaxRecipients, false); err == nil {
		t.Fatal("additional recipients exceeded registry bound")
	}
}

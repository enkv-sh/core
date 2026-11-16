package core

import (
	"bytes"
	"encoding/hex"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestCurrentBasisRequiresAdmittedPredecessor(t *testing.T) {
	for _, before := range []*StateSession{nil, {}} {
		for _, candidate := range []*Candidate{nil, {}, {session: before}} {
			if basis, err := qualifyCurrentBasis(t.Context(), before, candidate, contract.SuccessionRequestCore{}, nil); err == nil || basis != nil {
				t.Fatal("public candidate data created an independent current trust basis")
			}
		}
	}
}

// full_only: false
func TestCurrentBasisCloneOwnsCompletePublicBasis(t *testing.T) {
	id := contract.Hash([]byte("recipient"))
	basis := &qualifiedCurrentBasis{control: []byte{1}, selection: []byte{2}, enrollment: []recipientEnrollment{{id: id, status: contract.CurrentRecipient, name: "recipient"}}}
	cloned := basis.clone()
	basis.control[0] = 3
	basis.selection[0] = 4
	basis.enrollment[0].id[0] ^= 1
	basis.enrollment[0].name = "changed"
	basis.enrollment[0].status = contract.RetiredRecipient
	if cloned.control[0] != 1 || cloned.selection[0] != 2 || cloned.enrollment[0].id != id || cloned.enrollment[0].name != "recipient" || cloned.enrollment[0].status != contract.CurrentRecipient {
		t.Fatal("current basis retained mutable input backing")
	}
}

// full_only: false
func TestCurrentBasisRefusesObsoleteTrustInterpretation(t *testing.T) {
	state := generatedEmptyPredecessor(t)
	if _, ok := state.admission.currentControl(); !ok {
		t.Fatal("current basis refused")
	}
	descriptor, err := contract.DecodeGenesisDescriptorCore(state.admission.descriptor)
	if err != nil {
		t.Fatal(err)
	}
	// Independent SHA256 of the obsolete v8 interpretation domain, purpose
	// lists and support metadata; the wire schema itself has not changed.
	bytes, err := hex.DecodeString("719f88c954b8254d24e0fc673b1977e867e4432096dd6d8bc0924ef0b4e2b754")
	if err != nil {
		t.Fatal(err)
	}
	copy(descriptor.TrustInterpretationID[:], bytes)
	state.admission.descriptor, err = contract.EncodeGenesisDescriptorCore(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := state.admission.currentControl(); ok {
		t.Fatal("obsolete trust policy admitted")
	}
}

// full_only: false
func TestPublicBasisMatchesOnlyCompatibleCurrentControl(t *testing.T) {
	state := generatedEmptyPredecessor(t)
	basis := state.admission.publicBasis()
	domain, store := state.admission.domain, state.admission.store
	expected, err := basis.ControlCore(domain, store)
	if err != nil {
		t.Fatal(err)
	}
	body, err := contract.EncodeControlCore(expected)
	if err != nil {
		t.Fatal(err)
	}
	for _, condition := range []string{"unchanged", "advance", "new-incarnation", "regression", "domain", "store", "interpretation", "compatibility", "support", "signer", "authority-binding", "recovery", "invalid-basis", "wrong-domain", "wrong-store"} {
		t.Run(condition, func(t *testing.T) {
			current, err := contract.DecodeControlCore(body)
			if err != nil {
				t.Fatal(err)
			}
			source := basis
			suppliedDomain, suppliedStore := domain, store
			want := false
			switch condition {
			case "unchanged":
				want = true
			case "advance":
				current.AccessGeneration++
				want = true
			case "new-incarnation":
				current.AccessIncarnationID = contract.Hash([]byte("new authenticated access incarnation"))
				current.AccessGeneration = 1
				want = true
			case "regression":
				current.AccessGeneration--
			case "domain":
				current.DomainID = contract.Hash([]byte("another current domain"))
				current.NormalSigning.Binding.Domain = current.DomainID
			case "store":
				current.StoreID = contract.Hash([]byte("another current store"))
				current.NormalSigning.Binding.Store = current.StoreID
			case "interpretation":
				current.TrustInterpretationID = contract.Hash([]byte("another current interpretation"))
				current.NormalSigning.Binding.Interpretation = current.TrustInterpretationID
			case "compatibility":
				current.CompatibilityID = contract.Hash([]byte("another compatibility"))
			case "support":
				current.CryptoSupportID = contract.Hash([]byte("another support"))
			case "signer":
				current.NormalSigning.Binding.Epoch++
			case "authority-binding":
				current.AuthorityKMSBinding.BindingSerial++
			case "recovery":
				current.Recovery = &contract.RecoveryBindings{}
			case "invalid-basis":
				source = PublicBasis{}
			case "wrong-domain":
				suppliedDomain = contract.Hash([]byte("another basis domain"))
			case "wrong-store":
				suppliedStore.Identity = contract.Hash([]byte("another basis store"))
			}
			before, encodeErr := contract.EncodeControlCore(current)
			if got := source.MatchesCurrentControl(suppliedDomain, suppliedStore, current); got != want {
				t.Fatal("current/source control relation differs", condition, got, want)
			}
			after, afterErr := contract.EncodeControlCore(current)
			if (encodeErr == nil) != (afterErr == nil) || !bytes.Equal(before, after) {
				t.Fatal("basis comparison changed current control")
			}
		})
	}
	// Exercise the nonzero same-incarnation regression independently of the
	// genesis basis's generation-one floor.
	floor := expected
	floor.AccessGeneration = expected.AccessGeneration + 1
	if CurrentControlMatches(expected, floor) {
		t.Fatal("valid nonzero access generation regressed below its admitted basis")
	}
	recoveryState, _, _ := generatedCanonicalState(t, true)
	recoveryBasis := recoveryState.admission.publicBasis()
	recoveryDomain, recoveryStore := recoveryState.admission.domain, recoveryState.admission.store
	recoveryControl, err := recoveryBasis.ControlCore(recoveryDomain, recoveryStore)
	if err != nil || recoveryControl.Recovery == nil || !recoveryBasis.MatchesCurrentControl(recoveryDomain, recoveryStore, recoveryControl) {
		t.Fatal("valid enabled-Recovery basis was not admitted", err)
	}
	recoveryBody, err := contract.EncodeControlCore(recoveryControl)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"recovery-kek", "recovery-signing"} {
		t.Run(field, func(t *testing.T) {
			changed, err := contract.DecodeControlCore(recoveryBody)
			if err != nil {
				t.Fatal(err)
			}
			if field == "recovery-kek" {
				changed.Recovery.KMS.BindingSerial++
			} else {
				changed.Recovery.Signing.Binding.Epoch++
			}
			if _, err := contract.EncodeControlCore(changed); err != nil {
				t.Fatal("changed Recovery control is not structurally valid", err)
			}
			if recoveryBasis.MatchesCurrentControl(recoveryDomain, recoveryStore, changed) {
				t.Fatal("valid changed Recovery binding matched the unchanged basis", field)
			}
		})
	}
}

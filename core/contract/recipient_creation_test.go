package contract

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func recipientCreationLiteral(t *testing.T, encoded string) ID {
	t.Helper()
	b, err := hex.DecodeString(encoded)
	if err != nil || len(b) != len(ID{}) {
		t.Fatal("invalid independent identity literal")
	}
	return ID(b)
}

// full_only: false
func TestRecipientCreationIDDerivation(t *testing.T) {
	domain, snapshot, nonce := ID(bytes.Repeat([]byte{1}, 32)), ID(bytes.Repeat([]byte{2}, 32)), ID(bytes.Repeat([]byte{3}, 32))
	// Independent SHA-256 of "ENKV/recipient-creation/v1", NUL, domain,
	// snapshot and nonce, in that order. See tests/shared/testdata/README.md.
	want := recipientCreationLiteral(t, "1e0f632de874daa81aee1329862f853523752d968f470b92a94f56f45033f601")
	got, err := RecipientCreationID(domain, snapshot, nonce)
	if err != nil || got != want {
		t.Fatalf("recipient identity = %x, %v; want %x", got, err, want)
	}
	for _, tc := range []struct {
		name                    string
		domain, snapshot, nonce ID
	}{
		{"zero domain", ID{}, snapshot, nonce},
		{"zero snapshot", domain, ID{}, nonce},
		{"zero nonce", domain, snapshot, ID{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := RecipientCreationID(tc.domain, tc.snapshot, tc.nonce); err == nil || !got.IsZero() {
				t.Fatal("zero creation input produced an identity", got, err)
			}
		})
	}
	for index := range 3 {
		inputs := [3]ID{domain, snapshot, nonce}
		inputs[index][0] ^= 1
		changed, err := RecipientCreationID(inputs[0], inputs[1], inputs[2])
		if err != nil || changed.IsZero() || changed == want {
			t.Fatal("creation input did not bind identity", index, changed, err)
		}
	}
}

// full_only: false
func TestRecipientInitialBindingIDsDerivation(t *testing.T) {
	domain := ID(bytes.Repeat([]byte{1}, 32))
	recipient := recipientCreationLiteral(t, "1e0f632de874daa81aee1329862f853523752d968f470b92a94f56f45033f601")
	wantBinding := recipientCreationLiteral(t, "1335f7894345cceb330d579a02243aeae81ae5d6025d02304861ebf6a9bf34c6")
	wantIncarnation := recipientCreationLiteral(t, "1e34b1961d9a9f318d85f0c4357dbae41ce1cde49a340899d4e7660b45e1d581")
	binding, incarnation, err := RecipientInitialBindingIDs(domain, recipient)
	if err != nil || binding != wantBinding || incarnation != wantIncarnation {
		t.Fatalf("initial identities = %x, %x, %v; want %x, %x", binding, incarnation, err, wantBinding, wantIncarnation)
	}
	for _, inputs := range [][2]ID{{ID{}, recipient}, {domain, ID{}}} {
		binding, incarnation, err := RecipientInitialBindingIDs(inputs[0], inputs[1])
		if err == nil || !binding.IsZero() || !incarnation.IsZero() {
			t.Fatal("zero binding input produced identities", binding, incarnation, err)
		}
	}
	for index := range 2 {
		inputs := [2]ID{domain, recipient}
		inputs[index][0] ^= 1
		binding, incarnation, err := RecipientInitialBindingIDs(inputs[0], inputs[1])
		if err != nil || binding.IsZero() || incarnation.IsZero() || binding == wantBinding || incarnation == wantIncarnation || binding == incarnation {
			t.Fatal("initial binding identities lost domain separation", index, binding, incarnation, err)
		}
	}
}

package trust

import (
	"bytes"
	"context"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicRouteReopensAndRejectsInvalidSigning(t *testing.T) {
	id := contract.Hash([]byte("fixture route"))
	a := New(t, contract.GCP, id)
	b := New(t, contract.GCP, id)
	if !bytes.Equal(a.PublicKey(), b.PublicKey()) {
		t.Fatal("public route changed across reopen")
	}
	if result := a.Sign(context.Background(), contract.SignRequest{}); len(result.Signature) != 0 {
		t.Fatal("unsigned arbitrary request was accepted")
	}
	public := a.PublicKey()
	public[0] ^= 1
	if bytes.Equal(public, a.PublicKey()) {
		t.Fatal("public-key accessor aliases retained key")
	}
	recovery := NewRecovery(t, contract.GCP, id)
	if bytes.Equal(a.PublicKey(), recovery.PublicKey()) {
		t.Fatal("normal and recovery share signing material")
	}
}

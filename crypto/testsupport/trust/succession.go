package trust

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"enkv.sh/core/contract"
)

// Successor creates a separately controlled synthetic private route. The stable
// TrustID remains unchanged.
func (s *Signer) Successor(t testing.TB, before contract.PublicSigningBinding) (*Signer, contract.PublicSigningBinding) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := contract.PublicSigningBindingLength(before); err != nil || before.Provider != s.family || before.Role != s.role || before.Binding.Trust != s.id || before.KeySelector != s.selector || !bytes.Equal(before.SPKI, s.public) {
		t.Fatal("successor fixture requires the exact current signing binding")
	}
	after := before
	after.BindingID = contract.Hash(append([]byte("ENKV/TEST-SIGNING-SUCCESSOR/v1\x00"), before.BindingID[:]...))
	successor := newSigner(t, s.family, after.BindingID, s.role)
	successor.id = s.id
	if before.Binding.Epoch == ^uint64(0) {
		after.Binding.ControlIncarnationID = contract.Hash(append([]byte("ENKV/TEST-SIGNING-INCARNATION/v1\x00"), after.BindingID[:]...))
		after.Binding.Epoch = 1
	} else {
		after.Binding.Epoch++
	}
	after.SPKI = successor.PublicKey()
	after.KeySelector = successor.KeySelector()
	after.Fingerprint = contract.Hash(after.SPKI)
	after.Binding.PublicKey = after.Fingerprint
	after.SPKI = bytes.Clone(after.SPKI)
	if _, err := contract.PublicSigningBindingLength(after); err != nil {
		t.Fatal("invalid successor signing fixture", err)
	}
	return successor, after
}

// NewCurrent reconstructs only a synthetic route whose public binding exactly
// matches the selected current signer. No private signing state crosses Core.
func NewCurrent(t testing.TB, binding contract.PublicSigningBinding) *Signer {
	t.Helper()
	if _, err := contract.PublicSigningBindingLength(binding); err != nil {
		t.Fatal("invalid current signing fixture", err)
	}
	for _, identity := range []contract.ID{binding.Binding.Trust, binding.BindingID} {
		signer := newSigner(t, binding.Provider, identity, binding.Role)
		signer.id = binding.Binding.Trust
		if signer.selector == binding.KeySelector && bytes.Equal(signer.public, binding.SPKI) {
			return signer
		}
	}
	t.Fatal("current signing fixture route differs from selected public binding")
	return nil
}

// RetiredSuccessionProof creates only the signed kind-2 negative fixture from
// a valid recovery-signer replacement. Private material stays in this facade.
func (s *Signer) RetiredSuccessionProof(t testing.TB, subject contract.SuccessionSubject) ([]byte, []byte) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if subject.OperationKind != contract.SuccessionReplaceRecoveryBasis || subject.ChangeMask != contract.SuccessionChangeRecoverySigner || subject.ApprovalRole != s.role {
		t.Fatal("retired proof fixture requires the current authorizer's recovery-signer replacement")
	}
	body, err := contract.EncodeSuccessionSubject(subject)
	if err != nil {
		t.Fatal("invalid recovery-signer subject for retired proof fixture", err)
	}
	body[len("ENKV/SUCCESSION/v8\x00")+2] = 2
	digest := contract.Hash(body)
	signature, err := ecdsa.SignASN1(rand.Reader, s.key, digest[:])
	if err != nil {
		t.Fatal("retired proof fixture signing failed")
	}
	return body, signature
}

// Package trust owns synthetic signing material for component tests. It exposes
// typed signing operations and public records, never private keys.
package trust

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"sync"
	"testing"

	"enkv.sh/core/contract"
)

type Signer struct {
	mu                    sync.Mutex
	id                    contract.ID
	family                contract.Family
	role                  uint8
	key                   *ecdsa.PrivateKey
	public                []byte
	selector              string
	calls, qualifications int
	unavailable, corrupt  bool
}

var _ contract.QualifyingTrust = (*Signer)(nil)

func New(t testing.TB, family contract.Family, identity contract.ID) *Signer {
	t.Helper()
	return newSigner(t, family, identity, contract.NormalSigningRole)
}

func NewRecovery(t testing.TB, family contract.Family, identity contract.ID) *Signer {
	t.Helper()
	return newSigner(t, family, identity, contract.RecoverySigningRole)
}

// NewWithIdentity keeps the chosen synthetic key resource independent from the
// provider construction identity used in public bindings.
func NewWithIdentity(t testing.TB, family contract.Family, material, identity contract.ID, role uint8) *Signer {
	t.Helper()
	if identity.IsZero() || role != contract.NormalSigningRole && role != contract.RecoverySigningRole {
		t.Fatal("invalid test signing construction identity")
	}
	signer := newSigner(t, family, material, role)
	signer.id = identity
	return signer
}

func newSigner(t testing.TB, family contract.Family, identity contract.ID, role uint8) *Signer {
	t.Helper()
	if !family.Valid() || identity.IsZero() {
		t.Fatal("invalid test signing route")
	}
	// A test-only route reproduces its synthetic key in a fresh process. The
	// process message carries the public route identity, not a private key.
	seed := contract.Hash(append(append([]byte("ENKV/TEST-SIGNING-ROUTE/v1\x00"), identity[:]...), byte(family), role))
	curve := elliptic.P256()
	n := new(big.Int).Sub(curve.Params().N, big.NewInt(1))
	d := new(big.Int).SetBytes(seed[:])
	d.Mod(d, n).Add(d, big.NewInt(1))
	scalar := d.FillBytes(make([]byte, 32))
	key, err := ecdsa.ParseRawPrivateKey(curve, scalar)
	clear(scalar)
	clear(seed[:])
	if err != nil {
		t.Fatal("test signing key unavailable")
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal("test public signing key unavailable")
	}
	selector := fmt.Sprintf("projects/fixture/locations/us-central1/keyRings/fixture/cryptoKeys/signing-%x-%d/cryptoKeyVersions/1", identity[:8], role)
	if family == contract.AWS {
		fingerprint := contract.Hash(public)
		selector = fmt.Sprintf("arn:aws:kms:us-east-1:123456789012:key/%x-%x-%x-%x-%x", fingerprint[:4], fingerprint[4:6], fingerprint[6:8], fingerprint[8:10], fingerprint[10:16])
	}
	return &Signer{id: identity, family: family, role: role, key: key, public: public, selector: selector}
}

func (s *Signer) Identity() contract.ID   { return s.id }
func (s *Signer) Family() contract.Family { return s.family }
func (s *Signer) PublicKey() []byte       { return bytes.Clone(s.public) }
func (s *Signer) KeySelector() string     { return s.selector }
func (s *Signer) Calls() int              { s.mu.Lock(); defer s.mu.Unlock(); return s.calls }
func (s *Signer) QualificationCalls() int { s.mu.Lock(); defer s.mu.Unlock(); return s.qualifications }
func (s *Signer) SetUnavailable(v bool)   { s.mu.Lock(); defer s.mu.Unlock(); s.unavailable = v }
func (s *Signer) SetCorrupt(v bool)       { s.mu.Lock(); defer s.mu.Unlock(); s.corrupt = v }

func (s *Signer) Sign(ctx context.Context, request contract.SignRequest) contract.SignResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if ctx == nil || ctx.Err() != nil || s.unavailable {
		return contract.SignResult{Reason: contract.ReasonAccess}
	}
	if !request.Valid() || !contract.SigningPurposeAllowed(s.role, request.Purpose()) {
		return contract.SignResult{Reason: contract.ReasonProof}
	}
	digest := request.Digest()
	if s.corrupt {
		digest[0] ^= 1
	}
	signature, err := ecdsa.SignASN1(rand.Reader, s.key, digest[:])
	if err != nil {
		return contract.SignResult{Reason: contract.ReasonProof}
	}
	return contract.SignResult{Signature: signature}
}

func (s *Signer) QualifySigningBinding(ctx context.Context, binding contract.PublicSigningBinding) contract.SigningQualificationResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.qualifications++
	if ctx == nil || ctx.Err() != nil || s.unavailable {
		return contract.SigningQualificationResult{Reason: contract.ReasonAccess}
	}
	digest, err := contract.SigningBindingDigest(binding)
	if err != nil || binding.Role != s.role || binding.Provider != s.family || binding.KeySelector != s.selector || !bytes.Equal(binding.SPKI, s.public) || s.corrupt {
		return contract.SigningQualificationResult{Reason: contract.ReasonProof}
	}
	target := contract.NormalSignerTarget
	if s.role == contract.RecoverySigningRole {
		target = contract.RecoverySignerTarget
	}
	return contract.SigningQualificationResult{TargetRole: target, SigningBindingDigest: digest, Provider: s.family, Qualified: 1}
}

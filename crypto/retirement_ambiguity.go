package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"sync"

	"enkv.sh/core/contract"
)

// A proof can be bound once, to the retirement whose selected request commits
// to its public key. The installed interface exposes only its nonce and Close.
type retirementReturnProof struct {
	mu             sync.Mutex
	scalar, public []byte
	commitment     contract.ID
	claimed        bool
}

func NewRetirementReturnProof() (contract.RetirementReturnProof, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	public, err := key.PublicKey.Bytes()
	if err != nil {
		return nil, err
	}
	commitment, err := contract.RetirementReturnCommitment(public)
	if err != nil {
		return nil, err
	}
	scalar, err := key.Bytes()
	if err != nil {
		return nil, err
	}
	return &retirementReturnProof{scalar: scalar, public: public, commitment: commitment}, nil
}

func (p *retirementReturnProof) Commitment() contract.ID { return p.commitment }
func (p *retirementReturnProof) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	clear(p.scalar)
	p.scalar = nil
}

func (p *retirementReturnProof) claim(nonce contract.ID) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.scalar) == 0 || p.claimed || p.commitment != nonce {
		return false
	}
	p.claimed = true
	return true
}

func (p *retirementReturnProof) seal(o *generatedProducerReturnOwner, facts []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.claimed || len(p.scalar) == 0 || o.expired() {
		return nil, ErrAdmission
	}
	defer func() { clear(p.scalar); p.scalar = nil }()
	x := o.expected.Template
	v := contract.RetirementAmbiguityRecord{Domain: o.material.Core.DomainID, Operation: o.material.Core.OperationID, Attempt: x.AttemptID, Inbox: x.InboxID, Graph: o.expected.Plan.PlanGraphID, PublicKey: p.public, Facts: facts}
	digest, err := v.Digest()
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), p.scalar)
	if err != nil {
		return nil, err
	}
	v.Signature, err = ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	if o.expired() {
		return nil, ErrAdmission
	}
	return contract.EncodeRetirementAmbiguity(v)
}

package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"io"
	"time"

	"enkv.sh/core/contract"
)

// OpenContext can only be filled by an enclosing Core admission boundary.
// The local Authority adapter issues a protected, operation-scoped context;
// a parsed public descriptor cannot issue one.
type OpenContext struct{ admission *openAdmission }
type openAdmission struct {
	domain, trust, interpretation, recipient, composition contract.ID
	outputInterpreter                                     PublicOutputInterpreter
	publicationNamespaces                                 []publicationNamespace
	publicationPremise                                    func(contract.ID, contract.OutputTarget) (contract.ID, error)
	endWorkInvocation                                     contract.ID
	controlIncarnation                                    contract.ID
	store                                                 contract.Descriptor
	epoch                                                 uint64
	publicKey                                             []byte
	descriptor                                            []byte
	current                                               *qualifiedCurrentBasis
	observation                                           *readerPublicBasis
	expires                                               time.Time
	entropy                                               io.Reader
}

func (a openAdmission) valid(store contract.Store) bool {
	if store == nil || !a.store.Valid() || a.store != store.Descriptor() || a.domain.IsZero() || a.trust.IsZero() || a.interpretation != contract.InterpretationID() || a.recipient.IsZero() || a.composition.IsZero() || a.controlIncarnation.IsZero() || a.epoch == 0 || !time.Now().Before(a.expires) {
		return false
	}
	_, ok := a.currentControl()
	return ok
}
func (a openAdmission) domainBasis() (contract.GenesisDescriptorCore, bool) {
	if a.observation != nil {
		if a.current != nil || len(a.descriptor) != 0 || a.observation.observation == nil {
			return contract.GenesisDescriptorCore{}, false
		}
		head, image, configuration, ok := observationImage(*a.observation.observation)
		if !ok {
			return contract.GenesisDescriptorCore{}, false
		}
		return selectedGenesisClosure(head, &image, configuration)
	}
	if a.current != nil || a.epoch != 1 {
		return contract.GenesisDescriptorCore{}, false
	}
	d, err := contract.DecodeGenesisDescriptorCore(a.descriptor)
	if err != nil {
		return contract.GenesisDescriptorCore{}, false
	}
	return d, d.DomainID == a.domain && d.Provider == a.store.Family && d.StoreID == a.store.Identity && d.CoordinateID == a.store.Coordinate && d.NonBodyID == a.store.NonBody && d.TrustID == a.trust && d.InterpretationID == a.interpretation && d.TrustInterpretationID == contract.TrustInterpretationID() && d.CryptoSupportID == contract.CryptoSupportID() && d.CompatibilityID == contract.CompatibilityID() && d.AuthorityRecipientID == a.recipient && d.NormalSigning.Binding == binding(a)
}
func publicKey(der []byte) (*ecdsa.PublicKey, bool) {
	if len(der) == 0 || len(der) > contract.MaxPublicKey {
		return nil, false
	}
	v, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, false
	}
	k, ok := v.(*ecdsa.PublicKey)
	if !ok || k.Curve != elliptic.P256() {
		return nil, false
	}
	_, err = k.ECDH()
	return k, err == nil
}
func verify(key *ecdsa.PublicKey, request contract.SignRequest, signature []byte) bool {
	if key == nil || !request.Valid() || len(signature) == 0 || len(signature) > contract.MaxSignature {
		return false
	}
	d := request.Digest()
	return ecdsa.VerifyASN1(key, d[:], signature)
}
func binding(a openAdmission) contract.BindingSubject {
	return contract.BindingSubject{Domain: a.domain, Coordinate: a.store.Coordinate, Store: a.store.Identity, Trust: a.trust, PublicKey: contract.Hash(a.publicKey), Interpretation: a.interpretation, ControlIncarnationID: a.controlIncarnation, Epoch: a.epoch}
}

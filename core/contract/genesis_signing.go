package contract

import (
	"bytes"
	"context"
)

const (
	NormalSignerTarget           uint8 = 1
	RecoverySignerTarget         uint8 = 3
	GenesisSubjectLength               = 316
	GenesisK3ChallengeCoreLength       = 395
	genesisSubjectPrefix               = "ENKV/K2-GENESIS/v1\x00"
	genesisK3ChallengePrefix           = cryptoPurposePrefix + "genesis-k3-challenge-v1\x00"
)

type SigningQualificationResult struct {
	TargetRole           uint8
	SigningBindingDigest ID
	Provider             Family
	Qualified            uint8
	Reason               Reason
}

// QualifyingTrust can qualify an exact configured public signing route and its profile.
// Qualification does not establish candidate readiness or selection.
type QualifyingTrust interface {
	Trust
	QualifySigningBinding(context.Context, PublicSigningBinding) SigningQualificationResult
}

func SigningBindingDigest(v PublicSigningBinding) (ID, error) {
	if _, err := PublicSigningBindingLength(v); err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter(cryptoPurposePrefix + "signing-binding-v1\x00")
	writePublicSigningBindingBlob(&w, v)
	return w.result(0).Digest, nil
}
func NewK3BasisRequest(v PublicSigningBinding) (SignRequest, error) {
	if v.Role != RecoverySigningRole {
		return SignRequest{}, ErrSubject
	}
	if _, err := PublicSigningBindingLength(v); err != nil {
		return SignRequest{}, err
	}
	w := cryptoHashWriter(cryptoPurposePrefix + "k3-basis-binding\x00")
	writePublicSigningBindingBlob(&w, v)
	return SignRequest{purpose: K3BasisPurpose, digest: w.result(0).Digest}, nil
}

// These finite purpose sets own both signer admission and its interpretation
// commitment. They add no purpose beyond the existing role contract.
const normalSigningPurposeSet uint32 = 1<<BindingPurpose | 1<<LifecyclePurpose | 1<<GenesisPurpose | 1<<K2SuccessionPurpose | 1<<SuccessorSignerProbePurpose | 1<<GeneratorPurpose | 1<<EndWorkPurpose | 1<<SelectionAcceptancePurpose | 1<<OutputReservePurpose | 1<<OutputClosePurpose | 1<<GCPurpose
const recoverySigningPurposeSet uint32 = 1<<K3BasisPurpose | 1<<K3InitChallengePurpose | 1<<K3SuccessionPurpose | 1<<SuccessorSignerProbePurpose | 1<<SelectionAcceptancePurpose

func SigningPurposeAllowed(role uint8, p Purpose) bool {
	if p >= 32 {
		return false
	}
	var allowed uint32
	switch role {
	case NormalSigningRole:
		allowed = normalSigningPurposeSet
	case RecoverySigningRole:
		allowed = recoverySigningPurposeSet
	}
	return allowed&(1<<p) != 0
}

type GenesisK3ChallengeCore struct {
	InitID, DomainID, DescriptorDigest, RequestCoreDigest, GenesisPlanDigest                               ID
	StoreID, CoordinateID, RecoveryRoleID, K3SigningBindingDigest, RecoveryKMSBindingDigest, K3ChallengeID ID
}

func (v GenesisK3ChallengeCore) ids() []ID {
	return []ID{v.InitID, v.DomainID, v.DescriptorDigest, v.RequestCoreDigest, v.GenesisPlanDigest, v.StoreID, v.CoordinateID, v.RecoveryRoleID, v.K3SigningBindingDigest, v.RecoveryKMSBindingDigest, v.K3ChallengeID}
}
func writeGenesisK3ChallengeCore(w *cryptoWriter, v GenesisK3ChallengeCore) {
	w.raw([]byte(genesisK3ChallengePrefix))
	w.u16(CanonicalSchema)
	w.u16(GenesisProfile)
	for _, id := range v.ids() {
		w.id(id)
	}
}
func EncodeGenesisK3ChallengeCore(v GenesisK3ChallengeCore) ([]byte, error) {
	if !publicIDsValid(v.ids()...) {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, GenesisK3ChallengeCoreLength)}
	writeGenesisK3ChallengeCore(&w, v)
	return w.b, nil
}
func DecodeGenesisK3ChallengeCore(b []byte) (GenesisK3ChallengeCore, error) {
	if len(b) > GenesisK3ChallengeCoreLength {
		return GenesisK3ChallengeCore{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	if !bytes.Equal(r.take(len(genesisK3ChallengePrefix)), []byte(genesisK3ChallengePrefix)) || r.u16() != CanonicalSchema || r.u16() != GenesisProfile {
		return GenesisK3ChallengeCore{}, ErrRecord
	}
	v := GenesisK3ChallengeCore{InitID: r.requiredID(), DomainID: r.requiredID(), DescriptorDigest: r.requiredID(), RequestCoreDigest: r.requiredID(), GenesisPlanDigest: r.requiredID(), StoreID: r.requiredID(), CoordinateID: r.requiredID(), RecoveryRoleID: r.requiredID(), K3SigningBindingDigest: r.requiredID(), RecoveryKMSBindingDigest: r.requiredID(), K3ChallengeID: r.requiredID()}
	if err := r.end(); err != nil {
		return GenesisK3ChallengeCore{}, err
	}
	return v, nil
}
func NewK3InitChallengeRequest(v GenesisK3ChallengeCore) (SignRequest, error) {
	if !publicIDsValid(v.ids()...) {
		return SignRequest{}, ErrSubject
	}
	w := cryptoHashWriter("")
	writeGenesisK3ChallengeCore(&w, v)
	return SignRequest{purpose: K3InitChallengePurpose, digest: w.result(0).Digest}, nil
}

type GenesisSubject struct {
	InitID, DomainID, DescriptorDigest                                                                                  ID
	RequestCoreDigest, GenesisPlanDigest, ManifestDigest, BootstrapClosureDigest, HeadCoreDigest, ConditionalPlanDigest ID
	HeadCoreLength                                                                                                      uint32
	RecoveryMode                                                                                                        uint8
}

func (v GenesisSubject) ids() []ID {
	return []ID{v.InitID, v.DomainID, v.DescriptorDigest, v.RequestCoreDigest, v.GenesisPlanDigest, v.ManifestDigest, v.BootstrapClosureDigest, v.HeadCoreDigest, v.ConditionalPlanDigest}
}
func (v GenesisSubject) valid() bool {
	return publicIDsValid(v.ids()...) && v.HeadCoreLength == 349 && v.RecoveryMode <= 1
}
func writeGenesisSubject(w *cryptoWriter, v GenesisSubject) {
	w.raw([]byte(genesisSubjectPrefix))
	w.u16(CanonicalSchema)
	w.u16(GenesisProfile)
	for _, id := range v.ids() {
		w.id(id)
	}
	w.u32(v.HeadCoreLength)
	w.u8(v.RecoveryMode)
}
func EncodeGenesisSubject(v GenesisSubject) ([]byte, error) {
	if !v.valid() {
		return nil, ErrSubject
	}
	w := cryptoWriter{b: make([]byte, 0, GenesisSubjectLength)}
	writeGenesisSubject(&w, v)
	return w.b, nil
}
func DecodeGenesisSubject(b []byte) (GenesisSubject, error) {
	if len(b) > GenesisSubjectLength {
		return GenesisSubject{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	if !bytes.Equal(r.take(len(genesisSubjectPrefix)), []byte(genesisSubjectPrefix)) || r.u16() != CanonicalSchema || r.u16() != GenesisProfile {
		return GenesisSubject{}, ErrSubject
	}
	v := GenesisSubject{InitID: r.requiredID(), DomainID: r.requiredID(), DescriptorDigest: r.requiredID(), RequestCoreDigest: r.requiredID(), GenesisPlanDigest: r.requiredID(), ManifestDigest: r.requiredID(), BootstrapClosureDigest: r.requiredID(), HeadCoreDigest: r.requiredID(), ConditionalPlanDigest: r.requiredID(), HeadCoreLength: r.u32(), RecoveryMode: r.u8()}
	if err := r.end(); err != nil {
		return GenesisSubject{}, err
	}
	if !v.valid() {
		return GenesisSubject{}, ErrSubject
	}
	return v, nil
}
func NewGenesisRequest(v GenesisSubject) (SignRequest, error) {
	if !v.valid() {
		return SignRequest{}, ErrSubject
	}
	w := cryptoHashWriter("")
	writeGenesisSubject(&w, v)
	return SignRequest{purpose: GenesisPurpose, digest: w.result(0).Digest}, nil
}

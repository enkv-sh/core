// Package compositionaws selects only the AWS provider pair at build time.
package compositionaws

import (
	"errors"

	core "enkv.sh/core"
	"enkv.sh/core/contract"
	awsprovider "enkv.sh/providers/aws"
)

// StateSession pins the neutral component in this composition's compiled closure.
type StateSession = core.StateSession

var ErrClass = errors.New("unlisted AWS construction or verifier class")

type Config struct {
	StoreClass, TrustClass, VerifierClass string
	Store                                 awsprovider.StoreConfig
	Trust                                 awsprovider.TrustConfig
	KeyAccess                             []awsprovider.KeyAccessConfig
}

func CompatibilityManifest() contract.CompatibilityManifest {
	return contract.CompatibilityManifest{
		Identity: contract.Hash([]byte("enkv/composition/aws/v1")), Core: contract.CoreVersion, Engine: contract.EngineVersion, Format: contract.FormatVersion, ComponentContract: contract.ComponentContractVersion, Crypto: contract.CryptoVersion, CryptoProfile: contract.CryptoProfile,
		Components:    []contract.ComponentImplementation{{Family: contract.AWS, Kind: contract.StoreComponentKind, Class: awsprovider.StoreClass, Module: "enkv.sh/providers/aws", Version: "v0.0.0"}, {Family: contract.AWS, Kind: contract.TrustComponentKind, Class: awsprovider.TrustClass, Module: "enkv.sh/providers/aws", Version: "v0.0.0"}},
		Verifiers:     []contract.VerifierParser{{Family: contract.AWS, Class: awsprovider.VerifierClass, Parse: awsprovider.ParseVerifier}},
		Constructions: []contract.ConstructionClass{{Family: contract.AWS, Kind: contract.StoreComponentKind, Class: awsprovider.StoreClass}, {Family: contract.AWS, Kind: contract.TrustComponentKind, Class: awsprovider.TrustClass}},
	}
}
func New(c Config) (contract.Cell, error) {
	if c.StoreClass != awsprovider.StoreClass || c.TrustClass != awsprovider.TrustClass || c.VerifierClass != awsprovider.VerifierClass {
		return contract.Cell{}, ErrClass
	}
	s, err := awsprovider.NewStore(c.Store)
	if err != nil {
		return contract.Cell{}, err
	}
	t, err := awsprovider.NewTrust(c.Trust)
	if err != nil {
		return contract.Cell{}, err
	}
	crypto, err := awsprovider.NewCrypto(c.KeyAccess)
	if err != nil {
		return contract.Cell{}, err
	}
	sid, tid := s.Descriptor().Identity, t.Identity()
	body := append([]byte("ENKV/CELL/AWS/v1\x00"), sid[:]...)
	body = append(body, tid[:]...)
	return contract.Cell{Store: s, Trust: t, Crypto: crypto, Identity: contract.Hash(body)}, nil
}

// NewAuthority constructs only the Store and normal Trust routes used by an
// effect-free Authority operation. It applies the same closed class selection
// as New and does not construct a KEK or generator effect route.
func NewAuthority(c Config) (contract.Store, contract.Trust, error) {
	if c.StoreClass != awsprovider.StoreClass || c.TrustClass != awsprovider.TrustClass || c.VerifierClass != awsprovider.VerifierClass ||
		len(c.KeyAccess) != 0 {
		return nil, nil, ErrClass
	}
	s, err := awsprovider.NewStore(c.Store)
	if err != nil {
		return nil, nil, err
	}
	t, err := awsprovider.NewTrust(c.Trust)
	if err != nil {
		return nil, nil, err
	}
	return s, t, nil
}

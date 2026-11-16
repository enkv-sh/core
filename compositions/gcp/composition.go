// Package compositiongcp selects only the GCP provider pair at build time.
package compositiongcp

import (
	"context"
	"errors"

	core "enkv.sh/core"
	"enkv.sh/core/contract"
	gcpprovider "enkv.sh/providers/gcp"
)

// StateSession pins the neutral component in this composition's compiled closure.
type StateSession = core.StateSession

var ErrClass = errors.New("unlisted GCP construction or verifier class")

type Config struct {
	StoreClass, TrustClass, VerifierClass string
	Store                                 gcpprovider.StoreConfig
	Trust                                 gcpprovider.TrustConfig
	KeyAccess                             []gcpprovider.KeyAccessConfig
}

func CompatibilityManifest() contract.CompatibilityManifest {
	return contract.CompatibilityManifest{
		Identity: contract.Hash([]byte("enkv/composition/gcp/v1")), Core: contract.CoreVersion, Engine: contract.EngineVersion, Format: contract.FormatVersion, ComponentContract: contract.ComponentContractVersion, Crypto: contract.CryptoVersion, CryptoProfile: contract.CryptoProfile,
		Components:    []contract.ComponentImplementation{{Family: contract.GCP, Kind: contract.StoreComponentKind, Class: gcpprovider.StoreClass, Module: "enkv.sh/providers/gcp", Version: "v0.0.0"}, {Family: contract.GCP, Kind: contract.TrustComponentKind, Class: gcpprovider.TrustClass, Module: "enkv.sh/providers/gcp", Version: "v0.0.0"}},
		Verifiers:     []contract.VerifierParser{{Family: contract.GCP, Class: gcpprovider.VerifierClass, Parse: gcpprovider.ParseVerifier}},
		Constructions: []contract.ConstructionClass{{Family: contract.GCP, Kind: contract.StoreComponentKind, Class: gcpprovider.StoreClass}, {Family: contract.GCP, Kind: contract.TrustComponentKind, Class: gcpprovider.TrustClass}},
	}
}
func New(ctx context.Context, c Config) (contract.Cell, error) {
	if c.StoreClass != gcpprovider.StoreClass || c.TrustClass != gcpprovider.TrustClass || c.VerifierClass != gcpprovider.VerifierClass {
		return contract.Cell{}, ErrClass
	}
	if _, err := gcpprovider.ParseVerifier(c.Trust.PublicKey); err != nil {
		return contract.Cell{}, err
	}
	s, err := gcpprovider.NewStore(ctx, c.Store)
	if err != nil {
		return contract.Cell{}, err
	}
	t, err := gcpprovider.NewTrust(ctx, c.Trust)
	if err != nil {
		return contract.Cell{}, err
	}
	crypto, err := gcpprovider.NewCrypto(ctx, c.KeyAccess)
	if err != nil {
		return contract.Cell{}, err
	}
	sid, tid := s.Descriptor().Identity, t.Identity()
	body := append([]byte("ENKV/CELL/GCP/v1\x00"), sid[:]...)
	body = append(body, tid[:]...)
	return contract.Cell{Store: s, Trust: t, Crypto: crypto, Identity: contract.Hash(body)}, nil
}

// NewAuthority constructs only the Store and normal Trust routes used by an
// effect-free Authority operation. No Crypto, KEK or effect client is loaded.
func NewAuthority(ctx context.Context, c Config) (contract.Store, contract.Trust, error) {
	if c.StoreClass != gcpprovider.StoreClass || c.TrustClass != gcpprovider.TrustClass || c.VerifierClass != gcpprovider.VerifierClass ||
		len(c.KeyAccess) != 0 {
		return nil, nil, ErrClass
	}
	if _, err := gcpprovider.ParseVerifier(c.Trust.PublicKey); err != nil {
		return nil, nil, err
	}
	s, err := gcpprovider.NewStore(ctx, c.Store)
	if err != nil {
		return nil, nil, err
	}
	t, err := gcpprovider.NewTrust(ctx, c.Trust)
	if err != nil {
		return nil, nil, err
	}
	return s, t, nil
}

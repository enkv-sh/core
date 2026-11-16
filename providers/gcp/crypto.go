package gcp

import (
	"context"

	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
)

// NewCrypto installs the exact GCP key-access routes. Construction grants no
// source, operation or consumer admission and makes no provider call.
func NewCrypto(ctx context.Context, configs []KeyAccessConfig) (contract.Crypto, error) {
	if len(configs) == 0 || len(configs) > contract.CryptoMaxRecipients+1 {
		return nil, ErrConstruction
	}
	routes := make([]enkvcrypto.KeyAccess, len(configs))
	for i, config := range configs {
		route, err := NewKeyAccess(ctx, config)
		if err != nil {
			return nil, err
		}
		routes[i] = route
	}
	runtime, err := enkvcrypto.New(contract.GCP, routes)
	if err != nil {
		return nil, ErrConstruction
	}
	return runtime, nil
}

package compositionfull

import (
	"context"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
)

type configurationReplacementProviders struct {
	store      contract.Store
	close      func()
	signing    func(context.Context, string, uint8) (*core.ReplacementSigningKey, error)
	encryption func(context.Context, string) (*core.ReplacementEncryptionKey, error)
	signer     func(context.Context, contract.PublicSigningBinding) (contract.QualifyingTrust, error)
	privateKey func(context.Context, contract.KMSBinding, contract.ID) (enkvcrypto.KeyAccess, error)
	publicKey  func(context.Context, contract.KMSBinding, contract.ID) (enkvcrypto.PublicKeyQualifier, error)
}

// Only Store and credential discovery run here. Public lookup and private
// capability construction remain separate callbacks for Core's admitted stages.
func openConfigurationReplacementProviders(ctx context.Context, model *configuration.Model) (configurationReplacementProviders, error) {
	if ctx == nil || model == nil {
		return configurationReplacementProviders{}, errConfigurationReplacement
	}
	route := contract.Hash(append([]byte("enkv/keys-replacement/default-credential-route/v1\x00"), model.DomainID[:]...))
	transport := configurationProviderTransport()
	resources, err := selectReplacementProviders(ctx, model, route, transport)
	if err != nil {
		transport.CloseIdleConnections()
	}
	return resources, err
}

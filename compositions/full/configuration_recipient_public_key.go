package compositionfull

import (
	"context"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
)

// This path constructs only a public lookup client. In particular it does not
// construct initialization resources, a Store or private KeyAccess.
func resolveConfigurationRecipientPublicKey(ctx context.Context, model *configuration.Model, selector string) ([]byte, uint8, error) {
	if model == nil || !contract.PublicKeySelectorValid(model.Provider, selector, false) {
		return nil, 0, ErrLocalEdit
	}
	transport := configurationProviderTransport()
	defer transport.CloseIdleConnections()
	route := contract.Hash(append(append([]byte("ENKV/configuration/recipient-public-key/v1\x00"), model.DomainID[:]...), selector...))
	return selectRecipientPublicKey(ctx, model.Provider, selector, route, transport)
}

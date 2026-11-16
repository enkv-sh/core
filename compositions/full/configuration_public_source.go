package compositionfull

import (
	"context"
	"errors"
	"net/http"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
)

var errConfigurationPublicRead = errors.New("public configuration read source refused")

func configurationPublicReadRoute(ctx context.Context, m *configuration.Model, transport *http.Transport) (contract.ID, error) {
	if ctx == nil || ctx.Err() != nil || m == nil || transport == nil {
		return contract.ID{}, errConfigurationPublicRead
	}
	_, store, err := configurationPublicBasis(m)
	if err != nil {
		return contract.ID{}, err
	}
	return contract.Hash(append([]byte("ENKV/configuration/public-read/v1\x00"), store.Identity[:]...)), nil
}

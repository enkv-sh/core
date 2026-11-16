//go:build !enkv_aws

package compositionfull

import (
	"context"
	"encoding/hex"
	"net/http"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
	gcpprovider "enkv.sh/providers/gcp"
)

func defaultGCPInitializationResources(ctx context.Context, m *configuration.Model, route contract.ID, transport *http.Transport) (initializationResources, error) {
	credentials, err := gcpprovider.LoadDefaultCredentials(ctx)
	if err != nil {
		return initializationResources{}, errInitializationConfiguration
	}
	client, err := gcpprovider.NewClient(transport, credentials)
	if err != nil {
		return initializationResources{}, errInitializationConfiguration
	}
	text := hex.EncodeToString(route[:])
	store, err := gcpprovider.NewStore(ctx, gcpprovider.StoreConfig{Client: client, Domain: m.DomainID, Region: m.Store.Region, Endpoint: gcpprovider.StorageEndpoint(m.Store.Region), Bucket: m.Store.Bucket, Prefix: m.Store.PrefixBeforeHEAD, CredentialRoute: text})
	if err != nil {
		return initializationResources{}, errInitializationConfiguration
	}
	return initializationResources{store: store,
		signing: func(ctx context.Context, selector string, role uint8) (contract.QualifyingTrust, []byte, error) {
			key, ok := contract.ParseGCPKeySelector(selector, true)
			if !ok {
				return nil, nil, errInitializationConfiguration
			}
			anchor, err := gcpprovider.NewPublicSigningAnchor(ctx, gcpprovider.PublicSigningAnchorConfig{Role: role, Client: client, Region: key.Region, KeyVersion: selector, CredentialRoute: text})
			if err != nil {
				return nil, nil, errInitializationConfiguration
			}
			public, _, reason := anchor.ResolveSigningKey(ctx)
			if reason != contract.ReasonNone {
				return nil, nil, errInitializationConfiguration
			}
			trust, err := gcpprovider.NewTrust(ctx, gcpprovider.TrustConfig{Role: role, Client: client, Region: key.Region, Endpoint: gcpprovider.KMSEndpoint(key.Region), CredentialRoute: text, KeyVersion: selector, Algorithm: gcpprovider.SigningAlgorithm, Purpose: gcpprovider.SigningPurpose, PublicKey: public})
			if err != nil {
				return nil, nil, errInitializationConfiguration
			}
			return trust, public, nil
		},
		encryption: func(ctx context.Context, selector string, bindingID contract.ID) ([]byte, uint8, enkvcrypto.KeyAccess, error) {
			key, ok := contract.ParseGCPKeySelector(selector, false)
			if !ok {
				return nil, 0, nil, errInitializationConfiguration
			}
			c := gcpprovider.KeyAccessConfig{Client: client, Project: key.Project, Region: key.Region, Endpoint: gcpprovider.KMSEndpoint(key.Region), CredentialRoute: bindingID}
			public, _, protection, result := gcpprovider.ResolveEncryptionKey(ctx, c, selector)
			if result.Status != enkvcrypto.KeyOK {
				return nil, 0, nil, errInitializationConfiguration
			}
			access, err := gcpprovider.NewKeyAccess(ctx, c)
			if err != nil {
				return nil, 0, nil, errInitializationConfiguration
			}
			return public, protection, access, nil
		}}, nil
}

func resolveGCPConfigurationRecipientPublicKey(ctx context.Context, selector string, route contract.ID, transport *http.Transport) ([]byte, uint8, error) {
	key, ok := contract.ParseGCPKeySelector(selector, false)
	if !ok {
		return nil, 0, ErrLocalEdit
	}
	credentials, err := gcpprovider.LoadDefaultCredentials(ctx)
	if err != nil {
		return nil, 0, err
	}
	client, err := gcpprovider.NewClient(transport, credentials)
	if err != nil {
		return nil, 0, err
	}
	config := gcpprovider.KeyAccessConfig{Client: client, Project: key.Project, Region: key.Region, Endpoint: gcpprovider.KMSEndpoint(key.Region), CredentialRoute: route}
	public, _, protection, result := gcpprovider.ResolveEncryptionKey(ctx, config, selector)
	if result.Status != enkvcrypto.KeyOK {
		return nil, 0, ErrLocalEdit
	}
	return public, protection, nil
}

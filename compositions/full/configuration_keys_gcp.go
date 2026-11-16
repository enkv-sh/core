//go:build !enkv_aws

package compositionfull

import (
	"context"
	"encoding/hex"
	"net/http"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
	gcpprovider "enkv.sh/providers/gcp"
)

func openGCPConfigurationReplacementProviders(ctx context.Context, model *configuration.Model, route contract.ID, transport *http.Transport) (configurationReplacementProviders, error) {
	family, domain, location := model.Provider, model.DomainID, model.Store
	credentials, err := gcpprovider.LoadDefaultCredentials(ctx)
	if err != nil {
		return configurationReplacementProviders{}, err
	}
	client, err := gcpprovider.NewClient(transport, credentials)
	if err != nil {
		return configurationReplacementProviders{}, err
	}
	text := hex.EncodeToString(route[:])
	store, err := gcpprovider.NewStore(ctx, gcpprovider.StoreConfig{Client: client, Domain: domain, Region: location.Region, Endpoint: gcpprovider.StorageEndpoint(location.Region), Bucket: location.Bucket, Prefix: location.PrefixBeforeHEAD, CredentialRoute: text})
	if err != nil {
		return configurationReplacementProviders{}, err
	}
	return configurationReplacementProviders{store: store, close: transport.CloseIdleConnections,
		signing: func(ctx context.Context, selector string, role uint8) (*core.ReplacementSigningKey, error) {
			key, ok := contract.ParseGCPKeySelector(selector, true)
			if !ok {
				return nil, errConfigurationReplacement
			}
			anchor, err := gcpprovider.NewPublicSigningAnchor(ctx, gcpprovider.PublicSigningAnchorConfig{Role: role, Client: client, Region: key.Region, KeyVersion: selector, CredentialRoute: text})
			if err != nil {
				return nil, err
			}
			public, fingerprint, reason := anchor.ResolveSigningKey(ctx)
			if reason != contract.ReasonNone {
				return nil, errConfigurationReplacement
			}
			return &core.ReplacementSigningKey{Selector: selector, SPKI: public, Fingerprint: fingerprint, Trust: anchor.Identity(), Profile: contract.P256SigningProfile}, nil
		},
		encryption: func(ctx context.Context, selector string) (*core.ReplacementEncryptionKey, error) {
			key, ok := contract.ParseGCPKeySelector(selector, false)
			if !ok {
				return nil, errConfigurationReplacement
			}
			public, fingerprint, protection, result := gcpprovider.ResolveEncryptionKey(ctx, gcpprovider.KeyAccessConfig{Client: client, Project: key.Project, Region: key.Region, Endpoint: gcpprovider.KMSEndpoint(key.Region), CredentialRoute: route}, selector)
			if result.Status != enkvcrypto.KeyOK {
				return nil, errConfigurationReplacement
			}
			return &core.ReplacementEncryptionKey{Selector: selector, SPKI: public, Fingerprint: fingerprint, Profile: contract.RSAOAEPWrapProfile, ProtectionClass: protection}, nil
		},
		signer: func(ctx context.Context, binding contract.PublicSigningBinding) (contract.QualifyingTrust, error) {
			key, ok := contract.ParseGCPKeySelector(binding.KeySelector, true)
			if !ok || binding.Provider != family {
				return nil, errConfigurationReplacement
			}
			return gcpprovider.NewTrust(ctx, gcpprovider.TrustConfig{Role: binding.Role, Client: client, Region: key.Region, Endpoint: gcpprovider.KMSEndpoint(key.Region), CredentialRoute: text, KeyVersion: binding.KeySelector, Algorithm: gcpprovider.SigningAlgorithm, Purpose: gcpprovider.SigningPurpose, PublicKey: binding.SPKI})
		},
		privateKey: func(ctx context.Context, binding contract.KMSBinding, privateRoute contract.ID) (enkvcrypto.KeyAccess, error) {
			key, ok := contract.ParseGCPKeySelector(binding.KeySelector, false)
			if !ok || binding.Provider != family {
				return nil, errConfigurationReplacement
			}
			return gcpprovider.NewKeyAccess(ctx, gcpprovider.KeyAccessConfig{Client: client, Project: key.Project, Region: key.Region, Endpoint: gcpprovider.KMSEndpoint(key.Region), CredentialRoute: privateRoute})
		},
		publicKey: func(ctx context.Context, binding contract.KMSBinding, publicRoute contract.ID) (enkvcrypto.PublicKeyQualifier, error) {
			key, ok := contract.ParseGCPKeySelector(binding.KeySelector, false)
			if !ok || binding.Provider != family {
				return nil, errConfigurationReplacement
			}
			return gcpprovider.NewPublicEncryptionQualifier(ctx, gcpprovider.KeyAccessConfig{Client: client, Project: key.Project, Region: key.Region, Endpoint: gcpprovider.KMSEndpoint(key.Region), CredentialRoute: publicRoute}, binding)
		}}, nil
}

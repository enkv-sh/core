//go:build !enkv_gcp

package compositionfull

import (
	"context"
	"net/http"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
	awsprovider "enkv.sh/providers/aws"
)

func openAWSConfigurationReplacementProviders(ctx context.Context, model *configuration.Model, route contract.ID, transport *http.Transport) (configurationReplacementProviders, error) {
	family, domain, location := model.Provider, model.DomainID, model.Store
	credentials, err := awsprovider.LoadDefaultCredentials(ctx, location.Region)
	if err != nil {
		return configurationReplacementProviders{}, err
	}
	store, err := awsprovider.NewStore(awsprovider.StoreConfig{Region: location.Region, Bucket: location.Bucket, ExpectedBucketOwner: location.ExpectedOwner, Prefix: location.PrefixBeforeHEAD, Domain: domain, CredentialRoute: route, Credentials: credentials, Transport: transport, Timeout: time.Minute})
	if err != nil {
		return configurationReplacementProviders{}, err
	}
	return configurationReplacementProviders{store: store, close: transport.CloseIdleConnections,
		signing: func(ctx context.Context, selector string, role uint8) (*core.ReplacementSigningKey, error) {
			key, ok := contract.ParseAWSKeySelector(selector, true)
			if !ok {
				return nil, errConfigurationReplacement
			}
			anchor, err := awsprovider.NewPublicSigningAnchor(awsprovider.PublicSigningAnchorConfig{Role: role, Region: key.Region, KeyARN: selector, CredentialRoute: route, Credentials: credentials, Transport: transport, Timeout: time.Minute})
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
			key, ok := contract.ParseAWSKeySelector(selector, false)
			if !ok {
				return nil, errConfigurationReplacement
			}
			public, fingerprint, protection, result := awsprovider.ResolveEncryptionKey(ctx, awsprovider.KeyAccessConfig{Region: key.Region, Account: key.Account, CredentialRoute: route, Credentials: credentials, Transport: transport, Timeout: time.Minute}, selector)
			if result.Status != enkvcrypto.KeyOK {
				return nil, errConfigurationReplacement
			}
			return &core.ReplacementEncryptionKey{Selector: selector, SPKI: public, Fingerprint: fingerprint, Profile: contract.RSAOAEPWrapProfile, ProtectionClass: protection}, nil
		},
		signer: func(ctx context.Context, binding contract.PublicSigningBinding) (contract.QualifyingTrust, error) {
			key, ok := contract.ParseAWSKeySelector(binding.KeySelector, true)
			if !ok || binding.Provider != family {
				return nil, errConfigurationReplacement
			}
			return awsprovider.NewTrust(awsprovider.TrustConfig{Role: binding.Role, Region: key.Region, KeyARN: binding.KeySelector, PublicKeyDER: binding.SPKI, CredentialRoute: route, Credentials: credentials, Transport: transport, Timeout: time.Minute})
		},
		privateKey: func(ctx context.Context, binding contract.KMSBinding, privateRoute contract.ID) (enkvcrypto.KeyAccess, error) {
			key, ok := contract.ParseAWSKeySelector(binding.KeySelector, false)
			if !ok || binding.Provider != family {
				return nil, errConfigurationReplacement
			}
			return awsprovider.NewKeyAccess(awsprovider.KeyAccessConfig{Region: key.Region, Account: key.Account, CredentialRoute: privateRoute, Credentials: credentials, Transport: transport, Timeout: time.Minute})
		},
		publicKey: func(ctx context.Context, binding contract.KMSBinding, publicRoute contract.ID) (enkvcrypto.PublicKeyQualifier, error) {
			key, ok := contract.ParseAWSKeySelector(binding.KeySelector, false)
			if !ok || binding.Provider != family {
				return nil, errConfigurationReplacement
			}
			return awsprovider.NewPublicEncryptionQualifier(awsprovider.KeyAccessConfig{Region: key.Region, Account: key.Account, CredentialRoute: publicRoute, Credentials: credentials, Transport: transport, Timeout: time.Minute}, binding)
		}}, nil
}

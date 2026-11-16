//go:build !enkv_gcp

package compositionfull

import (
	"context"
	"net/http"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
	awsprovider "enkv.sh/providers/aws"
)

func defaultAWSInitializationResources(ctx context.Context, m *configuration.Model, route contract.ID, transport *http.Transport) (initializationResources, error) {
	credentials, err := awsprovider.LoadDefaultCredentials(ctx, m.Store.Region)
	if err != nil {
		return initializationResources{}, errInitializationConfiguration
	}
	store, err := awsprovider.NewStore(awsprovider.StoreConfig{Region: m.Store.Region, Bucket: m.Store.Bucket, ExpectedBucketOwner: m.Store.ExpectedOwner,
		Prefix: m.Store.PrefixBeforeHEAD, Domain: m.DomainID, CredentialRoute: route, Credentials: credentials, Transport: transport, Timeout: time.Minute})
	if err != nil {
		return initializationResources{}, errInitializationConfiguration
	}
	return initializationResources{store: store,
		signing: func(ctx context.Context, selector string, role uint8) (contract.QualifyingTrust, []byte, error) {
			key, ok := contract.ParseAWSKeySelector(selector, true)
			if !ok {
				return nil, nil, errInitializationConfiguration
			}
			anchor, err := awsprovider.NewPublicSigningAnchor(awsprovider.PublicSigningAnchorConfig{Role: role, Region: key.Region, KeyARN: selector, CredentialRoute: route, Credentials: credentials, Transport: transport, Timeout: time.Minute})
			if err != nil {
				return nil, nil, errInitializationConfiguration
			}
			public, _, reason := anchor.ResolveSigningKey(ctx)
			if reason != contract.ReasonNone {
				return nil, nil, errInitializationConfiguration
			}
			trust, err := awsprovider.NewTrust(awsprovider.TrustConfig{Role: role, Region: key.Region, KeyARN: selector, PublicKeyDER: public, CredentialRoute: route, Credentials: credentials, Transport: transport, Timeout: time.Minute})
			if err != nil {
				return nil, nil, errInitializationConfiguration
			}
			return trust, public, nil
		},
		encryption: func(ctx context.Context, selector string, bindingID contract.ID) ([]byte, uint8, enkvcrypto.KeyAccess, error) {
			key, ok := contract.ParseAWSKeySelector(selector, false)
			if !ok {
				return nil, 0, nil, errInitializationConfiguration
			}
			c := awsprovider.KeyAccessConfig{Region: key.Region, Account: key.Account, CredentialRoute: bindingID, Credentials: credentials, Transport: transport, Timeout: time.Minute}
			public, _, protection, result := awsprovider.ResolveEncryptionKey(ctx, c, selector)
			if result.Status != enkvcrypto.KeyOK {
				return nil, 0, nil, errInitializationConfiguration
			}
			access, err := awsprovider.NewKeyAccess(c)
			if err != nil {
				return nil, 0, nil, errInitializationConfiguration
			}
			return public, protection, access, nil
		}}, nil
}

func resolveAWSConfigurationRecipientPublicKey(ctx context.Context, selector string, route contract.ID, transport *http.Transport) ([]byte, uint8, error) {
	key, ok := contract.ParseAWSKeySelector(selector, false)
	if !ok {
		return nil, 0, ErrLocalEdit
	}
	credentials, err := awsprovider.LoadDefaultCredentials(ctx, key.Region)
	if err != nil {
		return nil, 0, err
	}
	config := awsprovider.KeyAccessConfig{Region: key.Region, Account: key.Account, CredentialRoute: route, Credentials: credentials, Transport: transport, Timeout: time.Minute}
	public, _, protection, result := awsprovider.ResolveEncryptionKey(ctx, config, selector)
	if result.Status != enkvcrypto.KeyOK {
		return nil, 0, ErrLocalEdit
	}
	return public, protection, nil
}

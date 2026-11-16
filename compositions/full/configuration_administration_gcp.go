//go:build !enkv_aws

package compositionfull

import (
	"context"
	"encoding/hex"
	"net/http"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	gcpprovider "enkv.sh/providers/gcp"
)

func openGCPConfigurationPublicSource(ctx context.Context, m *configuration.Model, transport *http.Transport, newClient func(*http.Transport, gcpprovider.CredentialSource) (*gcpprovider.Client, error)) (core.PublicSelectedReader, error) {
	if newClient == nil {
		return nil, errConfigurationPublicRead
	}
	route, err := configurationPublicReadRoute(ctx, m, transport)
	if err != nil {
		return nil, err
	}
	credentials, err := gcpprovider.LoadDefaultCredentials(ctx)
	if err != nil {
		return nil, err
	}
	client, err := newClient(transport, credentials)
	if err != nil {
		return nil, err
	}
	return gcpprovider.NewPublicReader(ctx, gcpprovider.StoreConfig{Client: client, Domain: m.DomainID, Region: m.Store.Region, Endpoint: gcpprovider.StorageEndpoint(m.Store.Region), Bucket: m.Store.Bucket, Prefix: m.Store.PrefixBeforeHEAD, CredentialRoute: hex.EncodeToString(route[:])})
}

func openGCPNativeAbandonmentResources(ctx context.Context, m *configuration.Model, s abandonmentSource, mutation bool, transport *http.Transport, out abandonmentResources,
	newClient func(*http.Transport, gcpprovider.CredentialSource) (*gcpprovider.Client, error)) (abandonmentResources, error) {
	if !mutation {
		var err error
		out.reader, err = openGCPConfigurationPublicSource(ctx, m, transport, newClient)
		return out, err
	}
	route := contract.Hash(append([]byte("enkv/abandon/default-credential-route/v1\x00"), s.store.Identity[:]...))
	credentials, err := gcpprovider.LoadDefaultCredentials(ctx)
	if err != nil {
		return out, err
	}
	client, err := newClient(transport, credentials)
	if err != nil {
		return out, err
	}
	text := hex.EncodeToString(route[:])
	storeConfig := gcpprovider.StoreConfig{Client: client, Domain: m.DomainID, Region: m.Store.Region, Endpoint: gcpprovider.StorageEndpoint(m.Store.Region), Bucket: m.Store.Bucket, Prefix: m.Store.PrefixBeforeHEAD, CredentialRoute: text}
	signing, ok := contract.ParseGCPKeySelector(s.control.NormalSigning.KeySelector, true)
	if !ok {
		return out, ErrAbandonmentPlan
	}
	out.store, err = gcpprovider.NewStore(ctx, storeConfig)
	if err != nil {
		return out, err
	}
	out.trust, err = gcpprovider.NewTrust(ctx, gcpprovider.TrustConfig{Client: client, Role: contract.NormalSigningRole, Region: signing.Region, Endpoint: gcpprovider.KMSEndpoint(signing.Region), CredentialRoute: text, KeyVersion: s.control.NormalSigning.KeySelector, Algorithm: gcpprovider.SigningAlgorithm, Purpose: gcpprovider.SigningPurpose, PublicKey: s.control.NormalSigning.SPKI})
	return out, err
}

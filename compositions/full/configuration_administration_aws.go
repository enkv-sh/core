//go:build !enkv_gcp

package compositionfull

import (
	"context"
	"net/http"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	awsprovider "enkv.sh/providers/aws"
)

func openAWSConfigurationPublicSource(ctx context.Context, m *configuration.Model, transport *http.Transport) (core.PublicSelectedReader, error) {
	route, err := configurationPublicReadRoute(ctx, m, transport)
	if err != nil {
		return nil, err
	}
	credentials, err := awsprovider.LoadDefaultCredentials(ctx, m.Store.Region)
	if err != nil {
		return nil, err
	}
	return awsprovider.NewPublicReader(awsprovider.StoreConfig{Domain: m.DomainID, Region: m.Store.Region, Bucket: m.Store.Bucket, ExpectedBucketOwner: m.Store.ExpectedOwner, Prefix: m.Store.PrefixBeforeHEAD, CredentialRoute: route, Credentials: credentials, Transport: transport, Timeout: time.Minute})
}

func openAWSNativeAbandonmentResources(ctx context.Context, m *configuration.Model, s abandonmentSource, mutation bool, transport *http.Transport, out abandonmentResources) (abandonmentResources, error) {
	if !mutation {
		var err error
		out.reader, err = openAWSConfigurationPublicSource(ctx, m, transport)
		return out, err
	}
	route := contract.Hash(append([]byte("enkv/abandon/default-credential-route/v1\x00"), s.store.Identity[:]...))
	credentials, err := awsprovider.LoadDefaultCredentials(ctx, m.Store.Region)
	if err != nil {
		return out, err
	}
	storeConfig := awsprovider.StoreConfig{Domain: m.DomainID, Region: m.Store.Region, Bucket: m.Store.Bucket, ExpectedBucketOwner: m.Store.ExpectedOwner, Prefix: m.Store.PrefixBeforeHEAD, CredentialRoute: route, Credentials: credentials, Transport: transport, Timeout: time.Minute}
	signing, ok := contract.ParseAWSKeySelector(s.control.NormalSigning.KeySelector, true)
	if !ok {
		return out, ErrAbandonmentPlan
	}
	out.store, err = awsprovider.NewStore(storeConfig)
	if err != nil {
		return out, err
	}
	out.trust, err = awsprovider.NewTrust(awsprovider.TrustConfig{Role: contract.NormalSigningRole, Region: signing.Region, KeyARN: s.control.NormalSigning.KeySelector, PublicKeyDER: s.control.NormalSigning.SPKI, CredentialRoute: route, Credentials: credentials, Transport: transport, Timeout: time.Minute})
	return out, err
}

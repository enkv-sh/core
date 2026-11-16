package core

import (
	"context"
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/providers/gcp"
	"enkv.sh/telemetry"
)

func openPublicPrefixCleaner(ctx context.Context, input liveRunInput, domain contract.ID, directory string, ownership ...map[string]bool) (*livePrefixCleaner, error) {
	restore, err := publicSDKEnvironment(input, "cleanup", directory)
	if err != nil {
		return nil, err
	}
	defer restore()
	source, err := gcp.LoadDefaultCredentials(ctx)
	if err != nil {
		return nil, err
	}
	client, err := gcp.NewClient(&http.Transport{}, source)
	if err != nil {
		return nil, err
	}
	s := input.Settings
	storage := "https://storage." + s.Region + ".rep.googleapis.com/storage/v1/"
	kms := "https://" + s.Region + "-cloudkms.googleapis.com/"
	selectedStore, err := gcp.NewStore(ctx, gcp.StoreConfig{Client: client, Domain: domain, Region: s.Region, Endpoint: storage, Bucket: s.Bucket, Prefix: input.Prefix, CredentialRoute: "public-prefix-cleanup-adc"})
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second, MaxResponseHeaderBytes: gcpSetupLimit, DisableKeepAlives: true, DisableCompression: true}
	setup, err := newGCPSetup(ctx, source, transport, s.Bucket, input.Prefix, domain, storage, kms)
	if err != nil {
		return nil, err
	}
	var store contract.Store = selectedStore
	if len(ownership) > 1 {
		return nil, errInventory
	}
	if len(ownership) == 1 {
		allowed := ownership[0]
		setup.ownedKey = func(key string) bool { return publicOwnedKey(input.Prefix, key, allowed) }
		store = &publicCleanupReadStore{Store: store, prefix: input.Prefix, allowed: allowed, open: func(selected contract.ID) (contract.Store, error) {
			return gcp.NewStore(ctx, gcp.StoreConfig{Client: client, Domain: selected, Region: s.Region, Endpoint: storage, Bucket: s.Bucket, Prefix: input.Prefix, CredentialRoute: "public-prefix-cleanup-adc"})
		}}
	}
	return &livePrefixCleaner{Store: store, Check: func(ctx context.Context) error { return setup.checkBucket(ctx, s) }, List: setup.listPrefix, Delete: setup.delete, ValidKey: setup.validKey}, nil
}

func openPublicReaderStore(ctx context.Context, input liveRunInput, domain contract.ID, directory string) (contract.Store, error) {
	restore, err := publicSDKEnvironment(input, "reader", directory)
	if err != nil {
		return nil, err
	}
	defer restore()
	source, err := gcp.LoadDefaultCredentials(ctx)
	if err != nil {
		return nil, err
	}
	client, err := gcp.NewClient(&http.Transport{}, source)
	if err != nil {
		return nil, err
	}
	s := input.Settings
	return gcp.NewStore(ctx, gcp.StoreConfig{Client: client, Domain: domain, Region: s.Region, Endpoint: "https://storage." + s.Region + ".rep.googleapis.com/storage/v1/", Bucket: s.Bucket, Prefix: input.Prefix, CredentialRoute: "public-get-only-adc"})
}

func openPublicOperatorClient(t testing.TB, ctx context.Context, input liveRunInput, role, directory string, domain contract.ID, signing *contract.PublicSigningBinding) (publicOperatorClient, error) {
	t.Helper()
	restore, err := publicSDKEnvironment(input, role, directory)
	if err != nil {
		return publicOperatorClient{}, err
	}
	defer restore()
	s := input.Settings
	source, err := gcp.LoadDefaultCredentials(ctx)
	if err != nil {
		return publicOperatorClient{}, err
	}
	transport := &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	client, err := gcp.NewClient(transport, source)
	if err != nil {
		return publicOperatorClient{}, err
	}
	route := contract.Hash([]byte("enkv/test/public-administrative/gcp/" + role))
	storage, kms := "https://storage."+s.Region+".rep.googleapis.com/storage/v1/", "https://"+s.Region+"-cloudkms.googleapis.com/"
	store, err := gcp.NewStore(ctx, gcp.StoreConfig{Client: client, Domain: domain, Region: s.Region, Endpoint: storage, Bucket: s.Bucket, Prefix: input.Prefix, CredentialRoute: operatorIDText(route)})
	if err != nil {
		return publicOperatorClient{}, err
	}
	adapter, err := gcp.NewCrypto(ctx, []gcp.KeyAccessConfig{{Client: client, Project: s.Project, Region: s.Region, Endpoint: kms, CredentialRoute: route}})
	if err != nil {
		return publicOperatorClient{}, err
	}
	result := publicOperatorClient{Store: store, Crypto: adapter, Route: route}
	if signing != nil {
		result.Trust, err = gcp.NewTrust(ctx, gcp.TrustConfig{Role: contract.NormalSigningRole, Client: client, Region: s.Region, Endpoint: kms, CredentialRoute: operatorIDText(route), KeyVersion: signing.KeySelector, Algorithm: "EC_SIGN_P256_SHA256", Purpose: "ASYMMETRIC_SIGN", PublicKey: signing.SPKI})
	}
	return result, err
}

func resolvePublicOperatorSuccessor(ctx context.Context, input liveRunInput, directory string) ([]byte, contract.ID, error) {
	restore, err := publicSDKEnvironment(input, "successor", directory)
	if err != nil {
		return nil, contract.ID{}, err
	}
	defer restore()
	s := input.Settings
	source, err := gcp.LoadDefaultCredentials(ctx)
	if err != nil {
		return nil, contract.ID{}, err
	}
	transport := &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
	defer transport.CloseIdleConnections()
	client, err := gcp.NewClient(transport, source)
	if err != nil {
		return nil, contract.ID{}, err
	}
	route := operatorIDText(contract.Hash([]byte("enkv/test/public-administrative/gcp/successor")))
	anchor, err := gcp.NewPublicSigningAnchor(ctx, gcp.PublicSigningAnchorConfig{Role: contract.NormalSigningRole, Client: client, Region: s.Region, KeyVersion: s.NormalSuccessorKeyID, CredentialRoute: route})
	if err != nil {
		return nil, contract.ID{}, err
	}
	public, _, reason := anchor.ResolveSigningKey(ctx)
	if reason != contract.ReasonNone {
		return nil, contract.ID{}, errInventory
	}
	trust, err := gcp.NewTrust(ctx, gcp.TrustConfig{Role: contract.NormalSigningRole, Client: client, Region: s.Region, Endpoint: "https://" + s.Region + "-cloudkms.googleapis.com/", CredentialRoute: route, KeyVersion: s.NormalSuccessorKeyID, Algorithm: "EC_SIGN_P256_SHA256", Purpose: "ASYMMETRIC_SIGN", PublicKey: public})
	if err != nil {
		return nil, contract.ID{}, err
	}
	return public, trust.Identity(), nil
}

func (s *gcpSetup) listPrefix(ctx context.Context, prefix, continuation string) (page livePrefixPage, err error) {
	if prefix != s.head[:len(s.head)-len("HEAD")] || len(continuation) > operatorPrefixTokenMax {
		return page, errInventory
	}
	err = s.read(ctx, s.storageHost, telemetry.OpSetupRead, func(callCtx context.Context) error {
		op, _ := callCtx.Value(gcpSetupContextKey{}).(*gcpSetupOperation)
		if op == nil {
			return errGCPSetup
		}
		op.bodyLimit = operatorPrefixBodyLimit
		request := s.storage.Objects.List(s.bucket).Prefix(prefix).MaxResults(operatorPrefixPageKeys).Projection("noAcl")
		if continuation != "" {
			request = request.PageToken(continuation)
		}
		out, callErr := request.Context(callCtx).Do()
		if callErr != nil {
			return callErr
		}
		if out == nil || op.status != http.StatusOK || out.Kind != "storage#objects" || len(out.Prefixes) != 0 ||
			len(out.Items) > operatorPrefixPageKeys || len(out.NextPageToken) > operatorPrefixTokenMax {
			return errGCPSetup
		}
		page.Keys = make([]string, 0, len(out.Items))
		for _, item := range out.Items {
			if item == nil || item.Bucket != s.bucket || !s.validKey(item.Name) || item.Size == 0 || item.Size > 2<<20 ||
				item.Generation <= 0 || item.EventBasedHold || item.TemporaryHold || item.Retention != nil || item.SoftDeleteTime != "" {
				return errGCPSetup
			}
			page.Keys = append(page.Keys, item.Name)
		}
		page.Next = out.NextPageToken
		return nil
	})
	if err != nil {
		return livePrefixPage{}, err
	}
	return page, nil
}

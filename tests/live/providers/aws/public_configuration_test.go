package core

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"enkv.sh/core/contract"
	awsprovider "enkv.sh/providers/aws"
	"enkv.sh/telemetry"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Only the selected cleanup role is loaded. This fixture route never becomes
// the credential context of public init, set, apply, Reader or consumption.
func openPublicPrefixCleaner(ctx context.Context, input liveRunInput, domain contract.ID, directory string, ownership ...map[string]bool) (*livePrefixCleaner, error) {
	restore, err := publicSDKEnvironment(input, "cleanup", directory)
	if err != nil {
		return nil, err
	}
	defer restore()
	credentials, err := awsprovider.LoadDefaultCredentials(ctx, input.Settings.Region)
	if err != nil {
		return nil, err
	}
	route := contract.Hash([]byte("enkv/test/public-prefix-cleanup/aws/v1"))
	base := &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
	s := input.Settings
	selectedStore, err := awsprovider.NewStore(awsprovider.StoreConfig{Region: s.Region, Bucket: s.Bucket, ExpectedBucketOwner: s.Account, Prefix: input.Prefix, Domain: domain, CredentialRoute: route, Credentials: credentials, Transport: base, Timeout: time.Minute})
	if err != nil {
		return nil, err
	}
	setup := newAWSSetup(s, input.Prefix, domain, nil, credentials, base)
	var store contract.Store = selectedStore
	if len(ownership) > 1 {
		return nil, errInventory
	}
	if len(ownership) == 1 {
		allowed := ownership[0]
		setup.ownedKey = func(key string) bool { return publicOwnedKey(input.Prefix, key, allowed) }
		store = &publicCleanupReadStore{Store: store, prefix: input.Prefix, allowed: allowed, open: func(selected contract.ID) (contract.Store, error) {
			return awsprovider.NewStore(awsprovider.StoreConfig{Region: s.Region, Bucket: s.Bucket, ExpectedBucketOwner: s.Account, Prefix: input.Prefix, Domain: selected, CredentialRoute: route, Credentials: credentials, Transport: base, Timeout: time.Minute})
		}}
	}
	return &livePrefixCleaner{Store: store, Check: setup.checkBucket, List: setup.listPrefix, Delete: setup.delete, ValidKey: setup.validKey}, nil
}

func openPublicReaderStore(ctx context.Context, input liveRunInput, domain contract.ID, directory string) (contract.Store, error) {
	restore, err := publicSDKEnvironment(input, "reader", directory)
	if err != nil {
		return nil, err
	}
	defer restore()
	credentials, err := awsprovider.LoadDefaultCredentials(ctx, input.Settings.Region)
	if err != nil {
		return nil, err
	}
	route := contract.Hash([]byte("enkv/test/public-get-only/aws/v1"))
	s := input.Settings
	return awsprovider.NewStore(awsprovider.StoreConfig{Region: s.Region, Bucket: s.Bucket, ExpectedBucketOwner: s.Account, Prefix: input.Prefix, Domain: domain, CredentialRoute: route, Credentials: credentials, Transport: &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}, Timeout: time.Minute})
}

func openPublicOperatorClient(t testing.TB, ctx context.Context, input liveRunInput, role, directory string, domain contract.ID, signing *contract.PublicSigningBinding) (publicOperatorClient, error) {
	t.Helper()
	restore, err := publicSDKEnvironment(input, role, directory)
	if err != nil {
		return publicOperatorClient{}, err
	}
	defer restore()
	s := input.Settings
	credentials, err := awsprovider.LoadDefaultCredentials(ctx, s.Region)
	if err != nil {
		return publicOperatorClient{}, err
	}
	route := contract.Hash([]byte("enkv/test/public-administrative/aws/" + role))
	transport := &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	store, err := awsprovider.NewStore(awsprovider.StoreConfig{Region: s.Region, Bucket: s.Bucket, ExpectedBucketOwner: s.Account, Prefix: input.Prefix, Domain: domain, CredentialRoute: route, Credentials: credentials, Transport: transport, Timeout: time.Minute})
	if err != nil {
		return publicOperatorClient{}, err
	}
	adapter, err := awsprovider.NewCrypto([]awsprovider.KeyAccessConfig{{Region: s.Region, Account: s.Account, CredentialRoute: route, Credentials: credentials, Transport: transport, Timeout: time.Minute}})
	if err != nil {
		return publicOperatorClient{}, err
	}
	result := publicOperatorClient{Store: store, Crypto: adapter, Route: route}
	if signing != nil {
		result.Trust, err = awsprovider.NewTrust(awsprovider.TrustConfig{Role: contract.NormalSigningRole, Region: s.Region, KeyARN: signing.KeySelector, PublicKeyDER: signing.SPKI, CredentialRoute: route, Credentials: credentials, Transport: transport, Timeout: time.Minute})
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
	credentials, err := awsprovider.LoadDefaultCredentials(ctx, s.Region)
	if err != nil {
		return nil, contract.ID{}, err
	}
	route := contract.Hash([]byte("enkv/test/public-administrative/aws/successor"))
	transport := &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
	defer transport.CloseIdleConnections()
	anchor, err := awsprovider.NewPublicSigningAnchor(awsprovider.PublicSigningAnchorConfig{Role: contract.NormalSigningRole, Region: s.Region, KeyARN: s.NormalSuccessorKeyID, CredentialRoute: route, Credentials: credentials, Transport: transport, Timeout: time.Minute})
	if err != nil {
		return nil, contract.ID{}, err
	}
	public, _, reason := anchor.ResolveSigningKey(ctx)
	if reason != contract.ReasonNone {
		return nil, contract.ID{}, errInventory
	}
	trust, err := awsprovider.NewTrust(awsprovider.TrustConfig{Role: contract.NormalSigningRole, Region: s.Region, KeyARN: s.NormalSuccessorKeyID, PublicKeyDER: public, CredentialRoute: route, Credentials: credentials, Transport: transport, Timeout: time.Minute})
	if err != nil {
		return nil, contract.ID{}, err
	}
	return public, trust.Identity(), nil
}

func (s *awsSetup) listPrefix(ctx context.Context, prefix, continuation string) (page livePrefixPage, resultErr error) {
	call := telemetry.Start(ctx, telemetry.ProviderAWS, telemetry.OpSetupRead)
	defer func() { finishSetupCall(call, resultErr) }()
	if prefix != s.head[:len(s.head)-len("HEAD")] || len(continuation) > operatorPrefixTokenMax {
		return page, awsSetupFailureFor(ctx, errAWSSetup, "admission", "invalid_request", nil)
	}
	callCtx, cancel, credentials, err := s.begin(ctx, "s3", telemetry.OpSetupRead)
	defer cancel()
	if err != nil {
		return page, err
	}
	op := awsSetupOperationFrom(callCtx)
	op.bodyLimit = operatorPrefixBodyLimit
	input := &s3.ListObjectsV2Input{Bucket: aws.String(s.settings.Bucket), ExpectedBucketOwner: aws.String(s.settings.Account),
		Prefix: aws.String(prefix), MaxKeys: aws.Int32(operatorPrefixPageKeys)}
	if continuation != "" {
		input.ContinuationToken = aws.String(continuation)
	}
	out, err := s.s3(credentials).ListObjectsV2(callCtx, input)
	if err != nil {
		return page, awsSetupFailureFor(callCtx, errAWSSetup, "ownership_read", "transport", err)
	}
	if out == nil || op.status.Load() != http.StatusOK || aws.ToString(out.Name) != s.settings.Bucket ||
		aws.ToString(out.Prefix) != prefix || aws.ToInt32(out.MaxKeys) != operatorPrefixPageKeys ||
		out.KeyCount == nil || int(aws.ToInt32(out.KeyCount)) != len(out.Contents) ||
		len(out.CommonPrefixes) != 0 || out.Delimiter != nil || out.EncodingType != "" || out.IsTruncated == nil ||
		(continuation != "" && aws.ToString(out.ContinuationToken) != continuation) ||
		(continuation == "" && out.ContinuationToken != nil) || len(out.Contents) > operatorPrefixPageKeys {
		return page, awsSetupFailureFor(callCtx, errAWSSetup, "response_intake", "malformed_envelope", nil)
	}
	page.Keys = make([]string, 0, len(out.Contents))
	for _, item := range out.Contents {
		if item.Key == nil || !s.validKey(*item.Key) || item.Size == nil || *item.Size <= 0 || *item.Size > 2<<20 {
			return livePrefixPage{}, awsSetupFailureFor(callCtx, errAWSSetup, "ownership_check", "ownership_mismatch", nil)
		}
		page.Keys = append(page.Keys, *item.Key)
	}
	if aws.ToBool(out.IsTruncated) {
		page.Next = aws.ToString(out.NextContinuationToken)
		if page.Next == "" || len(page.Next) > operatorPrefixTokenMax {
			return livePrefixPage{}, awsSetupFailureFor(callCtx, errAWSSetup, "response_intake", "malformed_envelope", nil)
		}
	} else if out.NextContinuationToken != nil {
		return livePrefixPage{}, awsSetupFailureFor(callCtx, errAWSSetup, "response_intake", "malformed_envelope", errors.New("unexpected continuation"))
	}
	return page, nil
}

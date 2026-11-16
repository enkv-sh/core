package awsprovider

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const maximumObjectKeyLength = 1024

const StoreClass = "aws-s3-regional-v2"

var accountPattern = regexp.MustCompile(`^[0-9]{12}$`)

// StoreConfig supplies independent construction evidence. CredentialRoute is a
// runtime admission identity, not a persistent Store fact or credential.
// Transport supplies admitted dial, TLS and timeout settings. Construction owns
// the TLS policy and disables proxying, redirects, HTTP/2, compression and
// connection reuse. Unsupported TLS state and caller TLS dialers are refused.
type StoreConfig struct {
	Region, Bucket, ExpectedBucketOwner, Prefix string
	Domain, CredentialRoute                     contract.ID
	Credentials                                 aws.CredentialsProvider
	Transport                                   *http.Transport
	Timeout                                     time.Duration
}

type Store struct {
	config     StoreConfig
	descriptor contract.Descriptor
	client     *http.Client
}

var _ contract.Store = (*Store)(nil)
var _ contract.ConditionalDeleteStore = (*Store)(nil)

func NewStore(c StoreConfig) (*Store, error) {
	if !validStore(c) {
		return nil, ErrConstruction
	}
	t, err := privateTransport(c.Transport)
	if err != nil {
		return nil, err
	}
	return newStore(c, t)
}
func validStore(c StoreConfig) bool {
	if !validCommon(c.Region, c.CredentialRoute, c.Credentials, c.Timeout) {
		return false
	}
	_, err := contract.EncodeStoreConfiguration(storeConfiguration(c))
	return err == nil
}
func storeConfiguration(c StoreConfig) contract.StoreConfiguration {
	return contract.StoreConfiguration{Provider: contract.AWS, ConstructionProfile: contract.StoreConstructionProfile,
		DomainID: c.Domain, Region: c.Region, Bucket: c.Bucket, PrefixBeforeHEAD: c.Prefix,
		ExpectedOwner: c.ExpectedBucketOwner}
}
func keyLimit(prefix string, domain contract.ID, key string) int {
	if key == prefix+"/HEAD" {
		return contract.MaxHeadLength
	}
	object, err := contract.ParseStoreObjectKey(prefix, domain, key)
	if err != nil {
		return 0
	}
	return int(contract.StoreObjectLimit(object))
}

func newStore(c StoreConfig, rt http.RoundTripper) (*Store, error) {
	if !validStore(c) || rt == nil {
		return nil, ErrConstruction
	}
	d, err := storeDescriptor(c)
	if err != nil {
		return nil, err
	}
	host := "s3." + c.Region + ".amazonaws.com"
	s := &Store{config: c, descriptor: d}
	s.client = ownedClient(rt, host, c.Timeout)
	return s, nil
}
func storeDescriptor(c StoreConfig) (contract.Descriptor, error) {
	host := "s3." + c.Region + ".amazonaws.com"
	coordinate := identity(StoreClass, host, c.Bucket, c.Prefix+"/HEAD", fmt.Sprintf("%x", c.Domain))
	nonbody := identity(StoreClass, "PUT", "application/octet-stream", c.ExpectedBucketOwner, "sha256", "fixed-content-length", "path-style", "single-attempt", "no-cache-transform")
	id, err := contract.StoreConfigurationID(storeConfiguration(c))
	if err != nil {
		return contract.Descriptor{}, ErrConstruction
	}
	d := contract.Descriptor{Family: contract.AWS, Identity: id, Coordinate: coordinate, NonBody: nonbody, Prefix: c.Prefix, HeadKey: c.Prefix + "/HEAD"}
	return d, nil
}
func (s *Store) Descriptor() contract.Descriptor { return s.descriptor }
func (s *Store) StoreConfiguration() contract.StoreConfiguration {
	return storeConfiguration(s.config)
}
func (s *Store) sdk(creds aws.CredentialsProvider) *s3.Client {
	return storeClient(s.client, s.config.Region, creds)
}
func storeClient(client *http.Client, region string, creds aws.CredentialsProvider) *s3.Client {
	return s3.New(s3.Options{Region: region, BaseEndpoint: aws.String("https://s3." + region + ".amazonaws.com"), UsePathStyle: true, Credentials: creds, HTTPClient: client, Retryer: aws.NopRetryer{}, RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired, ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired})
}
func (s *Store) Read(ctx context.Context, key string, limit uint32) (result contract.ReadResult) {
	ctx, call := startTelemetryDetails(ctx, telemetry.OpStoreRead, storeDetails(s, key))
	defer func() { finishReadTelemetry(call, result) }()
	if s == nil || !s.descriptor.Valid() || limit == 0 || limit > uint32(keyLimit(s.config.Prefix, s.config.Domain, key)) {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	return readS3Object(ctx, s.client, s.config.Region, s.config.Bucket, s.config.ExpectedBucketOwner, s.config.Credentials, key, limit)
}

// An empty owner is admitted only by CandidateReader. Ordinary Store
// construction requires an expected owner before it can reach this path.
func readS3Object(ctx context.Context, client *http.Client, region, bucket, owner string, credentials aws.CredentialsProvider, key string, limit uint32) contract.ReadResult {
	var observation *attempt
	ctx, observation = storeReadContext(ctx, int64(limit))
	creds, ok := retrieve(ctx, credentials)
	if !ok {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
	}
	sdk := storeClient(client, region, creds)
	input := &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)}
	if owner != "" {
		input.ExpectedBucketOwner = aws.String(owner)
	}
	out, err := sdk.GetObject(ctx, input)
	if err != nil {
		if errors.Is(err, errResponse) {
			return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed}
		}
		status, code := serviceError(err)
		if status == http.StatusNotFound && code == "NoSuchKey" {
			return contract.ReadResult{Status: contract.ReadMissing}
		}
		reason := contract.ReasonTransport
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			reason = contract.ReasonAccess
		}
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: reason}
	}
	defer out.Body.Close() //nolint:errcheck // The owned transport replaces the response with an in-memory body whose Close cannot fail.
	if out.ContentLength == nil || *out.ContentLength < 0 || *out.ContentLength > int64(limit) || aws.ToString(out.ContentRange) != "" || aws.ToString(out.ContentEncoding) != "" {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed}
	}
	body, err := io.ReadAll(io.LimitReader(out.Body, int64(limit)+1))
	if err != nil {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
	}
	token := contract.Token{Family: contract.AWS, Value: observation.responseETag}
	if int64(len(body)) != *out.ContentLength || len(body) > int(limit) || !token.Valid() || aws.ToString(out.ETag) != token.Value {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed}
	}
	return contract.ReadResult{Status: contract.ReadOK, Body: body, Token: token}
}
func (s *Store) Create(ctx context.Context, key string, body []byte) (result contract.WriteResult) {
	ctx, call := startTelemetryDetails(ctx, telemetry.OpStoreCreate, storeDetails(s, key))
	call.InputBytes(int64(len(body)))
	defer func() { finishImmutableWriteTelemetry(call, result) }()
	if s == nil || !s.descriptor.Valid() || key == s.descriptor.HeadKey {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}
	}
	return s.write(ctx, key, contract.Token{}, body, false)
}
func (s *Store) CreateHead(ctx context.Context, request contract.HeadCreateRequest) (result contract.WriteResult) {
	ctx, call := startTelemetryDetails(ctx, telemetry.OpStoreCreate, headStoreDetails(s))
	call.InputBytes(int64(request.Length()))
	defer func() { finishWriteTelemetry(call, result) }()
	if s == nil || !request.Valid() || request.Descriptor() != s.descriptor {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}
	}
	return s.write(ctx, s.descriptor.HeadKey, contract.Token{}, request.Body(), false)
}
func (s *Store) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) (result contract.WriteResult) {
	ctx, call := startTelemetryDetails(ctx, telemetry.OpStoreCompareAndSwap, storeDetails(s, key))
	call.InputBytes(int64(len(body)))
	defer func() { finishWriteTelemetry(call, result) }()
	if s == nil || !s.descriptor.Valid() || key != s.descriptor.HeadKey || token.Family != contract.AWS || !token.Valid() {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}
	}
	return s.write(ctx, key, token, body, true)
}

func (s *Store) DeleteIfToken(ctx context.Context, key string, token contract.Token) (result contract.WriteResult) {
	ctx, call := startTelemetryDetails(ctx, telemetry.OpCleanup, storeDetails(s, key))
	defer func() { finishWriteTelemetry(call, result) }()
	if s == nil || !s.descriptor.Valid() || key == s.descriptor.HeadKey ||
		keyLimit(s.config.Prefix, s.config.Domain, key) == 0 || token.Family != contract.AWS || !token.Valid() {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}
	}
	ctx = operationContext(ctx, maximumPublicResponseBytes)
	creds, ok := retrieve(ctx, s.config.Credentials)
	if !ok {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess, NotSent: true}
	}
	_, err := s.sdk(creds).DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(s.config.Bucket), Key: aws.String(key),
		ExpectedBucketOwner: aws.String(s.config.ExpectedBucketOwner), IfMatch: aws.String(token.Value)})
	if err == nil {
		observation, complete := ctx.Value(attemptKey{}).(*attempt)
		if !complete || observation.status != http.StatusNoContent || len(observation.response) != 0 {
			return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonMalformed}
		}
		return contract.WriteResult{Status: contract.WriteAcknowledged}
	}
	status, code := serviceError(err)
	switch {
	case status == http.StatusPreconditionFailed && code == "PreconditionFailed", status == http.StatusNotFound:
		return contract.WriteResult{Status: contract.WritePrecondition, Reason: contract.ReasonCondition}
	case status == http.StatusConflict && code == "ConditionalRequestConflict":
		return contract.WriteResult{Status: contract.WriteConflict, Reason: contract.ReasonCondition}
	}
	observation, observed := ctx.Value(attemptKey{}).(*attempt)
	return contract.WriteResult{Status: contract.WriteUnknown, Reason: storeWriteFailureReason(err, status, code), NotSent: observed && observation.sent.Load() == 0}
}

func (s *Store) write(ctx context.Context, key string, token contract.Token, body []byte, cas bool) contract.WriteResult {
	if len(body) == 0 || len(body) > keyLimit(s.config.Prefix, s.config.Domain, key) || (cas && len(body) > contract.MaxHeadLength) {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonLimit}
	}
	frozen := bytes.Clone(body)
	ctx = operationContext(ctx, maximumPublicResponseBytes)
	creds, ok := retrieve(ctx, s.config.Credentials)
	if !ok {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess, NotSent: true}
	}
	hash := contract.Hash(frozen)
	in := &s3.PutObjectInput{Bucket: aws.String(s.config.Bucket), Key: aws.String(key), ExpectedBucketOwner: aws.String(s.config.ExpectedBucketOwner), Body: bytes.NewReader(frozen), ContentLength: aws.Int64(int64(len(frozen))), ContentType: aws.String("application/octet-stream"), ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(hash[:]))}
	if cas {
		in.IfMatch = aws.String(token.Value)
	} else {
		in.IfNoneMatch = aws.String("*")
	}
	_, err := s.sdk(creds).PutObject(ctx, in)
	if err == nil {
		observation, complete := ctx.Value(attemptKey{}).(*attempt)
		if !complete || observation.status != http.StatusOK || len(observation.response) != 0 {
			return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonMalformed}
		}
		return contract.WriteResult{Status: contract.WriteAcknowledged}
	}
	status, code := serviceError(err)
	if status == http.StatusPreconditionFailed && code == "PreconditionFailed" {
		return contract.WriteResult{Status: contract.WritePrecondition, Reason: contract.ReasonCondition}
	}
	if status == http.StatusConflict && code == "ConditionalRequestConflict" {
		return contract.WriteResult{Status: contract.WriteConflict, Reason: contract.ReasonCondition}
	}
	observation, observed := ctx.Value(attemptKey{}).(*attempt)
	return contract.WriteResult{Status: contract.WriteUnknown, Reason: storeWriteFailureReason(err, status, code), NotSent: observed && observation.sent.Load() == 0}
}

func storeWriteFailureReason(err error, status int, code string) contract.Reason {
	if errors.Is(err, errResponse) {
		return contract.ReasonMalformed
	}
	switch {
	case status == 0:
		return contract.ReasonTransport
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return contract.ReasonAccess
	case status == http.StatusBadRequest && code == "InvalidRequest":
		return contract.ReasonConstruction
	case status == http.StatusInternalServerError && code == "InternalError":
		// S3 can return this response after applying a write. Its documented
		// retry does not establish that the original request had no effect.
		return contract.ReasonTransport
	case status == http.StatusServiceUnavailable && code == "SlowDown":
		return contract.ReasonTransport
	default:
		return contract.ReasonMalformed
	}
}

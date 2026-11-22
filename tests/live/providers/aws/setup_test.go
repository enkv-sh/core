package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
	awsprovider "enkv.sh/providers/aws"
	"enkv.sh/telemetry"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/logging"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

var errAWSSetup = errors.New("AWS test resource check failed")
var errAWSDelete = errors.New("AWS conditional cleanup was not acknowledged")

const awsSetupLimit = 64 << 10

func openLiveBackend(ctx context.Context, c liveSettings, prefix string, domain contract.ID) (*liveBackend, error) {
	block, rest := pem.Decode([]byte(c.PublicKeyPEM))
	if c.Provider != "aws" || block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 || !strings.HasPrefix(c.KeyID, "arn:aws:kms:"+c.Region+":"+c.Account+":key/") {
		return nil, awsSetupFailureFor(ctx, errAWSSetup, "admission", "invalid_request", nil)
	}
	if _, err := awsprovider.ParseVerifier(block.Bytes); err != nil {
		return nil, awsSetupFailureFor(ctx, errAWSSetup, "admission", "invalid_request", err)
	}
	credentials, err := awsprovider.LoadSharedCredentialsFile(ctx, c.CredentialsFile, c.Profile, c.CredentialExpires)
	if err != nil {
		return nil, awsSetupFailureFor(ctx, errAWSSetup, "authentication", "authentication_refused", err)
	}
	transport := &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
	route := contract.Hash([]byte("aws-public-resource-route:" + settingsBinding(c)))
	store, err := awsprovider.NewStore(awsprovider.StoreConfig{Region: c.Region, Bucket: c.Bucket, ExpectedBucketOwner: c.Account, Prefix: prefix, Domain: domain, CredentialRoute: route, Credentials: credentials, Transport: transport, Timeout: time.Minute})
	if err != nil {
		return nil, awsSetupFailureFor(ctx, errAWSSetup, "admission", "invalid_request", err)
	}
	trust, err := awsprovider.NewTrust(awsprovider.TrustConfig{Region: c.Region, KeyARN: c.KeyID, PublicKeyDER: block.Bytes, CredentialRoute: route, Credentials: credentials, Transport: transport, Timeout: time.Minute})
	if err != nil {
		return nil, awsSetupFailureFor(ctx, errAWSSetup, "admission", "invalid_request", err)
	}
	setup := newAWSSetup(c, prefix, domain, block.Bytes, credentials, transport)
	return &liveBackend{Store: store, Trust: trust, PublicKey: bytes.Clone(block.Bytes), Put: setup.put, Delete: setup.delete, Check: setup.check}, nil
}

type awsSetup struct {
	ownedKey      func(string) bool
	settings      liveSettings
	head, objects string
	publicKey     []byte
	credentials   aws.CredentialsProvider
	transport     *awsSetupTransport
	client        *http.Client
}

func newAWSSetup(c liveSettings, prefix string, domain contract.ID, publicKey []byte, credentials aws.CredentialsProvider, base *http.Transport) *awsSetup {
	t := &http.Transport{DialContext: base.DialContext, TLSHandshakeTimeout: base.TLSHandshakeTimeout, ResponseHeaderTimeout: base.ResponseHeaderTimeout, MaxResponseHeaderBytes: awsSetupLimit, DisableCompression: true, DisableKeepAlives: true, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
	if base.TLSClientConfig != nil {
		t.TLSClientConfig = base.TLSClientConfig.Clone()
	} else {
		t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	t.TLSClientConfig.NextProtos = []string{"http/1.1"}
	transport := &awsSetupTransport{base: t}
	client := &http.Client{Transport: transport, Timeout: time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &awsSetup{settings: c, head: prefix + "/HEAD", objects: prefix + "/" + hex.EncodeToString(domain[:]) + "/", publicKey: bytes.Clone(publicKey), credentials: credentials, transport: transport, client: client}
}

type awsSetupCredentials struct{ value aws.Credentials }

func (c awsSetupCredentials) Retrieve(context.Context) (aws.Credentials, error) { return c.value, nil }

type awsSetupOperation struct {
	host      string
	metric    telemetry.Operation
	bodyLimit int64
	sent      atomic.Bool
	timedOut  atomic.Bool
	status    atomic.Int32
}
type awsSetupContextKey struct{}

// awsSetupFailure keeps only closed diagnostic facts. The SDK error remains
// available to in-process errors.Is/As callers, but never appears in Error().
type awsSetupFailure struct {
	Operation, Stage, Cause, Effect string
	HTTPStatus, EnvelopeStatus      int
	ProviderCode                    string
	Attempt                         uint8
	sentinel, original              error
}

func (e *awsSetupFailure) Error() string { return e.sentinel.Error() }

func (e *awsSetupFailure) Unwrap() []error {
	if e.original == nil || e.original == e.sentinel {
		return []error{e.sentinel}
	}
	return []error{e.sentinel, e.original}
}

func (e *awsSetupFailure) SafeHarnessFailure() records.HarnessFailure {
	f := records.HarnessFailure{Operation: e.Operation, Stage: e.Stage, Cause: e.Cause, Effect: e.Effect, ProviderCode: e.ProviderCode, Attempt: e.Attempt}
	if e.HTTPStatus >= 100 && e.HTTPStatus <= 599 {
		status := uint16(e.HTTPStatus)
		f.HTTPStatus = &status
	}
	if e.EnvelopeStatus >= 100 && e.EnvelopeStatus <= 599 {
		status := uint16(e.EnvelopeStatus)
		f.EnvelopeStatus = &status
	}
	return f
}

func awsSetupOperationFrom(ctx context.Context) *awsSetupOperation {
	op, _ := ctx.Value(awsSetupContextKey{}).(*awsSetupOperation)
	return op
}

func awsSetupOperationKind(op *awsSetupOperation) string {
	if op != nil && op.metric == telemetry.OpSetupDelete {
		return "object_cleanup"
	}
	return "setup_check"
}

func awsSetupCallStage(op *awsSetupOperation) string {
	if op != nil && op.metric == telemetry.OpSetupDelete {
		return "conditional_delete"
	}
	return "configuration_check"
}

func awsSetupAllowedCode(code string) string {
	switch code {
	case "PreconditionFailed", "ConditionalRequestConflict", "AccessDenied", "InternalError", "NoSuchLifecycleConfiguration", "ReplicationConfigurationNotFoundError":
		return code
	default:
		return ""
	}
}

func awsSetupFailureFor(ctx context.Context, sentinel error, stage, cause string, original error) *awsSetupFailure {
	op := awsSetupOperationFrom(ctx)
	f := &awsSetupFailure{Operation: awsSetupOperationKind(op), Stage: stage, Cause: cause, Effect: "no_send", sentinel: sentinel, original: original}
	if op != nil {
		f.HTTPStatus = int(op.status.Load())
		if op.sent.Load() {
			f.Attempt = 1
			f.Effect = "unknown"
		}
	}
	var prior *awsSetupFailure
	if errors.As(original, &prior) {
		f.Stage, f.Cause = prior.Stage, prior.Cause
		if prior.HTTPStatus != 0 {
			f.HTTPStatus = prior.HTTPStatus
		}
		f.EnvelopeStatus, f.ProviderCode = prior.EnvelopeStatus, prior.ProviderCode
	} else {
		var response *smithyhttp.ResponseError
		if errors.As(original, &response) {
			f.EnvelopeStatus = response.HTTPStatusCode()
		}
		var api smithy.APIError
		if errors.As(original, &api) {
			f.ProviderCode = awsSetupAllowedCode(api.ErrorCode())
		}
		if cause == "transport" || cause == "provider_refused" || cause == "invalid_acknowledgement" {
			var timeout net.Error
			switch {
			case errors.Is(original, context.Canceled):
				f.Cause = "cancelled"
			case errors.Is(original, context.DeadlineExceeded):
				f.Cause = "deadline"
			case errors.As(original, &timeout) && timeout.Timeout():
				f.Cause = "deadline"
			case f.HTTPStatus >= 200 && f.HTTPStatus < 300 && original != nil && original != sentinel:
				f.Cause = "malformed_envelope"
			case f.HTTPStatus == 401 || f.HTTPStatus == 403:
				f.Cause = "access_refused"
			case f.HTTPStatus == 409 || f.HTTPStatus == 412:
				f.Cause = "condition_refused"
			case f.HTTPStatus >= 400:
				f.Cause = "provider_refused"
			}
		}
	}
	return f
}

func (s *awsSetup) begin(ctx context.Context, service string, operation telemetry.Operation) (context.Context, context.CancelFunc, aws.CredentialsProvider, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	value, err := s.credentials.Retrieve(ctx)
	if err != nil || ctx.Err() != nil || !value.HasKeys() || value.CanExpire && !time.Now().Before(value.Expires) {
		cause := "authentication_refused"
		if errors.Is(ctx.Err(), context.Canceled) {
			cause = "cancelled"
		} else if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			cause = "deadline"
		}
		failure := awsSetupFailureFor(ctx, errAWSSetup, "authentication", cause, err)
		if operation == telemetry.OpSetupDelete {
			failure.Operation = "object_cleanup"
		}
		cancel()
		return ctx, func() {}, nil, failure
	}
	return context.WithValue(ctx, awsSetupContextKey{}, &awsSetupOperation{host: service + "." + s.settings.Region + ".amazonaws.com", metric: operation}), cancel, awsSetupCredentials{value: value}, nil
}

func (s *awsSetup) s3(creds aws.CredentialsProvider) *s3.Client {
	return s3.New(s3.Options{Region: s.settings.Region, BaseEndpoint: aws.String("https://s3." + s.settings.Region + ".amazonaws.com"), UsePathStyle: true, Credentials: creds, HTTPClient: s.client, Retryer: aws.NopRetryer{}, Logger: logging.Nop{}, RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired, ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired})
}

func (s *awsSetup) validKey(key string) bool {
	if s.ownedKey != nil {
		return s.ownedKey(key)
	}
	return liveFixtureKeyValid(s.head, s.objects, key)
}

func (s *awsSetup) put(ctx context.Context, key string, body []byte) (result contract.WriteResult) {
	call := telemetry.Start(ctx, telemetry.ProviderAWS, telemetry.OpSetupCreate)
	call.InputBytes(int64(len(body)))
	defer func() { call.Finish(setupWriteResult(result.Status)) }()
	if !s.validKey(key) || len(body) == 0 || len(body) > 2<<20 || key == s.head && len(body) > awsSetupLimit {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}
	}
	frozen := bytes.Clone(body)
	ctx, cancel, credentials, err := s.begin(ctx, "s3", telemetry.OpSetupCreate)
	defer cancel()
	if err != nil {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess}
	}
	digest := contract.Hash(frozen)
	out, err := s.s3(credentials).PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(s.settings.Bucket), Key: aws.String(key), ExpectedBucketOwner: aws.String(s.settings.Account), IfNoneMatch: aws.String("*"), Body: bytes.NewReader(frozen), ContentLength: aws.Int64(int64(len(frozen))), ContentType: aws.String("application/octet-stream"), ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(digest[:]))})
	if err == nil && aws.ToString(out.VersionId) == "" {
		return contract.WriteResult{Status: contract.WriteAcknowledged}
	}
	status, code := awsSetupError(err)
	if status == 412 && code == "PreconditionFailed" {
		return contract.WriteResult{Status: contract.WritePrecondition, Reason: contract.ReasonCondition}
	}
	if status == 409 && code == "ConditionalRequestConflict" {
		return contract.WriteResult{Status: contract.WriteConflict, Reason: contract.ReasonCondition}
	}
	reason := contract.ReasonTransport
	if status == 401 || status == 403 {
		reason = contract.ReasonAccess
	}
	return contract.WriteResult{Status: contract.WriteUnknown, Reason: reason}
}

func (s *awsSetup) delete(ctx context.Context, key string, token contract.Token) (resultErr error) {
	call := telemetry.Start(ctx, telemetry.ProviderAWS, telemetry.OpSetupDelete)
	defer func() { finishSetupCall(call, resultErr) }()
	if !s.validKey(key) || token.Family != contract.AWS || !token.Valid() || len(token.Value) < 2 || token.Value[0] != '"' || token.Value[len(token.Value)-1] != '"' || strings.ContainsRune(token.Value[1:len(token.Value)-1], '"') {
		failure := awsSetupFailureFor(ctx, errAWSDelete, "admission", "invalid_request", nil)
		failure.Operation = "object_cleanup"
		return failure
	}
	ctx, cancel, credentials, err := s.begin(ctx, "s3", telemetry.OpSetupDelete)
	defer cancel()
	if err != nil {
		failure := awsSetupFailureFor(ctx, errAWSDelete, "authentication", "authentication_refused", err)
		failure.Operation = "object_cleanup"
		return failure
	}
	out, err := s.s3(credentials).DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(s.settings.Bucket), Key: aws.String(key), ExpectedBucketOwner: aws.String(s.settings.Account), IfMatch: aws.String(token.Value)})
	if err != nil {
		return awsSetupFailureFor(ctx, errAWSDelete, "conditional_delete", "transport", err)
	}
	op := awsSetupOperationFrom(ctx)
	if out == nil || op == nil || op.status.Load() != http.StatusNoContent || aws.ToBool(out.DeleteMarker) || aws.ToString(out.VersionId) != "" {
		return awsSetupFailureFor(ctx, errAWSDelete, "acknowledgement", "invalid_acknowledgement", nil)
	}
	return nil
}

func awsSetupError(err error) (int, string) {
	var response *smithyhttp.ResponseError
	var api smithy.APIError
	status, code := 0, ""
	if errors.As(err, &response) {
		status = response.HTTPStatusCode()
	}
	if errors.As(err, &api) {
		code = api.ErrorCode()
	}
	return status, code
}

func (s *awsSetup) s3Check(ctx context.Context, check func(context.Context, *s3.Client) error) (resultErr error) {
	return s.checkedRead(ctx, "s3", telemetry.OpSetupRead, func(ctx context.Context, credentials aws.CredentialsProvider) error {
		return check(ctx, s.s3(credentials))
	})
}

func (s *awsSetup) checkedRead(ctx context.Context, service string, operation telemetry.Operation, check func(context.Context, aws.CredentialsProvider) error) error {
	ctx, stop := context.WithTimeout(ctx, 30*time.Second)
	defer stop()
	for attempt := 0; attempt < 3; attempt++ {
		call := telemetry.Start(ctx, telemetry.ProviderAWS, operation)
		requestCtx, cancel, credentials, err := s.begin(ctx, service, operation)
		if err == nil {
			err = check(requestCtx, credentials)
		}
		var timedOut bool
		if state, ok := requestCtx.Value(awsSetupContextKey{}).(*awsSetupOperation); ok {
			timedOut = state.timedOut.Load()
		}
		cancel()
		if err == nil {
			finishSetupCall(call, nil)
			return nil
		}
		failure := awsSetupFailureFor(requestCtx, errAWSSetup, "configuration_check", "invalid_acknowledgement", err)
		finishSetupCall(call, failure)
		if !timedOut || attempt == 2 || ctx.Err() != nil {
			return failure
		}
		wait := time.NewTimer([]time.Duration{100 * time.Millisecond, 400 * time.Millisecond}[attempt])
		select {
		case <-ctx.Done():
			wait.Stop()
			return awsSetupFailureFor(ctx, errAWSSetup, "configuration_check", "cancelled", ctx.Err())
		case <-wait.C:
		}
	}
	return awsSetupFailureFor(ctx, errAWSSetup, "configuration_check", "evidence_unavailable", nil)
}

func (s *awsSetup) check(ctx context.Context) error {
	if err := s.checkBucket(ctx); err != nil {
		return err
	}
	for _, public := range []bool{false, true} {
		if err := s.checkKey(ctx, public); err != nil {
			return err
		}
	}
	return nil
}

func (s *awsSetup) checkBucket(ctx context.Context) error {
	return s.checkBucketVersioning(ctx, "")
}

func (s *awsSetup) checkBucketVersioning(ctx context.Context, want s3types.BucketVersioningStatus) error {
	bucket, owner := aws.String(s.settings.Bucket), aws.String(s.settings.Account)
	checks := []func(context.Context, *s3.Client) error{
		func(ctx context.Context, c *s3.Client) error {
			out, err := c.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: bucket, ExpectedBucketOwner: owner})
			if err != nil {
				return err
			}
			region := string(out.LocationConstraint)
			if region == "" {
				region = "us-east-1"
			}
			if region == "EU" {
				region = "eu-west-1"
			}
			if region != s.settings.Region {
				return errAWSSetup
			}
			return nil
		},
		func(ctx context.Context, c *s3.Client) error {
			out, err := c.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: bucket, ExpectedBucketOwner: owner})
			if err != nil {
				return err
			}
			if out.Status != want || out.MFADelete != "" {
				return errAWSSetup
			}
			return nil
		},
		func(ctx context.Context, c *s3.Client) error {
			_, err := c.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: bucket, ExpectedBucketOwner: owner})
			if status, code := awsSetupError(err); status != 404 || code != "NoSuchLifecycleConfiguration" {
				if err != nil {
					return err
				}
				return errAWSSetup
			}
			return nil
		},
		func(ctx context.Context, c *s3.Client) error {
			_, err := c.GetBucketReplication(ctx, &s3.GetBucketReplicationInput{Bucket: bucket, ExpectedBucketOwner: owner})
			if status, code := awsSetupError(err); status != 404 || code != "ReplicationConfigurationNotFoundError" {
				if err != nil {
					return err
				}
				return errAWSSetup
			}
			return nil
		},
		func(ctx context.Context, c *s3.Client) error {
			_, err := c.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: bucket, ExpectedBucketOwner: owner})
			if status, code := awsSetupError(err); status != 404 || code != "ObjectLockConfigurationNotFoundError" {
				if err != nil {
					return err
				}
				return errAWSSetup
			}
			return nil
		},
		func(ctx context.Context, c *s3.Client) error {
			out, err := c.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: bucket, ExpectedBucketOwner: owner})
			if err != nil {
				return err
			}
			p := out.PublicAccessBlockConfiguration
			if p == nil || !aws.ToBool(p.BlockPublicAcls) || !aws.ToBool(p.BlockPublicPolicy) || !aws.ToBool(p.IgnorePublicAcls) || !aws.ToBool(p.RestrictPublicBuckets) {
				return errAWSSetup
			}
			return nil
		},
		func(ctx context.Context, c *s3.Client) error {
			out, err := c.GetBucketOwnershipControls(ctx, &s3.GetBucketOwnershipControlsInput{Bucket: bucket, ExpectedBucketOwner: owner})
			if err != nil {
				return err
			}
			if out.OwnershipControls == nil || len(out.OwnershipControls.Rules) != 1 || out.OwnershipControls.Rules[0].ObjectOwnership != s3types.ObjectOwnershipBucketOwnerEnforced {
				return errAWSSetup
			}
			return nil
		},
		func(ctx context.Context, c *s3.Client) error {
			out, err := c.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: bucket, ExpectedBucketOwner: owner})
			if err != nil {
				return err
			}
			if out.ServerSideEncryptionConfiguration == nil || len(out.ServerSideEncryptionConfiguration.Rules) != 1 {
				return errAWSSetup
			}
			rule := out.ServerSideEncryptionConfiguration.Rules[0]
			if rule.ApplyServerSideEncryptionByDefault == nil || rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm != s3types.ServerSideEncryptionAes256 || aws.ToString(rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID) != "" || aws.ToBool(rule.BucketKeyEnabled) {
				return errAWSSetup
			}
			return nil
		},
	}
	for _, check := range checks {
		if err := s.s3Check(ctx, check); err != nil {
			return err
		}
	}
	return nil
}

func (s *awsSetup) checkKey(ctx context.Context, public bool) (resultErr error) {
	operation := telemetry.OpSetupRead
	if public {
		operation = telemetry.OpSetupPublicKey
	}
	return s.checkedRead(ctx, "kms", operation, func(ctx context.Context, credentials aws.CredentialsProvider) error {
		c := kms.New(kms.Options{Region: s.settings.Region, BaseEndpoint: aws.String("https://kms." + s.settings.Region + ".amazonaws.com"), Credentials: credentials, HTTPClient: s.client, Retryer: aws.NopRetryer{}, Logger: logging.Nop{}})
		if public {
			out, err := c.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(s.settings.KeyID)})
			if err != nil {
				return err
			}
			if aws.ToString(out.KeyId) != s.settings.KeyID || out.KeySpec != kmstypes.KeySpecEccNistP256 || out.KeyUsage != kmstypes.KeyUsageTypeSignVerify || len(out.SigningAlgorithms) != 1 || out.SigningAlgorithms[0] != kmstypes.SigningAlgorithmSpecEcdsaSha256 || !bytes.Equal(out.PublicKey, s.publicKey) {
				return errAWSSetup
			}
			return nil
		}
		out, err := c.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(s.settings.KeyID)})
		if err != nil {
			return err
		}
		if out.KeyMetadata == nil {
			return errAWSSetup
		}
		k := out.KeyMetadata
		if aws.ToString(k.Arn) != s.settings.KeyID || aws.ToString(k.AWSAccountId) != s.settings.Account || !k.Enabled || k.KeyState != kmstypes.KeyStateEnabled || k.KeySpec != kmstypes.KeySpecEccNistP256 || k.KeyUsage != kmstypes.KeyUsageTypeSignVerify || aws.ToBool(k.MultiRegion) {
			return errAWSSetup
		}
		return nil
	})
}

type awsSetupTransport struct {
	base *http.Transport
}

func (t *awsSetupTransport) RoundTrip(r *http.Request) (result *http.Response, err error) {
	op, ok := r.Context().Value(awsSetupContextKey{}).(*awsSetupOperation)
	if !ok || r.URL.Scheme != "https" || r.URL.Host != op.host || r.URL.User != nil || op.sent.Swap(true) {
		return nil, awsSetupFailureFor(r.Context(), errAWSSetup, "admission", "invalid_request", nil)
	}
	r.GetBody = nil
	attempt := telemetry.StartHTTP(r.Context(), telemetry.ProviderAWS, op.metric)
	var requestObservation, responseObservation *telemetry.BodyObservation
	status := 0
	defer func() {
		if attempt != nil {
			attempt.ObserveRequest(requestObservation.Snapshot())
			if responseObservation != nil {
				attempt.ObserveResponse(responseObservation.Snapshot())
			}
			attempt.Finish(status, err != nil)
		}
	}()
	var requestBody *setupRequestBody
	if r.Body != nil && r.Body != http.NoBody {
		if attempt != nil {
			requestObservation = telemetry.TrackBody(r.Body, r.ContentLength)
			r.Body = requestObservation
		}
		requestBody = &setupRequestBody{ReadCloser: r.Body, done: make(chan struct{})}
		r.Body = requestBody
	}
	defer func() {
		if !requestBody.finished(r.Context()) {
			// Setup bodies borrow finite owned bytes. Stop later reads and join
			// admitted reads before their caller can release those bytes.
			closeErr := requestBody.Close()
			<-requestBody.done
			result, err = nil, awsSetupFailureFor(r.Context(), errAWSSetup, "response_intake", "transport", errors.Join(err, r.Context().Err(), closeErr))
		}
	}()
	response, err := t.base.RoundTrip(r)
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		op.timedOut.Store(true)
	}
	if response != nil {
		status = response.StatusCode
		op.status.Store(int32(status))
		if response.Body != nil {
			if attempt != nil {
				responseObservation = telemetry.TrackBody(response.Body, response.ContentLength)
				response.Body = responseObservation
			}
			defer response.Body.Close()
		}
	}
	if err != nil {
		return nil, awsSetupFailureFor(r.Context(), errAWSSetup, awsSetupCallStage(op), "transport", err)
	}
	if response == nil {
		return nil, awsSetupFailureFor(r.Context(), errAWSSetup, "response_intake", "missing_response", nil)
	}
	if response.Body == nil {
		return nil, awsSetupFailureFor(r.Context(), errAWSSetup, "response_intake", "missing_response", nil)
	}
	if response.Uncompressed || response.Header.Get("Content-Encoding") != "" {
		return nil, awsSetupFailureFor(r.Context(), errAWSSetup, "response_intake", "invalid_encoding", nil)
	}
	limit := int64(awsSetupLimit)
	if op.bodyLimit != 0 {
		limit = op.bodyLimit
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		cause := "invalid_length"
		if errors.Is(err, io.ErrUnexpectedEOF) {
			cause = "early_eof"
		}
		return nil, awsSetupFailureFor(r.Context(), errAWSSetup, "response_intake", cause, err)
	}
	if int64(len(body)) > limit {
		return nil, awsSetupFailureFor(r.Context(), errAWSSetup, "response_intake", "body_overflow", nil)
	}
	if response.ContentLength >= 0 && response.ContentLength != int64(len(body)) {
		cause := "invalid_length"
		if response.ContentLength > int64(len(body)) {
			cause = "early_eof"
		}
		return nil, awsSetupFailureFor(r.Context(), errAWSSetup, "response_intake", cause, nil)
	}
	if op.metric == telemetry.OpSetupDelete && response.StatusCode == http.StatusNoContent && len(body) != 0 {
		return nil, awsSetupFailureFor(r.Context(), errAWSSetup, "acknowledgement", "invalid_acknowledgement", nil)
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	return response, nil
}

package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	outputcredential "enkv.sh/plugins/outputs/aws-secrets-manager/credential"
	"errors"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	records "enkv.sh/core/internal/testrecords"
	awsprovider "enkv.sh/providers/aws"
	"enkv.sh/telemetry"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/logging"
)

var errAWSOutputFixture = errors.New("AWS output fixture refused")

const (
	awsOutputCredentialLimit = 64 << 10
	awsOutputRequestLimit    = 4 << 10
	awsOutputReplyLimit      = 512 << 10
	awsOutputValueLimit      = 65536
	awsOutputNameCharacters  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/_+=.@-"
)

type awsOutputActor struct {
	selected    liveOutputActor
	identity    os.FileInfo
	credentials aws.Credentials
	principal   string
}

type awsLiveOutput struct {
	mu                                    sync.Mutex
	location                              liveOutputLocation
	writer, cleaner, consumerA, consumerB *awsOutputActor
	otherPrincipals                       []string
	budget                                *runBudget
	transport                             http.RoundTripper
	route                                 liveOutputCredentialRoute
	prepared                              bool
	deletes                               map[string]bool
	captureFailure                        error
}

func newLiveCloudOutput(spec liveCloudOutputSpec) (liveCloudOutput, error) {
	l := spec.Location
	if l.Provider != "aws" || l.ProjectNumber != "" || !resourceAWSOutputLabel(l.Region, 64) || !awsOutputAccount(l.Account) ||
		len(l.SecretNamePrefix) == 0 || len(l.SecretNamePrefix) > 478 || !awsOutputCharacters(l.SecretNamePrefix, awsOutputNameCharacters) || spec.Budget == nil {
		return nil, awsOutputFailure(false, "admission", "invalid_request", false, 0, nil)
	}
	// The fixed commercial-region output profile also bounds fixture endpoints.
	if !awsOutputCommercialRegion(l.Region) {
		return nil, awsOutputFailure(false, "admission", "invalid_request", false, 0, nil)
	}
	writerMode := spec.Writer != nil && spec.Cleaner == nil && spec.ConsumerA != nil && spec.ConsumerB != nil && len(spec.OtherActorPrincipals) == 0
	cleanerMode := spec.Writer == nil && spec.Cleaner != nil && spec.ConsumerA == nil && spec.ConsumerB == nil && len(spec.OtherActorPrincipals) == 3
	if !writerMode && !cleanerMode {
		return nil, awsOutputFailure(false, "admission", "invalid_request", false, 0, nil)
	}
	s := &awsLiveOutput{location: l, budget: spec.Budget, otherPrincipals: append([]string(nil), spec.OtherActorPrincipals...), deletes: make(map[string]bool)}
	paths, principals := map[string]bool{}, map[string]bool{}
	copyActor := func(actor *liveOutputActor, consumer bool) (*awsOutputActor, error) {
		if actor == nil {
			return nil, nil
		}
		v := *actor
		if !filepath.IsAbs(v.CredentialsFile) || filepath.Clean(v.CredentialsFile) != v.CredentialsFile || paths[v.CredentialsFile] ||
			!resourceAWSOutputLabel(v.Profile, 128) || v.ServiceAccount != "" || !consumer && v.Principal != "" || consumer && !awsOutputIAMUser(v.Principal, l.Account) {
			return nil, errAWSOutputFixture
		}
		paths[v.CredentialsFile] = true
		if consumer {
			if principals[v.Principal] {
				return nil, errAWSOutputFixture
			}
			principals[v.Principal] = true
		}
		return &awsOutputActor{selected: v}, nil
	}
	var err error
	for _, row := range []struct {
		source   *liveOutputActor
		target   **awsOutputActor
		consumer bool
	}{{spec.Writer, &s.writer, false}, {spec.Cleaner, &s.cleaner, false}, {spec.ConsumerA, &s.consumerA, true}, {spec.ConsumerB, &s.consumerB, true}} {
		*row.target, err = copyActor(row.source, row.consumer)
		if err != nil {
			return nil, awsOutputFailure(false, "admission", "invalid_request", false, 0, err)
		}
	}
	for _, principal := range s.otherPrincipals {
		if !awsOutputIAMUser(principal, l.Account) || principals[principal] {
			return nil, awsOutputFailure(false, "admission", "invalid_request", false, 0, nil)
		}
		principals[principal] = true
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	s.transport = &http.Transport{Proxy: nil, DisableCompression: true, DisableKeepAlives: true, Protocols: protocols, MaxConnsPerHost: 1,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 20 * time.Second, MaxResponseHeaderBytes: awsOutputRequestLimit}
	return s, nil
}

func awsOutputCommercialRegion(region string) bool {
	switch region {
	case "us-east-1", "us-east-2", "us-west-1", "us-west-2", "af-south-1", "ap-east-1", "ap-east-2", "ap-south-1", "ap-south-2", "ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-southeast-4", "ap-southeast-5", "ap-southeast-6", "ap-southeast-7", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ca-central-1", "ca-west-1", "eu-central-1", "eu-central-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-south-1", "eu-south-2", "eu-north-1", "il-central-1", "mx-central-1", "me-south-1", "me-central-1", "sa-east-1":
		return true
	}
	return false
}
func resourceAWSOutputLabel(v string, maximum int) bool {
	return len(v) > 0 && len(v) <= maximum && awsOutputCharacters(v, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")
}
func awsOutputCharacters(v, allowed string) bool {
	for _, c := range v {
		if !strings.ContainsRune(allowed, c) {
			return false
		}
	}
	return true
}
func awsOutputAccount(v string) bool { return len(v) == 12 && awsOutputCharacters(v, "0123456789") }
func awsOutputIAMUser(v, account string) bool {
	prefix := "arn:aws:iam::" + account + ":user/"
	return strings.HasPrefix(v, prefix) && resourceAWSOutputLabel(strings.TrimPrefix(v, prefix), 64)
}

func (s *awsLiveOutput) captureActors(ctx context.Context, actors ...*awsOutputActor) (resultErr error) {
	if s.captureFailure != nil {
		return s.captureFailure
	}
	var captures []*liveOutputCredentialFile
	defer func() {
		for _, capture := range captures {
			if err := capture.Close(); err != nil {
				resultErr = awsOutputFailure(s.cleaner != nil, "authentication", "persistence_failed", false, 0, errors.Join(resultErr, err))
			}
		}
		if resultErr != nil {
			s.captureFailure = resultErr
		}
	}()
	for _, actor := range actors {
		if actor == nil {
			return errAWSOutputFixture
		}
		if actor.identity != nil {
			continue
		}
		capture, err := captureLiveOutputCredentialFile(actor.selected.CredentialsFile, awsOutputCredentialLimit)
		if err != nil {
			return awsOutputFailure(s.cleaner != nil, "authentication", "authentication_refused", false, 0, err)
		}
		captures = append(captures, capture)
		for _, other := range []*awsOutputActor{s.writer, s.cleaner, s.consumerA, s.consumerB} {
			if other != nil && other != actor && other.identity != nil && records.SameLocalFile(capture.Identity, other.identity) {
				return awsOutputFailure(s.cleaner != nil, "authentication", "authentication_refused", false, 0, nil)
			}
		}
		actor.identity = capture.Identity
		provider, err := awsprovider.LoadSharedCredentialsFile(ctx, capture.Path, actor.selected.Profile, time.Time{})
		if err == nil {
			actor.credentials, err = provider.Retrieve(ctx)
		}
		if err != nil || !awsOutputStaticCredentialValid(actor.credentials) {
			return awsOutputFailure(s.cleaner != nil, "authentication", "authentication_refused", false, 0, err)
		}
	}
	// No identity request can enter before all selected file aliases are checked.
	for _, actor := range actors {
		if actor.principal != "" {
			continue
		}
		principal, err := s.callerIdentity(ctx, actor.credentials)
		if err != nil {
			return err
		}
		if actor.selected.Principal != "" && actor.selected.Principal != principal {
			return awsOutputFailure(s.cleaner != nil, "authentication", "ownership_mismatch", false, 0, nil)
		}
		for _, other := range []*awsOutputActor{s.writer, s.cleaner, s.consumerA, s.consumerB} {
			if other != nil && other != actor && other.principal == principal {
				return awsOutputFailure(s.cleaner != nil, "authentication", "ownership_mismatch", false, 0, nil)
			}
		}
		for _, other := range s.otherPrincipals {
			if principal == other {
				return awsOutputFailure(true, "authentication", "ownership_mismatch", false, 0, nil)
			}
		}
		actor.principal = principal
	}
	return nil
}

func (s *awsLiveOutput) PrepareWriter(ctx context.Context, route liveOutputCredentialRoute, deadline time.Time) (facts liveOutputCredentialFacts, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	call := telemetry.Start(ctx, telemetry.ProviderAWS, telemetry.OpAuthentication)
	defer func() { finishSetupCall(call, resultErr) }()
	if ctx != nil && ctx.Err() != nil {
		return facts, awsOutputFailure(false, "admission", "invalid_request", false, 0, ctx.Err())
	}
	if s.writer == nil || ctx == nil || ctx.Err() != nil || route.ID.IsZero() || !filepath.IsAbs(route.Path) || filepath.Clean(route.Path) != route.Path || deadline.IsZero() || !time.Now().Before(deadline) {
		return facts, awsOutputFailure(false, "admission", "invalid_request", false, 0, nil)
	}
	if s.prepared {
		if route.Path != s.route.Path || route.ID != s.route.ID {
			return facts, awsOutputFailure(false, "admission", "invalid_request", false, 0, nil)
		}
		return liveOutputCredentialFacts{Principal: s.writer.principal}, nil
	}
	if route.Path == s.writer.selected.CredentialsFile || route.Path == s.consumerA.selected.CredentialsFile || route.Path == s.consumerB.selected.CredentialsFile {
		return facts, awsOutputFailure(false, "admission", "invalid_request", false, 0, nil)
	}
	if err := s.captureActors(ctx, s.writer, s.consumerA, s.consumerB); err != nil {
		return facts, err
	}
	body, err := awsOutputNativeCredential(s.writer.credentials)
	if err != nil {
		return facts, awsOutputFailure(false, "authentication", "authentication_refused", false, 0, err)
	}
	defer clear(body)
	if ctx.Err() != nil || !time.Now().Before(deadline) {
		return facts, awsOutputFailure(false, "authentication", "deadline", false, 0, ctx.Err())
	}
	if err := writeLiveOutputCredentialRoute(route, body); err != nil {
		return facts, awsOutputFailure(false, "persistence", "persistence_failed", false, 0, err)
	}
	s.route, s.prepared = route, true
	return liveOutputCredentialFacts{Principal: s.writer.principal}, nil
}

func awsOutputStaticCredentialValid(value aws.Credentials) bool {
	if value.CanExpire || value.SessionToken != "" || len(value.AccessKeyID) < 16 || len(value.AccessKeyID) > 128 || !awsOutputCharacters(value.AccessKeyID, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") || len(value.SecretAccessKey) == 0 || len(value.SecretAccessKey) > 256 {
		return false
	}
	for _, c := range value.SecretAccessKey {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}
func awsOutputNativeCredential(value aws.Credentials) ([]byte, error) {
	if !awsOutputStaticCredentialValid(value) {
		return nil, errAWSOutputFixture
	}
	return outputcredential.Encode(value.AccessKeyID, value.SecretAccessKey, value.SessionToken, time.Time{})
}

func (s *awsLiveOutput) callerIdentity(ctx context.Context, credentials aws.Credentials) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	op := &awsOutputRequest{owner: s, host: "sts." + s.location.Region + ".amazonaws.com", cleanup: s.cleaner != nil, stage: "authentication", requestLimit: awsOutputRequestLimit, responseLimit: awsOutputRequestLimit}
	client := &http.Client{Transport: op, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	sdk := sts.New(sts.Options{Region: s.location.Region, BaseEndpoint: aws.String("https://" + op.host), Credentials: awsSetupCredentials{value: credentials}, HTTPClient: client, Retryer: aws.NopRetryer{}, Logger: logging.Nop{}})
	out, err := sdk.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", op.failure("authentication_refused", err)
	}
	if out == nil || aws.ToString(out.Account) != s.location.Account || !awsOutputIAMUser(aws.ToString(out.Arn), s.location.Account) || aws.ToString(out.UserId) == "" {
		return "", op.failure("ownership_mismatch", nil)
	}
	return aws.ToString(out.Arn), nil
}

func (s *awsLiveOutput) qualifiedName(arn string) (string, bool) {
	if len(arn) < 7 || arn[len(arn)-7] != '-' || !awsOutputCharacters(arn[len(arn)-6:], "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") {
		return "", false
	}
	return s.plannedName(arn[:len(arn)-7])
}
func (s *awsLiveOutput) plannedName(slot string) (string, bool) {
	prefix := "arn:aws:secretsmanager:" + s.location.Region + ":" + s.location.Account + ":secret:"
	if !strings.HasPrefix(slot, prefix) {
		return "", false
	}
	name := strings.TrimPrefix(slot, prefix)
	return name, len(name) <= 512 && strings.HasPrefix(name, s.location.SecretNamePrefix) && len(name) > len(s.location.SecretNamePrefix) && awsOutputCharacters(name, awsOutputNameCharacters)
}

func (s *awsLiveOutput) ReadConsumer(ctx context.Context, which liveOutputConsumer, locator string, maximum uint32) (result liveOutputRead, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	call := telemetry.Start(ctx, telemetry.ProviderAWS, telemetry.OpSetupRead)
	defer func() { finishSetupCall(call, resultErr) }()
	if ctx != nil && ctx.Err() != nil {
		return result, awsOutputFailure(false, "admission", "invalid_request", false, 0, ctx.Err())
	}
	arn, stage, resolved := strings.Cut(locator, "?stage=")
	name, valid := s.qualifiedName(arn)
	if s.writer == nil || !resolved || stage != "AWSCURRENT" || !valid || maximum == 0 || maximum > awsOutputValueLimit || which != liveOutputConsumerA && which != liveOutputConsumerB || ctx == nil || ctx.Err() != nil {
		return result, awsOutputFailure(false, "admission", "invalid_request", false, 0, nil)
	}
	if err := s.captureActors(ctx, s.writer, s.consumerA, s.consumerB); err != nil {
		return result, err
	}
	actor := s.consumerA
	if which == liveOutputConsumerB {
		actor = s.consumerB
	}
	response, op, err := s.secretRequest(ctx, actor.credentials, "GetSecretValue", struct {
		SecretID     string `json:"SecretId"`
		VersionStage string `json:"VersionStage"`
	}{arn, stage}, awsOutputReplyLimit, false, "configuration_check")
	if err != nil {
		return result, err
	}
	defer clear(response.body)
	result.HTTPStatus = response.status
	code := awsOutputErrorCode(response.body)
	if response.status == http.StatusBadRequest && (code == "AccessDeniedException" || code == "NotAuthorized") {
		return liveOutputRead{HTTPStatus: response.status, AccessRefused: true}, nil
	}
	if response.status != http.StatusOK {
		return result, op.failure("provider_refused", nil)
	}
	fields, err := awsOutputObject(response.body)
	if err != nil {
		return result, op.failure("malformed_envelope", err)
	}
	var out struct {
		ARN, Name, VersionId       string
		VersionStages              []string
		SecretBinary, SecretString *string
	}
	if json.Unmarshal(response.body, &out) != nil || out.ARN != arn || out.Name != name || len(out.VersionId) < 32 || len(out.VersionId) > 64 || !awsOutputCharacters(out.VersionId, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-") || len(out.VersionStages) == 0 || len(out.VersionStages) > 20 || (out.SecretBinary == nil) == (out.SecretString == nil) {
		return result, op.failure("malformed_envelope", nil)
	}
	_, binaryPresent := fields["SecretBinary"]
	_, stringPresent := fields["SecretString"]
	if binaryPresent == stringPresent || binaryPresent && out.SecretBinary == nil || stringPresent && out.SecretString == nil {
		return result, op.failure("malformed_envelope", nil)
	}
	stages := map[string]bool{}
	for _, stage := range out.VersionStages {
		if len(stage) == 0 || len(stage) > 256 || stages[stage] {
			return result, op.failure("malformed_envelope", nil)
		}
		stages[stage] = true
	}
	if !stages["AWSCURRENT"] {
		return result, op.failure("malformed_envelope", nil)
	}
	var value []byte
	if out.SecretBinary != nil {
		value, err = base64.StdEncoding.Strict().DecodeString(*out.SecretBinary)
	} else {
		value = []byte(*out.SecretString)
	}
	if err != nil || len(value) == 0 || uint64(len(value)) > uint64(maximum) {
		clear(value)
		return result, op.failure("invalid_length", err)
	}
	return liveOutputRead{HTTPStatus: response.status, Bytes: value}, nil
}

func (s *awsLiveOutput) DeleteFixture(ctx context.Context, target liveOutputCleanupTarget) (result liveOutputCleanupResult, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if target.Index > 1000000 {
		return result, awsOutputFailure(false, "admission", "invalid_request", false, 0, nil)
	}
	call := telemetry.Start(ctx, telemetry.ProviderAWS, telemetry.OpSetupDelete)
	defer func() { finishSetupCall(call, resultErr) }()
	name, valid := s.plannedName(target.PlannedSlot)
	failure := func(stage, cause string, sent bool, status int, original error) error {
		e := awsOutputFailure(true, stage, cause, sent, status, original)
		index := target.Index
		e.fact.TargetKind = "output_inventory"
		e.fact.TargetIndex = &index
		return e
	}
	if ctx != nil && ctx.Err() != nil {
		return result, failure("admission", "invalid_request", false, 0, ctx.Err())
	}
	if s.cleaner == nil || !valid || target.CreateAttempt.IsZero() || ctx == nil || ctx.Err() != nil {
		return result, failure("admission", "invalid_request", false, 0, nil)
	}
	id := name
	if target.OwnedInstance != "" {
		ownedName, ok := s.qualifiedName(target.OwnedInstance)
		if !ok || ownedName != name {
			return result, failure("admission", "ownership_mismatch", false, 0, nil)
		}
		id = target.OwnedInstance
	}
	if s.deletes[target.PlannedSlot] {
		return result, failure("admission", "invalid_request", false, 0, nil)
	}
	if err := s.captureActors(ctx, s.cleaner); err != nil {
		return result, awsOutputWithTarget(err, target.Index)
	}
	response, op, err := s.secretRequest(ctx, s.cleaner.credentials, "DescribeSecret", struct {
		SecretID string `json:"SecretId"`
	}{id}, awsOutputRequestLimit, true, "ownership_read")
	if err != nil {
		return result, awsOutputWithTarget(err, target.Index)
	}
	defer clear(response.body)
	if response.status == http.StatusBadRequest && awsOutputErrorCode(response.body) == "ResourceNotFoundException" {
		return liveOutputCleanupResult{Disposition: liveOutputAbsent, ResolvedInstance: target.OwnedInstance}, nil
	}
	if response.status != http.StatusOK {
		return result, awsOutputWithTarget(op.failure("provider_refused", nil), target.Index)
	}
	if _, err := awsOutputObject(response.body); err != nil {
		return result, awsOutputWithTarget(op.failure("malformed_envelope", err), target.Index)
	}
	var metadata struct {
		ARN, Name   string
		DeletedDate json.RawMessage
	}
	if json.Unmarshal(response.body, &metadata) != nil {
		return result, awsOutputWithTarget(op.failure("malformed_envelope", nil), target.Index)
	}
	resolvedName, ok := s.qualifiedName(metadata.ARN)
	if !ok || resolvedName != name || metadata.Name != name || target.OwnedInstance != "" && metadata.ARN != target.OwnedInstance {
		return result, awsOutputWithTarget(op.failure("ownership_mismatch", nil), target.Index)
	}
	if len(metadata.DeletedDate) != 0 {
		if !awsOutputTimestamp(metadata.DeletedDate) {
			return result, awsOutputWithTarget(op.failure("malformed_envelope", nil), target.Index)
		}
		return liveOutputCleanupResult{Disposition: liveOutputDeletionScheduled, ResolvedInstance: metadata.ARN}, nil
	}
	// A failed or lost entered DELETE is never replayed through this helper.
	s.deletes[target.PlannedSlot] = true
	response, op, err = s.secretRequest(ctx, s.cleaner.credentials, "DeleteSecret", struct {
		SecretID       string `json:"SecretId"`
		RecoveryWindow int    `json:"RecoveryWindowInDays"`
	}{metadata.ARN, 7}, awsOutputRequestLimit, true, "conditional_delete")
	if err != nil {
		return result, awsOutputWithTarget(err, target.Index)
	}
	defer clear(response.body)
	if response.status != http.StatusOK {
		return result, awsOutputWithTarget(op.failure("provider_refused", nil), target.Index)
	}
	if _, err := awsOutputObject(response.body); err != nil {
		return result, awsOutputWithTarget(op.failure("malformed_envelope", err), target.Index)
	}
	var deleted struct {
		ARN, Name    string
		DeletionDate json.RawMessage
	}
	if json.Unmarshal(response.body, &deleted) != nil || deleted.ARN != metadata.ARN || deleted.Name != name || !awsOutputTimestamp(deleted.DeletionDate) {
		return result, awsOutputWithTarget(op.failure("invalid_acknowledgement", nil), target.Index)
	}
	return liveOutputCleanupResult{Disposition: liveOutputDeletionScheduled, ResolvedInstance: metadata.ARN}, nil
}
func awsOutputTimestamp(raw json.RawMessage) bool {
	var value *float64
	if json.Unmarshal(raw, &value) != nil || value == nil {
		return false
	}
	v := *value
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v > 0 && v < 253402300800
}

type awsOutputResponse struct {
	status int
	body   []byte
}

func (s *awsLiveOutput) secretRequest(ctx context.Context, credentials aws.Credentials, action string, input any, maximum int64, cleanup bool, stage string) (awsOutputResponse, *awsOutputRequest, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	op := &awsOutputRequest{owner: s, host: "secretsmanager." + s.location.Region + ".amazonaws.com", cleanup: cleanup, stage: stage, requestLimit: awsOutputRequestLimit, responseLimit: maximum}
	body, err := json.Marshal(input)
	if err != nil || len(body) > awsOutputRequestLimit {
		return awsOutputResponse{}, op, op.failure("invalid_request", err)
	}
	defer clear(body)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+op.host+"/", bytes.NewReader(body))
	if err != nil {
		return awsOutputResponse{}, op, op.failure("invalid_request", err)
	}
	request.Header.Set("Content-Type", "application/x-amz-json-1.1")
	request.Header.Set("X-Amz-Target", "secretsmanager."+action)
	request.Close = true
	hash := sha256.Sum256(body)
	if err := v4.NewSigner().SignHTTP(ctx, credentials, request, hex.EncodeToString(hash[:]), "secretsmanager", s.location.Region, time.Now()); err != nil {
		return awsOutputResponse{}, op, op.failure("authentication_refused", err)
	}
	request.GetBody = nil
	client := &http.Client{Transport: op, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return awsOutputResponse{}, op, op.failure("transport", err)
	}
	b, err := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil {
		clear(b)
		return awsOutputResponse{}, op, op.failure("invalid_length", errors.Join(err, closeErr))
	}
	return awsOutputResponse{status: response.StatusCode, body: b}, op, nil
}

// Each physical request owns its budget and closes/joins its borrowed body.
// The buffered response bounds the SDK deserializer as well as direct reads.
type awsOutputRequest struct {
	owner                       *awsLiveOutput
	host, stage                 string
	cleanup, sent               bool
	status                      int
	requestLimit, responseLimit int64
}

func (op *awsOutputRequest) RoundTrip(r *http.Request) (result *http.Response, resultErr error) {
	if op.sent || r.Context().Err() != nil || r.Method != http.MethodPost || r.URL.Scheme != "https" || r.URL.Host != op.host || r.URL.Path != "/" || r.URL.RawQuery != "" || r.URL.User != nil || r.ContentLength < 0 || r.ContentLength > op.requestLimit || r.Header.Get("Authorization") == "" {
		if r.Body != nil {
			if err := r.Body.Close(); err != nil {
				return nil, op.failure("unknown_effect", err)
			}
		}
		return nil, op.failure("invalid_request", nil)
	}
	if !op.owner.budget.reserve(1, uint64(op.requestLimit+op.responseLimit), "", 0) {
		if r.Body != nil {
			if err := r.Body.Close(); err != nil {
				return nil, op.failure("unknown_effect", err)
			}
		}
		return nil, op.failure("budget_exhausted", nil)
	}
	r.GetBody = nil
	if r.Body == nil {
		r.Body = http.NoBody
	}
	metric := telemetry.OpSetupRead
	if op.cleanup {
		metric = telemetry.OpSetupDelete
	}
	call := telemetry.StartHTTP(r.Context(), telemetry.ProviderAWS, metric)
	var requestObservation, responseObservation *telemetry.BodyObservation
	if call != nil {
		requestObservation = telemetry.TrackBody(r.Body, r.ContentLength)
		r.Body = requestObservation
	}
	requestBody := &setupRequestBody{ReadCloser: r.Body, done: make(chan struct{})}
	r.Body = requestBody
	defer func() {
		closeErr := requestBody.Close()
		if !requestBody.finished(r.Context()) || closeErr != nil {
			if result != nil && result.Body != nil {
				result.Body.Close()
			}
			result = nil
			resultErr = op.failure("unknown_effect", closeErr)
		}
		if call != nil {
			call.ObserveRequest(requestObservation.Snapshot())
			if responseObservation != nil {
				call.ObserveResponse(responseObservation.Snapshot())
			}
			call.Finish(op.status, resultErr != nil)
		}
	}()
	op.sent = true
	response, err := op.owner.transport.RoundTrip(r)
	responseBodyClosed := false
	if response != nil {
		op.status = response.StatusCode
		if response.Body != nil {
			if call != nil {
				responseObservation = telemetry.TrackBody(response.Body, response.ContentLength)
				response.Body = responseObservation
			}
			originalBody := response.Body
			defer func() {
				if !responseBodyClosed {
					if err := originalBody.Close(); err != nil {
						if result != nil && result.Body != nil {
							result.Body.Close()
						}
						result = nil
						resultErr = awsOutputFailure(op.cleanup, "response_intake", "unknown_effect", op.sent, op.status, errors.Join(resultErr, err))
					}
				}
			}()
		}
	}
	if err != nil {
		return nil, op.failure("transport", err)
	}
	if response == nil || response.Body == nil {
		return nil, op.failure("missing_response", nil)
	}
	if response.Uncompressed || response.Header.Get("Content-Encoding") != "" {
		return nil, op.failure("invalid_encoding", nil)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, op.responseLimit+1))
	closeErr := response.Body.Close()
	responseBodyClosed = true
	if err != nil || closeErr != nil {
		clear(body)
		return nil, op.failure("early_eof", errors.Join(err, closeErr))
	}
	if int64(len(body)) > op.responseLimit {
		clear(body)
		return nil, op.failure("body_overflow", nil)
	}
	if response.ContentLength >= 0 && response.ContentLength != int64(len(body)) {
		clear(body)
		return nil, op.failure("invalid_length", nil)
	}
	response.Body = &awsOutputBufferedBody{Reader: bytes.NewReader(body), body: body}
	return response, nil
}

type awsOutputBufferedBody struct {
	*bytes.Reader
	body []byte
}

func (b *awsOutputBufferedBody) Close() error { clear(b.body); b.body = nil; return nil }

type awsOutputFixtureFailure struct {
	fact     records.HarnessFailure
	original error
}

func (e *awsOutputFixtureFailure) Error() string { return errAWSOutputFixture.Error() }
func (e *awsOutputFixtureFailure) Unwrap() []error {
	if e.original == nil {
		return []error{errAWSOutputFixture}
	}
	return []error{errAWSOutputFixture, e.original}
}
func (e *awsOutputFixtureFailure) SafeHarnessFailure() records.HarnessFailure { return e.fact }
func awsOutputFailure(cleanup bool, stage, cause string, sent bool, status int, original error) *awsOutputFixtureFailure {
	operation := "setup_check"
	if cleanup {
		operation = "output_cleanup"
	}
	f := records.HarnessFailure{Operation: operation, Stage: stage, Cause: cause, Effect: "no_send"}
	if sent {
		f.Attempt = 1
		f.Effect = "unknown"
	}
	if status >= 100 && status <= 599 {
		v := uint16(status)
		f.HTTPStatus = &v
	}
	if errors.Is(original, context.Canceled) {
		f.Cause = "cancelled"
	} else if errors.Is(original, context.DeadlineExceeded) {
		f.Cause = "deadline"
	}
	return &awsOutputFixtureFailure{fact: f, original: original}
}
func (op *awsOutputRequest) failure(cause string, err error) *awsOutputFixtureFailure {
	var prior *awsOutputFixtureFailure
	if errors.As(err, &prior) {
		return prior
	}
	return awsOutputFailure(op.cleanup, op.stage, cause, op.sent, op.status, err)
}
func awsOutputWithTarget(err error, index uint32) error {
	var f *awsOutputFixtureFailure
	if errors.As(err, &f) {
		copy := *f
		copy.fact.TargetKind = "output_inventory"
		copy.fact.TargetIndex = &index
		return &copy
	}
	f = awsOutputFailure(true, "ownership_read", "evidence_unavailable", false, 0, err)
	f.fact.TargetKind = "output_inventory"
	f.fact.TargetIndex = &index
	return f
}
func awsOutputErrorCode(body []byte) string {
	if len(body) > awsOutputRequestLimit {
		return ""
	}
	fields, err := awsOutputObject(body)
	if err != nil {
		return ""
	}
	for field, value := range fields {
		if field != "__type" && field != "Message" && field != "message" {
			return ""
		}
		var text *string
		if json.Unmarshal(value, &text) != nil || text == nil {
			return ""
		}
	}
	var code string
	if json.Unmarshal(fields["__type"], &code) != nil {
		return ""
	}
	switch code {
	case "AccessDeniedException", "NotAuthorized", "ResourceNotFoundException":
		return code
	}
	return ""
}

func awsOutputObject(body []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(body) {
		return nil, errAWSOutputFixture
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errAWSOutputFixture
	}
	fields := map[string]json.RawMessage{}
	names := map[string]bool{}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		name, ok := key.(string)
		if !ok {
			return nil, errAWSOutputFixture
		}
		canonical := strings.ToLower(name)
		if names[canonical] {
			return nil, errAWSOutputFixture
		}
		names[canonical] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		fields[name] = value
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errAWSOutputFixture
	}
	return fields, nil
}

func (s *awsLiveOutput) BindWriterEnvironment(bind func(string, string)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if bind == nil || !s.prepared || s.writer == nil || !awsOutputStaticCredentialValid(s.writer.credentials) {
		return errAWSOutputFixture
	}
	bind("AWS_ACCESS_KEY_ID", s.writer.credentials.AccessKeyID)
	bind("AWS_SECRET_ACCESS_KEY", s.writer.credentials.SecretAccessKey)
	bind("AWS_SESSION_TOKEN", s.writer.credentials.SessionToken)
	bind("AWS_REGION", s.location.Region)
	bind("AWS_EC2_METADATA_DISABLED", "true")
	return nil
}

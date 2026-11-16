package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"hash/crc32"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/providers/gcp"
	"enkv.sh/telemetry"
	"google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
	"google.golang.org/api/storage/v1"
)

var errGCPSetup = errors.New("GCP test resource check failed")
var errGCPDelete = errors.New("GCP conditional cleanup was not acknowledged")

type gcpSetupFailure struct {
	sentinel, causeErr error
	operation          string
	stage, cause       string
	status, envelope   int
	effect             string
	attempt            uint8
}

func (f *gcpSetupFailure) Error() string { return f.sentinel.Error() }
func (f *gcpSetupFailure) Unwrap() error { return f.causeErr }
func (f *gcpSetupFailure) Is(target error) bool {
	return target == f.sentinel
}
func (f *gcpSetupFailure) SafeHarnessFailure() records.HarnessFailure {
	facts := records.HarnessFailure{Operation: f.operation, Stage: f.stage, Cause: f.cause, Effect: f.effect, Attempt: f.attempt}
	if f.status >= 100 && f.status <= 599 {
		status := uint16(f.status)
		facts.HTTPStatus = &status
	}
	if f.envelope != 0 {
		status := uint16(f.envelope)
		facts.EnvelopeStatus = &status
	}
	return facts
}

func gcpFailureCause(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	default:
		var timedOut net.Error
		if errors.As(err, &timedOut) && timedOut.Timeout() {
			return "deadline"
		}
		return "transport"
	}
}

func gcpDeleteFailure(stage, cause, effect string, op *gcpSetupOperation, causeErr error) *gcpSetupFailure {
	failure := &gcpSetupFailure{sentinel: errGCPDelete, causeErr: causeErr, operation: "object_cleanup", stage: stage, cause: cause, effect: effect}
	if op != nil {
		failure.status, failure.attempt = op.status, op.attempt
	}
	return failure
}

func gcpDeleteFromSetupFailure(op *gcpSetupOperation, err error) error {
	var source *gcpSetupFailure
	if errors.As(err, &source) {
		failure := gcpDeleteFailure(source.stage, source.cause, source.effect, op, err)
		failure.status, failure.envelope, failure.attempt = source.status, source.envelope, source.attempt
		return failure
	}
	return gcpDeleteFailure("conditional_delete", gcpFailureCause(err), "unknown", op, err)
}

const gcpSetupLimit = 64 << 10

func openLiveBackend(ctx context.Context, c liveSettings, prefix string, domain contract.ID) (*liveBackend, error) {
	return openGCPBackend(ctx, c, prefix, domain, gcp.LoadServiceAccountFile)
}

func openGCPBackend(ctx context.Context, c liveSettings, prefix string, domain contract.ID, load func(context.Context, string) (gcp.CredentialSource, error)) (*liveBackend, error) {
	publicKey, err := gcpPublicKey(c.PublicKeyPEM)
	projectNumber, numberErr := strconv.ParseUint(c.ProjectNumber, 10, 64)
	if err != nil || numberErr != nil || projectNumber == 0 || strconv.FormatUint(projectNumber, 10) != c.ProjectNumber || c.Project == "" || !strings.HasPrefix(c.KeyID, "projects/"+c.Project+"/locations/"+c.Region+"/") {
		return nil, errGCPSetup
	}
	selected, err := load(ctx, c.CredentialsFile)
	if err != nil {
		return nil, err
	}
	client, err := gcp.NewClient(&http.Transport{}, selected)
	if err != nil {
		return nil, err
	}
	storageEndpoint := "https://storage." + c.Region + ".rep.googleapis.com/storage/v1/"
	kmsEndpoint := "https://" + c.Region + "-cloudkms.googleapis.com/"
	storeConfig := gcp.StoreConfig{Client: client, Domain: domain, Region: c.Region, Endpoint: storageEndpoint, Bucket: c.Bucket, Prefix: prefix, CredentialRoute: "service-account-file"}
	store, err := gcp.NewStore(ctx, storeConfig)
	if err != nil {
		return nil, err
	}
	readCredentials := &gcpActorCredentials{CredentialSource: selected}
	readClient, err := gcp.NewClient(&http.Transport{}, readCredentials)
	if err != nil {
		return nil, err
	}
	readStoreConfig := storeConfig
	readStoreConfig.Client = readClient
	readStore, err := gcp.NewStore(ctx, readStoreConfig)
	if err != nil {
		return nil, err
	}
	trust, err := gcp.NewTrust(ctx, gcp.TrustConfig{Client: client, Region: c.Region, Endpoint: kmsEndpoint, CredentialRoute: "service-account-file", KeyVersion: c.KeyID, Algorithm: "EC_SIGN_P256_SHA256", Purpose: "ASYMMETRIC_SIGN", PublicKey: publicKey})
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
		TLSNextProto:        map[string]func(string, *tls.Conn) http.RoundTripper{},
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second,
		MaxResponseHeaderBytes: gcpSetupLimit, DisableKeepAlives: true, DisableCompression: true,
	}
	setup, err := newGCPSetup(ctx, selected, transport, c.Bucket, prefix, domain, storageEndpoint, kmsEndpoint)
	if err != nil {
		return nil, err
	}
	reader := &gcpActorReadStore{Store: store, readStore: readStore, readCredentials: readCredentials, headWrites: setup.headWrites}
	return &liveBackend{
		Store: reader, Trust: trust, PublicKey: publicKey, Put: setup.put, Delete: setup.delete,
		Check:         func(ctx context.Context) error { return setup.check(ctx, c, publicKey) },
		AccessRefused: reader.accessRefused.Load,
	}, nil
}

type gcpActorCredentials struct {
	gcp.CredentialSource
	authenticated bool
}

func (c *gcpActorCredentials) Token(ctx context.Context) (string, error) {
	token, err := c.CredentialSource.Token(ctx)
	c.authenticated = err == nil && ctx.Err() == nil && len(token) > 0 && len(token) <= 16384 && !strings.ContainsAny(token, "\r\n\t ")
	return token, err
}

type gcpActorReadStore struct {
	contract.Store
	readStore       contract.Store
	readCredentials *gcpActorCredentials
	readMu          sync.Mutex
	accessRefused   atomic.Bool
	headWrites      *gcpHeadWriteGate
}

func (s *gcpActorReadStore) StoreConfiguration() contract.StoreConfiguration {
	return fixtureStoreConfiguration(s.Store)
}

func (s *gcpActorReadStore) Read(ctx context.Context, key string, maximum uint32) contract.ReadResult {
	// Only the dedicated read client uses this recorder. Serializing reset,
	// credential acquisition and result capture excludes other calls' evidence
	// without passing caller context values across the provider boundary.
	s.readMu.Lock()
	defer s.readMu.Unlock()
	s.readCredentials.authenticated = false
	result := s.readStore.Read(ctx, key, maximum)
	s.accessRefused.Store(s.readCredentials.authenticated && ctx.Err() == nil && result.Status == contract.ReadUnavailable && result.Reason == contract.ReasonAccess)
	return result
}

func gcpPublicKey(value string) ([]byte, error) {
	block, rest := pem.Decode([]byte(value))
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errGCPSetup
	}
	if _, err := gcp.ParseVerifier(block.Bytes); err != nil {
		return nil, errGCPSetup
	}
	return block.Bytes, nil
}

type gcpSetup struct {
	ownedKey                                    func(string) bool
	credentials                                 gcp.CredentialSource
	transport                                   *gcpSetupTransport
	storage                                     *storage.Service
	kms                                         *cloudkms.Service
	bucket, head, objects, storageHost, kmsHost string
	headWrites                                  *gcpHeadWriteGate
}

func newGCPSetup(ctx context.Context, credentials gcp.CredentialSource, base http.RoundTripper, bucket, prefix string, domain contract.ID, storageEndpoint, kmsEndpoint string) (*gcpSetup, error) {
	transport := &gcpSetupTransport{base: base}
	client := &http.Client{Transport: transport, Timeout: time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	options := func(endpoint string) []option.ClientOption {
		return []option.ClientOption{option.WithHTTPClient(client), option.WithEndpoint(endpoint), option.WithUniverseDomain("googleapis.com"), option.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))}
	}
	storageService, err := storage.NewService(ctx, options(storageEndpoint)...)
	if err != nil {
		return nil, errGCPSetup
	}
	kmsService, err := cloudkms.NewService(ctx, options(kmsEndpoint)...)
	if err != nil {
		return nil, errGCPSetup
	}
	return &gcpSetup{credentials: credentials, transport: transport, storage: storageService, kms: kmsService,
		bucket: bucket, head: prefix + "/HEAD", objects: prefix + "/" + hex.EncodeToString(domain[:]) + "/",
		headWrites:  newGCPHeadWriteGate(),
		storageHost: strings.Split(strings.TrimPrefix(storageEndpoint, "https://"), "/")[0], kmsHost: strings.Split(strings.TrimPrefix(kmsEndpoint, "https://"), "/")[0]}, nil
}

type gcpSetupOperation struct {
	host, token string
	metric      telemetry.Operation
	bodyLimit   int64
	sent        atomic.Bool
	attempt     uint8
	status      int
	body        []byte
	failure     *gcpSetupFailure
}

type gcpSetupContextKey struct{}

func (op *gcpSetupOperation) fail(stage, cause string, causeErr error) error {
	effect := "no_send"
	if op.attempt != 0 {
		effect = "unknown"
		if op.metric == telemetry.OpSetupRead || op.metric == telemetry.OpSetupPublicKey {
			effect = "no_effect"
		}
	}
	failure := &gcpSetupFailure{sentinel: errGCPSetup, causeErr: causeErr, operation: gcpHarnessOperation(op.metric), stage: stage, cause: cause, status: op.status, effect: effect, attempt: op.attempt}
	op.failure = failure
	return failure
}

func (s *gcpSetup) begin(ctx context.Context, host string, operation telemetry.Operation) (context.Context, *gcpSetupOperation, error) {
	token, err := s.credentials.Token(ctx)
	if err != nil || token == "" || len(token) > 16384 || strings.ContainsAny(token, " \r\n\t") || ctx.Err() != nil {
		cause := "authentication_refused"
		causeErr := err
		if ctx.Err() != nil {
			cause = gcpFailureCause(ctx.Err())
			causeErr = ctx.Err()
		} else if err != nil && gcpFailureCause(err) != "transport" {
			cause = gcpFailureCause(err)
		}
		return ctx, nil, &gcpSetupFailure{sentinel: errGCPSetup, causeErr: causeErr, operation: gcpHarnessOperation(operation), stage: "authentication", cause: cause, effect: "no_send"}
	}
	op := &gcpSetupOperation{host: host, token: token, metric: operation}
	return context.WithValue(ctx, gcpSetupContextKey{}, op), op, nil
}

func gcpHarnessOperation(operation telemetry.Operation) string {
	if operation == telemetry.OpSetupDelete {
		return "object_cleanup"
	}
	return "setup_check"
}

func gcpSendStage(operation telemetry.Operation) string {
	switch operation {
	case telemetry.OpSetupCreate:
		return "conditional_create"
	case telemetry.OpSetupDelete:
		return "conditional_delete"
	default:
		return "ownership_read"
	}
}

func (s *gcpSetup) validKey(key string) bool {
	if s.ownedKey != nil {
		return s.ownedKey(key)
	}
	return liveFixtureKeyValid(s.head, s.objects, key)
}

func (s *gcpSetup) put(ctx context.Context, key string, body []byte) (result contract.WriteResult) {
	call := telemetry.Start(ctx, telemetry.ProviderGCP, telemetry.OpSetupCreate)
	call.InputBytes(int64(len(body)))
	defer func() { call.Finish(setupWriteResult(result.Status)) }()
	limit := 2 << 20
	if key == s.head {
		limit = gcpSetupLimit
	}
	if !s.validKey(key) || len(body) == 0 || len(body) > limit {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}
	}
	if key == s.head {
		if !s.headWrites.begin(ctx) {
			return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess}
		}
		defer s.headWrites.finish()
	}
	ctx, op, err := s.begin(ctx, s.storageHost, telemetry.OpSetupCreate)
	if err != nil {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess}
	}
	frozen := bytes.Clone(body)
	checksum := gcpChecksum(frozen)
	metadata := &storage.Object{Name: key, ContentType: "application/octet-stream", CacheControl: "private, no-store, no-transform", Crc32c: checksum}
	object, err := s.storage.Objects.Insert(s.bucket, metadata).Media(bytes.NewReader(frozen), googleapi.ChunkSize(0), googleapi.ContentType("application/octet-stream")).IfGenerationMatch(0).Context(ctx).Do()
	if err != nil {
		return gcpSetupWriteFailure(op, err)
	}
	var raw struct {
		Generation string `json:"generation"`
	}
	if json.Unmarshal(op.body, &raw) != nil || !((contract.Token{Family: contract.GCP, Value: raw.Generation}).Valid()) || raw.Generation != strconv.FormatInt(object.Generation, 10) || object.Name != key || object.Bucket != s.bucket || object.Size != uint64(len(frozen)) || object.Crc32c != checksum || object.EventBasedHold || object.TemporaryHold || object.Retention != nil || object.RetentionExpirationTime != "" {
		return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonMalformed}
	}
	return contract.WriteResult{Status: contract.WriteAcknowledged}
}

func gcpSetupWriteFailure(op *gcpSetupOperation, err error) contract.WriteResult {
	var api *googleapi.Error
	if op.status == 0 || !errors.As(err, &api) || api.Code != op.status {
		return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
	}
	var body struct {
		Error struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(op.body, &body) != nil || (body.Error.Code != 0 && body.Error.Code != op.status) {
		return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
	}
	if op.status == 412 && len(api.Errors) == 1 && api.Errors[0].Reason == "conditionNotMet" {
		return contract.WriteResult{Status: contract.WritePrecondition, Reason: contract.ReasonCondition}
	}
	if op.status == 400 || op.status == 401 || op.status == 403 || op.status == 404 || op.status == 412 {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess}
	}
	return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
}

func (s *gcpSetup) delete(ctx context.Context, key string, token contract.Token) (resultErr error) {
	call := telemetry.Start(ctx, telemetry.ProviderGCP, telemetry.OpSetupDelete)
	defer func() { finishSetupCall(call, resultErr) }()
	if !s.validKey(key) || token.Family != contract.GCP || !token.Valid() {
		return gcpDeleteFailure("admission", "invalid_request", "no_send", nil, nil)
	}
	if key == s.head {
		if !s.headWrites.begin(ctx) {
			cause := "ownership_mismatch"
			if ctx.Err() != nil {
				cause = gcpFailureCause(ctx.Err())
			}
			return gcpDeleteFailure("admission", cause, "no_send", nil, ctx.Err())
		}
		defer s.headWrites.finish()
	}
	generation, _ := strconv.ParseInt(token.Value, 10, 64)
	ctx, op, err := s.begin(ctx, s.storageHost, telemetry.OpSetupDelete)
	if err != nil {
		return gcpDeleteFromSetupFailure(nil, err)
	}
	err = s.storage.Objects.Delete(s.bucket, key).Generation(generation).IfGenerationMatch(generation).Context(ctx).Do()
	if op.failure != nil {
		return gcpDeleteFromSetupFailure(op, op.failure)
	}
	if err != nil {
		return gcpDeleteFromResponse(op, err)
	}
	if op.status != http.StatusNoContent || len(op.body) != 0 {
		return gcpDeleteFailure("acknowledgement", "invalid_acknowledgement", "unknown", op, nil)
	}
	return nil
}

func gcpDeleteFromResponse(op *gcpSetupOperation, err error) error {
	if op.status == 0 {
		return gcpDeleteFailure("conditional_delete", gcpFailureCause(err), "unknown", op, err)
	}
	code, ok := gcpResponseErrorCode(op, err)
	if !ok {
		return gcpDeleteFailure("conditional_delete", "malformed_envelope", "unknown", op, err)
	}
	cause := "provider_refused"
	switch op.status {
	case http.StatusForbidden, http.StatusUnauthorized:
		cause = "access_refused"
	case http.StatusPreconditionFailed:
		cause = "condition_refused"
	}
	failure := gcpDeleteFailure("conditional_delete", cause, "unknown", op, err)
	failure.envelope = code
	return failure
}

func gcpResponseErrorCode(op *gcpSetupOperation, err error) (int, bool) {
	var api *googleapi.Error
	if !errors.As(err, &api) || api.Code != op.status {
		return 0, false
	}
	var body struct {
		Error struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(op.body, &body) != nil || body.Error.Code != op.status {
		return 0, false
	}
	return body.Error.Code, true
}

func (s *gcpSetup) read(ctx context.Context, host string, operation telemetry.Operation, read func(context.Context) error) (resultErr error) {
	call := telemetry.Start(ctx, telemetry.ProviderGCP, operation)
	defer func() { finishSetupCall(call, resultErr) }()
	callCtx, op, err := s.begin(ctx, host, operation)
	if err != nil {
		return err
	}
	err = read(callCtx)
	if err == nil {
		return nil
	}
	if op.failure != nil {
		return op.failure
	}
	stage, cause := "ownership_read", gcpFailureCause(err)
	if errors.Is(err, errGCPSetup) {
		stage, cause = "ownership_check", "ownership_mismatch"
	} else if op.status != 0 {
		stage, cause = "response_intake", "malformed_envelope"
		if _, ok := gcpResponseErrorCode(op, err); ok {
			stage, cause = "ownership_read", "provider_refused"
			if op.status == http.StatusForbidden || op.status == http.StatusUnauthorized {
				cause = "access_refused"
			}
		}
	}
	failure := &gcpSetupFailure{sentinel: errGCPSetup, causeErr: err, operation: "setup_check", stage: stage, cause: cause, status: op.status, effect: "no_effect", attempt: op.attempt}
	if code, ok := gcpResponseErrorCode(op, err); ok {
		failure.envelope = code
	}
	return failure
}

func (s *gcpSetup) check(ctx context.Context, c liveSettings, expected []byte) error {
	if err := s.checkBucket(ctx, c); err != nil {
		return err
	}
	if err := s.read(ctx, s.kmsHost, telemetry.OpSetupRead, func(callCtx context.Context) error {
		keyName := c.KeyID[:strings.LastIndex(c.KeyID, "/cryptoKeyVersions/")]
		key, err := s.kms.Projects.Locations.KeyRings.CryptoKeys.Get(keyName).Context(callCtx).Do()
		if err != nil {
			return err
		}
		if key.Name != keyName || key.Purpose != "ASYMMETRIC_SIGN" {
			return errGCPSetup
		}
		return nil
	}); err != nil {
		return err
	}
	if err := s.read(ctx, s.kmsHost, telemetry.OpSetupRead, func(callCtx context.Context) error {
		version, err := s.kms.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.Get(c.KeyID).Context(callCtx).Do()
		if err != nil {
			return err
		}
		if version.Name != c.KeyID || version.State != "ENABLED" || version.Algorithm != "EC_SIGN_P256_SHA256" {
			return errGCPSetup
		}
		return nil
	}); err != nil {
		return err
	}
	return s.read(ctx, s.kmsHost, telemetry.OpSetupPublicKey, func(callCtx context.Context) error {
		publicKey, err := s.kms.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.GetPublicKey(c.KeyID).Context(callCtx).Do()
		if err != nil {
			return err
		}
		if publicKey.Name != c.KeyID || publicKey.Algorithm != "EC_SIGN_P256_SHA256" || publicKey.PemCrc32c != int64(crc32.Checksum([]byte(publicKey.Pem), crc32.MakeTable(crc32.Castagnoli))) {
			return errGCPSetup
		}
		actual, err := gcpPublicKey(publicKey.Pem)
		if err != nil || !bytes.Equal(actual, expected) {
			return errGCPSetup
		}
		return nil
	})
}

func (s *gcpSetup) checkBucket(ctx context.Context, c liveSettings) error {
	if err := s.read(ctx, s.storageHost, telemetry.OpSetupRead, func(callCtx context.Context) error {
		bucket, err := s.storage.Buckets.Get(s.bucket).Projection("noAcl").Context(callCtx).Do()
		if err != nil {
			return err
		}
		if !gcpBucketAdmitted(bucket, c) {
			return errGCPSetup
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

func gcpBucketAdmitted(b *storage.Bucket, c liveSettings) bool {
	return b != nil && b.Name == c.Bucket && strconv.FormatUint(b.ProjectNumber, 10) == c.ProjectNumber && strings.EqualFold(b.Location, c.Region) && b.LocationType == "region" && b.StorageClass == "STANDARD" &&
		(b.SoftDeletePolicy == nil || b.SoftDeletePolicy.RetentionDurationSeconds == 0) && (b.Versioning == nil || !b.Versioning.Enabled) && b.RetentionPolicy == nil && b.ObjectRetention == nil && !b.DefaultEventBasedHold &&
		(b.Lifecycle == nil || len(b.Lifecycle.Rule) == 0) && (b.Rpo == "" || b.Rpo == "DEFAULT") && b.CustomPlacementConfig == nil && (b.Autoclass == nil || !b.Autoclass.Enabled) &&
		(b.HierarchicalNamespace == nil || !b.HierarchicalNamespace.Enabled) && (b.Encryption == nil || b.Encryption.DefaultKmsKeyName == "") && (b.Billing == nil || !b.Billing.RequesterPays) && b.SoftDeleteTime == "" && b.HardDeleteTime == ""
}

func gcpChecksum(body []byte) string {
	var checksum [4]byte
	binary.BigEndian.PutUint32(checksum[:], crc32.Checksum(body, crc32.MakeTable(crc32.Castagnoli)))
	return base64.StdEncoding.EncodeToString(checksum[:])
}

type gcpSetupTransport struct {
	base http.RoundTripper
}

func (s *gcpSetupTransport) RoundTrip(req *http.Request) (response *http.Response, err error) {
	op, ok := req.Context().Value(gcpSetupContextKey{}).(*gcpSetupOperation)
	if !ok {
		return nil, errGCPSetup
	}
	if req.URL.Scheme != "https" || req.URL.Host != op.host || req.URL.User != nil || req.URL.Fragment != "" || op.sent.Swap(true) {
		return nil, op.fail("admission", "invalid_request", nil)
	}
	frozen := req.Clone(req.Context())
	frozen.GetBody = nil
	frozen.Close = true
	frozen.Header = make(http.Header)
	if contentType := req.Header.Get("Content-Type"); contentType != "" {
		frozen.Header.Set("Content-Type", contentType)
	}
	frozen.Header.Set("Authorization", "Bearer "+op.token)
	frozen.Header.Set("Accept-Encoding", "identity")
	frozen.Header.Set("Cache-Control", "no-cache, no-transform")
	frozen.Header.Set("User-Agent", "enkv-live-check/google-api-go-client-v0.222.0")
	if frozen.Body != nil && frozen.Body != http.NoBody {
		body, readErr := io.ReadAll(io.LimitReader(frozen.Body, (2<<20)+gcpSetupLimit+1))
		closeErr := frozen.Body.Close()
		if readErr != nil || closeErr != nil || len(body) > (2<<20)+gcpSetupLimit {
			return nil, op.fail("admission", "invalid_request", errors.Join(readErr, closeErr))
		}
		frozen.Body = io.NopCloser(bytes.NewReader(body))
		frozen.ContentLength = int64(len(body))
	}
	attempt := telemetry.StartHTTP(frozen.Context(), telemetry.ProviderGCP, op.metric)
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
	if frozen.Body != nil && frozen.Body != http.NoBody {
		if attempt != nil {
			requestObservation = telemetry.TrackBody(frozen.Body, frozen.ContentLength)
			frozen.Body = requestObservation
		}
		requestBody = &setupRequestBody{ReadCloser: frozen.Body, done: make(chan struct{})}
		frozen.Body = requestBody
	}
	defer func() {
		if !requestBody.finished(frozen.Context()) {
			// The captured body is a bounded bytes.Reader. Stop later reads and
			// join reads already admitted before returning the cancelled result.
			closeErr := requestBody.Close()
			<-requestBody.done
			cause := gcpFailureCause(frozen.Context().Err())
			if closeErr != nil {
				cause = "transport"
			}
			response, err = nil, op.fail(gcpSendStage(op.metric), cause, errors.Join(frozen.Context().Err(), closeErr))
		}
	}()
	op.attempt = 1
	response, err = s.base.RoundTrip(frozen)
	if response != nil {
		status = response.StatusCode
		op.status = status
		if response.Body != nil {
			if attempt != nil {
				responseObservation = telemetry.TrackBody(response.Body, response.ContentLength)
				response.Body = responseObservation
			}
			defer response.Body.Close()
		}
	}
	if err != nil {
		return nil, op.fail(gcpSendStage(op.metric), gcpFailureCause(err), err)
	}
	if response == nil || response.Body == nil {
		return nil, op.fail(gcpSendStage(op.metric), "missing_response", nil)
	}
	limit := int64(gcpSetupLimit)
	if op.bodyLimit != 0 {
		limit = op.bodyLimit
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if readErr != nil {
		cause := "transport"
		if errors.Is(readErr, io.ErrUnexpectedEOF) || errors.Is(readErr, io.EOF) {
			cause = "early_eof"
		}
		return nil, op.fail("response_intake", cause, readErr)
	}
	if int64(len(body)) > limit {
		return nil, op.fail("response_intake", "body_overflow", nil)
	}
	if response.Uncompressed || response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		return nil, op.fail("response_intake", "invalid_encoding", nil)
	}
	if response.ContentLength >= 0 && response.ContentLength != int64(len(body)) {
		return nil, op.fail("response_intake", "invalid_length", nil)
	}
	op.body = body
	response.Body = io.NopCloser(bytes.NewReader(body))
	return response, nil
}

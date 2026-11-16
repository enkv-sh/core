package gcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"hash/crc32"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/storage/v1"
)

const StoreClass = "gcp-gcs-json-v2"

// StoreConfig records an independently admitted domain construction. CredentialRoute
// is a runtime route identity, not a persistent Store fact or credential material.
type StoreConfig struct {
	Client                                            *Client
	Domain                                            contract.ID
	Region, Endpoint, Bucket, Prefix, CredentialRoute string
}
type Store struct {
	config     StoreConfig
	descriptor contract.Descriptor
	service    *storage.Service
	apiService *storage.Service
	host       string
}

var _ contract.ConditionalDeleteStore = (*Store)(nil)

func NewStore(ctx context.Context, c StoreConfig) (*Store, error) {
	if !sdkEnvironmentAdmitted() || c.Client == nil || c.Client.http == nil || c.Client.credentials == nil ||
		c.Endpoint != StorageEndpoint(c.Region) || !CredentialRouteValid(c.CredentialRoute) {
		return nil, ErrConstruction
	}
	d, err := storeDescriptor(c)
	if err != nil {
		return nil, err
	}
	// Regional media GET uses /download/storage/v1/. The generated insert
	// method independently resolves its absolute /upload/storage/v1/ path.
	mediaEndpoint := strings.TrimSuffix(c.Endpoint, "storage/v1/") + "download/storage/v1/"
	service, err := storage.NewService(ctx, sdkOptions(c.Client, mediaEndpoint)...)
	if err != nil {
		return nil, ErrConstruction
	}
	apiService, err := storage.NewService(ctx, sdkOptions(c.Client, c.Endpoint)...)
	if err != nil {
		return nil, ErrConstruction
	}
	host, _ := url.Parse(c.Endpoint)
	return &Store{config: c, descriptor: d, service: service, apiService: apiService, host: host.Host}, nil
}
func storeDescriptor(c StoreConfig) (contract.Descriptor, error) {
	identity, err := contract.StoreConfigurationID(storeConfiguration(c))
	if err != nil {
		return contract.Descriptor{}, ErrConstruction
	}
	domain := hex.EncodeToString(c.Domain[:])
	d := contract.Descriptor{Family: contract.GCP, Prefix: c.Prefix, HeadKey: c.Prefix + "/HEAD"}
	d.Identity = identity
	d.Coordinate = storeBinding(StoreClass, "HEAD", c.Endpoint, c.Bucket, d.HeadKey, domain)
	d.NonBody = storeBinding(StoreClass, "JSON-MULTIPART-INSERT/v1", c.Endpoint, c.Bucket, "ifGenerationMatch", "application/octet-stream", "private, no-store, no-transform", "crc32c", "one-send")
	return d, nil
}
func storeConfiguration(c StoreConfig) contract.StoreConfiguration {
	return contract.StoreConfiguration{Provider: contract.GCP, ConstructionProfile: contract.StoreConstructionProfile,
		DomainID: c.Domain, Region: c.Region, Bucket: c.Bucket, PrefixBeforeHEAD: c.Prefix}
}
func (s *Store) Descriptor() contract.Descriptor { return s.descriptor }
func (s *Store) StoreConfiguration() contract.StoreConfiguration {
	return storeConfiguration(s.config)
}
func (s *Store) keyLimit(key string) int {
	return storeKeyLimit(key, s.config.Prefix, s.descriptor.HeadKey, s.config.Domain)
}

func storeKeyLimit(key, storePrefix, headKey string, domain contract.ID) int {
	if key == headKey {
		return contract.MaxHeadLength
	}
	object, err := contract.ParseStoreObjectKey(storePrefix, domain, key)
	if err != nil {
		return 0
	}
	return int(contract.StoreObjectLimit(object))
}

func (s *Store) Read(ctx context.Context, key string, limit uint32) (result contract.ReadResult) {
	ctx, call := startTelemetryDetails(ctx, telemetry.OpStoreRead, storeDetails(s, key))
	defer func() { finishReadTelemetry(call, result) }()
	keyLimit := s.keyLimit(key)
	if keyLimit == 0 || limit == 0 || limit > uint32(keyLimit) {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	return readGCSObject(ctx, s.config.Client, s.service, s.host, s.config.Bucket, key, limit)
}

// The bounded media response supplies both the body and generation token.
func readGCSObject(ctx context.Context, client *Client, service *storage.Service, host, bucket, key string, limit uint32) contract.ReadResult {
	ctx, ok := client.begin(ctx, host, int64(limit))
	if !ok {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
	}
	response, err := service.Objects.Get(bucket, key).Context(ctx).Download()
	if err != nil {
		return readFailure(err, bucket, key)
	}
	defer response.Body.Close() //nolint:errcheck // The owned transport replaces the response with an in-memory body whose Close cannot fail.
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Range") != "" || len(response.Header.Values("X-Goog-Generation")) != 1 {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed}
	}
	token := contract.Token{Family: contract.GCP, Value: response.Header.Get("X-Goog-Generation")}
	if !token.Valid() {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed}
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if err != nil {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
	}
	if len(body) > int(limit) {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed}
	}
	return contract.ReadResult{Status: contract.ReadOK, Body: body, Token: token}
}
func readFailure(err error, bucket, key string) contract.ReadResult {
	if errors.Is(err, errMalformedResponse) {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed}
	}
	var api *googleapi.Error
	if errors.As(err, &api) {
		switch api.Code {
		case http.StatusNotFound:
			if missingGCSObjectResponse([]byte(api.Body), bucket, key) {
				return contract.ReadResult{Status: contract.ReadMissing}
			}
			return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed}
		case http.StatusUnauthorized, http.StatusForbidden:
			return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
		}
	}
	return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
}

func missingGCSObjectResponse(body []byte, bucket, key string) bool {
	if string(body) == "No such object: "+bucket+"/"+key {
		return true
	}
	if code, present, ok := publicErrorCode(body); ok {
		if !present || code != http.StatusNotFound {
			return false
		}
		errorBody, _, _ := publicErrorField(body, "error")
		rawErrors, present, ok := publicErrorField(errorBody, "errors")
		var rows []json.RawMessage
		if !ok || !present || json.Unmarshal(rawErrors, &rows) != nil || len(rows) != 1 {
			return false
		}
		rawReason, present, ok := publicErrorField(rows[0], "reason")
		var reason string
		return ok && present && json.Unmarshal(rawReason, &reason) == nil && reason == "notFound"
	}
	var reply struct {
		XMLName xml.Name `xml:"Error"`
		Codes   []string `xml:"Code"`
	}
	decoder := xml.NewDecoder(bytes.NewReader(body))
	if decoder.Decode(&reply) != nil || len(reply.Codes) != 1 || reply.Codes[0] != "NoSuchKey" && reply.Codes[0] != "NoSuchBucket" {
		return false
	}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return true
		}
		if err != nil {
			return false
		}
		data, whitespace := token.(xml.CharData)
		if !whitespace || len(bytes.TrimSpace(data)) != 0 {
			return false
		}
	}
}
func (s *Store) Create(ctx context.Context, key string, body []byte) (result contract.WriteResult) {
	ctx, call := startTelemetryDetails(ctx, telemetry.OpStoreCreate, storeDetails(s, key))
	call.InputBytes(int64(len(body)))
	defer func() { finishImmutableWriteTelemetry(call, result) }()
	if key == s.descriptor.HeadKey {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}
	}
	return s.write(ctx, key, 0, body)
}
func (s *Store) CreateHead(ctx context.Context, request contract.HeadCreateRequest) (result contract.WriteResult) {
	ctx, call := startTelemetryDetails(ctx, telemetry.OpStoreCreate, headStoreDetails(s))
	call.InputBytes(int64(request.Length()))
	defer func() { finishWriteTelemetry(call, result) }()
	if s == nil || !request.Valid() || request.Descriptor() != s.descriptor {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}
	}
	return s.write(ctx, s.descriptor.HeadKey, 0, request.Body())
}
func (s *Store) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) (result contract.WriteResult) {
	ctx, call := startTelemetryDetails(ctx, telemetry.OpStoreCompareAndSwap, storeDetails(s, key))
	call.InputBytes(int64(len(body)))
	defer func() { finishWriteTelemetry(call, result) }()
	if key != s.descriptor.HeadKey || token.Family != contract.GCP || !token.Valid() {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}
	}
	generation, _ := strconv.ParseInt(token.Value, 10, 64)
	return s.write(ctx, key, generation, body)
}

func (s *Store) DeleteIfToken(ctx context.Context, key string, token contract.Token) (result contract.WriteResult) {
	ctx, call := startTelemetryDetails(ctx, telemetry.OpCleanup, storeDetails(s, key))
	defer func() { finishWriteTelemetry(call, result) }()
	if s == nil || s.keyLimit(key) == 0 || key == s.descriptor.HeadKey || token.Family != contract.GCP || !token.Valid() {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}
	}
	generation, err := strconv.ParseInt(token.Value, 10, 64)
	if err != nil || generation <= 0 || strconv.FormatInt(generation, 10) != token.Value {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}
	}
	ctx, ok := s.config.Client.begin(ctx, s.host, maxJSON)
	if !ok {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess, NotSent: true}
	}
	if err := s.apiService.Objects.Delete(s.config.Bucket, key).IfGenerationMatch(generation).Context(ctx).Do(); err != nil {
		return writeFailure(ctx, err)
	}
	op, complete := ctx.Value(operationKey{}).(*operation)
	if !complete || op.status != http.StatusNoContent || len(op.response) != 0 {
		return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonMalformed}
	}
	return contract.WriteResult{Status: contract.WriteAcknowledged}
}

var crcTable = crc32.MakeTable(crc32.Castagnoli)

func crc(b []byte) uint32 { return crc32.Checksum(b, crcTable) }
func crcBase64(b []byte) string {
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], crc(b))
	return base64.StdEncoding.EncodeToString(out[:])
}
func (s *Store) write(ctx context.Context, key string, generation int64, body []byte) contract.WriteResult {
	limit := s.keyLimit(key)
	if limit == 0 || len(body) == 0 || len(body) > limit {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}
	}
	frozen := bytes.Clone(body)
	checksum := crcBase64(frozen)
	ctx, ok := s.config.Client.begin(ctx, s.host, maxJSON)
	if !ok {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess, NotSent: true}
	}
	metadata := &storage.Object{Name: key, ContentType: "application/octet-stream", CacheControl: "private, no-store, no-transform", Crc32c: checksum}
	object, err := s.service.Objects.Insert(s.config.Bucket, metadata).Media(bytes.NewReader(frozen), googleapi.ChunkSize(0), googleapi.ContentType("application/octet-stream")).IfGenerationMatch(generation).Context(ctx).Do()
	if err != nil {
		return writeFailure(ctx, err)
	}
	op, complete := ctx.Value(operationKey{}).(*operation)
	if !complete || op.status != http.StatusOK {
		return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonMalformed}
	}
	rawGeneration, present := responseString(ctx, "generation")
	returnedToken := contract.Token{Family: contract.GCP, Value: rawGeneration}
	if !present || !returnedToken.Valid() || rawGeneration != strconv.FormatInt(object.Generation, 10) || object.Name != key || object.Bucket != s.config.Bucket || object.Size != uint64(len(frozen)) || object.Crc32c != checksum {
		return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonMalformed}
	}
	return contract.WriteResult{Status: contract.WriteAcknowledged}
}
func writeFailure(ctx context.Context, err error) contract.WriteResult {
	if errors.Is(err, errMalformedResponse) {
		return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonMalformed}
	}
	op, complete := ctx.Value(operationKey{}).(*operation)
	var api *googleapi.Error
	if complete && op.status != 0 && errors.As(err, &api) {
		// The pinned write decoder trusts nonzero JSON error.code. Definitive
		// rejection requires agreement with the complete physical response.
		var reply struct {
			Error struct {
				Code json.RawMessage `json:"code"`
			} `json:"error"`
		}
		if api.Code != op.status || json.Unmarshal(op.response, &reply) != nil {
			return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonMalformed}
		}
		if len(reply.Error.Code) != 0 {
			var code int
			if json.Unmarshal(reply.Error.Code, &code) != nil || code != op.status {
				return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonMalformed}
			}
		}
		if op.status == http.StatusPreconditionFailed {
			if len(api.Errors) == 1 && api.Errors[0].Reason == "conditionNotMet" {
				return contract.WriteResult{Status: contract.WritePrecondition, Reason: contract.ReasonCondition}
			}
			return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonCondition}
		}
		if op.status == http.StatusBadRequest || op.status == http.StatusUnauthorized || op.status == http.StatusForbidden || op.status == http.StatusNotFound {
			return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess}
		}
	}
	return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport, NotSent: complete && op.sent.Load() == 0}
}

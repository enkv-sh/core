package credentials

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/endpointcreds"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

const (
	endpointCredentialResponseLimit   = 64 << 10
	imdsCredentialResponseLimit       = 64 << 10
	endpointCredentialResponseTimeout = 5 * time.Second
)

// LoadDefaultCredentials uses the SDK's standard credential provider chain.
// Each operation captures one credential value before its first request.
func LoadDefaultCredentials(ctx context.Context, region string) (aws.CredentialsProvider, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrCredentials
	}
	installed, err := config.LoadDefaultConfig(ctx, config.WithRegion(region), config.WithEndpointCredentialOptions(func(o *endpointcreds.Options) {
		transport := awshttp.NewBuildableClient().GetTransport()
		transport.MaxResponseHeaderBytes = 16 << 10
		transport.DisableCompression = true
		transport.DisableKeepAlives = true
		o.HTTPClient = endpointCredentialClient{client: &http.Client{
			Transport:     transport,
			Timeout:       endpointCredentialResponseTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}}
	}), config.WithAPIOptions([]func(*middleware.Stack) error{boundIMDSResponses}))
	if err != nil || installed.Credentials == nil {
		return nil, ErrCredentials
	}

	return installed.Credentials, nil
}

func boundIMDSResponses(stack *middleware.Stack) error {
	// Pinned IMDS metadata stacks carry APITokenProvider; its token stack
	// instead carries tokenTTLRequestHeader. Bound both before SDK body reads.
	_, metadata := stack.Finalize.Get("APITokenProvider")
	_, token := stack.Serialize.Get("tokenTTLRequestHeader")
	if !metadata && !token {
		return nil
	}
	return stack.Deserialize.Add(imdsResponseBoundary{}, middleware.After)
}

type imdsResponseBoundary struct{}

func (imdsResponseBoundary) ID() string { return "EnkvIMDSResponseBoundary" }

func (imdsResponseBoundary) HandleDeserialize(ctx context.Context, input middleware.DeserializeInput, next middleware.DeserializeHandler) (out middleware.DeserializeOutput, metadata middleware.Metadata, resultErr error) {
	var observation *httpTelemetry
	if request, ok := input.Request.(*smithyhttp.Request); ok && request != nil && request.Request != nil {
		observation = startHTTPTelemetry(request.Request)
	}
	defer func() { observation.finish(resultErr != nil) }()
	out, metadata, resultErr = next.HandleDeserialize(ctx, input)
	response, ok := out.RawResponse.(*smithyhttp.Response)
	if ok && response != nil {
		observation.observeResponse(response.Response)
	}
	if resultErr != nil {
		return out, metadata, resultErr
	}
	if !ok || response == nil || response.Response == nil {
		return out, metadata, endpointCredentialRefusal{}
	}
	raw, readErr := readCredentialResponse(response.Response, imdsCredentialResponseLimit)
	if readErr != nil {
		return out, metadata, readErr
	}
	response.Body = &endpointCredentialBody{Reader: bytes.NewReader(raw), raw: raw}
	return out, metadata, nil
}

type endpointCredentialClient struct{ client *http.Client }

func (c endpointCredentialClient) Do(request *http.Request) (result *http.Response, resultErr error) {
	observation := startHTTPTelemetry(request)
	defer func() { observation.finish(resultErr != nil) }()
	response, err := c.client.Do(request)
	observation.observeResponse(response)
	if err != nil {
		return nil, endpointCredentialTransferError{cause: err}
	}
	raw, readErr := readCredentialResponse(response, endpointCredentialResponseLimit)
	if readErr != nil {
		return nil, readErr
	}
	if !validEndpointCredentialResponse(response, raw) {
		clear(raw)
		return nil, endpointCredentialRefusal{}
	}
	response.Body = &endpointCredentialBody{Reader: bytes.NewReader(raw), raw: raw}
	return response, nil
}

func readCredentialResponse(response *http.Response, limit int64) ([]byte, error) {
	if response.Body == nil {
		return nil, endpointCredentialRefusal{}
	}
	if response.StatusCode == http.StatusSwitchingProtocols {
		_ = response.Body.Close()
		return nil, endpointCredentialRefusal{}
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, limit+1))
	closeErr := response.Body.Close()
	if readErr != nil {
		clear(raw)
		return nil, endpointCredentialReadError{endpointCredentialTransferError{cause: readErr}}
	}
	if closeErr != nil || int64(len(raw)) > limit {
		clear(raw)
		return nil, endpointCredentialRefusal{}
	}
	return raw, nil
}

// The pinned SDK decodes pointer shapes and dereferences them. Validate the
// complete object first; unknown fields retain the SDK's standard meaning.
func validEndpointCredentialResponse(response *http.Response, raw []byte) bool {
	success := response.StatusCode >= 200 && response.StatusCode < 300
	if !success && response.Header.Get("Content-Type") != "application/json" {
		return true
	}
	object := bytes.TrimSpace(raw)
	if len(object) == 0 || object[0] != '{' {
		return false
	}
	if success {
		var shape struct {
			AccessKeyID     string
			SecretAccessKey string
			Token           string
			AccountID       string
			Expiration      *time.Time
		}
		return json.Unmarshal(raw, &shape) == nil && shape.AccessKeyID != "" && shape.SecretAccessKey != ""
	}
	var shape struct {
		Code    string
		Message string
	}
	return json.Unmarshal(raw, &shape) == nil
}

type endpointCredentialBody struct {
	*bytes.Reader
	raw []byte
}

func (b *endpointCredentialBody) Close() error { clear(b.raw); b.raw = nil; return nil }

// Smithy wraps HTTP client errors as connection failures. A local response
// refusal must stop before that generic classification can schedule a retry.
type endpointCredentialRefusal struct{}

func (endpointCredentialRefusal) Error() string        { return ErrCredentials.Error() }
func (endpointCredentialRefusal) Unwrap() error        { return ErrCredentials }
func (endpointCredentialRefusal) RetryableError() bool { return false }

type endpointCredentialTransferError struct{ cause error }

func (e endpointCredentialTransferError) Error() string { return ErrCredentials.Error() }
func (e endpointCredentialTransferError) Unwrap() error { return e.cause }

type endpointCredentialReadError struct {
	endpointCredentialTransferError
}

// Classify the read cause before Smithy wraps it as a request-send error.
func (e endpointCredentialReadError) RetryableError() bool {
	return retry.IsErrorRetryables(retry.DefaultRetryables).IsErrorRetryable(e.cause) == aws.TrueTernary
}

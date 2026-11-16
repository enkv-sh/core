package gcp

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
)

type reconstructionTransportCredentials struct {
	token string
	calls *atomic.Uint64
}

func (credentials reconstructionTransportCredentials) Token(ctx context.Context) (string, error) {
	if credentials.calls != nil {
		credentials.calls.Add(1)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return credentials.token, nil
}

// NewReconstructionTransportTestClient replaces transport only in test builds.
// Production SDK constructors, credentials and single-send checks still run.
func NewReconstructionTransportTestClient(transport http.RoundTripper) *Client {
	return NewReconstructionTransportTestClientWithToken(transport, "installed-test-token")
}

func NewReconstructionTransportTestClientWithToken(transport http.RoundTripper, token string) *Client {
	return makeClient(transport, reconstructionTransportCredentials{token: token})
}

func NewReconstructionSetupTestClient(transport http.RoundTripper, token string, calls *atomic.Uint64) *Client {
	return makeClient(transport, reconstructionTransportCredentials{token: token, calls: calls})
}

// LoadReconstructionServiceAccountTestSource preserves production credential
// admission and caching while accounting physical token requests in tests.
func LoadReconstructionServiceAccountTestSource(ctx context.Context, path string, transport http.RoundTripper) (CredentialSource, error) {
	return LoadServiceAccountFileForTest(ctx, path, transport)
}
func NewReconstructionCredentialTestClient(transport http.RoundTripper, credentials CredentialSource) *Client {
	return makeClient(transport, credentials)
}

// full_only: false
func TestReconstructionCredentialBridgeKeepsProductionTokenCache(t *testing.T) {
	fields, _ := serviceAccountJSON(t)
	path := serviceAccountPath(t, fields)
	var calls atomic.Uint64
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		if request.URL.String() != tokenURL || request.Method != http.MethodPost {
			t.Error("non-OAuth request reached credential transport")
		}
		return response(200, `{"access_token":"synthetic-local-token","token_type":"Bearer","expires_in":3600}`), nil
	})
	source, err := LoadReconstructionServiceAccountTestSource(t.Context(), path, transport)
	if err != nil || calls.Load() != 0 {
		t.Fatal("credential constructor sent a request")
	}
	for range 2 {
		token, err := source.Token(t.Context())
		if err != nil || token != "synthetic-local-token" {
			t.Fatal("credential bridge refused local token")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("Token cache repeated its OAuth transport call")
	}
}

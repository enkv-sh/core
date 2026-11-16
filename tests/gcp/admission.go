package gcp

import (
	"context"
	"net/http"
	"time"

	providercredentials "enkv.sh/providers/gcp/credentials"
)

// NewLocalResponderClient is assembled only in local tests. It keeps the
// production client's SDK, single-send and credential path while the test
// transport directs requests to a local HTTPS responder.
func NewLocalResponderClient(transport *http.Transport, credentials CredentialSource) (*Client, error) {
	if transport == nil || credentials == nil {
		return nil, ErrConstruction
	}
	return makeClient(transport, credentials), nil
}

func LoadServiceAccountFileForTest(ctx context.Context, path string, transport http.RoundTripper) (CredentialSource, error) {
	return providercredentials.LoadServiceAccountFileForTest(ctx, path, transport)
}

func CaptureServiceAccountTokenForTest(ctx context.Context, source CredentialSource) (string, time.Time, error) {
	return providercredentials.CaptureServiceAccountTokenForTest(ctx, source)
}

func ServiceAccountEmailForTest(source CredentialSource) (string, error) {
	return providercredentials.ServiceAccountEmailForTest(source)
}

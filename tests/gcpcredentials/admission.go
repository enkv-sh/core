package credentials

import (
	"context"
	"net/http"
	"time"
)

// LoadServiceAccountFileForTest keeps the production parser and fixed OAuth route
// while allowing test-owned physical request accounting.
func LoadServiceAccountFileForTest(ctx context.Context, path string, transport http.RoundTripper) (CredentialSource, error) {
	if transport == nil {
		return nil, ErrCredentials
	}
	return loadServiceAccountFile(ctx, path, transport)
}

// CaptureServiceAccountTokenForTest returns one token and its actual expiry from
// the loaded service-account source, with the same cache and gate as Token.
func CaptureServiceAccountTokenForTest(ctx context.Context, source CredentialSource) (string, time.Time, error) {
	credentials, ok := source.(*ManagedSource)
	if !ok || credentials == nil || credentials.email == "" {
		return "", time.Time{}, ErrCredentials
	}
	return credentials.tokenSnapshot(ctx)
}

// ServiceAccountEmailForTest identifies the same captured source that mints its
// token. It does not reopen the credential file.
func ServiceAccountEmailForTest(source CredentialSource) (string, error) {
	credentials, ok := source.(*ManagedSource)
	if !ok || credentials == nil || credentials.email == "" {
		return "", ErrCredentials
	}
	return credentials.email, nil
}

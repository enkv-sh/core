package gcp

import (
	"context"

	providercredentials "enkv.sh/providers/gcp/credentials"
)

// CredentialSource supplies an already selected credential route.
type CredentialSource = providercredentials.CredentialSource

// CapturedCredentials fixes one provider-owned bearer and quota project before service dispatch.
type CapturedCredentials = providercredentials.CapturedCredentials

var ErrCredentials = providercredentials.ErrCredentials

func LoadServiceAccountFile(ctx context.Context, path string) (CredentialSource, error) {
	return providercredentials.LoadServiceAccountFile(ctx, path)
}

// CaptureCredentials accepts only credentials created by the provider loaders.
func CaptureCredentials(ctx context.Context, source CredentialSource) (CapturedCredentials, error) {
	return providercredentials.CaptureCredentials(ctx, source)
}

func (c *Client) retrieveCredential(ctx context.Context) (captured CapturedCredentials, ok bool) {
	ctx, call := providercredentials.StartAuthenticationTelemetry(ctx)
	defer func() { finishCredentialTelemetry(call, ok) }()
	if ctx.Err() != nil {
		return CapturedCredentials{}, false
	}
	if _, selected := c.credentials.(*providercredentials.ManagedSource); selected {
		captured, err := CaptureCredentials(ctx, c.credentials)
		return captured, err == nil && ctx.Err() == nil
	}
	token, err := c.credentials.Token(ctx)
	if err != nil || ctx.Err() != nil || !providercredentials.ValidAccessToken(token) {
		return CapturedCredentials{}, false
	}
	return CapturedCredentials{Token: token}, true
}

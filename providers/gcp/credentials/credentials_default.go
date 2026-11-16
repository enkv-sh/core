package credentials

import (
	"context"
	"io"
	"log/slog"
	"net/http"

	authcredentials "cloud.google.com/go/auth/credentials"
)

// LoadDefaultCredentials uses Application Default Credentials. The selected
// provider can refresh cached tokens in the background; caller cancellation
// does not join that refresh.
func LoadDefaultCredentials(ctx context.Context) (CredentialSource, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrCredentials
	}
	selected, err := authcredentials.DetectDefault(&authcredentials.DetectOptions{
		Scopes: []string{"https://www.googleapis.com/auth/cloud-platform"}, DisableAsyncRefresh: true,
		Client: &http.Client{Timeout: credentialTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil || selected == nil {
		return nil, ErrCredentials
	}
	universe, err := selected.UniverseDomain(ctx)
	if err != nil || ctx.Err() != nil || universe != "googleapis.com" {
		return nil, ErrCredentials
	}
	quotaProject, err := selected.QuotaProjectID(ctx)
	if err != nil || ctx.Err() != nil || !validQuotaProject(quotaProject) {
		return nil, ErrCredentials
	}
	return &ManagedSource{tokens: selected.TokenProvider, gate: make(chan struct{}, 1), quotaProject: quotaProject}, nil
}

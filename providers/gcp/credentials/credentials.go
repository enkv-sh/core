// Package credentials owns GCP credential discovery and captured bearer sources.
package credentials

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"cloud.google.com/go/auth"
	"enkv.sh/telemetry"
)

const (
	maximumAccessTokenLength          = 16384
	maximumAccessTokenLifetimeSeconds = 3600
	minimumServiceAccountRSAKeyBits   = 2048
)

// CredentialSource supplies an already selected credential route. Token is
// called before the request starts; the request uses that captured value.
// The credential source may independently refresh cached tokens.
// Its implementation and credential reach need independent deployment admission.
type CredentialSource interface {
	Token(context.Context) (string, error)
}

// CapturedCredentials fixes one provider-owned bearer and quota project before
// service dispatch. Expiry is the selected token's actual expiration time.
type CapturedCredentials struct {
	Token        string
	Expiry       time.Time
	QuotaProject string
}

// CaptureCredentials captures default or explicitly loaded service-account
// credentials. It does not invoke arbitrary injected token sources.
func CaptureCredentials(ctx context.Context, source CredentialSource) (CapturedCredentials, error) {
	selected, ok := source.(*ManagedSource)
	if !ok || selected == nil || selected.tokens == nil || selected.gate == nil || ctx == nil {
		return CapturedCredentials{}, ErrCredentials
	}
	token, expiry, err := selected.tokenSnapshot(ctx)
	if err != nil {
		return CapturedCredentials{}, err
	}
	return CapturedCredentials{Token: token, Expiry: expiry, QuotaProject: selected.quotaProject}, nil
}

// ValidAccessToken checks the bearer representation used by service capture.
func ValidAccessToken(token string) bool {
	return len(token) > 0 && len(token) <= maximumAccessTokenLength && !strings.ContainsAny(token, "\r\n\t ")
}

// This bounds a single header identifier while retaining legacy domain-scoped
// project IDs. The service owns project existence and quota permissions.
func validQuotaProject(project string) bool {
	if len(project) > 253 {
		return false
	}
	for _, c := range []byte(project) {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '.' && c != ':' {
			return false
		}
	}
	return true
}

var ErrCredentials = errors.New("GCP credential file refused")

const tokenURL = "https://oauth2.googleapis.com/token"
const credentialTimeout = 30 * time.Second
const credentialLimit = 64 << 10

func LoadServiceAccountFile(ctx context.Context, path string) (CredentialSource, error) {
	transport := &http.Transport{
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  credentialTimeout,
		MaxResponseHeaderBytes: credentialLimit,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		TLSNextProto:           map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	return loadServiceAccountFile(ctx, path, transport)
}

func loadServiceAccountFile(ctx context.Context, path string, transport http.RoundTripper) (source CredentialSource, err error) {
	call := telemetry.Start(ctx, telemetry.ProviderGCP, telemetry.OpAuthentication)
	defer func() { finishCredentialTelemetry(call, err == nil) }()
	b, ok := captureCredentialFile(ctx, path, credentialLimit)
	if !ok {
		if ctx != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrCredentials
	}
	defer clearCredentialBytes(b)
	var file struct {
		Type           string `json:"type"`
		ClientEmail    string `json:"client_email"`
		PrivateKey     string `json:"private_key"`
		PrivateKeyID   string `json:"private_key_id"`
		TokenURI       string `json:"token_uri"`
		UniverseDomain string `json:"universe_domain"`
		QuotaProject   string `json:"quota_project_id"`
	}
	if json.Unmarshal(b, &file) != nil || file.Type != "service_account" || file.ClientEmail == "" || file.TokenURI != tokenURL || (file.UniverseDomain != "" && file.UniverseDomain != "googleapis.com") || !validQuotaProject(file.QuotaProject) {
		return nil, ErrCredentials
	}
	privateKey := []byte(file.PrivateKey)
	defer func() { clearCredentialBytes(privateKey) }()
	block, rest := pem.Decode(privateKey)
	if block != nil {
		defer clearCredentialBytes(block.Bytes)
	}
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrCredentials
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if err != nil || !ok || rsaKey.Validate() != nil || rsaKey.N.BitLen() < minimumServiceAccountRSAKeyBits {
		return nil, ErrCredentials
	}
	provider, err := auth.New2LOTokenProvider(&auth.Options2LO{
		Email: file.ClientEmail, PrivateKey: privateKey, PrivateKeyID: file.PrivateKeyID,
		TokenURL: tokenURL, Scopes: []string{"https://www.googleapis.com/auth/cloud-platform"},
		Client: &http.Client{Transport: tokenTransport{next: transport}, Timeout: credentialTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		return nil, ErrCredentials
	}
	// The SDK retains Options2LO.PrivateKey and parses it on each token refresh.
	// Transfer this buffer only after construction accepts that lifetime.
	privateKey = nil
	return &ManagedSource{
		tokens:       auth.NewCachedTokenProvider(provider, &auth.CachedTokenProviderOptions{DisableAsyncRefresh: true}),
		gate:         make(chan struct{}, 1),
		email:        file.ClientEmail,
		quotaProject: file.QuotaProject,
	}, nil
}

// ManagedSource is created by the credential loaders and owns their cache and gate.
type ManagedSource struct {
	tokens       auth.TokenProvider
	gate         chan struct{}
	email        string
	quotaProject string
}

func (c *ManagedSource) Token(ctx context.Context) (string, error) {
	value, _, err := c.tokenSnapshot(ctx)
	return value, err
}

func (c *ManagedSource) tokenSnapshot(ctx context.Context) (value string, expiry time.Time, err error) {
	ctx, call := StartAuthenticationTelemetry(ctx)
	defer func() { finishCredentialTelemetry(call, err == nil) }()
	ctx, cancel := context.WithTimeout(ctx, credentialTimeout)
	defer cancel()
	select {
	case c.gate <- struct{}{}:
		defer func() { <-c.gate }()
	case <-ctx.Done():
		return "", time.Time{}, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return "", time.Time{}, err
	}
	if !validQuotaProject(c.quotaProject) {
		return "", time.Time{}, ErrCredentials
	}
	token, err := c.tokens.Token(ctx)
	if err := ctx.Err(); err != nil {
		return "", time.Time{}, err
	}
	if err != nil || token == nil || !ValidAccessToken(token.Value) || token.Expiry.IsZero() || !time.Now().Before(token.Expiry) || !strings.EqualFold(token.Type, "Bearer") {
		return "", time.Time{}, ErrCredentials
	}
	return token.Value, token.Expiry, nil
}

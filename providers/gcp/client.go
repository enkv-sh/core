// Package gcp implements the pinned GCS and Cloud KMS byte/proof boundary.
// Credential sources support explicit inputs and standard ADC discovery.
// Service targets remain explicit; the client has no public apply or retry loop.
package gcp

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"google.golang.org/api/option"
)

const (
	tlsHandshakeTimeout       = 10 * time.Second
	responseHeaderTimeout     = 30 * time.Second
	maximumConnectionsPerHost = 16
	requestTimeout            = 60 * time.Second
)

// Client owns the HTTP client and replay policy. Its fields are private so an
// arbitrary RoundTripper or credential-refresh transport cannot be installed.
type Client struct {
	http        *http.Client
	credentials CredentialSource
}

// NewClient admits concrete transport capabilities, then constructs its own
// transport with fixed bounds. Caller tuning and future protocol options are
// not inherited. Custom dial/TLS hooks, proxies, and TLS bypasses are refused.
func NewClient(transport *http.Transport, credentials CredentialSource) (*Client, error) {
	if transport == nil || credentials == nil || transport.Proxy != nil || transport.Dial != nil || transport.DialContext != nil || transport.DialTLS != nil || transport.DialTLSContext != nil || transport.TLSNextProto != nil { //nolint:staticcheck // Reject deprecated dial hooks as well as their replacements.
		return nil, ErrConstruction
	}
	if t := transport.TLSClientConfig; t != nil {
		if t.InsecureSkipVerify || t.ServerName != "" || t.GetClientCertificate != nil || t.VerifyPeerCertificate != nil || t.VerifyConnection != nil || len(t.Certificates) != 0 || t.RootCAs != nil {
			return nil, ErrConstruction
		}
	}
	owned := &http.Transport{}
	owned.Proxy = nil
	owned.DisableKeepAlives = true
	owned.DisableCompression = true
	owned.ForceAttemptHTTP2 = false
	owned.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	owned.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	owned.TLSHandshakeTimeout = tlsHandshakeTimeout
	owned.ResponseHeaderTimeout = responseHeaderTimeout
	owned.MaxResponseHeaderBytes = maxJSON
	owned.MaxConnsPerHost = maximumConnectionsPerHost
	return makeClient(owned, credentials), nil
}

func sdkOptions(client *Client, endpoint string) []option.ClientOption {
	return []option.ClientOption{
		option.WithHTTPClient(client.http),
		option.WithEndpoint(endpoint),
		option.WithUniverseDomain("googleapis.com"),
		// SDK wire logging can contain bodies and caller context headers. This
		// boundary exposes only its bounded result reasons, never raw SDK logs.
		option.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
	}
}

// The pinned HTTP constructor probes default client certificates before it
// returns an explicit HTTP client. It forbids combining WithHTTPClient with
// WithClientCertSource. Refuse ambient discovery instead of changing process
// settings or bypassing SDK validation. The admitted process must not mutate
// its environment concurrently with construction.
func sdkEnvironmentAdmitted() bool {
	return !strings.EqualFold(os.Getenv("GOOGLE_API_USE_CLIENT_CERTIFICATE"), "true") &&
		!strings.EqualFold(os.Getenv("EXPERIMENTAL_GOOGLE_API_USE_S2A"), "true")
}

func makeClient(transport http.RoundTripper, credentials CredentialSource) *Client {
	return &Client{http: &http.Client{Transport: &singleSend{base: transport}, Timeout: requestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, credentials: credentials}
}

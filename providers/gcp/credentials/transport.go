package credentials

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"enkv.sh/providers/gcp/internal/httptransport"
)

func privateRequestContext(ctx context.Context) context.Context {
	private := httptransport.PrivateContext(ctx)
	if ctx.Value(authenticationKey{}) == true {
		private = context.WithValue(private, authenticationKey{}, true)
	}
	return private
}

type tokenTransport struct {
	next http.RoundTripper
}

func (t tokenTransport) RoundTrip(r *http.Request) (result *http.Response, err error) {
	if r.Method != http.MethodPost || r.URL.String() != tokenURL || r.URL.User != nil {
		return nil, ErrCredentials
	}
	r = r.Clone(privateRequestContext(r.Context()))
	r.GetBody = nil
	observation := startHTTPTelemetry(r)
	defer func() { observation.finish(err != nil) }()
	requestBody := httptransport.TrackRequestCompletion(r)
	defer func() {
		if !requestBody.Wait(r.Context()) {
			result, err = nil, ErrCredentials
		}
	}()
	response, err := t.next.RoundTrip(r)
	observation.observeResponse(response)
	if err != nil {
		return nil, ErrCredentials
	}
	if response == nil || response.Body == nil {
		return nil, ErrCredentials
	}
	defer response.Body.Close() //nolint:errcheck // Close failure marks body telemetry incomplete; it does not change the validated reply.
	body, err := io.ReadAll(io.LimitReader(response.Body, credentialLimit+1))
	if err != nil || len(body) > credentialLimit || response.Uncompressed || response.Header.Get("Content-Encoding") != "" || (response.ContentLength >= 0 && int64(len(body)) != response.ContentLength) {
		return nil, ErrCredentials
	}
	if response.StatusCode == http.StatusOK {
		var token struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			ExpiresIn   int64  `json:"expires_in"`
			IDToken     string `json:"id_token"`
		}
		if json.Unmarshal(body, &token) != nil || token.AccessToken == "" || len(token.AccessToken) > maximumAccessTokenLength ||
			strings.ContainsAny(token.AccessToken, "\r\n\t ") || !strings.EqualFold(token.TokenType, "Bearer") ||
			token.ExpiresIn <= 0 || token.ExpiresIn > maximumAccessTokenLifetimeSeconds || token.IDToken != "" {
			return nil, ErrCredentials
		}
	} else if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices {
		return nil, ErrCredentials
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	return response, nil
}

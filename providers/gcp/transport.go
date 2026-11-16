package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync/atomic"

	"enkv.sh/core/contract"
	"enkv.sh/providers/gcp/internal/httptransport"
	"enkv.sh/telemetry"
)

const (
	maxObject = 2 << 20
	maxJSON   = 64 << 10
)

var errTransport = errors.New("GCP transport evidence unavailable")
var errMalformedResponse = errors.New("GCP response exceeds admitted bound")

type operationKey struct{}
type operation struct {
	host         string
	token        string
	quotaProject string
	limit        int64
	attempts     atomic.Uint32
	sent         atomic.Uint32
	status       int
	response     []byte
	private      *privateDecrypt
	list         *gcsListObservation
}

func privateRequestContext(ctx context.Context) context.Context {
	private := httptransport.PrivateContext(ctx)
	if operation, ok := ctx.Value(telemetryOperationKey{}).(telemetry.Operation); ok {
		private = context.WithValue(private, telemetryOperationKey{}, operation)
	}
	return private
}

func (c *Client) begin(ctx context.Context, host string, limit int64) (context.Context, bool) {
	ctx = privateRequestContext(ctx)
	captured, ok := c.retrieveCredential(ctx)
	if !ok {
		return ctx, false
	}
	return context.WithValue(ctx, operationKey{}, &operation{host: host, token: captured.Token, quotaProject: captured.QuotaProject, limit: limit}), true
}

type singleSend struct{ base http.RoundTripper }

func (s *singleSend) RoundTrip(req *http.Request) (result *http.Response, err error) {
	op, ok := req.Context().Value(operationKey{}).(*operation)
	if !ok || req.URL.Scheme != "https" || req.URL.Host != op.host || req.URL.User != nil || req.URL.Fragment != "" || op.attempts.Add(1) != 1 {
		return nil, errTransport
	}
	frozen := req.Clone(context.WithValue(privateRequestContext(req.Context()), operationKey{}, op))
	frozen.GetBody = nil
	frozen.Close = true
	// The generated client also accepts headers from caller context metadata.
	// That context must not alter this construction's condition, billing route,
	// encryption headers, cache policy, or identity. Rebuild the closed header set.
	contentType := frozen.Header.Get("Content-Type")
	frozen.Header = make(http.Header)
	if contentType != "" {
		frozen.Header.Set("Content-Type", contentType)
	}
	frozen.Header.Set("User-Agent", "enkv-gcp/google-api-go-client-v0.222.0")
	frozen.Header.Set("Authorization", "Bearer "+op.token)
	if op.quotaProject != "" {
		frozen.Header.Set("X-Goog-User-Project", op.quotaProject)
	}
	frozen.Header.Set("Accept-Encoding", "identity")
	frozen.Header.Set("Cache-Control", "no-cache, no-transform")
	// The generated multipart body is fully materialized once. This gives the
	// physical request an exact Content-Length without a resumable upload path.
	if frozen.Body != nil && frozen.Body != http.NoBody {
		body, err := io.ReadAll(io.LimitReader(frozen.Body, maxObject+maxJSON+1))
		closeErr := frozen.Body.Close()
		if err != nil || closeErr != nil || len(body) > maxObject+maxJSON {
			return nil, errTransport
		}
		frozen.Body = io.NopCloser(bytes.NewReader(body))
		frozen.ContentLength = int64(len(body))
	}
	observation := startHTTPTelemetry(frozen)
	defer func() { observation.finish(err != nil) }()
	requestBody := httptransport.TrackRequestCompletion(frozen)
	defer func() {
		if op.private != nil {
			if requestBody != nil {
				closeErr := requestBody.Close()
				<-requestBody.Done()
				if closeErr != nil {
					result, err = nil, errTransport
				}
			}
			return
		}
		if !requestBody.Wait(frozen.Context()) {
			result, err = nil, errTransport
		}
	}()
	op.sent.Add(1)
	response, err := s.base.RoundTrip(frozen)
	observation.observeResponse(response)
	if err != nil {
		if op.private != nil && response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, errTransport
	}
	if response == nil || response.Body == nil {
		return nil, errTransport
	}
	if op.private != nil {
		return op.private.response(response)
	}
	defer response.Body.Close() //nolint:errcheck // Close failure marks body telemetry incomplete; it does not change the validated reply.
	if response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		return nil, errTransport
	}
	limit := op.limit
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		limit = maxJSON
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, errTransport
	}
	if int64(len(body)) > limit {
		// Actual excess bytes prove a successful object violates the bound.
		// LimitReader stopping here is not evidence of an interrupted transfer.
		if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices {
			if op.list != nil {
				op.list.reason = contract.ReasonLimit
			}
			return nil, errMalformedResponse
		}
		return nil, errTransport
	}
	if response.ContentLength >= 0 && response.ContentLength != int64(len(body)) {
		return nil, errTransport
	}
	if op.list != nil && response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices &&
		(response.StatusCode != http.StatusOK || !op.list.decode(body)) {
		if op.list.reason == contract.ReasonNone {
			op.list.reason = contract.ReasonMalformed
		}
		return nil, errMalformedResponse
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	op.status = response.StatusCode
	op.response = body
	return response, nil
}

// Generated int64 fields normalize noncanonical decimal strings. Check the
// original bounded response for fields whose exact API representation matters.
func responseString(ctx context.Context, field string) (string, bool) {
	op, ok := ctx.Value(operationKey{}).(*operation)
	if !ok {
		return "", false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(op.response, &fields) != nil {
		return "", false
	}
	var value string
	if json.Unmarshal(fields[field], &value) != nil {
		return "", false
	}
	return value, true
}

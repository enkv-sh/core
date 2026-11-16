package awsprovider

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"enkv.sh/core/contract"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

const (
	maximumResponseHeaderBytes = 16 << 10
	maximumPublicResponseBytes = 16 << 10
)

const maxErrorResponse = 16 << 10

var errTransport = errors.New("AWS transport refused request")
var errResponse = errors.New("AWS response failed bounds or encoding")

func privateTransport(t *http.Transport) (*http.Transport, error) {
	if t == nil || t.Dial != nil || t.DialTLS != nil || t.DialTLSContext != nil { //nolint:staticcheck // Reject deprecated dial hooks as well as their replacements.
		return nil, ErrConstruction
	}
	tlsConfig, err := ownedTLSConfig(t.TLSClientConfig)
	if err != nil {
		return nil, err
	}
	// Copy only the admitted transport fields. Future net/http protocol defaults
	// and injected alternate protocol registries cannot expand this construction.
	return &http.Transport{DialContext: t.DialContext, TLSClientConfig: tlsConfig, TLSHandshakeTimeout: t.TLSHandshakeTimeout, ResponseHeaderTimeout: t.ResponseHeaderTimeout, ExpectContinueTimeout: t.ExpectContinueTimeout, MaxResponseHeaderBytes: maximumResponseHeaderBytes, DisableCompression: true, DisableKeepAlives: true, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}, nil
}

func ownedTLSConfig(source *tls.Config) (*tls.Config, error) {
	owned := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	if source == nil {
		return owned, nil
	}
	policy := reflect.ValueOf(source).Elem()
	policyType := policy.Type()
	for i := 0; i < policy.NumField(); i++ {
		field := policyType.Field(i)
		if !field.IsExported() {
			continue
		}
		switch field.Name {
		case "RootCAs", "MinVersion", "MaxVersion", "NextProtos", "CipherSuites", "CurvePreferences", "SessionTicketsDisabled", "DynamicRecordSizingDisabled":
			continue
		}
		if !policy.Field(i).IsZero() {
			return nil, ErrConstruction
		}
	}
	if source.MinVersion != 0 {
		if source.MinVersion != tls.VersionTLS12 && source.MinVersion != tls.VersionTLS13 {
			return nil, ErrConstruction
		}
		owned.MinVersion = source.MinVersion
	}
	if source.MaxVersion != 0 && (source.MaxVersion < owned.MinVersion || source.MaxVersion > tls.VersionTLS13) {
		return nil, ErrConstruction
	}
	if len(source.NextProtos) != 0 && (len(source.NextProtos) != 1 || source.NextProtos[0] != "http/1.1") {
		return nil, ErrConstruction
	}
	for _, suite := range source.CipherSuites {
		switch suite {
		case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		default:
			return nil, ErrConstruction
		}
	}
	for _, curve := range source.CurvePreferences {
		switch curve {
		case tls.CurveP256, tls.CurveP384, tls.CurveP521, tls.X25519,
			tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024, tls.MLKEM1024:
		default:
			return nil, ErrConstruction
		}
	}
	owned.MaxVersion = source.MaxVersion
	owned.CipherSuites = slices.Clone(source.CipherSuites)
	owned.CurvePreferences = slices.Clone(source.CurvePreferences)
	owned.SessionTicketsDisabled = source.SessionTicketsDisabled
	owned.DynamicRecordSizingDisabled = source.DynamicRecordSizingDisabled
	if source.RootCAs != nil {
		owned.RootCAs = source.RootCAs.Clone()
	}
	return owned, nil
}

type attemptKey struct{}
type attempt struct {
	calls             atomic.Uint32
	sent              atomic.Uint32
	limit             int64
	private           *privateDecrypt
	requireStrongETag bool
	responseETag      string
	status            int
	response          []byte
	list              *s3ListObservation
}

func operationContext(ctx context.Context, limit int64) context.Context {
	return context.WithValue(ctx, attemptKey{}, &attempt{limit: limit})
}

func storeReadContext(ctx context.Context, limit int64) (context.Context, *attempt) {
	a := &attempt{limit: limit, requireStrongETag: true}
	return context.WithValue(ctx, attemptKey{}, a), a
}

// The owned client admits one RoundTrip per SDK operation. Its production
// transport cannot replay on a reused connection because reuse is disabled.
type boundedTransport struct {
	next http.RoundTripper
	host string
}

func (t boundedTransport) RoundTrip(r *http.Request) (result *http.Response, err error) {
	a, ok := r.Context().Value(attemptKey{}).(*attempt)
	if !ok || a.calls.Add(1) != 1 || r.URL.Scheme != "https" || r.URL.Host != t.host || r.URL.User != nil {
		return nil, errTransport
	}
	r.GetBody = nil
	observation := startHTTPTelemetry(r)
	defer func() { observation.finish(err != nil) }()
	requestBody := trackRequestCompletion(r)
	defer func() {
		if a.private != nil {
			if requestBody != nil {
				closeErr := requestBody.Close()
				<-requestBody.done
				if closeErr != nil {
					result, err = nil, errTransport
				}
			}
			return
		}
		if !requestBody.wait(r.Context()) {
			result, err = nil, errTransport
		}
	}()
	a.sent.Add(1)
	resp, err := t.next.RoundTrip(r)
	observation.observeResponse(resp)
	if err != nil {
		if a.private != nil {
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
			return nil, errTransport
		}
		return nil, err
	}
	if resp == nil || resp.Body == nil {
		return nil, errTransport
	}
	if a.private != nil {
		return a.private.response(resp)
	}
	defer resp.Body.Close() //nolint:errcheck // Close failure marks body telemetry incomplete; it does not change the validated reply.
	if a.requireStrongETag && resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
		etag, ok := singletonHeader(resp.Header, "ETag")
		if !ok || !(contract.Token{Family: contract.AWS, Value: etag}).Valid() {
			return nil, errResponse
		}
		a.responseETag = etag
	}
	limit, invalid := a.limit, errResponse
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		// Error envelopes are not object bytes. Their size must not depend on
		// the selected object's length, and a failed envelope proves no state.
		limit, invalid = maxErrorResponse, errTransport
	}
	if resp.Header.Get("Content-Encoding") != "" || resp.Uncompressed {
		return nil, invalid
	}
	// The pinned PutObject deserializer reads only success headers. Complete the
	// bounded reply here, so a truncated 200 cannot become an acknowledgment.
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, errTransport
	}
	if int64(len(body)) > limit {
		// Actual excess bytes prove an oversized object; a declared length
		// alone does not establish this when the transfer is interrupted.
		if a.list != nil && resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
			a.list.reason = contract.ReasonLimit
		}
		return nil, invalid
	}
	if resp.ContentLength >= 0 && int64(len(body)) != resp.ContentLength {
		return nil, errTransport
	}
	if a.list != nil && resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices &&
		(resp.StatusCode != http.StatusOK || !a.list.decode(body)) {
		if a.list.reason == contract.ReasonNone {
			a.list.reason = contract.ReasonMalformed
		}
		return nil, errResponse
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	a.status = resp.StatusCode
	a.response = body
	return resp, nil
}

func singletonHeader(header http.Header, name string) (string, bool) {
	var value string
	count := 0
	for key, values := range header {
		if !strings.EqualFold(key, name) {
			continue
		}
		count += len(values)
		if count != 1 {
			return "", false
		}
		value = values[0]
	}
	return value, count == 1
}

func ownedClient(rt http.RoundTripper, host string, timeout time.Duration) *http.Client {
	return &http.Client{Transport: boundedTransport{next: rt, host: host}, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// Request completion is transport policy, independent of telemetry. Close must
// finish and all active reads must return before RoundTrip acknowledges a reply.
type requestCompletion struct {
	io.ReadCloser
	mu              sync.Mutex
	reads           int
	closing, closed bool
	done            chan struct{}
	closeOnce       sync.Once
	closeErr        error
}

func trackRequestCompletion(r *http.Request) *requestCompletion {
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	body := &requestCompletion{ReadCloser: r.Body, done: make(chan struct{})}
	r.Body = body
	return body
}

func (body *requestCompletion) wait(ctx context.Context) bool {
	if body == nil {
		return true
	}
	select {
	case <-body.done:
		return true
	default:
	}
	select {
	case <-body.done:
		return true
	case <-ctx.Done():
		return false
	}
}

func (b *requestCompletion) Read(p []byte) (int, error) {
	b.mu.Lock()
	if b.closing {
		b.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	b.reads++
	b.mu.Unlock()

	n, err := b.ReadCloser.Read(p)
	b.mu.Lock()
	b.reads--
	if b.closed && b.reads == 0 {
		close(b.done)
	}
	b.mu.Unlock()
	return n, err
}

func (b *requestCompletion) Close() error {
	b.closeOnce.Do(func() {
		b.mu.Lock()
		b.closing = true
		b.mu.Unlock()
		// Close must be able to unblock a Read without waiting for its lock.
		b.closeErr = b.ReadCloser.Close()
		b.mu.Lock()
		b.closed = true
		if b.reads == 0 {
			close(b.done)
		}
		b.mu.Unlock()
	})
	return b.closeErr
}

func serviceError(err error) (int, string) {
	var response *smithyhttp.ResponseError
	var api smithy.APIError
	var status int
	var code string
	if errors.As(err, &response) {
		status = response.HTTPStatusCode()
	}
	if errors.As(err, &api) {
		code = api.ErrorCode()
	}
	return status, code
}

package gcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"enkv.sh/telemetry"
)

// full_only: false
func TestTelemetryHTTPIncludesPartialAndFailedTransfers(t *testing.T) {
	for _, mode := range []string{"success", "send-error", "body-error", "oversized", "http-error"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "1")
			ctx, snapshot := collectTelemetry(t)
			transport := singleSend{base: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if n, err := io.CopyN(io.Discard, r.Body, 2); n != 2 || err != nil {
					t.Fatal("request body unavailable")
				}
				if mode == "send-error" {
					return nil, io.ErrUnexpectedEOF
				}
				resp := response(200, "abc")
				if mode == "body-error" {
					resp.Body = io.NopCloser(&interruptedBody{body: "abc"})
				}
				if mode == "oversized" {
					resp = response(200, "abcdefgh")
				}
				if mode == "http-error" {
					resp.StatusCode = 503
				}
				return resp, nil
			})}
			ctx, call := startTelemetry(ctx, telemetry.OpStoreCreate)
			defer call.Finish(telemetry.ResultSuccess)
			ctx = context.WithValue(ctx, operationKey{}, &operation{host: "fixture.invalid", token: "synthetic", limit: 4})
			r, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://fixture.invalid/", strings.NewReader("abcdef"))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := transport.RoundTrip(r)
			if resp != nil {
				if err := resp.Body.Close(); err != nil {
					t.Error(err)
				}
			}
			responseBytes, responseStatus, result, status := int64(3), "complete", "success", "2xx"
			if mode == "send-error" {
				responseBytes, status = 0, "none"
			}
			if mode == "oversized" {
				responseBytes = 5
			}
			if mode == "send-error" || mode == "body-error" || mode == "oversized" {
				result, responseStatus = "failure", "incomplete"
			}
			if mode == "http-error" {
				status = "5xx"
			}
			if (err != nil) != (result == "failure") {
				t.Fatalf("transport error=%v, want result %s", err, result)
			}
			if _, err := transport.RoundTrip(r); err == nil {
				t.Fatal("refused replay was counted as a physical attempt")
			}
			data := snapshot()
			for _, want := range []struct {
				name, result, status string
				value                int64
			}{
				{telemetry.HTTPAttempts, "", "", 1},
				{telemetry.HTTPResults, result, status, 1},
				{telemetry.HTTPRequestBodyBytes, "", "incomplete", 2},
				{telemetry.HTTPRequestBodyObservations, "", "incomplete", 1},
				{telemetry.HTTPResponseBodyBytes, "", responseStatus, responseBytes},
				{telemetry.HTTPResponseBodyObservations, "", responseStatus, 1},
			} {
				if got := telemetrySum(data, want.name, telemetry.OpStoreCreate, want.result, want.status); got != want.value {
					t.Errorf("%s %s %s = %d, want %d", want.name, want.result, want.status, got, want.value)
				}
			}
		})
	}
}

// full_only: false
func TestTelemetryHTTPIsSafeDuringConcurrentTransfers(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "1")
	const transfers = 16
	want := map[string]struct {
		result   telemetry.Result
		status   string
		value    int64
		duration bool
	}{
		telemetry.OperationCalls:               {value: 1},
		telemetry.OperationResults:             {result: telemetry.ResultSuccess, value: 1},
		telemetry.OperationDuration:            {result: telemetry.ResultSuccess, duration: true},
		telemetry.HTTPAttempts:                 {value: 1},
		telemetry.HTTPResults:                  {result: telemetry.ResultSuccess, status: "2xx", value: 1},
		telemetry.HTTPDuration:                 {result: telemetry.ResultSuccess, status: "2xx", duration: true},
		telemetry.HTTPRequestBodyBytes:         {result: telemetry.ResultSuccess, status: "complete", value: 4},
		telemetry.HTTPRequestBodyObservations:  {result: telemetry.ResultSuccess, status: "complete", value: 1},
		telemetry.HTTPResponseBodyBytes:        {result: telemetry.ResultSuccess, status: "complete", value: 5},
		telemetry.HTTPResponseBodyObservations: {result: telemetry.ResultSuccess, status: "complete", value: 1},
	}
	points := make(chan telemetry.MetricPoint, transfers*len(want))
	var capabilities [transfers]*telemetry.Capability
	transport := singleSend{base: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		_, err := io.Copy(io.Discard, r.Body)
		return response(200, "reply"), err
	})}
	var workers sync.WaitGroup
	t.Cleanup(func() {
		workers.Wait()
		for _, capability := range capabilities {
			capability.Deactivate()
		}
	})
	// Each transfer has its own capability because shared admission can drop contended points.
	// The transport calls remain concurrent.
	for i := range capabilities {
		capabilities[i] = telemetry.NewCapability(points, nil)
		ctx := telemetry.WithCapability(context.Background(), capabilities[i])
		workers.Add(1)
		go func() {
			defer workers.Done()
			ctx, call := startTelemetry(ctx, telemetry.OpStoreCreate)
			defer call.Finish(telemetry.ResultSuccess)
			ctx = context.WithValue(ctx, operationKey{}, &operation{host: "fixture.invalid", token: "synthetic", limit: 8})
			r, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://fixture.invalid/", strings.NewReader("body"))
			if err != nil {
				t.Error(err)
				return
			}
			resp, err := transport.RoundTrip(r)
			if err != nil {
				t.Error(err)
				return
			}
			if err := resp.Body.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	workers.Wait()
	for i, capability := range capabilities {
		if capability.LostMetrics() != 0 || capability.RejectedMetrics() != 0 {
			t.Errorf("transfer %d lost=%d rejected=%d", i, capability.LostMetrics(), capability.RejectedMetrics())
		}
	}
	seen := make(map[string]int, len(want))
	for len(points) != 0 {
		point := <-points
		expected, ok := want[point.Name]
		if !ok {
			t.Errorf("unexpected metric point %q", point.Name)
			continue
		}
		seen[point.Name]++
		if point.Provider != telemetry.ProviderGCP || point.Operation != telemetry.OpStoreCreate || point.Result != expected.result || point.Status != expected.status || point.Barrier != nil || point.IntValue != expected.value || math.IsNaN(point.FloatValue) || math.IsInf(point.FloatValue, 0) || point.FloatValue < 0 || !expected.duration && point.FloatValue != 0 {
			t.Errorf("concurrent transfer metric differs: %+v", point)
		}
	}
	for name := range want {
		if seen[name] != transfers {
			t.Errorf("metric %s observations=%d want=%d", name, seen[name], transfers)
		}
	}
}

// full_only: false
func TestTelemetryStoreTrustAndCredentialHTTPAreSeparate(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "1")
	ctx, snapshot := collectTelemetry(t)
	fields, _ := serviceAccountJSON(t)
	p, err := LoadServiceAccountFileForTest(ctx, serviceAccountPath(t, fields), roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Fatal(err)
		}
		return response(200, `{"access_token":"synthetic","token_type":"Bearer","expires_in":3600}`), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	client := makeClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Body != nil {
			if _, err := io.Copy(io.Discard, r.Body); err != nil {
				t.Fatal(err)
			}
		}
		return response(503, `{"error":{"code":503}}`), nil
	}), p)
	s, err := NewStore(ctx, config(client))
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrust(ctx, trustConfig(client, public))
	if err != nil {
		t.Fatal(err)
	}
	s.Read(ctx, s.Descriptor().HeadKey, 32)
	trust.Sign(ctx, signRequest(t))
	data := snapshot()
	if telemetrySum(data, telemetry.HTTPAttempts, telemetry.OpStoreRead, "", "") != 1 || telemetrySum(data, telemetry.HTTPAttempts, telemetry.OpTrustSign, "", "") != 1 || telemetrySum(data, telemetry.HTTPRequestBodyBytes, telemetry.OpStoreRead, "", "") != 0 || telemetrySum(data, telemetry.HTTPRequestBodyBytes, telemetry.OpTrustSign, "", "complete") == 0 {
		t.Fatal("Store and KMS HTTP observations were combined")
	}
	if telemetrySum(data, telemetry.HTTPAttempts, telemetry.OpAuthentication, "", "") != 1 || telemetrySum(data, telemetry.HTTPRequestBodyBytes, telemetry.OpAuthentication, "", "complete") == 0 || telemetrySum(data, telemetry.HTTPResponseBodyBytes, telemetry.OpAuthentication, "", "complete") == 0 {
		t.Fatal("credential HTTP observations are unavailable")
	}
}

// full_only: false
func TestTelemetryHTTPPreservesKnownEmptyRequestBody(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "1")
	ctx, snapshot := collectTelemetry(t)
	ctx, call := startTelemetry(ctx, telemetry.OpStoreCreate)
	defer call.Finish(telemetry.ResultSuccess)
	ctx = context.WithValue(ctx, operationKey{}, &operation{host: "fixture.invalid", token: "synthetic", limit: 8})
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://fixture.invalid/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	transport := singleSend{base: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Body != http.NoBody || r.ContentLength != 0 {
			t.Fatal("telemetry changed empty-body framing")
		}
		return response(200, "{}"), nil
	})}
	resp, err := transport.RoundTrip(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	data := snapshot()
	if telemetrySum(data, telemetry.HTTPAttempts, telemetry.OpStoreCreate, "", "") != 1 || telemetrySum(data, telemetry.HTTPRequestBodyBytes, telemetry.OpStoreCreate, "", "") != 0 || telemetrySum(data, telemetry.HTTPRequestBodyObservations, telemetry.OpStoreCreate, "", "complete") != 1 {
		t.Fatal("empty request observations differ")
	}
}

type delayedRequestTransport struct {
	started  chan struct{}
	release  chan struct{}
	consumed chan struct{}
}

func (d delayedRequestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	go func() {
		close(d.started)
		<-d.release
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		close(d.consumed)
	}()
	if r.URL.String() == tokenURL {
		return response(200, `{"access_token":"joined-token","token_type":"Bearer","expires_in":3600}`), nil
	}
	return response(200, "{}"), nil
}

// full_only: false
func TestTransportWaitsForRequestBodyCompletionWithoutTelemetry(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "")
	for _, route := range []string{"service"} {
		t.Run(route, func(t *testing.T) {
			ctx, snapshot := collectTelemetry(t)
			base := delayedRequestTransport{make(chan struct{}), make(chan struct{}), make(chan struct{})}
			ctx, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			transport := &singleSend{base: base}
			endpoint := "https://fixture.invalid/"
			ctx = context.WithValue(ctx, operationKey{}, &operation{host: "fixture.invalid", token: "synthetic", limit: 8})
			r, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader("abc"))
			if err != nil {
				t.Fatal(err)
			}
			returned := make(chan error, 1)
			go func() {
				resp, err := transport.RoundTrip(r)
				if resp != nil {
					_ = resp.Body.Close()
				}
				returned <- err
			}()
			<-base.started
			early := false
			select {
			case <-returned:
				early = true
				t.Error("transport returned before request body completion")
			case <-time.After(20 * time.Millisecond):
			}
			close(base.release)
			<-base.consumed
			if !early {
				if err := <-returned; err != nil {
					t.Fatal(err)
				}
			}
			if len(snapshot().ScopeMetrics) != 0 {
				t.Fatal("disabled telemetry produced request observations")
			}
		})
	}
}

// full_only: false
func TestTransportBoundsRequestBodyCompletionWithoutTelemetry(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "")
	for _, route := range []string{"service"} {
		t.Run(route, func(t *testing.T) {
			ctx, snapshot := collectTelemetry(t)
			base := delayedRequestTransport{make(chan struct{}), make(chan struct{}), make(chan struct{})}
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			transport := &singleSend{base: base}
			endpoint, wantErr := "https://fixture.invalid/", errTransport
			ctx = context.WithValue(ctx, operationKey{}, &operation{host: "fixture.invalid", token: "synthetic", limit: 8})
			r, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader("abc"))
			if err != nil {
				t.Fatal(err)
			}
			returned := make(chan error, 1)
			go func() {
				resp, err := transport.RoundTrip(r)
				if resp != nil {
					_ = resp.Body.Close()
				}
				returned <- err
			}()
			<-base.started
			cancel()
			select {
			case err := <-returned:
				if err != wantErr {
					t.Errorf("incomplete request did not return the safe error: %v", err)
				}
			case <-time.After(time.Second):
				t.Error("request body completion exceeded its context bound")
			}
			close(base.release)
			<-base.consumed
			if len(snapshot().ScopeMetrics) != 0 {
				t.Fatal("disabled telemetry produced request observations")
			}
		})
	}
}

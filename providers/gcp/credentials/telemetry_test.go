package credentials

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/observability"
	"enkv.sh/telemetry"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func collectTelemetry(t *testing.T) (context.Context, func() metricdata.ResourceMetrics) {
	t.Helper()
	settings, err := observability.Decode([]byte(`{"schema_version":1,"logs":{"exporters":[]},"metrics":{"exporters":["capture"]},"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"}}}`), observability.Options{})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := observability.Start(settings, observability.SetupOptions{BaseDirectory: t.TempDir(), ManualMetrics: true})
	if err != nil {
		t.Fatal(err)
	}
	ready, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := runtime.AwaitMetrics(ready); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closeContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runtime.Close(closeContext); err != nil {
			t.Error(err)
		}
	})
	return runtime.Context(context.Background()), func() metricdata.ResourceMetrics {
		flushContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runtime.FlushMetrics(flushContext); err != nil {
			t.Fatal(err)
		}
		var data metricdata.ResourceMetrics
		if err := runtime.ManualReader().Collect(flushContext, &data); err != nil {
			t.Fatal(err)
		}
		return data
	}
}

func telemetrySum(data metricdata.ResourceMetrics, name string, operation telemetry.Operation, result, status string) int64 {
	var sum int64
	for _, scope := range data.ScopeMetrics {
		for _, metric := range scope.Metrics {
			if metric.Name != name {
				continue
			}
			for _, point := range metric.Data.(metricdata.Sum[int64]).DataPoints {
				provider, _ := point.Attributes.Value("provider")
				op, _ := point.Attributes.Value("operation")
				r, _ := point.Attributes.Value("result")
				s, _ := point.Attributes.Value("status")
				if provider.AsString() == "gcp" && op.AsString() == string(operation) && (result == "" || r.AsString() == result) && (status == "" || s.AsString() == status) {
					sum += point.Value
				}
			}
		}
	}
	return sum
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (reply *http.Response, err error) {
	if r.Body != nil {
		defer func() { err = errors.Join(err, r.Body.Close()) }()
	}
	return f(r)
}

func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}
}

type interruptedBody struct{ body string }

func (b *interruptedBody) Read(p []byte) (int, error) {
	n := copy(p, b.body)
	b.body = b.body[n:]
	if len(b.body) == 0 {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
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
func TestTelemetryCredentialHTTPIncludesIncompleteResponse(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "1")
	ctx, snapshot := collectTelemetry(t)
	transport := tokenTransport{next: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if _, err := io.CopyN(io.Discard, r.Body, 2); err != nil {
			t.Fatal(err)
		}
		resp := response(200, "abc")
		resp.Body = io.NopCloser(&interruptedBody{body: "abc"})
		return resp, nil
	})}
	ctx, call := StartAuthenticationTelemetry(ctx)
	defer call.Finish(telemetry.ResultFailure)
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader("assertion"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.RoundTrip(r); err != ErrCredentials {
		t.Fatal("incomplete credential response was accepted")
	}
	data := snapshot()
	if telemetrySum(data, telemetry.HTTPAttempts, telemetry.OpAuthentication, "", "") != 1 || telemetrySum(data, telemetry.HTTPResults, telemetry.OpAuthentication, "failure", "2xx") != 1 || telemetrySum(data, telemetry.HTTPRequestBodyBytes, telemetry.OpAuthentication, "", "incomplete") != 2 || telemetrySum(data, telemetry.HTTPResponseBodyBytes, telemetry.OpAuthentication, "", "incomplete") != 3 {
		t.Fatal("partial credential transfer observations differ")
	}
	if telemetrySum(data, telemetry.HTTPRequestBodyObservations, telemetry.OpAuthentication, "", "incomplete") != 1 || telemetrySum(data, telemetry.HTTPResponseBodyObservations, telemetry.OpAuthentication, "", "incomplete") != 1 {
		t.Fatal("partial credential transfer was marked complete")
	}
}

// full_only: false
func TestTelemetryHTTPWaitsForRequestCompletion(t *testing.T) {
	for _, route := range []string{"authentication"} {
		for _, mode := range []string{"complete", "cancelled"} {
			t.Run(route+"/"+mode, func(t *testing.T) {
				t.Setenv("ENKV_TELEMETRY", "1")
				ctx, snapshot := collectTelemetry(t)
				base := delayedRequestTransport{make(chan struct{}), make(chan struct{}), make(chan struct{})}
				ctx, cancel := context.WithTimeout(ctx, time.Second)
				defer cancel()
				op, endpoint, wantErr := telemetry.OpAuthentication, tokenURL, ErrCredentials
				var transport http.RoundTripper = tokenTransport{next: base}
				ctx, call := StartAuthenticationTelemetry(ctx)
				defer call.Finish(telemetry.ResultSuccess)
				r, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader("abc"))
				if err != nil {
					t.Fatal(err)
				}
				returned := make(chan error, 1)
				go func() {
					reply, err := transport.RoundTrip(r)
					if reply != nil {
						_ = reply.Body.Close()
					}
					returned <- err
				}()
				<-base.started
				data := snapshot()
				if telemetrySum(data, telemetry.HTTPAttempts, op, "", "") != 1 || telemetrySum(data, telemetry.HTTPResults, op, "", "") != 0 {
					t.Error("HTTP result preceded request completion")
				}
				if mode == "cancelled" {
					cancel()
					if err := <-returned; err != wantErr {
						t.Errorf("cancelled request error=%v", err)
					}
					data = snapshot()
					if telemetrySum(data, telemetry.HTTPRequestBodyObservations, op, "", "incomplete") != 1 || telemetrySum(data, telemetry.HTTPRequestBodyBytes, op, "", "") != 0 || telemetrySum(data, telemetry.HTTPResults, op, "failure", "2xx") != 1 {
						t.Error("cancelled transfer was marked complete")
					}
					close(base.release)
				} else {
					close(base.release)
					if err := <-returned; err != nil {
						t.Errorf("complete request error=%v", err)
					}
					data = snapshot()
					if telemetrySum(data, telemetry.HTTPRequestBodyObservations, op, "", "complete") != 1 || telemetrySum(data, telemetry.HTTPRequestBodyBytes, op, "", "complete") != 3 {
						t.Error("joined request bytes were lost")
					}
				}
				<-base.consumed
				if mode == "cancelled" {
					data = snapshot()
					if telemetrySum(data, telemetry.HTTPRequestBodyObservations, op, "", "incomplete") != 0 || telemetrySum(data, telemetry.HTTPRequestBodyBytes, op, "", "") != 0 {
						t.Error("late reads changed a completed partial observation")
					}
				}
			})
		}
	}
}

// full_only: false
func TestTransportWaitsForRequestBodyCompletionWithoutTelemetry(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "")
	for _, route := range []string{"authentication"} {
		t.Run(route, func(t *testing.T) {
			ctx, snapshot := collectTelemetry(t)
			base := delayedRequestTransport{make(chan struct{}), make(chan struct{}), make(chan struct{})}
			ctx, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			var transport http.RoundTripper = tokenTransport{next: base}
			endpoint := tokenURL
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
	for _, route := range []string{"authentication"} {
		t.Run(route, func(t *testing.T) {
			ctx, snapshot := collectTelemetry(t)
			base := delayedRequestTransport{make(chan struct{}), make(chan struct{}), make(chan struct{})}
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			var transport http.RoundTripper = tokenTransport{next: base}
			endpoint, wantErr := tokenURL, ErrCredentials
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

package observability

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"

	"enkv.sh/telemetry"
	"go.opentelemetry.io/otel/attribute"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"
)

// full_only: false
func TestTelemetryTextRefusesInvalidUTF8AtEveryStartupBoundary(t *testing.T) {
	invalid := string([]byte{0xff})
	if _, err := proto.Marshal(&commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: invalid}}); err == nil {
		t.Fatal("invalid text fixture did not reach protobuf string validation")
	}
	for _, test := range []struct {
		name    string
		options Options
	}{
		{"environment-key", Options{EnvResourceAttributes: "%FF=value"}},
		{"environment-value", Options{EnvResourceAttributes: "key=%FF"}},
		{"environment-service", Options{EnvServiceName: invalid}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Resolve(Config{}, test.options); err != errConfiguration {
				t.Error("invalid environment text accepted or unsafe refusal", err)
			}
		})
	}
	for _, test := range []struct {
		name   string
		config Config
		edit   func(*Resolved)
	}{
		{"resource-key", Config{Resource: ResourceConfig{Attributes: map[string]any{invalid: "value"}}}, func(s *Resolved) { s.Resource[invalid] = "value" }},
		{"resource-value", Config{Resource: ResourceConfig{Attributes: map[string]any{"key": invalid}}}, func(s *Resolved) { s.Resource["key"] = invalid }},
		{"resource-array", Config{Resource: ResourceConfig{Attributes: map[string]any{"key": []any{"value", invalid}}}}, func(s *Resolved) { s.Resource["key"] = []any{"value", invalid} }},
		{"service-name", Config{Resource: ResourceConfig{Attributes: map[string]any{"service.name": invalid}}}, func(s *Resolved) { s.Resource["service.name"] = invalid }},
		{"scope-name", Config{Scopes: map[string]Scope{"core": {Name: invalid}}}, func(s *Resolved) { s.Scopes["core"] = Scope{Name: invalid} }},
		{"scope-version", Config{Scopes: map[string]Scope{"core": {Name: "example.core", Version: invalid}}}, func(s *Resolved) { s.Scopes["core"] = Scope{Name: "example.core", Version: invalid} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.config.SchemaVersion = 1
			if _, err := Resolve(test.config, Options{}); err != errConfiguration {
				t.Error("invalid typed text accepted or unsafe refusal", err)
			}
			settings, err := Resolve(Config{}, Options{})
			if err != nil {
				t.Fatal("default fixture", err)
			}
			test.edit(&settings)
			if err := settings.Validate(); err != errConfiguration {
				t.Error("invalid resolved text accepted or unsafe refusal", err)
			}
			runtime, err := Start(settings, SetupOptions{Console: io.Discard})
			if runtime != nil {
				if closeErr := runtime.Close(context.Background()); closeErr != nil {
					t.Error("unexpected runtime did not close")
				}
			}
			if runtime != nil || err != errConfiguration {
				t.Error("invalid startup text accepted or unsafe refusal", err)
			}
		})
	}
}

// full_only: false
func TestTelemetryUnicodeResourceAndScopeTextStaysExact(t *testing.T) {
	const text = "café/שלום/日本/�"
	settings, err := Resolve(Config{SchemaVersion: 1,
		Resource: ResourceConfig{Attributes: map[string]any{"service.name": text, "Name": text, "name": "different", "array": []any{text, "é"}}},
		Scopes:   map[string]Scope{"core": {Name: text, Version: text}},
	}, Options{EnvResourceAttributes: "environment=caf%C3%A9"})
	if err != nil || settings.Validate() != nil || settings.Resource["service.name"] != text || settings.Resource["Name"] != text || settings.Resource["name"] != "different" || settings.Resource["environment"] != "café" || !reflect.DeepEqual(settings.Resource["array"], []any{text, "é"}) || settings.Scopes["core"] != (Scope{Name: text, Version: text}) {
		t.Fatal("valid Unicode was refused or changed", err)
	}
	for _, message := range []proto.Message{
		&resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			{Key: "service.name", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: settings.Resource["service.name"].(string)}}},
			{Key: "Name", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: settings.Resource["Name"].(string)}}},
		}},
		&commonpb.InstrumentationScope{Name: settings.Scopes["core"].Name, Version: settings.Scopes["core"].Version},
	} {
		if _, err := proto.Marshal(message); err != nil {
			t.Fatal("accepted Unicode is not protobuf text", err)
		}
	}
}

// full_only: false
func TestResourceAdmissionNormalizesStartupValues(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input any
		want  attribute.Value
	}{
		{"int64-int", []any{int64(1), int(2)}, attribute.Int64SliceValue([]int64{1, 2})},
		{"float-json", []any{float64(1.5), json.Number("2.5")}, attribute.Float64SliceValue([]float64{1.5, 2.5})},
		{"scalar-int", int(3), attribute.Int64Value(3)},
		{"scalar-json", json.Number("4"), attribute.Int64Value(4)},
		{"array-int-first", []any{int(1), int64(2)}, attribute.Int64SliceValue([]int64{1, 2})},
		{"array-json-first", []any{json.Number("1.5"), float64(2.5)}, attribute.Float64SliceValue([]float64{1.5, 2.5})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings, err := Decode([]byte(`{"schema_version":1,"logs":{"level":"off"},"traces":{"exporters":["capture"]},"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"}}}`), Options{})
			if err != nil {
				t.Fatal(err)
			}
			settings.Resource["numeric"] = tc.input
			if err = settings.Validate(); err != nil {
				t.Fatal("valid numeric refused", err)
			}
			// Literal expectations above are derived from the admitted Go/JSON numbers,
			// independently of resourceValue and startup conversion.
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("accepted input panicked: %v", p)
				}
			}()
			runtime, err := Start(settings, SetupOptions{BaseDirectory: t.TempDir(), Console: io.Discard})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := runtime.Close(context.Background()); err != nil {
					t.Error(err)
				}
			}()
			attrs := resourceAttributes(runtime.Resource())
			want := map[attribute.Key]attribute.Value{"service.name": attribute.StringValue("enkv"), "numeric": tc.want}
			got := map[attribute.Key]attribute.Value{}
			for _, a := range attrs {
				got[a.Key] = a.Value
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("resource=%v want=%v", got, want)
			}
			if list, ok := tc.input.([]any); ok {
				list[0] = "changed"
				after := map[attribute.Key]attribute.Value{}
				for _, a := range resourceAttributes(runtime.Resource()) {
					after[a.Key] = a.Value
				}
				if !reflect.DeepEqual(after, want) {
					t.Fatal("startup borrowed caller array", after)
				}
			}
		})
	}
	t.Run("decode-control", func(t *testing.T) {
		s, e := Decode([]byte(`{"schema_version":1,"resource":{"attributes":{"numeric":[1,2]}}}`), Options{})
		if e != nil {
			t.Fatal(e)
		}
		if got := s.Resource["numeric"]; !reflect.DeepEqual(got, []any{int64(1), int64(2)}) {
			t.Fatal(got)
		}
	})
	for _, bad := range []any{[]any{int(1), "two"}, []any{}, json.Number("NaN"), struct{}{}} {
		s, e := Resolve(Config{}, Options{})
		if e != nil {
			t.Fatal(e)
		}
		s.Resource["numeric"] = bad
		if r, e := Start(s, SetupOptions{}); e == nil {
			if err := r.Close(context.Background()); err != nil {
				t.Error("unexpected admitted runtime cleanup failed", err)
			}
			t.Errorf("invalid numeric admitted: %v", bad)
		}
	}
}

// full_only: false
func TestAcceptedEndpointSpellingsDeliverAllSignals(t *testing.T) {
	t.Setenv("ENKV_ENDPOINT_TEST_KEY", "synthetic-token")
	for _, endpoint := range []string{"https://collector.invalid", "https://collector.invalid/", "https://collector.invalid:", "https://collector.invalid:/", "https://collector.invalid?", "https://collector.invalid/?", "https://collector.invalid#", "https://collector.invalid/#", "https://collector.invalid:/?#"} {
		t.Run(endpoint, func(t *testing.T) {
			var mu sync.Mutex
			seen := map[string]int{}
			base := roundTripFunc(func(request *http.Request) (*http.Response, error) {
				mu.Lock()
				defer mu.Unlock()
				if request.URL.Host != "collector.invalid" || request.URL.Scheme != "https" || request.URL.RawQuery != "" || request.URL.Fragment != "" || request.URL.ForceQuery || request.Header.Get("x-honeycomb-team") != "synthetic-token" {
					t.Errorf("wrong route %s", request.URL)
				}
				seen[request.URL.Path]++
				_, e := io.Copy(io.Discard, request.Body)
				if e != nil {
					t.Error(e)
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
			})
			names := []string{"hosted"}
			s, e := Resolve(Config{SchemaVersion: 1, Exporters: map[string]Exporter{"hosted": {Type: "otlp_http", Endpoint: endpoint, APIKeyEnv: "ENKV_ENDPOINT_TEST_KEY"}}, Logs: LogConfig{Exporters: &names}, Metrics: SignalConfig{Exporters: &names}, Traces: TraceConfig{Exporters: &names}}, Options{})
			if e != nil {
				t.Fatal("admissible endpoint refused", e)
			}
			if s.ActiveExporters["hosted"].Endpoint != "https://collector.invalid" {
				t.Errorf("resolved endpoint not canonical: %q", s.ActiveExporters["hosted"].Endpoint)
			}
			// A direct caller may edit Resolved after Resolve. Startup must enforce
			// the same normalization before every signal worker receives its copy.
			edited := s.ActiveExporters["hosted"]
			edited.Endpoint = endpoint
			s.ActiveExporters["hosted"] = edited
			r, e := Start(s, SetupOptions{remoteBase: base})
			if e != nil {
				t.Fatal(e)
			}
			if e = r.AwaitMetrics(context.Background()); e != nil {
				t.Fatal(e)
			}
			if e = r.AwaitTraces(context.Background()); e != nil {
				t.Fatal(e)
			}
			telemetry.Start(r.Context(context.Background()), telemetry.ProviderCore, telemetry.OpCoreOpen).Finish(telemetry.ResultAdmissionRefused)
			if e = r.Close(context.Background()); e != nil {
				t.Error("shutdown", e)
			}
			mu.Lock()
			defer mu.Unlock()
			for _, signal := range []string{"logs", "metrics", "traces"} {
				status := r.DeliveryStatuses()[signal+".hosted"]
				if seen["/v1/"+signal] == 0 || status.Written == 0 || status.Accepted != status.Written || status.Dropped != 0 || status.Failed != 0 || status.Incomplete {
					t.Errorf("%s route=%d status=%+v", signal, seen["/v1/"+signal], status)
				}
			}
		})
	}
	t.Run("refuse-target-changes", func(t *testing.T) {
		for _, endpoint := range []string{"http://collector.invalid", "https://user@collector.invalid", "https://collector.invalid/other", "https://collector.invalid?q=1", "https://collector.invalid#other"} {
			s, e := Resolve(Config{}, Options{})
			if e != nil {
				t.Fatal(e)
			}
			s.LogExporters = []string{"hosted"}
			s.ActiveExporters = map[string]Exporter{"hosted": {Type: "otlp_http", Endpoint: endpoint, APIKeyEnv: "ENKV_ENDPOINT_TEST_KEY"}}
			if r, e := Start(s, SetupOptions{}); e == nil {
				if err := r.Close(context.Background()); err != nil {
					t.Error("unexpected admitted runtime cleanup failed", err)
				}
				t.Errorf("changed target admitted %s", endpoint)
			}
		}
	})
}

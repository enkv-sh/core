package observability

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"enkv.sh/telemetry"
)

// full_only: false
func TestTypedZeroIsDefaultButEmptySelectedFileIsRefused(t *testing.T) {
	settings, err := Resolve(Config{}, Options{})
	if err != nil || settings.LogLevel != Warn || !settings.Console {
		t.Fatal("typed zero did not resolve defaults", err)
	}
	path := filepath.Join(t.TempDir(), "empty.json")
	if os.WriteFile(path, nil, 0o600) != nil {
		t.Fatal("fixture")
	}
	if _, err := Load(path, Options{}); err == nil {
		t.Fatal("empty selected configuration was accepted")
	}
}

// full_only: false
func TestDefaultConfigurationKeepsOnlyWarningConsole(t *testing.T) {
	for _, document := range []string{"", `{"schema_version":1}`} {
		settings, err := Decode([]byte(document), Options{})
		if err != nil {
			t.Fatal(err)
		}
		if settings.LogLevel != Warn || !settings.Console || len(settings.LogExporters) != 0 || len(settings.MetricExporters) != 0 || len(settings.TraceExporters) != 0 {
			t.Fatalf("unexpected default routes: %+v", settings)
		}
		if settings.Resource["service.name"] != "enkv" {
			t.Fatalf("unexpected default service: %+v", settings.Resource)
		}
	}
}

// full_only: false
func TestLogLevelPrecedenceDoesNotSelectExport(t *testing.T) {
	const document = `{"schema_version":1,"logs":{"level":"info"}}`
	for _, test := range []struct {
		name    string
		options Options
		want    Severity
	}{
		{"configuration", Options{}, Info},
		{"environment", Options{EnvLogLevel: "DEBUG"}, Debug},
		{"command", Options{EnvLogLevel: "DEBUG", LogLevel: "17"}, Error},
		{"shadowed_environment", Options{EnvLogLevel: "invalid", LogLevel: "error"}, Error},
		{"empty_environment", Options{EnvLogLevel: ""}, Info},
		{"off", Options{LogLevel: "off"}, Off},
	} {
		t.Run(test.name, func(t *testing.T) {
			settings, err := Decode([]byte(document), test.options)
			if err != nil {
				t.Fatal(err)
			}
			if settings.LogLevel != test.want || len(settings.LogExporters) != 0 || len(settings.MetricExporters) != 0 || len(settings.TraceExporters) != 0 {
				t.Fatalf("unexpected level/routes: %+v", settings)
			}
		})
	}
}

// full_only: false
func TestResourcePrecedenceAndInactiveDestinations(t *testing.T) {
	const document = `{"schema_version":1,"resource":{"attributes":{"service.name":"configured","deployment.environment.name":"local","retries":3}},"exporters":{"unused":{"type":"otlp_file","directory":"capture"}}}`
	settings, err := Decode([]byte(document), Options{
		EnvServiceName:        "environment-service",
		EnvResourceAttributes: "service.name=environment-resource,service.namespace=team",
	})
	if err != nil {
		t.Fatal(err)
	}
	if settings.Resource["service.name"] != "configured" || settings.Resource["service.namespace"] != "team" || settings.Resource["deployment.environment.name"] != "local" || settings.Resource["retries"] != int64(3) {
		t.Fatalf("unexpected resource precedence: %+v", settings.Resource)
	}
	if len(settings.ActiveExporters) != 0 {
		t.Fatalf("unused destination became active: %+v", settings.ActiveExporters)
	}
	settings, err = Decode([]byte(`{"schema_version":1}`), Options{EnvServiceName: "environment-service", EnvResourceAttributes: "service.name=environment-resource"})
	if err != nil || settings.Resource["service.name"] != "environment-service" {
		t.Fatalf("OTEL_SERVICE_NAME precedence: %+v, %v", settings.Resource, err)
	}
}

// full_only: false
func TestDefaultScopesCoverTelemetryProviders(t *testing.T) {
	settings, err := Resolve(Config{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[telemetry.Provider]Scope{
		telemetry.ProviderCore:          {Name: "enkv.sh/core"},
		telemetry.ProviderCrypto:        {Name: "enkv.sh/crypto"},
		telemetry.ProviderAWS:           {Name: "enkv.sh/providers/aws"},
		telemetry.ProviderGCP:           {Name: "enkv.sh/providers/gcp"},
		telemetry.ProviderGeneratorHost: {Name: "enkv.sh/compositions/generatorhost"},
		telemetry.ProviderOutputHost:    {Name: "enkv.sh/compositions/outputhost"},
		telemetry.ProviderManifestHost:  {Name: "enkv.sh/compositions/manifesthost"},
		telemetry.ProviderApplication:   {Name: "enkv.sh/tests/examples/telemetry"},
		telemetry.ProviderWorker:        {Name: "enkv.sh/tests/shared/records"},
	}
	if len(settings.Scopes) != len(want) {
		t.Errorf("default scope count=%d want=%d", len(settings.Scopes), len(want))
	}
	for provider, scope := range want {
		if got, present := settings.Scopes[string(provider)]; !present || got != scope {
			t.Errorf("default scope for %s=%+v present=%t want=%+v", provider, got, present, scope)
		}
	}
}

// full_only: false
func TestExplicitRoutesAndScopeOverride(t *testing.T) {
	const document = `{"schema_version":1,"logs":{"level":"debug","exporters":["console","capture"]},"metrics":{"exporters":["capture"]},"traces":{"exporters":["capture"],"sample_ratio":0},"scopes":{"core":{"name":"example.core"},"outputhost":{"name":"example.outputhost","version":"7.2"}},"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"}}}`
	settings, err := Decode([]byte(document), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !settings.Console || settings.LogLevel != Debug || len(settings.ActiveExporters) != 1 || len(settings.MetricExporters) != 1 || len(settings.TraceExporters) != 1 || settings.TraceSampleRatio != 0 || settings.Scopes["core"].Name != "example.core" || settings.Scopes["outputhost"] != (Scope{Name: "example.outputhost", Version: "7.2"}) {
		t.Fatalf("unexpected explicit routes: %+v", settings)
	}
}

// full_only: false
func TestConfigurationRefusalsDoNotEchoInput(t *testing.T) {
	for _, document := range []string{
		`{"schema_version":2}`,
		`{"schema_version":1,"scopes":{"unknown":{"name":"secret-sentinel"}}}`,
		`{"schema_version":1,"unexpected":"secret-sentinel"}`,
		`{"schema_version":1,"schema_version":1}`,
		`{"schema_version":1,"logs":{"level":"bogus"}}`,
		`{"schema_version":1,"logs":{"exporters":["missing"]}}`,
		`{"schema_version":1,"metrics":{"exporters":["console"]}}`,
		`{"schema_version":1,"exporters":{"capture":{"type":"otlp_file","directory":"../outside"}}}`,
		`{"schema_version":1,"resource":{"attributes":{"secret":"secret-sentinel\nline"}}}`,
	} {
		_, err := Decode([]byte(document), Options{})
		if err == nil || strings.Contains(err.Error(), "secret-sentinel") {
			t.Fatalf("unsafe acceptance/error for %s: %v", document, err)
		}
	}
}

// full_only: false
func TestConfigurationRequiresExactJSONMemberNames(t *testing.T) {
	for _, test := range []struct {
		name, document, member, alias string
	}{
		{"schema", `{"schema_version":1}`, `"schema_version":1`, `"SCHEMA_VERSION":1`},
		{"resource", `{"schema_version":1,"resource":{"attributes":{"name":"lower","Name":"upper"}}}`, `"resource":`, `"Resource":`},
		{"attributes", `{"schema_version":1,"resource":{"attributes":{"name":"lower","Name":"upper"}}}`, `"attributes":`, `"Attributes":`},
		{"scopes", `{"schema_version":1,"scopes":{"core":{"name":"example.core"}}}`, `"scopes":`, `"Scopes":`},
		{"scope-name", `{"schema_version":1,"scopes":{"core":{"name":"example.core"}}}`, `"name":"example.core"`, `"Name":"example.core"`},
		{"scope-version", `{"schema_version":1,"scopes":{"core":{"name":"example.core","version":"1"}}}`, `"version":"1"`, `"Version":"1"`},
		{"logs", `{"schema_version":1,"logs":{"level":"info"}}`, `"logs":`, `"Logs":`},
		{"log-level", `{"schema_version":1,"logs":{"level":"info"}}`, `"level":"info"`, `"Level":"info"`},
		{"log-exporters", `{"schema_version":1,"logs":{"exporters":[]}}`, `"exporters":[]`, `"Exporters":[]`},
		{"metrics", `{"schema_version":1,"metrics":{"exporters":[]}}`, `"metrics":`, `"Metrics":`},
		{"metric-exporters", `{"schema_version":1,"metrics":{"exporters":[]}}`, `"exporters":[]`, `"Exporters":[]`},
		{"traces", `{"schema_version":1,"traces":{"sample_ratio":0}}`, `"traces":`, `"Traces":`},
		{"trace-exporters", `{"schema_version":1,"traces":{"exporters":[]}}`, `"exporters":[]`, `"Exporters":[]`},
		{"sample-ratio", `{"schema_version":1,"traces":{"sample_ratio":0}}`, `"sample_ratio":0`, `"Sample_Ratio":0`},
		{"exporters", `{"schema_version":1,"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"}}}`, `"exporters":`, `"Exporters":`},
		{"exporter-type", `{"schema_version":1,"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"}}}`, `"type":"otlp_file"`, `"Type":"otlp_file"`},
		{"exporter-directory", `{"schema_version":1,"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"}}}`, `"directory":"telemetry"`, `"Directory":"telemetry"`},
		{"exporter-endpoint", `{"schema_version":1,"exporters":{"hosted":{"type":"otlp_http","endpoint":"https://collector.invalid","api_key_env":"ENKV_TEST_KEY"}}}`, `"endpoint":"https://collector.invalid"`, `"Endpoint":"https://collector.invalid"`},
		{"exporter-key", `{"schema_version":1,"exporters":{"hosted":{"type":"otlp_http","endpoint":"https://collector.invalid","api_key_env":"ENKV_TEST_KEY"}}}`, `"api_key_env":"ENKV_TEST_KEY"`, `"API_KEY_ENV":"ENKV_TEST_KEY"`},
		{"exporter-dataset", `{"schema_version":1,"exporters":{"hosted":{"type":"otlp_http","endpoint":"https://collector.invalid","api_key_env":"ENKV_TEST_KEY","dataset":"events"}}}`, `"dataset":"events"`, `"Dataset":"events"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Decode([]byte(test.document), Options{}); err != nil {
				t.Fatal("canonical member refused", err)
			}
			member, alias := test.member, test.alias
			if strings.HasSuffix(member, ":") {
				start := strings.Index(test.document, member) + len(member)
				var value json.RawMessage
				if err := json.NewDecoder(strings.NewReader(test.document[start:])).Decode(&value); err != nil {
					t.Fatal("section fixture", err)
				}
				member += string(value)
				alias += string(value)
			}
			for _, variant := range []struct{ name, replacement string }{
				{"alias-only", alias}, {"canonical-first", member + "," + alias}, {"alias-first", alias + "," + member},
			} {
				t.Run(variant.name, func(t *testing.T) {
					document := strings.Replace(test.document, member, variant.replacement, 1)
					if !json.Valid([]byte(document)) {
						t.Fatal("alias fixture is not JSON")
					}
					if _, err := Decode([]byte(document), Options{}); err != errConfiguration {
						t.Error("noncanonical member accepted or unsafe refusal", err)
					}
				})
			}
		})
	}
	settings, err := Decode([]byte(`{"schema_version":1,"resource":{"attributes":{"name":"lower","Name":"upper","Attributes":"literal"}}}`), Options{})
	if err != nil || settings.Resource["name"] != "lower" || settings.Resource["Name"] != "upper" || settings.Resource["Attributes"] != "literal" {
		t.Fatal("resource map keys lost their exact meaning", err)
	}
}

// full_only: false
func TestOnlyEffectiveLogLevelIsValidated(t *testing.T) {
	for _, test := range []struct {
		name, configured string
		options          Options
		want             Severity
		refused          bool
	}{
		{"invalid_configuration", "invalid", Options{}, Off, true},
		{"empty_configuration", "", Options{}, Off, true},
		{"invalid_environment", "info", Options{EnvLogLevel: "invalid"}, Off, true},
		{"invalid_command", "info", Options{EnvLogLevel: "debug", LogLevel: "invalid"}, Off, true},
		{"environment_shadows_invalid_configuration", "invalid", Options{EnvLogLevel: "debug"}, Debug, false},
		{"command_shadows_invalid_configuration", "invalid", Options{LogLevel: "error"}, Error, false},
		{"command_shadows_both", "invalid", Options{EnvLogLevel: "invalid", LogLevel: "off"}, Off, false},
		{"environment_shadows_empty_configuration", "", Options{EnvLogLevel: "debug"}, Debug, false},
		{"command_shadows_empty_configuration", "", Options{LogLevel: "error"}, Error, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			document := `{"schema_version":1,"logs":{"level":"` + test.configured + `"}}`
			settings, err := Decode([]byte(document), test.options)
			if test.refused {
				if err == nil {
					t.Fatal("invalid effective level was accepted")
				}
				return
			}
			if err != nil || settings.LogLevel != test.want || !settings.Console || len(settings.ActiveExporters) != 0 || len(settings.LogExporters) != 0 || len(settings.MetricExporters) != 0 || len(settings.TraceExporters) != 0 {
				t.Fatal("shadowed level changed effective settings or activated export", settings, err)
			}
		})
	}
	for _, document := range []string{
		`{"schema_version":2,"logs":{"level":"invalid"}}`,
		`{"schema_version":1,"logs":{"level":"invalid","exporters":["missing"]}}`,
		`{"schema_version":1,"logs":{"level":"invalid"},"resource":{"attributes":{"service.name":false}}}`,
		`{"schema_version":1,"logs":{"level":"invalid"},"exporters":{"unused":{"type":"unknown"}}}`,
	} {
		if _, err := Decode([]byte(document), Options{LogLevel: "warn"}); err == nil {
			t.Fatal("log-level override relaxed unrelated configuration validation")
		}
	}
}

// full_only: false
func TestResourceCountAndArrayBoundaries(t *testing.T) {
	attributes := map[string]any{"service.name": "enkv"}
	for i := 0; i < 63; i++ {
		attributes["field_"+strconv.Itoa(i)] = "safe"
	}
	config := Config{SchemaVersion: 1, Resource: ResourceConfig{Attributes: attributes}}
	settings, err := Resolve(config, Options{})
	if err != nil || len(settings.Resource) != 64 || settings.Validate() != nil {
		t.Fatal("exact resource count refused", err)
	}
	attributes["first_excess"] = "safe"
	if _, err := Resolve(config, Options{}); err == nil {
		t.Fatal("first excess resource attribute admitted")
	}
	settings.Resource["first_excess"] = "safe"
	if settings.Validate() == nil {
		t.Fatal("resolved resource count was not rechecked")
	}
	for _, count := range []int{16, 17} {
		values := make([]any, count)
		for i := range values {
			values[i] = "safe"
		}
		config.Resource.Attributes = map[string]any{"array": values}
		settings, err := Resolve(config, Options{})
		if (err == nil) != (count == 16) {
			t.Fatalf("resource array length %d: %v", count, err)
		}
		if err == nil && len(settings.Resource["array"].([]any)) != count {
			t.Fatal("resource array truncated")
		}
	}
}

package observability

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"enkv.sh/telemetry"
)

const (
	configurationSchemaVersion        = 1
	maximumResourceAttributes         = 64
	maximumScopeVersionLength         = 256
	maximumResolvedExportersPerSignal = 2
	maximumInputDestinationsPerSignal = 3 // Includes the console route for logs.
	maximumDestinationNameLength      = 64
	maximumResourceKeyLength          = 256
	maximumResourceValueLength        = 1024
	maximumResourceArrayItems         = 16
	maximumConfigurationDepth         = 16
)

const maxConfigurationBytes = 64 << 10

type Severity int

const (
	Off   Severity = 0
	Trace Severity = Severity(telemetry.SeverityTrace)
	Debug Severity = Severity(telemetry.SeverityDebug)
	Info  Severity = Severity(telemetry.SeverityInfo)
	Warn  Severity = Severity(telemetry.SeverityWarn)
	Error Severity = Severity(telemetry.SeverityError)
	Fatal Severity = Severity(telemetry.SeverityFatal)
)

func parseSeverity(value string) (Severity, bool) {
	switch strings.ToLower(value) {
	case "off":
		return Off, true
	case "trace", "1":
		return Trace, true
	case "debug", "5":
		return Debug, true
	case "info", "9":
		return Info, true
	case "warn", "13":
		return Warn, true
	case "error", "17":
		return Error, true
	case "fatal", "21":
		return Fatal, true
	}
	return 0, false
}

type Config struct {
	SchemaVersion int                 `json:"schema_version"`
	Resource      ResourceConfig      `json:"resource,omitempty"`
	Scopes        map[string]Scope    `json:"scopes,omitempty"`
	Logs          LogConfig           `json:"logs,omitempty"`
	Metrics       SignalConfig        `json:"metrics,omitempty"`
	Traces        TraceConfig         `json:"traces,omitempty"`
	Exporters     map[string]Exporter `json:"exporters,omitempty"`
}

type ResourceConfig struct {
	Attributes map[string]any `json:"attributes,omitempty"`
}

type Scope struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type LogConfig struct {
	Level     *string   `json:"level,omitempty"`
	Exporters *[]string `json:"exporters,omitempty"`
}

type SignalConfig struct {
	Exporters *[]string `json:"exporters,omitempty"`
}

type TraceConfig struct {
	Exporters   *[]string `json:"exporters,omitempty"`
	SampleRatio *float64  `json:"sample_ratio,omitempty"`
}

type Exporter struct {
	Type      string `json:"type"`
	Directory string `json:"directory,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
	APIKeyEnv string `json:"api_key_env,omitempty"`
	Dataset   string `json:"dataset,omitempty"`
}

// Options contains only the selected startup inputs. Workers receive Resolved
// and never read these environment variables again.
type Options struct {
	LogLevel              string
	EnvLogLevel           string
	EnvServiceName        string
	EnvResourceAttributes string
}

func EnvironmentOptions(logLevel string) Options {
	return Options{
		LogLevel: logLevel, EnvLogLevel: os.Getenv("ENKV_LOG_LEVEL"),
		EnvServiceName: os.Getenv("OTEL_SERVICE_NAME"), EnvResourceAttributes: os.Getenv("OTEL_RESOURCE_ATTRIBUTES"),
	}
}

type Resolved struct {
	LogLevel         Severity            `json:"log_level"`
	Console          bool                `json:"console"`
	LogExporters     []string            `json:"log_exporters,omitempty"`
	MetricExporters  []string            `json:"metric_exporters,omitempty"`
	TraceExporters   []string            `json:"trace_exporters,omitempty"`
	TraceSampleRatio float64             `json:"trace_sample_ratio"`
	Resource         map[string]any      `json:"resource"`
	Scopes           map[string]Scope    `json:"scopes"`
	ActiveExporters  map[string]Exporter `json:"active_exporters,omitempty"`
}

func (settings Resolved) Validate() error {
	if settings.LogLevel != Off && settings.LogLevel != Trace && settings.LogLevel != Debug && settings.LogLevel != Info && settings.LogLevel != Warn && settings.LogLevel != Error && settings.LogLevel != Fatal ||
		math.IsNaN(settings.TraceSampleRatio) || settings.TraceSampleRatio < 0 || settings.TraceSampleRatio > 1 || len(settings.Resource) == 0 || len(settings.Resource) > maximumResourceAttributes {
		return errConfiguration
	}
	for key, value := range settings.Resource {
		if !validResourceKey(key) {
			return errConfiguration
		}
		if _, ok := resourceValue(value); !ok {
			return errConfiguration
		}
	}
	service, ok := settings.Resource["service.name"].(string)
	if !ok || service == "" {
		return errConfiguration
	}
	defaults := defaultScopes()
	if len(settings.Scopes) != len(defaults) {
		return errConfiguration
	}
	for component, scope := range settings.Scopes {
		if _, known := defaults[component]; !known || scope.Name == "" || !validResourceString(scope.Name) || len(scope.Version) > maximumScopeVersionLength || !utf8.ValidString(scope.Version) || hasControl(scope.Version) {
			return errConfiguration
		}
	}
	for name, exporter := range settings.ActiveExporters {
		if !validDestinationName(name) || !validExporter(exporter) {
			return errConfiguration
		}
	}
	used := map[string]bool{}
	for _, routes := range [][]string{settings.LogExporters, settings.MetricExporters, settings.TraceExporters} {
		if len(routes) > maximumResolvedExportersPerSignal {
			return errConfiguration
		}
		seen := map[string]bool{}
		for _, name := range routes {
			if seen[name] || name == "console" || settings.ActiveExporters[name].Type == "" {
				return errConfiguration
			}
			seen[name], used[name] = true, true
		}
	}
	if len(used) != len(settings.ActiveExporters) {
		return errConfiguration
	}
	file, remote := 0, 0
	for _, exporter := range settings.ActiveExporters {
		if exporter.Type == "otlp_file" {
			file++
		} else {
			remote++
		}
	}
	if file > 1 || remote > 1 {
		return errConfiguration
	}
	return nil
}

func (settings Resolved) Clone() Resolved {
	clonedSettings := settings
	clonedSettings.LogExporters = append([]string(nil), settings.LogExporters...)
	clonedSettings.MetricExporters = append([]string(nil), settings.MetricExporters...)
	clonedSettings.TraceExporters = append([]string(nil), settings.TraceExporters...)
	clonedSettings.Resource = make(map[string]any, len(settings.Resource))
	for key, value := range settings.Resource {
		if list, ok := value.([]any); ok {
			clonedSettings.Resource[key] = append([]any(nil), list...)
		} else {
			clonedSettings.Resource[key] = value
		}
	}
	clonedSettings.Scopes = make(map[string]Scope, len(settings.Scopes))
	for key, value := range settings.Scopes {
		clonedSettings.Scopes[key] = value
	}
	clonedSettings.ActiveExporters = make(map[string]Exporter, len(settings.ActiveExporters))
	for key, value := range settings.ActiveExporters {
		clonedSettings.ActiveExporters[key] = value
	}
	return clonedSettings
}

var errConfiguration = errors.New("telemetry configuration refused")
var environmentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func Load(path string, options Options) (Resolved, error) {
	if path == "" {
		return Resolve(Config{SchemaVersion: configurationSchemaVersion}, options)
	}
	file, err := os.Open(path)
	if err != nil {
		return Resolved{}, errConfiguration
	}
	data, err := io.ReadAll(io.LimitReader(file, maxConfigurationBytes+1))
	closeErr := file.Close()
	if err != nil || closeErr != nil || len(data) == 0 || len(data) > maxConfigurationBytes {
		return Resolved{}, errConfiguration
	}
	return Decode(data, options)
}

func Decode(data []byte, options Options) (Resolved, error) {
	if len(data) == 0 {
		return Resolve(Config{SchemaVersion: configurationSchemaVersion}, options)
	}
	if len(data) > maxConfigurationBytes || uniqueKeys(json.NewDecoder(bytes.NewReader(data)), 0, reflect.TypeFor[Config]()) != nil {
		return Resolved{}, errConfiguration
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	var config Config
	if decoder.Decode(&config) != nil || decoder.Decode(new(any)) != io.EOF {
		return Resolved{}, errConfiguration
	}
	return Resolve(config, options)
}

// Resolve copies typed configuration into invocation-owned settings.
func Resolve(config Config, options Options) (Resolved, error) {
	if reflect.DeepEqual(config, Config{}) {
		config.SchemaVersion = configurationSchemaVersion
	}
	if config.SchemaVersion != configurationSchemaVersion {
		return Resolved{}, errConfiguration
	}
	selectedLevel := "warn"
	if config.Logs.Level != nil {
		selectedLevel = *config.Logs.Level
	}
	if options.EnvLogLevel != "" {
		selectedLevel = options.EnvLogLevel
	}
	if options.LogLevel != "" {
		selectedLevel = options.LogLevel
	}
	level, valid := parseSeverity(selectedLevel)
	if !valid {
		return Resolved{}, errConfiguration
	}
	resolved := Resolved{LogLevel: level, TraceSampleRatio: 1, Resource: map[string]any{"service.name": "enkv"}, Scopes: defaultScopes(), ActiveExporters: map[string]Exporter{}}
	if options.EnvResourceAttributes != "" {
		for _, part := range strings.Split(options.EnvResourceAttributes, ",") {
			key, value, ok := strings.Cut(part, "=")
			if !ok {
				return Resolved{}, errConfiguration
			}
			key, err := url.PathUnescape(key)
			if err != nil {
				return Resolved{}, errConfiguration
			}
			value, err = url.PathUnescape(value)
			if err != nil || !validResourceKey(key) || !validResourceString(value) {
				return Resolved{}, errConfiguration
			}
			resolved.Resource[key] = value
		}
	}
	if options.EnvServiceName != "" {
		if !validResourceString(options.EnvServiceName) {
			return Resolved{}, errConfiguration
		}
		resolved.Resource["service.name"] = options.EnvServiceName
	}
	for key, value := range config.Resource.Attributes {
		if !validResourceKey(key) {
			return Resolved{}, errConfiguration
		}
		copied, ok := resourceValue(value)
		if !ok {
			return Resolved{}, errConfiguration
		}
		resolved.Resource[key] = copied
	}
	if len(resolved.Resource) > maximumResourceAttributes {
		return Resolved{}, errConfiguration
	}
	service, ok := resolved.Resource["service.name"].(string)
	if !ok || service == "" {
		return Resolved{}, errConfiguration
	}
	for component, scope := range config.Scopes {
		if _, known := resolved.Scopes[component]; !known || scope.Name == "" || !validResourceString(scope.Name) || len(scope.Version) > maximumScopeVersionLength || !utf8.ValidString(scope.Version) || hasControl(scope.Version) {
			return Resolved{}, errConfiguration
		}
		resolved.Scopes[component] = scope
	}
	if config.Traces.SampleRatio != nil {
		if math.IsNaN(*config.Traces.SampleRatio) || *config.Traces.SampleRatio < 0 || *config.Traces.SampleRatio > 1 {
			return Resolved{}, errConfiguration
		}
		resolved.TraceSampleRatio = *config.Traces.SampleRatio
	}
	for name, exporter := range config.Exporters {
		if name == "console" || !validDestinationName(name) || !validExporter(exporter) {
			return Resolved{}, errConfiguration
		}
	}
	logs := []string{"console"}
	if config.Logs.Exporters != nil {
		logs = *config.Logs.Exporters
	}
	metrics := []string{}
	if config.Metrics.Exporters != nil {
		metrics = *config.Metrics.Exporters
	}
	traces := []string{}
	if config.Traces.Exporters != nil {
		traces = *config.Traces.Exporters
	}
	for signal, routes := range map[string][]string{"logs": logs, "metrics": metrics, "traces": traces} {
		if len(routes) > maximumInputDestinationsPerSignal {
			return Resolved{}, errConfiguration
		}
		seen := map[string]bool{}
		for _, name := range routes {
			if seen[name] || name == "console" && signal != "logs" {
				return Resolved{}, errConfiguration
			}
			seen[name] = true
			if name == "console" {
				resolved.Console = true
				continue
			}
			exporter, found := config.Exporters[name]
			if !found {
				return Resolved{}, errConfiguration
			}
			if exporter.Type == "otlp_http" {
				normalized, ok := normalizeRemoteEndpoint(exporter.Endpoint)
				if !ok {
					return Resolved{}, errConfiguration
				}
				exporter.Endpoint = normalized
			}
			resolved.ActiveExporters[name] = exporter
			switch signal {
			case "logs":
				resolved.LogExporters = append(resolved.LogExporters, name)
			case "metrics":
				resolved.MetricExporters = append(resolved.MetricExporters, name)
			case "traces":
				resolved.TraceExporters = append(resolved.TraceExporters, name)
			}
		}
	}
	file, remote := 0, 0
	for _, exporter := range resolved.ActiveExporters {
		if exporter.Type == "otlp_file" {
			file++
		} else {
			remote++
		}
	}
	if file > 1 || remote > 1 {
		return Resolved{}, errConfiguration
	}
	resolved.LogExporters = append([]string(nil), resolved.LogExporters...)
	resolved.MetricExporters = append([]string(nil), resolved.MetricExporters...)
	resolved.TraceExporters = append([]string(nil), resolved.TraceExporters...)
	if resolved.Validate() != nil {
		return Resolved{}, errConfiguration
	}
	return resolved, nil
}

func validDestinationName(name string) bool {
	if len(name) == 0 || len(name) > maximumDestinationNameLength {
		return false
	}
	for _, r := range name {
		if r != '-' && r != '_' && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func defaultScopes() map[string]Scope {
	const prefix = "enkv.sh/"
	return map[string]Scope{
		"core": {Name: prefix + "core"}, "crypto": {Name: prefix + "crypto"},
		"aws": {Name: prefix + "providers/aws"}, "gcp": {Name: prefix + "providers/gcp"},
		"generatorhost": {Name: prefix + "compositions/generatorhost"},
		"outputhost":    {Name: prefix + "compositions/outputhost"},
		"manifesthost":  {Name: prefix + "compositions/manifesthost"},
		"application":   {Name: prefix + "tests/examples/telemetry"},
		"worker":        {Name: prefix + "tests/shared/records"},
	}
}

func validExporter(exporter Exporter) bool {
	switch exporter.Type {
	case "otlp_file":
		return exporter.Endpoint == "" && exporter.APIKeyEnv == "" && exporter.Dataset == "" && validDirectory(exporter.Directory)
	case "otlp_http":
		_, valid := normalizeRemoteEndpoint(exporter.Endpoint)
		return valid && exporter.Directory == "" && environmentName.MatchString(exporter.APIKeyEnv) && (exporter.Dataset == "" || validRemoteHeaderValue(exporter.Dataset, maximumDatasetHeaderLength))
	}
	return false
}

// Normalize the admitted base once. Exporters and the egress guard consume
// this exact host/path spelling rather than normalizing it independently.
func normalizeRemoteEndpoint(value string) (string, bool) {
	endpoint, err := url.Parse(value)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" && endpoint.Path != "/" {
		return "", false
	}
	// net/http removes an empty port when it constructs a request.
	endpoint.Host = strings.TrimSuffix(endpoint.Host, ":")
	endpoint.Path = ""
	endpoint.RawPath = ""
	endpoint.ForceQuery = false
	endpoint.RawFragment = ""
	return endpoint.String(), true
}

func validDirectory(directory string) bool {
	if directory == "" || filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == "." || strings.Contains(directory, "\\") || hasControl(directory) {
		return false
	}
	for _, segment := range strings.Split(directory, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func validResourceKey(key string) bool {
	return key != "" && len(key) <= maximumResourceKeyLength && utf8.ValidString(key) && !strings.ContainsAny(key, "=,") && !hasControl(key)
}

func validResourceString(value string) bool {
	return len(value) <= maximumResourceValueLength && utf8.ValidString(value) && !hasControl(value)
}

func ambientTLSFilesAbsent(signal string) bool {
	// The pinned metric/trace constructors read these files before applying
	// the owned HTTP client, including when the destination is a local file.
	for _, prefix := range []string{"OTEL_EXPORTER_OTLP_", "OTEL_EXPORTER_OTLP_" + signal + "_"} {
		for _, suffix := range []string{"CERTIFICATE", "CLIENT_CERTIFICATE", "CLIENT_KEY"} {
			if os.Getenv(prefix+suffix) != "" {
				return false
			}
		}
	}
	return true
}

func hasControl(value string) bool {
	for _, r := range value {
		if r < ' ' || r == 0x7f {
			return true
		}
	}
	return false
}

func resourceValue(value any) (any, bool) {
	switch v := value.(type) {
	case string:
		return v, validResourceString(v)
	case bool:
		return v, true
	case json.Number:
		if n, err := strconv.ParseInt(string(v), 10, 64); err == nil {
			return n, true
		}
		n, err := strconv.ParseFloat(string(v), 64)
		return n, err == nil && !math.IsInf(n, 0) && !math.IsNaN(n)
	case int:
		return int64(v), true
	case int64:
		return v, true
	case float64:
		return v, !math.IsInf(v, 0) && !math.IsNaN(v)
	case []any:
		if len(v) == 0 || len(v) > maximumResourceArrayItems {
			return nil, false
		}
		clonedValues := make([]any, len(v))
		kind := ""
		for i, item := range v {
			if _, nested := item.([]any); nested {
				return nil, false
			}
			converted, ok := resourceValue(item)
			if !ok {
				return nil, false
			}
			_, nested := converted.([]any)
			if nested {
				return nil, false
			}
			thisKind := "string"
			switch converted.(type) {
			case bool:
				thisKind = "bool"
			case int64:
				thisKind = "int"
			case float64:
				thisKind = "float"
			}
			if kind != "" && kind != thisKind {
				return nil, false
			}
			kind, clonedValues[i] = thisKind, converted
		}
		return clonedValues, true
	}
	return nil, false
}

func uniqueKeys(decoder *json.Decoder, depth int, schema reflect.Type) error {
	if depth > maximumConfigurationDepth {
		return errConfiguration
	}
	token, err := decoder.Token()
	if err != nil || token == nil {
		return errConfiguration
	}
	delimiter, nested := token.(json.Delim)
	if !nested {
		return nil
	}
	for schema != nil && schema.Kind() == reflect.Pointer {
		schema = schema.Elem()
	}
	seen := map[string]bool{}
	for decoder.More() {
		var valueSchema reflect.Type
		if delimiter == '{' {
			key, err := decoder.Token()
			if err != nil {
				return errConfiguration
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errConfiguration
			}
			seen[name] = true
			if schema != nil {
				switch schema.Kind() {
				case reflect.Struct:
					for i := 0; i < schema.NumField(); i++ {
						field := schema.Field(i)
						tag, _, _ := strings.Cut(field.Tag.Get("json"), ",")
						if name == tag {
							valueSchema = field.Type
							break
						}
					}
					if valueSchema == nil {
						return errConfiguration
					}
				case reflect.Map:
					valueSchema = schema.Elem()
				}
			}
		} else if schema != nil && (schema.Kind() == reflect.Array || schema.Kind() == reflect.Slice) {
			valueSchema = schema.Elem()
		}
		if uniqueKeys(decoder, depth+1, valueSchema) != nil {
			return errConfiguration
		}
	}
	if _, err := decoder.Token(); err != nil {
		return errConfiguration
	}
	return nil
}

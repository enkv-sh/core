package observability

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/telemetry"
	"github.com/go-logr/logr"
	"go.opentelemetry.io/otel"
)

type sdkErrorTrap struct{ calls *atomic.Uint64 }

func (trap sdkErrorTrap) Error() string {
	trap.calls.Add(1)
	return "SYNTHETIC_CONFIDENTIAL_SDK_ERROR"
}

type sdkStringerTrap struct{ calls *atomic.Uint64 }

func (trap sdkStringerTrap) String() string {
	trap.calls.Add(1)
	return "SYNTHETIC_CONFIDENTIAL_SDK_VALUE"
}

// full_only: false
func TestSDKDiagnosticsCountWithoutFormattingOrRetainingInput(t *testing.T) {
	installSDKErrorHandler()
	before := sdkCallbackCount.Load()
	var formattingCalls atomic.Uint64
	failure, value := sdkErrorTrap{&formattingCalls}, sdkStringerTrap{&formattingCalls}
	logger := logr.New(sdkLogSink{})
	for _, derived := range []logr.Logger{
		logger,
		logger.WithValues("credential", value),
		logger.WithName("SYNTHETIC_CONFIDENTIAL_SDK_NAME"),
		logger.WithValues("credential", value).WithName("SYNTHETIC_CONFIDENTIAL_SDK_NAME"),
	} {
		if kind := reflect.TypeOf(derived.GetSink()); kind != reflect.TypeFor[sdkLogSink]() || kind.Size() != 0 {
			t.Fatal("SDK diagnostic sink retained derived logger state")
		}
		derived.Info("SYNTHETIC_CONFIDENTIAL_SDK_MESSAGE", "credential", value)
		derived.V(1).Info("SYNTHETIC_CONFIDENTIAL_SDK_MESSAGE", "credential", value)
		derived.V(8).Error(failure, "SYNTHETIC_CONFIDENTIAL_SDK_MESSAGE", "credential", value)
		for _, level := range []int{2, 4, 8} {
			if derived.V(level).Enabled() {
				t.Fatalf("SDK diagnostic verbosity %d is enabled", level)
			}
			derived.V(level).Info("SYNTHETIC_CONFIDENTIAL_SDK_MESSAGE", "credential", value)
		}
	}
	otel.Handle(failure)
	if formattingCalls.Load() != 0 {
		t.Fatal("SDK diagnostic formatted an error or Stringer")
	}
	if got := sdkCallbackCount.Load() - before; got != 13 {
		t.Fatalf("SDK diagnostic count = %d, want 13", got)
	}
}

const sdkDiagnosticChildEnv = "ENKV_TEST_SDK_DIAGNOSTIC_CHILD"

// full_only: false
func TestSDKConstructorDiagnosticsExcludeConfidentialHeaders(t *testing.T) {
	if child := os.Getenv(sdkDiagnosticChildEnv); child != "" {
		runSDKDiagnosticChild(t, child)
		return
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	const secret = "SYNTHETIC_CONFIDENTIAL_SDK_HEADER"
	secrets := []string{secret, hex.EncodeToString([]byte(secret)), base64.StdEncoding.EncodeToString([]byte(secret))}
	headers := "authorization=Bearer%ZZ" + secrets[0] + ",x-api-key=%ZZ" + secrets[1] + ",x-honeycomb-team=%ZZ" + secrets[2]
	for _, destination := range []string{"file", "http"} {
		for _, signal := range []string{"metrics", "traces", "logs"} {
			variables := []string{"OTEL_EXPORTER_OTLP_HEADERS", "OTEL_EXPORTER_OTLP_" + strings.ToUpper(signal) + "_HEADERS"}
			if signal == "logs" {
				variables = append(variables, "")
			}
			for _, variable := range variables {
				name := variable
				if name == "" {
					name = "no-headers"
				}
				t.Run(destination+"/"+signal+"/"+name, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()
					command := exec.CommandContext(ctx, executable, "-test.run=^TestSDKConstructorDiagnosticsExcludeConfidentialHeaders$", "-test.count=1")
					for _, entry := range os.Environ() {
						if !strings.HasPrefix(entry, "OTEL_") && !strings.HasPrefix(entry, "ENKV_LOG_LEVEL=") && !strings.HasPrefix(entry, sdkDiagnosticChildEnv+"=") && !strings.HasPrefix(entry, "ENKV_SDK_TEST_KEY=") {
							command.Env = append(command.Env, entry)
						}
					}
					command.Env = append(command.Env, sdkDiagnosticChildEnv+"="+destination+"/"+signal, "ENKV_SDK_TEST_KEY=synthetic-transport-key")
					if variable != "" {
						command.Env = append(command.Env, variable+"="+headers)
					}
					var stdout, stderr bytes.Buffer
					command.Stdout, command.Stderr = &stdout, &stderr
					runErr := command.Run()
					for _, excluded := range secrets {
						if bytes.Contains(stdout.Bytes(), []byte(excluded)) || bytes.Contains(stderr.Bytes(), []byte(excluded)) {
							t.Fatal("SDK constructor disclosed a confidential header")
						}
					}
					if runErr != nil {
						t.Fatalf("SDK constructor child failed: %v", runErr)
					}
					var callbacks uint64
					for _, line := range strings.Split(stdout.String(), "\n") {
						if value, ok := strings.CutPrefix(line, "sdk_callback_count="); ok {
							callbacks, err = strconv.ParseUint(value, 10, 64)
							if err != nil {
								t.Fatal("SDK constructor child returned an invalid callback count")
							}
						}
					}
					if callbacks == 0 {
						t.Fatal("SDK constructor did not exercise a diagnostic callback")
					}
				})
			}
		}
	}
}

func runSDKDiagnosticChild(t *testing.T, child string) {
	t.Helper()
	destination, signal, ok := strings.Cut(child, "/")
	if !ok {
		t.Fatal("invalid SDK constructor child selection")
	}
	level := "off"
	routes, noRoutes := []string{"selected"}, []string{}
	config := Config{SchemaVersion: 1, Logs: LogConfig{Level: &level, Exporters: &noRoutes}}
	options := SetupOptions{BaseDirectory: t.TempDir()}
	switch destination {
	case "file":
		config.Exporters = map[string]Exporter{"selected": {Type: "otlp_file", Directory: "telemetry"}}
	case "http":
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "application/x-protobuf")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()
		config.Exporters = map[string]Exporter{"selected": {Type: "otlp_http", Endpoint: server.URL, APIKeyEnv: "ENKV_SDK_TEST_KEY"}}
		options.remoteBase = server.Client().Transport
	default:
		t.Fatal("invalid SDK constructor destination")
	}
	expectedCallbacks := uint64(3)
	switch signal {
	case "metrics":
		config.Metrics.Exporters = &routes
	case "traces":
		config.Traces.Exporters = &routes
	case "logs":
		level = "warn"
		config.Logs.Exporters = &routes
		// SDK v0.12.1 Record.AddAttributes warns once through setDropped(0),
		// even without loss. The no-headers child establishes that baseline.
		expectedCallbacks = 1
		if os.Getenv("OTEL_EXPORTER_OTLP_HEADERS") != "" || os.Getenv("OTEL_EXPORTER_OTLP_LOGS_HEADERS") != "" {
			expectedCallbacks++
		}
	default:
		t.Fatal("invalid SDK constructor signal")
	}
	settings, err := Resolve(config, Options{})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := Start(settings, options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	t.Cleanup(func() { _ = runtime.Close(ctx) })
	if signal != "logs" && runtime.LogsEnabled() {
		t.Fatal("SDK constructor check enabled application logs")
	}
	if err := runtime.AwaitMetrics(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runtime.AwaitTraces(ctx); err != nil {
		t.Fatal(err)
	}
	telemetry.Start(runtime.Context(ctx), telemetry.ProviderCore, telemetry.OpCoreOpen).Finish(telemetry.ResultAdmissionRefused)
	if err := runtime.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if status := runtime.DeliveryStatuses()[signal+".selected"]; status.Written == 0 || status.Incomplete {
		t.Fatalf("SDK constructor changed normal delivery: %+v", status)
	}
	if got := runtime.SDKCallbackCount(); got != expectedCallbacks {
		t.Fatalf("SDK constructor callback count = %d, want %d", got, expectedCallbacks)
	}
	if destination == "file" {
		data, err := os.ReadFile(filepath.Join(options.BaseDirectory, "telemetry", signal+".jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		const secret = "SYNTHETIC_CONFIDENTIAL_SDK_HEADER"
		for _, excluded := range []string{secret, hex.EncodeToString([]byte(secret)), base64.StdEncoding.EncodeToString([]byte(secret))} {
			if bytes.Contains(data, []byte(excluded)) {
				t.Fatal("SDK constructor copied a confidential header into file output")
			}
		}
	}
	if _, err := fmt.Fprintf(os.Stdout, "sdk_callback_count=%d\n", runtime.SDKCallbackCount()); err != nil {
		t.Fatal(err)
	}
}

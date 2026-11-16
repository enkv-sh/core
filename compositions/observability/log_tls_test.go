package observability

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enkv.sh/telemetry"
	"golang.org/x/sys/unix"
)

const logTLSChildEnv = "ENKV_TEST_LOG_TLS_CHILD"

// full_only: false
func TestMetricAndTraceStartupRefusesAmbientTLSFiles(t *testing.T) {
	const childEnv = "ENKV_TEST_METRIC_TRACE_TLS_CHILD"
	if selected := os.Getenv(childEnv); selected != "" {
		runMetricTraceTLSChild(t, selected)
		return
	}
	for _, signal := range []string{"metrics", "traces"} {
		for _, destination := range []string{"file", "http"} {
			for _, suffix := range []string{"CERTIFICATE", "CLIENT_CERTIFICATE", "CLIENT_KEY", strings.ToUpper(signal) + "_CERTIFICATE", strings.ToUpper(signal) + "_CLIENT_CERTIFICATE", strings.ToUpper(signal) + "_CLIENT_KEY"} {
				for _, kind := range []string{"fifo", "oversized"} {
					t.Run(signal+"/"+destination+"/"+suffix+"/"+kind, func(t *testing.T) {
						root := t.TempDir()
						path, companion := filepath.Join(root, "unused-tls"), filepath.Join(root, "companion")
						if err := os.WriteFile(companion, []byte("synthetic-invalid-certificate"), 0600); err != nil {
							t.Fatal(err)
						}
						if kind == "fifo" {
							if err := unix.Mkfifo(path, 0600); err != nil {
								t.Fatal(err)
							}
						} else if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, (1<<20)+1), 0600); err != nil {
							t.Fatal(err)
						}
						ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
						defer cancel()
						command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMetricAndTraceStartupRefusesAmbientTLSFiles$", "-test.count=1")
						command.WaitDelay = time.Second
						for _, entry := range os.Environ() {
							if !strings.HasPrefix(entry, "OTEL_") && !strings.HasPrefix(entry, childEnv+"=") && !strings.HasPrefix(entry, "ENKV_METRIC_TRACE_TLS_KEY=") {
								command.Env = append(command.Env, entry)
							}
						}
						command.Env = append(command.Env, childEnv+"="+signal+"/"+destination, "ENKV_METRIC_TRACE_TLS_KEY=synthetic-key", "OTEL_EXPORTER_OTLP_"+suffix+"="+path)
						if suffix == "CERTIFICATE" {
							command.Env = append(command.Env, "OTEL_EXPORTER_OTLP_"+strings.ToUpper(signal)+"_CERTIFICATE="+companion)
						}
						if strings.HasSuffix(suffix, "CLIENT_CERTIFICATE") {
							command.Env = append(command.Env, "OTEL_EXPORTER_OTLP_"+strings.TrimSuffix(suffix, "CERTIFICATE")+"KEY="+companion)
						} else if strings.HasSuffix(suffix, "CLIENT_KEY") {
							command.Env = append(command.Env, "OTEL_EXPORTER_OTLP_"+strings.TrimSuffix(suffix, "KEY")+"CERTIFICATE="+companion)
						}
						var output bytes.Buffer
						command.Stdout, command.Stderr = &output, &output
						if err := command.Start(); err != nil {
							t.Fatal("TLS admission child did not start", err)
						}
						done := make(chan error, 1)
						go func() { done <- command.Wait() }()
						ticker := time.NewTicker(10 * time.Millisecond)
						defer ticker.Stop()
						acquired := false
						var runErr error
					wait:
						for {
							select {
							case runErr = <-done:
								break wait
							case <-ticker.C:
								if kind != "fifo" {
									continue
								}
								fd, err := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK, 0)
								if err == nil {
									acquired = true
									if err := unix.Close(fd); err != nil {
										t.Error("FIFO release failed", err)
									}
								} else if err != unix.ENXIO {
									t.Error("FIFO observation failed", err)
								}
							}
						}
						if acquired {
							t.Error("exporter construction acquired an unsupported ambient TLS file")
						}
						if runErr != nil || !bytes.Contains(output.Bytes(), []byte("ambient_tls_refused")) {
							t.Errorf("startup did not safely refuse: terminal=%v refused=%t", runErr, bytes.Contains(output.Bytes(), []byte("ambient_tls_refused")))
						}
					})
				}
			}
		}
	}
}

func runMetricTraceTLSChild(t *testing.T, selected string) {
	t.Helper()
	signal, destination, ok := strings.Cut(selected, "/")
	if !ok || signal != "metrics" && signal != "traces" || destination != "file" && destination != "http" {
		t.Fatal("invalid TLS child selection")
	}
	level, routes := "off", []string{"capture"}
	config := Config{SchemaVersion: 1, Logs: LogConfig{Level: &level}, Exporters: map[string]Exporter{"capture": {Type: "otlp_file", Directory: "telemetry"}}}
	if signal == "metrics" {
		config.Metrics.Exporters = &routes
	} else {
		config.Traces.Exporters = &routes
	}
	if destination == "http" {
		config.Exporters["capture"] = Exporter{Type: "otlp_http", Endpoint: "https://collector.invalid", APIKeyEnv: "ENKV_METRIC_TRACE_TLS_KEY"}
	}
	settings, err := Resolve(config, Options{})
	if err != nil {
		t.Fatal("TLS child settings refused", err)
	}
	runtime, err := Start(settings, SetupOptions{BaseDirectory: t.TempDir(), Console: io.Discard})
	if err == errConfiguration && runtime == nil {
		fmt.Println("ambient_tls_refused")
		return
	}
	if runtime != nil {
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		if signal == "metrics" {
			if err := runtime.AwaitMetrics(ctx); err != nil {
				t.Error("unexpected metric initialization did not settle")
			}
		} else {
			if err := runtime.AwaitTraces(ctx); err != nil {
				t.Error("unexpected trace initialization did not settle")
			}
		}
		if err := runtime.Close(ctx); err != nil {
			t.Error("unexpected runtime did not close cleanly")
		}
	}
	t.Fatal("unsupported ambient TLS setting was admitted")
}

// full_only: false
func TestMetricAndTraceConstructorsRecheckAmbientTLSFiles(t *testing.T) {
	t.Setenv("ENKV_METRIC_TRACE_TLS_KEY", "synthetic-key")
	for _, signal := range []string{"metrics", "traces"} {
		for _, destination := range []string{"file", "http"} {
			t.Run(signal+"/"+destination, func(t *testing.T) {
				routes := []string{"capture"}
				exporter := Exporter{Type: "otlp_file", Directory: "telemetry"}
				if destination == "http" {
					exporter = Exporter{Type: "otlp_http", Endpoint: "https://collector.invalid", APIKeyEnv: "ENKV_METRIC_TRACE_TLS_KEY"}
				}
				config := Config{SchemaVersion: 1, Exporters: map[string]Exporter{"capture": exporter}}
				if signal == "metrics" {
					config.Metrics.Exporters = &routes
				} else {
					config.Traces.Exporters = &routes
				}
				settings, err := Resolve(config, Options{})
				if err != nil {
					t.Fatal("constructor fixture", err)
				}
				path := filepath.Join(t.TempDir(), "unused-certificate")
				if err := os.WriteFile(path, []byte("synthetic-invalid-certificate"), 0600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("OTEL_EXPORTER_OTLP_CERTIFICATE", path)
				runtime := &Runtime{settings: settings, baseDirectory: t.TempDir(), metricStatus: map[string]*deliveryCounter{"capture": new(deliveryCounter)}}
				runtime.remote = newRemoteTransport(settings, roundTripFunc(func(*http.Request) (*http.Response, error) {
					return nil, errRemoteDelivery
				}))
				ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
				defer cancel()
				if signal == "metrics" {
					readers := runtime.metricReaders()
					for _, reader := range readers {
						if err := reader.Shutdown(ctx); err != nil {
							t.Error("unexpected reader did not shut down")
						}
					}
					if len(readers) != 0 || runtime.metricStatus["capture"].snapshot().Failed != 1 {
						t.Error("metric constructor admitted an ambient TLS file")
					}
					return
				}
				factories := []traceExporterFactory{runtime.traceExporter}
				if destination == "file" {
					factories = append(factories, fileTraceExporter)
				}
				for _, factory := range factories {
					transport := newFileTransport(runtime.baseDirectory, "telemetry", "traces")
					underlying, err := factory(ctx, exporter, transport)
					if underlying != nil {
						if closeErr := underlying.Shutdown(ctx); closeErr != nil {
							t.Error("unexpected exporter did not shut down")
						}
					}
					if underlying != nil || err != errConfiguration {
						t.Error("trace constructor admitted an ambient TLS file or unsafe refusal", err)
					}
				}
			})
		}
	}
}

// full_only: false
func TestAmbientTLSFilesDoNotChangeUnselectedSignals(t *testing.T) {
	for _, selected := range []string{"none", "metrics", "traces"} {
		t.Run(selected, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "unused-certificate")
			if err := os.WriteFile(path, []byte("synthetic-invalid-certificate"), 0600); err != nil {
				t.Fatal(err)
			}
			for _, signal := range []string{"", "METRICS_", "TRACES_"} {
				for _, suffix := range []string{"CERTIFICATE", "CLIENT_CERTIFICATE", "CLIENT_KEY"} {
					value := ""
					if selected == "none" || signal != "" && signal != strings.ToUpper(selected)+"_" {
						value = path
					}
					t.Setenv("OTEL_EXPORTER_OTLP_"+signal+suffix, value)
				}
			}
			routes := []string{"capture"}
			config := Config{SchemaVersion: 1}
			if selected != "none" {
				config.Exporters = map[string]Exporter{"capture": {Type: "otlp_file", Directory: "telemetry"}}
				if selected == "metrics" {
					config.Metrics.Exporters = &routes
				} else {
					config.Traces.Exporters = &routes
				}
			}
			settings, err := Resolve(config, Options{})
			if err != nil {
				t.Fatal("unselected signal fixture", err)
			}
			runtime, err := Start(settings, SetupOptions{BaseDirectory: t.TempDir(), Console: io.Discard})
			if err != nil {
				t.Fatal("unselected ambient TLS setting changed startup", err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			if err := runtime.AwaitMetrics(ctx); err != nil {
				t.Error("metric initialization did not settle", err)
			}
			if err := runtime.AwaitTraces(ctx); err != nil {
				t.Error("trace initialization did not settle", err)
			}
			if err := runtime.Close(ctx); err != nil {
				t.Error("unselected ambient setting changed close", err)
			}
		})
	}
}

// full_only: false
func TestMetricAndTraceStartupRefusesSingleTLSClientSetting(t *testing.T) {
	for _, signal := range []string{"metrics", "traces"} {
		for _, prefix := range []string{"", strings.ToUpper(signal) + "_"} {
			for _, suffix := range []string{"CLIENT_CERTIFICATE", "CLIENT_KEY"} {
				t.Run(signal+"/"+prefix+suffix, func(t *testing.T) {
					for _, scope := range []string{"", "METRICS_", "TRACES_"} {
						for _, part := range []string{"CERTIFICATE", "CLIENT_CERTIFICATE", "CLIENT_KEY"} {
							t.Setenv("OTEL_EXPORTER_OTLP_"+scope+part, "")
						}
					}
					t.Setenv("OTEL_EXPORTER_OTLP_"+prefix+suffix, filepath.Join(t.TempDir(), "unused"))
					routes := []string{"capture"}
					config := Config{SchemaVersion: 1, Exporters: map[string]Exporter{"capture": {Type: "otlp_file", Directory: "telemetry"}}}
					if signal == "metrics" {
						config.Metrics.Exporters = &routes
					} else {
						config.Traces.Exporters = &routes
					}
					settings, err := Resolve(config, Options{})
					if err != nil {
						t.Fatal("single client setting fixture", err)
					}
					runtime, err := Start(settings, SetupOptions{BaseDirectory: t.TempDir(), Console: io.Discard})
					if runtime != nil {
						ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
						defer cancel()
						if closeErr := runtime.Close(ctx); closeErr != nil {
							t.Error("unexpected runtime did not shut down")
						}
					}
					if runtime != nil || err != errConfiguration {
						t.Error("unsupported lone client setting admitted or unsafe refusal", err)
					}
				})
			}
		}
	}
}

// full_only: false
func TestSuppliedLogClientDoesNotAcquireAmbientTLSFiles(t *testing.T) {
	if selected := os.Getenv(logTLSChildEnv); selected != "" {
		runLogTLSChild(t, selected)
		return
	}
	for _, destination := range []string{"file", "http"} {
		for _, kind := range []string{"missing", "fifo"} {
			for _, scope := range []string{"general-root", "signal-root", "general-client", "signal-client"} {
				t.Run(destination+"/"+kind+"/"+scope, func(t *testing.T) {
					path := filepath.Join(t.TempDir(), "unused-tls")
					if kind == "fifo" {
						if err := unix.Mkfifo(path, 0600); err != nil {
							t.Fatal(err)
						}
					}
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSuppliedLogClientDoesNotAcquireAmbientTLSFiles$", "-test.count=1")
					for _, entry := range os.Environ() {
						if !strings.HasPrefix(entry, "OTEL_") && !strings.HasPrefix(entry, logTLSChildEnv+"=") && !strings.HasPrefix(entry, "ENKV_LOG_TLS_KEY=") {
							command.Env = append(command.Env, entry)
						}
					}
					command.Env = append(command.Env, logTLSChildEnv+"="+destination, "ENKV_LOG_TLS_KEY=synthetic-key")
					variables := map[string][]string{"general-root": {"OTEL_EXPORTER_OTLP_CERTIFICATE"}, "signal-root": {"OTEL_EXPORTER_OTLP_LOGS_CERTIFICATE"}, "general-client": {"OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE", "OTEL_EXPORTER_OTLP_CLIENT_KEY"}, "signal-client": {"OTEL_EXPORTER_OTLP_LOGS_CLIENT_CERTIFICATE", "OTEL_EXPORTER_OTLP_LOGS_CLIENT_KEY"}}[scope]
					for _, key := range variables {
						command.Env = append(command.Env, key+"="+path)
					}
					var output bytes.Buffer
					command.Stdout = &output
					command.Stderr = &output
					if err := command.Start(); err != nil {
						t.Fatal(err)
					}
					done := make(chan error, 1)
					go func() { done <- command.Wait() }()
					ticker := time.NewTicker(10 * time.Millisecond)
					defer ticker.Stop()
					acquired := false
					var runErr error
				wait:
					for {
						select {
						case runErr = <-done:
							break wait
						case <-ticker.C:
							if kind != "fifo" {
								continue
							}
							fd, err := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK, 0)
							if err == nil {
								// A nonblocking writer can open only after the constructor acquired a reader.
								acquired = true
								if _, err := unix.Write(fd, []byte("synthetic-invalid-certificate")); err != nil {
									t.Error(err)
								}
								if err := unix.Close(fd); err != nil {
									t.Error(err)
								}
							} else if err != unix.ENXIO {
								t.Error(err)
							}
						}
					}
					if acquired {
						t.Fatal("supplied log client acquired an unused TLS file")
					}
					if runErr != nil {
						t.Fatalf("log client child did not finish: %v\n%s", runErr, output.String())
					}
					if !bytes.Contains(output.Bytes(), []byte("log_tls_complete")) {
						t.Fatal("log client did not join startup, delivery and close")
					}
				})
			}
		}
	}
}

func runLogTLSChild(t *testing.T, destination string) {
	t.Helper()
	level := "warn"
	routes := []string{"capture"}
	config := Config{SchemaVersion: 1, Logs: LogConfig{Level: &level, Exporters: &routes}, Exporters: map[string]Exporter{"capture": {Type: "otlp_file", Directory: "telemetry"}}}
	options := SetupOptions{BaseDirectory: t.TempDir()}
	if destination == "http" {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "application/x-protobuf")
		}))
		defer server.Close()
		config.Exporters["capture"] = Exporter{Type: "otlp_http", Endpoint: server.URL, APIKeyEnv: "ENKV_LOG_TLS_KEY"}
		options.remoteBase = server.Client().Transport
	} else if destination != "file" {
		t.Fatal("invalid child destination")
	}
	settings, err := Resolve(config, Options{})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := Start(settings, options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	telemetry.Start(runtime.Context(ctx), telemetry.ProviderCore, telemetry.OpCoreOpen).Finish(telemetry.ResultAdmissionRefused)
	if err := runtime.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if status := runtime.LogStatus("capture"); status.Written != 1 || status.Incomplete || status.Failed != 0 {
		t.Fatalf("log delivery did not finish: %+v", status)
	}
	// The pinned SDK emits one callback for AddAttributes even with no lost field.
	if got := runtime.SDKCallbackCount(); got != 1 {
		t.Fatalf("unused TLS settings reached SDK construction: callbacks=%d want=1", got)
	}
	fmt.Println("log_tls_complete")
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	records "enkv.sh/core/internal/testrecords"
	collectlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collecttrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"
)

// full_only: false
func TestTelemetryRoutesPreserveSmallScenario(t *testing.T) {
	root := testRepositoryRoot(t)
	bootstrap := repetitionTestBootstrap(t, root, t.TempDir())
	const scenario = "secret.competing-supplied-candidates-preserve-atomic-outcomes/plain2_secret2_competing_and_lost_reply"
	var baseline []string
	for _, route := range []struct {
		name                string
		file, http, trusted bool
	}{{"file", true, false, true}, {"http", false, true, true}, {"both", true, true, true}, {"http_missing_trust", false, true, false}} {
		t.Run(route.name, func(t *testing.T) {
			owned := t.TempDir()
			var logs collectlogs.ExportLogsServiceRequest
			var metrics collectmetrics.ExportMetricsServiceRequest
			var traces collecttrace.ExportTraceServiceRequest
			seen := map[string]bool{}
			var captureLock sync.Mutex
			var captureFailure string
			requests, capturedBytes := 0, 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
				captureLock.Lock()
				defer captureLock.Unlock()
				requests++
				capturedBytes += len(body)
				// Decode as requests arrive. The total byte and request bounds
				// govern this complete multi-worker witness, independently of
				// the exporter's choice of batch sizes.
				if err != nil || len(body) == 0 || len(body) > 1<<20 || capturedBytes > 32<<20 || requests > 4096 {
					captureFailure = "local OTLP capture bound or read failure"
				} else if r.Header.Get("Content-Type") != "application/x-protobuf" || r.Header.Get("x-honeycomb-team") != "TEST_LOCAL_ONLY_TOKEN" || r.Header.Get("x-honeycomb-dataset") != "local-telemetry-witness" || r.Header.Get("Content-Encoding") != "" || bytes.Contains(body, []byte("TEST_LOCAL_ONLY_TOKEN")) {
					captureFailure = "local OTLP envelope or privacy failure"
				}
				if captureFailure != "" {
					http.Error(w, "capture refused", http.StatusBadRequest)
					return
				}
				signal := strings.TrimPrefix(r.URL.Path, "/v1/")
				var message, target proto.Message
				switch signal {
				case "logs":
					message, target = new(collectlogs.ExportLogsServiceRequest), &logs
				case "metrics":
					message, target = new(collectmetrics.ExportMetricsServiceRequest), &metrics
				case "traces":
					message, target = new(collecttrace.ExportTraceServiceRequest), &traces
				default:
					captureFailure = "unexpected signal path"
				}
				if captureFailure == "" && proto.Unmarshal(body, message) != nil {
					captureFailure = "invalid OTLP payload"
				}
				if captureFailure != "" {
					http.Error(w, "capture refused", http.StatusBadRequest)
					return
				}
				proto.Merge(target, message)
				seen[signal] = true
				w.Header().Set("Content-Type", "application/x-protobuf")
			}))
			defer server.Close()
			cert := filepath.Join(owned, "roots.pem")
			var certificate []byte
			if route.trusted {
				certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			}
			if err := os.WriteFile(cert, certificate, 0600); err != nil {
				t.Fatal(err)
			}
			suite := filepath.Join(owned, "suite.json")
			if err := os.WriteFile(suite, []byte(`{"schema_version":2,"name":"local-telemetry-witness","description":"Small supplied candidate telemetry witness","required_roles":["authority","recovery"],"scenarios":["`+scenario+`"]}`), 0600); err != nil {
				t.Fatal(err)
			}
			names := []string{}
			if route.file {
				names = append(names, `"capture"`)
			}
			if route.http {
				names = append(names, `"receiver"`)
			}
			selected := "[" + strings.Join(names, ",") + "]"
			configuration := fmt.Sprintf(`{"schema_version":1,"resource":{"attributes":{"service.name":"enkv-test-runner"}},"logs":{"level":"warn","exporters":%s},"metrics":{"exporters":%s},"traces":{"sample_ratio":1,"exporters":%s},"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"},"receiver":{"type":"otlp_http","endpoint":%q,"api_key_env":"ENKV_TEST_LOCAL_KEY","dataset":"local-telemetry-witness"}}}`, selected, selected, selected, server.URL)
			config := filepath.Join(owned, "telemetry.json")
			if err := os.WriteFile(config, []byte(configuration), 0600); err != nil {
				t.Fatal(err)
			}
			for key, value := range map[string]string{"GOPROXY": "off", "GOSUMDB": "off", "GONOPROXY": "none", "SSL_CERT_FILE": cert, "SSL_CERT_DIR": owned, "GODEBUG": os.Getenv("GODEBUG") + ",x509sslcertoverrideplatform=1", "ENKV_TEST_LOCAL_KEY": "TEST_LOCAL_ONLY_TOKEN", "ENKV_TELEMETRY": "", "OTEL_SERVICE_NAME": "", "OTEL_RESOURCE_ATTRIBUTES": ""} {
				t.Setenv(key, value)
			}
			workflow := filepath.Join(owned, "workflow.json")
			saveSelection(t, workflow, map[string]any{"schema_version": 1, "name": "telemetry-routes", "steps": []any{
				map[string]any{"id": "current", "kind": "run", "recovery_mode": "both",
					"suites": []string{suite}, "environment": filepath.Join(root, "tests/environments/hermetic.json"), "telemetry_config": config, "log_level": "warn"},
			}})
			ctx, cancel := context.WithTimeout(workflowTestContext(t, root), 3*time.Minute)
			defer cancel()
			plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: workflow})
			if err != nil || len(plan.Steps) != 1 {
				t.Fatal("telemetry route selection failed", err)
			}
			ctx = withExecutionCapacity(ctx, plan.Execution)
			source, err := sourceRevision(ctx, root)
			if err != nil {
				t.Fatal(err)
			}
			toolchain, err := runGo(ctx, root, "core", "version")
			if err != nil {
				t.Fatal(err)
			}
			state, err := newRunState(root, plan.Steps[0].request, source, strings.TrimSpace(string(toolchain)))
			if err != nil {
				t.Fatal(err)
			}
			var executionErr error
			defer func() {
				if err := state.finishCurrentRun(io.Discard, executionErr); err != nil && executionErr == nil {
					t.Error("current telemetry owner finalization failed", err)
				}
				if executionErr == nil {
					if _, err := os.Lstat(state.current.path); !errors.Is(err, os.ErrNotExist) {
						t.Error("joined telemetry consumers retained current scratch", err)
					}
				}
			}()
			ctx, err = state.privateOwner.protectedFixtureContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			build := filepath.Join(state.private, "build")
			if err := os.Mkdir(build, 0700); err != nil {
				t.Fatal(err)
			}
			assembled, err := buildAssembly(runGoEnvironment, nil, ctx, root, "hermetic", "memory", bootstrap, build)
			if err != nil {
				executionErr = err
				t.Fatal(err)
			}
			state.record.BuildClosure = &assembled.Closure
			state.failureSources = assembled.FailureSources
			executionErr = state.executeSchedule(ctx, assembled.Binary, nil, limits{})
			if executionErr != nil {
				t.Fatal("actual telemetry scenario failed", executionErr)
			}
			state.finish()
			if err := state.save(); err != nil {
				t.Fatal(err)
			}
			server.Close()
			if captureFailure != "" {
				t.Fatal(captureFailure)
			}
			run := state.record
			outputs := map[string]string{}
			if err := filepath.WalkDir(state.private, func(path string, entry os.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if entry.IsDir() || entry.Name() != "invocation.json" {
					return nil
				}
				var invocation records.Invocation
				if err := records.ReadJSON(path, &invocation); err != nil {
					return err
				}
				if invocation.RunID != run.RunID || outputs[invocation.Worker] != "" {
					return errors.New("current telemetry output identity differs")
				}
				outputs[invocation.Worker] = invocation.OutputDir
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if run.Outcome != "passed" || !run.Correctness.Passed || !run.Correctness.EvidenceComplete || run.BuildClosure == nil || run.BuildClosure.Race || run.BuildClosure.RaceOptions != "" || run.Resolved == nil || run.Resolved.RecoveryMode != "both" {
				t.Fatal("telemetry changed scenario correctness or race evidence")
			}
			destinations := []string{}
			if route.file {
				destinations = append(destinations, "file")
			}
			if route.http {
				destinations = append(destinations, "http")
			}
			if !validTelemetryDisplay(run.EffectiveTelemetry) || *run.EffectiveTelemetry.LogLevel != 13 || *run.EffectiveTelemetry.TraceSampleRatio != 1 || !slices.Equal(run.EffectiveTelemetry.Logs, destinations) || !slices.Equal(run.EffectiveTelemetry.Metrics, destinations) || !slices.Equal(run.EffectiveTelemetry.Traces, destinations) {
				t.Fatal("resolved collection or destinations changed")
			}
			workers := map[string]workerEvidence{}
			found, writerWarnings, smoke, freshBefore := false, false, false, false
			var targetWriter string
			deliveryLoss := false
			for _, result := range run.Scenarios {
				if result.Scenario == "state.single-value-update-preserves-other-values/members_32" {
					smoke = true
				}
				if result.Scenario == scenario {
					found = true
					if result.Fixture.Members != 2 || result.Fixture.SmallValueBytes != 1 {
						t.Fatal("small witness fixture changed")
					}
				}
				if result.Outcome != "passed" || !result.CorrectnessPassed {
					t.Fatal("selected scenario did not pass")
				}
				for _, worker := range scenarioWorkers(result) {
					if worker.Process != "passed" || !worker.Joined || worker.Outcome != "passed" || len(worker.Deliveries) != 3*len(destinations) || outputs[worker.Worker] == "" {
						t.Fatal("actual worker lost execution or selected routes", worker.Role)
					}
					if _, duplicate := workers[worker.Worker]; duplicate {
						t.Fatal("worker evidence duplicated")
					}
					workers[worker.Worker] = worker
					if worker.Role == "fresh_before" {
						freshBefore = true
					}
					if result.Scenario == scenario && worker.Role == "writer" {
						targetWriter = worker.Worker
					}
					for _, signal := range []string{"logs", "metrics", "traces"} {
						for _, destination := range destinations {
							status, present := worker.Deliveries[signal+"."+destination]
							if !present || status.Accepted == nil || status.Written == nil || status.Dropped == nil || status.Failed == nil || status.Incomplete == nil {
								t.Fatal("worker omitted delivery fields")
							}
							if route.trusted {
								if *status.Accepted != *status.Written || *status.Failed != 0 {
									t.Fatal("selected worker delivery failed", worker.Role, signal)
								}
								if signal == "logs" || signal == "metrics" {
									if *status.Incomplete != (*status.Dropped != 0) {
										t.Fatal("counted loss and delivery status differ", worker.Role, signal)
									}
									deliveryLoss = deliveryLoss || *status.Dropped != 0
								}
								if signal != "logs" && (*status.Written == 0 || signal == "traces" && (status.EvidenceIncomplete() || *status.Dropped != 0)) {
									t.Fatalf("selected measurement delivery incomplete: scenario=%s role=%s worker=%s signal=%s destination=%s accepted=%d written=%d dropped=%d failed=%d incomplete=%t", result.Scenario, worker.Role, worker.Worker, signal, destination, *status.Accepted, *status.Written, *status.Dropped, *status.Failed, *status.Incomplete)
								}
							}
							if result.Scenario == scenario && worker.Role == "writer" && signal == "logs" && *status.Written > 0 {
								writerWarnings = true
							}
							if !route.trusted && signal != "logs" && (!status.EvidenceIncomplete() || *status.Failed == 0 || *status.Written != 0) {
								t.Fatal("untrusted receiver appeared delivered", worker.Role, signal)
							}
						}
					}
				}
			}
			if !found || !smoke || !freshBefore || targetWriter == "" {
				t.Fatal("small scenario or actual fresh workers missing")
			}
			if !route.trusted {
				if requests != 0 || run.Telemetry.Status != "incomplete" {
					t.Fatal("missing trust was not refused with incomplete telemetry")
				}
				return
			}
			wantStatus, wantFailure := "complete", ""
			if deliveryLoss {
				wantStatus, wantFailure = "incomplete", "worker_evidence_incomplete"
			}
			if !writerWarnings || run.Telemetry.Status != wantStatus || run.Telemetry.FailureClass != wantFailure {
				t.Fatal("expected warning or counted telemetry status absent")
			}
			if route.file {
				for workerID, worker := range workers {
					for signal, envelope := range map[string]string{"logs": "resourceLogs", "metrics": "resourceMetrics", "traces": "resourceSpans"} {
						if *worker.Deliveries[signal+".file"].Written == 0 {
							continue
						}
						currentFile := filepath.Join(outputs[workerID], "telemetry", signal+".jsonl")
						body, err := os.ReadFile(currentFile)
						if err != nil || len(body) == 0 {
							t.Fatalf("delivered %s current file missing for %s: %v", signal, workerID, err)
						}
						info, err := os.Lstat(currentFile)
						if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
							t.Fatal("current telemetry file permissions differ")
						}
						parent, err := os.Lstat(filepath.Dir(currentFile))
						if err != nil || !parent.IsDir() || parent.Mode().Perm() != 0700 {
							t.Fatal("current telemetry directory permissions differ")
						}
						for _, line := range bytes.Split(bytes.TrimSpace(body), []byte{'\n'}) {
							var message map[string]json.RawMessage
							if json.Unmarshal(line, &message) != nil || len(message[envelope]) == 0 || bytes.Contains(line, []byte("TEST_LOCAL_ONLY_TOKEN")) {
								t.Fatal("current telemetry lost its OTLP signal or leaked credentials")
							}
						}
					}
				}
			}
			var snapshots []records.Snapshot
			for _, group := range state.snapshots {
				snapshots = append(snapshots, group...)
			}
			facts := map[string]bool{}
			for _, snapshot := range snapshots {
				if snapshot.RunID != run.RunID || workers[snapshot.Worker].Worker == "" || snapshot.Status != "complete" || snapshot.Resource["service.name"] != "enkv-test-runner" {
					t.Fatal("current measurements lost worker identity or resource")
				}
				for _, metric := range snapshot.Metrics {
					facts[metric.Name+"|"+metric.Unit+"|"+metric.Kind+"|"+metric.Attributes["provider"]+"|"+metric.Attributes["operation"]+"|"+metric.Attributes["result"]] = true
				}
			}
			keys := make([]string, 0, len(facts))
			for fact := range facts {
				keys = append(keys, fact)
			}
			slices.Sort(keys)
			if len(keys) == 0 {
				t.Fatal("current measurements empty")
			}
			if baseline == nil {
				baseline = keys
			} else if !slices.Equal(keys, baseline) {
				t.Fatal("output destination changed measurement semantics")
			}
			if !route.http {
				if requests != 0 {
					t.Fatal("file-only run sent HTTP")
				}
				return
			}
			if !seen["logs"] || !seen["metrics"] || !seen["traces"] || len(metrics.ResourceMetrics) == 0 {
				t.Fatal("HTTP route omitted a signal")
			}
			spanOperation := map[string]string{}
			spanParents := map[string]string{}
			roots := map[string]string{}
			for _, resource := range traces.ResourceSpans {
				for _, scope := range resource.ScopeSpans {
					for _, span := range scope.Spans {
						id := fmt.Sprintf("%x/%x", span.GetTraceId(), span.GetSpanId())
						if len(span.GetTraceId()) != 16 || len(span.GetSpanId()) != 8 || spanOperation[id] != "" {
							t.Fatal("invalid or repeated span identity")
						}
						spanOperation[id] = span.GetName()
						if len(span.GetParentSpanId()) != 0 {
							spanParents[id] = fmt.Sprintf("%x/%x", span.GetTraceId(), span.GetParentSpanId())
						}
						if span.GetName() == "worker.invocation" {
							worker, invocation := "", ""
							for _, attribute := range span.GetAttributes() {
								switch attribute.GetKey() {
								case "worker.id":
									worker = attribute.GetValue().GetStringValue()
								case "invocation.id":
									invocation = attribute.GetValue().GetStringValue()
								}
							}
							if invocation != run.RunID || workers[worker].Worker == "" || roots[worker] != "" || len(span.GetParentSpanId()) != 0 {
								t.Fatal("worker invocation correlation changed")
							}
							roots[worker] = id
						}
					}
				}
			}
			if len(roots) != len(workers) {
				t.Fatal("HTTP traces omitted a worker invocation")
			}
			spanRoot := map[string]string{}
			for id := range spanOperation {
				node := id
				for remaining := len(spanOperation); spanParents[node] != "" && remaining > 0; remaining-- {
					node = spanParents[node]
				}
				if spanOperation[node] != "worker.invocation" || spanParents[node] != "" {
					t.Fatal("operation span lost its worker invocation parent chain")
				}
				spanRoot[id] = node
			}
			writerWarning := false
			for _, resource := range logs.ResourceLogs {
				for _, scope := range resource.ScopeLogs {
					for _, log := range scope.LogRecords {
						operation := ""
						for _, attribute := range log.GetAttributes() {
							if attribute.GetKey() == "operation" {
								operation = attribute.GetValue().GetStringValue()
							}
						}
						id := fmt.Sprintf("%x/%x", log.GetTraceId(), log.GetSpanId())
						writerWarning = writerWarning || spanRoot[id] == roots[targetWriter]
						if log.GetSeverityNumber() < 13 || operation == "" || spanOperation[fmt.Sprintf("%x/%x", log.GetTraceId(), log.GetSpanId())] != operation {
							t.Fatal("warning lost its own operation span")
						}
					}
				}
			}
			if !writerWarning {
				t.Fatal("HTTP payload omitted the selected writer warning")
			}
			httpFacts := map[string]bool{}
			for _, resource := range metrics.ResourceMetrics {
				for _, scope := range resource.ScopeMetrics {
					for _, metric := range scope.Metrics {
						if sum := metric.GetSum(); sum != nil {
							for _, point := range sum.DataPoints {
								attrs := map[string]string{}
								for _, attribute := range point.GetAttributes() {
									attrs[attribute.GetKey()] = attribute.GetValue().GetStringValue()
								}
								httpFacts[metric.GetName()+"|"+metric.GetUnit()+"|sum|"+attrs["provider"]+"|"+attrs["operation"]+"|"+attrs["result"]] = true
							}
						} else if histogram := metric.GetHistogram(); histogram != nil {
							for _, point := range histogram.DataPoints {
								attrs := map[string]string{}
								for _, attribute := range point.GetAttributes() {
									attrs[attribute.GetKey()] = attribute.GetValue().GetStringValue()
								}
								httpFacts[metric.GetName()+"|"+metric.GetUnit()+"|histogram|"+attrs["provider"]+"|"+attrs["operation"]+"|"+attrs["result"]] = true
							}
						} else {
							t.Fatal("HTTP metric lost its supported kind")
						}
					}
				}
			}
			httpKeys := make([]string, 0, len(httpFacts))
			for key := range httpFacts {
				httpKeys = append(httpKeys, key)
			}
			slices.Sort(httpKeys)
			if !slices.Equal(httpKeys, keys) {
				t.Fatalf("HTTP metric point semantics differ from current observations: HTTP=%v current=%v", httpKeys, keys)
			}

		})
	}
}

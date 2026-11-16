package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// full_only: false
func TestCommandTelemetryExportFailurePreservesResult(t *testing.T) {
	for _, key := range []string{"ENKV_LOG_LEVEL", "OTEL_SERVICE_NAME", "OTEL_RESOURCE_ATTRIBUTES"} {
		t.Setenv(key, "")
	}
	for _, signals := range [][]string{{"logs"}, {"metrics"}, {"traces"}, {"logs", "metrics", "traces"}} {
		for _, original := range []int{0, 1, 2, 3} {
			t.Run(fmt.Sprintf("%s/exit=%d", strings.Join(signals, "+"), original), func(t *testing.T) {
				directory := t.TempDir()
				t.Chdir(directory)
				const destination = "private-export-destination-sentinel"
				if err := os.WriteFile(filepath.Join(directory, destination), []byte("blocked"), 0600); err != nil {
					t.Fatal(err)
				}
				settings := map[string]any{
					"schema_version": 1,
					"logs":           map[string]any{"level": "off"},
					"exporters":      map[string]any{"selected": map[string]any{"type": "otlp_file", "directory": destination}},
				}
				for _, signal := range signals {
					setting := map[string]any{"exporters": []string{"selected"}}
					if signal == "logs" {
						setting["level"] = "warn"
					}
					if signal == "traces" {
						setting["sample_ratio"] = 1
					}
					settings[signal] = setting
				}
				body, err := json.Marshal(settings)
				if err != nil {
					t.Fatal(err)
				}
				configuration := filepath.Join(directory, "telemetry.json")
				if err := os.WriteFile(configuration, body, 0600); err != nil {
					t.Fatal(err)
				}
				const facts = "{\"state_result\":\"commit-outcome-unknown\",\"commit_may_have_occurred\":true}\n"
				var stdout, diagnostic bytes.Buffer
				calls := 0
				code := withCommandTelemetry(t.Context(), commandTelemetryOptions{configuration: configuration, differenceIsSuccess: true}, &diagnostic, func() int { return 19 }, func(ctx context.Context, _ io.Writer) int {
					calls++
					stdout.WriteString(facts)
					telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreOpen).Finish(telemetry.ResultAdmissionRefused)
					return original
				})
				want := original
				if want == 0 || want == 1 {
					want = 2
				}
				if code != want || calls != 1 || stdout.String() != facts {
					t.Errorf("export failure changed command facts or lost its exit: code=%d want=%d calls=%d stdout=%q", code, want, calls, stdout.String())
				}
				if !strings.Contains(diagnostic.String(), "diagnostic delivery incomplete; retain the result on stdout") || strings.Contains(diagnostic.String(), destination) {
					t.Errorf("export failure lacks a safe delivery diagnostic: %q", diagnostic.String())
				}
			})
		}
	}
}

type heldCommandConsole struct {
	entered, release, commandEntered chan struct{}
	once                             sync.Once
	logActive, overlap               atomic.Bool
	mu                               sync.Mutex
	body                             bytes.Buffer
}

func (w *heldCommandConsole) Write(body []byte) (int, error) {
	if bytes.Equal(body, []byte("command restoration message\n")) {
		w.overlap.Store(w.logActive.Load())
		close(w.commandEntered)
	} else {
		w.once.Do(func() { w.logActive.Store(true); close(w.entered); <-w.release; w.logActive.Store(false) })
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.body.Write(body)
}

// full_only: false
func TestCommandTelemetrySerializesConsoleAndCommandDiagnostics(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	sink := &heldCommandConsole{entered: make(chan struct{}), release: make(chan struct{}), commandEntered: make(chan struct{})}
	var release sync.Once
	open := func() { release.Do(func() { close(sink.release) }) }
	t.Cleanup(open)
	attempted := make(chan struct{})
	done := make(chan int, 1)
	go func() {
		done <- withCommandTelemetry(ctx, commandTelemetryOptions{logLevel: "warn"}, sink, func() int { return 17 }, func(ctx context.Context, diagnostic io.Writer) int {
			call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreReaderCompare)
			call.Finish(telemetry.ResultAdmissionRefused)
			select {
			case <-sink.entered:
			case <-ctx.Done():
				return 18
			}
			close(attempted)
			if _, err := fmt.Fprintln(diagnostic, "command restoration message"); err != nil {
				return 19
			}
			return 2
		})
	}()
	select {
	case <-attempted:
	case <-ctx.Done():
		open()
		<-done
		t.Fatal("console write did not reach the controlled overlap")
	}
	// The console worker is held inside the sink and the callback has begun its
	// write. A second sink entry before release violates the owner boundary.
	select {
	case <-sink.commandEntered:
	case <-time.After(100 * time.Millisecond):
	case <-ctx.Done():
	}
	open()
	var code int
	select {
	case code = <-done:
	case <-ctx.Done():
		t.Fatal("command did not join console shutdown")
	}
	if code != 2 || sink.overlap.Load() {
		t.Fatal("console and command writes were not serialized", code)
	}
	sink.mu.Lock()
	body := bytes.Clone(sink.body.Bytes())
	sink.mu.Unlock()
	if bytes.Count(body, []byte("command restoration message\n")) != 1 || !bytes.Contains(body, []byte(`operation="core.reader.compare"`)) || !bytes.Contains(body, []byte(`result="admission_refused"`)) {
		t.Fatal("serialized diagnostics lost command or telemetry facts")
	}
}

// full_only: false
func TestCommandDiagnosticWriterPreservesExactWriteResults(t *testing.T) {
	sentinel := errors.New("sink write failed")
	calls := 0
	writer := &commandDiagnosticWriter{writer: commandWriterFunc(func(body []byte) (int, error) {
		calls++
		if string(body) != "complete diagnostic" {
			t.Fatal("writer changed diagnostic bytes")
		}
		if calls == 1 {
			return 3, sentinel
		}
		if calls == 2 {
			return 4, nil
		}
		return len(body), nil
	})}
	for _, want := range []struct {
		n   int
		err error
	}{{3, sentinel}, {4, nil}, {len("complete diagnostic"), nil}} {
		n, err := writer.Write([]byte("complete diagnostic"))
		if n != want.n || err != want.err {
			t.Fatal("diagnostic writer changed count or error", n, err)
		}
	}
	if calls != 3 {
		t.Fatal("failed write prevented later diagnostic delivery")
	}
}

type failedCommandConsole struct {
	entered, release chan struct{}
	once             sync.Once
	short            bool
	calls            atomic.Int32
}

func (w *failedCommandConsole) Write(body []byte) (int, error) {
	w.calls.Add(1)
	w.once.Do(func() { close(w.entered); <-w.release })
	if w.short {
		return len(body) - 1, nil
	}
	return 0, errors.New("private-console-error-sentinel")
}

// full_only: false
func TestCommandTelemetryDiagnosticFailurePreservesResultAndJoinsConsole(t *testing.T) {
	for _, short := range []bool{false, true} {
		for _, originalCode := range []int{0, 1, 3} {
			name := "error/success"
			if short {
				name = "short/success"
			}
			if originalCode == 1 {
				name = strings.Replace(name, "success", "verified-difference", 1)
			} else if originalCode != 0 {
				name = strings.Replace(name, "success", "unknown", 1)
			}
			t.Run(name, func(t *testing.T) {
				for _, key := range []string{"ENKV_LOG_LEVEL", "OTEL_SERVICE_NAME", "OTEL_RESOURCE_ATTRIBUTES"} {
					t.Setenv(key, "")
				}
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				sink := &failedCommandConsole{entered: make(chan struct{}), release: make(chan struct{}), short: short}
				var release sync.Once
				open := func() { release.Do(func() { close(sink.release) }) }
				t.Cleanup(open)
				// The telemetry wrapper borrows an already rendered command result. It
				// cannot change these bytes when separate diagnostic delivery fails.
				facts := []byte("{\"schema\":\"ProductResult/v1\",\"state_result\":\"success\",\"commit_may_have_occurred\":false,\"receipt_hex\":\"0102\"}\n")
				if originalCode == 3 {
					facts = []byte("{\"schema\":\"ProductResult/v1\",\"state_result\":\"commit-outcome-unknown\",\"commit_may_have_occurred\":true}\n")
				}
				var out bytes.Buffer
				done := make(chan int, 1)
				go func() {
					done <- withCommandTelemetry(ctx, commandTelemetryOptions{logLevel: "warn", differenceIsSuccess: true}, sink, func() int { return 19 }, func(ctx context.Context, _ io.Writer) int {
						n, err := out.Write(facts)
						if err != nil || n != len(facts) {
							return 18
						}
						call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreReaderCompare)
						call.Finish(telemetry.ResultAdmissionRefused)
						return originalCode
					})
				}()
				select {
				case <-sink.entered:
				case code := <-done:
					t.Fatalf("command returned before pending console write: %d", code)
				case <-ctx.Done():
					open()
					<-done
					t.Fatal("console did not reach controlled delivery failure")
				}
				select {
				case code := <-done:
					open()
					t.Fatalf("command did not join blocked console: %d", code)
				default:
				}
				open()
				var code int
				select {
				case code = <-done:
				case <-ctx.Done():
					code = <-done
					t.Fatal("command did not join console shutdown", code)
				}
				want := originalCode
				if want == 0 || want == 1 {
					want = 2
				}
				if code != want || !bytes.Equal(out.Bytes(), facts) || sink.calls.Load() == 0 {
					t.Fatal("diagnostic failure lost delivery exit or changed operation facts", code, want)
				}
				if bytes.Contains(out.Bytes(), []byte("private-console-error-sentinel")) {
					t.Fatal("raw console error escaped command result")
				}
			})
		}
	}
}

// full_only: false
func TestCommandTelemetryDistinguishesVerifiedDifferenceFromFailure(t *testing.T) {
	for _, comparison := range []bool{false, true} {
		for _, exit := range []int{0, 1, 2, 3} {
			t.Run(fmt.Sprintf("comparison=%t/exit=%d", comparison, exit), func(t *testing.T) {
				var diagnostic bytes.Buffer
				code := withCommandTelemetry(t.Context(), commandTelemetryOptions{logLevel: "info", differenceIsSuccess: comparison}, &diagnostic, func() int { return 19 }, func(context.Context, io.Writer) int { return exit })
				result := "failure"
				if exit == 0 || comparison && exit == 1 {
					result = "success"
				}
				if code != exit || bytes.Count(diagnostic.Bytes(), []byte(`operation="application.invocation"`)) != 1 || !bytes.Contains(diagnostic.Bytes(), []byte(`result="`+result+`"`)) {
					t.Fatal("command completion telemetry changed exit meaning or lost its result")
				}
			})
		}
	}
}

// full_only: false
func TestCommandDiagnosticFailureKeepsSetInputCleanupAndRefusal(t *testing.T) {
	for _, short := range []bool{false, true} {
		name := "error"
		if short {
			name = "short"
		}
		t.Run(name, func(t *testing.T) {
			input := &setCommandInput{closeErr: errors.New("private-input-close-sentinel")}
			var out bytes.Buffer
			calls := 0
			sink := commandWriterFunc(func(body []byte) (int, error) {
				calls++
				if short {
					return len(body) - 1, nil
				}
				return 0, errors.New("private-diagnostic-sentinel")
			})
			code := runSetContext(t.Context(), []string{"--source", "/absolute/source.json", "--source-format", "json", "--name", "entry", "--json", "--log-level", "invalid-level-sentinel"}, input, &out, sink)
			var result struct {
				Schema        string `json:"schema"`
				Operation     string `json:"operation_kind"`
				State         string `json:"state_result"`
				CommitUnknown bool   `json:"commit_may_have_occurred"`
			}
			if code != 2 || input.reads != 0 || input.closes != 1 || calls < 2 || json.Unmarshal(out.Bytes(), &result) != nil || result.Schema != "ProductResult/v1" || result.Operation != "set-confidential" || result.State != "refused" || result.CommitUnknown {
				t.Fatal("failed diagnostic lost unread input cleanup or closed refusal", code, input.reads, input.closes, calls)
			}
			for _, private := range []string{"private-input-close-sentinel", "private-diagnostic-sentinel", "invalid-level-sentinel"} {
				if bytes.Contains(out.Bytes(), []byte(private)) {
					t.Fatal("private diagnostic input escaped refusal")
				}
			}
		})
	}
}

// full_only: false
func TestPrepareKnownSetupHasOneActionableWarning(t *testing.T) {
	for _, short := range []bool{false, true} {
		t.Run(fmt.Sprintf("short-output=%t", short), func(t *testing.T) {
			path, _, _, _ := setCommandPreparedSource(t)
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var source map[string]any
			if json.Unmarshal(body, &source) != nil {
				t.Fatal("source fixture is invalid")
			}
			binding, err := contract.EncodeNormalOutputBinding(contract.NormalOutputBinding{DestinationID: "destination", Destination: contract.OutputDestination{ConfigContractID: "fixture/output/config/v1", ServiceContractID: "fixture-output", CanonicalSettings: []byte(`{}`), Capabilities: contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityWriteValue}})
			if err != nil {
				t.Fatal(err)
			}
			source["outputs"].(map[string]any)["destinations"] = map[string]any{"destination": map[string]any{"plugin": nil, "canonical": map[string]any{"settings": map[string]any{}}}}
			generatedPath := filepath.Join(filepath.Dir(path), source["generated"].(string))
			generatedBody, err := os.ReadFile(generatedPath)
			if err != nil {
				t.Fatal(err)
			}
			var generated map[string]any
			if err := json.Unmarshal(generatedBody, &generated); err != nil {
				t.Fatal(err)
			}
			generated["canonical_records"] = map[string]any{"generators": map[string]any{}, "outputs": map[string]any{"destination": binding}}
			generatedBody, err = json.Marshal(generated)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(generatedPath, generatedBody, 0600); err != nil {
				t.Fatal(err)
			}
			body, err = json.Marshal(source)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			var out, diagnostic bytes.Buffer
			var writer io.Writer = &out
			if short {
				writer = prepareShortWriter{}
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			code := runPrepareWithCoordinator(ctx, []string{"--source", path, "--source-format", "json", "--json"}, writer, &diagnostic, compositionfull.PrepareConfiguration)
			if code != 2 {
				t.Fatal("known plugin setup changed exit", code, diagnostic.String())
			}
			if short {
				if !strings.Contains(diagnostic.String(), "prepare result delivery failed") || strings.Contains(diagnostic.String(), "WARNING: plugin setup incomplete") {
					t.Fatal("output failure reported ordinary setup", diagnostic.String())
				}
				return
			}
			facts := prepareCommandRecord(t, out.Bytes())
			if facts["outcome"] != "incomplete" || facts["dependencies"].(map[string]any)["all_declared_ready"] != false {
				t.Fatal("warning changed readiness facts", facts)
			}
			if strings.Count(diagnostic.String(), "WARNING:") != 1 || !strings.Contains(diagnostic.String(), "run prepare on the existing pair") || strings.Contains(diagnostic.String(), "ERROR") || strings.Contains(diagnostic.String(), `result="failure"`) || strings.Contains(diagnostic.String(), "use recover") {
				t.Fatal("known setup lacks one actionable warning", diagnostic.String())
			}
		})
	}
}

// full_only: false
func TestCommandTelemetrySetupStatusDoesNotOverrideOtherExits(t *testing.T) {
	for _, exit := range []int{0, 2, 3} {
		t.Run(fmt.Sprintf("exit=%d", exit), func(t *testing.T) {
			setup := true
			var diagnostic bytes.Buffer
			code := withCommandTelemetry(t.Context(), commandTelemetryOptions{logLevel: "debug", setupIncomplete: &setup}, &diagnostic, func() int { return 19 }, func(context.Context, io.Writer) int { return exit })
			want := "failure"
			switch exit {
			case 0:
				want = "success"
			case 2:
				want = "setup_incomplete"
			}
			if code != exit || !strings.Contains(diagnostic.String(), `result="`+want+`"`) {
				t.Fatal("typed setup status changed another outcome", code, diagnostic.String())
			}
		})
	}
}

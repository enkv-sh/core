package core

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"enkv.sh/compositions/observability"
	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/crypto/testsupport/custody"
	"enkv.sh/telemetry"
	collectlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collecttrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const assertionArgumentSentinel = "ASSERTION_ARGUMENT_SECRET_SENTINEL"
const assertionFormatSentinel = "ASSERTION_FORMAT_SECRET_SENTINEL"
const assertionErrorSentinel = "ASSERTION_ERROR_SECRET_SENTINEL"
const assertionResourceSentinel = "ASSERTION_RESOURCE_SECRET_SENTINEL"

// This object's formatting is owned by testing. It checks that interception
// completed before testing could format or inspect an assertion argument.
type assertionFormattingProbe struct{ directory string }

func (probe assertionFormattingProbe) String() string {
	if _, err := os.Lstat(filepath.Join(probe.directory, "failure.json")); err != nil {
		if os.WriteFile(filepath.Join(probe.directory, "formatting-before-marker"), []byte("failed"), 0o600) != nil {
			panic("formatting-order proof could not be saved")
		}
	}
	return assertionFormatSentinel
}

func assertionExpectedLine(t testing.TB, inv records.Invocation, line int) {
	t.Helper()
	if records.WriteJSON(filepath.Join(inv.OutputDir, "expected-line.json"), struct {
		Line int `json:"line"`
	}{line}, 0o600) != nil {
		t.Fatal("expected source line unavailable")
	}
}

func maintainedFixtureFirstFatalLine(t testing.TB, name string) int {
	t.Helper()
	for _, path := range []string{"tests/shared/fixture_test.go", "../tests/shared/fixture_test.go"} {
		set := token.NewFileSet()
		file, err := parser.ParseFile(set, path, nil, 0)
		if err != nil {
			continue
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Name.Name != name {
				continue
			}
			line := 0
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || selector.Sel.Name != "Fatal" {
					return true
				}
				owner, ok := selector.X.(*ast.Ident)
				if ok && owner.Name == "t" && (line == 0 || set.Position(call.Pos()).Line < line) {
					line = set.Position(call.Pos()).Line
				}
				return true
			})
			if line > 0 {
				return line
			}
		}
	}
	t.Fatal("maintained fixture assertion source unavailable", name)
	return 0
}

func liveAssertionChild(t testing.TB, inv records.Invocation, input liveRunInput, failure *records.FailureRecorder, mode string) {
	worker, err := records.NewWorker(inv, liveProvider(), input.Scenarios[0], failure)
	if err != nil {
		t.Fatal("assertion worker construction failed")
	}
	defer func() {
		if records.WriteJSON(filepath.Join(inv.OutputDir, "deferred.json"), struct{}{}, 0o600) != nil {
			t.Error("deferred proof unavailable")
		}
		if worker.Finish(context.Background(), !t.Failed()) != nil {
			t.Error("final record failed")
		}
	}()
	seq := liveBeginPhase(t, worker, "setup", false)
	liveEndPhase(t, worker, seq, true)
	if mode == "cleanup" {
		t.Cleanup(func() {
			_, _, line, _ := runtime.Caller(0)
			assertionExpectedLine(t, inv, line+2)
			t.Error(assertionArgumentSentinel)
		})
		return
	}
	_ = liveBeginPhase(t, worker, "transition", false)
	operation := telemetry.Start(worker.Context(context.Background()), telemetry.ProviderCore, telemetry.OpCoreOpen)
	operation.Finish(telemetry.ResultAdmissionRefused)
	probe := assertionFormattingProbe{directory: inv.OutputDir}
	assertionErr := errors.New(assertionErrorSentinel)
	switch mode {
	case "consumer_failure":
		p := liveConsumerScenario(t, context.Background(), livePublicationCloudScope, 6, true)
		p.runtime.input = &records.OutputFixtureInput{InventoryPath: filepath.Join(inv.StateDir, "output-inventory.json")}
		body := []byte(assertionArgumentSentinel)
		defer func() {
			if !bytes.Equal(body, make([]byte, len(body))) {
				t.Error("failed consumer retained returned bytes")
			}
		}()
		p.runtime.profiles[0].cloud = livePublicationConsumerCheck{read: func(context.Context, liveOutputConsumer, string, uint32) (liveOutputRead, error) {
			return liveOutputRead{HTTPStatus: 403, Bytes: body}, assertionErr
		}}
		p.consumers()
	case "fixture_init":
		fixtureInitAdmission(t, fixtureEnvironment{}, OpenContext{})
	case "artifact":
		persistGenesisArtifact(t, filepath.Join(inv.StateDir, assertionErrorSentinel), 1, contract.Hash([]byte("artifact")), []byte(assertionArgumentSentinel))
	case "custody":
		custody.NewLive(t, nil, contract.ID{}, contract.ID{}, nil, nil)
	case "generated_failure", "generated_failure_qualified":
		tracker := newGeneratedFailureTracker(failure)
		id := contract.Hash([]byte(assertionArgumentSentinel))
		locator := contract.Hash([]byte("missing generated locator"))
		authority := contract.Hash([]byte("missing generated authority"))
		var outcome custody.GeneratedProducerOutcome
		if mode == "generated_failure_qualified" {
			outcome = custody.GeneratedProducerOutcome{ID: id, Locator: locator, Authority: authority,
				Code: contract.CryptoSuccess, Effect: "unknown", Qualified: true,
				Disposition: contract.GeneratorDispositionUnknown, Reason: contract.GeneratorReasonTransport}
		} else {
			env, _ := genesisEnvironment(t, contract.GCP, true)
			packet, facts, observed := env.Custody.InvokeGeneratedProducerOutcome(context.Background(), id, locator, authority)
			if observed.Code != contract.CryptoInvalidAdmission || len(packet) != 0 || facts.Schema != 0 {
				t.Fatal("generated missing-admission control changed")
			}
			outcome = observed
		}
		tracker.observe(outcome)
		tracker.selectFailure("generated_create", id, locator, authority, outcome.Code, true)
		t.Fatal("generated result refused")
	case "fatal":
		_, _, line, _ := runtime.Caller(0)
		assertionExpectedLine(t, inv, line+2)
		t.Fatal(assertionArgumentSentinel, probe, assertionErr)
	case "fatalf":
		_, _, line, _ := runtime.Caller(0)
		assertionExpectedLine(t, inv, line+2)
		t.Fatalf("%s %s %v", assertionArgumentSentinel, probe, assertionErr)
	case "error", "finalizer":
		_, _, line, _ := runtime.Caller(0)
		assertionExpectedLine(t, inv, line+2)
		t.Error(assertionArgumentSentinel, probe, assertionErr)
	case "errorf":
		_, _, line, _ := runtime.Caller(0)
		assertionExpectedLine(t, inv, line+2)
		t.Errorf("%s %s %v", assertionArgumentSentinel, probe, assertionErr)
	case "fail_now":
		_, _, line, _ := runtime.Caller(0)
		assertionExpectedLine(t, inv, line+2)
		t.FailNow()
	case "fail":
		_, _, line, _ := runtime.Caller(0)
		assertionExpectedLine(t, inv, line+2)
		t.Fail()
	default:
		t.Fatal("unknown assertion case")
	}
	if records.WriteJSON(filepath.Join(inv.OutputDir, "continued.json"), struct{}{}, 0o600) != nil {
		t.Fatal("nonfatal continuation unavailable")
	}
	if mode == "finalizer" {
		file := filepath.Join(inv.OutputDir, "worker.json")
		if os.Remove(file) != nil || os.Mkdir(file, 0o700) != nil {
			t.Fatal("finalizer write fault unavailable")
		}
	}
}

// full_only: false
func TestFailureFactsSurviveDisabledTelemetry(t *testing.T) {
	if mode := os.Getenv("ENKV_TEST_GENERATED_FAILURE_CASE"); mode != "" {
		handle, inv, input, failure := readLiveInvocation(t, "writer")
		liveAssertionChild(handle, inv, input, failure, mode)
		return
	}
	for _, mode := range []string{"generated_failure", "generated_failure_qualified", "consumer_failure"} {
		t.Run(mode, func(t *testing.T) {
			inv := assertionProtocolInvocation(t)
			t.Setenv("ENKV_TEST_GENERATED_FAILURE_CASE", mode)
			if runLiveProtocolEntry(t, "TestFailureFactsSurviveDisabledTelemetry", saveLiveProtocolInvocation(t, inv)) == nil {
				t.Fatal("failed generated worker passed")
			}
			assertions := records.InspectAssertions(inv, false)
			if mode == "consumer_failure" {
				path := filepath.Join(inv.StateDir, "output-consumer-failure.json")
				var facts liveConsumerFailure
				info, err := os.Stat(path)
				if err != nil || info.Mode().Perm() != 0600 || records.ReadJSON(path, &facts) != nil ||
					assertions.Marker != "valid_failure_marker" || assertions.Completed != (records.CompletedCheckpoint{Code: "setup", Sequence: 1}) {
					t.Fatal("consumer failure facts did not survive without telemetry")
				}
				if facts.Stage != "value" || facts.Row != 7 || facts.Actor != liveOutputConsumerA || facts.Attempts != 1 ||
					facts.HTTPStatus != 403 || facts.AccessRefused || facts.CurrentMatch || facts.PriorMatch ||
					facts.Length != len(assertionArgumentSentinel) || facts.Cause != "read_failed" || facts.ElapsedSeconds < 0 {
					t.Fatalf("consumer failure scalar facts differ: %+v", facts)
				}
				body, err := os.ReadFile(path)
				if err != nil || bytes.Contains(body, []byte(assertionArgumentSentinel)) || bytes.Contains(body, []byte(assertionErrorSentinel)) || bytes.Contains(body, []byte("slot")) || bytes.Contains(body, []byte("instance")) {
					t.Fatal("private consumer data entered scalar failure facts")
				}
				assertFailureFilesExcludeSecrets(t, inv)
				return
			}
			facts := assertions.OperationFailure
			if assertions.Marker != "valid_failure_marker" || assertions.Completed != (records.CompletedCheckpoint{Code: "setup", Sequence: 1}) ||
				facts == nil || facts.Operation != "generated_create" {
				t.Fatal("generated failure facts did not survive without telemetry", assertions)
			}
			if mode == "generated_failure" {
				if facts.Stage != "entry" || facts.Category != "invalid" || facts.Code != contract.CryptoInvalidAdmission ||
					facts.Effect != "no_send" || facts.FactsStatus != "facts_unavailable" || facts.SafeFacts != nil {
					t.Fatal("no-send failure facts changed", assertions)
				}
			} else if facts.Stage != "completed" || facts.Category != "none" || facts.Code != contract.CryptoSuccess ||
				facts.Effect != "unknown" || facts.FactsStatus != "qualified" || facts.SafeFacts == nil ||
				facts.SafeFacts.Disposition != contract.GeneratorDispositionUnknown || facts.SafeFacts.Reason != contract.GeneratorReasonTransport {
				t.Fatal("qualified failure facts changed", assertions)
			}
			assertFailureFilesExcludeSecrets(t, inv)
		})
	}
}

// full_only: false
func TestGeneratedFailureFactsBindExactInvocation(t *testing.T) {
	for _, change := range []string{"exact", "wrong_authority", "duplicate"} {
		t.Run(change, func(t *testing.T) {
			inv := assertionProtocolInvocation(t)
			failure, err := records.NewFailureRecorder(inv)
			if err != nil {
				t.Fatal(err)
			}
			tracker := newGeneratedFailureTracker(failure)
			id := contract.Hash([]byte("generated exact invocation"))
			locator := contract.Hash([]byte("generated private locator"))
			authority := contract.Hash([]byte("generated private authority"))
			qualified := custody.GeneratedProducerOutcome{ID: id, Locator: locator, Authority: authority,
				Code: contract.CryptoSuccess, Effect: "unknown", Qualified: true,
				Disposition: contract.GeneratorDispositionUnknown, Reason: contract.GeneratorReasonTransport}
			tracker.observe(custody.GeneratedProducerOutcome{ID: contract.Hash([]byte("unrelated")),
				Code: contract.CryptoInvalidAdmission, Stage: "entry", Category: "invalid", Effect: "no_send"})
			tracker.observe(qualified)
			if change == "duplicate" {
				tracker.observe(qualified)
			}
			selectedAuthority := authority
			if change == "wrong_authority" {
				selectedAuthority = contract.Hash([]byte("wrong authority"))
			}
			tracker.selectFailure("generated_create", id, locator, selectedAuthority, contract.CryptoSuccess, true)
			failure.Record("fatal", "enkv.sh/core/tests_live_runner_failure_checks_test.go", 1)
			assertions := records.InspectAssertions(inv, false)
			if assertions.Marker != "valid_failure_marker" {
				t.Fatal("first assertion marker was lost")
			}
			if change != "exact" {
				if assertions.OperationFailure != nil {
					t.Fatal("unmatched or duplicate callback entered the marker")
				}
				return
			}
			facts := assertions.OperationFailure
			if facts == nil || facts.Operation != "generated_create" || facts.Stage != "completed" || facts.Category != "none" ||
				facts.Code != contract.CryptoSuccess || facts.Effect != "unknown" || facts.FactsStatus != "qualified" ||
				facts.SafeFacts == nil || facts.SafeFacts.Disposition != contract.GeneratorDispositionUnknown ||
				facts.SafeFacts.Reason != contract.GeneratorReasonTransport {
				t.Fatal("qualified outcome was not bound to its exact invocation", assertions)
			}
			body, err := os.ReadFile(filepath.Join(inv.OutputDir, "failure.json"))
			if err != nil || bytes.Contains(body, []byte(fmt.Sprintf("%x", id))) ||
				bytes.Contains(body, []byte(fmt.Sprintf("%x", locator))) || bytes.Contains(body, []byte(fmt.Sprintf("%x", authority))) {
				t.Fatal("private invocation identity entered the marker")
			}
		})
	}
}

// full_only: false
func TestLiveProtocolAssertionEvidence(t *testing.T) {
	if mode := os.Getenv("ENKV_TEST_ASSERTION_CASE"); mode != "" {
		handle, inv, input, failure := readLiveInvocation(t, "writer")
		liveAssertionChild(handle, inv, input, failure, mode)
		return
	}
	for _, mode := range []string{"fixture_init", "artifact", "custody", "fatal", "fatalf", "error", "errorf", "fail_now", "fail", "cleanup", "finalizer"} {
		t.Run(mode, func(t *testing.T) {
			inv := assertionProtocolInvocation(t)
			t.Setenv("ENKV_TEST_ASSERTION_CASE", mode)
			if runLiveProtocolEntry(t, "TestLiveProtocolAssertionEvidence", saveLiveProtocolInvocation(t, inv)) == nil {
				t.Fatal("assertion process passed")
			}
			var marker records.FailureMarker
			if records.ReadJSONLimit(filepath.Join(inv.OutputDir, "failure.json"), &marker, 4096) != nil {
				t.Fatal("assertion marker did not survive Goexit")
			}
			source := "tests/live/runner/failure_checks_test.go"
			code := mode
			line := 0
			switch mode {
			case "fixture_init":
				source, code, line = "tests/shared/fixture_test.go", "fatal", maintainedFixtureFirstFatalLine(t, "fixtureInitAdmission")
			case "artifact":
				source, code, line = "tests/shared/fixture_test.go", "fatal", maintainedFixtureFirstFatalLine(t, "persistGenesisArtifact")
			case "custody":
				source, code, line = "crypto/testsupport/custody/live.go", "fatal", 22
			case "cleanup", "finalizer":
				code = "error"
			}
			if line == 0 && mode != "fixture_init" && mode != "artifact" {
				var expected struct {
					Line int `json:"line"`
				}
				if records.ReadJSON(filepath.Join(inv.OutputDir, "expected-line.json"), &expected) != nil {
					t.Fatal("independent source line unavailable")
				}
				line = expected.Line
			}
			if marker.Source != source || marker.Code != code || marker.Line != line || marker.Completed != (records.CompletedCheckpoint{Code: "setup", Sequence: 1}) {
				t.Fatal("immediate lower assertion or checkpoint differs", marker)
			}
			if _, err := os.Lstat(filepath.Join(inv.OutputDir, "deferred.json")); err != nil {
				t.Fatal("Goexit skipped deferred finalization")
			}
			_, continued := os.Lstat(filepath.Join(inv.OutputDir, "continued.json"))
			nonfatal := mode == "error" || mode == "errorf" || mode == "fail" || mode == "finalizer"
			if (continued == nil) != nonfatal {
				t.Fatal("fatal and nonfatal Go behavior changed")
			}
			if _, err := os.Lstat(filepath.Join(inv.OutputDir, "formatting-before-marker")); !os.IsNotExist(err) {
				t.Fatal("assertion arguments were formatted before marker publication")
			}
			assertions := records.InspectAssertions(inv, mode == "cleanup")
			want := "valid_failure_marker"
			if mode == "cleanup" {
				want = "contradictory_failure_marker"
			}
			if assertions.Marker != want {
				t.Fatal("cleanup contradiction or first failure was lost", assertions)
			}
			if mode == "cleanup" {
				var saved records.WorkerResult
				if records.ReadJSON(filepath.Join(inv.OutputDir, "worker.json"), &saved) != nil || saved.Outcome != "passed" {
					t.Fatal("cleanup assertion did not occur after passing deferred finalization")
				}
			}
			assertFailureFilesExcludeSecrets(t, inv)
		})
	}
}

func assertFailureFilesExcludeSecrets(t testing.TB, inv records.Invocation) {
	t.Helper()
	err := filepath.WalkDir(inv.OutputDir, func(file string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || entry.Name() == "invocation.json" {
			return nil
		}
		body, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		for _, secret := range []string{assertionArgumentSentinel, assertionFormatSentinel, assertionErrorSentinel, assertionResourceSentinel, "ASSERTION_CREDENTIAL_SECRET_SENTINEL"} {
			if bytes.Contains(body, []byte(secret)) {
				t.Errorf("confidential assertion content reached %s", entry.Name())
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestLiveProtocolAssertionEvidenceTelemetryPrivacy(t *testing.T) {
	for _, metrics := range []bool{false, true} {
		for _, logs := range []bool{false, true} {
			t.Run(fmt.Sprintf("metrics_%t_logs_%t", metrics, logs), func(t *testing.T) {
				inv := assertionProtocolInvocation(t)
				metricRoutes, logRoutes := "[]", "[]"
				if metrics {
					metricRoutes = `["capture"]`
				}
				if logs {
					logRoutes = `["capture"]`
				}
				settings, err := observability.Decode([]byte(`{"schema_version":1,"logs":{"level":"debug","exporters":`+logRoutes+`},"metrics":{"exporters":`+metricRoutes+`},"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"}}}`), observability.Options{})
				if err != nil {
					t.Fatal(err)
				}
				inv.TelemetrySettings = &settings
				t.Setenv("ENKV_TEST_ASSERTION_CASE", "errorf")
				if runLiveProtocolEntry(t, "TestLiveProtocolAssertionEvidence", saveLiveProtocolInvocation(t, inv)) == nil {
					t.Fatal("assertion process passed")
				}
				evidence := records.InspectAssertions(inv, false)
				if evidence.Marker != "valid_failure_marker" || evidence.Completed.Code != "setup" {
					t.Fatal("optional signal settings changed assertion evidence", evidence)
				}
				assertFailureFilesExcludeSecrets(t, inv)
				for _, signal := range []struct {
					name    string
					enabled bool
				}{{"metrics", metrics}, {"logs", logs}} {
					file := filepath.Join(inv.OutputDir, "telemetry", signal.name+".jsonl")
					body, err := os.ReadFile(file)
					if !signal.enabled {
						if !os.IsNotExist(err) {
							t.Fatal("disabled signal created a file")
						}
						continue
					}
					if err != nil || len(body) == 0 {
						t.Fatal("enabled local signal evidence unavailable", signal.name, err)
					}
					for _, line := range bytes.Split(bytes.TrimSpace(body), []byte("\n")) {
						var message proto.Message = &collectlogs.ExportLogsServiceRequest{}
						if signal.name == "metrics" {
							message = &collectmetrics.ExportMetricsServiceRequest{}
						}
						if protojson.Unmarshal(line, message) != nil {
							t.Fatal("local OTLP payload refused")
						}
					}
				}
			})
		}
	}
}

// full_only: false
func TestLiveProtocolAssertionEvidenceLocalOTLPPrivacy(t *testing.T) {
	type request struct {
		path string
		body []byte
	}
	received := make(chan request, 128)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
		if err != nil || len(body) > 1<<20 {
			t.Error("local OTLP request exceeded its test bound")
		}
		select {
		case received <- request{r.URL.Path, body}:
		default:
			t.Error("local OTLP receiver overflow")
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	certificate := filepath.Join(t.TempDir(), "server.pem")
	if os.WriteFile(certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600) != nil {
		t.Fatal("local trust fixture unavailable")
	}
	// The pinned Go toolchain accepts an explicit certificate file on each
	// supported native platform; the child needs no process-global HTTP hook.
	t.Setenv("SSL_CERT_FILE", certificate)
	t.Setenv("SSL_CERT_DIR", filepath.Dir(certificate))
	t.Setenv("GODEBUG", os.Getenv("GODEBUG")+",x509sslcertoverrideplatform=1")
	t.Setenv("ENKV_ASSERTION_TEST_KEY", "ASSERTION_CREDENTIAL_SECRET_SENTINEL")
	t.Setenv("ENKV_TEST_ASSERTION_CASE", "errorf")
	inv := assertionProtocolInvocation(t)
	settings, err := observability.Decode([]byte(`{"schema_version":1,"logs":{"level":"debug","exporters":["capture","local_http"]},"metrics":{"exporters":["capture","local_http"]},"traces":{"exporters":["capture","local_http"]},"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"},"local_http":{"type":"otlp_http","endpoint":"`+server.URL+`","api_key_env":"ENKV_ASSERTION_TEST_KEY"}}}`), observability.Options{})
	if err != nil {
		t.Fatal(err)
	}
	inv.TelemetrySettings = &settings
	if runLiveProtocolEntry(t, "TestLiveProtocolAssertionEvidence", saveLiveProtocolInvocation(t, inv)) == nil {
		t.Fatal("assertion process passed")
	}
	assertFailureFilesExcludeSecrets(t, inv)
	server.Close()
	close(received)
	seen := map[string]bool{}
	for req := range received {
		var message proto.Message
		switch req.path {
		case "/v1/logs":
			message = &collectlogs.ExportLogsServiceRequest{}
		case "/v1/metrics":
			message = &collectmetrics.ExportMetricsServiceRequest{}
		case "/v1/traces":
			message = &collecttrace.ExportTraceServiceRequest{}
		default:
			t.Fatal("unexpected local OTLP path")
		}
		if len(req.body) == 0 || proto.Unmarshal(req.body, message) != nil {
			t.Fatal("local OTLP payload refused")
		}
		for _, secret := range []string{assertionArgumentSentinel, assertionFormatSentinel, assertionErrorSentinel, assertionResourceSentinel, "ASSERTION_CREDENTIAL_SECRET_SENTINEL"} {
			if bytes.Contains(req.body, []byte(secret)) {
				t.Fatal("confidential assertion content reached local OTLP")
			}
		}
		seen[req.path] = true
	}
	for _, path := range []string{"/v1/logs", "/v1/metrics", "/v1/traces"} {
		if !seen[path] {
			t.Fatal("configured local signal was not observed", path)
		}
	}
	if got := records.InspectAssertions(inv, false); got.Marker != "valid_failure_marker" {
		t.Fatal("local export changed private assertion evidence")
	}
}

// full_only: false
func TestLiveProtocolFreshChildRejectsPassingAssertionMarker(t *testing.T) {
	inv, _ := liveProtocolInvocation(t, "fresh_before")
	failure, err := records.NewFailureRecorder(inv)
	if err != nil {
		t.Fatal(err)
	}
	failure.Record("error", "enkv.sh/core/tests_live_runner_failure_checks_test.go", 1)
	result := records.WorkerResult{SchemaVersion: records.SchemaVersion, RunID: inv.RunID, Worker: inv.Worker, Role: inv.Role, Scenario: inv.Scenario, Outcome: "passed"}
	if records.WriteJSON(filepath.Join(inv.OutputDir, "worker.json"), result, 0600) != nil {
		t.Fatal("passing child fixture")
	}
	got, err := readFreshChildResult(inv, nil)
	if err == nil || got.Outcome != "passed" || records.InspectAssertions(inv, true).Marker != "contradictory_failure_marker" {
		t.Fatal("child assertion contradiction became a successful read")
	}
}

func assertionProtocolInvocation(t *testing.T) records.Invocation {
	t.Helper()
	inv, input := liveProtocolInvocation(t, "writer")
	input.Settings.KeyID = assertionResourceSentinel
	if records.WriteJSON(inv.Input, input, 0400) != nil {
		t.Fatal("private assertion input unavailable")
	}
	return inv
}

// full_only: false
func TestLiveProtocolFreshChildRetainsMarkerWithoutWorkerResult(t *testing.T) {
	for _, state := range []string{"missing", "malformed"} {
		t.Run(state, func(t *testing.T) {
			inv, _ := liveProtocolInvocation(t, "fresh_before")
			owner, err := records.NewFailureRecorder(inv)
			if err != nil {
				t.Fatal(err)
			}
			owner.Record("fatal", "enkv.sh/core/tests_live_runner_failure_checks_test.go", 1)
			if state == "malformed" && os.WriteFile(filepath.Join(inv.OutputDir, "worker.json"), []byte("{"), 0600) != nil {
				t.Fatal("malformed child fixture")
			}
			result, err := readFreshChildResult(inv, errors.New("controlled process failure"))
			if err == nil || result.Assertions == nil || result.Assertions.Marker != "valid_failure_marker" {
				t.Fatal("missing child result hid the independent marker")
			}
		})
	}
}

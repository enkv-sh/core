package generatorhost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
	protocol "enkv.sh/sdk/protocols/generator"
	"enkv.sh/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

func testID(label byte) protocol.ID {
	return sha256.Sum256([]byte{label})
}

func testDependencyManifest() contract.ID {
	return sha256.Sum256([]byte("ENKV/TEST/HERMETIC-GENERATOR-DEPENDENCIES/v1"))
}

func buildSDKGenerator(t *testing.T) string {
	t.Helper()
	return buildTestGenerator(t, "sdk")
}

func artifactIdentity(t *testing.T, path string) (contract.ID, uint64) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	return sha256.Sum256(body), uint64(len(body))
}

func testCommand(implementation contract.GeneratorImplementation) protocol.Command {
	intent, err := protocol.EncodeIntent(protocol.Intent{Schema: 1, ConfigContractID: protocol.ID(implementation.ConfigContractID), LifecycleMode: protocol.LifecycleManaged, ResourceContractID: testID(22), Settings: []byte(`{"policies":["read"]}`)})
	if err != nil {
		panic(err)
	}
	digest, err := protocol.IntentDigest(intent)
	if err != nil {
		panic(err)
	}
	return protocol.Command{Schema: 1, DomainID: testID(1), OperationID: testID(2), RequestIdentityDigest: testID(3), PlanGraphID: testID(4), LineageID: testID(5), AttemptID: testID(6), TransmissionID: testID(7), ResultID: testID(8), ResultContractID: testID(9), DescriptorID: protocol.ID(implementation.DescriptorID), ExecutorID: protocol.ID(implementation.ExecutorID), CredentialRouteID: protocol.ID(implementation.CredentialRouteID), Action: protocol.ActionCreate, DeadlineUnixMillis: uint64(time.Now().Add(time.Minute).UnixMilli()), RequestDigest: testID(12), IntentDigest: digest, LifecycleMode: protocol.LifecycleManaged, ResourceContractID: testID(22), Intent: intent}
}
func buildTestGenerator(t *testing.T, mode string) string {
	t.Helper()
	t.Setenv("TMPDIR", t.TempDir())
	path := filepath.Join(t.TempDir(), "generator")
	cmd := exec.Command("go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags=-buildid= -X=main.mode="+mode, "-o", path, "./testdata/hermetic")
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local")
	prepareNativeModule(t, filepath.Join("..", ".."), cmd, path+".mod")
	modules, packages := generatorBuildInputs(t, cmd)
	sources, err := artifact.CaptureSourcesForModules(t.Context(), "generator", packages, modules)
	if err != nil {
		t.Fatal(err)
	}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build generator: %v\n%s", err, output)
	}
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	recordGeneratorBuildFacts(t, path, cmd, modules, packages, sources)
	return path
}

func boundImplementation(t *testing.T, path string) contract.GeneratorImplementation {
	t.Helper()
	digest, length := artifactIdentity(t, path)
	route, err := credentialroute.Encode(credentialroute.Route{Schema: 1, ContractID: [32]byte{1}, Mode: credentialroute.ModeEnvironment, Names: []string{"ENKV_GENERATOR_TEST_TOKEN"}})
	if err != nil {
		t.Fatal(err)
	}
	recipe, err := credentialroute.Decode(route)
	if err != nil {
		t.Fatal(err)
	}
	routeID, err := credentialroute.Identity(recipe)
	if err != nil {
		t.Fatal(err)
	}
	return contract.GeneratorImplementation{Schema: contract.GeneratorImplementationSchema, Kind: contract.GeneratorComponentKind, DescriptorID: contract.ID(testID(10)), ProtocolID: contract.ID(protocol.ProtocolID()), ExecutorID: contract.ID(testID(11)), ArtifactContractID: contract.ID(testID(12)), DependencyManifestID: testDependencyManifest(), ArtifactSHA256: digest, ConfigContractID: contract.ID(testID(13)), CredentialRouteID: contract.ID(routeID), CredentialRoute: route, ArtifactLength: length, Module: "author.test/generator", Command: "author.test/generator/cmd/tool", Version: "1.0.0", GoVersion: runtime.Version(), NativeTuple: runtime.GOOS + "/" + runtime.GOARCH}
}

func testLauncher(t *testing.T, mode string, credential []byte) (*NativeLauncher, protocol.Command, string) {
	t.Helper()
	path := buildTestGenerator(t, mode)
	implementation := boundImplementation(t, path)
	t.Setenv("ENKV_GENERATOR_TEST_TOKEN", string(credential))
	launcher, err := newHermeticNative(Config{ArtifactPath: path, Artifact: implementation})
	if err != nil {
		t.Fatal(err)
	}
	return launcher, testCommand(implementation), path
}
func startAndRead(t *testing.T, launcher *NativeLauncher, command protocol.Command) (protocol.Result, protocol.Status, error) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	run, err := launcher.Start(context.Background(), command, writer)
	if err != nil {
		_ = reader.Close()
		return protocol.Result{}, protocol.Status{}, err
	}
	body, readErr := protocol.ReadExpectedFrame(reader, protocol.KindResult, run.CommandID(), protocol.MaximumResultBody)
	if readErr == nil {
		readErr = protocol.RequireEOF(reader)
	}
	_ = reader.Close()
	status, waitErr := run.Wait(context.Background())
	if readErr != nil {
		return protocol.Result{}, status, errors.Join(readErr, waitErr)
	}
	result, decodeErr := protocol.DecodeResult(body)
	result.Value = bytes.Clone(result.Value)
	result.SafeFacts.Target = bytes.Clone(result.SafeFacts.Target)
	result.SafeFacts.ResourceData = bytes.Clone(result.SafeFacts.ResourceData)
	result.SafeFacts.ProviderFacts = bytes.Clone(result.SafeFacts.ProviderFacts)
	clear(body)
	if decodeErr != nil {
		return protocol.Result{}, status, decodeErr
	}
	return result, status, waitErr
}

// full_only: false
func TestHostTelemetryOwnsStagesAndSafeDetails(t *testing.T) {
	credential := []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	launcher, command, artifactPath := testLauncher(t, "success", credential)
	recorder := telemetry.NewRecorder()
	capture := &hostTraceCapture{Tracer: noop.NewTracerProvider().Tracer("host-test")}
	ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapabilityWithTracers(nil, recorder, map[telemetry.Provider]trace.Tracer{telemetry.ProviderGeneratorHost: capture}))
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	run, err := launcher.Start(ctx, command, writer)
	if err != nil {
		_ = reader.Close()
		t.Fatal(err)
	}
	if _, err := writer.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("successful start retained the result writer", err)
	}
	body, err := protocol.ReadExpectedFrame(reader, protocol.KindResult, run.CommandID(), protocol.MaximumResultBody)
	if err == nil {
		err = protocol.RequireEOF(reader)
	}
	_ = reader.Close()
	clear(body)
	if err != nil {
		t.Fatal(err)
	}
	if status, err := run.Wait(context.Background()); err != nil || status.Stage != 5 {
		t.Fatal("host result changed", status, err)
	}
	if status, err := run.Wait(context.Background()); err != nil || status.Stage != 5 {
		t.Fatal("repeated wait changed result", status, err)
	}
	records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 32))
	commandID := run.CommandID()
	want := []telemetry.Operation{telemetry.OpGeneratorHostStart, telemetry.OpGeneratorHostHandshake, telemetry.OpGeneratorHostCommandSend, telemetry.OpGeneratorHostStatusRead, telemetry.OpGeneratorHostJoin}
	for _, operation := range want {
		var starts, returns int
		for _, record := range records {
			if err := record.Validate(); err != nil {
				t.Fatal(err)
			}
			if record.Operation != operation {
				continue
			}
			if record.Provider != telemetry.ProviderGeneratorHost || record.Path != "" || record.PathKind != "" {
				t.Fatal("host telemetry exposed an executable path or lost provider identity")
			}
			if operation != telemetry.OpGeneratorHostStart && record.CommandID != hex.EncodeToString(commandID[:]) {
				t.Fatal("host telemetry lost command identity")
			}
			switch record.Event {
			case telemetry.DiagnosticStart:
				starts++
			case telemetry.DiagnosticReturn:
				returns++
				if record.Result != telemetry.ResultSuccess {
					t.Fatal("host stage did not return success", operation, record.Result)
				}
			}
		}
		if starts != 1 || returns != 1 {
			t.Fatalf("host %s starts=%d returns=%d", operation, starts, returns)
		}
	}
	encoded, err := json.Marshal(records)
	if err != nil || bytes.Contains(encoded, credential) || bytes.Contains(encoded, command.Intent) || bytes.Contains(encoded, []byte(artifactPath)) || bytes.Contains(encoded, []byte(launcher.config.ArtifactPath+".private-input")) {
		t.Fatal("host telemetry retained credential or command payload")
	}
	capture.assertSafe(t, records, artifactPath, launcher.config.ArtifactPath+".private-input", string(credential), string(command.Intent))
}

// full_only: false
func TestHostTelemetryCancellationSettlesOnce(t *testing.T) {
	credential := []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	launcher, command, _ := testLauncher(t, "hang", credential)
	recorder := telemetry.NewRecorder()
	capture := &hostTraceCapture{Tracer: noop.NewTracerProvider().Tracer("host-test")}
	base := telemetry.WithCapability(context.Background(), telemetry.NewCapabilityWithTracers(nil, recorder, map[telemetry.Provider]trace.Tracer{telemetry.ProviderGeneratorHost: capture}))
	ctx, cancel := context.WithCancel(base)
	defer cancel()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	run, err := launcher.Start(ctx, command, writer)
	if err != nil {
		_ = reader.Close()
		t.Fatal(err)
	}
	cancel()
	_, _ = protocol.ReadFrame(reader, protocol.MaximumResultBody)
	_ = reader.Close()
	if _, err := run.Wait(context.Background()); err == nil {
		t.Fatal("cancelled child reported success")
	}
	_, _ = run.Wait(context.Background())
	_ = run.Cancel()
	records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 32))
	for _, operation := range []telemetry.Operation{telemetry.OpGeneratorHostCancel, telemetry.OpGeneratorHostStatusRead, telemetry.OpGeneratorHostJoin} {
		var starts, returns int
		for _, record := range records {
			if record.Operation != operation {
				continue
			}
			switch record.Event {
			case telemetry.DiagnosticStart:
				starts++
			case telemetry.DiagnosticReturn:
				returns++
			}
		}
		if starts != 1 || returns != 1 {
			t.Fatalf("host %s starts=%d returns=%d after repeated Wait and Cancel", operation, starts, returns)
		}
	}
	capture.assertSafe(t, records, launcher.config.ArtifactPath, launcher.config.ArtifactPath+".private-input", string(credential), string(command.Intent))
}

// full_only: false
func TestHostTelemetryKeepsReviewedFailureAndExcludesCredential(t *testing.T) {
	credential := bytes.Repeat([]byte("private-credential-sentinel"), 3000)
	launcher, command, path := testLauncher(t, "success", credential)
	recorder := telemetry.NewRecorder()
	capture := &hostTraceCapture{Tracer: noop.NewTracerProvider().Tracer("host-test")}
	ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapabilityWithTracers(nil, recorder, map[telemetry.Provider]trace.Tracer{telemetry.ProviderGeneratorHost: capture}))
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := launcher.Start(ctx, command, writer); !errors.Is(err, ErrCredential) {
		_ = reader.Close()
		t.Fatal("credential refusal changed", err)
	}
	_ = reader.Close()
	records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 32))
	var seen bool
	for _, record := range records {
		if record.Operation == telemetry.OpGeneratorHostCommandSend && record.Event == telemetry.DiagnosticReturn {
			seen = true
			if record.Path != "" || record.PathKind != "" || record.CommandID == "" || record.Result != telemetry.ResultDenied || record.ErrorClass != telemetry.DiagnosticReasonDenied || record.ErrorDetail != ErrCredential.Error() || record.ErrorDetailStatus != "reviewed" {
				t.Fatal("host failure lost safe source facts", record)
			}
		}
	}
	if !seen {
		t.Fatal("host command refusal was not recorded")
	}
	encoded, err := json.Marshal(records)
	if err != nil || bytes.Contains(encoded, credential) || bytes.Contains(encoded, command.Intent) || bytes.Contains(encoded, []byte(path)) || bytes.Contains(encoded, []byte(launcher.config.ArtifactPath+".private-input")) {
		t.Fatal("host refusal captured credential or command payload")
	}
	capture.assertSafe(t, records, path, launcher.config.ArtifactPath+".private-input", string(credential), string(command.Intent))
}

func rssBytes(t *testing.T, usage any) uint64 {
	t.Helper()
	r, ok := usage.(*syscall.Rusage)
	if !ok || r.Maxrss <= 0 {
		t.Fatal("process RSS measurement unavailable")
	}
	value := uint64(r.Maxrss)
	if runtime.GOOS == "linux" {
		value *= 1024
	}
	return value
}

// full_only: false
func TestNativeGeneratorParentAndChildMemoryMeasurement(t *testing.T) {
	launcher, command, _ := testLauncher(t, "memory-measurement", []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ\n"))
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	startedRun, err := launcher.Start(context.Background(), command, writer)
	if err != nil {
		_ = reader.Close()
		t.Fatal(err)
	}
	run, ok := startedRun.(*nativeRun)
	if !ok {
		_ = reader.Close()
		t.Fatal("native measurement lost the process owner")
	}
	body, err := protocol.ReadExpectedFrame(reader, protocol.KindResult, run.CommandID(), protocol.MaximumResultBody)
	if err == nil {
		err = protocol.RequireEOF(reader)
	}
	_ = reader.Close()
	if err != nil {
		status, waitErr := run.Wait(context.Background())
		exit := -1
		if run.cmd.ProcessState != nil {
			exit = run.cmd.ProcessState.ExitCode()
		}
		t.Fatal("child result measurement failed", err, status, waitErr, "exit", exit)
	}
	result, err := protocol.DecodeResult(body)
	if err != nil || len(result.Value) != 32 || string(result.Value[:8]) != "ENKVMEM1" {
		clear(body)
		t.Fatal("child heap measurement unavailable", err)
	}
	childHeapAlloc := binary.BigEndian.Uint64(result.Value[8:16])
	childHeapSys := binary.BigEndian.Uint64(result.Value[16:24])
	childSystem := binary.BigEndian.Uint64(result.Value[24:32])
	clear(body)
	status, err := run.Wait(context.Background())
	if err != nil || status != (protocol.Status{Stage: 5}) || run.cmd.ProcessState == nil {
		t.Fatal("measured child failed", status, err)
	}
	childRSS := rssBytes(t, run.cmd.ProcessState.SysUsage())
	runtime.GC()
	var parent runtime.MemStats
	runtime.ReadMemStats(&parent)
	var parentUsage syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &parentUsage) != nil {
		t.Fatal("parent RSS measurement unavailable")
	}
	parentRSS := rssBytes(t, &parentUsage)
	if childHeapAlloc == 0 || childHeapSys < childHeapAlloc || childSystem < childHeapSys || childRSS < childHeapAlloc || parentRSS < parent.HeapAlloc ||
		ParentFixedOwnedBytes+ChildFixedOwnedBytes >= 1664<<20 {
		t.Fatal("native process measurement violated its ownership bounds")
	}
	t.Logf("native generator process measurement tuple=%s/%s duration=%s parent_owned_bytes=%d child_owned_bytes=%d parent_heap_alloc_bytes=%d parent_heap_sys_bytes=%d parent_system_bytes=%d parent_rss_bytes=%d child_heap_alloc_bytes=%d child_heap_sys_bytes=%d child_system_bytes=%d child_rss_bytes=%d",
		runtime.GOOS, runtime.GOARCH, time.Since(started), ParentFixedOwnedBytes, ChildFixedOwnedBytes, parent.HeapAlloc, parent.HeapSys, parent.Sys, parentRSS, childHeapAlloc, childHeapSys, childSystem, childRSS)
}

// full_only: true
// Maximum-capacity or accumulated-history proof; smaller behavior checks remain in dev.
func TestSequentialMaximumGeneratorLaunchesFitCommandDeadline(t *testing.T) {
	path := buildTestGenerator(t, "success")
	implementation := boundImplementation(t, path)
	t.Setenv("ENKV_GENERATOR_TEST_TOKEN", "private-test-value")
	deadline := time.Now().Add(time.Duration(contract.GeneratorMaximumChildCommandDurationMillis) * time.Millisecond)
	started := time.Now()
	for action := uint8(1); action <= 2; action++ {
		for index := 0; index < 128; index++ {
			launcher, err := newHermeticNative(Config{ArtifactPath: path, Artifact: implementation})
			if err != nil {
				t.Fatal(err)
			}
			command := testCommand(implementation)
			command.Action = action
			command.AttemptID = sha256.Sum256([]byte(fmt.Sprintf("attempt/%d/%d", action, index)))
			command.TransmissionID = sha256.Sum256([]byte(fmt.Sprintf("transmission/%d/%d", action, index)))
			command.ResultID = sha256.Sum256([]byte(fmt.Sprintf("result/%d/%d", action, index)))
			command.DeadlineUnixMillis = uint64(deadline.UnixMilli())
			if action == 2 {
				facts := command.NewFacts(protocol.DispositionCompleteCreate, protocol.ReasonNone)
				facts.Action = protocol.ActionCreate
				facts.Target = []byte("account")
				facts.ResourceData = []byte(fmt.Sprintf("target/%d", index))
				var encodeErr error
				command.OriginalFacts, encodeErr = protocol.EncodeSafeFacts(facts)
				if encodeErr != nil {
					t.Fatal("original create facts fixture refused", encodeErr)
				}
			}
			result, status, err := startAndRead(t, launcher, command)
			wantDisposition := uint8(1)
			if action == 2 {
				wantDisposition = protocol.DispositionRetirementAcknowledged
			}
			if err != nil || status != (protocol.Status{Stage: 5}) || result.SafeFacts.Disposition != wantDisposition {
				clear(result.Value)
				t.Fatalf("sequential launch %d/%d failed: status=%+v disposition=%d err=%v", action, index, status, result.SafeFacts.Disposition, err)
			}
			clear(result.Value)
		}
	}
	duration := time.Since(started)
	if !time.Now().Before(deadline) {
		t.Fatalf("256 sequential generator launches exceeded the %d ms command lifetime: %s", contract.GeneratorMaximumChildCommandDurationMillis, duration)
	}
	t.Logf("sequential generator launches tuple=%s/%s creates=128 retires=128 processes=256 duration=%s deadline=%s", runtime.GOOS, runtime.GOARCH, duration, time.Duration(contract.GeneratorMaximumChildCommandDurationMillis)*time.Millisecond)
}

// full_only: false
func TestNativeLaunchUsesClosedDescriptorsAndWire(t *testing.T) {
	for _, mode := range []string{"success", "stdout-stderr"} {
		t.Run(mode, func(t *testing.T) {
			launcher, command, _ := testLauncher(t, mode, []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ\n"))
			result, status, err := startAndRead(t, launcher, command)
			if err != nil || status != (protocol.Status{Stage: 5}) {
				t.Fatal("native run failed", status, err)
			}
			if result.AttemptID != command.AttemptID || result.ResultID != command.ResultID || result.ResultContractID != command.ResultContractID ||
				result.ExecutorID != command.ExecutorID || result.SafeFacts.RequestDigest != command.RequestDigest ||
				len(result.Value) != 53 || !bytes.HasPrefix(result.Value, []byte("enkv_")) {
				t.Fatal("native result changed custody coordinates")
			}
			clear(result.Value)
			reader, writer, _ := os.Pipe()
			if _, err := launcher.Start(context.Background(), command, writer); !errors.Is(err, ErrAdmission) {
				t.Fatal("launcher accepted a second command", err)
			}
			_ = reader.Close()
		})
	}
}

// full_only: false
func TestNativeSetupClosesOwnedResourcesAfterDescriptorExhaustion(t *testing.T) {
	for _, tc := range []struct {
		name          string
		freeAfterCopy int
	}{
		{"credential pipe", 0},
		{"status pipe", 2},
		{"null device", 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			launcher, command, path := testLauncher(t, "success", []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer closeFile(reader)
			var held []*os.File
			defer func() { closeFiles(held...) }()
			launcher.afterSourceCheck = func() {
				for {
					file, err := os.Open(os.DevNull)
					if err != nil {
						if !errors.Is(err, syscall.EMFILE) {
							t.Fatalf("exhaust descriptors: %v", err)
						}
						break
					}
					held = append(held, file)
				}
				for i := 0; i < tc.freeAfterCopy; i++ {
					last := len(held) - 1
					closeFile(held[last])
					held = held[:last]
				}
			}
			run, err := launcher.Start(context.Background(), command, writer)
			if run != nil {
				_ = run.Cancel()
			}
			if !errors.Is(err, syscall.EMFILE) {
				t.Errorf("descriptor exhaustion did not stop setup: %v", err)
			}
			closeFiles(held...)
			held = nil
			if _, err := writer.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Errorf("supplied result writer survived setup failure: %v", err)
			}
			entries, err := filepath.Glob(filepath.Join(os.TempDir(), "enkv-generator-*"))
			if err != nil || len(entries) != 0 {
				t.Errorf("staging directory retained a failed launch: entries=%v err=%v", entries, err)
			}
			if _, err := os.Stat(path); err != nil {
				t.Errorf("failed setup damaged the installed artifact: %v", err)
			}
		})
	}
}

// full_only: false
func TestStartConsumesResultWriterOnRefusal(t *testing.T) {
	launcher, command, _ := testLauncher(t, "success", []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
	for _, tc := range []struct {
		name    string
		launch  *NativeLauncher
		ctx     context.Context
		command protocol.Command
		want    error
	}{
		{"nil launcher", nil, context.Background(), command, ErrAdmission},
		{"nil context", launcher, nil, command, ErrAdmission},
		{"cancelled context", launcher, func() context.Context { ctx, cancel := context.WithCancel(context.Background()); cancel(); return ctx }(), command, context.Canceled},
		{"malformed command", launcher, context.Background(), protocol.Command{}, ErrAdmission},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer closeFile(reader)
			if _, err := tc.launch.Start(tc.ctx, tc.command, writer); !errors.Is(err, tc.want) {
				t.Fatal("unexpected refusal", err)
			}
			if _, err := writer.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("refusal retained result writer", err)
			}
		})
	}
}

// full_only: false
func TestPartialExecutableCopyClosesOwnedResources(t *testing.T) {
	launcher, command, path := testLauncher(t, "success", []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
	launcher.beforeSourceCopy = func(context.Context) {
		if err := os.Truncate(path, 1); err != nil {
			t.Fatal(err)
		}
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFile(reader)
	run, err := launcher.Start(context.Background(), command, writer)
	if run != nil {
		_ = run.Cancel()
	}
	if !errors.Is(err, ErrAdmission) {
		t.Fatal("partial executable copy did not refuse", err)
	}
	if _, err := writer.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("partial copy retained the result writer", err)
	}
	entries, err := filepath.Glob(filepath.Join(os.TempDir(), "enkv-generator-*"))
	if err != nil || len(entries) != 0 {
		t.Fatal("partial copy retained staging data", entries, err)
	}
}

// full_only: false
func TestHandshakePrecedesCredentialRead(t *testing.T) {
	launcher, command, _ := testLauncher(t, "bad-handshake", []byte("short"))
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFile(reader)
	if _, err := launcher.Start(context.Background(), command, writer); !errors.Is(err, ErrAdmission) {
		t.Fatal("bad handshake did not fail before the bad credential", err)
	}
}

// full_only: false
func TestArtifactSubstitutionAndModeAreClosed(t *testing.T) {
	credential := []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	t.Run("wrong digest", func(t *testing.T) {
		launcher, command, path := testLauncher(t, "success", credential)
		if err := os.WriteFile(path, []byte("replacement"), 0500); err != nil {
			t.Fatal(err)
		}
		reader, writer, _ := os.Pipe()
		defer closeFile(reader)
		if _, err := launcher.Start(context.Background(), command, writer); !errors.Is(err, ErrAdmission) {
			t.Fatal("replacement artifact passed", err)
		}
	})
	t.Run("replacement during check", func(t *testing.T) {
		launcher, command, path := testLauncher(t, "success", credential)
		launcher.afterSourceCopy = func() {
			_ = os.Rename(path, path+".old")
			_ = os.WriteFile(path, []byte("replacement"), 0500)
		}
		reader, writer, _ := os.Pipe()
		defer closeFile(reader)
		if _, err := launcher.Start(context.Background(), command, writer); !errors.Is(err, ErrAdmission) {
			t.Fatal("during-check substitution passed", err)
		}
	})
	t.Run("replacement after check", func(t *testing.T) {
		launcher, command, path := testLauncher(t, "success", credential)
		launcher.afterSourceCheck = func() {
			_ = os.Rename(path, path+".old")
			_ = os.WriteFile(path, []byte("replacement"), 0500)
		}
		if _, status, err := startAndRead(t, launcher, command); err != nil || status.Stage != 5 {
			t.Fatal("sealed launch copy followed the replaced path", status, err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		launcher, command, path := testLauncher(t, "success", credential)
		link := filepath.Join(t.TempDir(), "generator-link")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		launcher.config.ArtifactPath = link
		reader, writer, _ := os.Pipe()
		defer closeFile(reader)
		if _, err := launcher.Start(context.Background(), command, writer); !errors.Is(err, ErrAdmission) {
			t.Fatal("symlink artifact passed", err)
		}
	})
	t.Run("group writable", func(t *testing.T) {
		launcher, command, path := testLauncher(t, "success", credential)
		if err := os.Chmod(path, 0520); err != nil {
			t.Fatal(err)
		}
		reader, writer, _ := os.Pipe()
		defer closeFile(reader)
		if _, err := launcher.Start(context.Background(), command, writer); !errors.Is(err, ErrAdmission) {
			t.Fatal("group-writable artifact passed", err)
		}
	})
}

// full_only: false
func TestLaunchOwnsPrivateTemporaryStagingRoot(t *testing.T) {
	launcher, command, path := testLauncher(t, "success", bytes.Repeat([]byte("x"), protocol.MaximumEnvironmentBody))
	launcher.afterSourceCopy = func() {
		roots, err := filepath.Glob(filepath.Join(os.TempDir(), "enkv-generator-*"))
		if err != nil || len(roots) != 1 {
			t.Fatal("temporary root inventory", roots, err)
		}
		info, err := os.Lstat(roots[0])
		if err != nil || info.Mode().Perm() != 0700 || !fileOwnedByCurrentUID(info) {
			t.Fatal("launch root is not private", err)
		}
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFile(reader)
	if _, err := launcher.Start(t.Context(), command, writer); !errors.Is(err, ErrCredential) {
		t.Fatal("temporary launch did not reach exact credential refusal", err)
	}
	roots, err := filepath.Glob(filepath.Join(os.TempDir(), "enkv-generator-*"))
	if err != nil || len(roots) != 0 {
		t.Fatal("temporary launch root retained", roots, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("borrowed artifact changed", err)
	}
	t.Run("unavailable temporary parent", func(t *testing.T) {
		launcher, command, _ := testLauncher(t, "success", bytes.Repeat([]byte("x"), protocol.MaximumEnvironmentBody))
		t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "absent"))
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer closeFile(reader)
		if _, err := launcher.Start(t.Context(), command, writer); !errors.Is(err, ErrAdmission) {
			t.Fatal("unavailable temporary root admitted", err)
		}
	})
}

// full_only: false
func TestCredentialInputIsClosed(t *testing.T) {
	route, _ := credentialroute.Decode(boundImplementation(t, buildTestGenerator(t, "success")).CredentialRoute)
	for _, value := range []string{"", "short", "spaces and punctuation !", "line\nend"} {
		t.Setenv("ENKV_GENERATOR_TEST_TOKEN", value)
		body, err := readEnvironmentInputs(t.Context(), route)
		if err != nil {
			t.Fatal("generic environment applied provider grammar", err)
		}
		inputs, err := credentialroute.DecodeInputs(route, body)
		if err != nil || len(inputs) != 1 || !inputs[0].Present || string(inputs[0].Value) != value {
			t.Fatal("private input changed", err)
		}
		clear(body)
	}
	t.Setenv("ENKV_GENERATOR_TEST_TOKEN", strings.Repeat("x", credentialroute.MaxInputsBytes))
	if body, err := readEnvironmentInputs(t.Context(), route); body != nil || !errors.Is(err, ErrCredential) {
		t.Fatal("private input overflow admitted", err)
	}
}

// full_only: false
func TestRuntimeAdmissionRefusesChangedRowAndCoordinates(t *testing.T) {
	path := buildSDKGenerator(t)
	installed := generatorInstallation(t, path)
	base := Config{ArtifactPath: path, Artifact: installed.Artifact(), Installation: installed}
	changes := map[string]func(*Config){"descriptor": func(v *Config) { v.Artifact.DescriptorID[0] ^= 1 }, "protocol": func(v *Config) { v.Artifact.ProtocolID[0] ^= 1 }, "executor": func(v *Config) { v.Artifact.ExecutorID[0] ^= 1 }, "artifact digest": func(v *Config) { v.Artifact.ArtifactSHA256[0] ^= 1 }, "native tuple": func(v *Config) { v.Artifact.NativeTuple = "linux/arm64" }, "relative artifact": func(v *Config) { v.ArtifactPath = "generator" }, "route": func(v *Config) { v.Artifact.CredentialRouteID[0] ^= 1 }, "route body": func(v *Config) { v.Artifact.CredentialRoute[2] ^= 1 }, "dependency": func(v *Config) { v.Artifact.DependencyManifestID[0] ^= 1 }, "toolchain": func(v *Config) { v.Artifact.GoVersion += "-different" }, "length": func(v *Config) { v.Artifact.ArtifactLength++ }, "config": func(v *Config) { v.Artifact.ConfigContractID[0] ^= 1 }}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			changed := base
			changed.Artifact.CredentialRoute = bytes.Clone(base.Artifact.CredentialRoute)
			change(&changed)
			if _, err := NewNative(t.Context(), changed); !errors.Is(err, ErrAdmission) {
				t.Fatal("changed installed expectation admitted", err)
			}
		})
	}
}

// full_only: false
func TestInstalledImplementationRequiresExactArtifactBinding(t *testing.T) {
	path := buildSDKGenerator(t)
	metadata, dependency := generatorMetadata(t, path)
	installed, err := NewInstallation(metadata, dependency)
	if err != nil {
		t.Fatal(err)
	}
	bound := installed.Artifact()
	if _, err := NewNative(t.Context(), Config{ArtifactPath: path, Artifact: bound}); !errors.Is(err, ErrAdmission) {
		t.Fatal("missing trusted expectation admitted", err)
	}
	config := Config{ArtifactPath: path, Artifact: bound, Installation: installed}
	launcher, err := NewNative(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENKV_GENERATOR_TEST_TOKEN", "")
	_, status, err := startAndRead(t, launcher, testCommand(bound))
	if !errors.Is(err, ErrProcess) || status.Stage != protocol.StatusStageResponse || status.Category != protocol.StatusUnavailable {
		t.Fatal("plugin refusal lost joined failure cause or closed status", err, status)
	}
	for _, change := range []func(*Config){func(c *Config) { c.Artifact.ArtifactSHA256[0] ^= 1 }, func(c *Config) { c.Artifact.DependencyManifestID[0] ^= 1 }, func(c *Config) { c.Artifact.Module += "/other" }} {
		changed := config
		change(&changed)
		if _, err := NewNative(t.Context(), changed); !errors.Is(err, ErrAdmission) {
			t.Fatal("changed captured expectation admitted", err)
		}
	}
	for _, body := range [][]byte{nil, []byte("invalid dependency"), append(append([]byte(nil), dependency...), 0)} {
		if _, err := NewInstallation(metadata, body); err == nil {
			t.Fatal("inexact dependency admitted")
		}
	}
	tagged := buildSDKGenerator(t)
	taggedMetadata, taggedDependency := generatorMetadata(t, tagged)
	if _, err := NewInstallation(taggedMetadata, taggedDependency); err != nil {
		t.Fatal("exact independently built artifact refused", err)
	}
}

// full_only: false
func TestInstalledGeneratorArtifactRefusesSubstitutionBeforeCredential(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*testing.T, *NativeLauncher, string)
		want   error
	}{
		{"changed bytes", func(t *testing.T, _ *NativeLauncher, path string) {
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			body[len(body)/2] ^= 1
			if err := os.WriteFile(path, body, 0500); err != nil {
				t.Fatal(err)
			}
			clear(body)
		}, ErrAdmission},
		{"missing file", func(t *testing.T, _ *NativeLauncher, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}, ErrAdmission},
		{"symlink file", func(t *testing.T, _ *NativeLauncher, path string) {
			if err := os.Rename(path, path+".original"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(path+".original", path); err != nil {
				t.Fatal(err)
			}
		}, ErrAdmission},
		{"group writable file", func(t *testing.T, _ *NativeLauncher, path string) {
			if err := os.Chmod(path, 0520); err != nil {
				t.Fatal(err)
			}
		}, ErrAdmission},

		{"non-executable copy", func(t *testing.T, launcher *NativeLauncher, path string) {
			launcher.afterSourceCheck = func() {
				copies, _ := filepath.Glob(filepath.Join(os.TempDir(), "enkv-generator-*", ".launch-*", "generator"))
				if len(copies) != 1 || os.Chmod(copies[0], 0400) != nil {
					t.Error("checked private copy unavailable")
				}
			}
		}, ErrProcess},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := buildSDKGenerator(t)
			installed := generatorInstallation(t, path)
			bound := installed.Artifact()
			config := Config{ArtifactPath: path, Artifact: bound, Installation: installed}
			launcher, err := NewNative(t.Context(), config)
			if err != nil {
				t.Fatal("installed production artifact refused before substitution", err)
			}
			test.change(t, launcher, path)
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer closeFile(reader)
			if _, err := launcher.Start(context.Background(), testCommand(bound), writer); !errors.Is(err, test.want) {
				t.Fatal("installed artifact substitution reached credential read", err)
			}
		})
	}
}

// full_only: false
func TestImplementationIdentityVector(t *testing.T) {
	path := buildSDKGenerator(t)
	metadata, dependency := generatorMetadata(t, path)
	installed, err := NewInstallation(metadata, dependency)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := metadata.GeneratorFacts()
	if err != nil {
		t.Fatal(err)
	}
	row := installed.Artifact()
	if row.DescriptorID != contract.ID(facts.DescriptorID) || row.ExecutorID != contract.ID(facts.ExecutorID) || row.ArtifactContractID != contract.ID(facts.ArtifactContractID) || row.DependencyManifestID != contract.ID(facts.DependencyManifestID) || row.ConfigContractID != contract.ID(facts.Descriptor.Generator.ConfigContractID) {
		t.Fatal("measured identities changed at host boundary")
	}
	row.CredentialRoute[2] ^= 1
	if installed.validRuntime(row) {
		t.Fatal("published route mutation changed immutable installation")
	}
	if !installed.validRuntime(installed.Artifact()) {
		t.Fatal("caller mutation changed retained installation")
	}
}

// full_only: false
func TestStartRefusesDifferentDescriptorBeforeCredentialRead(t *testing.T) {
	launcher, command, _ := testLauncher(t, "success", []byte("private-value"))
	command.DescriptorID[0] ^= 1
	launcher.afterSourceCopy = func() { t.Fatal("different descriptor reached artifact launch") }
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFile(reader)
	if _, err := launcher.Start(t.Context(), command, writer); !errors.Is(err, ErrAdmission) {
		t.Fatal("different descriptor reached credential access", err)
	}
}

// full_only: false
func TestStartRefusesProducerThatDoesNotNameArtifact(t *testing.T) {
	launcher, command, _ := testLauncher(t, "success", []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
	command.ExecutorID[0] ^= 1
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFile(reader)
	if _, err := launcher.Start(context.Background(), command, writer); !errors.Is(err, ErrAdmission) {
		t.Fatal("wrong producer reached process launch", err)
	}
}

// full_only: false
func TestNativeLaunchCarriesExactCanonicalIntent(t *testing.T) {
	launcher, command, _ := testLauncher(t, "success", []byte("private-value"))
	intent, err := protocol.EncodeIntent(protocol.Intent{Schema: 1, ConfigContractID: protocol.ID(launcher.config.Artifact.ConfigContractID), LifecycleMode: protocol.LifecycleManaged, ResourceContractID: command.ResourceContractID, Settings: []byte(`{"author-data":"\u0061","number":1.00}`)})
	if err != nil {
		t.Fatal(err)
	}
	command.Intent = intent
	command.IntentDigest = generatorIntentDigestForTest(intent)
	result, status, err := startAndRead(t, launcher, command)
	if err != nil || status != (protocol.Status{Stage: 5}) || result.SafeFacts.IntentDigest != command.IntentDigest {
		t.Fatal("canonical intent bytes changed across native boundary", status, err)
	}
	clear(result.Value)
}

// full_only: false
func TestExpiredCommandDoesNotReachChildCommand(t *testing.T) {
	launcher, command, _ := testLauncher(t, "success", []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
	command.DeadlineUnixMillis = uint64(time.Now().Add(-time.Second).UnixMilli())
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFile(reader)
	if _, err := launcher.Start(context.Background(), command, writer); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expired command reached native launch", err)
	}
	probe, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if launcher.WaitCommand(probe) {
		t.Fatal("expired command crossed the child boundary")
	}
}

// full_only: false
func TestNativeLaunchCapsWholeChildCommandAtNinetySeconds(t *testing.T) {
	launcher, command, _ := testLauncher(t, "deadline-cap", []byte("private-value"))
	command.DeadlineUnixMillis = uint64(time.Now().Add(24 * time.Hour).UnixMilli())
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFile(reader)
	var deadline time.Time
	var hasDeadline bool
	launcher.beforeSourceCopy = func(ctx context.Context) { deadline, hasDeadline = ctx.Deadline() }
	before := time.Now()
	run, err := launcher.Start(t.Context(), command, writer)
	if err != nil {
		t.Fatal(err)
	}
	if !hasDeadline || deadline.Before(before) || deadline.After(time.Now().Add(90*time.Second)) {
		_ = run.Cancel()
		t.Fatal("host launch lacks complete finite deadline")
	}
	body, readErr := protocol.ReadExpectedFrame(reader, protocol.KindResult, run.CommandID(), protocol.MaximumResultBody)
	if readErr == nil {
		readErr = protocol.RequireEOF(reader)
	}
	result, decodeErr := protocol.DecodeResult(body)
	status, waitErr := run.Wait(t.Context())
	defer clear(body)
	if readErr != nil || decodeErr != nil || waitErr != nil || status != (protocol.Status{Stage: 5}) || len(result.SafeFacts.ProviderFacts) != 8 || binary.BigEndian.Uint64(result.SafeFacts.ProviderFacts) != command.DeadlineUnixMillis {
		t.Fatal("admitted deadline changed or child failed to join", readErr, decodeErr, waitErr, status)
	}
}

// full_only: false
func TestMalformedCommandRefusesBeforeCredentialReadOrChildStart(t *testing.T) {
	credential := []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	for _, tc := range []struct {
		name   string
		change func(*protocol.Command)
	}{
		{"zero fixed identity", func(command *protocol.Command) { command.RequestIdentityDigest = protocol.ID{} }},
		{"invalid action target", func(command *protocol.Command) { command.Action = protocol.ActionRetire }},
		{"oversized intent", func(command *protocol.Command) {
			command.Intent = bytes.Repeat([]byte{'x'}, protocol.MaximumIntentLength+1)
		}},
		{"zero deadline", func(command *protocol.Command) { command.DeadlineUnixMillis = 0 }},
		{"overflow deadline", func(command *protocol.Command) { command.DeadlineUnixMillis = ^uint64(0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			launcher, command, _ := testLauncher(t, "success", credential)
			t.Setenv("ENKV_GENERATOR_TEST_TOKEN", strings.Repeat("x", protocol.MaximumEnvironmentBody))
			tc.change(&command)
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer closeFile(reader)
			if _, err := launcher.Start(context.Background(), command, writer); !errors.Is(err, ErrAdmission) || launcher.started {
				t.Fatal("malformed command reached credential or child launch", err)
			}
			probe, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			if launcher.WaitCommand(probe) {
				t.Fatal("malformed command crossed child command boundary")
			}
		})
	}
}

// full_only: false
func TestHighDescriptorSentinelIsRejectedAndParentHighDescriptorsStayClosed(t *testing.T) {
	var files []*os.File
	defer func() { closeFiles(files...) }()
	for len(files) < 1024 {
		file, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
		if file.Fd() > 255 {
			break
		}
	}
	if len(files) == 0 || files[len(files)-1].Fd() <= 255 {
		t.Fatal("test did not obtain a parent descriptor above 255")
	}
	launcher, command, _ := testLauncher(t, "success", []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
	result, status, err := startAndRead(t, launcher, command)
	clear(result.Value)
	if err != nil || status != (protocol.Status{Stage: 5}) {
		t.Fatal("closed high parent descriptors disrupted child", status, err)
	}
	launcher, command, _ = testLauncher(t, "high-fd-sentinel", []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFile(reader)
	if _, err := launcher.Start(context.Background(), command, writer); err == nil {
		t.Fatal("child descriptor scan stopped before the high sentinel")
	}
}

func generatorIntentDigestForTest(value []byte) protocol.ID {
	hash := sha256.New()
	_, _ = hash.Write([]byte("ENKV/GENERATOR/v1/intent-v3\x00"))
	var length [4]byte
	length[0], length[1], length[2], length[3] = byte(len(value)>>24), byte(len(value)>>16), byte(len(value)>>8), byte(len(value))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write(value)
	var out protocol.ID
	copy(out[:], hash.Sum(nil))
	return out
}

// full_only: false
func TestLaunchDeadlineSurvivesReturnedResult(t *testing.T) {
	launcher, command, _ := testLauncher(t, "stall-after-result", []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	run, err := launcher.Start(ctx, command, writer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.ReadExpectedFrame(reader, protocol.KindResult, run.CommandID(), protocol.MaximumResultBody); err != nil {
		t.Fatal("returned result not received", err)
	}
	if err := protocol.RequireEOF(reader); err != nil {
		t.Fatal("result descriptor remained open", err)
	}
	_ = reader.Close()
	started := time.Now()
	if _, err := run.Wait(context.Background()); err == nil || time.Since(started) > 5*time.Second {
		t.Fatal("launch deadline did not stop the stalled child", err, time.Since(started))
	}
	if _, err := os.Stat(run.(*nativeRun).launchDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stalled launch directory survived joined child", err)
	}
}

// full_only: false
func TestNativeLaunchCancellationJoinsChild(t *testing.T) {
	launcher, command, _ := testLauncher(t, "hang", []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader, writer, _ := os.Pipe()
	run, err := launcher.Start(ctx, command, writer)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	_, readErr := protocol.ReadFrame(reader, protocol.MaximumResultBody)
	_ = reader.Close()
	if readErr == nil {
		t.Fatal("cancelled child returned a result")
	}
	if _, err := run.Wait(context.Background()); err == nil {
		t.Fatal("cancelled child reported success")
	}
	if _, err := os.Stat(run.(*nativeRun).launchDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("launch directory survived joined child", err)
	}
}

// full_only: false
func TestCancellationBeforeLaunchDoesNotReadCredential(t *testing.T) {
	launcher, command, _ := testLauncher(t, "success", bytes.Repeat([]byte("x"), protocol.MaximumEnvironmentBody))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reader, writer, _ := os.Pipe()
	defer closeFile(reader)
	if _, err := launcher.Start(ctx, command, writer); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled launch reached the credential", err)
	}
}

// full_only: false
func TestBlockedHandshakeCancellationJoinsChild(t *testing.T) {
	launcher, command, _ := testLauncher(t, "hang-handshake", []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	reader, writer, _ := os.Pipe()
	defer closeFile(reader)
	started := time.Now()
	if _, err := launcher.Start(ctx, command, writer); err == nil || time.Since(started) > 5*time.Second {
		t.Fatal("blocked handshake did not cancel and join", err, time.Since(started))
	}
}

// full_only: false
func TestResultDescriptorIsWriteOnlyPipe(t *testing.T) {
	launcher, command, _ := testLauncher(t, "success", []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
	file, err := os.Create(filepath.Join(t.TempDir(), "not-a-pipe"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := launcher.Start(context.Background(), command, file); !errors.Is(err, ErrAdmission) {
		t.Fatal("regular secret descriptor passed", err)
	}
	launcher, command, _ = testLauncher(t, "success", []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
	reader, writer, _ := os.Pipe()
	_ = writer.Close()
	if _, err := launcher.Start(context.Background(), command, reader); !errors.Is(err, ErrAdmission) {
		t.Fatal("read-only secret descriptor passed", err)
	}
}

// full_only: false
func TestFixedOwnershipLedgerFitsBudget(t *testing.T) {
	const processBudget = 1664 << 20
	if ParentFixedOwnedBytes <= 0 || ChildFixedOwnedBytes <= 0 || ParentFixedOwnedBytes+ChildFixedOwnedBytes >= processBudget {
		t.Fatal("generator host ownership ledger exceeds the process budget")
	}
}

// full_only: false
func TestSourceTreeHasNoEmbeddedCredential(t *testing.T) {
	body, err := os.ReadFile("host.go")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ")) {
		t.Fatal("test credential entered production source")
	}
	clear(body)
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("native boundary is specified only for Darwin and Linux")
	}
	if _, err := io.Discard.Write(nil); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestNativeInheritedDescriptorClosesOnlyInChild(t *testing.T) {
	const inheritedDescriptor = 512
	if encoded := os.Getenv("ENKV_TEST_NATIVE_INHERITED_LAUNCH"); encoded != "" {
		var input struct {
			Config  Config
			Command protocol.Command
		}
		if err := json.Unmarshal([]byte(encoded), &input); err != nil {
			t.Fatal(err)
		}
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, inheritedDescriptor, syscall.F_GETFD, 0)
		if errno != 0 || flags&syscall.FD_CLOEXEC != 0 {
			t.Fatal("fixture did not inherit a non-close-on-exec high descriptor")
		}
		launcher, err := newHermeticNative(input.Config)
		if err != nil {
			t.Fatal("fixture constructor refused", err)
		}
		result, status, err := startAndRead(t, launcher, input.Command)
		clear(result.Value)
		after, _, afterErr := syscall.Syscall(syscall.SYS_FCNTL, inheritedDescriptor, syscall.F_GETFD, 0)
		if afterErr != 0 || after != flags {
			t.Fatal("launcher changed caller descriptor ownership or flags")
		}
		t.Logf("inherited_descriptor=%d caller_descriptor_preserved=true child_joined=true launch_success=%t", inheritedDescriptor, err == nil)
		if err != nil || status != (protocol.Status{Stage: 5}) {
			t.Fatal("inherited parent descriptor disrupted admitted child", status, err)
		}
		return
	}
	launcher, command, _ := testLauncher(t, "success", []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
	encoded, err := json.Marshal(struct {
		Config  Config
		Command protocol.Command
	}{launcher.config, command})
	if err != nil {
		t.Fatal(err)
	}
	sentinel, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := sentinel.Close(); err != nil {
			t.Error("close sentinel", err)
		}
	}()
	child := exec.Command(os.Args[0], "-test.run=^TestNativeInheritedDescriptorClosesOnlyInChild$", "-test.v")
	child.Env = append(os.Environ(), "ENKV_TEST_NATIVE_INHERITED_LAUNCH="+string(encoded))
	child.ExtraFiles = make([]*os.File, inheritedDescriptor-2)
	child.ExtraFiles[inheritedDescriptor-3] = sentinel
	output, err := child.CombinedOutput()
	if err != nil {
		t.Fatalf("inherited descriptor launch failed: %v\n%s", err, output)
	}
	t.Logf("fresh_parent_joined=true\n%s", output)
}

// hostTraceCapture observes attributes at the actual tracer boundary without
// installing a global provider or adding an SDK dependency to the native host.
type hostTraceCapture struct {
	trace.Tracer
	mu    sync.Mutex
	spans []*hostCapturedSpan
}

type hostCapturedSpan struct {
	trace.Span
	mu         sync.Mutex
	name       string
	attributes []attribute.KeyValue
	ended      bool
}

func (capture *hostTraceCapture) Start(ctx context.Context, name string, options ...trace.SpanStartOption) (context.Context, trace.Span) {
	_, base := capture.Tracer.Start(ctx, name, options...)
	config := trace.NewSpanStartConfig(options...)
	span := &hostCapturedSpan{Span: base, name: name, attributes: config.Attributes()}
	capture.mu.Lock()
	capture.spans = append(capture.spans, span)
	capture.mu.Unlock()
	return trace.ContextWithSpan(ctx, span), span
}

func (span *hostCapturedSpan) SetAttributes(attributes ...attribute.KeyValue) {
	span.mu.Lock()
	defer span.mu.Unlock()
	span.attributes = append(span.attributes, attributes...)
}

func (span *hostCapturedSpan) End(...trace.SpanEndOption) {
	span.mu.Lock()
	defer span.mu.Unlock()
	span.ended = true
}

func (capture *hostTraceCapture) assertSafe(t *testing.T, records []telemetry.DiagnosticRecord, excluded ...string) {
	t.Helper()
	returns := map[string]telemetry.DiagnosticRecord{}
	starts := 0
	for _, record := range records {
		if err := record.Validate(); err != nil {
			t.Fatal(err)
		}
		if record.Path != "" || record.PathKind != "" {
			t.Fatal("host diagnostic disclosed an executable path")
		}
		if record.Event == telemetry.DiagnosticStart {
			starts++
		}
		if record.Event == telemetry.DiagnosticReturn {
			returns[string(record.Operation)] = record
		}
	}
	encoded, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range excluded {
		if value != "" && bytes.Contains(encoded, []byte(value)) {
			t.Fatal("host diagnostic captured private path or payload")
		}
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if len(capture.spans) == 0 || len(capture.spans) != starts {
		t.Fatal("host span and diagnostic starts differ")
	}
	for _, span := range capture.spans {
		span.mu.Lock()
		ended := span.ended
		attrs := append([]attribute.KeyValue(nil), span.attributes...)
		span.mu.Unlock()
		if !ended {
			t.Fatal("host retained an unfinished span", span.name)
		}
		var provider, operation, result, reason, command string
		for _, attr := range attrs {
			switch string(attr.Key) {
			case "path", "path.kind":
				t.Fatal("host span disclosed an executable path")
			case "provider":
				provider = attr.Value.AsString()
			case "operation":
				operation = attr.Value.AsString()
			case "result":
				result = attr.Value.AsString()
			case "reason":
				reason = attr.Value.AsString()
			case "command.id":
				command = attr.Value.AsString()
			}
		}
		record, exists := returns[span.name]
		if !exists || provider != string(telemetry.ProviderGeneratorHost) || operation != span.name || result != string(record.Result) || reason != string(record.Reason) || command != record.CommandID {
			t.Fatal("host span lost exact stage/result identity")
		}
		encoded, err := json.Marshal(attrs)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range excluded {
			if value != "" && bytes.Contains(encoded, []byte(value)) {
				t.Fatal("host span captured private path or payload")
			}
		}
	}
}

// full_only: false
func TestNativeGeneratorCancellationOwnsEachEndpoint(t *testing.T) {
	for _, mode := range []string{"hold-handshake", "hold-handshake-short", "hold-control", "hold-credential", "hold-status", "hold-status-short", "hold-status-eof"} {
		t.Run(mode, func(t *testing.T) {
			credential := []byte("private fixture credential")
			if mode == "hold-credential" {
				// Schema/count, name length, name, presence and value length use 9+name bytes.
				credential = bytes.Repeat([]byte{'x'}, protocol.MaximumEnvironmentBody-9-len("ENKV_GENERATOR_TEST_TOKEN"))
			}
			launcher, command, path := testLauncher(t, mode, credential)
			if mode == "hold-control" {
				var err error
				command.Intent, err = protocol.EncodeIntent(protocol.Intent{Schema: 1, ConfigContractID: protocol.ID(launcher.Implementation().ConfigContractID), LifecycleMode: protocol.LifecycleManaged, ResourceContractID: testID(22), Settings: []byte(`"` + strings.Repeat("x", 200000) + `"`)})
				if err != nil {
					t.Fatal(err)
				}
				command.IntentDigest, err = protocol.IntentDigest(command.Intent)
				if err != nil {
					t.Fatal(err)
				}
			}
			listener := endpointHolderListener(t, filepath.Dir(path))
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := reader.Close(); err != nil {
					t.Error(err)
				}
			}()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				run, err := launcher.Start(ctx, command, writer)
				if err == nil {
					_, readErr := io.Copy(io.Discard, reader)
					_, waitErr := run.Wait(ctx)
					err = errors.Join(readErr, waitErr)
				}
				done <- err
			}()
			holder := receiveHeldEndpoint(t, listener)
			assertEndpointCancellation(t, cancel, done, holder)
			assertNoLaunchDescriptors(t, path)
		})
	}
}

func endpointHolderListener(t *testing.T, directory string) *net.UnixListener {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "enkv-pipe-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	path := filepath.Join(root, "holder")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := os.WriteFile(filepath.Join(directory, ".endpoint-socket"), []byte(path), 0600); err != nil {
		t.Fatal(err)
	}
	return listener
}

func receiveHeldEndpoint(t *testing.T, listener *net.UnixListener) *os.File {
	t.Helper()
	if err := listener.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	connection, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal("fixture did not reach the selected endpoint", err)
	}
	defer func() {
		if err := connection.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	data, rights := make([]byte, 1), make([]byte, syscall.CmsgSpace(4))
	n, count, _, _, err := connection.ReadMsgUnix(data, rights)
	if err != nil || n != 1 || data[0] != 1 {
		t.Fatal("fixture descriptor transfer failed", err)
	}
	messages, err := syscall.ParseSocketControlMessage(rights[:count])
	if err != nil || len(messages) != 1 {
		t.Fatal("fixture descriptor rights unavailable", err)
	}
	fds, err := syscall.ParseUnixRights(&messages[0])
	if err != nil || len(fds) != 1 {
		t.Fatal("fixture transferred an unexpected endpoint set", err)
	}
	holder := os.NewFile(uintptr(fds[0]), "test held opposite endpoint")
	t.Cleanup(func() {
		if err := holder.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Error(err)
		}
	})
	// The fixture closes all original protocol ends before closing this socket.
	if _, err := io.Copy(io.Discard, connection); err != nil {
		t.Fatal("fixture did not relinquish its original endpoints", err)
	}
	return holder
}

func assertEndpointCancellation(t *testing.T, cancel context.CancelFunc, done <-chan error, holder *os.File) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatal("exchange returned before its retained opposite endpoint was released", err)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	var result error
	select {
	case result = <-done:
	case <-time.After(time.Second):
		if err := holder.Close(); err != nil {
			t.Error(err)
		}
		select {
		case result = <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("exchange failed to join after test endpoint release")
		}
		t.Error("cancellation did not close its own blocked endpoint")
	}
	if !errors.Is(result, context.Canceled) {
		t.Error("endpoint cancellation cause was lost", result)
	}
}

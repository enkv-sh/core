package outputhost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
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

	"enkv.sh/sdk/artifact"
	protocol "enkv.sh/sdk/protocols/output"
	"enkv.sh/telemetry"
)

func testArtifactAndConfig(t *testing.T, endpoint ...string) Config {
	t.Helper()
	root := t.TempDir()
	pluginDir := filepath.Join("..", "..", "tests", "fixtures", "output-contract-test")
	path := filepath.Join(root, "enkv-output-contract-test")
	build := exec.CommandContext(t.Context(), "go", "build", "-trimpath", "-buildvcs=false", "-o", path, "./cmd/enkv-output-contract-test")
	if len(endpoint) != 0 {
		build.Args = append(build.Args[:2], append([]string{"-ldflags=-X=main.endpointHold=" + endpoint[0] + " -X=main.endpointSocket=" + endpoint[1]}, build.Args[2:]...)...)
	}
	build.Dir = pluginDir
	build.Env = testOutputBuildEnvironment(false)
	prepareNativeModule(t, filepath.Join("..", ".."), build, path+".mod")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build test plugin: %v: %s", err, out)
	}
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", root)
	t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", "private credential")
	descriptorBody, err := os.ReadFile(filepath.Join(pluginDir, "cmd", "enkv-output-contract-test", "plugin.json"))
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := artifact.DecodeDescriptor(descriptorBody)
	if err != nil {
		t.Fatal(err)
	}
	installation := testBindExecutable(t, path, pluginDir, descriptor, false)
	return Config{ArtifactPath: path, Installation: installation}
}
func testBindExecutable(t *testing.T, path, directory string, descriptor artifact.Descriptor, race bool) *Installation {
	t.Helper()
	dependency := testBuildDependencyManifest(t, path, directory, race, descriptor)
	facts, err := artifact.DecodeDependency(dependency)
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	metadata, dependency := metadataFromBuildFacts(t, facts, descriptor, sha256.Sum256(binary), uint64(len(binary)))
	body, err := artifact.EncodeMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".metadata", body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".dependencies", dependency, 0600); err != nil {
		t.Fatal(err)
	}
	installation, err := NewInstallation(metadata, dependency)
	if err != nil {
		t.Fatal(err)
	}
	return installation
}
func testNativeTuple() string { return runtime.GOOS + "/" + runtime.GOARCH }
func testOutputCommand(t *testing.T, a Artifact, target string) (protocol.Command, protocol.Policy, []byte) {
	t.Helper()
	policy := protocol.Policy{ContractID: "test-policy", Data: []byte("7,11")}
	domain := protocol.ID(sha256.Sum256([]byte("test domain")))
	digest, err := protocol.PolicyDigest(domain, policy)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("private data")
	return protocol.Command{Schema: 1, Action: protocol.ActionCreateWithValue, DomainID: domain,
		OperationID: sha256.Sum256([]byte("operation")), AttemptID: sha256.Sum256([]byte("attempt")), CoordinateID: sha256.Sum256([]byte("coordinate")), ProjectionCommitment: sha256.Sum256([]byte("projection")), DispatchContextDigest: sha256.Sum256([]byte("dispatch")), RequestContractDigest: sha256.Sum256([]byte("request")), ResponseContractDigest: sha256.Sum256([]byte("response")), DescriptorID: a.DescriptorID, CredentialRouteID: a.CredentialRouteID, PolicyDigest: digest, PolicyContractID: policy.ContractID,
		BindingIncarnationID: sha256.Sum256([]byte("binding")), EntryIncarnationID: sha256.Sum256([]byte("entry")), TargetRowDigest: sha256.Sum256([]byte("target row")), ValueBasisDigest: sha256.Sum256([]byte("value basis")), DeadlineUnixMillis: uint64(time.Now().Add(10 * time.Second).UnixMilli()), PayloadLengthMode: protocol.LengthExact, PayloadLength: uint32(len(payload)), BindingDestinationID: "test-destination",
		Target: protocol.Target{ServiceContractID: "test-output/service/v1", TargetContractID: "test-output/target/v1", CanonicalTarget: target, ConsumerLocator: target, TargetData: []byte("public"), PayloadEncoding: protocol.EncodingRaw, Capabilities: protocol.CapabilityCreateEmpty | protocol.CapabilityCreateWithValue | protocol.CapabilityWriteValue | protocol.CapabilityUpdatePolicy | protocol.CapabilityDeleteOwned | protocol.CapabilityDeleteReservedSlot | protocol.CapabilityCreateSetsPolicy | protocol.CapabilityWriteSetsPolicy, CreateValueBounds: protocol.PayloadBounds{Maximum: 65536}, WriteValueBounds: protocol.PayloadBounds{Maximum: 65536}}}, policy, payload
}

// full_only: false
func TestNativeOutputPositiveJoinAndOneUse(t *testing.T) {
	config := testArtifactAndConfig(t)
	missing := config
	missing.Installation = nil
	if _, err := NewNative(t.Context(), missing); !errors.Is(err, ErrAdmission) {
		t.Fatalf("missing installation accepted: %v", err)
	}
	native, err := NewNative(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	command, policy, payload := testOutputCommand(t, config.Installation.Artifact(), "fixture")
	result, err := native.Dispatch(context.Background(), command, policy, payload)
	if err != nil || result.Class != protocol.ClassAcknowledged || result.NormalizedStatus != 201 {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if _, err := native.Dispatch(context.Background(), command, policy, payload); !errors.Is(err, ErrAdmission) {
		t.Fatalf("reused launcher err=%v", err)
	}
	assertNoStagedChild(t, config.ArtifactPath)
}

// full_only: false
func TestNativeOutputRefusesCreateWithoutResourceIdentity(t *testing.T) {
	config := testArtifactAndConfig(t)
	t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", "test-result-create-without-resource")
	native, err := NewNative(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	command, policy, payload := testOutputCommand(t, config.Installation.Artifact(), "fixture")
	recorder := telemetry.NewRecorder()
	ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
	result, err := native.Dispatch(ctx, command, policy, payload)
	if !errors.Is(err, protocol.ErrProtocol) || result != (protocol.Result{}) {
		t.Error("independent malformed create acquired a result", result, err)
	}
	joined := false
	for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 32)) {
		if err := record.Validate(); err != nil {
			t.Fatal(err)
		}
		if record.Event == telemetry.DiagnosticReturn && record.Operation == telemetry.OpOutputHostJoin {
			joined = true
		}
	}
	if !joined {
		t.Error("invalid result returned without child settlement")
	}
	if _, err := native.Dispatch(ctx, command, policy, payload); !errors.Is(err, ErrAdmission) {
		t.Error("invalid result restored a send permission", err)
	}
	assertNoStagedChild(t, config.ArtifactPath)
}

// full_only: false
func TestNativeOutputArmDiffersFromEmptyValuePayload(t *testing.T) {
	for _, tc := range []struct {
		name, target string
		action       protocol.Action
	}{
		{"metadata arm", "fixture", protocol.ActionCreateEmpty},
		{"empty raw value", "empty-value", protocol.ActionCreateWithValue},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := testArtifactAndConfig(t)
			native, err := NewNative(t.Context(), config)
			if err != nil {
				t.Fatal(err)
			}
			command, policy, _ := testOutputCommand(t, config.Installation.Artifact(), tc.target)
			command.Action = tc.action
			command.PayloadLength = 0
			if tc.action == protocol.ActionCreateEmpty {
				command.PayloadLengthMode = protocol.LengthAbsent
				command.ValueBasisDigest = protocol.ID{}
			}
			result, err := native.Dispatch(context.Background(), command, policy, nil)
			if err != nil || result.Class != protocol.ClassAcknowledged || result.NormalizedStatus != 201 {
				t.Fatalf("result=%#v err=%v", result, err)
			}
			assertNoStagedChild(t, config.ArtifactPath)
		})
	}
}

// full_only: false
func TestNativeOutputDescriptorRefusedBeforeCredential(t *testing.T) {
	config := testArtifactAndConfig(t)
	native, err := NewNative(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", "")
	command, policy, payload := testOutputCommand(t, config.Installation.Artifact(), "fixture")
	command.DescriptorID[0] ^= 1
	if _, err := native.Dispatch(context.Background(), command, policy, payload); !errors.Is(err, ErrAdmission) {
		t.Fatalf("wrong provider reached credential route: %v", err)
	}
	assertNoStagedChild(t, config.ArtifactPath)
}

// full_only: false
func TestNativeOutputBadCredentialNeverGetsPayload(t *testing.T) {
	config := testArtifactAndConfig(t)
	t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", "bad credential")
	native, err := NewNative(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	command, policy, payload := testOutputCommand(t, config.Installation.Artifact(), "fixture")
	if _, err := native.Dispatch(context.Background(), command, policy, payload); !errors.Is(err, ErrCredential) {
		t.Fatalf("bad credential err=%v", err)
	}
	assertNoStagedChild(t, config.ArtifactPath)
}

// full_only: false
func TestNativeCredentialGateNeedsExplicitCleanRefusal(t *testing.T) {
	for _, tc := range []struct {
		name, credential string
		wantError        error
		wantJoin         telemetry.Result // Empty permits either observed termination after malformed bytes.
	}{
		{"rejected credential", "bad credential", ErrCredential, telemetry.ResultSuccess},
		{"child exits before Ready", "test-exit-before-ready", ErrProcess, telemetry.ResultFailure},
		{"child exits after refusal 66", "test-refuse-exit66", ErrProcess, telemetry.ResultFailure},
		{"child exits after refusal 17", "test-refuse-exit17", ErrProcess, telemetry.ResultFailure},
		{"malformed refusal", "test-refuse-malformed", protocol.ErrProtocol, ""},
		{"wrong correlation", "test-refuse-wrong-correlation", protocol.ErrProtocol, ""},
		{"nonzero body", "test-refuse-nonzero-body", protocol.ErrProtocol, ""},
		{"trailing byte", "test-refuse-trailing-byte", protocol.ErrProtocol, ""},
		{"duplicate frame", "test-refuse-duplicate-frame", protocol.ErrProtocol, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := testArtifactAndConfig(t)
			t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", tc.credential)
			native, err := NewNative(t.Context(), config)
			if err != nil {
				t.Fatal(err)
			}
			command, policy, payload := testOutputCommand(t, config.Installation.Artifact(), "fixture")
			recorder := telemetry.NewRecorder()
			ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
			result, err := native.Dispatch(ctx, command, policy, payload)
			if !errors.Is(err, tc.wantError) {
				t.Fatalf("credential gate cause=%v, want %v", err, tc.wantError)
			}
			if tc.wantError == ErrCredential {
				want := command.NewResult()
				want.Entry, want.Class = protocol.EntryNotEntered, protocol.ClassQualifiedNoEffect
				if result != want {
					t.Errorf("complete pre-arm refusal lost its exact no-effect result: %+v", result)
				}
				if !errors.Is(err, ErrCredential) || errors.Is(err, ErrProcess) {
					t.Fatalf("credential refusal cause=%v", err)
				}
			} else {
				if result != (protocol.Result{}) {
					t.Errorf("incomplete refusal acquired a result: %+v", result)
				}
				if errors.Is(err, ErrCredential) {
					t.Fatalf("unproved child failure classified as credential refusal: %v", err)
				}
			}
			joined, credentialGate, resultRead := false, false, false
			for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 24)) {
				if err := record.Validate(); err != nil {
					t.Fatal(err)
				}
				if record.Event != telemetry.DiagnosticReturn {
					continue
				}
				switch record.Operation {
				case telemetry.OpOutputHostJoin:
					joined = true
					if tc.wantJoin != "" && record.Result != tc.wantJoin {
						t.Fatalf("child exit classified %s, want %s", record.Result, tc.wantJoin)
					}
				case telemetry.OpOutputHostCredentialGate:
					credentialGate = true
				case telemetry.OpOutputHostResultRead:
					resultRead = true
				}
			}
			if !joined || !credentialGate || resultRead {
				t.Fatalf("child gate/join/result phases: join=%t credential=%t result=%t", joined, credentialGate, resultRead)
			}
			assertNoStagedChild(t, config.ArtifactPath)
		})
	}
}

// full_only: false
func TestNativeOutputCancellationJoinsChild(t *testing.T) {
	config := testArtifactAndConfig(t)
	native, err := NewNative(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	command, policy, payload := testOutputCommand(t, config.Installation.Artifact(), "sleep")
	recorder := telemetry.NewRecorder()
	base := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
	ctx, cancel := context.WithTimeout(base, time.Second)
	defer cancel()
	if _, err := native.Dispatch(ctx, command, policy, payload); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancellation err=%v", err)
	}
	assertNoStagedChild(t, config.ArtifactPath)
	seen := map[telemetry.Operation]bool{}
	joinWasReportedSuccessful, expired := false, false
	for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 32)) {
		if err := record.Validate(); err != nil {
			t.Fatal(err)
		}
		if record.Event == telemetry.DiagnosticReturn {
			seen[record.Operation] = true
			if record.Operation == telemetry.OpOutputHostJoin && record.Result == telemetry.ResultSuccess {
				joinWasReportedSuccessful = true
			}
			if record.Operation == telemetry.OpOutputHostDispatch && record.Result == telemetry.ResultExpired {
				expired = true
			}
		}
	}
	if !seen[telemetry.OpOutputHostCancel] || !seen[telemetry.OpOutputHostJoin] || !seen[telemetry.OpOutputHostDispatch] {
		t.Fatalf("cancellation did not return through output diagnostics: %+v", seen)
	}
	if joinWasReportedSuccessful {
		t.Fatal("canceled child join was reported as successful child completion")
	}
	if !expired {
		t.Fatal("ordinary send expiry lost its Expired disposition")
	}
}

// full_only: false
func TestNativeOutputCancellationOwnsEachEndpoint(t *testing.T) {
	for _, mode := range []string{"control", "credential", "payload", "result", "result-short", "result-eof", "refusal-eof"} {
		t.Run(mode, func(t *testing.T) {
			listener := endpointHolderListener(t, t.TempDir())
			config := testArtifactAndConfig(t, mode, listener.Addr().String())
			native, err := NewNative(t.Context(), config)
			if err != nil {
				t.Fatal(err)
			}
			command, policy, payload := testOutputCommand(t, config.Installation.Artifact(), "fixture")
			if mode == "control" {
				policy.Data = bytes.Repeat([]byte{'p'}, protocol.MaximumPolicyBytes-256)
				command.PolicyDigest, err = protocol.PolicyDigest(command.DomainID, policy)
				if err != nil {
					t.Fatal(err)
				}
			}
			if mode == "credential" {
				t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", strings.Repeat("x", protocol.MaximumCredentialBytes-9-len("ENKV_OUTPUT_TEST_CREDENTIAL")))
			}
			if mode == "payload" {
				payload = bytes.Repeat([]byte{'x'}, protocol.MaximumPayloadBytes)
				command.PayloadLength = uint32(len(payload))
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			done := make(chan error, 1)
			var result protocol.Result
			go func() {
				var err error
				result, err = native.Dispatch(ctx, command, policy, payload)
				done <- err
			}()
			holder := receiveHeldEndpoint(t, listener)
			assertEndpointCancellation(t, cancel, done, holder)
			if result != (protocol.Result{}) {
				t.Fatal("incomplete canceled exchange acquired a qualified result", result)
			}
			if _, err := native.Dispatch(context.Background(), command, policy, payload); !errors.Is(err, ErrAdmission) {
				t.Fatal("canceled exchange restored a send permission", err)
			}
			assertNoStagedChild(t, config.ArtifactPath)
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

// full_only: false
func TestOwnedEndpointReleaseJoinsEnteredCancellation(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := writer.Close(); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithCancel(t.Context())
	endpoint := ownEndpoint(ctx, reader)
	if !endpoint.stop() {
		t.Fatal("original endpoint callback entered before controlled replacement")
	}
	callbackEntered := make(chan struct{})
	endpoint.done = make(chan struct{})
	endpoint.stop = context.AfterFunc(ctx, func() {
		defer close(endpoint.done)
		close(callbackEntered)
		if err := endpoint.close(); err != nil {
			t.Error(err)
		}
	})
	closeEntered, allowClose, closeDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	releaseClose := func() { unblock.Do(func() { close(allowClose) }) }
	done := make(chan error, 1)
	started, joined := false, false
	t.Cleanup(func() {
		releaseClose()
		cancel()
		waitEndpointSignal(t, closeDone, "controlled close did not join")
		waitEndpointSignal(t, endpoint.done, "cancellation callback did not join")
		if started && !joined {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("endpoint release did not settle")
			}
		}
	})
	go func() {
		endpoint.closeOnce.Do(func() {
			close(closeEntered)
			<-allowClose
			endpoint.closeErr = endpoint.Close()
		})
		close(closeDone)
	}()
	if !waitEndpointSignal(t, closeEntered, "controlled close did not enter") {
		return
	}
	cancel()
	if !waitEndpointSignal(t, callbackEntered, "controlled cancellation callback did not enter") {
		return
	}
	started = true
	go func() { done <- endpoint.release() }()
	select {
	case err := <-done:
		joined = true
		t.Error("release returned while cancellation close was entered", err)
		return
	case <-time.After(50 * time.Millisecond):
	}
	if _, err := reader.Stat(); err != nil {
		t.Error("descriptor closed before the controlled close completed", err)
	}
	releaseClose()
	select {
	case err := <-done:
		joined = true
		if err != nil {
			t.Error(err)
		}
	case <-time.After(5 * time.Second):
		t.Error("release did not join the entered cancellation close")
		return
	}
	select {
	case <-endpoint.done:
	default:
		t.Error("release did not join the cancellation callback")
	}
}

func waitEndpointSignal(t *testing.T, signal <-chan struct{}, failure string) bool {
	t.Helper()
	select {
	case <-signal:
		return true
	case <-time.After(5 * time.Second):
		t.Error(failure)
		return false
	}
}

// full_only: false
func TestOwnedEndpointReleaseRetainsCloseFailure(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal close", true: "cancellation close"}[canceled], func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := writer.Close(); err != nil {
					t.Error(err)
				}
			}()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			endpoint := ownEndpoint(ctx, reader)
			if err := reader.Close(); err != nil {
				t.Fatal(err)
			}
			if canceled {
				cancel()
				if !waitEndpointSignal(t, endpoint.done, "canceled close-fault callback did not join") {
					return
				}
			}
			done := make(chan [2]error, 1)
			go func() { done <- [2]error{endpoint.release(), endpoint.release()} }()
			select {
			case result := <-done:
				if !errors.Is(result[0], os.ErrClosed) || result[0] != result[1] {
					t.Fatal("required descriptor close failure was lost or replaced", result[0], result[1])
				}
			case <-time.After(5 * time.Second):
				t.Fatal("repeated release did not settle")
			}
		})
	}
}

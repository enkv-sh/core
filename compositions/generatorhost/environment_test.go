package generatorhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/sdk/artifact/credentialroute"
	protocol "enkv.sh/sdk/protocols/generator"
	"enkv.sh/telemetry"
)

func environmentImplementation(t *testing.T, path string) contract.GeneratorImplementation {
	return boundImplementation(t, path)
}
func capturedValue(t *testing.T, row contract.GeneratorImplementation, body []byte) []byte {
	t.Helper()
	route, err := credentialroute.Decode(row.CredentialRoute)
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := credentialroute.DecodeInputs(route, body)
	if err != nil || len(inputs) != 1 {
		t.Fatal("private input decode failed", err)
	}
	return inputs[0].Value
}
func allZero(body []byte) bool {
	for _, value := range body {
		if value != 0 {
			return false
		}
	}
	return true
}

// full_only: false
func TestInstalledGeneratorOwnsDeclaredRouteWithoutCredentialAuthority(t *testing.T) {
	path := buildSDKGenerator(t)
	installed := generatorInstallation(t, path)
	row := installed.Artifact()
	route, err := installed.CredentialRoute()
	if err != nil {
		t.Fatal(err)
	}
	if len(route.Names) != 1 || route.Names[0] != "ENKV_GENERATOR_TEST_TOKEN" {
		t.Fatal("declared route changed")
	}
	route.Names[0] = "CHANGED"
	route.PublicData = append(route.PublicData, 1)
	other, err := installed.CredentialRoute()
	if err != nil || other.Names[0] != "ENKV_GENERATOR_TEST_TOKEN" {
		t.Fatal("published route shares caller memory", err)
	}
	t.Setenv("ENKV_GENERATOR_TEST_TOKEN", "first")
	if _, err := NewNative(t.Context(), Config{Installation: installed, ArtifactPath: path, Artifact: row}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENKV_GENERATOR_TEST_TOKEN", "rotated")
	if !implementationEqual(row, installed.Artifact()) {
		t.Fatal("credential rotation changed public artifact")
	}
	if _, err := NewNative(t.Context(), Config{Installation: installed, ArtifactPath: path, Artifact: row}); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestNativeEnvironmentCredentialReachesOnlyPrivateDescriptor(t *testing.T) {
	const token = "private ordinary token, no provider grammar"
	t.Setenv("ENKV_GENERATOR_TEST_TOKEN", token)
	t.Setenv("ENKV_UNRELATED_PARENT_SENTINEL", "must-not-reach-child")
	path := buildTestGenerator(t, "environment-credential")
	row := environmentImplementation(t, path)
	launcher, err := newHermeticNative(Config{ArtifactPath: path, Artifact: row})
	if err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFile(reader)
	recorder := telemetry.NewRecorder()
	ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
	command := testCommand(row)
	run, err := launcher.Start(ctx, command, writer)
	if err != nil {
		t.Fatal(err)
	}
	owned := run.(*nativeRun)
	private := owned.credential[:cap(owned.credential)]
	if !bytes.Equal(capturedValue(t, row, owned.credential), []byte(token)) {
		_ = run.Cancel()
		t.Fatal("private input changed")
	}
	t.Setenv("ENKV_GENERATOR_TEST_TOKEN", "replacement")
	body, readErr := protocol.ReadExpectedFrame(reader, protocol.KindResult, run.CommandID(), protocol.MaximumResultBody)
	defer clear(body)
	if readErr == nil {
		readErr = protocol.RequireEOF(reader)
	}
	status, waitErr := run.Wait(t.Context())
	if readErr != nil || waitErr != nil || status != (protocol.Status{Stage: 5}) {
		t.Fatal("private descriptor or empty ambient environment failed", readErr, waitErr, status)
	}
	if !allZero(private) {
		t.Fatal("joined invocation retained private input")
	}
	encoded, err := json.Marshal(recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 32)))
	if err != nil || bytes.Contains(encoded, []byte(token)) || bytes.Contains(encoded, command.Intent) || bytes.Contains(encoded, []byte(path)) {
		t.Fatal("private input reached telemetry")
	}
	assertNoLaunchDescriptors(t, path)
}

// full_only: false
func TestEnvironmentCredentialCaptureIsFixedAndBounded(t *testing.T) {
	route := credentialroute.Route{Schema: 1, ContractID: [32]byte{1}, Mode: credentialroute.ModeEnvironment, Names: []string{"ENKV_GENERATOR_TEST_TOKEN"}}
	for _, present := range []bool{false, true} {
		for _, value := range []string{"", "short", "spaces ! ", "line\nend"} {
			t.Setenv("ENKV_GENERATOR_TEST_TOKEN", value)
			if !present {
				if err := os.Unsetenv("ENKV_GENERATOR_TEST_TOKEN"); err != nil {
					t.Fatal(err)
				}
			}
			body, err := readEnvironmentInputs(t.Context(), route)
			if err != nil {
				t.Fatal(err)
			}
			inputs, err := credentialroute.DecodeInputs(route, body)
			if err != nil || len(inputs) != 1 || inputs[0].Present != present || present && string(inputs[0].Value) != value {
				t.Fatal("absence or empty value changed", err)
			}
			t.Setenv("ENKV_GENERATOR_TEST_TOKEN", "replacement")
			if present && string(inputs[0].Value) != value {
				t.Fatal("owned capture followed environment mutation")
			}
			clear(body)
		}
	}
	maximum := credentialroute.MaxInputsBytes - 3 - 6 - len(route.Names[0])
	t.Setenv(route.Names[0], strings.Repeat("x", maximum))
	body, err := readEnvironmentInputs(t.Context(), route)
	if err != nil || len(body) != credentialroute.MaxInputsBytes {
		t.Fatal("complete input maximum refused", err)
	}
	clear(body)
	t.Setenv(route.Names[0], strings.Repeat("x", maximum+1))
	if body, err := readEnvironmentInputs(t.Context(), route); body != nil || !errors.Is(err, ErrCredential) {
		t.Fatal("complete private input overflow admitted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if body, err := readEnvironmentInputs(ctx, route); body != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled input retained bytes", err)
	}
}

// full_only: false
func TestEnvironmentCredentialRefusalHasNoFileFallback(t *testing.T) {
	launcher, command, path := testLauncher(t, "success", bytes.Repeat([]byte("x"), credentialroute.MaxInputsBytes))
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFile(reader)
	if run, err := launcher.Start(t.Context(), command, writer); run != nil || !errors.Is(err, ErrCredential) {
		t.Fatal("overflow acquired an invocation", err)
	}
	assertNoLaunchDescriptors(t, path)
	select {
	case <-launcher.commandSent:
		t.Fatal("failed environment delivery marked complete")
	default:
	}
}

// full_only: false
func TestEnvironmentCancellationClearsOwnedCredentialAfterJoin(t *testing.T) {
	launcher, command, path := testLauncher(t, "hang", []byte("private-value"))
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFile(reader)
	run, err := launcher.Start(t.Context(), command, writer)
	if err != nil {
		t.Fatal(err)
	}
	owned := run.(*nativeRun)
	private := owned.credential[:cap(owned.credential)]
	if len(private) == 0 || allZero(private) {
		_ = run.Cancel()
		t.Fatal("running invocation has no private input owner")
	}
	if err := run.Cancel(); err == nil {
		t.Fatal("cancelled child returned success")
	}
	if owned.cmd.ProcessState == nil || !allZero(private) {
		t.Fatal("cancellation did not join before clearing input")
	}
	assertNoLaunchDescriptors(t, path)
}

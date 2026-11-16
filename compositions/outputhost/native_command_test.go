package outputhost

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enkv.sh/sdk/artifact"
	"enkv.sh/telemetry"
)

// full_only: false
func TestIndependentOutputCommandPassiveAndCredentialGate(t *testing.T) {
	config := testArtifactAndConfig(t)
	assertCapturedClosureRefusedBeforeCredentials(t, config)
	validator, err := NewPublicValidator(t.Context(), config.ArtifactPath, config.Installation)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", "")
	request, policy := testPublicRequest(t, config.Installation.Artifact(), "fixture")
	recorder := telemetry.NewRecorder()
	ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
	if _, err := validator.CheckAction(ctx, request, policy); err != nil {
		t.Fatal("real arbitrary child passive check refused", err)
	}
	assertProductionChildTrace(t, recorder, false)
	assertNoStagedChild(t, config.ArtifactPath)
	t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", "bad credential")
	native, err := NewNative(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	command, policy, payload := testOutputCommand(t, config.Installation.Artifact(), "fixture")
	recorder = telemetry.NewRecorder()
	ctx = telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
	if _, err := native.Dispatch(ctx, command, policy, payload); !errors.Is(err, ErrCredential) {
		t.Fatal("real child credential refusal lost", err)
	}
	assertProductionChildTrace(t, recorder, true)
	assertNoStagedChild(t, config.ArtifactPath)
}

func stagedOutputRoots(t *testing.T, artifactPath string) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(filepath.Dir(artifactPath), ".enkv-output-stage-*"))
	if err != nil {
		t.Fatal(err)
	}
	return paths
}

func assertNoStagedChild(t *testing.T, artifactPath string) {
	t.Helper()
	entries := stagedOutputRoots(t, artifactPath)
	if len(entries) != 0 {
		t.Fatalf("joined child retained private staging roots: %v", entries)
	}
}

func assertProductionChildTrace(t *testing.T, recorder *telemetry.Recorder, private bool) {
	t.Helper()
	joined, denied, privatePhase, resultRead := false, false, false, false
	var joinResult telemetry.Result
	for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 32)) {
		if err := record.Validate(); err != nil {
			t.Fatal(err)
		}
		if record.Event != telemetry.DiagnosticReturn {
			continue
		}
		switch record.Operation {
		case telemetry.OpOutputHostJoin:
			joined = true
			joinResult = record.Result
		case telemetry.OpOutputHostCredentialGate:
			privatePhase = true
			denied = record.Result == telemetry.ResultDenied
		case telemetry.OpOutputHostResultRead:
			resultRead = true
		}
	}
	if !joined || joinResult != telemetry.ResultSuccess || resultRead != !private || privatePhase != private || private && !denied {
		t.Fatalf("wrong production child phase or join: joined=%t joinResult=%s private=%t denied=%t resultRead=%t", joined, joinResult, privatePhase, denied, resultRead)
	}
}

func assertCapturedClosureRefusedBeforeCredentials(t *testing.T, config Config) {
	t.Helper()
	body, err := os.ReadFile(config.ArtifactPath + ".metadata")
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := artifact.DecodeMetadata(body)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := metadata.Descriptor()
	if err != nil {
		t.Fatal(err)
	}
	changed := false
	for i := range metadata.Compiled {
		row := &metadata.Compiled[i]
		if row.Path == metadata.MainModule || row.Replacement == nil {
			continue
		}
		row.Replacement.Path += "/changed"
		for j := range metadata.Resolved {
			if metadata.Resolved[j].Path == row.Path {
				metadata.Resolved[j].Replacement.Path = row.Replacement.Path
			}
		}
		changed = true
		break
	}
	if !changed {
		t.Fatal("fixture lacks a compiled local dependency")
	}
	metadata, dependency := bindOutputMetadata(t, metadata, descriptor)
	installation, err := NewInstallation(metadata, dependency)
	if err != nil {
		t.Fatal("coherent changed closure metadata refused before binary check", err)
	}
	t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", strings.Repeat("x", 65536))
	if _, err := NewNative(t.Context(), Config{ArtifactPath: config.ArtifactPath, Installation: installation}); !errors.Is(err, ErrArtifactIncompatible) || errors.Is(err, ErrCredential) {
		t.Fatal("different compiled closure reached credential capture", err)
	}
	if _, err := NewPublicValidator(t.Context(), config.ArtifactPath, installation); !errors.Is(err, ErrArtifactIncompatible) {
		t.Fatal("different compiled closure reached passive child", err)
	}
	if err := VerifyInstalledArtifact(t.Context(), config.ArtifactPath, installation); !errors.Is(err, ErrArtifactIncompatible) {
		t.Fatal("passive verification admitted changed closure", err)
	}
	assertNoStagedChild(t, config.ArtifactPath)
}

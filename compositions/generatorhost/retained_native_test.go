package generatorhost

import (
	"bytes"
	"errors"
	"testing"
)

// full_only: false
func TestRetainedNativeKeepsExactBuildAndCurrentCredentialInputs(t *testing.T) {
	pathA := buildSDKGenerator(t)
	metadata, dependency := generatorMetadata(t, pathA)
	installedA, err := NewRetainedInstallation(metadata, dependency)
	if err != nil {
		t.Fatal(err)
	}
	rowA := installedA.Artifact()
	pathB := buildTestGenerator(t, "success")
	installedB := generatorInstallation(t, pathB)
	if rowA.ExecutorID == installedB.Artifact().ExecutorID {
		t.Fatal("different controlled builds have identical executor")
	}
	if _, err := NewNative(t.Context(), Config{Installation: installedB, ArtifactPath: pathB, Artifact: rowA}); !errors.Is(err, ErrAdmission) {
		t.Fatal("current B substituted for exact A", err)
	}
	for _, value := range []string{"first-current-token", "rotated-current-token"} {
		t.Setenv("ENKV_GENERATOR_TEST_TOKEN", value)
		launcher, err := NewNative(t.Context(), Config{Installation: installedA, ArtifactPath: pathA, Artifact: rowA})
		if err != nil {
			t.Fatal(err)
		}
		result, status, err := startAndRead(t, launcher, testCommand(rowA))
		if err != nil || status.Category != 0 || !bytes.Equal(result.Value, []byte("different-size-value")) {
			t.Fatal("exact A continuation refused current token", err, status)
		}
		clear(result.Value)
	}
	if _, err := NewNative(t.Context(), Config{Installation: installedA, ArtifactPath: pathA + "-missing", Artifact: rowA}); !errors.Is(err, ErrArtifactMissing) {
		t.Fatal("missing exact A fell back to current B", err)
	}
}

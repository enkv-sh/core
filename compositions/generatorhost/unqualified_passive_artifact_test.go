package generatorhost

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// full_only: false
func TestIndependentGeneratorPassiveArtifactAdmitsExactSDKClosure(t *testing.T) {
	path := buildSDKGenerator(t)
	installed := generatorInstallation(t, path)
	artifact := installed.Artifact()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyInstalledArtifact(t.Context(), path, installed); err != nil {
		t.Fatal("exact passive SDK closure refused", err)
	}
	metadata, dependency := generatorMetadata(t, path)
	if _, err := NewInstallation(metadata, dependency); err != nil {
		t.Fatal("independent metadata refused", err)
	}
	if err := VerifyInstalledArtifact(t.Context(), path+"-missing", installed); !errors.Is(err, ErrArtifactMissing) || !errors.Is(err, os.ErrNotExist) {
		t.Fatal("passive fixture verification lost missing-file causes", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := VerifyInstalledArtifact(cancelled, path, installed); !errors.Is(err, context.Canceled) {
		t.Fatal("passive fixture verification lost cancellation", err)
	}
	changed := artifact
	changed.NativeTuple = "other/other"
	if err := VerifyInstalledArtifact(t.Context(), path, &Installation{artifact: changed, facts: installed.facts}); !errors.Is(err, ErrArtifactPlatform) {
		t.Fatal("different native tuple lost platform refusal", err)
	}
	changed = artifact
	changed.DependencyManifestID[0] ^= 1
	if err := VerifyInstalledArtifact(t.Context(), path, &Installation{artifact: changed, facts: installed.facts}); !errors.Is(err, ErrArtifactIncompatible) {
		t.Fatal("different dependency manifest admitted", err)
	}
	tampered := bytes.Clone(before)
	tampered[0] ^= 1
	tamperedPath := path + "-tampered"
	if err := os.WriteFile(tamperedPath, tampered, 0500); err != nil {
		t.Fatal(err)
	}
	if err := VerifyInstalledArtifact(t.Context(), tamperedPath, installed); !errors.Is(err, ErrArtifactIdentity) {
		t.Fatal("tampered passive fixture lost exact identity refusal", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("passive fixture verification changed installed bytes", err)
	}
	retained, err := filepath.Glob(filepath.Join(os.TempDir(), "enkv-generator-*"))
	if err != nil || len(retained) != 0 {
		t.Fatal("passive fixture verification retained staging", err)
	}
}

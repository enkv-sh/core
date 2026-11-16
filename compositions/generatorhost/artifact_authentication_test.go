package generatorhost

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"
	"time"
)

// full_only: false
func TestArtifactAuthenticationPrecedesBuildMetadata(t *testing.T) {
	path := buildSDKGenerator(t)
	installed := generatorInstallation(t, path)
	implementation := installed.Artifact()
	if err := verifyArtifactBuildInfo(t.Context(), path, installed); err != nil {
		t.Fatal("exact authenticated production metadata refused", err)
	}
	artifact := installed.Artifact()
	if artifact.CredentialRouteID.IsZero() || len(artifact.CredentialRoute) == 0 {
		t.Fatal("declared public route missing")
	}
	if err := VerifyInstalledArtifact(t.Context(), path, installed); err != nil {
		t.Fatal("passive verification required runtime credentials", err)
	}
	if err := VerifyInstalledArtifact(t.Context(), path+"-missing", installed); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing artifact lost its dependency outcome", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := VerifyInstalledArtifact(cancelled, path, installed); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled verification lost its cause", err)
	}
	changed := artifact
	changed.NativeTuple = "other/other"
	if err := VerifyInstalledArtifact(t.Context(), path, &Installation{artifact: changed, facts: installed.facts}); !errors.Is(err, ErrArtifactIncompatible) || !errors.Is(err, ErrArtifactPlatform) {
		t.Fatal("wrong native tuple admitted", err)
	}
	changed = artifact
	changed.DependencyManifestID[0] ^= 1
	if err := VerifyInstalledArtifact(t.Context(), path, &Installation{artifact: changed, facts: installed.facts}); !errors.Is(err, ErrArtifactIncompatible) {
		t.Fatal("different dependency closure admitted", err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), original...)
	tampered[0] ^= 1
	tamperedPath := path + "-tampered"
	if err := os.WriteFile(tamperedPath, tampered, 0500); err != nil {
		t.Fatal(err)
	}
	if err := VerifyInstalledArtifact(t.Context(), tamperedPath, installed); !errors.Is(err, ErrArtifactIdentity) {
		t.Fatal("tampered artifact lost exact identity refusal", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(original) {
		t.Fatal("verification changed installed artifact", err)
	}
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*debug.BuildInfo)
	}{
		{"missing helper", func(info *debug.BuildInfo) { info.Deps = info.Deps[1:] }},
		{"unknown dependency", func(info *debug.BuildInfo) { info.Deps[0].Path = "example.invalid/sdk" }},
		{"duplicate dependency", func(info *debug.BuildInfo) { info.Deps[1] = info.Deps[0] }},
		{"wrong helper version", func(info *debug.BuildInfo) {
			for _, dep := range info.Deps {
				if dep.Path == "enkv.sh/sdk/generator" {
					dep.Version = "v0.0.1"
				}
			}
		}},
		{"wrong helper replacement", func(info *debug.BuildInfo) {
			for _, dep := range info.Deps {
				if dep.Path == "enkv.sh/sdk/generator" {
					dep.Replace.Path = "../../other"
				}
			}
		}},
		{"stale protocol replacement", func(info *debug.BuildInfo) {
			for _, dep := range info.Deps {
				if dep.Path == "enkv.sh/sdk/protocols/generator" {
					dep.Replace.Path = "../../protocols/generator"
				}
			}
		}},
		{"tagged construction", func(info *debug.BuildInfo) {
			info.Settings = append(info.Settings, debug.BuildSetting{Key: "-tags", Value: "fixture_tag"})
		}},
		{"duplicate setting", func(info *debug.BuildInfo) { info.Settings = append(info.Settings, info.Settings[0]) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := *info
			changed.Settings = append([]debug.BuildSetting(nil), info.Settings...)
			changed.Deps = make([]*debug.Module, len(info.Deps))
			for i, dep := range info.Deps {
				copy := *dep
				if dep.Replace != nil {
					replacement := *dep.Replace
					copy.Replace = &replacement
				}
				changed.Deps[i] = &copy
			}
			test.mutate(&changed)
			if installed.verifyBuildInfo(&changed) == nil {
				t.Fatal("changed build metadata admitted")
			}
		})
	}
	implementation.ArtifactSHA256[0] ^= 1
	changedInstallation := *installed
	changedInstallation.artifact = implementation
	if verifyArtifactBuildInfo(t.Context(), path, &changedInstallation) == nil {
		t.Fatal("build metadata admitted before artifact digest authentication")
	}
	entries, err := filepath.Glob(filepath.Join(os.TempDir(), "enkv-generator-*"))
	if err != nil || len(entries) != 0 {
		t.Fatal("constructor capture retained a private stage", err)
	}
	t.Log("authenticated_metadata_accepted=true wrong_digest_refused=true constructor_stage_removed=true")
}

// full_only: false
func TestNativeConstructionUsesCallerContext(t *testing.T) {
	path := buildSDKGenerator(t)
	installed := generatorInstallation(t, path)
	config := Config{Installation: installed, ArtifactPath: path, Artifact: installed.Artifact()}
	credentials := NewInvocationCredentials(t.Context())
	defer credentials.Close()
	for _, interruption := range []string{"cancelled", "expired"} {
		t.Run(interruption, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			want := context.Canceled
			if interruption == "expired" {
				cancel()
				ctx, cancel = context.WithDeadline(t.Context(), time.Unix(0, 0))
				want = context.DeadlineExceeded
			} else {
				cancel()
			}
			defer cancel()
			if launcher, err := NewNative(ctx, config); launcher != nil || !errors.Is(err, want) {
				t.Error("native constructor lost the caller lifetime", err)
			}
			if validator, err := NewPublicValidator(ctx, path, installed); validator != nil || !errors.Is(err, want) {
				t.Error("public constructor lost the caller lifetime", err)
			}
			if launcher, err := NewNativeForInvocation(ctx, config, credentials); launcher != nil || !errors.Is(err, want) {
				t.Error("invocation constructor lost the caller lifetime", err)
			}
		})
	}
	var absent context.Context
	if launcher, err := NewNative(absent, config); launcher != nil || !errors.Is(err, ErrAdmission) {
		t.Error("native constructor accepted a nil context", err)
	}
	if validator, err := NewPublicValidator(absent, path, installed); validator != nil || !errors.Is(err, ErrAdmission) {
		t.Error("public constructor accepted a nil context", err)
	}
}

// full_only: false
func TestStageCleanupUsesOpenedRootAfterRename(t *testing.T) {
	t.Run("renamed-before-construction", func(t *testing.T) {
		parent := t.TempDir()
		path := filepath.Join(parent, "staging")
		moved := filepath.Join(parent, "moved")
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		root, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path, moved); err != nil {
			_ = root.Close()
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0700); err != nil {
			_ = root.Close()
			t.Fatal(err)
		}
		stage, err := newArtifactStage(context.Background(), root, ".launch-test", "executable")
		if stage != nil {
			if closeErr := stage.close(); closeErr != nil {
				t.Error(closeErr)
			}
		}
		if !errors.Is(err, ErrAdmission) || stage != nil {
			t.Fatal("creation and cleanup roots differed without refusal", err)
		}
		if _, err := root.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("refusal retained the consumed root", err)
		}
		for _, directory := range []string{path, moved} {
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) != 0 {
				t.Fatal("refusal changed a root or retained a stage", err)
			}
		}
	})
	t.Run("renamed-after-construction", func(t *testing.T) {
		parent := t.TempDir()
		path := filepath.Join(parent, "staging")
		moved := filepath.Join(parent, "moved")
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		root, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		stage, err := newArtifactStage(context.Background(), root, ".launch-test", "executable")
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := stage.close(); err != nil {
				t.Error(err)
			}
		}()
		if err := os.Rename(path, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		control := filepath.Join(path, "keep")
		if err := os.WriteFile(control, []byte("keep"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := stage.close(); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(moved)
		if err != nil || len(entries) != 0 {
			t.Fatal("owned stage was not removed after its root moved", err)
		}
		body, err := os.ReadFile(control)
		if err != nil || string(body) != "keep" {
			t.Fatal("cleanup changed a different directory", err)
		}

	})
}

// full_only: false
func TestTemporaryStageCleanupPreservesSubstitutedRoot(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	stage, err := newTemporaryArtifactStage(t.Context(), ".launch-test", "executable")
	if err != nil {
		t.Fatal(err)
	}
	original := stage.rootFile.Name()
	moved := original + "-moved"
	if err := os.Rename(original, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(original, 0700); err != nil {
		t.Fatal(err)
	}
	control := filepath.Join(original, "keep")
	if err := os.WriteFile(control, []byte("foreign replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := stage.close(); !errors.Is(err, errStagingCleanup) || !errors.Is(err, ErrArtifactUnavailable) {
		t.Fatal("lost owned root reported complete cleanup", err)
	}
	body, err := os.ReadFile(control)
	if err != nil || string(body) != "foreign replacement" {
		t.Fatal("cleanup changed substituted root", err)
	}
	entries, err := os.ReadDir(moved)
	if err != nil || len(entries) != 0 {
		t.Fatal("held root retained owned launch", err)
	}
	if stage.rootFile != nil || stage.directory != nil || stage.root != nil {
		t.Fatal("cleanup retained directory descriptors")
	}
}

// full_only: false
func TestArtifactReadsHonorCallerCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact")
	want := []byte("artifact bytes")
	if err := os.WriteFile(path, want, 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	})
	t.Run("read-at", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		reader := artifactFileReader{ctx, file}
		body := make([]byte, 4)
		if n, err := reader.ReadAt(body, 0); n != len(body) || err != nil || string(body) != "arti" {
			t.Fatal("valid artifact read changed", n, err)
		}
		cancel()
		body = []byte("kept")
		if n, err := reader.ReadAt(body, 4); n != 0 || !errors.Is(err, context.Canceled) || string(body) != "kept" {
			t.Fatal("cancelled build-info read reached the file", n, err)
		}
	})
	t.Run("copy", func(t *testing.T) {
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		writer := artifactCancellingWriter{cancel: cancel}
		n, err := io.Copy(&writer, io.LimitReader(artifactFileReader{ctx, file}, int64(len(want)+1)))
		if n != int64(len(want)) || !errors.Is(err, context.Canceled) || !bytes.Equal(writer.body.Bytes(), want) {
			t.Fatal("copy did not observe cancellation after its owned write", n, err)
		}
	})
	t.Run("pre-cancelled-copy", func(t *testing.T) {
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		var output bytes.Buffer
		n, err := io.Copy(&output, io.LimitReader(artifactFileReader{ctx, file}, int64(len(want)+1)))
		position, positionErr := file.Seek(0, io.SeekCurrent)
		if n != 0 || !errors.Is(err, context.Canceled) || output.Len() != 0 || positionErr != nil || position != 0 {
			t.Fatal("cancelled copy reached the file", n, err, position)
		}
	})
}

type artifactCancellingWriter struct {
	body   bytes.Buffer
	cancel context.CancelFunc
}

func (writer *artifactCancellingWriter) Write(body []byte) (int, error) {
	n, err := writer.body.Write(body)
	writer.cancel()
	return n, err
}

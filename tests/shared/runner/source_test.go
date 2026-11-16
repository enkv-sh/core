package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

func publicSourceFixture(t *testing.T, root string) {
	t.Helper()
	rawSourceWrite(t, filepath.Join(filepath.Dir(root), "enkv-extensions"), moduleInventoryPath, "fixture inventory\n")
	rawSourceWrite(t, filepath.Join(filepath.Dir(root), "enkv-extensions"), "go.work", "fixture workspace\n")
	for _, source := range moduleSources {
		if source.Sibling == "" {
			continue
		}
		owner := filepath.Join(filepath.Dir(root), source.Sibling, source.Directory)
		for _, input := range []string{"go.mod", "LICENSE", "wire_test.go", "testdata/frame.bin"} {
			path := filepath.Join(owner, input)
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// full_only: false
func TestPublicSourceRecordDigestIsBounded(t *testing.T) {
	source := records.Source{Revision: strings.Repeat("a", 40)}
	for _, test := range []struct {
		digest string
		valid  bool
	}{{"", true}, {strings.Repeat("b", 64), true}, {strings.Repeat("b", 63), false}, {strings.Repeat("b", 65), false}, {strings.Repeat("z", 64), false}} {
		source.PublicSourcesSHA256 = test.digest
		if validSource(source) != test.valid {
			t.Fatal("public source record validation differs", len(test.digest))
		}
	}
	unavailable := records.Source{ObservationIncomplete: true}
	if !validSource(unavailable) || validSource(records.Source{}) {
		t.Fatal("unavailable source observation requires an explicit record")
	}
	for _, change := range []func(*records.Source){
		func(value *records.Source) { value.Revision = "invalid" },
		func(value *records.Source) { value.Dirty = true },
		func(value *records.Source) { value.DirtyDiffSHA256 = new(strings.Repeat("b", 64)) },
		func(value *records.Source) { value.PublicSourcesSHA256 = strings.Repeat("b", 64) },
		func(value *records.Source) { value.Algorithm = rawSourceAlgorithm },
		func(value *records.Source) { value.Tree = strings.Repeat("b", 40) },
		func(value *records.Source) { value.PublicRepository = "enkv-extensions" },
		func(value *records.Source) { value.PublicRevision = strings.Repeat("b", 40) },
		func(value *records.Source) { value.PublicTree = strings.Repeat("b", 40) },
		func(value *records.Source) { value.PublicPaths = []string{"sdk/output"} },
	} {
		malformed := unavailable
		change(&malformed)
		if validSource(malformed) {
			t.Error("incomplete observation accepted malformed source fields")
		}
	}
}

// full_only: false
func TestUnavailableSourceObservationDoesNotBlockSelectedWork(t *testing.T) {
	t.Run("joined-git-failure", func(t *testing.T) {
		ctx, root, bootstrap, marker, workflow, _ := completePreparationFixture(t, "")
		realGit, err := exec.LookPath("git")
		if err != nil {
			t.Fatal(err)
		}
		control := t.TempDir()
		script := "#!/bin/sh\nif [ \"${1-}\" = -c ] && [ \"${2-}\" = core.fsmonitor=false ] && [ \"${3-}\" = rev-parse ]; then exit 23; fi\nexec " + shellQuote(realGit) + " \"$@\"\n"
		if err := os.WriteFile(filepath.Join(control, "git"), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", control+string(os.PathListSeparator)+os.Getenv("PATH"))
		var output strings.Builder
		if err := runCommand(ctx, root, bootstrap, []string{"run", "--workflow", workflow}, &output); err != nil {
			t.Fatal("Git observation blocked selected work", err, output.String())
		}
		if _, err := os.Stat(marker); err != nil || !strings.Contains(output.String(), "Workflow passed") || !strings.Contains(output.String(), "Source observation incomplete") {
			t.Fatal("selected work or incomplete observation was lost", err, output.String())
		}
	})
	t.Run("missing-git", func(t *testing.T) {
		root := t.TempDir()
		t.Setenv("PATH", t.TempDir())
		for _, observe := range []func(context.Context, string) (records.Source, error){sourceRevision, sourceIdentity} {
			source, err := observe(t.Context(), root)
			if err != nil || !source.ObservationIncomplete || source.Revision != "" || !validSource(source) {
				t.Fatal("missing Git became a source permission gate", source, err)
			}
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := sourceRevision(ctx, t.TempDir()); !errors.Is(err, context.Canceled) {
			t.Fatal("source observation hid invocation cancellation", err)
		}
		unjoined := &sourceCommandFailure{operation: "rev-parse", process: processResult{Started: true}}
		if sourceCommandsJoined(errors.Join(errors.New("observation unavailable"), unjoined)) {
			t.Fatal("unjoined source observation became informational")
		}
	})
}

func initializePublicSourceGitFixture(t *testing.T, root string) {
	t.Helper()
	public := filepath.Join(filepath.Dir(root), "enkv-extensions")
	for _, args := range [][]string{{"init", "--quiet"}, {"-c", "user.name=Local Test", "-c", "user.email=local@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "--allow-empty", "-m", "Public source fixture"}} {
		command := exec.Command("git", args...)
		command.Dir = public
		if body, err := command.CombinedOutput(); err != nil {
			t.Fatalf("public source fixture: %v %s", err, body)
		}
	}
}

// full_only: false
func TestLegacySourceIdentityRejectsRawFieldsWithoutAlgorithm(t *testing.T) {
	legacy := records.Source{Revision: strings.Repeat("a", 40)}
	for _, change := range []func(*records.Source){
		func(value *records.Source) { value.Tree = strings.Repeat("b", 40) },
		func(value *records.Source) { value.PublicRepository = "enkv-extensions" },
		func(value *records.Source) { value.PublicRevision = strings.Repeat("c", 40) },
		func(value *records.Source) { value.PublicTree = strings.Repeat("d", 40) },
		func(value *records.Source) { value.PublicPaths = []string{"sdk/output"} },
	} {
		mixed := legacy
		change(&mixed)
		if validSource(mixed) || sameSource(mixed, legacy) || sameSource(legacy, mixed) || sameSource(mixed, mixed) {
			t.Error("raw fields without their algorithm acquired legacy identity")
		}
		if _, err := sourceForRecovery(t.Context(), t.TempDir(), mixed); err == nil {
			t.Error("mixed retained identity selected a reader")
		}
	}
	if !validSource(legacy) || !sameSource(legacy, legacy) {
		t.Error("revision-only current binding lost its existing validity")
	}
}

func copyModuleInventoryFixture(t *testing.T, root string) {
	t.Helper()
	maintained := filepath.Clean(filepath.Join(filepath.Dir(savedWorkflowPath(t, "dev")), "../.."))
	body, err := moduleInventoryBytes(maintained)
	if err != nil {
		t.Fatal(err)
	}
	rawSourceWrite(t, filepath.Join(filepath.Dir(root), "enkv-extensions"), moduleInventoryPath, string(body))
	workspace, err := os.ReadFile(filepath.Join(filepath.Dir(maintained), "enkv-extensions/go.work"))
	if err != nil {
		t.Fatal(err)
	}
	rawSourceWrite(t, filepath.Join(filepath.Dir(root), "enkv-extensions"), "go.work", string(workspace))

}

// full_only: false
func TestSourceObservationReportsEditsWithoutRawCapture(t *testing.T) {
	root, _ := rawSourceFixture(t)
	clean, err := sourceIdentity(t.Context(), root)
	if err != nil || clean.Dirty || clean.Algorithm != "" || clean.Tree != "" {
		t.Fatal("clean observation differs", clean, err)
	}
	rawSourceWrite(t, root, "tracked.go", "tracked")
	rawSourceCommit(t, root)
	if err := os.Remove(filepath.Join(root, "tracked.go")); err != nil {
		t.Fatal(err)
	}
	deleted, err := sourceIdentity(t.Context(), root)
	if err != nil || !deleted.Dirty || deleted.ObservationIncomplete || !validSource(deleted) {
		t.Fatal("tracked deletion made its source observation incomplete", deleted, err)
	}
	path := filepath.Join(root, "input.go")
	rawSourceWrite(t, root, "input.go", "first")
	before, err := sourceIdentity(t.Context(), root)
	if err != nil || !before.Dirty {
		t.Fatal("untracked file not observed", before, err)
	}
	rawSourceWrite(t, root, "input.go", "second value")
	after, err := sourceIdentity(t.Context(), root)
	if err != nil || sameSource(before, after) || after.Algorithm != "" || after.Tree != "" {
		t.Fatal("source edit was not an observation", after, err)
	}
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	control := t.TempDir()
	script := "#!/bin/sh\nset -eu\n" + shellQuote(realGit) + " \"$@\"\nif [ \"${3-}\" = ls-files ]; then rm -- " + shellQuote(path) + "; fi\n"
	if err := os.WriteFile(filepath.Join(control, "git"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", control+string(os.PathListSeparator)+os.Getenv("PATH"))
	incomplete, err := sourceIdentity(t.Context(), root)
	if err != nil || !incomplete.ObservationIncomplete || !validSource(incomplete) {
		t.Fatal("concurrent deletion became an execution refusal", incomplete, err)
	}
	var output strings.Builder
	if _, err := finishSourceObservation(t.Context(), root, incomplete, &output); err != nil || !strings.Contains(output.String(), "Source observation incomplete") {
		t.Fatal("incomplete observation lost its informational result", err, output.String())
	}
}

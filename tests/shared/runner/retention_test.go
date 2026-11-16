package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestNewRunDirectoryUsesRecordedStartAndLocalOffset(t *testing.T) {
	original := time.Local
	time.Local = time.FixedZone("run-test", 10*60*60)
	t.Cleanup(func() { time.Local = original })
	s := completedPrivateFixture(t, "live")
	want := filepath.Join(s.root, "tests", s.record.Suite, "runs", s.record.StartedAt.In(time.Local).Format("2006-01-02"), s.record.StartedAt.In(time.Local).Format("15-04-05-0700")+"-"+s.record.RunID)
	if s.directory != want {
		t.Fatalf("run directory = %q, want recorded local start %q", s.directory, want)
	}
	if s.record.StartedAt.Location() != time.UTC {
		t.Fatal("public start is not UTC")
	}
}

// full_only: false
func TestRunCreationProtectsExistingParentPermissions(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	started := time.Date(2026, 9, 7, 17, 11, 1, 0, time.UTC)
	id := "abcdef0123456789abcdef0123456789"
	original := time.Local
	time.Local = time.FixedZone("run-test", 10*60*60)
	t.Cleanup(func() { time.Local = original })
	date := filepath.Join(root, "tests/hermetic/runs/2026-09-08")
	if os.MkdirAll(date, 0755) != nil || os.Chmod(date, 0755) != nil || os.Chmod(filepath.Dir(date), 0755) != nil {
		t.Fatal("public parent fixture")
	}
	directory, err := createRunDirectory(root, "hermetic", id, started)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Dir(date), date, directory} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0700 {
			t.Fatal("run owner or date directory is not private")
		}
	}
}

// full_only: false
func TestNewRunsPreserveEarlierRawEvidence(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "")
	for _, suite := range []string{"live"} {
		t.Run(suite, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			baseline := filepath.Join(root, "tests", suite, "runs", "legacy-baseline", "run.json")
			if os.MkdirAll(filepath.Dir(baseline), 0700) != nil || os.WriteFile(baseline, []byte("retained historical bytes\n"), 0400) != nil {
				t.Fatal("retained fixture")
			}
			schedule, err := catalog.Resolve(catalog.Request{Include: []string{"state.single-value-update-preserves-other-values/members_32"}, Repetitions: 1})
			if err != nil {
				t.Fatal(err)
			}
			request := runRequest{Suite: suite, Provider: "memory", Schedule: schedule}
			if suite == "live" {
				request.Provider = "gcp"
			}
			first, err := newRunState(root, request, records.Source{}, "controlled")
			if err != nil || first.save() != nil {
				t.Fatal("first run record")
			}
			firstPath := filepath.Join(first.directory, "run.json")
			before, err := os.ReadFile(firstPath)
			if err != nil {
				t.Fatal(err)
			}
			second, err := newRunState(root, request, records.Source{}, "controlled")
			if err != nil || second.record.RunID == first.record.RunID {
				t.Fatal("new run reused an identity")
			}
			second.fail("assembly_failed", "build")
			second.finish()
			if second.save() != nil {
				t.Fatal("failed run record")
			}
			after, err := os.ReadFile(firstPath)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("failed run changed earlier run bytes")
			}
			old, err := os.ReadFile(baseline)
			if err != nil || string(old) != "retained historical bytes\n" {
				t.Fatal("new run changed historical evidence")
			}
			var failed runRecord
			if records.ReadJSON(filepath.Join(second.directory, "run.json"), &failed) != nil || failed.Outcome != "failed" || failed.Failure == nil || failed.Failure.Class != "assembly_failed" {
				t.Fatal("new failure evidence was lost")
			}
		})
	}
}

// full_only: false
func TestFailedOfflineChecksPreserveEarlierEvidence(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if os.Mkdir(filepath.Join(root, "core"), 0700) != nil {
		t.Fatal("controlled module directory")
	}
	// The real Go command can read its version, then refuses this invalid module.
	if os.WriteFile(filepath.Join(root, "core", "go.mod"), []byte("invalid module directive\n"), 0600) != nil {
		t.Fatal("controlled module failure")
	}
	for _, args := range [][]string{{"init", "--quiet"}, {"-c", "user.name=Local Test", "-c", "user.email=local@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "--allow-empty", "-m", "Retention fixture"}} {
		command := exec.Command("git", args...)
		command.Dir = root
		if body, err := command.CombinedOutput(); err != nil {
			t.Fatalf("local repository fixture: %v\n%s", err, body)
		}
	}
	runs := filepath.Join(root, "tests", "hermetic", "runs")
	baseline := filepath.Join(runs, "legacy-baseline", "build-closure.json")
	if os.MkdirAll(filepath.Dir(baseline), 0700) != nil || os.WriteFile(baseline, []byte("retained baseline\n"), 0400) != nil {
		t.Fatal("baseline fixture")
	}
	retained := map[string][]byte{baseline: []byte("retained baseline\n")}
	for range 2 {
		record, runErr := runOfflineResponsibility(context.Background(), root, "", "full", "common", "", io.Discard)
		if runErr == nil || record == nil || record.Outcome != "failed" {
			t.Fatal("invalid module did not preserve its current failed outcome")
		}
		for path, before := range retained {
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("new check changed earlier evidence", err)
			}
		}
		entries, err := os.ReadDir(runs)
		if err != nil || len(entries) != 1 || entries[0].Name() != "legacy-baseline" {
			t.Fatal("ordinary offline check added a historical result", entries, err)
		}
	}
}

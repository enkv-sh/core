package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

func completedPrivateFixture(t *testing.T, suite string) *runState {
	t.Helper()
	t.Setenv("ENKV_TELEMETRY", "")
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return completedPrivateFixtureAt(t, root, suite)
}

func completedPrivateFixtureAt(t *testing.T, root, suite string) *runState {
	t.Helper()
	schedule, err := catalog.Resolve(catalog.Request{Include: []string{"state.single-value-update-preserves-other-values/members_32"}, Repetitions: 1})
	if err != nil {
		t.Fatal(err)
	}
	provider := "memory"
	if suite == "live" {
		provider = "gcp"
	}
	s, err := newRunState(root, runRequest{Suite: suite, Provider: provider, Target: provider, Schedule: schedule}, records.Source{}, "controlled")
	if err != nil {
		t.Fatal(err)
	}
	worker := func(name, role string) workerEvidence {
		return workerEvidence{Worker: name, Role: role, Outcome: "passed", Process: "passed", Joined: true, Phases: []records.PhaseResult{{Sequence: 1, Name: "verification", Outcome: "passed"}}}
	}
	for _, entry := range schedule.Entries {
		writer, fresh, cleanup := worker("writer", "writer"), worker("fresh", "fresh_after"), worker("cleanup", "cleanup")
		shape, _ := recordedFixture(entry.Scenario, entry.Members)
		result := scenarioResult{Entry: entry, Fixture: shape, Outcome: "passed", CorrectnessPassed: true, Writer: &writer, PostExit: []workerEvidence{fresh}, Cleanup: noCleanup()}
		if suite == "live" {
			result.Cleanup = records.Cleanup{Outcome: "passed", RemainingOwnedObjects: new(int64), UnknownEffects: new(int64)}
			result.CleanupWorker = &cleanup
		}
		s.record.Scenarios = append(s.record.Scenarios, result)
	}
	s.finish()
	if os.WriteFile(filepath.Join(s.private, "owned-input.json"), []byte("private sentinel"), 0400) != nil || s.save() != nil {
		t.Fatal("private fixture")
	}
	return s
}

// full_only: false
func TestPrivateRemovalRejectsChangedOwnershipAndSymlinks(t *testing.T) {
	for _, mode := range []string{"wrong_run", "wrong_suite", "different_path", "replacement", "run_replacement", "directory_symlink", "child_symlink"} {
		t.Run(mode, func(t *testing.T) {
			suite := "hermetic"
			if mode == "wrong_run" || mode == "wrong_suite" {
				suite = "live"
			}
			s := completedPrivateFixture(t, suite)
			outside, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil || os.WriteFile(filepath.Join(outside, "keep"), []byte("outside sentinel"), 0600) != nil {
				t.Fatal("outside fixture")
			}
			switch mode {
			case "wrong_run":
				s.privateOwner.id = strings.Repeat("f", 32)
			case "wrong_suite":
				s.privateOwner.suite = "hermetic"
			case "different_path":
				s.privateOwner.path = outside
			case "run_replacement":
				retained := filepath.Join(outside, "original-run")
				if os.Rename(s.directory, retained) != nil || os.Mkdir(s.directory, 0700) != nil || os.Rename(filepath.Join(retained, "private"), s.private) != nil {
					t.Fatal("replacement run retained the original private inode")
				}
			case "replacement", "directory_symlink":
				if os.Rename(s.private, filepath.Join(s.directory, "retained-private")) != nil {
					t.Fatal("retained original private")
				}
				if mode == "replacement" {
					err = os.Mkdir(s.private, 0700)
				} else {
					err = os.Symlink(outside, s.private)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "child_symlink":
				if os.Symlink(outside, filepath.Join(s.private, "link")) != nil {
					t.Fatal("child symlink")
				}
			}
			if err := s.privateOwner.remove(); err == nil || !strings.Contains(err.Error(), "private files retained") || len(err.Error()) > 256 {
				t.Fatal("unsafe disposal did not return its bounded error")
			}
			if _, err := os.Lstat(s.private); err != nil {
				t.Fatal("unsafe disposal removed private directory")
			}
			if body, err := os.ReadFile(filepath.Join(outside, "keep")); err != nil || string(body) != "outside sentinel" {
				t.Fatal("unsafe disposal changed outside data")
			}
			if s.record.Outcome != "passed" {
				t.Fatal("disposal failure changed public outcome")
			}
		})
	}
}

// full_only: false
func TestSuccessfulRecoveryDisposesOnlyNewPrivateDirectory(t *testing.T) {
	s := completedPrivateFixture(t, "live")
	old, original := unresolvedPrivateRecoveryFixture(t, s.root)
	defer assertPrivateRecoveryUnchanged(t, original)
	s.record.RecoveryRunID = old.record.RunID
	for i := range s.record.Scenarios {
		s.record.Scenarios[i].Writer = nil
		s.record.Scenarios[i].PostExit = nil
	}
	s.finish()
	if err := s.privateOwner.remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(s.private); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("successful recovery retained its own private files")
	}
	if _, err := os.Stat(old.private); err != nil {
		t.Fatal("recovery removed the referenced old run's private directory")
	}
}

// full_only: false
func TestGeneratorFixtureLedgerCannotGrantProductSuccessOrOwnership(t *testing.T) {
	state, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	runID := strings.Repeat("a", 32)
	account := strings.Repeat("b", 32)
	resource := strings.Repeat("c", 32)
	path, err := createGeneratorFixtureLedger(state, runID, generatorReference{Account: account})
	if err != nil || recordGeneratorFixtureResource(path, runID, resource) != nil {
		t.Fatal("fixture ledger unavailable", err)
	}
	targets, err := generatorFixtureCleanupTargets(path, runID)
	if err != nil || !reflect.DeepEqual(targets, []string{resource}) {
		t.Fatal("exact owned fixture target unavailable", err)
	}
	// The only public record remains failed and unresolved. The private ID is a
	// cleanup target; it is not Product authority or correctness evidence.
	s := runState{record: runRecord{Suite: "live", Provider: "gcp", Outcome: "incomplete", Cleanup: unresolvedCleanup()}}
	s.finish()
	public, err := json.Marshal(s.record)
	if err != nil || s.record.Outcome != "failed" || s.record.Correctness.Passed || cleanupPassed(s.record.Cleanup) || bytes.Contains(public, []byte(resource)) || bytes.Contains(public, []byte(account)) || bytes.Contains(public, []byte(path)) {
		t.Fatal("fixture ID changed Product evidence or escaped private state", err)
	}
	if err := retireGeneratorFixtureResource(path, runID, resource); err != nil {
		t.Fatal(err)
	}
	targets, err = generatorFixtureCleanupTargets(path, runID)
	if err != nil || len(targets) != 0 {
		t.Fatal("retired fixture stayed in exact cleanup targets", err)
	}
	if recordGeneratorFixtureResource(path, runID, resource) == nil || retireGeneratorFixtureResource(path, runID, strings.Repeat("d", 32)) == nil {
		t.Fatal("fixture ledger admitted duplicate or unknown ownership")
	}
}

// These fixtures supply terminal scalar claims only to exercise the local
// filesystem owner. The N3 coordinator witness proves actual worker behavior.

// full_only: false
func TestCurrentCleanupRequiresEveryStartedReconstructionJoin(t *testing.T) {
	for _, condition := range []string{"joined", "unjoined", "unstarted"} {
		t.Run(condition, func(t *testing.T) {
			state := completedPrivateFixture(t, "hermetic")
			state.record.Scenarios[0].Reconstruction = []configurationRecoveryEvidence{{Phases: []records.ProcessCompletion{
				{Phase: "resource-owner", Started: true, Joined: true},
				{Phase: "reconstruction-parent", Started: condition != "unstarted", Joined: condition == "joined"},
			}}}
			wantJoined := condition != "unjoined"
			if runProcessesJoined(state.record) != wantJoined {
				t.Error("cleanup ignored actual Reconstruction phase settlement")
			}
			directory := state.current.path
			err := state.finishCurrentRun(&bytes.Buffer{}, nil)
			if wantJoined {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Lstat(directory); !os.IsNotExist(err) {
					t.Fatal("joined consumers retained scratch", err)
				}
			} else {
				if err == nil {
					t.Error("uncertain Reconstruction join allowed cleanup")
				}
				if _, err := os.Lstat(directory); err != nil {
					t.Fatal("uncertain Reconstruction lost its owned scratch", err)
				}
			}
		})
	}
}

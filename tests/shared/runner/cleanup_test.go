package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

func recoveryFixture(t *testing.T, count int) (string, cleanupRequest, []recoveryEntry) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	config, rawSettings := configurationFixture(t, "gcp")
	settings, err := validateSettings(rawSettings, "gcp", filepath.Dir(config))
	if err != nil {
		t.Fatal(err)
	}
	request := cleanupRequest{RunID: strings.Repeat("d", 32), Limits: filepath.Join(root, "limits.json")}
	allowance := testLimits()
	if records.WriteJSON(request.Limits, allowance, 0600) != nil {
		t.Fatal("limits fixture")
	}
	var entries []recoveryEntry
	for i := 0; i < count; i++ {
		state := filepath.Join(root, "tests/live/runs", request.RunID, "private", fmt.Sprintf("%04d-state-single-value-update-preserves-other-values", i))
		if os.MkdirAll(state, 0700) != nil {
			t.Fatal("original state")
		}
		input := workerInput{Settings: settings, Limits: &allowance, Scenarios: []string{"state.single-value-update-preserves-other-values"}, Repetitions: 1, RunID: request.RunID, Prefix: fmt.Sprintf("enkv-test/%s/%04d", request.RunID, i), Participants: map[string]string{"authority": "operator"}}
		path := filepath.Join(state, "input.json")
		if records.WriteJSON(path, input, 0400) != nil || records.WriteJSON(filepath.Join(state, "inventory.json"), map[string]int{"version": 1}, 0600) != nil {
			t.Fatal("original records")
		}
		entries = append(entries, recoveryEntry{State: state, InputPath: path, Input: input})
	}
	return root, request, entries
}

func assertCleanupRefusalHasOnlySourceObservation(t *testing.T, output string) {
	t.Helper()
	if output != "" && output != "Source observation incomplete; prepared builds remain in use\n" {
		t.Fatal("cleanup refusal emitted execution output", output)
	}
}

// full_only: false
func TestCleanupRejectsInvalidIdentityBeforeLookup(t *testing.T) {
	for _, id := range []string{"../escape", "/tmp/escape", "a/b", ".", "", "synthetic-secret"} {
		root := t.TempDir()
		var output bytes.Buffer
		if runCommand(context.Background(), root, "", []string{"cleanup", id, "--limits", "unavailable"}, &output) == nil {
			t.Fatal("invalid cleanup identity accepted")
		}
		files, err := os.ReadDir(root)
		if err != nil || len(files) != 0 {
			t.Fatal("invalid identity caused effects")
		}
		assertCleanupRefusalHasOnlySourceObservation(t, output.String())
	}
	for _, id := range []string{strings.Repeat("a", 32), "20260907T010203Z-retained", "legacy-baseline"} {
		if _, err := parseCleanupRequest([]string{"cleanup", id, "--limits", "limits.json"}); err != nil {
			t.Fatal("retained run ID form refused")
		}
	}
}

// full_only: false
func TestCleanupRejectsChangedResourcesBeforeAnyProcess(t *testing.T) {
	for _, field := range []string{"region", "bucket", "key_id", "public_key_pem", "project", "project_number", "authority_kek_id", "authority_kek_public_key_pem", "reader_kek_id", "reader_kek_public_key_pem"} {
		t.Run(field, func(t *testing.T) {
			root, request, entries := recoveryFixture(t, 2)
			settings := make(liveSettings)
			for key, value := range entries[0].Input.Settings {
				settings[key] = value
			}
			settings[field] += "1"
			request.Environment = filepath.Join(root, "replacement.json")
			if records.WriteJSON(request.Environment, environmentFor(settings), 0600) != nil {
				t.Fatal("replacement fixture")
			}
			bootstrap := filepath.Join(root, "bootstrap.json")
			if err := records.WriteJSON(bootstrap, struct{ Replace map[string]string }{map[string]string{}}, 0600); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			err := runCommand(context.Background(), root, bootstrap, []string{"cleanup", request.RunID, "--limits", request.Limits, "--environment", request.Environment}, &output)
			assertClosedPreparationError(t, err, root, settings[field])
			var failure *checkFailure
			if !errors.As(err, &failure) || failure.cause == nil || failure.cause.Error() != "cleanup resource identities changed" {
				t.Fatalf("identity change: %v", err)
			}
			assertCleanupRefusalHasOnlySourceObservation(t, output.String())
			runs, err := os.ReadDir(filepath.Join(root, "tests/live/runs"))
			if err != nil || len(runs) != 1 {
				t.Fatal("changed resources created a recovery run")
			}
		})
	}
}

// full_only: false
func TestCleanupPreparationPreservesOriginalInputsAndAllowsNewCredentials(t *testing.T) {
	root, request, entries := recoveryFixture(t, 2)
	before, err := os.ReadFile(entries[0].InputPath)
	if err != nil {
		t.Fatal(err)
	}
	settings := make(liveSettings)
	for key, value := range entries[0].Input.Settings {
		settings[key] = value
	}
	settings["credentials_file"] = filepath.Join(root, "replacement-identity.json")
	if os.WriteFile(settings["credentials_file"], []byte("synthetic-secret"), 0600) != nil {
		t.Fatal("replacement identity")
	}
	request.Environment = filepath.Join(root, "replacement.json")
	if records.WriteJSON(request.Environment, environmentFor(settings), 0600) != nil {
		t.Fatal("replacement config")
	}
	plan, err := prepareRecovery(root, request)
	if err != nil || len(plan.Entries) != 2 || plan.Settings["credentials_file"] != settings["credentials_file"] {
		t.Fatalf("replacement refused: %v", err)
	}
	after, err := os.ReadFile(entries[0].InputPath)
	if err != nil || !bytes.Equal(before, after) || plan.Entries[0].Input.Settings["credentials_file"] == plan.Settings["credentials_file"] {
		t.Fatal("replacement rewrote original ownership evidence")
	}
}

// full_only: false
func TestCleanupIgnoresUnusedObserverCredentials(t *testing.T) {
	root, request, entries := recoveryFixture(t, 1)
	input := entries[0].Input
	input.Scenarios[0], _ = catalog.HistoricalName("state.single-value-update-preserves-other-values")
	input.ObserverSettings = liveSettings{"credentials_file": "/unavailable-observer-credentials"}
	input.ReaderSettings = liveSettings{"credentials_file": "/unavailable-reader-credentials"}
	input.RecoverySettings = liveSettings{"credentials_file": "/unavailable-recovery-credentials"}
	input.DeniedReaderSettings = liveSettings{"credentials_file": "/unavailable-denied-reader-credentials"}
	if records.WriteJSON(entries[0].InputPath, input, 0400) != nil {
		t.Fatal("canonical recovery fixture")
	}
	before, err := os.ReadFile(entries[0].InputPath)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := prepareRecovery(root, request)
	if err != nil || len(plan.Entries) != 1 || plan.Entries[0].State != entries[0].State || plan.Entries[0].Input.Scenarios[0] != input.Scenarios[0] {
		t.Fatalf("canonical input lost fixture ownership: %v", err)
	}
	after, err := os.ReadFile(entries[0].InputPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("recovery changed retained input")
	}
}

// full_only: false
func TestCleanupRecoveryResolvesNestedOriginalRun(t *testing.T) {
	root, request, entries := recoveryFixture(t, 1)
	original := filepath.Join(root, "tests/live/runs", request.RunID)
	nested := filepath.Join(root, "tests/live/runs/2026-09-08", "03-11-01+1000-"+request.RunID)
	before, err := os.ReadFile(entries[0].InputPath)
	if err != nil || os.MkdirAll(filepath.Dir(nested), 0700) != nil || os.Rename(original, nested) != nil {
		t.Fatal("nested recovery fixture")
	}
	plan, err := prepareRecovery(root, request)
	if err != nil || len(plan.Entries) != 1 || plan.Entries[0].State != filepath.Join(nested, "private/0000-state-single-value-update-preserves-other-values") {
		t.Fatalf("nested recovery refused or resolved another run: %v", err)
	}
	after, err := os.ReadFile(plan.Entries[0].InputPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("nested lookup changed retained input bytes")
	}
}

// full_only: false
func TestCleanupPreparationRejectsInconsistentOrEscapedState(t *testing.T) {
	for _, mode := range []string{"other_run", "other_provider", "other_resource", "other_prefix", "traversal_prefix", "bad_scenario", "bad_members", "repetition", "missing_authority", "state_symlink", "input_symlink", "missing_input"} {
		t.Run(mode, func(t *testing.T) {
			root, request, entries := recoveryFixture(t, 2)
			entry := entries[1]
			input := entry.Input
			switch mode {
			case "other_run":
				input.RunID = strings.Repeat("e", 32)
			case "other_provider":
				input.Settings["provider"] = "aws"
			case "other_resource":
				input.Settings["bucket"] = "other-bucket"
			case "other_prefix":
				input.Prefix = "enkv-test/foreign/point"
			case "traversal_prefix":
				input.Prefix += "/../foreign"
			case "bad_scenario":
				input.Scenarios = []string{"unknown"}
			case "bad_members":
				input.MemberCount = 65
			case "repetition":
				input.Repetitions = 2
			case "missing_authority":
				input.Participants = nil
			}
			if records.WriteJSON(entry.InputPath, input, 0400) != nil {
				t.Fatal("changed input")
			}
			switch mode {
			case "state_symlink":
				outside := filepath.Join(root, "retained-state")
				if os.Rename(entry.State, outside) != nil || os.Symlink(outside, entry.State) != nil {
					t.Fatal("state alias")
				}
			case "input_symlink":
				outside := filepath.Join(root, "retained-input.json")
				if os.Rename(entry.InputPath, outside) != nil || os.Symlink(outside, entry.InputPath) != nil {
					t.Fatal("input alias")
				}
			case "missing_input":
				if os.Remove(entry.InputPath) != nil {
					t.Fatal("missing input fixture")
				}
			}
			if _, err := prepareRecovery(root, request); err == nil {
				t.Fatal("invalid retained state accepted")
			}
		})
	}
}

// full_only: false
func TestCleanupRecoveryUsesNewOutputsAndOriginalStateOnly(t *testing.T) {
	t.Run("preparation_refusal_and_admitted_failure", func(t *testing.T) {
		t.Setenv("ENKV_TELEMETRY", "")
		root, request, entries := recoveryFixture(t, 1)
		retained := runRecord{SchemaVersion: records.SchemaVersion, RunID: request.RunID, Suite: "live", Provider: "gcp", Outcome: "failed", Failure: &records.Failure{Class: "cleanup_run_failed", Stage: "cleanup"}}
		retainedPath := filepath.Join(root, "tests/live/runs", request.RunID, "run.json")
		if err := records.WriteJSON(retainedPath, retained, 0600); err != nil {
			t.Fatal(err)
		}
		before := map[string][]byte{}
		for _, path := range []string{retainedPath, entries[0].InputPath, filepath.Join(entries[0].State, "inventory.json")} {
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			before[path] = body
		}
		if err := os.Mkdir(filepath.Join(root, "core"), 0700); err != nil {
			t.Fatal(err)
		}
		initializeWorkflowExecutionFixture(t, root)
		if err := os.WriteFile(filepath.Join(root, ".git/info/exclude"), []byte("tests/live/runs/\n"), 0600); err != nil {
			t.Fatal(err)
		}
		parallel, memory := 2, 512
		request.execution = executionPolicy{Requested: executionRequest{Parallel: &parallel, MemoryLimitMiB: &memory}, Resolved: executionCapacity{Parallel: 2, MemoryLimitMiB: 512}}
		admissions := 0
		ctx := context.WithValue(withRacePolicy(t.Context(), false), rootAdmitterContextKey{}, rootAdmitter(func(ctx context.Context, _ rootAdmission) (context.Context, error) {
			admissions++
			return ctx, fmt.Errorf("invalid preparation reached root admission")
		}))
		var output bytes.Buffer
		args := []string{"cleanup", request.RunID, "--limits", request.Limits, "--parallel=2", "--memory-limit-mib=512"}
		bootstrap := filepath.Join(root, "absent-overlay.json")
		err := runCommand(ctx, root, bootstrap, args, &output)
		assertClosedPreparationError(t, err, root)
		var pathError *os.PathError
		if !errors.Is(err, os.ErrNotExist) || !errors.As(err, &pathError) || pathError.Path != bootstrap || admissions != 0 || output.Len() != 0 {
			t.Fatal("absent bootstrap did not refuse before root admission", err, admissions, output.String())
		}
		directories, err := os.ReadDir(filepath.Join(root, "tests/live/runs"))
		if err != nil || len(directories) != 1 || directories[0].Name() != request.RunID {
			t.Fatal("preparation failure created durable live state", directories, err)
		}
		for path, original := range before {
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(original, after) {
				t.Fatal("preparation changed retained evidence", path, err)
			}
		}

		// A failure after an admitted execution owner exists still needs its
		// durable failed record. Use the production recovery/finalization owners
		// and a local directory collision, without a compiler or cloud worker.
		plan, err := prepareRecovery(root, request)
		if err != nil {
			t.Fatal(err)
		}
		source, err := sourceIdentity(t.Context(), root)
		if err != nil {
			t.Fatal(err)
		}
		s, err := newRunState(root, runRequest{execution: request.execution, Suite: "live", Provider: "gcp", Target: "gcp", Schedule: recoverySchedule(plan)}, source, "controlled")
		if err != nil {
			t.Fatal(err)
		}
		s.recovery.executionSource, s.record.ExecutionSource = &source, &source
		s.record.RecoveryRunID = request.RunID
		s.record.Context, s.record.Limits = safeRunContext(plan.Settings), &plan.Limits
		if err := s.save(); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(s.private, "build"), 0700); err != nil {
			t.Fatal(err)
		}
		executionErr := executePreparedRecovery(t.Context(), root, "must-not-build", s, plan)
		if executionErr == nil || executionErr.Error() != "cleanup assembly directory unavailable" {
			t.Fatal("controlled post-admission build failure unavailable", executionErr)
		}
		if err := s.finalizeCleanupRun(t.Context(), root, &output, executionErr); err == nil {
			t.Fatal("failed cleanup lost its terminal error")
		}
		body, err := os.ReadFile(filepath.Join(s.directory, "run.json"))
		if err != nil {
			t.Fatal(err)
		}
		var result runRecord
		if err := records.ReadJSON(filepath.Join(s.directory, "run.json"), &result); err != nil {
			t.Fatal(err)
		}
		if result.Outcome != "failed" || result.FinishedAt == nil || result.Failure == nil || result.Failure.Class != "cleanup_run_failed" || result.Failure.Stage != "cleanup" || len(result.Scenarios) != 0 || result.RecoveryRunID != request.RunID {
			t.Fatalf("post-admission assembly refusal lost its durable failure: %+v", result.Failure)
		}
		assertPublicExecutionCapacity(t, body, map[string]int{"parallel": 2, "memory_limit_mib": 512}, 2, 512)
		for path, original := range before {
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(original, after) {
				t.Fatal("failed cleanup changed retained evidence", path, err)
			}
		}
	})
	for _, mode := range []string{"passed", "replacement_authority", "budget_exhausted", "missing_inventory", "failed_cleanup"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "")
			root, request, entries := recoveryFixture(t, 2)
			passed := mode == "passed" || mode == "replacement_authority"
			authority := "operator"
			if mode == "replacement_authority" {
				authority = "cleanup_operator"
				environment := environmentFor(entries[0].Input.Settings)
				participant := environment.Participants["operator"]
				participant.Access.CredentialsFile = filepath.Join(root, "replacement-credentials.json")
				if os.WriteFile(participant.Access.CredentialsFile, []byte("synthetic replacement credentials"), 0600) != nil {
					t.Fatal("replacement credential fixture")
				}
				environment.Participants = map[string]participantReference{authority: participant, "unused": {Access: accessReference{CredentialsFile: "/missing-unused-credentials"}}}
				environment.RoleBindings = map[string]string{"authority": authority, "observer": "unused"}
				request.Environment = filepath.Join(root, "replacement-environment.json")
				if records.WriteJSON(request.Environment, environment, 0600) != nil {
					t.Fatal("replacement environment fixture")
				}
			}
			if mode == "passed" {
				for i := range entries {
					entries[i].Input.Scenarios[0], _ = catalog.HistoricalName("state.single-value-update-preserves-other-values")
					if records.WriteJSON(entries[i].InputPath, entries[i].Input, 0400) != nil {
						t.Fatal("canonical recovery input")
					}
				}
			}
			plan, err := prepareRecovery(root, request)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "budget_exhausted" {
				plan.Limits.CleanupRequests = 5
			}
			if mode == "missing_inventory" && os.Remove(filepath.Join(entries[0].State, "inventory.json")) != nil {
				t.Fatal("inventory fixture")
			}
			if mode == "failed_cleanup" {
				plan.Settings["test_mode"] = "failed_cleanup"
			}
			original := make([][]byte, len(entries))
			for i, entry := range entries {
				original[i], err = os.ReadFile(entry.InputPath)
				if err != nil {
					t.Fatal(err)
				}
			}
			s, err := newRunState(root, runRequest{Suite: "live", Provider: "gcp", Target: "gcp", Schedule: recoverySchedule(plan)}, records.Source{}, "controlled")
			if err != nil {
				t.Fatal(err)
			}
			s.record.RecoveryRunID = request.RunID
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			if err := s.executeRecovery(context.Background(), binary, plan); err != nil {
				t.Fatal(err)
			}
			s.finish()
			if (s.record.Outcome == "passed") != passed || s.record.FullCoverage || s.record.Correctness.Passed {
				t.Fatal("recovery claimed transition correctness or wrong outcome")
			}
			if cleanupPassed(s.record.Cleanup) != passed {
				t.Fatal("recovery claimed aggregate cleanup for an unchecked or unresolved inventory")
			}
			want := 1
			if passed {
				want = 2
			}
			if len(s.record.Scenarios) != want {
				t.Fatal("cleanup did not share one budget or stop on failure")
			}
			for i, item := range s.record.Scenarios {
				if item.Writer != nil || len(item.Children) != 0 || len(item.PostExit) != 0 {
					t.Fatal("recovery resumed writer work")
				}
				path := filepath.Join(s.private, fmt.Sprintf("%04d-state-single-value-update-preserves-other-values", i), "cleanup", "invocation.json")
				inv, err := records.LoadInvocation(path)
				if err != nil || inv.StateDir != entries[i].State || inv.RunID == request.RunID || !strings.HasPrefix(inv.OutputDir, s.private+string(filepath.Separator)) || inv.Role != "cleanup" {
					t.Fatalf("recovery ownership: %v", err)
				}
				var input workerInput
				if records.ReadJSON(inv.Input, &input) != nil || input.RunID != request.RunID || input.Prefix != entries[i].Input.Prefix {
					t.Fatal("recovery adopted new output ownership for original objects")
				}
				if len(input.Participants) != 1 || input.Participants["authority"] != authority || len(input.ObserverSettings) != 0 || len(input.ReaderSettings) != 0 || len(input.RecoverySettings) != 0 || len(input.DeniedReaderSettings) != 0 || input.Settings["credentials_file"] != plan.Settings["credentials_file"] {
					t.Fatal("cleanup used or retained another participant route")
				}
				if item.CleanupWorker != nil {
					if len(item.CleanupWorker.Phases) == 0 {
						t.Fatal("cleanup worker has no completed phase evidence")
					}
					if item.CleanupWorker.Actor != authority || item.CleanupWorker.Phases[0].Actor != authority {
						t.Fatal("cleanup evidence reports the old authority participant")
					}
				}
			}
			for i, entry := range entries {
				after, err := os.ReadFile(entry.InputPath)
				if err != nil || !bytes.Equal(after, original[i]) {
					t.Fatal("recovery changed original input bytes")
				}
				if _, err := os.Stat(filepath.Join(entry.State, "worker.json")); !os.IsNotExist(err) {
					t.Fatal("recovery reused original writer output")
				}
			}
		})
	}
}

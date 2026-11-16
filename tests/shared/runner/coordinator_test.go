package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/observability"
	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/telemetry"
)

func prebuiltWorkerArgumentFixture(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "worker")
	body := "#!/bin/bash\nprintf '%s\\n' \"$@\" > \"$0.arguments\"\nexit 7\n"
	if err := os.WriteFile(binary, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	return binary
}

func assertPrebuiltWorkerArguments(t *testing.T, binary string, result processResult, want []string) {
	t.Helper()
	var exit *exec.ExitError
	if result.Status != "process_failed" || !result.Started || !result.Joined || !errors.As(result.Cause, &exit) || exit.ExitCode() != 7 {
		t.Fatalf("controlled worker did not record and join its refusal: %+v", result)
	}
	body, err := os.ReadFile(binary + ".arguments")
	if err != nil {
		t.Fatal("worker arguments unavailable", err)
	}
	got := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("worker arguments = %q, want %q", got, want)
	}
}

// full_only: false
func TestCoordinatorWorkerCommandsUseOneTestLane(t *testing.T) {
	for _, test := range []struct {
		suite, role, name string
		parallel          int
	}{
		{"hermetic", "writer", "TestHermeticRun", 1},
		{"live", "writer", "TestLiveRun", 2},
		{"hermetic", "fresh_before", "TestHermeticChild", 3},
		{"hermetic", "fresh_after", "TestHermeticChild", 2},
		{"live", "fresh_after", "TestLiveChild", 1},
		{"live", "cleanup", "TestLiveCleanup", 2},
		{"live", "rerun", "TestLiveRecovery", 3},
	} {
		t.Run(test.suite+"-"+test.role, func(t *testing.T) {
			for _, parentLimit := range []time.Duration{0, 45 * time.Second} {
				t.Run(parentLimit.String(), func(t *testing.T) {
					binary := prebuiltWorkerArgumentFixture(t)
					root := filepath.Dir(binary)
					inv := records.Invocation{Role: test.role, OutputDir: root}
					ctx := withExecutionParallel(t.Context(), test.parallel)
					if parentLimit != 0 {
						var cancel context.CancelFunc
						ctx, cancel = context.WithTimeout(ctx, parentLimit)
						defer cancel()
					}
					const requested = time.Minute
					before := time.Now()
					result := runInvocation(ctx, binary, root, test.suite, inv, requested, false)
					after := time.Now()
					alarm := "1h"
					if test.suite == "hermetic" {
						body, err := os.ReadFile(binary + ".arguments")
						if err != nil {
							t.Fatal("worker arguments unavailable", err)
						}
						args := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
						if len(args) != 3 || !strings.HasPrefix(args[1], "-test.timeout=") {
							t.Fatal("worker timeout argument unavailable", args)
						}
						alarm = strings.TrimPrefix(args[1], "-test.timeout=")
						got, err := time.ParseDuration(alarm)
						latest := before.Add(requested)
						if deadline, ok := ctx.Deadline(); ok && deadline.Before(latest) {
							latest = deadline
						}
						if err != nil || got <= 0 || got > latest.Sub(before) || got < latest.Sub(after) {
							t.Errorf("worker alarm = %q, want the remaining case allowance in [%s, %s]", alarm, latest.Sub(after), latest.Sub(before))
						}
					}
					assertPrebuiltWorkerArguments(t, binary, result, []string{"-test.run=^" + test.name + "$", "-test.timeout=" + alarm, "-test.parallel=1"})
				})
			}
		})
	}
	for _, test := range []struct {
		name    string
		timeout time.Duration
		cause   error
	}{
		{"zero_timeout", 0, context.DeadlineExceeded},
		{"negative_timeout", -time.Second, context.DeadlineExceeded},
		{"expired_parent", time.Minute, context.DeadlineExceeded},
		{"cancelled_parent", time.Minute, context.Canceled},
	} {
		t.Run("not_started_"+test.name, func(t *testing.T) {
			binary := prebuiltWorkerArgumentFixture(t)
			root := filepath.Dir(binary)
			ctx := t.Context()
			if test.name == "expired_parent" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
			}
			if test.name == "cancelled_parent" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			result := runInvocation(ctx, binary, root, "hermetic", records.Invocation{Role: "writer", OutputDir: root}, test.timeout, false)
			want := "timed_out"
			if errors.Is(test.cause, context.Canceled) {
				want = "interrupted"
			}
			if result.Status != want || result.Started || !result.Joined || !errors.Is(result.Cause, test.cause) {
				t.Fatal("exhausted case allowance did not refuse the worker before start", result)
			}
			if _, err := os.Stat(binary + ".arguments"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("exhausted worker ran", err)
			}
		})
	}
}

// full_only: false
func TestCoordinatorWorkerFailureDetailsStayWithinComposition(t *testing.T) {
	for _, selection := range []struct{ suite, failure string }{{"hermetic", "worker"}, {"hermetic", "current-owner"}, {"live", "worker"}, {"live", "parent-save"}, {"live", "receipt-save"}} {
		suite := selection.suite
		t.Run(suite+"/"+selection.failure, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "worker")
			const assertion = "synthetic-secret assertion: got 3, want 5"
			if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf '%s\\n' '"+assertion+"'\nprintf '%s\\n' 'synthetic-secret stderr' >&2\nexit 7\n"), 0700); err != nil {
				t.Fatal(err)
			}
			result := runInvocation(t.Context(), binary, filepath.Dir(binary), suite, records.Invocation{Role: "writer", OutputDir: filepath.Dir(binary)}, time.Minute, false)
			if result.Status != "process_failed" || !result.Started || !result.Joined {
				t.Fatal("controlled worker did not fail after a positive join", result)
			}
			if (result.diagnostic != nil) != (suite == "hermetic") {
				t.Error("worker failure capture differs from its composition")
			}
			public, err := json.Marshal(result)
			if err != nil || bytes.Contains(public, []byte("synthetic-secret")) {
				t.Fatal("raw worker output reached public process fields", err)
			}
			s, _ := coordinatorFixture(t)
			if suite == "hermetic" {
				original := s
				s, err = newRunState(original.root, runRequest{Suite: "hermetic", Provider: "memory", Target: "controlled", Schedule: original.record.Schedule}, records.Source{}, "controlled")
				if err != nil {
					t.Fatal(err)
				}
				owned := *s.current
				t.Cleanup(func() {
					if _, err := os.Lstat(owned.path); errors.Is(err, os.ErrNotExist) {
						return
					}
					if err := owned.remove(runProcessesJoined(s.record)); err != nil {
						t.Error("fixture current cleanup", err)
					}
				})
				resolved := *original.record.Resolved
				resolved.Mode = "hermetic"
				s.record.Resolved = &resolved
				s.record.Scenarios = original.record.Scenarios
				s.failureSources = controlledFailureSources(t, s.private)
			}
			if selection.failure == "parent-save" || selection.failure == "receipt-save" {
				body, err := os.ReadFile(binary)
				if err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(s.directory, "run.json")
				action := "rm -f '" + strings.ReplaceAll(target, "'", "'\"'\"'") + "'\nmkdir '" + strings.ReplaceAll(target, "'", "'\"'\"'") + "'\n"
				if selection.failure == "receipt-save" {
					target = filepath.Join(s.directory, caseReceiptPath(s.record.Scenarios[0].Sequence))
					action = "mkdir -p '" + strings.ReplaceAll(target, "'", "'\"'\"'") + "'\n"
				}
				body = bytes.Replace(body, []byte("exit 7"), []byte(action+"exit 7"), 1)
				if err := os.WriteFile(binary, body, 0700); err != nil {
					t.Fatal(err)
				}
			}
			var executionErr error
			if selection.failure == "receipt-save" {
				s.record.Scenarios = nil
				executionErr = s.executeSchedule(t.Context(), binary, liveSettings{"recovery_mode": "disabled"}, testLimits())
			} else {
				executionErr = s.executeScenario(t.Context(), binary, liveSettings{"recovery_mode": "disabled"}, testLimits(), &s.record.Scenarios[0])
			}
			scenario := &s.record.Scenarios[0]
			if executionErr == nil || scenario.Outcome != "failed" || scenario.CorrectnessPassed || scenario.Writer == nil || !scenario.Writer.Started || !scenario.Writer.Joined {
				t.Fatal("actual failed worker did not reach coordinator completion", executionErr, scenario.Outcome)
			}
			s.fail("scenario_failed", "execution")
			s.finish()
			if selection.failure == "current-owner" {
				s.current.identity = nil
			}
			var terminal bytes.Buffer
			finalizationErr := s.finishCurrentRun(&terminal, executionErr)
			if finalizationErr != nil && selection.failure == "worker" {
				t.Fatal("coordinator could not publish its failed result", finalizationErr)
			}
			if selection.failure == "current-owner" && finalizationErr == nil {
				t.Fatal("changed current owner did not fail finalization")
			}
			if suite == "hermetic" {
				if !strings.Contains(terminal.String(), assertion) || !strings.Contains(terminal.String(), "synthetic-secret stderr") {
					t.Error("coordinator terminal omitted hermetic assertion values", terminal.String())
				}
				_, statErr := os.Lstat(s.current.path)
				if selection.failure == "worker" && !errors.Is(statErr, os.ErrNotExist) {
					t.Error("joined hermetic current files were not removed", statErr)
				}
				if selection.failure == "current-owner" && statErr != nil {
					t.Error("refused current cleanup did not retain its files", statErr)
				}
			} else if strings.Contains(terminal.String(), "synthetic-secret") {
				t.Error("coordinator terminal exposed live raw output")
			}
			public, err = json.Marshal(s.record)
			if suite == "live" && selection.failure == "worker" {
				public, err = os.ReadFile(filepath.Join(s.directory, "run.json"))
			}
			if err != nil || bytes.Contains(public, []byte("synthetic-secret")) {
				t.Fatal("raw assertion reached public run fields", err)
			}
		})
	}
}

// These subprocess entries exercise the common coordinator protocol without
// provider credentials. Product and oracle behavior runs in the real assemblies.
type scenarioRepetitionWorkerObservation struct {
	Invocation          records.Invocation `json:"invocation"`
	Input               workerInput        `json:"input"`
	PID                 int                `json:"pid"`
	PreviousWorker      string             `json:"previous_worker,omitempty"`
	PreviousStateDir    string             `json:"previous_state_dir,omitempty"`
	PreviousStateStatus string             `json:"previous_state_status,omitempty"`
}

func coordinatorWorker(t *testing.T, role string) (records.Invocation, workerInput, *records.WorkerRecorder, *records.FailureRecorder, bool) {
	t.Helper()
	path := os.Getenv("ENKV_TEST_INVOCATION")
	if path == "" {
		t.Skip("controlled worker requires a coordinator invocation")
	}
	inv, err := records.LoadInvocation(path)
	if err != nil || inv.Role != role {
		t.Fatal("controlled invocation refused")
	}
	var input workerInput
	if records.ReadJSON(inv.Input, &input) != nil {
		t.Fatal("controlled input refused")
	}
	if directory := input.Settings["test_repetition_witness"]; directory != "" && role == "writer" {
		observation := scenarioRepetitionWorkerObservation{Invocation: inv, Input: input, PID: os.Getpid()}
		if input.Settings["test_repetition_lifetime"] == "true" {
			// A new real writer starts only after the preceding case returned.
			// Record the observed state; the worker never decides test success
			// from a cleanup expectation supplied by its parent.
			entries, err := os.ReadDir(directory)
			if err != nil {
				observation.PreviousStateStatus = "witness_read_failed"
			} else if len(entries) > 0 {
				var previous scenarioRepetitionWorkerObservation
				if records.ReadJSON(filepath.Join(directory, entries[len(entries)-1].Name()), &previous) != nil {
					observation.PreviousStateStatus = "witness_read_failed"
				} else {
					observation.PreviousWorker, observation.PreviousStateDir = previous.Invocation.Worker, previous.Invocation.StateDir
					info, err := os.Lstat(previous.Invocation.StateDir)
					switch {
					case os.IsNotExist(err):
						observation.PreviousStateStatus = "absent"
					case err != nil:
						observation.PreviousStateStatus = "inspection_failed"
					case info.IsDir():
						observation.PreviousStateStatus = "present"
					default:
						observation.PreviousStateStatus = "replaced"
					}
				}
			}
		}
		if records.WriteJSON(filepath.Join(directory, inv.Worker+".json"), observation, 0600) != nil {
			t.Fatal("actual repetition worker observation unavailable")
		}
	}
	if role == "rerun" {
		file, err := os.OpenFile(filepath.Join(inv.StateDir, "rerun-starts"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := file.WriteString(inv.Nonce + "\n")
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatal("controlled rerun start evidence")
		}
	}
	if strings.HasPrefix(input.Settings["test_mode"], "cleanup_retry_") && (role == "writer" || role == "fresh_after") {
		file, err := os.OpenFile(filepath.Join(inv.StateDir, role+"-starts"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := file.WriteString(inv.Nonce + "\n")
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatal("controlled Product start evidence")
		}
	}
	failure, err := records.NewFailureRecorder(inv)
	if err != nil {
		t.Fatal(err)
	}
	provider := "core"
	if input.PublicConfiguration != nil {
		provider = input.Settings["provider"]
	}
	if input.Outputs != nil {
		for _, profile := range input.Outputs.Profiles {
			if profile.Cloud != nil {
				provider = profile.Cloud.Provider
				break
			}
		}
	}
	worker, err := records.NewWorker(inv, provider, input.Scenarios[0], failure)
	if err != nil {
		t.Fatal(err)
	}
	roleName := "authority"
	if role == "cleanup" && input.PublicConfiguration != nil {
		roleName = "cleanup"
	}
	if role == "fresh_before" || role == "fresh_after" {
		execution, known := catalog.ExecutionFor(input.Scenarios[0], "live")
		if !known {
			t.Fatal("controlled execution facts unavailable")
		}
		roleName = execution.FreshAfter[0].Role
	}
	worker.Result.Actor = input.Participants[roleName]
	return inv, input, worker, failure, true
}

func controlledPhases(t *testing.T, worker *records.WorkerRecorder, input workerInput, role string) {
	t.Helper()
	steps := workerSteps(input.Scenarios[0], "live", role, worker.Result.Cleanup, nil, "")
	phases := passedWorkerPhases(input.Scenarios[0], "live", role, input.Participants, worker.Result.Cleanup, nil)
	for index, step := range steps {
		sequence, err := worker.BeginPhase(step.Name, phases[index].MeasurementsExpected)
		if err != nil {
			t.Fatal(err)
		}
		phase := &worker.Result.Phases[sequence-1]
		phase.Actor, phase.Expected = input.Participants[step.Role], step.Expected
		if input.Settings["test_mode"] == "telemetry_routes" || input.Settings["test_mode"] == "telemetry_timeout" || input.Settings["test_mode"] == "telemetry_write_failed" {
			telemetry.Start(worker.Context(context.Background()), telemetry.ProviderCore, telemetry.OpCoreOpen).Finish(telemetry.ResultAdmissionRefused)
		}
		if worker.EndPhase(context.Background(), sequence, !t.Failed()) != nil {
			t.Fatal("controlled phase finish")
		}
	}
}

// full_only: false
func TestLiveRun(t *testing.T) {
	inv, input, worker, failure, present := coordinatorWorker(t, "writer")
	if !present {
		return
	}
	mode := input.Settings["test_mode"]
	if mode == "first_writer_failure" && strings.HasPrefix(inv.Worker, "0000-") {
		mode = "failed_writer"
	}
	if mode == "repetition_leaf_save_second" && strings.HasPrefix(inv.Worker, "0002-") {
		// The real worker still completes. Only its later exclusive public
		// case receipt save encounters this test-owned storage collision.
		if err := os.Mkdir(filepath.Join(input.Settings["test_case_receipts"], "0002.json"), 0700); err != nil {
			t.Fatal("controlled case receipt collision unavailable", err)
		}
	}
	if mode == "repetition_failure_second" && strings.HasPrefix(inv.Worker, "0002-") {
		// The first selected case's second execution fails in the real worker.
		mode = "assertion_writer_cleanup"
	}
	defer func() {
		if worker.Finish(context.Background(), !t.Failed()) != nil {
			t.Error("controlled worker finish")
		}
		retainControlledFreshProcessFacts(t, inv)
		path := filepath.Join(inv.OutputDir, "worker.json")
		switch mode {
		case "missing_result", "assertion_missing_result":
			if os.Remove(path) != nil {
				t.Error("controlled missing result")
			}
		case "assertion_malformed_result":
			if os.WriteFile(path, []byte("{"), 0600) != nil {
				t.Error("controlled malformed result")
			}
		case "empty_phases", "failed_phase":
			if mode == "empty_phases" {
				worker.Result.Phases = nil
			} else {
				worker.Result.Phases[0].Outcome = "failed"
			}
			if records.WriteJSON(path, worker.Result, 0600) != nil {
				t.Error("controlled incomplete result")
			}
		}
	}()
	worker.Result.BudgetReserved = &records.BudgetReservation{Requests: 2, BodyBytes: 3, Objects: 1, ObjectBytes: 4}
	if mode != "missing_inventory" {
		if records.WriteJSON(filepath.Join(inv.StateDir, "inventory.json"), map[string]int{"version": 1}, 0600) != nil {
			t.Fatal("controlled inventory")
		}
	}
	if worker.Save() != nil {
		t.Fatal("controlled reservation")
	}
	if records.WriteJSON(filepath.Join(inv.StateDir, "ready.json"), map[string]bool{"reservation_saved": true}, 0600) != nil {
		t.Fatal("controlled readiness")
	}
	if input.Scenarios[0] == sameDomainRecoveryScenario {
		controlledRecoveryFailure(t, inv, input, worker, failure)
		return
	}
	if mode == "timeout_checkpoint" {
		sequence, phaseErr := worker.BeginPhase("authentication", true)
		if phaseErr != nil || worker.EndPhase(context.Background(), sequence, true) != nil {
			t.Fatal("controlled completed checkpoint")
		}
	}
	if mode == "timeout" || mode == "interrupt" || mode == "timeout_checkpoint" || mode == "telemetry_timeout" {
		time.Sleep(time.Hour)
	}
	switch mode {
	case "assertion_missing_result", "assertion_malformed_result", "assertion_writer_cleanup", "cleanup_retry_prior_failure_cancelled":
		failure.Record("fatal", controlledAssertionCaller, 1)
		t.Fatal("synthetic-secret worker assertion")
	case "assertion_write_fault":
		if os.Mkdir(filepath.Join(inv.OutputDir, "failure.json"), 0700) != nil {
			t.Fatal("marker write fault fixture")
		}
		failure.Record("fatal", controlledAssertionCaller, 1)
		t.Fatal("synthetic-secret unwritten assertion")
	case "assertion_malformed_marker":
		if os.WriteFile(filepath.Join(inv.OutputDir, "failure.json"), []byte("{"), 0600) != nil {
			t.Fatal("malformed marker fixture")
		}
		t.Fatal("synthetic-secret malformed marker")
	case "assertion_passing_marker":
		failure.Record("error", controlledAssertionCaller, 1)
	case "assertion_cleanup_callback":
		t.Cleanup(func() {
			failure.Record("error", controlledAssertionCaller, 2)
			t.Error("synthetic-secret deferred cleanup")
		})
	}
	if mode == "telemetry_write_failed" {
		if err := os.Mkdir(filepath.Join(inv.OutputDir, "telemetry.json"), 0700); err != nil {
			t.Fatal("controlled worker telemetry write failure", err)
		}
	}
	if mode == "failed_writer" {
		t.Fatal("synthetic-secret worker failure")
	}
	if records.WriteJSON(filepath.Join(inv.StateDir, "facts.json"), map[string]bool{"persisted": true}, 0400) != nil {
		t.Fatal("controlled facts")
	}
	worker.Result.FreshChecks = []records.FreshCheck{{Facts: "facts.json"}}
	execution, known := catalog.ExecutionFor(input.Scenarios[0], "live")
	if !known {
		t.Fatal("controlled execution facts unavailable")
	}
	for index, childFact := range execution.ExpandedFreshBefore() {
		step := childFact.Step
		child, err := makeInvocation(records.Invocation{Scenario: input.Scenarios[0], FailureSources: inv.FailureSources, RunID: inv.RunID, Worker: fmt.Sprintf("fresh-before-%s-%d", digestBytes([]byte(inv.Worker))[:12], index), Role: "fresh_before", Input: inv.Input, StateDir: inv.StateDir, OutputDir: filepath.Join(inv.OutputDir, fmt.Sprintf("fresh-before-%d", index)), Facts: "facts.json"}, "live")
		if err != nil {
			t.Fatal(err)
		}
		child.Nonce = inv.FreshBefore[index].Nonce
		if records.WriteJSON(filepath.Join(child.OutputDir, "invocation.json"), child, 0400) != nil {
			t.Fatal("controlled child binding")
		}
		owner, _, _, err := records.PrivateOwner(inv.StateDir)
		if err != nil {
			t.Fatal(err)
		}
		relative, err := filepath.Rel(owner, filepath.Join(child.OutputDir, "invocation.json"))
		if err != nil {
			t.Fatal(err)
		}
		worker.Result.Children = append(worker.Result.Children, records.ChildInvocation{Worker: child.Worker, Invocation: relative})
		result := records.WorkerResult{SchemaVersion: records.SchemaVersion, RunID: inv.RunID, Worker: child.Worker, Role: child.Role, Actor: input.Participants[step.Role], Scenario: input.Scenarios[0], Outcome: "passed", Phases: passedWorkerPhases(input.Scenarios[0], "live", child.Role, input.Participants, nil, &step), BudgetReserved: &records.BudgetReservation{Requests: 3, BodyBytes: 4}}
		if mode == "assertion_child_parent" {
			result.Outcome = "failed"
		}
		runControlledFreshProcess(t, child, result, mode)
	}
	if mode == "assertion_child_parent" {
		failure.Record("fatal", controlledAssertionCaller, 4)
		t.Fatal("synthetic-secret parent assertion")
	}
	controlledPhases(t, worker, input, "writer")
	if mode == "actual_fresh_parent_failed" {
		t.Error("controlled writer fails after its child completed")
	}
}

func controlledRecoveryHandoff(t *testing.T, input workerInput) records.RecoveryHandoff {
	t.Helper()
	// The P-256 base point and odd 3072-bit modulus are public structural
	// material, as in the contract tests. No private key or provider is needed.
	signing, err := hex.DecodeString("3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
	if err != nil {
		t.Fatal(err)
	}
	modulus := new(big.Int).Lsh(big.NewInt(1), 3071)
	modulus.Add(modulus, big.NewInt(12347))
	wrapping, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: modulus, E: 65537})
	if err != nil {
		t.Fatal(err)
	}
	kms := contract.KMSBinding{BindingID: contract.ID{11}, BindingIncarnationID: contract.ID{12}, BindingSerial: 1, Provider: contract.GCP,
		WrapProfile: contract.RSAOAEPWrapProfile, ProtectionClass: contract.SoftwareProtection,
		KeySelector: "projects/fixture/locations/us-central1/keyRings/ring/cryptoKeys/encryption/cryptoKeyVersions/1", SPKI: wrapping, Fingerprint: contract.Hash(wrapping)}
	descriptor := contract.GenesisDescriptorCore{
		InitID: contract.ID{1}, DomainID: contract.ID{2}, DescriptorArtifactID: contract.ID{3}, ManifestArtifactID: contract.ID{4},
		Provider: contract.GCP, StoreID: contract.ID{5}, CoordinateID: contract.ID{6}, NonBodyID: contract.ID{7}, TrustID: contract.ID{8},
		InterpretationID: contract.InterpretationID(), TrustInterpretationID: contract.TrustInterpretationID(), CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(),
		AuthorityRecipientID: contract.ID{9},
		NormalSigning: contract.PublicSigningBinding{Schema: contract.PublicSigningBindingSchema, Role: contract.NormalSigningRole, Provider: contract.GCP, SigningProfile: contract.P256SigningProfile, BindingID: contract.ID{10},
			KeySelector: "projects/fixture/locations/us-central1/keyRings/ring/cryptoKeys/signing/cryptoKeyVersions/1", SPKI: signing, Fingerprint: contract.Hash(signing),
			Binding: contract.BindingSubject{Domain: contract.ID{2}, Store: contract.ID{5}, Coordinate: contract.ID{6}, Trust: contract.ID{8}, PublicKey: contract.Hash(signing), Interpretation: contract.InterpretationID(), ControlIncarnationID: contract.ID{13}, Epoch: 1}},
		Recipients: []contract.RecipientRecord{{RecipientID: contract.ID{9}, Status: contract.CurrentRecipient, CurrentBinding: &kms}},
	}
	basis, err := contract.EncodeGenesisDescriptorCore(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	handoff := records.RecoveryHandoff{Version: 1, RunID: input.RunID, Scenario: input.Scenarios[0], Prefix: input.Prefix, Domain: contract.ID{2},
		Genesis: records.RecoveryGenesisIDs{Init: contract.ID{1}, Domain: contract.ID{2}, DescriptorArtifact: contract.ID{3}, ManifestArtifact: contract.ID{4}}, Basis: basis,
		Desired: []records.RecoveryPlainValue{{Name: "goal", Recipients: []contract.ID{{9}}, Value: []byte("restored")}}}
	if err := handoff.Validate(input.RunID, input.Scenarios[0], input.Prefix); err != nil {
		t.Fatal(err)
	}
	return handoff
}

func controlledRecoveryFailure(t *testing.T, inv records.Invocation, input workerInput, worker *records.WorkerRecorder, failure *records.FailureRecorder) {
	t.Helper()
	handoff := controlledRecoveryHandoff(t, input)
	if input.Settings["test_mode"] != "missing_recovery_handoff" {
		if records.WriteJSON(filepath.Join(inv.StateDir, "recovery-handoff.json"), handoff, 0400) != nil {
			t.Fatal("controlled recovery handoff")
		}
	}
	inventory := sameDomainInventoryRecord{Version: 1, RunID: input.RunID, Binding: "controlled", Prefix: input.Prefix, Domain: contract.ID{2}, Intents: []json.RawMessage{}, Deleted: map[string]int{}}
	if records.WriteJSON(filepath.Join(inv.StateDir, "inventory.json"), inventory, 0600) != nil {
		t.Fatal("controlled recovery inventory")
	}
	worker.Result.Failure = &records.Failure{Class: "store_transport_exhausted", Stage: "transition"}
	worker.Result.StoreFailure = &records.StoreFailure{StoreReason: "transport", Outcome: "evidence-unavailable", Reason: "write-uncertain"}
	switch input.Settings["test_mode"] {
	case "missing_store_failure":
		worker.Result.StoreFailure = nil
	case "mismatched_store_failure":
		worker.Result.StoreFailure.StoreReason = "access"
	}
	for _, step := range workerSteps(input.Scenarios[0], "live", "writer", nil, nil, "") {
		sequence, err := worker.BeginPhase(step.Name, true)
		if err != nil {
			t.Fatal(err)
		}
		worker.Result.Phases[sequence-1].Expected = step.Expected
		if worker.EndPhase(context.Background(), sequence, step.Name != "transition") != nil {
			t.Fatal("controlled recovery phase finish")
		}
		if step.Name == "transition" {
			break
		}
	}
	switch input.Settings["test_mode"] {
	case "failed_writer":
	case "assertion_malformed_marker", "failed_rerun", "missing_recovery_handoff":
		if os.WriteFile(filepath.Join(inv.OutputDir, "failure.json"), []byte("{"), 0600) != nil {
			t.Fatal("controlled recovery malformed marker")
		}
	default:
		failure.Record("fatal", controlledAssertionCaller, 1)
	}
	t.Fatal("synthetic-secret controlled transport failure")
}

// full_only: false
func TestLiveRecovery(t *testing.T) {
	inv, input, worker, failure, present := coordinatorWorker(t, "rerun")
	if !present {
		return
	}
	defer func() {
		if worker.Finish(context.Background(), !t.Failed()) != nil {
			t.Error("controlled rerun finish")
		}
	}()
	handoff, err := readSameDomainHandoff(inv.StateDir, input)
	if err != nil || handoff.Domain != (contract.ID{2}) || len(handoff.Desired) != 1 || handoff.Desired[0].Name != "goal" || !bytes.Equal(handoff.Desired[0].Value, []byte("restored")) || !slices.Equal(handoff.Desired[0].Recipients, []contract.ID{{9}}) {
		t.Fatal("controlled rerun lost the original domain or goal")
	}
	worker.Result.BudgetReserved = &records.BudgetReservation{Requests: 7, BodyBytes: 8, Objects: 1, ObjectBytes: 9}
	controlledPhases(t, worker, input, "rerun")
	if input.Settings["test_mode"] == "failed_rerun" {
		failure.Record("fatal", controlledAssertionCaller, 2)
		t.Fatal("synthetic-secret rerun failure")
	}
	if records.WriteJSON(filepath.Join(inv.StateDir, "facts.json"), map[string]bool{"persisted": true}, 0400) != nil {
		t.Fatal("controlled rerun facts")
	}
	worker.Result.FreshChecks = []records.FreshCheck{{Facts: "facts.json"}}
}

// full_only: false
func TestLiveChild(t *testing.T) {
	if os.Getenv("ENKV_FRESH_BEFORE_FIXTURE") != "" {
		runControlledFreshProcessChild(t)
		return
	}
	inv, input, worker, _, present := coordinatorWorker(t, "fresh_after")
	if !present {
		return
	}
	defer func() {
		if worker.Finish(context.Background(), !t.Failed()) != nil {
			t.Error("controlled child finish")
		}
	}()
	var facts map[string]bool
	if records.ReadJSON(filepath.Join(inv.StateDir, inv.Facts), &facts) != nil || !facts["persisted"] {
		t.Fatal("persisted facts required")
	}
	worker.Result.BudgetReserved = &records.BudgetReservation{Requests: 3, BodyBytes: 4}
	controlledPhases(t, worker, input, "fresh_after")
}

// full_only: false
func TestLiveCleanup(t *testing.T) {
	inv, input, worker, failure, present := coordinatorWorker(t, "cleanup")
	if !present {
		return
	}
	// The local cached-assembly fixture selects a failed controlled subprocess
	// after its immutable parent input and grant have already been admitted.
	if os.Getenv("ENKV_CONTROLLED_CLEANUP_FAILURE") == "1" {
		input.Settings["test_mode"] = "failed_cleanup"
	}
	if strings.HasPrefix(inv.Worker, "0002-") {
		switch input.Settings["test_mode"] {
		case "repetition_cleanup_second":
			input.Settings["test_mode"] = "failed_cleanup"
		case "repetition_unknown_second":
			input.Settings["test_mode"] = "cleanup_unknown_effect"
		}
	}
	defer func() {
		if worker.Finish(context.Background(), !t.Failed()) != nil {
			t.Error("controlled cleanup finish")
		}
		if input.Settings["test_mode"] == "repetition_unstarted_second" && strings.HasPrefix(inv.Worker, "0001-") {
			// Retire only the test-owned executable alias after the preceding
			// cleanup worker has saved its actual result. The next exec fails
			// before starting; the running binary and its source stay intact.
			if err := os.Remove(input.Settings["test_binary_alias"]); err != nil {
				t.Error("controlled executable alias retirement", err)
			}
		}
	}()
	if input.OutputRecovery != nil {
		zero := int64(0)
		reservation := &records.BudgetReservation{Requests: 5, BodyBytes: 6}
		worker.Result.BudgetReserved = reservation
		worker.Result.Cleanup = &records.Cleanup{Outcome: "passed", RemainingOwnedObjects: &zero, UnknownEffects: &zero, BudgetReserved: reservation}
		retainControlledOutputRecovery(t, inv, input)
		sequence, err := worker.BeginPhase("cleanup", true)
		if err != nil {
			t.Fatal(err)
		}
		worker.Result.Phases[sequence-1].Actor = input.Participants["cleanup"]
		worker.Result.Phases[sequence-1].Expected = "success"
		if input.Settings["test_mode"] == "output_recovery_before_store" {
			worker.Result.Cleanup = &records.Cleanup{Outcome: "unresolved", Failure: &records.Failure{Class: "cleanup_unresolved", Stage: "cleanup"}, BudgetReserved: reservation}
			failure.Record("fatal", controlledAssertionCaller, 1)
			t.Fatal("controlled recovery stopped before Store cleanup")
		}
		if worker.EndPhase(t.Context(), sequence, true) != nil {
			t.Fatal("controlled cleanup phase unavailable")
		}
		return
	}
	if records.WriteJSON(filepath.Join(inv.StateDir, "cleanup-called.json"), map[string]bool{"called": true}, 0600) != nil {
		t.Fatal("controlled cleanup marker")
	}
	if input.Settings["test_mode"] == "cleanup_retry_cancelled" && input.CleanupRetry == nil {
		time.Sleep(150 * time.Millisecond)
	}
	if input.Settings["test_mode"] == "cleanup_retry_prior_failure_cancelled" && input.CleanupRetry == nil {
		// Cleanup begins only after the parent has imported and saved the
		// original joined writer failure. Wait for the test's cancellation
		// acknowledgement before returning the first bounded cleanup failure.
		waitCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		tick := time.NewTicker(5 * time.Millisecond)
		defer tick.Stop()
		for {
			if _, err := os.Stat(filepath.Join(inv.StateDir, "cleanup-cancel-ack")); err == nil {
				break
			}
			select {
			case <-waitCtx.Done():
				t.Fatal("controlled cleanup cancellation acknowledgement unavailable")
			case <-tick.C:
			}
		}
	}
	zero := int64(0)
	reservation := &records.BudgetReservation{Requests: 5, BodyBytes: 6}
	worker.Result.BudgetReserved = reservation
	worker.Result.Cleanup = &records.Cleanup{Outcome: "passed", RemainingOwnedObjects: &zero, UnknownEffects: &zero, BudgetReserved: reservation}
	if input.Settings["test_mode"] == "publication_scheduled_empty" {
		reservation = &records.BudgetReservation{}
		worker.Result.BudgetReserved, worker.Result.Cleanup.BudgetReserved = reservation, reservation
	}
	if input.PublicConfiguration != nil {
		// A local handoff fixture supplies the same durable files as a joined
		// public cleanup worker. It claims no cloud request or Product result.
		for _, file := range []struct{ source, target string }{
			{"controlled-public-cleanup-snapshot.json", filepath.Join(inv.OutputDir, "public-configuration-evidence.json")},
			{"controlled-public-cleanup-inventory.json", filepath.Join(inv.StateDir, "public-cleanup-inventory.json")},
			{"controlled-public-cleanup-token-source.json", filepath.Join(inv.StateDir, "public-cleanup-inventory.json.token-evidence.json")},
		} {
			body, err := os.ReadFile(filepath.Join(inv.StateDir, file.source))
			if os.IsNotExist(err) {
				continue
			}
			if err != nil || os.WriteFile(file.target, body, 0600) != nil {
				t.Fatal("controlled public cleanup evidence unavailable")
			}
		}
		sequence, err := worker.BeginPhase("cleanup", true)
		if err != nil {
			t.Fatal(err)
		}
		phase := &worker.Result.Phases[sequence-1]
		phase.Actor, phase.Expected = input.Participants["cleanup"], "success"
		if err := worker.EndPhase(t.Context(), sequence, true); err != nil {
			t.Fatal(err)
		}
	} else {
		controlledPhases(t, worker, input, "cleanup")
	}
	if input.Settings["test_mode"] == "cleanup_unknown_effect" {
		one := int64(1)
		worker.Result.Cleanup.UnknownEffects = &one
		worker.Result.Cleanup.Outcome = "unresolved"
		t.Error("controlled unknown cleanup effect")
		return
	}
	if input.Settings["test_mode"] == "publication_scheduled_store_failure" {
		failure.Record("error", controlledAssertionCaller, 5)
		two, one, target := int64(2), int64(1), uint32(0)
		fact := records.HarnessFailure{Operation: "object_cleanup", Stage: "conditional_delete", Cause: "deadline", Effect: "unknown", TargetKind: "inventory", TargetIndex: &target, Attempt: 1}
		worker.Result.HarnessFailure, worker.Result.Cleanup.HarnessFailure = &fact, &fact
		worker.Result.Cleanup.RemainingOwnedObjects, worker.Result.Cleanup.UnknownEffects = &two, &one
		worker.Result.Cleanup.Outcome = "unresolved"
		t.Error("controlled Store cleanup failure after scheduled output deletion")
		return
	}
	if strings.HasPrefix(input.Settings["test_mode"], "publication_scheduled") {
		one := int64(1)
		worker.Result.Cleanup.RemainingOwnedObjects = &one
		return
	}
	if strings.HasPrefix(input.Settings["test_mode"], "cleanup_retry_") {
		ordinal := uint8(1)
		if input.CleanupRetry != nil {
			ordinal = input.CleanupRetry.Ordinal
			if input.CleanupRetry.TargetIndex != 0 {
				t.Fatal("controlled retry changed target")
			}
		}
		mode := input.Settings["test_mode"]
		if mode == "cleanup_retry_fail_once" && ordinal == 2 {
			return
		}
		if mode == "cleanup_retry_changed" && ordinal == 2 {
			one, target := int64(1), uint32(0)
			fact := records.HarnessFailure{Operation: "object_cleanup", Stage: "ownership_check", Cause: "ownership_mismatch",
				Effect: "no_send", TargetKind: "inventory", TargetIndex: &target}
			worker.Result.HarnessFailure, worker.Result.Cleanup.HarnessFailure = &fact, &fact
			worker.Result.Cleanup.RemainingOwnedObjects, worker.Result.Cleanup.UnknownEffects = &one, &one
			worker.Result.Cleanup.Outcome = "unresolved"
			t.Error("synthetic-secret changed cleanup target")
			return
		}
		failure.Record("error", controlledAssertionCaller, 5)
		one, status, target := int64(1), uint16(503), uint32(0)
		fact := records.HarnessFailure{Operation: "object_cleanup", Stage: "conditional_delete", Cause: "provider_refused",
			Effect: "unknown", HTTPStatus: &status, EnvelopeStatus: &status, TargetKind: "inventory", TargetIndex: &target, Attempt: ordinal}
		if mode == "cleanup_retry_permanent" {
			fact.Cause, fact.Effect, fact.HTTPStatus, fact.EnvelopeStatus, fact.Attempt = "access_refused", "no_send", nil, nil, 0
		}
		worker.Result.HarnessFailure, worker.Result.Cleanup.HarnessFailure = &fact, &fact
		worker.Result.Cleanup.RemainingOwnedObjects, worker.Result.Cleanup.UnknownEffects = &one, &one
		if mode == "cleanup_retry_permanent" {
			zero := int64(0)
			worker.Result.Cleanup.UnknownEffects = &zero
		}
		worker.Result.Cleanup.Outcome = "unresolved"
		t.Error("synthetic-secret cleanup retry failure")
		return
	}
	if input.Settings["test_mode"] == "typed_cleanup_cause" {
		failure.Record("error", controlledAssertionCaller, 5)
		one, status, target := int64(1), uint16(503), uint32(0)
		fact := records.HarnessFailure{Operation: "object_cleanup", Stage: "conditional_delete", Cause: "provider_refused",
			Effect: "unknown", HTTPStatus: &status, TargetKind: "inventory", TargetIndex: &target, Attempt: 1}
		worker.Result.HarnessFailure = &fact
		worker.Result.Cleanup.HarnessFailure = &fact
		worker.Result.Cleanup.RemainingOwnedObjects, worker.Result.Cleanup.UnknownEffects = &one, &one
		worker.Result.Cleanup.Outcome = "unresolved"
		t.Error("synthetic-secret cleanup failure")
		return
	}
	if input.Settings["test_mode"] == "failed_cleanup" || input.Settings["test_mode"] == "assertion_writer_cleanup" {
		failure.Record("error", controlledAssertionCaller, 5)
		one := int64(1)
		worker.Result.Cleanup.RemainingOwnedObjects = &one
		worker.Result.Cleanup.Outcome = "unresolved"
		t.Error("synthetic-secret cleanup failure")
	}
}

// full_only: false
func TestCoordinatorRetainsClosedCleanupCauseWithoutTelemetry(t *testing.T) {
	s, binary := coordinatorFixture(t)
	result := &s.record.Scenarios[0]
	if s.executeScenario(context.Background(), binary, liveSettings{"recovery_mode": "disabled", "test_mode": "typed_cleanup_cause"}, testLimits(), result) == nil ||
		!result.CorrectnessPassed || cleanupPassed(result.Cleanup) || result.Cleanup.HarnessFailure == nil ||
		result.Cleanup.HarnessFailure.Cause != "provider_refused" || result.Cleanup.UnknownEffects == nil || *result.Cleanup.UnknownEffects != 1 ||
		result.CleanupWorker == nil || !result.CleanupWorker.Joined || result.CleanupWorker.HarnessFailure == nil {
		t.Fatal("joined cleanup worker lost its typed cause or uncertainty")
	}
	s.finish()
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(filepath.Join(s.directory, "run.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"stage":"conditional_delete"`, `"cause":"provider_refused"`, `"effect":"unknown"`, `"http_status":503`} {
		if !bytes.Contains(saved, []byte(want)) {
			t.Fatal("saved run lost closed cleanup cause", want)
		}
	}
	if bytes.Contains(saved, []byte("synthetic-secret")) {
		t.Fatal("raw cleanup assertion escaped to public evidence")
	}
}

// full_only: false
func TestCleanupRecoveryDoesNotRepeatProductWork(t *testing.T) {
	for _, test := range []struct {
		mode, outcome, blocker string
		attempts               int
		requests               uint64
	}{
		{"cleanup_retry_fail_once", "passed", "", 2, 10},
		{"cleanup_retry_repeated", "failed", "attempts_exhausted", 3, 15},
		{"cleanup_retry_changed", "failed", "target_changed", 2, 10},
		{"cleanup_retry_permanent", "failed", "cause_ineligible", 0, 5},
		{"cleanup_retry_budget", "failed", "budget_exhausted", 0, 5},
	} {
		t.Run(test.mode, func(t *testing.T) {
			s, binary := coordinatorFixture(t)
			result := &s.record.Scenarios[0]
			allowance := testLimits()
			allowance.CleanupSeconds = 15
			allowance.CleanupRequests = 100
			allowance.CleanupBytes = 1000
			if test.mode == "cleanup_retry_budget" {
				allowance.CleanupRequests = 5
			}
			err := s.executeScenario(context.Background(), binary, liveSettings{"recovery_mode": "disabled", "test_mode": test.mode}, allowance, result)
			if (err == nil) != (test.outcome == "passed") || result.Outcome != test.outcome || !result.CorrectnessPassed || result.CleanupRetryBlocker != test.blocker || len(result.CleanupAttempts) != test.attempts {
				t.Fatalf("unexpected cleanup recovery: outcome=%s correct=%t blocker=%s attempts=%d error=%v", result.Outcome, result.CorrectnessPassed, result.CleanupRetryBlocker, len(result.CleanupAttempts), err)
			}
			state := filepath.Join(s.private, "0000-c2b1ece74d4795f96fc27a467324d41147e34a736c84f0fa7972738f5cf75981")
			for _, role := range []string{"writer", "fresh_after"} {
				body, err := os.ReadFile(filepath.Join(state, role+"-starts"))
				if err != nil || len(bytes.Split(bytes.TrimSpace(body), []byte("\n"))) != 1 {
					t.Fatal("cleanup retry repeated Product work", role, err)
				}
			}
			if result.Cleanup.BudgetReserved == nil || result.Cleanup.BudgetReserved.Requests != test.requests {
				t.Fatal("cleanup retry lost cumulative request reservations", result.Cleanup.BudgetReserved)
			}
			if test.attempts > 0 {
				for index, attempt := range result.CleanupAttempts {
					if int(attempt.Ordinal) != index+1 || attempt.Worker == nil || !attempt.Worker.Joined || attempt.TargetIndex == nil || *attempt.TargetIndex != 0 {
						t.Fatal("cleanup attempt receipt incomplete", index)
					}
				}
				if result.CleanupAttempts[0].Cleanup.Outcome != "unresolved" || result.CleanupAttempts[0].Cleanup.HarnessFailure == nil {
					t.Fatal("original cleanup failure disappeared")
				}
			}
			s.finish()
			if err := s.save(); err != nil {
				t.Fatal(err)
			}
			if test.attempts > 0 && (len(result.CleanupAttempts) == 0 || result.CleanupAttempts[0].Cleanup.Outcome != "unresolved") {
				t.Fatal("report lost original failure")
			}
		})
	}
}

// full_only: false
func TestCleanupRecoveryStopsOnCancellation(t *testing.T) {
	s, binary := coordinatorFixture(t)
	result := &s.record.Scenarios[0]
	allowance := testLimits()
	allowance.CleanupSeconds = 15
	allowance.CleanupRequests = 100
	allowance.CleanupBytes = 1000
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	state := filepath.Join(s.private, "0000-c2b1ece74d4795f96fc27a467324d41147e34a736c84f0fa7972738f5cf75981")
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		until := time.Now().Add(5 * time.Second)
		for time.Now().Before(until) {
			if _, err := os.Stat(filepath.Join(state, "cleanup-called.json")); err == nil {
				cancel()
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
	}()
	err := s.executeScenario(ctx, binary, liveSettings{"recovery_mode": "disabled", "test_mode": "cleanup_retry_cancelled"}, allowance, result)
	<-joined
	if err == nil || result.Outcome != "failed" || !result.CorrectnessPassed || result.CleanupRetryBlocker != "interrupted" || len(result.CleanupAttempts) != 0 || result.CleanupWorker == nil || !result.CleanupWorker.Joined {
		t.Fatalf("cancelled cleanup retry did not stop after joined initial worker: outcome=%s blocker=%s error=%v", result.Outcome, result.CleanupRetryBlocker, err)
	}
	if _, err := os.Stat(filepath.Join(state, "workers", "cleanup-retry-2")); !os.IsNotExist(err) {
		t.Fatal("cancelled cleanup started another worker")
	}
}

func coordinatorFixture(t *testing.T) (*runState, string) {
	t.Helper()
	t.Setenv("ENKV_TELEMETRY", "")
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	schedule, err := catalog.Resolve(catalog.Request{Include: []string{"state.single-value-update-preserves-other-values/members_32"}, Repetitions: 1})
	if err != nil {
		t.Fatal(err)
	}
	s, err := newRunState(root, runRequest{Suite: "live", Provider: "gcp", Target: "controlled", Schedule: schedule}, records.Source{}, "controlled toolchain")
	if err != nil {
		t.Fatal(err)
	}
	s.failureSources = controlledFailureSources(t, s.private)
	s.record.Resolved = &resolvedRequest{Mode: "live", RecoveryMode: "disabled", Provider: "gcp", Schedule: schedule, RoleBindings: map[string]string{"authority": "operator"}, Participants: []string{"operator"}}
	entry := schedule.Entries[0]
	shape, _ := recordedFixture(entry.Scenario, entry.Members)
	s.record.Scenarios = []scenarioResult{{Entry: entry, Fixture: shape, Outcome: "incomplete", Cleanup: unresolvedCleanup()}}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return s, binary
}

// full_only: false
func TestCoordinatorAssertionEvidencePreservesTypedRerun(t *testing.T) {
	for _, test := range []struct {
		name, mode, marker, rerun, failureStage string
		typed, correct, clean                   bool
	}{
		{"absent_marker", "failed_writer", "no_failure_marker", "passed", "", true, true, true},
		{"valid_marker", "store_transport_failure", "valid_failure_marker", "passed", "", true, true, true},
		{"invalid_marker", "assertion_malformed_marker", "invalid_failure_marker", "passed", "", true, true, true},
		{"missing_typed_failure", "missing_store_failure", "valid_failure_marker", "", "writer", false, false, true},
		{"mismatched_typed_failure", "mismatched_store_failure", "valid_failure_marker", "", "writer", false, false, true},
		{"cleanup_failure", "assertion_writer_cleanup", "valid_failure_marker", "passed", "", true, true, false},
		{"rerun_failure", "failed_rerun", "invalid_failure_marker", "failed", "rerun", true, false, true},
		{"missing_handoff", "missing_recovery_handoff", "invalid_failure_marker", "", "rerun", true, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, binary := coordinatorFixture(t)
			_, complete := coverageFixture(t)
			if !fullCoverage(complete) {
				t.Fatal("complete coverage control refused")
			}
			// The other entries retain the existing coverage fixture. Only the
			// recovery entry obtains evidence from these controlled processes.
			complete.RunID, complete.StartedAt, complete.FinishedAt = s.record.RunID, s.record.StartedAt, nil
			complete.Target, complete.Outcome = "controlled", "incomplete"
			s.record = complete
			index := slices.IndexFunc(s.record.Scenarios, func(result scenarioResult) bool { return result.Scenario == sameDomainRecoveryScenario })
			if index < 0 {
				t.Fatal("recovery scenario missing from coverage fixture")
			}
			result := &s.record.Scenarios[index]
			*result = scenarioResult{Entry: result.Entry, Fixture: result.Fixture, Outcome: "incomplete", Cleanup: unresolvedCleanup()}
			allowance := testLimits()
			allowance.ElapsedSeconds = 30
			passed := test.correct && test.clean
			err := s.executeScenario(context.Background(), binary, liveSettings{"recovery_mode": "disabled", "test_mode": test.mode}, allowance, result)
			if (err == nil) != passed || (result.Outcome == "passed") != passed || result.CorrectnessPassed != test.correct || cleanupPassed(result.Cleanup) != test.clean {
				t.Fatalf("execution, correctness, or cleanup changed: outcome=%s correct=%t cleanup=%s error=%v", result.Outcome, result.CorrectnessPassed, result.Cleanup.Outcome, err)
			}
			if test.failureStage == "" {
				if result.Failure != nil {
					t.Fatal("cleanup replaced successful recovery with execution failure")
				}
			} else {
				class := "writer_failed"
				if test.failureStage == "rerun" {
					class = "same_domain_rerun_failed"
				}
				if result.Failure == nil || *result.Failure != (records.Failure{Class: class, Stage: test.failureStage}) {
					t.Fatal("failure occurred at a different boundary", result.Failure)
				}
			}
			if result.Writer == nil || result.Writer.Role != "writer" || result.Writer.Outcome != "failed" || result.Writer.Process != "process_failed" || !result.Writer.Joined || len(result.Children) != 0 {
				t.Fatal("first writer failure or positive join was lost")
			}
			assertions := result.Writer.Assertions
			if assertions == nil || assertions.Marker != test.marker || assertions.Checkpoint != "valid_checkpoint" || assertions.Completed != (records.CompletedCheckpoint{Code: "setup", Sequence: 3}) || assertions.MarkerWriteError {
				t.Fatal("writer marker or last completed checkpoint changed", assertions)
			}
			if len(result.Writer.Phases) != 4 || result.Writer.Phases[3].Name != "transition" || result.Writer.Phases[3].Outcome != "failed" || result.Writer.Phases[3].Actual != "failed" {
				t.Fatal("writer did not reach the intended transport failure")
			}
			wantFailure := records.Failure{Class: "store_transport_exhausted", Stage: "transition"}
			wantStore := records.StoreFailure{StoreReason: "transport", Outcome: "evidence-unavailable", Reason: "write-uncertain"}
			if test.typed {
				if result.Writer.Failure == nil || *result.Writer.Failure != wantFailure || result.Writer.StoreFailure == nil || *result.Writer.StoreFailure != wantStore {
					t.Fatal("assertion evidence replaced the first typed failure")
				}
			} else if result.Writer.StoreFailure != nil {
				t.Fatal("assertion evidence supplied typed recovery permission")
			}
			if test.rerun == "" {
				if result.Rerun != nil || result.FirstFailure != nil {
					t.Fatal("refused recovery started a command")
				}
			} else if result.Rerun == nil || result.Rerun.Role != "rerun" || result.Rerun.Outcome != test.rerun || !result.Rerun.Joined || result.FirstFailure == nil || *result.FirstFailure != wantFailure {
				t.Fatal("rerun evidence replaced or lost the first failure")
			}
			if test.rerun == "passed" {
				if result.Rerun.Process != "passed" || result.Rerun.Failure != nil || len(result.PostExit) != 1 || result.PostExit[0].Role != "fresh_after" || result.PostExit[0].Process != "passed" || result.PostExit[0].Outcome != "passed" || !result.PostExit[0].Joined {
					t.Fatal("successful rerun or independent cold reopen was not imported")
				}
			} else if len(result.PostExit) != 0 || test.rerun == "failed" && result.Rerun.Process != "process_failed" {
				t.Fatal("failed or refused rerun started a cold reopen")
			}
			wantBudget := records.BudgetReservation{Requests: 2, BodyBytes: 3, Objects: 1, ObjectBytes: 4}
			if test.rerun == "passed" {
				wantBudget = records.BudgetReservation{Requests: 12, BodyBytes: 15, Objects: 2, ObjectBytes: 13}
			} else if test.rerun == "failed" {
				wantBudget = records.BudgetReservation{Requests: 9, BodyBytes: 11, Objects: 2, ObjectBytes: 13}
			}
			if result.BudgetReserved == nil || *result.BudgetReserved != wantBudget || result.Cleanup.BudgetReserved == nil || *result.Cleanup.BudgetReserved != (records.BudgetReservation{Requests: 5, BodyBytes: 6}) {
				t.Fatal("first, rerun, cold reopen, or independent cleanup reservation was lost")
			}
			name, err := currentCaseDirectory(result.Entry)
			if err != nil {
				t.Fatal("current recovery case directory unavailable", err)
			}
			state := filepath.Join(s.private, name)
			writerInv, err := records.LoadInvocation(filepath.Join(state, "workers", "writer", "invocation.json"))
			if err != nil {
				t.Fatal(err)
			}
			var input workerInput
			if records.ReadJSON(writerInv.Input, &input) != nil || input.RunID != s.record.RunID || !slices.Equal(input.Scenarios, []string{sameDomainRecoveryScenario}) || input.RecoveryMode != "disabled" || len(input.Participants) != 1 || input.Participants["authority"] != "operator" {
				t.Fatal("recovery control has an unrelated input or participant error")
			}
			handoff, handoffErr := readSameDomainHandoff(state, input)
			if test.mode == "missing_recovery_handoff" {
				if handoffErr == nil {
					t.Fatal("missing handoff control supplied a handoff")
				}
			} else if handoffErr != nil || handoff.Domain != (contract.ID{2}) {
				t.Fatal("recovery control has an unrelated handoff error", handoffErr)
			}
			var raw records.WorkerResult
			if records.ReadJSON(filepath.Join(writerInv.OutputDir, "worker.json"), &raw) != nil || raw.Failure == nil || *raw.Failure != wantFailure {
				t.Fatal("controlled writer did not retain its original failure")
			}
			if test.mode == "missing_store_failure" {
				if raw.StoreFailure != nil {
					t.Fatal("missing typed failure control supplied StoreFailure")
				}
			} else {
				if test.mode == "mismatched_store_failure" {
					wantStore.StoreReason = "access"
				}
				if raw.StoreFailure == nil || *raw.StoreFailure != wantStore {
					t.Fatal("writer did not reach the intended typed failure control")
				}
			}
			if _, err := readWorkerResult(writerInv, sameDomainRecoveryScenario); err != nil {
				t.Fatal("recovery control failed before the typed failure boundary", err)
			}
			var cleaned map[string]bool
			if records.ReadJSON(filepath.Join(state, "cleanup-called.json"), &cleaned) != nil || !cleaned["called"] || result.CleanupWorker == nil || !result.CleanupWorker.Joined {
				t.Fatal("cleanup did not run after the settled worker sequence")
			}
			type workerExpectation struct {
				directory, worker, role, marker string
				evidence                        *workerEvidence
			}
			workers := []workerExpectation{
				{"writer", name + "-writer", "writer", test.marker, result.Writer},
				{"cleanup", name + "-writer-cleanup", "cleanup", "no_failure_marker", result.CleanupWorker},
			}
			if !test.clean {
				workers[1].marker = "valid_failure_marker"
				if result.CleanupWorker.Process != "process_failed" || result.CleanupWorker.Outcome != "failed" || result.Cleanup.RemainingOwnedObjects == nil || *result.Cleanup.RemainingOwnedObjects != 1 {
					t.Fatal("cleanup failure was hidden by successful recovery")
				}
			} else if result.CleanupWorker.Process != "passed" || result.CleanupWorker.Outcome != "passed" {
				t.Fatal("successful cleanup worker was not imported")
			}
			if test.rerun != "" {
				marker := "no_failure_marker"
				if test.rerun == "failed" {
					marker = "valid_failure_marker"
				}
				workers = append(workers, workerExpectation{"rerun", name + "-writer-rerun", "rerun", marker, result.Rerun})
				var rerunInput workerInput
				if records.ReadJSON(filepath.Join(state, "rerun-input.json"), &rerunInput) != nil || rerunInput.RunID != input.RunID || rerunInput.Prefix != input.Prefix || !slices.Equal(rerunInput.Scenarios, input.Scenarios) || rerunInput.Limits == nil || rerunInput.Limits.Requests != allowance.Requests-2 || rerunInput.Limits.BodyBytes != allowance.BodyBytes-3 || rerunInput.Limits.Objects != allowance.Objects-1 || rerunInput.Limits.ObjectBytes != allowance.ObjectBytes-4 || rerunInput.Limits.ElapsedSeconds == 0 || rerunInput.Limits.ElapsedSeconds >= allowance.ElapsedSeconds {
					t.Fatal("rerun changed the domain input or reset its first reservation")
				}
			}
			if test.rerun == "passed" {
				workers = append(workers, workerExpectation{"fresh-0000-after", name + "-fresh-0000-after", "fresh_after", "no_failure_marker", &result.PostExit[0]})
			}
			entries, err := os.ReadDir(filepath.Join(state, "workers"))
			if err != nil || len(entries) != len(workers) {
				t.Fatal("coordinator omitted a worker or exceeded the one-rerun bound", err)
			}
			nonces := map[string]bool{}
			for _, want := range workers {
				inv, err := records.LoadInvocation(filepath.Join(state, "workers", want.directory, "invocation.json"))
				if err != nil || inv.RunID != s.record.RunID || inv.Scenario != sameDomainRecoveryScenario || inv.Worker != want.worker || inv.Role != want.role || inv.StateDir != state || inv.Nonce == "" || nonces[inv.Nonce] {
					t.Fatal("writer, rerun, cold reopen, and cleanup did not retain distinct bindings", err)
				}
				nonces[inv.Nonce] = true
				if want.evidence.Worker != want.worker || want.evidence.Role != want.role || want.evidence.Assertions == nil || want.evidence.Assertions.Marker != want.marker {
					t.Fatal("imported assertion evidence differs from its invocation", want.role)
				}
				if got := records.InspectAssertions(inv, want.marker == "no_failure_marker" && want.role != "writer"); got.Marker != want.marker {
					t.Fatal("worker assertion evidence crossed invocation bindings", want.role, got)
				}
				if want.role == "rerun" {
					starts, err := os.ReadFile(filepath.Join(state, "rerun-starts"))
					if err != nil || string(starts) != inv.Nonce+"\n" {
						t.Fatal("coordinator did not start exactly one rerun process", err)
					}
				}
			}
			if test.rerun == "" {
				if _, err := os.Stat(filepath.Join(state, "rerun-starts")); !os.IsNotExist(err) {
					t.Fatal("refused recovery entered a rerun process", err)
				}
			}
			s.finish()
			if s.record.Correctness.Passed != test.correct || s.record.Correctness.EvidenceComplete != test.correct || (s.record.Outcome == "passed") != passed || fullCoverage(s.record) != passed {
				t.Fatal("complete-run checks changed recovery or cleanup outcome")
			}
			if err := s.save(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(filepath.Join(s.directory, "run.json"))
			if err != nil {
				t.Fatal(err)
			}
			if s.record.Scenarios[index].Writer == nil || s.record.Scenarios[index].Writer.Assertions == nil || s.record.Scenarios[index].Writer.Assertions.Marker != test.marker {
				t.Fatal("current run lost its assertion marker")
			}
			if (s.record.Scenarios[index].FirstFailure != nil) != (test.rerun != "") {
				t.Fatal("current run changed first command failure")
			}
			for nonce := range nonces {
				if bytes.Contains(before, []byte(nonce)) {
					t.Fatal("private invocation nonce reached public evidence")
				}
			}
			if bytes.Contains(before, []byte("synthetic-secret")) {
				t.Fatal("controlled assertion text reached public evidence")
			}
			after, err := os.ReadFile(filepath.Join(s.directory, "run.json"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("report regeneration changed retained worker evidence")
			}
		})
	}
}

func coordinatorTelemetryDeliveryDetails(t *testing.T, directory, signal string, status records.DeliveryStatus, diagnostics records.Diagnostics) []byte {
	t.Helper()
	diagnostics.Source = ""
	facts := struct {
		Status         records.DeliveryStatus
		Diagnostics    records.Diagnostics
		RawReadStatus  string
		RawDeliveries  map[string]records.DeliveryStatus
		RawDiagnostics records.Diagnostics
		FileStatus     string
		Bytes          int
		Lines          int
		Truncated      bool
	}{Status: status, Diagnostics: diagnostics, RawReadStatus: "read_failed"}
	var raw records.WorkerResult
	if err := records.ReadJSON(filepath.Join(directory, "worker.json"), &raw); err == nil {
		raw.Diagnostics.Source = ""
		facts.RawReadStatus, facts.RawDeliveries, facts.RawDiagnostics = "read", raw.Deliveries, raw.Diagnostics
	}
	file, err := os.Open(filepath.Join(directory, "telemetry", signal+".jsonl"))
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			facts.FileStatus = "missing"
		case errors.Is(err, os.ErrPermission):
			facts.FileStatus = "permission_denied"
		default:
			facts.FileStatus = "open_failed"
		}
	} else {
		const maximumDiagnosticBytes = 64 << 10
		body, readErr := io.ReadAll(io.LimitReader(file, maximumDiagnosticBytes+1))
		closeErr := file.Close()
		facts.FileStatus = "read"
		if readErr != nil {
			facts.FileStatus = "read_failed"
		} else if closeErr != nil {
			facts.FileStatus = "close_failed"
		}
		if len(body) > maximumDiagnosticBytes {
			body, facts.Truncated = body[:maximumDiagnosticBytes], true
		}
		facts.Bytes, facts.Lines = len(body), bytes.Count(body, []byte{'\n'})
	}
	body, err := json.Marshal(facts)
	if err != nil {
		t.Fatal("encode closed telemetry delivery facts", err)
	}
	return body
}

// full_only: false
func TestCoordinatorJoinsWorkersAndKeepsCleanupIndependent(t *testing.T) {
	const localTelemetry = `{"schema_version":1,"logs":{"level":"warn","exporters":["local"]},"metrics":{"exporters":["local"]},"traces":{"sample_ratio":1,"exporters":["local"]},"exporters":{"local":{"type":"otlp_file","directory":"telemetry"}}}`
	t.Run("selected_telemetry", func(t *testing.T) {
		s, binary := coordinatorFixture(t)
		settings, err := observability.Decode([]byte(localTelemetry), observability.Options{})
		if err != nil {
			t.Fatal(err)
		}
		s.telemetrySettings = &settings
		s.record.Telemetry = records.Telemetry{Enabled: true, Status: "incomplete"}
		s.record.EffectiveTelemetry = summarizeTelemetry(settings, observability.Options{})
		result := &s.record.Scenarios[0]
		if err := s.executeScenario(context.Background(), binary, liveSettings{"recovery_mode": "disabled", "test_mode": "telemetry_routes"}, testLimits(), result); err != nil {
			t.Fatal("controlled telemetry workers failed", err)
		}
		if !result.CorrectnessPassed || !cleanupPassed(result.Cleanup) || result.Writer == nil || result.CleanupWorker == nil || len(result.PostExit) != 1 {
			t.Fatal("telemetry changed coordinator execution or cleanup")
		}
		state := filepath.Join(s.private, "0000-c2b1ece74d4795f96fc27a467324d41147e34a736c84f0fa7972738f5cf75981")
		for _, item := range []struct {
			directory, role string
			worker          *workerEvidence
		}{
			{"writer", "writer", result.Writer},
			{"fresh-0000-after", "fresh_after", &result.PostExit[0]},
			{"cleanup", "cleanup", result.CleanupWorker},
		} {
			inv, err := records.LoadInvocation(filepath.Join(state, "workers", item.directory, "invocation.json"))
			if err != nil || inv.Role != item.role || inv.Worker != item.worker.Worker || !reflect.DeepEqual(inv.TelemetrySettings, &settings) {
				t.Fatal("worker lost the selected telemetry settings", item.role, err)
			}
			if item.worker.Outcome != "passed" || item.worker.Process != "passed" || !item.worker.Joined || item.worker.Telemetry.Status != "complete" || len(item.worker.Deliveries) != 3 {
				t.Fatal("worker telemetry or execution evidence incomplete", item.role)
			}
			for _, signal := range []string{"logs", "metrics", "traces"} {
				status, exists := item.worker.Deliveries[signal+".file"]
				if !exists || status.EvidenceIncomplete() || *status.Written == 0 || *status.Accepted != *status.Written || *status.Dropped != 0 || *status.Failed != 0 {
					t.Fatalf("worker lost selected file delivery: role=%s signal=%s exists=%t facts=%s", item.role, signal, exists, coordinatorTelemetryDeliveryDetails(t, inv.OutputDir, signal, status, item.worker.Diagnostics))
				}
				body, err := os.ReadFile(filepath.Join(inv.OutputDir, "telemetry", signal+".jsonl"))
				if err != nil || len(body) == 0 {
					t.Fatal("worker output was not local to its invocation", item.role, signal, err)
				}
			}
		}
		// The existing coordinator fixture fabricates fresh-before protocol
		// evidence. It cannot qualify that child's telemetry; the real launcher
		// witness owns propagation through actual fresh-before processes.
		for _, child := range result.Children {
			for _, status := range child.Deliveries {
				if !status.EvidenceIncomplete() {
					t.Fatal("controlled child invented telemetry delivery")
				}
			}
		}
	})
	t.Run("selected_telemetry_timeout", func(t *testing.T) {
		s, binary := coordinatorFixture(t)
		settings, err := observability.Decode([]byte(localTelemetry), observability.Options{})
		if err != nil {
			t.Fatal(err)
		}
		s.telemetrySettings = &settings
		s.record.Telemetry = records.Telemetry{Enabled: true, Status: "incomplete"}
		s.record.EffectiveTelemetry = summarizeTelemetry(settings, observability.Options{})
		allowance := testLimits()
		allowance.ElapsedSeconds = 1
		result := &s.record.Scenarios[0]
		if err := s.executeScenario(context.Background(), binary, liveSettings{"recovery_mode": "disabled", "test_mode": "telemetry_timeout"}, allowance, result); err == nil {
			t.Fatal("timed-out writer supplied success")
		}
		if result.CorrectnessPassed || result.Failure == nil || len(result.PostExit) != 0 || !cleanupPassed(result.Cleanup) {
			t.Fatal("termination lost execution failure or independent cleanup")
		}
		writer, cleanup := result.Writer, result.CleanupWorker
		if writer == nil || !writer.Joined || writer.Process != "timed_out" || writer.Outcome != "failed" || len(writer.Deliveries) != 3 || !s.telemetryIncomplete {
			t.Fatal("terminated writer did not retain joined incomplete evidence")
		}
		for _, signal := range []string{"logs", "metrics", "traces"} {
			status, exists := writer.Deliveries[signal+".file"]
			if !exists || !status.EvidenceIncomplete() || status.Accepted != nil || status.Written != nil || status.Dropped != nil || status.Failed != nil || status.Incomplete != nil {
				t.Fatal("terminated writer invented final delivery counters", signal)
			}
		}
		if cleanup == nil || !cleanup.Joined || cleanup.Process != "passed" || cleanup.Outcome != "passed" || cleanup.Telemetry.Status != "complete" || len(cleanup.Deliveries) != 3 {
			t.Fatal("writer timeout prevented cleanup telemetry")
		}
		state := filepath.Join(s.private, "0000-c2b1ece74d4795f96fc27a467324d41147e34a736c84f0fa7972738f5cf75981")
		for _, role := range []string{"writer", "cleanup"} {
			inv, err := records.LoadInvocation(filepath.Join(state, "workers", role, "invocation.json"))
			if err != nil || inv.Role != role || !reflect.DeepEqual(inv.TelemetrySettings, &settings) {
				t.Fatal("termination changed the selected telemetry settings", role, err)
			}
		}
		for _, signal := range []string{"logs", "metrics", "traces"} {
			status, exists := cleanup.Deliveries[signal+".file"]
			if !exists || status.EvidenceIncomplete() || *status.Accepted != *status.Written || *status.Dropped != 0 || *status.Failed != 0 || signal != "logs" && *status.Written == 0 {
				t.Fatalf("cleanup lost selected file delivery: signal=%s exists=%t facts=%s", signal, exists, coordinatorTelemetryDeliveryDetails(t, filepath.Join(state, "workers/cleanup"), signal, status, cleanup.Diagnostics))
			}
		}
	})
	for _, mode := range []string{"passed", "failed_writer", "missing_inventory", "failed_cleanup", "timeout", "interrupt", "missing_result", "empty_phases", "failed_phase"} {
		t.Run(mode, func(t *testing.T) {
			s, binary := coordinatorFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			allowance := testLimits()
			allowance.ElapsedSeconds = 10
			if mode == "timeout" {
				allowance.ElapsedSeconds = 1
			}
			state := filepath.Join(s.private, "0000-c2b1ece74d4795f96fc27a467324d41147e34a736c84f0fa7972738f5cf75981")
			interruptDone := make(chan struct{})
			if mode == "interrupt" {
				go func() {
					defer close(interruptDone)
					deadline := time.Now().Add(5 * time.Second)
					for time.Now().Before(deadline) {
						if _, err := os.Stat(filepath.Join(state, "ready.json")); err == nil {
							cancel()
							return
						}
						time.Sleep(10 * time.Millisecond)
					}
					cancel()
				}()
			} else {
				close(interruptDone)
			}
			result := &s.record.Scenarios[0]
			err := s.executeScenario(ctx, binary, liveSettings{"recovery_mode": "disabled", "test_mode": mode}, allowance, result)
			<-interruptDone
			if (err == nil) != (mode == "passed") {
				t.Fatalf("result %s: %v", result.Outcome, err)
			}
			if result.Writer == nil || !result.Writer.Joined {
				t.Fatal("writer did not join")
			}
			_, cleanupErr := os.Stat(filepath.Join(state, "cleanup-called.json"))
			if mode == "missing_inventory" {
				if !os.IsNotExist(cleanupErr) || result.Cleanup.RemainingOwnedObjects != nil || result.Cleanup.UnknownEffects != nil {
					t.Fatal("missing inventory claimed known cleanup or started effects")
				}
			} else if cleanupErr != nil {
				t.Fatal("failed or interrupted writer did not clean")
			}
			if mode == "failed_cleanup" || mode == "missing_inventory" {
				if result.Failure != nil || !result.CorrectnessPassed || cleanupPassed(result.Cleanup) {
					t.Fatal("cleanup failure replaced successful execution")
				}
			} else if !cleanupPassed(result.Cleanup) {
				t.Fatal("known exact cleanup missing")
			}
			invalidEvidence := mode == "missing_result" || mode == "empty_phases" || mode == "failed_phase"
			if invalidEvidence && (result.Writer.Process != "passed" || result.Writer.Outcome != "failed") {
				t.Fatal("exit-zero process supplied success without complete worker evidence")
			}
			if mode == "failed_phase" && (len(result.Writer.Phases) == 0 || result.Writer.Phases[0].Outcome != "failed") {
				t.Fatal("failed phase evidence was lost")
			}
			if mode == "failed_writer" || mode == "timeout" || mode == "interrupt" || invalidEvidence {
				if result.Failure == nil || result.CorrectnessPassed || len(result.PostExit) != 0 {
					t.Fatal("failed writer resumed work or lost execution failure")
				}
			} else if len(result.PostExit) != 1 || result.PostExit[0].Role != "fresh_after" || result.PostExit[0].Worker == result.Writer.Worker {
				t.Fatal("fresh reader output was not separate")
			}
			wantRequests := uint64(2 + 3*len(result.Children))
			if len(result.PostExit) != 0 {
				wantRequests += 3
			}
			if mode == "missing_result" && result.BudgetReserved != nil || mode != "missing_result" && (result.BudgetReserved == nil || result.BudgetReserved.Requests != wantRequests) {
				t.Fatal("independent reservation lost")
			}
			if invalidEvidence {
				s.finish()
				if s.record.Correctness.Passed || s.record.Correctness.EvidenceComplete || s.record.Outcome != "failed" {
					t.Fatal("incomplete worker evidence supplied successful run correctness")
				}
			}
			if err := s.save(); err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(filepath.Join(s.directory, "run.json"))
			if err != nil || bytes.Contains(body, []byte("synthetic-secret")) || bytes.Contains(body, []byte(state)) {
				t.Fatal("private worker output reached public records")
			}
			if _, err := os.Stat(filepath.Join(s.directory, "telemetry.json")); !os.IsNotExist(err) {
				t.Fatal("disabled run wrote telemetry")
			}
		})
	}
}

// full_only: false
func TestWorkerEvidenceRejectsIdentityAndKeepsSafePartialPhases(t *testing.T) {
	s, _ := coordinatorFixture(t)
	state := filepath.Join(s.private, "0000-c2b1ece74d4795f96fc27a467324d41147e34a736c84f0fa7972738f5cf75981")
	if os.Mkdir(state, 0700) != nil || os.Mkdir(filepath.Join(state, "workers"), 0700) != nil {
		t.Fatal("state")
	}
	input := filepath.Join(state, "input.json")
	if records.WriteJSON(input, map[string]bool{"test": true}, 0400) != nil {
		t.Fatal("input")
	}
	inv, err := makeInvocation(records.Invocation{
		Scenario:  "state.single-value-update-preserves-other-values/members_32",
		RunID:     s.record.RunID,
		Worker:    "0000-c2b1ece74d4795f96fc27a467324d41147e34a736c84f0fa7972738f5cf75981-writer",
		Role:      "writer",
		Input:     input,
		StateDir:  state,
		OutputDir: filepath.Join(state, "workers", "writer"),
	}, "live")
	if err != nil {
		t.Fatal(err)
	}
	base := records.WorkerResult{
		SchemaVersion: 2, RunID: inv.RunID, Worker: inv.Worker, Role: inv.Role, Scenario: "state.single-value-update-preserves-other-values/members_32", Actor: "writer", Outcome: "failed",
		Phases:  []records.PhaseResult{{Sequence: 1, Name: "transition", Actor: "reader", Expected: "success", Actual: "access-refused", Outcome: "passed"}},
		Failure: &records.Failure{Class: "synthetic-secret", Stage: "synthetic-secret"},
	}
	for _, test := range []struct {
		name     string
		accepted bool
		change   func(*records.WorkerResult)
	}{
		{"partial", true, func(*records.WorkerResult) {}},
		{"other_run", false, func(r *records.WorkerResult) { r.RunID = strings.Repeat("e", 32) }},
		{"other_worker", false, func(r *records.WorkerResult) { r.Worker = "different" }},
		{"other_role", false, func(r *records.WorkerResult) { r.Role = "cleanup" }},
		{"other_scenario", false, func(r *records.WorkerResult) {
			r.Scenario = "state.historical-bytes-get-new-identities/members_32_three_generations"
		}},
		{"bad_sequence", false, func(r *records.WorkerResult) { r.Phases[0].Sequence = 2 }},
		{"unsafe_worker_actor", false, func(r *records.WorkerResult) { r.Actor = "private/synthetic-secret" }},
		{"unsafe_phase_actor", false, func(r *records.WorkerResult) { r.Phases[0].Actor = "private/synthetic-secret" }},
		{"unsafe_expected", false, func(r *records.WorkerResult) { r.Phases[0].Expected = "synthetic-secret" }},
		{"unsafe_actual", false, func(r *records.WorkerResult) { r.Phases[0].Actual = "synthetic-secret" }},
		{"reader_and_catalog_outcome", true, func(r *records.WorkerResult) {
			r.Actor, r.Phases[0].Actor = "reader", "writer"
			r.Phases[0].Expected, r.Phases[0].Actual = "complete-state-matches", "complete-state-matches"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := base
			value.Phases = slices.Clone(base.Phases)
			test.change(&value)
			if records.WriteJSON(filepath.Join(inv.OutputDir, "worker.json"), value, 0600) != nil {
				t.Fatal("worker fixture")
			}
			got, err := readWorkerResult(inv, "state.single-value-update-preserves-other-values/members_32")
			if (err == nil) != test.accepted {
				t.Fatalf("worker evidence acceptance: got %v, want %t", err, test.accepted)
			}
			body, err := json.Marshal(got)
			if err != nil || bytes.Contains(body, []byte("synthetic-secret")) {
				t.Fatal("unsafe worker fields retained")
			}
			if test.accepted {
				if len(got.Phases) != 1 || completeWorker(got, "live", s.record.Resolved.RoleBindings, "", nil) {
					t.Fatal("partial evidence lost or claimed success")
				}
				if got.Actor != value.Actor || got.Phases[0].Actor != value.Phases[0].Actor || got.Phases[0].Expected != value.Phases[0].Expected || got.Phases[0].Actual != value.Phases[0].Actual {
					t.Fatal("safe actor or step outcomes changed")
				}
			}
		})
	}
}

// full_only: false
func TestCoordinatorTelemetryWriteFailureDoesNotChangeExecution(t *testing.T) {
	s, binary := coordinatorFixture(t)
	settings, err := observability.Decode([]byte(`{"schema_version":1,"metrics":{"exporters":["local"]},"exporters":{"local":{"type":"otlp_file","directory":"telemetry"}}}`), observability.Options{})
	if err != nil {
		t.Fatal(err)
	}
	s.telemetrySettings = &settings
	s.record.Telemetry = records.Telemetry{Enabled: true, Status: "incomplete"}
	s.record.EffectiveTelemetry = summarizeTelemetry(settings, observability.Options{})
	result := &s.record.Scenarios[0]
	if err := s.executeScenario(context.Background(), binary, liveSettings{"recovery_mode": "disabled", "test_mode": "telemetry_write_failed"}, testLimits(), result); err != nil {
		t.Fatal(err)
	}
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	if !result.CorrectnessPassed || !cleanupPassed(result.Cleanup) || result.Writer == nil || result.CleanupWorker == nil || len(result.PostExit) != 1 {
		t.Fatal("telemetry write changed correctness or cleanup")
	}
	state := filepath.Join(s.private, "0000-c2b1ece74d4795f96fc27a467324d41147e34a736c84f0fa7972738f5cf75981")
	inv, err := records.LoadInvocation(filepath.Join(state, "workers/writer/invocation.json"))
	if err != nil {
		t.Fatal("writer invocation unavailable", err)
	}
	var writer records.WorkerResult
	if err := records.ReadJSON(filepath.Join(inv.OutputDir, "worker.json"), &writer); err != nil || writer.Outcome != "passed" || writer.Failure != nil || writer.Telemetry.Status != "incomplete" || writer.Telemetry.FailureClass != "write_failed" {
		t.Fatal("actual telemetry write failure lost its passed worker or closed failure class", err, writer.Telemetry)
	}
	if result.Writer.Telemetry.Status != "incomplete" || result.Writer.Telemetry.FailureClass != "telemetry_unavailable" || s.record.Telemetry.Status != "incomplete" || s.record.Telemetry.FailureClass != "worker_evidence_incomplete" {
		t.Fatal("telemetry write failure disappeared during import or save")
	}
	var saved runRecord
	if err := records.ReadJSON(filepath.Join(s.directory, "run.json"), &saved); err != nil || saved.Telemetry.Status != "incomplete" || saved.Telemetry.FailureClass != "worker_evidence_incomplete" {
		t.Fatal("live save lost the telemetry write failure", err)
	}
	if result.CleanupWorker.Telemetry.Status != "complete" {
		t.Fatal("writer telemetry write failure prevented cleanup telemetry")
	}
	workers := []*workerEvidence{result.Writer, result.CleanupWorker}
	for index := range result.Children {
		workers = append(workers, &result.Children[index])
	}
	for index := range result.PostExit {
		workers = append(workers, &result.PostExit[index])
	}
	for _, worker := range workers {
		if !worker.Started || !worker.Joined || worker.Process != "passed" || worker.Outcome != "passed" {
			t.Fatal("telemetry write failure changed worker execution or joins", worker.Role)
		}
	}
}

// full_only: false
func TestCoordinatorPreparationFailureIsExecutionFailure(t *testing.T) {
	s, binary := coordinatorFixture(t)
	state := filepath.Join(s.private, "0000-c2b1ece74d4795f96fc27a467324d41147e34a736c84f0fa7972738f5cf75981")
	if os.WriteFile(state, []byte("retain"), 0600) != nil {
		t.Fatal("controlled path conflict")
	}
	result := &s.record.Scenarios[0]
	if s.executeScenario(context.Background(), binary, nil, testLimits(), result) == nil || result.Outcome != "failed" || result.Failure == nil || result.Failure.Stage != "setup" || result.Writer != nil || result.CleanupWorker != nil {
		t.Fatal("preparation failure misreported or launched work")
	}
}

// full_only: false
func TestScenarioScheduleSharesBudgetAndRetainsResults(t *testing.T) {
	for _, test := range []struct {
		name, mode string
		selection  catalog.Request
		objects    uint64
		want       int
		passed     bool
	}{
		{"focused", "passed", catalog.Request{Include: []string{"state.single-value-update-preserves-other-values/members_32"}, Repetitions: 1}, 256, 1, true},
		{"joined_failures", "failed_writer", catalog.Request{Include: []string{"state.single-value-update-preserves-other-values/members_1", "state.single-value-update-preserves-other-values/members_2"}, SmokePolicy: catalog.SmokeFirstSelectedPoint, Repetitions: 1}, 256, 2, false},
		{"shared_objects", "passed", catalog.Request{Include: []string{"state.single-value-update-preserves-other-values/members_32", "state.identical-input-keeps-current-state/members_32"}, Repetitions: 1}, 1, 1, false},
		{"member_counts_once", "passed", catalog.Request{Include: []string{"state.single-value-update-preserves-other-values/members_1", "state.single-value-update-preserves-other-values/members_2", "state.single-value-update-preserves-other-values/members_3"}, SmokePolicy: catalog.SmokeFirstSelectedPoint, Repetitions: 1}, 256, 3, true},
		{"member_shared_objects", "passed", catalog.Request{Include: []string{"state.single-value-update-preserves-other-values/members_1", "state.single-value-update-preserves-other-values/members_2", "state.single-value-update-preserves-other-values/members_3"}, SmokePolicy: catalog.SmokeFirstSelectedPoint, Repetitions: 1}, 2, 2, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, binary := coordinatorFixture(t)
			schedule, err := catalog.Resolve(test.selection)
			if err != nil {
				t.Fatal(err)
			}
			s.record.Schedule, s.record.Scenarios = schedule, nil
			allowance := testLimits()
			allowance.Objects = test.objects
			allowance.ElapsedSeconds = 30
			if err := s.executeSchedule(context.Background(), binary, liveSettings{"recovery_mode": "disabled", "test_mode": test.mode}, allowance); err != nil {
				t.Fatal(err)
			}
			s.finish()
			if len(s.record.Scenarios) != test.want || (s.record.Outcome == "passed") != test.passed || s.record.FullCoverage {
				t.Fatal("schedule did not share limits or preserve failed selected results")
			}
			for i, result := range s.record.Scenarios {
				if result.Entry != schedule.Entries[i] {
					t.Fatal("schedule order or member count changed")
				}
				var input workerInput
				directory, err := currentCaseDirectory(result.Entry)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(s.private, directory, "input.json")
				if records.ReadJSON(path, &input) != nil || input.MemberCount != 0 || len(input.Scenarios) != 1 || input.Scenarios[0] != result.Scenario {
					t.Fatal("named case identity was not passed unchanged to the worker")
				}
				if test.mode == "passed" && input.Limits.Objects != test.objects-uint64(i) {
					t.Fatal("scenario reset the shared object budget")
				}
			}
			if test.want < len(schedule.Entries) {
				next := schedule.Entries[test.want]
				directory, err := currentCaseDirectory(next)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(filepath.Join(s.private, directory)); !os.IsNotExist(err) {
					t.Fatal("stopped schedule created the next fixture")
				}
			}
		})
	}

	t.Run("repetitions", func(t *testing.T) {
		cases := []string{"state.single-value-update-preserves-other-values/members_1", "state.single-value-update-preserves-other-values/members_2"}
		for _, test := range []struct {
			name, mode string
			objects    uint64
			want       int
			passed     bool
			completed  []int
			sequences  [][]int
			outcomes   []string
		}{
			{"three_fresh_executions", "passed", 256, 6, true, []int{3, 3}, [][]int{{0, 2, 4}, {1, 3, 5}}, []string{"passed", "passed"}},
			{"joined_failure_second", "repetition_failure_second", 256, 6, false, []int{3, 3}, [][]int{{0, 2, 4}, {1, 3, 5}}, []string{"failed", "passed"}},
			{"cumulative_budget_before_second", "passed", 2, 2, false, []int{1, 1}, [][]int{{0}, {1}}, []string{"failed", "failed"}},
			{"unstarted_second", "repetition_unstarted_second", 256, 3, false, []int{1, 1}, [][]int{{0, 2}, {1}}, []string{"failed", "failed"}},
			{"cleanup_failure_second", "repetition_cleanup_second", 256, 3, false, []int{2, 1}, [][]int{{0, 2}, {1}}, []string{"failed", "failed"}},
			{"unknown_effect_second", "repetition_unknown_second", 256, 3, false, []int{2, 1}, [][]int{{0, 2}, {1}}, []string{"failed", "failed"}},
			{"leaf_save_failure_second", "repetition_leaf_save_second", 256, 3, false, []int{2, 1}, [][]int{{0, 2}, {1}}, []string{"failed", "failed"}},
		} {
			t.Run(test.name, func(t *testing.T) {
				s, binary := coordinatorFixture(t)
				schedule, err := catalog.Resolve(catalog.Request{Include: cases, RecoveryMode: "disabled", SmokePolicy: catalog.SmokeFirstSelectedPoint, Repetitions: 3})
				if err != nil {
					t.Fatal(err)
				}
				s.record.Schedule, s.record.Resolved.Schedule, s.record.Scenarios = schedule, schedule, nil
				witness := t.TempDir()
				settings := liveSettings{"recovery_mode": "disabled", "test_mode": test.mode, "test_repetition_witness": witness}
				if test.name == "three_fresh_executions" {
					settings["test_repetition_lifetime"] = "true"
				}
				if test.mode == "repetition_leaf_save_second" {
					settings["test_case_receipts"] = filepath.Join(s.directory, "cases")
				}
				if test.mode == "repetition_unstarted_second" {
					alias := filepath.Join(t.TempDir(), "worker-alias")
					if err := os.Symlink(binary, alias); err != nil {
						t.Fatal(err)
					}
					binary, settings["test_binary_alias"] = alias, alias
				}
				allowance := testLimits()
				allowance.Objects, allowance.ElapsedSeconds, allowance.CleanupSeconds = test.objects, 60, 60
				originalAllowance := allowance
				ctx := withExecutionCapacity(t.Context(), defaultExecutionPolicy())
				capacity := executionCapacityFromContext(ctx)
				executionErr := s.executeSchedule(ctx, binary, settings, allowance)
				if test.mode == "repetition_leaf_save_second" {
					if executionErr == nil || !strings.Contains(executionErr.Error(), "terminal case receipt unavailable") {
						t.Fatal("second execution did not reach the actual exclusive receipt save refusal", executionErr)
					}
				} else if test.mode == "repetition_unstarted_second" {
					if executionErr == nil || !strings.Contains(executionErr.Error(), "budget evidence unavailable") {
						t.Fatal("failed starts did not retain the missing budget evidence failure", executionErr)
					}
				} else if executionErr != nil {
					t.Fatal("repeated schedule could not retain its scalar receipts", executionErr)
				}
				s.finish()
				if err := s.save(); err != nil {
					t.Fatal(err)
				}
				if len(s.record.Scenarios) != test.want || (s.record.Outcome == "passed") != test.passed || s.record.FullCoverage || s.record.ScenarioCoverage {
					t.Fatal("repetition changed stop order or focused coverage", len(s.record.Scenarios), s.record.Outcome)
				}
				if allowance != originalAllowance || executionCapacityFromContext(ctx) != capacity || ctx.Err() != nil {
					t.Fatal("repetition changed caller allowance, capacity, or context")
				}
				nonces := map[string]bool{}
				pids := map[int]bool{}
				var elapsedDebit, cleanupElapsedDebit uint64
				for index, result := range s.record.Scenarios {
					if result.Entry != schedule.Entries[index] || result.Smoke != (index == 0) || result.Repetition != index/2+1 {
						t.Fatal("selected smoke did not remain repetition one or schedule order changed", result.Entry)
					}
					directory, err := currentCaseDirectory(result.Entry)
					if err != nil {
						t.Fatal(err)
					}
					state := filepath.Join(s.private, directory)
					var input workerInput
					var inv records.Invocation
					if test.mode == "repetition_unstarted_second" && index == 2 {
						// This failed case remains retained: no worker could write a
						// witness, so use the coordinator's actual attempted input.
						if records.ReadJSON(filepath.Join(state, "input.json"), &input) != nil || records.ReadJSON(filepath.Join(state, "workers", "writer", "invocation.json"), &inv) != nil {
							t.Fatal("failed-start input or invocation unavailable")
						}
						if _, err := os.Stat(filepath.Join(witness, directory+"-writer.json")); !os.IsNotExist(err) {
							t.Fatal("failed-start attempt produced a real writer witness", err)
						}
					} else {
						// The worker saves this real observation outside disposable
						// case state. No fixture synthesizes process or result facts.
						var observation scenarioRepetitionWorkerObservation
						if records.ReadJSON(filepath.Join(witness, directory+"-writer.json"), &observation) != nil || observation.PID <= 0 || pids[observation.PID] {
							t.Fatal("fresh actual worker process observation unavailable", observation)
						}
						pids[observation.PID] = true
						if test.name == "three_fresh_executions" {
							if index == 0 {
								if observation.PreviousWorker != "" || observation.PreviousStateDir != "" || observation.PreviousStateStatus != "" {
									t.Fatal("first real execution observed a nonexistent predecessor", observation)
								}
							} else {
								previous, err := currentCaseDirectory(s.record.Scenarios[index-1].Entry)
								if err != nil {
									t.Fatal(err)
								}
								if observation.PreviousWorker != previous+"-writer" || observation.PreviousStateDir != filepath.Join(s.private, previous) {
									t.Fatal("real writer observed the wrong preceding case", observation)
								}
								if observation.PreviousStateStatus != "present" {
									t.Error("previous completed live case lost its recovery state before the run completed", index, observation.PreviousStateStatus)
								}
							}
						}
						input, inv = observation.Input, observation.Invocation
					}
					retainedInv, err := records.LoadInvocation(filepath.Join(state, "workers", "writer", "invocation.json"))
					var retainedInput workerInput
					if err != nil || !reflect.DeepEqual(retainedInv, inv) || records.ReadJSON(retainedInv.Input, &retainedInput) != nil || !reflect.DeepEqual(retainedInput, input) {
						t.Fatal("live repetition lost original case inputs needed for recovery", index, err)
					}
					if input.Limits == nil || input.Limits.Objects != test.objects-uint64(index) || input.Limits.ElapsedSeconds != originalAllowance.ElapsedSeconds-elapsedDebit || input.Limits.CleanupSeconds != originalAllowance.CleanupSeconds-cleanupElapsedDebit || input.Repetitions != 1 || input.MemberCount != 0 || !slices.Equal(input.Scenarios, []string{result.Scenario}) {
						t.Fatal("repetition reset cumulative allowance or changed exact worker selection", input)
					}
					if inv.Nonce == "" || nonces[inv.Nonce] || inv.Worker != directory+"-writer" || inv.StateDir != state || result.Writer == nil || !result.Writer.Joined {
						t.Fatal("actual invocation/fixture identity or positive writer join unavailable", inv, result.Writer)
					}
					nonces[inv.Nonce] = true
					// Each prior actual workload and cleanup consumes its rounded-up
					// wall duration from the original total allowance, without top-up.
					elapsedDebit += uint64((result.WorkloadElapsed + time.Second - 1) / time.Second)
					cleanupElapsedDebit += uint64((result.CleanupElapsed + time.Second - 1) / time.Second)
					if test.mode == "repetition_unstarted_second" && index == 2 {
						if result.Writer.Process != "process_failed" || result.Writer.Started || len(result.Writer.Phases) != 0 {
							t.Fatal("failed-start control did not fail before Product work", result.Writer)
						}
						if result.CleanupWorker != nil || result.Cleanup.Outcome != "unresolved" || result.CleanupRetryBlocker != "product_incomplete" || len(result.CleanupAttempts) != 0 || result.BudgetReserved != nil || result.Cleanup.BudgetReserved != nil {
							t.Fatal("missing executable invented cleanup or budget evidence", result.CleanupWorker, result.Cleanup, result.BudgetReserved)
						}
						if _, err := os.Stat(filepath.Join(state, "ready.json")); !os.IsNotExist(err) {
							t.Fatal("failed-start control actually entered a writer", err)
						}
					} else if test.mode == "repetition_failure_second" && index == 2 {
						if result.Writer.Process != "process_failed" || result.Writer.Assertions == nil || result.Writer.Assertions.Marker != "valid_failure_marker" || result.CorrectnessPassed || !cleanupPassed(result.Cleanup) {
							t.Fatal("failure two lost actual assertion, correctness, or joined cleanup facts", result)
						}
					} else if (test.mode == "repetition_cleanup_second" || test.mode == "repetition_unknown_second") && index == 2 {
						if result.Writer.Process != "passed" || !result.CorrectnessPassed || result.Failure != nil || result.Outcome != "failed" || result.Cleanup.Outcome != "unresolved" || result.CleanupWorker == nil || !result.CleanupWorker.Joined || result.CleanupWorker.Process != "process_failed" || len(result.CleanupAttempts) != 0 || result.Cleanup.RemainingOwnedObjects == nil || result.Cleanup.UnknownEffects == nil {
							t.Fatal("second cleanup failure lost independent correctness, positive join, or stop facts", result)
						}
						remaining, unknown := int64(1), int64(0)
						if test.mode == "repetition_unknown_second" {
							remaining, unknown = 0, 1
						}
						if *result.Cleanup.RemainingOwnedObjects != remaining || *result.Cleanup.UnknownEffects != unknown {
							t.Fatal("second cleanup failure erased its known/unknown ownership", result.Cleanup)
						}
					} else if result.Outcome != "passed" || !result.CorrectnessPassed || result.Writer.Process != "passed" || !cleanupPassed(result.Cleanup) {
						t.Fatal("earlier actual execution or cleanup did not pass", result)
					}
				}
				observations, err := os.ReadDir(witness)
				wantStarted := test.want
				if test.mode == "repetition_unstarted_second" {
					wantStarted--
				}
				if err != nil || len(observations) != wantStarted {
					t.Fatal("stopped schedule entered an unexpected writer or lost its actual witness", len(observations), wantStarted, err)
				}
				wantReceipts := test.want
				if test.mode == "repetition_leaf_save_second" {
					wantReceipts--
				}
				if len(s.record.CaseReceipts) != wantReceipts {
					t.Fatal("immutable scalar receipt count did not match actual successful saves", s.record.CaseReceipts)
				}
				if test.mode == "repetition_failure_second" || test.mode == "repetition_unstarted_second" || test.mode == "repetition_cleanup_second" || test.mode == "repetition_unknown_second" || test.mode == "repetition_leaf_save_second" {
					failedEntry := s.record.Scenarios[len(s.record.Scenarios)-1].Entry
					if test.mode == "repetition_failure_second" {
						failedEntry = s.record.Scenarios[2].Entry
					}
					failed, err := currentCaseDirectory(failedEntry)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := os.Lstat(filepath.Join(s.private, failed)); err != nil {
						t.Fatal("second failed, unstarted, or unsealed execution lost its private evidence", err)
					}
				}
				if test.name == "three_fresh_executions" {
					if err := validateCaseReceiptSet(s.directory, s.record); err != nil {
						t.Fatal("retained live repetitions lost immutable scalar receipts", err)
					}
				}
				for _, next := range schedule.Entries[test.want:] {
					directory, err := currentCaseDirectory(next)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := os.Stat(filepath.Join(s.private, directory)); !os.IsNotExist(err) {
						t.Fatal("stopped repetition created a later selected fixture", next)
					}
				}
				// Raw JSON keeps this proof compilable before the public fields exist.
				var saved struct {
					Groups []struct {
						Scenario  string `json:"scenario"`
						Requested int    `json:"requested_executions"`
						Completed int    `json:"completed_executions"`
						Outcome   string `json:"outcome"`
						Sequences []int  `json:"case_sequences"`
					} `json:"repetition_groups"`
					Scenarios []struct {
						Writer struct {
							Started bool `json:"started"`
						} `json:"writer"`
					} `json:"scenarios"`
				}
				body, err := os.ReadFile(filepath.Join(s.directory, "run.json"))
				if err != nil || json.Unmarshal(body, &saved) != nil || len(saved.Scenarios) != test.want {
					t.Fatal("saved scalar repetition evidence unavailable", err)
				}
				for index, result := range saved.Scenarios {
					wantStarted := !(test.mode == "repetition_unstarted_second" && index == 2)
					if result.Writer.Started != wantStarted {
						t.Error("actual writer start fact missing or invented", index, result.Writer.Started, wantStarted)
					}
				}
				if len(saved.Groups) != len(cases) {
					t.Error("scenario repetition accounting unavailable", saved.Groups)
				} else {
					for index, group := range saved.Groups {
						if group.Scenario != cases[index] || group.Requested != 3 || group.Completed != test.completed[index] || group.Outcome != test.outcomes[index] || !slices.Equal(group.Sequences, test.sequences[index]) {
							t.Error("scenario repetition accounting changed requested N, joined K, outcome, or attempts", index, group)
						}
					}
				}
				if test.passed {
					if err := s.finishCurrentRun(&bytes.Buffer{}, nil); err != nil {
						t.Fatal("completed live repetition could not finalize its recovery owner", err)
					}
					if _, err := os.Lstat(s.directory); !os.IsNotExist(err) {
						t.Error("completed live repetition retained its owned packet after finalization", err)
					}
				}
			})
		}
	})

}

// full_only: false
func TestCleanupInputExcludesEveryOtherActor(t *testing.T) {
	input := workerInput{RecoveryMode: "enabled", Settings: liveSettings{"credentials_file": "operator"}, Participants: map[string]string{"authority": "operator", "reader": "reader", "recovery": "recovery", "denied-reader": "denied-reader", "observer": "observer", "denied-observer": "denied-observer"}, DeniedObserverSettings: liveSettings{"credentials_file": "denied-observer"}, ObserverSettings: liveSettings{"credentials_file": "observer"}, ReaderSettings: liveSettings{"credentials_file": "reader"}, RecoverySettings: liveSettings{"credentials_file": "recovery"}, DeniedReaderSettings: liveSettings{"credentials_file": "denied-reader"}}
	cleanup := input.authorityOnly()
	if len(cleanup.Participants) != 1 || cleanup.Participants["authority"] != "operator" || cleanup.Settings["credentials_file"] != "operator" || cleanup.RecoveryMode != "enabled" || cleanup.ReaderSettings != nil || cleanup.RecoverySettings != nil || cleanup.DeniedReaderSettings != nil || cleanup.ObserverSettings != nil || cleanup.DeniedObserverSettings != nil {
		t.Fatal("cleanup retained another actor or changed its resources")
	}
	if len(input.Participants) != 6 || input.ReaderSettings == nil || input.RecoverySettings == nil {
		t.Fatal("cleanup rewrote retained writer input")
	}
}

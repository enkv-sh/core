package records

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const failureTestCaller = "enkv.sh/core/tests_shared_fixture_test.go"

func failureTestInvocation(t *testing.T) Invocation {
	t.Helper()
	inv := testInvocation(t)
	sources := FailureSources{SchemaVersion: 1, BinarySHA256: strings.Repeat("1", 64), OverlaySHA256: strings.Repeat("2", 64), Paths: map[string]string{
		failureTestCaller: "tests/shared/fixture_test.go",
		"enkv.sh/crypto@v0.0.0/testsupport/custody/live.go": "crypto/testsupport/custody/live.go",
	}}
	sourcePath := filepath.Join(inv.StateDir, "failure-sources.json")
	if err := WriteJSON(sourcePath, sources, 0o400); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	inv.FailureSources = &FailureSourceBinding{Path: sourcePath, SHA256: hex.EncodeToString(digest[:])}
	return inv
}

func failureTestRecorder(t *testing.T, inv Invocation) *FailureRecorder {
	t.Helper()
	recorder, err := NewFailureRecorder(inv)
	if err != nil {
		t.Fatal(err)
	}
	return recorder
}

func failureTestMarker(t *testing.T, inv Invocation) FailureMarker {
	t.Helper()
	var marker FailureMarker
	file := filepath.Join(inv.OutputDir, "failure.json")
	if err := ReadJSONLimit(file, &marker, MaximumFailureBytes); err != nil {
		t.Fatal(err)
	}
	sources, err := ReadFailureSources(*inv.FailureSources)
	if err != nil || marker.Validate(inv, sources) != nil {
		t.Fatal("marker was not bound to the admitted invocation")
	}
	info, err := os.Lstat(file)
	if err != nil || info.Mode().Perm() != 0o600 || info.Size() > MaximumFailureBytes {
		t.Fatal("marker exceeded its private file contract")
	}
	return marker
}

// full_only: false
func TestFailureMarkerFirstAssertionWins(t *testing.T) {
	for _, concurrent := range []bool{false, true} {
		t.Run(map[bool]string{false: "repeated", true: "concurrent"}[concurrent], func(t *testing.T) {
			inv := failureTestInvocation(t)
			recorder := failureTestRecorder(t, inv)
			var callers sync.WaitGroup
			for line := 1; line <= 64; line++ {
				if concurrent {
					callers.Add(1)
					go func() { defer callers.Done(); recorder.Record("error", failureTestCaller, line) }()
				} else {
					recorder.Record("error", failureTestCaller, line)
				}
			}
			callers.Wait()
			marker := failureTestMarker(t, inv)
			if marker.Code != "error" || marker.Line < 1 || marker.Line > 64 || !concurrent && marker.Line != 1 {
				t.Fatal("first assertion was lost")
			}
			first, err := os.ReadFile(filepath.Join(inv.OutputDir, "failure.json"))
			if err != nil {
				t.Fatal(err)
			}
			recorder.Record("fatal", failureTestCaller, 1000)
			after, err := os.ReadFile(filepath.Join(inv.OutputDir, "failure.json"))
			if err != nil || !bytes.Equal(first, after) {
				t.Fatal("later finalization changed the first assertion")
			}
			if _, err := NewFailureRecorder(inv); err == nil {
				t.Fatal("another owner reused assertion evidence")
			}
		})
	}
}

// full_only: false
func TestFailureFactsSurviveDisabledTelemetry(t *testing.T) {
	inv := failureTestInvocation(t)
	recorder := failureTestRecorder(t, inv)
	if recorder.begin("transition", 1) != nil {
		t.Fatal("phase begin")
	}
	first, err := recorder.CaptureOperationFailure(OperationFailureFacts{SchemaVersion: OperationFailureSchemaVersion,
		Operation: "generated_create", Stage: "result_read", Category: "unavailable", Code: 9,
		Effect: "unknown", FactsStatus: "facts_unavailable",
	})
	if err != nil {
		t.Fatal("capture first operation", err)
	}
	_, err = recorder.CaptureOperationFailure(OperationFailureFacts{SchemaVersion: OperationFailureSchemaVersion,
		Operation: "generated_retire", Stage: "facts", Category: "protocol", Code: 9,
		Effect: "unknown", FactsStatus: "facts_unavailable",
	})
	if err != nil || recorder.SelectOperationFailure(first) != nil {
		t.Fatal("exact operation selection", err)
	}
	recorder.Record("fatal", failureTestCaller, 451)
	marker := failureTestMarker(t, inv)
	if marker.OperationFailure == nil || marker.OperationFailure.Operation != "generated_create" || marker.OperationFailure.Stage != "result_read" || marker.Completed.Code != "none" {
		t.Fatal("first assertion lost its selected operation and checkpoint", marker)
	}
	evidence := InspectAssertions(inv, false)
	if evidence.OperationFailure == nil || *evidence.OperationFailure != *marker.OperationFailure {
		t.Fatal("public operation facts were lost without telemetry", evidence)
	}
	if contradictory := InspectAssertions(inv, true); contradictory.Marker != "contradictory_failure_marker" || contradictory.PermitsSuccess() || contradictory.OperationFailure == nil {
		t.Fatal("passing worker admitted a selected failure", contradictory)
	}
}

// full_only: false
func TestFailureFactsBeforeInvocationDoNotInventCryptoCode(t *testing.T) {
	inv := failureTestInvocation(t)
	recorder := failureTestRecorder(t, inv)
	fact := OperationFailureFacts{SchemaVersion: OperationFailureSchemaVersion, Operation: "generated_create", Stage: "pre_invocation", Category: "unavailable", Effect: "no_send", FactsStatus: "facts_unavailable"}
	ref, err := recorder.CaptureOperationFailure(fact)
	if err != nil || recorder.SelectOperationFailure(ref) != nil {
		t.Fatal("pre-invocation fact refused", err)
	}
	recorder.Record("fatal", failureTestCaller, 21)
	marker := failureTestMarker(t, inv)
	if marker.OperationFailure == nil || marker.OperationFailure.Code != 0 || marker.OperationFailure.Stage != "pre_invocation" {
		t.Fatal("unobserved Crypto code was invented", marker)
	}
	fact.Code = 2
	if fact.Validate() == nil {
		t.Fatal("pre-invocation boundary accepted a Crypto result")
	}
	fact.Code, fact.Stage, fact.Category = 0, "entry", "invalid"
	if fact.Validate() == nil {
		t.Fatal("private return boundary omitted its Crypto result")
	}
}

// full_only: false
func TestFailureOperationFactsRejectUnclosedInput(t *testing.T) {
	base := OperationFailureFacts{SchemaVersion: OperationFailureSchemaVersion, Operation: "generated_create", Stage: "completed", Category: "none", Code: 1,
		Effect: "unknown", FactsStatus: "qualified", SafeFacts: &QualifiedSafeFacts{Disposition: 5, Reason: 8}}
	if base.Validate() != nil {
		t.Fatal("qualified closed fact refused")
	}
	for _, name := range []string{"schema", "operation", "stage", "category", "code", "effect", "facts_status", "missing_facts", "disposition", "reason", "unqualified_ack", "no_send_with_facts"} {
		t.Run(name, func(t *testing.T) {
			bad := cloneOperationFailure(base)
			switch name {
			case "schema":
				bad.SchemaVersion = 1
			case "operation":
				bad.Operation = "SECRET_SENTINEL"
			case "stage":
				bad.Stage = "SECRET_SENTINEL"
			case "category":
				bad.Category = "SECRET_SENTINEL"
			case "code":
				bad.Code = 13
			case "effect":
				bad.Effect = "SECRET_SENTINEL"
			case "facts_status":
				bad.FactsStatus = "SECRET_SENTINEL"
			case "missing_facts":
				bad.SafeFacts = nil
			case "disposition":
				bad.SafeFacts.Disposition = 9
			case "reason":
				bad.SafeFacts.Reason = 11
			case "unqualified_ack":
				bad.FactsStatus, bad.SafeFacts, bad.Effect = "facts_unavailable", nil, "complete"
			case "no_send_with_facts":
				bad.Effect = "no_send"
			}
			if bad.Validate() == nil {
				t.Fatal("unclosed operation fact accepted", name)
			}
			inv := failureTestInvocation(t)
			if _, err := failureTestRecorder(t, inv).CaptureOperationFailure(bad); err == nil {
				t.Fatal("unclosed operation fact captured", name)
			}
		})
	}
}

// full_only: false
func TestFailureOperationEffectFollowsQualifiedDisposition(t *testing.T) {
	for _, test := range []struct {
		name, operation, effect string
		disposition, reason     uint8
	}{
		{"complete_create", "generated_create", "complete", 1, 0},
		{"owned_unusable_create", "generated_create", "owned_unusable", 2, 1},
		{"confirmed_no_effect_create", "generated_create", "no_effect", 3, 0},
		{"rejected_no_effect_create", "generated_create", "no_effect", 3, 7},
		{"delete_acknowledged", "generated_retire", "delete_acknowledged", 4, 0},
		{"unknown_create", "generated_create", "unknown", 5, 8},
		{"unknown_retire", "generated_retire", "unknown", 5, 9},
		{"scoped_retirement", "generated_retire", "unknown", 6, 0},
		{"continued_retirement", "generated_retire", "unknown", 7, 0},
		{"conflicting_retirement", "generated_retire", "unknown", 8, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			fact := OperationFailureFacts{SchemaVersion: OperationFailureSchemaVersion, Operation: test.operation, Stage: "completed", Category: "none", Code: 1,
				Effect: test.effect, FactsStatus: "qualified", SafeFacts: &QualifiedSafeFacts{Disposition: test.disposition, Reason: test.reason}}
			if fact.Validate() != nil {
				t.Fatal("qualified disposition refused")
			}
			if test.disposition != 5 {
				other := fact
				if other.Operation == "generated_create" {
					other.Operation = "generated_retire"
				} else {
					other.Operation = "generated_create"
				}
				if other.Validate() == nil {
					t.Fatal("qualified disposition crossed its operation")
				}
			}
			fact.Effect = "no_send"
			if fact.Validate() == nil {
				t.Fatal("qualified effect changed to no-send")
			}
		})
	}
	for _, stage := range []string{"entry", "authority", "owner", "deadline", "pipe"} {
		if (OperationFailureFacts{SchemaVersion: OperationFailureSchemaVersion, Operation: "generated_create", Stage: stage, Category: "unavailable", Code: 9, Effect: "no_send", FactsStatus: "facts_unavailable"}).Validate() != nil {
			t.Fatal("pre-send failure refused", stage)
		}
	}
	if (OperationFailureFacts{SchemaVersion: OperationFailureSchemaVersion, Operation: "generated_create", Stage: "launch", Category: "unavailable", Code: 9, Effect: "no_send", FactsStatus: "facts_unavailable"}).Validate() == nil {
		t.Fatal("uncertain launch claimed no-send")
	}
}

// full_only: false
func TestFailureOperationSelectionIsBoundedAndInvocationScoped(t *testing.T) {
	inv := failureTestInvocation(t)
	recorder := failureTestRecorder(t, inv)
	facts := OperationFailureFacts{SchemaVersion: OperationFailureSchemaVersion, Operation: "generated_create", Stage: "completed", Category: "none", Code: 1,
		Effect: "unknown", FactsStatus: "qualified", SafeFacts: &QualifiedSafeFacts{Disposition: 5, Reason: 8}}
	ref, err := recorder.CaptureOperationFailure(facts)
	if err != nil {
		t.Fatal(err)
	}
	facts.SafeFacts.Disposition = 9
	other := failureTestRecorder(t, failureTestInvocation(t))
	if other.SelectOperationFailure(ref) == nil {
		t.Fatal("cross-invocation operation fact selected")
	}
	if recorder.SelectOperationFailure(ref) != nil {
		t.Fatal("captured operation could not be selected")
	}
	recorder.Record("fatal", failureTestCaller, 451)
	marker := failureTestMarker(t, inv)
	if marker.OperationFailure.SafeFacts.Disposition != 5 || marker.OperationFailure.SafeFacts.Reason != 8 {
		t.Fatal("caller mutation changed captured facts", marker.OperationFailure)
	}
	body, err := os.ReadFile(filepath.Join(inv.OutputDir, "failure.json"))
	if err != nil || bytes.Contains(body, []byte("SECRET_SENTINEL")) || bytes.Contains(body, []byte("999")) {
		t.Fatal("private or mutated input entered marker")
	}
	if _, err := recorder.CaptureOperationFailure(facts); err == nil || recorder.SelectOperationFailure(ref) == nil {
		t.Fatal("first assertion accepted later operation facts")
	}

	bound := failureTestRecorder(t, failureTestInvocation(t))
	for range MaximumOperationFacts {
		if _, err := bound.CaptureOperationFailure(OperationFailureFacts{SchemaVersion: OperationFailureSchemaVersion, Operation: "generated_create", Stage: "entry", Category: "invalid", Code: 2, Effect: "no_send", FactsStatus: "facts_unavailable"}); err != nil {
			t.Fatal("bounded capture refused early", err)
		}
	}
	if _, err := bound.CaptureOperationFailure(OperationFailureFacts{SchemaVersion: OperationFailureSchemaVersion, Operation: "generated_create", Stage: "entry", Category: "invalid", Code: 2, Effect: "no_send", FactsStatus: "facts_unavailable"}); err == nil {
		t.Fatal("unbounded operation capture")
	}
}

// full_only: false
func TestFailurePublicationNeverReplacesExistingBytes(t *testing.T) {
	directory := canonicalTemp(t)
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, "failure.json")
	var group sync.WaitGroup
	results := make(chan error, 32)
	for value := range 32 {
		group.Add(1)
		go func() {
			defer group.Done()
			results <- WriteJSONExclusive(file, struct {
				Value int `json:"value"`
			}{value}, 4096)
		}()
	}
	group.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		}
	}
	if winners != 1 {
		t.Fatal("exclusive publication did not have one winner", winners)
	}
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if WriteJSONExclusive(file, struct{}{}, 4096) == nil {
		t.Fatal("later publication replaced the winner")
	}
	after, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("existing marker bytes changed")
	}
}

// full_only: false
func TestFailureMarkerWriteFailureKeepsFirstAssertion(t *testing.T) {
	for _, retained := range []bool{false, true} {
		t.Run(map[bool]string{false: "no_writable_directory", true: "marker_name_blocked"}[retained], func(t *testing.T) {
			inv := failureTestInvocation(t)
			recorder := failureTestRecorder(t, inv)
			ref, err := recorder.CaptureOperationFailure(OperationFailureFacts{SchemaVersion: OperationFailureSchemaVersion, Operation: "generated_create", Stage: "launch", Category: "unavailable", Code: 9, Effect: "unknown", FactsStatus: "facts_unavailable"})
			if err != nil || recorder.SelectOperationFailure(ref) != nil {
				t.Fatal("operation failure selection", err)
			}
			file := filepath.Join(inv.OutputDir, "failure.json")
			moved := inv.OutputDir + "-moved"
			if retained {
				if err := os.Mkdir(file, 0o700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Rename(inv.OutputDir, moved); err != nil {
				t.Fatal(err)
			}
			recorder.Record("fatal", failureTestCaller, 21)
			if retained {
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Rename(moved, inv.OutputDir); err != nil {
				t.Fatal(err)
			}
			recorder.Record("errorf", failureTestCaller, 99)
			evidence := InspectAssertions(inv, false)
			if evidence.Marker != "no_failure_marker" || evidence.MarkerWriteError != retained || evidence.OperationFailure != nil {
				t.Fatal("failed first write retried or invented a write-error fact", evidence)
			}
			if retained && (evidence.Checkpoint != "valid_checkpoint" || evidence.Completed.Code != "none") {
				t.Fatal("retained write error lost its coarse checkpoint")
			}
			if !retained && evidence.Checkpoint != "no_checkpoint" {
				t.Fatal("unwritten checkpoint was invented")
			}
		})
	}
}

// full_only: false
func TestFailureCheckpointAdvancesOnlyAfterCompletedSavedPhase(t *testing.T) {
	inv := failureTestInvocation(t)
	recorder := failureTestRecorder(t, inv)
	worker, err := NewWorker(inv, "core", inv.Scenario, recorder)
	if err != nil {
		t.Fatal(err)
	}
	sequence, err := worker.BeginPhase("setup", false)
	if err != nil {
		t.Fatal(err)
	}
	if got := InspectAssertions(inv, false); got.Checkpoint != "no_checkpoint" {
		t.Fatal("phase begin became completion", got)
	}
	if worker.EndPhase(context.Background(), sequence, true) != nil {
		t.Fatal("completed phase was not saved")
	}
	sequence, err = worker.BeginPhase("transition", false)
	if err != nil {
		t.Fatal(err)
	}
	if worker.EndPhase(context.Background(), sequence, false) != nil {
		t.Fatal("failed phase could not be saved")
	}
	recorder.Record("fatal", failureTestCaller, 451)
	marker := failureTestMarker(t, inv)
	if marker.Completed != (CompletedCheckpoint{Code: "setup", Sequence: 1}) || marker.Phase != "transition" || marker.Sequence != 2 {
		t.Fatal("unfinished operation advanced checkpoint", marker)
	}
	if worker.Finish(context.Background(), false) != nil {
		t.Fatal("worker finalization failed")
	}
	if got := InspectAssertions(inv, false); got.Completed != marker.Completed || got.Marker != "valid_failure_marker" {
		t.Fatal("finalization rewrote assertion checkpoint", got)
	}
}

// full_only: false
func TestFailureCheckpointDoesNotAdvanceAfterControlSaveFailure(t *testing.T) {
	for _, file := range []string{"worker.json", "checkpoint.json"} {
		t.Run(file, func(t *testing.T) {
			inv := failureTestInvocation(t)
			recorder := failureTestRecorder(t, inv)
			worker, err := NewWorker(inv, "core", inv.Scenario, recorder)
			if err != nil {
				t.Fatal(err)
			}
			sequence, err := worker.BeginPhase("setup", false)
			if err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(inv.OutputDir, file)
			if file == "worker.json" {
				if err := os.Remove(target); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Mkdir(target, 0o700); err != nil {
				t.Fatal(err)
			}
			if worker.EndPhase(context.Background(), sequence, true) == nil {
				t.Fatal("failed completion save was hidden")
			}
			recorder.Record("fatal", failureTestCaller, 451)
			if marker := failureTestMarker(t, inv); marker.Completed != (CompletedCheckpoint{Code: "none"}) {
				t.Fatal("failed save advanced checkpoint")
			}
			if err := os.Remove(target); err != nil {
				t.Fatal(err)
			}
			if worker.Finish(context.Background(), false) != nil {
				t.Fatal("failed worker did not release its runtime")
			}
		})
	}
}

// full_only: false
func TestFailureMarkerRejectsInvalidEvidence(t *testing.T) {
	for _, name := range []string{"valid", "schema", "run", "worker", "role", "scenario", "nonce", "unknown_field", "unknown_code", "operation_secret", "operation_unknown_field", "operation_old_schema", "operation_missing_schema", "operation_provider_status", "operation_provider_codes", "zero_line", "negative_line", "absolute", "traversal", "backslash", "escaped", "unmapped", "phase", "phase_sequence", "checkpoint_code", "checkpoint_ahead", "checkpoint_zero", "checkpoint_same_sequence", "malformed", "trailing", "limit", "excess", "symlink", "directory", "public_mode"} {
		t.Run(name, func(t *testing.T) {
			inv := failureTestInvocation(t)
			// The fixture is independent of the recorder under test.
			body := []byte(`{"schema_version":1,"run_id":"0123456789abcdef0123456789abcdef","worker":"0000-point-writer","role":"writer","scenario":"state.single-value-update-preserves-other-values/members_32","nonce":"0123456789abcdef0123456789abcdef","phase":"transition","sequence":2,"code":"fatal","source":"tests/shared/fixture_test.go","line":451,"completed":{"code":"setup","sequence":1}}`)
			var raw map[string]any
			if json.Unmarshal(body, &raw) != nil {
				t.Fatal("invalid literal fixture")
			}
			checkpoint := raw["completed"].(map[string]any)
			switch name {
			case "schema":
				raw["schema_version"] = 2
			case "run":
				raw["run_id"] = strings.Repeat("f", 32)
			case "worker":
				raw["worker"] = "other"
			case "role":
				raw["role"] = "cleanup"
			case "scenario":
				raw["scenario"] = "genesis.empty-domain-reopens/empty_genesis"
			case "nonce":
				raw["nonce"] = strings.Repeat("f", 32)
			case "unknown_field":
				raw["message"] = "SECRET_SENTINEL"
			case "unknown_code":
				raw["code"] = "SECRET_SENTINEL"
			case "operation_secret":
				raw["operation_failure"] = map[string]any{"schema_version": 2, "operation": "SECRET_SENTINEL", "stage": "entry", "category": "invalid", "code": 2, "effect": "no_send", "facts_status": "facts_unavailable"}
			case "operation_unknown_field":
				raw["operation_failure"] = map[string]any{"schema_version": 2, "operation": "generated_create", "stage": "entry", "category": "invalid", "code": 2, "effect": "no_send", "facts_status": "facts_unavailable", "private_id": "SECRET_SENTINEL"}
			case "operation_old_schema", "operation_missing_schema", "operation_provider_status", "operation_provider_codes":
				operation := map[string]any{"schema_version": 2, "operation": "generated_create", "stage": "completed", "category": "none", "code": 1, "effect": "unknown", "facts_status": "qualified"}
				facts := map[string]any{"disposition": 5, "reason": 8}
				operation["safe_facts"] = facts
				switch name {
				case "operation_old_schema":
					operation["schema_version"] = 1
				case "operation_missing_schema":
					delete(operation, "schema_version")
				case "operation_provider_status":
					facts["http_status"] = 503
				case "operation_provider_codes":
					facts["error_codes"] = []int{17}
				}
				raw["operation_failure"] = operation
			case "zero_line":
				raw["line"] = 0
			case "negative_line":
				raw["line"] = -1
			case "absolute":
				raw["source"] = "/tmp/fixture_test.go"
			case "traversal":
				raw["source"] = "tests/../core/fixture_test.go"
			case "backslash":
				raw["source"] = `tests\shared\fixture_test.go`
			case "escaped":
				raw["source"] = "tests/%2e%2e/fixture_test.go"
			case "unmapped":
				raw["source"] = "tests/shared/other_test.go"
			case "phase":
				raw["phase"] = "secret-phase"
			case "phase_sequence":
				raw["sequence"] = 0
			case "checkpoint_code":
				checkpoint["code"] = "secret-checkpoint"
			case "checkpoint_ahead":
				checkpoint["sequence"] = 3
			case "checkpoint_zero":
				checkpoint["sequence"] = 0
			case "checkpoint_same_sequence":
				checkpoint["sequence"] = 2
			}
			var err error
			body, err = json.Marshal(raw)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "malformed":
				body = []byte(`{`)
			case "trailing":
				body = append(body, []byte(` {}`)...)
			case "limit":
				body = append(body, bytes.Repeat([]byte(" "), 4096-len(body))...)
			case "excess":
				body = append(body, bytes.Repeat([]byte(" "), 4097-len(body))...)
			}
			file := filepath.Join(inv.OutputDir, "failure.json")
			switch name {
			case "symlink":
				target := filepath.Join(inv.StateDir, "outside.json")
				if os.WriteFile(target, body, 0o600) != nil || os.Symlink(target, file) != nil {
					t.Fatal("symlink fixture")
				}
			case "directory":
				if os.Mkdir(file, 0o700) != nil {
					t.Fatal("directory fixture")
				}
			default:
				mode := os.FileMode(0o600)
				if name == "public_mode" {
					mode = 0o644
				}
				if os.WriteFile(file, body, mode) != nil {
					t.Fatal("marker fixture")
				}
				if err := os.Chmod(file, mode); err != nil {
					t.Fatal("marker fixture permissions", err)
				}
				info, err := os.Lstat(file)
				if err != nil {
					t.Fatal("marker fixture stat", err)
				}
				if !info.Mode().IsRegular() || info.Mode().Perm() != mode {
					t.Fatal("marker fixture mode differs", info.Mode())
				}
			}
			want := "invalid_failure_marker"
			if name == "valid" || name == "limit" {
				want = "valid_failure_marker"
			}
			if got := InspectAssertions(inv, false); got.Marker != want || got.OperationFailure != nil {
				t.Fatal("marker admission differs", name, got)
			}
		})
	}
}

// full_only: false
func TestFailureMarkerBindsEveryInvocationRole(t *testing.T) {
	original := failureTestInvocation(t)
	recorder := failureTestRecorder(t, original)
	recorder.Record("fatal", failureTestCaller, 451)
	body, err := os.ReadFile(filepath.Join(original.OutputDir, "failure.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"writer", "fresh_before", "fresh_after", "rerun", "cleanup"} {
		t.Run(role, func(t *testing.T) {
			inv := original
			inv.Role = role
			inv.Worker = "another-" + role
			inv.Nonce, err = NewInvocationNonce()
			if err != nil {
				t.Fatal(err)
			}
			inv.OutputDir = filepath.Join(filepath.Dir(original.OutputDir), role)
			if inv.OutputDir == original.OutputDir {
				inv.OutputDir += "-next"
			}
			if os.Mkdir(inv.OutputDir, 0o700) != nil || os.WriteFile(filepath.Join(inv.OutputDir, "failure.json"), body, 0o600) != nil {
				t.Fatal("replay fixture")
			}
			if got := InspectAssertions(inv, false); got.Marker != "invalid_failure_marker" {
				t.Fatal("cross-invocation marker admitted", got)
			}
		})
	}
	original.Nonce = strings.Repeat("f", 32)
	if got := InspectAssertions(original, false); got.Marker != "invalid_failure_marker" {
		t.Fatal("same identity reused an earlier invocation marker")
	}
}

// full_only: false
func TestFailureSourceMappingUsesExactQualifiedPaths(t *testing.T) {
	for _, caller := range []string{failureTestCaller, "enkv.sh/crypto@v0.0.0/testsupport/custody/live.go", "/tmp/core/tests_shared_fixture_test.go", "enkv.sh/crypto@v0.0.1/testsupport/custody/live.go", "enkv.sh/core/tests_shared_fixture_test_other.go"} {
		t.Run(strings.ReplaceAll(caller, "/", "_"), func(t *testing.T) {
			inv := failureTestInvocation(t)
			recorder := failureTestRecorder(t, inv)
			recorder.Record("fatal", caller, 21)
			got := InspectAssertions(inv, false)
			want := "no_failure_marker"
			if caller == failureTestCaller || strings.Contains(caller, "crypto@v0.0.0/") {
				want = "valid_failure_marker"
			}
			if got.Marker != want {
				t.Fatal("source mapping guessed or lost an exact admitted path", got)
			}
		})
	}
	inv := failureTestInvocation(t)
	inv.FailureSources.SHA256 = strings.Repeat("f", 64)
	if _, err := NewFailureRecorder(inv); err == nil {
		t.Fatal("unbound source mapping admitted")
	}
	for _, row := range []struct {
		caller, source string
		allowed        bool
	}{
		{"enkv.sh/crypto@v0.0.0/zz_test_admission.go", "tests/crypto/admission.go", true},
		{"enkv.sh/compositions/generatorhost@v0.0.0/zz_test_environment.go", "tests/generatorhost/environment.go", true},
		{"enkv.sh/crypto@v0.0.0/zz_test_private_test.go", "tests/crypto/private_test.go", true},
		{"enkv.sh/core/zz_test_private_test.go", "tests/crypto/private_test.go", false},
		{"enkv.sh/compositions/full@v0.0.0/zz_test_admission.go", "tests/full/admission.go", true},
		{"enkv.sh/compositions/full@v0.0.0/zz_test_admission.go", "tests/gcp/admission.go", false},
		{"enkv.sh/providers/gcp@v0.0.0/credentials/zz_test_admission.go", "tests/gcpcredentials/admission.go", true},
		{"enkv.sh/providers/gcp@v0.0.0/zz_test_admission.go", "tests/gcp/admission.go", true},
		{"enkv.sh/providers/gcp@v0.0.0/zz_test_admission.go", "tests/gcpcredentials/admission.go", false},
		{"enkv.sh/providers/gcp@v0.0.0/credentials/zz_test_admission.go", "tests/gcp/admission.go", false},
		{"enkv.sh/core/tests_gcpcredentials_admission.go", "tests/gcpcredentials/admission.go", false},
		{"enkv.sh/crypto@v0.0.0/testsupport/custody/zz_test_output_box.go", "tests/live/custody/output_box.go", true},
		{"enkv.sh/core/tests_live_custody_output_box.go", "tests/live/custody/output_box.go", false},
		{"enkv.sh/crypto@v0.0.0/zz_test_output_box.go", "tests/live/custody/output_box.go", false},
		{"enkv.sh/crypto@v0.0.0/testsupport/trust/zz_test_output_box.go", "tests/live/custody/output_box.go", false},
		{"enkv.sh/crypto@v0.0.0/testsupport/custody/zz_test_other.go", "tests/live/custody/output_box.go", false},
		{"enkv.sh/crypto@v0.0.0/testsupport/custody/zz_test_output_box.go", "tests/live/custody/other.go", false},
		{"enkv.sh/providers/aws@v0.0.0/testsupport/custody/zz_test_output_box.go", "tests/live/custody/output_box.go", false},
	} {
		if failureSourceMatchesOwner(row.caller, row.source) != row.allowed {
			t.Fatal("credential admission source owner differs", row.caller)
		}
	}
}

// full_only: false
func TestFailureCheckpointRejectsInvalidEvidence(t *testing.T) {
	for _, name := range []string{"valid", "schema", "nonce", "scenario", "unknown", "unknown_code", "zero_sequence", "excess_sequence", "malformed", "trailing", "limit", "excess", "directory", "public_mode"} {
		t.Run(name, func(t *testing.T) {
			inv := failureTestInvocation(t)
			body := []byte(`{"schema_version":1,"run_id":"0123456789abcdef0123456789abcdef","worker":"0000-point-writer","role":"writer","scenario":"state.single-value-update-preserves-other-values/members_32","nonce":"0123456789abcdef0123456789abcdef","completed":{"code":"setup","sequence":1}}`)
			var raw map[string]any
			if json.Unmarshal(body, &raw) != nil {
				t.Fatal("checkpoint literal refused")
			}
			completed := raw["completed"].(map[string]any)
			switch name {
			case "schema":
				raw["schema_version"] = 2
			case "nonce":
				raw["nonce"] = strings.Repeat("f", 32)
			case "scenario":
				raw["scenario"] = "genesis.empty-domain-reopens/empty_genesis"
			case "unknown":
				raw["message"] = "SECRET_SENTINEL"
			case "unknown_code":
				completed["code"] = "SECRET_SENTINEL"
			case "zero_sequence":
				completed["sequence"] = 0
			case "excess_sequence":
				completed["sequence"] = 257
			}
			var err error
			body, err = json.Marshal(raw)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "malformed":
				body = []byte("{")
			case "trailing":
				body = append(body, []byte(" {}")...)
			case "limit":
				body = append(body, bytes.Repeat([]byte(" "), 4096-len(body))...)
			case "excess":
				body = append(body, bytes.Repeat([]byte(" "), 4097-len(body))...)
			}
			file := filepath.Join(inv.OutputDir, "checkpoint.json")
			if name == "directory" {
				if os.Mkdir(file, 0700) != nil {
					t.Fatal("checkpoint directory fixture")
				}
			} else {
				mode := os.FileMode(0600)
				if name == "public_mode" {
					mode = 0644
				}
				if os.WriteFile(file, body, mode) != nil {
					t.Fatal("checkpoint fixture unavailable")
				}
				if err := os.Chmod(file, mode); err != nil {
					t.Fatal("checkpoint fixture permissions", err)
				}
				info, err := os.Lstat(file)
				if err != nil {
					t.Fatal("checkpoint fixture stat", err)
				}
				if !info.Mode().IsRegular() || info.Mode().Perm() != mode {
					t.Fatal("checkpoint fixture mode differs", info.Mode())
				}
			}
			evidence := InspectAssertions(inv, false)
			valid := name == "valid" || name == "limit"
			if (evidence.Checkpoint == "valid_checkpoint") != valid || evidence.Marker != "no_failure_marker" || evidence.MarkerWriteError {
				t.Fatal("checkpoint admission differs", evidence)
			}
			if !valid && (evidence.Completed != (CompletedCheckpoint{Code: "none"}) || evidence.PermitsSuccess()) {
				t.Fatal("invalid checkpoint supplied a public completion", evidence)
			}
		})
	}
}

// full_only: false
func TestFailureOwnerRejectsChangedInvocationAndSourceBinding(t *testing.T) {
	inv := failureTestInvocation(t)
	owner := failureTestRecorder(t, inv)
	for _, field := range []string{"nonce", "scenario", "worker", "output", "source"} {
		t.Run(field, func(t *testing.T) {
			changed := inv
			switch field {
			case "nonce":
				changed.Nonce = strings.Repeat("f", 32)
			case "scenario":
				changed.Scenario = "access.provider-refuses-observer/members_32_denied_observer"
			case "worker":
				changed.Worker = "other"
			case "output":
				changed.OutputDir = inv.StateDir
			case "source":
				binding := *inv.FailureSources
				binding.SHA256 = strings.Repeat("f", 64)
				changed.FailureSources = &binding
			}
			if _, err := NewWorker(changed, "core", changed.Scenario, owner); err == nil {
				t.Fatal("failure owner crossed its admitted invocation")
			}
		})
	}
}

// full_only: false
func TestFailureEvidenceRequiresPrivateWorkerDirectory(t *testing.T) {
	inv := failureTestInvocation(t)
	if os.Chmod(inv.OutputDir, 0755) != nil {
		t.Fatal("directory permission fixture")
	}
	if _, err := NewFailureRecorder(inv); err == nil {
		t.Fatal("public worker directory admitted")
	}
	if os.Chmod(inv.OutputDir, 0700) != nil {
		t.Fatal("private directory fixture")
	}
	owner := failureTestRecorder(t, inv)
	if owner.begin("setup", 1) != nil || os.Chmod(inv.OutputDir, 0755) != nil {
		t.Fatal("changed directory fixture")
	}
	if owner.complete("setup", 1) == nil {
		t.Fatal("checkpoint was written under a public directory")
	}
	owner.Record("fatal", failureTestCaller, 1)
	for _, name := range []string{"failure.json", "checkpoint.json"} {
		if _, err := os.Lstat(filepath.Join(inv.OutputDir, name)); !os.IsNotExist(err) {
			t.Fatal("private evidence was published in a public directory")
		}
	}
}

// full_only: false
func TestFailureSourcesAdmitsOnlyPureProfileFiles(t *testing.T) {
	for _, owner := range []string{"cloudflare", "local-random-secret", "aws-output", "gcp-output", "github-output"} {
		source := "plugins/" + owner + "/profile/profile.go"
		sources := FailureSources{SchemaVersion: FailureSchemaVersion, BinarySHA256: strings.Repeat("1", 64), OverlaySHA256: strings.Repeat("2", 64), Paths: map[string]string{passiveFailureCaller(source): source}}
		if err := sources.Validate(); err != nil {
			t.Fatal("compiled pure profile source refused", owner, err)
		}
		for _, refused := range []string{"plugins/" + owner + "/client.go", "plugins/" + owner + "/internal/client.go", "plugins/" + owner + "/profile/nested/client.go", "plugins/uninstalled/profile/profile.go"} {
			sources.Paths = map[string]string{passiveFailureCaller(refused): refused}
			if sources.Validate() == nil {
				t.Fatal("unreviewed plugin source admitted", refused)
			}
		}
	}
}

// full_only: false
func TestFailureSourcesAdmitOnlyIndependentManifestConsumer(t *testing.T) {
	const module = "enkv.sh/sdk/examples/ini-reference-manifest@v0.0.0/"
	const selector = "sdk/examples/ini-reference-manifest/"
	for _, row := range []struct {
		name, caller, source string
		admitted             bool
	}{
		{"consumer", module + "consumer/read.go", selector + "consumer/read.go", true},
		{"consumer test", module + "consumer/read_test.go", selector + "consumer/read_test.go", true},
		{"other direct consumer source", module + "consumer/values.go", selector + "consumer/values.go", true},
		{"root", module + "main.go", selector + "main.go", false},
		{"sibling", module + "renderer/read.go", selector + "renderer/read.go", false},
		{"nested", module + "consumer/nested/read.go", selector + "consumer/nested/read.go", false},
		{"other example", "enkv.sh/sdk/examples/local-value-output@v0.0.0/consumer/read.go", "sdk/examples/local-value-output/consumer/read.go", false},
		{"private owner", "enkv.sh/core/consumer/read.go", selector + "consumer/read.go", false},
		{"SDK owner", "enkv.sh/sdk/manifest-generator@v0.0.0/consumer/read.go", selector + "consumer/read.go", false},
		{"example owner swap", "enkv.sh/sdk/examples/local-value-output@v0.0.0/consumer/read.go", selector + "consumer/read.go", false},
		{"root caller", module + "read.go", selector + "consumer/read.go", false},
		{"sibling caller", module + "renderer/read.go", selector + "consumer/read.go", false},
		{"nested caller", module + "consumer/nested/read.go", selector + "consumer/read.go", false},
		{"filename swap", module + "consumer/other.go", selector + "consumer/read.go", false},
		{"reverse owner swap", module + "consumer/read.go", "core/read.go", false},
		{"non-Go", module + "consumer/README.md", selector + "consumer/README.md", false},
		{"traversal", module + "consumer/../read.go", selector + "consumer/../read.go", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			sources := FailureSources{SchemaVersion: FailureSchemaVersion, BinarySHA256: strings.Repeat("1", 64), OverlaySHA256: strings.Repeat("2", 64), Paths: map[string]string{row.caller: row.source}}
			if err := sources.Validate(); (err == nil) != row.admitted {
				t.Fatal("independent consumer source mapping classification differs", err)
			}
		})
	}
}

// full_only: false
func TestFailureSourcesAdmitOnlyExactManifestModuleMappings(t *testing.T) {
	for _, row := range []struct {
		name, caller, source string
		admitted             bool
	}{
		{"SDK root", "enkv.sh/sdk/manifest-generator@v0.0.0/view.go", "sdk/manifest-generator/view.go", true},
		{"SDK released source", "enkv.sh/sdk/manifest-generator@v0.1.0/view.go", "sdk/manifest-generator/view.go", true},
		{"SDK pseudo-version source", "enkv.sh/sdk/manifest-generator@v0.0.0-20240905190251-b4127c9b8d78/view.go", "sdk/manifest-generator/view.go", true},
		{"plugin released source", "enkv.sh/plugins/manifest-generators/generic-json@v0.1.0/encode.go", "plugins/manifest-generators/generic-json/encode.go", true},
		{"plugin pseudo-version source", "enkv.sh/plugins/manifest-generators/generic-json@v0.0.0-20240905190251-b4127c9b8d78/encode.go", "plugins/manifest-generators/generic-json/encode.go", true},
		{"artifact released source", "enkv.sh/sdk/artifact@v0.1.0/types.go", "sdk/artifact/types.go", true},
		{"artifact pseudo-version source", "enkv.sh/sdk/artifact@v0.0.0-20240905190251-b4127c9b8d78/types.go", "sdk/artifact/types.go", true},
		{"generator artifact released source", "enkv.sh/plugins/generators/cloudflare-account-token@v0.1.0/artifact/manifest.go", "plugins/cloudflare/artifact/manifest.go", true},
		{"generator artifact pseudo-version source", "enkv.sh/plugins/generators/cloudflare-account-token@v0.0.0-20240905190251-b4127c9b8d78/artifact/manifest.go", "plugins/cloudflare/artifact/manifest.go", true},
		{"plugin root", "enkv.sh/plugins/manifest-generators/generic-json@v0.0.0/encode.go", "plugins/manifest-generators/generic-json/encode.go", true},
		{"SDK test source", "enkv.sh/sdk/manifest-generator@v0.0.0/artifact_test.go", "sdk/manifest-generator/artifact_test.go", true},
		{"writer root", "enkv.sh/sdk/manifest-generator@v0.0.0/jsonwriter/writer.go", "sdk/manifest-generator/jsonwriter/writer.go", true},
		{"OpenTofu root", "enkv.sh/plugins/manifest-generators/opentofu-tfvars-json@v0.0.0/encode.go", "plugins/manifest-generators/opentofu-tfvars-json/encode.go", true},
		{"writer missing version", "enkv.sh/sdk/manifest-generator/jsonwriter/writer.go", "sdk/manifest-generator/jsonwriter/writer.go", false},
		{"writer other release", "enkv.sh/sdk/manifest-generator@v0.0.1/jsonwriter/writer.go", "sdk/manifest-generator/jsonwriter/writer.go", true},
		{"writer wrong owner", "enkv.sh/plugins/manifest-generators/generic-json@v0.0.0/jsonwriter/writer.go", "sdk/manifest-generator/jsonwriter/writer.go", false},
		{"writer wrong filename", "enkv.sh/sdk/manifest-generator@v0.0.0/jsonwriter/other.go", "sdk/manifest-generator/jsonwriter/writer.go", false},
		{"writer nested source", "enkv.sh/sdk/manifest-generator@v0.0.0/jsonwriter/nested/writer.go", "sdk/manifest-generator/jsonwriter/nested/writer.go", false},
		{"OpenTofu missing version", "enkv.sh/plugins/manifest-generators/opentofu-tfvars-json/encode.go", "plugins/manifest-generators/opentofu-tfvars-json/encode.go", false},
		{"OpenTofu other release", "enkv.sh/plugins/manifest-generators/opentofu-tfvars-json@v0.0.1/encode.go", "plugins/manifest-generators/opentofu-tfvars-json/encode.go", true},
		{"OpenTofu wrong owner", "enkv.sh/plugins/manifest-generators/generic-json@v0.0.0/encode.go", "plugins/manifest-generators/opentofu-tfvars-json/encode.go", false},
		{"OpenTofu wrong filename", "enkv.sh/plugins/manifest-generators/opentofu-tfvars-json@v0.0.0/other.go", "plugins/manifest-generators/opentofu-tfvars-json/encode.go", false},
		{"OpenTofu nested source", "enkv.sh/plugins/manifest-generators/opentofu-tfvars-json@v0.0.0/internal/encode.go", "plugins/manifest-generators/opentofu-tfvars-json/internal/encode.go", false},
		{"SDK native runtime", "enkv.sh/sdk/manifest-generator@v0.0.0/native/main.go", "sdk/manifest-generator/native/main.go", false},
		{"OpenTofu native command", "enkv.sh/plugins/manifest-generators/opentofu-tfvars-json@v0.0.0/cmd/enkv-manifest-opentofu-tfvars-json/main.go", "plugins/manifest-generators/opentofu-tfvars-json/cmd/enkv-manifest-opentofu-tfvars-json/main.go", false},
		{"OpenTofu example", "enkv.sh/sdk/examples/ini-reference-manifest@v0.0.0/main.go", "sdk/examples/ini-reference-manifest/main.go", false},
		{"swapped plugin owner", "enkv.sh/sdk/manifest-generator@v0.0.0/encode.go", "plugins/manifest-generators/generic-json/encode.go", false},
		{"swapped SDK owner", "enkv.sh/plugins/manifest-generators/generic-json@v0.0.0/view.go", "sdk/manifest-generator/view.go", false},
		{"different source filename", "enkv.sh/sdk/manifest-generator@v0.0.0/other.go", "sdk/manifest-generator/view.go", false},
		{"SDK missing version", "enkv.sh/sdk/manifest-generator/view.go", "sdk/manifest-generator/view.go", false},
		{"SDK other release", "enkv.sh/sdk/manifest-generator@v0.0.1/view.go", "sdk/manifest-generator/view.go", true},
		{"plugin other release", "enkv.sh/plugins/manifest-generators/generic-json@v0.0.1/encode.go", "plugins/manifest-generators/generic-json/encode.go", true},
		{"SDK main version", "enkv.sh/sdk/manifest-generator@local/view.go", "sdk/manifest-generator/view.go", false},
		{"SDK traversal", "enkv.sh/sdk/manifest-generator@v0.0.0/../view.go", "sdk/manifest-generator/../view.go", false},
		{"plugin traversal", "enkv.sh/plugins/manifest-generators/generic-json@v0.0.0/../encode.go", "plugins/manifest-generators/generic-json/../encode.go", false},
		{"SDK conformance", "enkv.sh/sdk/manifest-generator@v0.0.0/conformance/check.go", "sdk/manifest-generator/conformance/check.go", false},
		{"plugin child", "enkv.sh/plugins/manifest-generators/generic-json@v0.0.0/internal/encode.go", "plugins/manifest-generators/generic-json/internal/encode.go", false},
		{"example runtime", "enkv.sh/sdk/examples/ini-reference-manifest@v0.0.0/main.go", "sdk/examples/ini-reference-manifest/main.go", false},
		{"output runtime", "enkv.sh/sdk/output@v0.0.0/main.go", "sdk/output/main.go", false},
		{"foreign caller", "example.invalid/sdk/manifest-generator@v0.0.0/view.go", "sdk/manifest-generator/view.go", false},
		{"private caller for public source", "enkv.sh/core/reader.go", "sdk/manifest-generator/view.go", false},
		{"public caller for private source", "enkv.sh/sdk/manifest-generator@v0.0.0/view.go", "core/reader.go", false},
		{"unknown public module", "enkv.sh/sdk/unknown@v0.0.0/view.go", "sdk/manifest-generator/view.go", false},
		{"non-Go source", "enkv.sh/sdk/manifest-generator@v0.0.0/go.mod", "sdk/manifest-generator/go.mod", false},
		{"artifact codec root", "enkv.sh/sdk/artifact@v0.0.0/types.go", "sdk/artifact/types.go", true},
		{"artifact codec test source", "enkv.sh/sdk/artifact@v0.0.0/types_test.go", "sdk/artifact/types_test.go", true},
		{"credential route source", "enkv.sh/sdk/artifact@v0.0.0/credentialroute/route.go", "sdk/artifact/credentialroute/route.go", true},
		{"credential route test source", "enkv.sh/sdk/artifact@v0.0.0/credentialroute/route_test.go", "sdk/artifact/credentialroute/route_test.go", true},
		{"credential route missing version", "enkv.sh/sdk/artifact/credentialroute/route.go", "sdk/artifact/credentialroute/route.go", false},
		{"credential route other release", "enkv.sh/sdk/artifact@v0.0.1/credentialroute/route.go", "sdk/artifact/credentialroute/route.go", true},
		{"credential route wrong owner", "enkv.sh/sdk/manifest-generator@v0.0.0/credentialroute/route.go", "sdk/artifact/credentialroute/route.go", false},
		{"credential route wrong filename", "enkv.sh/sdk/artifact@v0.0.0/credentialroute/other.go", "sdk/artifact/credentialroute/route.go", false},
		{"credential route nested source", "enkv.sh/sdk/artifact@v0.0.0/credentialroute/nested/route.go", "sdk/artifact/credentialroute/nested/route.go", false},
		{"credential route private source", "enkv.sh/sdk/artifact@v0.0.0/credentialroute/private/route.go", "sdk/artifact/credentialroute/private/route.go", false},
		{"artifact private source", "enkv.sh/sdk/artifact@v0.0.0/private/route.go", "sdk/artifact/private/route.go", false},
		{"artifact tooling source", "enkv.sh/sdk/artifact@v0.0.0/tools/route.go", "sdk/artifact/tools/route.go", false},
		{"credential route non-Go source", "enkv.sh/sdk/artifact@v0.0.0/credentialroute/go.mod", "sdk/artifact/credentialroute/go.mod", false},
		{"generator artifact root", "enkv.sh/plugins/generators/cloudflare-account-token@v0.0.0/artifact/manifest.go", "plugins/cloudflare/artifact/manifest.go", true},
		{"artifact codec different filename", "enkv.sh/sdk/artifact@v0.0.0/other.go", "sdk/artifact/types.go", false},
		{"generator artifact different filename", "enkv.sh/plugins/generators/cloudflare-account-token@v0.0.0/artifact/other.go", "plugins/cloudflare/artifact/manifest.go", false},
		{"artifact codec missing version", "enkv.sh/sdk/artifact/types.go", "sdk/artifact/types.go", false},
		{"generator artifact missing version", "enkv.sh/plugins/generators/cloudflare-account-token/artifact/manifest.go", "plugins/cloudflare/artifact/manifest.go", false},
		{"artifact codec other release", "enkv.sh/sdk/artifact@v0.0.1/types.go", "sdk/artifact/types.go", true},
		{"generator artifact other release", "enkv.sh/plugins/generators/cloudflare-account-token@v0.0.1/artifact/manifest.go", "plugins/cloudflare/artifact/manifest.go", true},
		{"artifact codec main version", "enkv.sh/sdk/artifact@local/types.go", "sdk/artifact/types.go", false},
		{"generator artifact main version", "enkv.sh/plugins/generators/cloudflare-account-token@local/artifact/manifest.go", "plugins/cloudflare/artifact/manifest.go", false},
		{"artifact codec swapped owner", "enkv.sh/plugins/generators/cloudflare-account-token@v0.0.0/artifact/types.go", "sdk/artifact/types.go", false},
		{"generator artifact swapped owner", "enkv.sh/sdk/artifact@v0.0.0/manifest.go", "plugins/cloudflare/artifact/manifest.go", false},
		{"artifact codec foreign caller", "example.invalid/artifact@v0.0.0/types.go", "sdk/artifact/types.go", false},
		{"generator artifact other plugin caller", "enkv.sh/plugins/outputs/aws-secrets-manager@v0.0.0/artifact/manifest.go", "plugins/cloudflare/artifact/manifest.go", false},
		{"other plugin artifact source", "enkv.sh/plugins/outputs/aws-secrets-manager@v0.0.0/artifact/manifest.go", "plugins/aws-output/artifact/manifest.go", false},
		{"unregistered plugin artifact source", "enkv.sh/plugins/generators/other@v0.0.0/artifact/manifest.go", "plugins/other/artifact/manifest.go", false},
		{"artifact codec nested source", "enkv.sh/sdk/artifact@v0.0.0/nested/types.go", "sdk/artifact/nested/types.go", false},
		{"generator artifact nested source", "enkv.sh/plugins/generators/cloudflare-account-token@v0.0.0/artifact/nested/manifest.go", "plugins/cloudflare/artifact/nested/manifest.go", false},
		{"artifact build tool", "enkv.sh/sdk/artifact@v0.0.0/build/build.go", "sdk/artifact/build/build.go", false},
		{"artifact command tool", "enkv.sh/sdk/artifact@v0.0.0/cmd/enkv-plugin-build/main.go", "sdk/artifact/cmd/enkv-plugin-build/main.go", false},
		{"artifact nested caller for root source", "enkv.sh/sdk/artifact@v0.0.0/build/types.go", "sdk/artifact/types.go", false},
		{"generator nested caller for root source", "enkv.sh/plugins/generators/cloudflare-account-token@v0.0.0/artifact/nested/manifest.go", "plugins/cloudflare/artifact/manifest.go", false},
		{"artifact codec traversal", "enkv.sh/sdk/artifact@v0.0.0/../types.go", "sdk/artifact/../types.go", false},
		{"generator artifact traversal", "enkv.sh/plugins/generators/cloudflare-account-token@v0.0.0/artifact/../manifest.go", "plugins/cloudflare/artifact/../manifest.go", false},
		{"artifact codec non-Go source", "enkv.sh/sdk/artifact@v0.0.0/go.mod", "sdk/artifact/go.mod", false},
		{"generator artifact non-Go source", "enkv.sh/plugins/generators/cloudflare-account-token@v0.0.0/artifact/go.mod", "plugins/cloudflare/artifact/go.mod", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			sources := FailureSources{SchemaVersion: FailureSchemaVersion, BinarySHA256: strings.Repeat("1", 64), OverlaySHA256: strings.Repeat("2", 64), Paths: map[string]string{row.caller: row.source}}
			if err := sources.Validate(); (err == nil) != row.admitted {
				t.Fatal("passive module source mapping classification differs", err)
			}
		})
	}
}

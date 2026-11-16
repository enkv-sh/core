package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/telemetry"
)

func caseReceiptFixture(t *testing.T, suite, provider string, sequence int) (*runState, scenarioResult) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	schedule, err := catalog.Resolve(catalog.Request{Include: []string{"state.single-value-update-preserves-other-values/members_32"}, Repetitions: 2})
	if err != nil || sequence >= len(schedule.Entries) {
		t.Fatal("controlled schedule unavailable", err)
	}
	s, err := newRunState(root, runRequest{Suite: suite, Provider: provider, Target: "controlled",
		Profile: "full", Schedule: schedule}, records.Source{Revision: strings.Repeat("a", 40)}, "go version go1.27.0 darwin/arm64")
	if err != nil {
		t.Fatal(err)
	}
	if s.current != nil {
		t.Cleanup(func() {
			if err := s.current.remove(true); err != nil {
				t.Error("remove receipt fixture without consumers", err)
			}
		})
	}
	s.record.CoverageScope = suite + "_scenarios"
	s.record.Resolved = &resolvedRequest{Profile: "full", Race: true, Mode: suite, Provider: provider,
		RecoveryMode: "disabled", Resource: "controlled", Schedule: schedule,
		RoleBindings: map[string]string{"authority": "operator"}}
	s.record.BuildClosure = &assemblyClosure{Suite: suite, Provider: provider, Race: true,
		BinarySHA256: strings.Repeat("b", 64), OverlaySHA256: strings.Repeat("c", 64)}
	s.record.Context = &runContext{Region: "controlled", ConfigurationSHA256: strings.Repeat("d", 64),
		ResourceHashes: map[string]string{"bucket": strings.Repeat("e", 64)}}
	allowance := testLimits()
	s.record.Limits = &allowance
	entry := schedule.Entries[sequence]
	shape, err := recordedFixture(entry.Scenario, entry.Members)
	if err != nil {
		t.Fatal(err)
	}
	result := scenarioResult{Entry: entry, Fixture: shape, Outcome: "passed", CorrectnessPassed: true,
		Cleanup: records.Cleanup{Outcome: "passed", RemainingOwnedObjects: new(int64), UnknownEffects: new(int64)}}
	s.record.Scenarios = []scenarioResult{result}
	return s, result
}

func writeControlledCaseReceipt(t *testing.T, s *runState, result scenarioResult) caseReceiptRef {
	t.Helper()
	identity, err := caseIdentitySHA256(s.record)
	if err != nil {
		t.Fatal("controlled case identity unavailable", err)
	}
	if err := s.writeCaseReceipt(result, identity); err != nil {
		t.Fatal("write controlled case receipt", err)
	}
	if err := s.save(); err != nil {
		t.Fatal("save controlled case receipt owner", err)
	}
	return s.record.CaseReceipts[0]
}

// full_only: false
func TestCaseReceiptKeepsRetainedNamedPointSmokeIdentity(t *testing.T) {
	const wire = `{"recovery_mode":"both","selected_scenarios":["state.single-value-update-preserves-other-values/members_32"],"repetitions":1,"entries":[{"scenario":"state.single-value-update-preserves-other-values/members_32","sequence":0,"repetition":0,"smoke":true}],"full_coverage":false,"smoke_policy":"first-selected-point"}`
	var retained catalog.Schedule
	if err := json.Unmarshal([]byte(wire), &retained); err != nil {
		t.Fatal(err)
	}
	s, result := caseReceiptFixture(t, "live", "gcp", 0)
	s.record.Schedule = retained
	s.record.Resolved.Schedule, s.record.Resolved.RecoveryMode = retained, "both"
	result.Entry = retained.Entries[0]
	s.record.Scenarios[0] = result
	ref := writeControlledCaseReceipt(t, s, result)
	path := filepath.Join(s.directory, filepath.FromSlash(ref.Path))
	parentPath := filepath.Join(s.directory, "run.json")
	before, err := os.ReadFile(path)
	if err != nil || digestBytes(before) != ref.SHA256 {
		t.Fatal("retained named receipt bytes unavailable", err)
	}
	beforeParent, err := os.ReadFile(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	var parent runRecord
	if records.ReadJSON(parentPath, &parent) != nil {
		t.Fatal("retained parent unavailable")
	}
	expected, err := reconstructRecordedSchedule(parent.Schedule)
	if err != nil || !reflect.DeepEqual(expected, retained) {
		t.Fatal("retained named schedule lost its original smoke identity", err)
	}
	if _, err := validateCaseReceipt(s.directory, parent, ref, expected.Entries[0]); err != nil || validateCaseReceiptSet(s.directory, parent) != nil {
		t.Fatal("retained source-bound named receipt refused", err)
	}
	stateBefore, err := recordedCaseDirectory(result.Entry)
	if err != nil {
		t.Fatal(err)
	}
	for _, damage := range []string{"source", "count", "smoke-repetition", "receipt-digest"} {
		t.Run(damage, func(t *testing.T) {
			var changed runRecord
			if err := json.Unmarshal(beforeParent, &changed); err != nil {
				t.Fatal(err)
			}
			changedRef := ref
			switch damage {
			case "source":
				changed.Source.Revision = strings.Repeat("f", 40)
			case "count":
				changed.Schedule.Repetitions = 3
			case "smoke-repetition":
				changed.Schedule.Entries[0].Repetition = 1
			case "receipt-digest":
				changedRef.SHA256 = strings.Repeat("f", 64)
			}
			if _, err := validateCaseReceipt(s.directory, changed, changedRef, result.Entry); err == nil {
				t.Fatal("retained named receipt authorized changed source, schedule or bytes")
			}
		})
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("retained receipt validation changed original bytes", err)
	}
	afterParent, err := os.ReadFile(parentPath)
	if err != nil || !bytes.Equal(beforeParent, afterParent) {
		t.Fatal("retained receipt validation changed parent schedule", err)
	}
	stateAfter, err := recordedCaseDirectory(parent.Schedule.Entries[0])
	if err != nil || stateAfter != stateBefore {
		t.Fatal("retained named state moved to another case directory", err)
	}
}

// full_only: false
func TestCaseReceiptIsImmutableAndBindsExactCatalogEntry(t *testing.T) {
	s, result := caseReceiptFixture(t, "live", "gcp", 0)
	ref := writeControlledCaseReceipt(t, s, result)
	if _, err := validateCaseReceipt(s.directory, s.record, ref, result.Entry); err != nil ||
		validateCaseReceiptSet(s.directory, s.record) != nil {
		t.Fatal("exact terminal case receipt refused", err)
	}
	var persisted runRecord
	if records.ReadJSON(filepath.Join(s.directory, "run.json"), &persisted) != nil ||
		validateCaseReceiptSet(s.directory, persisted) != nil {
		t.Fatal("persisted run record lost its terminal receipt")
	}
	path := filepath.Join(s.directory, filepath.FromSlash(ref.Path))
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := result
	changed.Outcome = "failed"
	identity, err := caseIdentitySHA256(s.record)
	if err != nil || s.writeCaseReceipt(changed, identity) == nil {
		t.Fatal("duplicate terminal receipt replaced an immutable leaf")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) || len(s.record.CaseReceipts) != 1 {
		t.Fatal("duplicate changed receipt or reference")
	}
	wrong := ref
	wrong.Sequence++
	if _, err := validateCaseReceipt(s.directory, s.record, wrong, result.Entry); err == nil {
		t.Fatal("changed catalog sequence was accepted")
	}
	parent := s.record
	parent.Scenarios = append([]scenarioResult(nil), parent.Scenarios...)
	parent.Scenarios[0].Members++
	if _, err := validateCaseReceipt(s.directory, parent, ref, result.Entry); err == nil {
		t.Fatal("changed catalog entry was accepted")
	}
	for _, boundary := range []string{"leaf_write", "parent_save"} {
		t.Run(boundary, func(t *testing.T) {
			s, result := caseReceiptFixture(t, "live", "gcp", 0)
			identity, err := caseIdentitySHA256(s.record)
			if err != nil || s.save() != nil {
				t.Fatal("initial receipt parent unavailable", err)
			}
			path := filepath.Join(s.directory, caseReceiptPath(result.Sequence))
			if boundary == "leaf_write" {
				if os.MkdirAll(path, 0700) != nil {
					t.Fatal("leaf obstruction unavailable")
				}
				if s.writeCaseReceipt(result, identity) == nil || len(s.record.CaseReceipts) != 0 {
					t.Fatal("failed leaf publication appended a reference")
				}
				var parent runRecord
				if records.ReadJSON(filepath.Join(s.directory, "run.json"), &parent) != nil || len(parent.CaseReceipts) != 0 {
					t.Fatal("failed leaf publication changed saved references")
				}
			} else {
				if s.writeCaseReceipt(result, identity) != nil || len(s.record.CaseReceipts) != 1 {
					t.Fatal("exclusive leaf publication unavailable")
				}
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				parentPath := filepath.Join(s.directory, "run.json")
				if os.Rename(parentPath, parentPath+".retained") != nil || os.Mkdir(parentPath, 0700) != nil {
					t.Fatal("parent save obstruction unavailable")
				}
				if s.save() == nil || s.writeCaseReceipt(result, identity) == nil {
					t.Fatal("failed parent save completed or replaced its leaf")
				}
				after, err := os.ReadFile(path)
				var parent runRecord
				if err != nil || !bytes.Equal(before, after) || records.ReadJSON(parentPath+".retained", &parent) != nil || len(parent.CaseReceipts) != 0 {
					t.Fatal("parent save failure changed exclusive leaf or prior parent")
				}
			}

		})
	}
}

// full_only: false
func TestCaseReceiptWithTelemetryDefinitionsSurvivesPersistedRead(t *testing.T) {
	s, result := caseReceiptFixture(t, "live", "gcp", 0)
	result.Writer = &workerEvidence{Worker: "writer", Role: "writer", Outcome: "passed", Process: "passed",
		Joined: true, Telemetry: records.Telemetry{Enabled: true, Status: "complete", Definitions: telemetry.Definitions()}}
	if err := json.Unmarshal([]byte(`{"deliveries":{"logs.file":{"accepted":0,"written":0,"dropped":0,"failed":0,"incomplete":false},"metrics.http":{"accepted":17,"written":11,"dropped":2,"failed":3,"incomplete":false},"traces.file":{"accepted":19,"written":16,"dropped":1,"failed":2,"incomplete":true}}}`), result.Writer); err != nil {
		t.Fatal("complete delivery fixture did not decode", err)
	}
	s.record.Scenarios[0] = result
	ref := writeControlledCaseReceipt(t, s, result)
	path := filepath.Join(s.directory, filepath.FromSlash(ref.Path))
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var leaf caseReceipt
	if err := records.ReadJSON(path, &leaf); err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(leaf)
	if err != nil || !bytes.Equal(body, append(canonical, '\n')) || !reflect.DeepEqual(leaf.Result.Writer.Deliveries, result.Writer.Deliveries) {
		t.Fatal("complete delivery claims changed canonical receipt bytes or values", err)
	}
	var persisted runRecord
	if err := records.ReadJSON(filepath.Join(s.directory, "run.json"), &persisted); err != nil {
		t.Fatal(err)
	}
	if _, err := validateCaseReceipt(s.directory, persisted, ref, result.Entry); err != nil ||
		validateCaseReceiptSet(s.directory, persisted) != nil {
		t.Fatal("persisted receipt with telemetry definitions was refused", err)
	}
	if !reflect.DeepEqual(persisted.Scenarios[0].Writer.Deliveries, result.Writer.Deliveries) {
		t.Fatal("persisted run lost complete delivery fields or explicit zero/false")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(body, after) {
		t.Fatal("persisted validation rewrote immutable delivery receipt", err)
	}
}

// full_only: false
func TestCaseReceiptRejectsStaticIdentityDrift(t *testing.T) {
	s, result := caseReceiptFixture(t, "live", "gcp", 0)
	ref := writeControlledCaseReceipt(t, s, result)
	for _, test := range []struct {
		name   string
		change func(*runRecord)
	}{
		{"source", func(r *runRecord) { r.Source.Revision = strings.Repeat("f", 40) }},
		{"dirty_source", func(r *runRecord) {
			digest := strings.Repeat("f", 64)
			r.Source.Dirty, r.Source.DirtyDiffSHA256 = true, &digest
		}},
		{"context", func(r *runRecord) {
			copy := *r.Context
			copy.ConfigurationSHA256 = strings.Repeat("f", 64)
			r.Context = &copy
		}},
		{"native", func(r *runRecord) { r.Native.GOARCH = "different" }},
		{"continuation_root", func(r *runRecord) { r.ContinuationRootRunID = strings.Repeat("f", 32) }},
		{"recovery_run", func(r *runRecord) { r.RecoveryRunID = strings.Repeat("f", 32) }},
		{"cleanup_basis", func(r *runRecord) {
			r.CleanupRecoveryBasis = &cleanupRecoveryBasis{OriginalRunID: strings.Repeat("f", 32),
				OriginalCaseReceiptSHA256: strings.Repeat("e", 64), Entry: result.Entry,
				TargetIndex: 0, Decision: "gcp_exact_generation"}
		}},
		{"resolved_mode", func(r *runRecord) {
			copy := *r.Resolved
			copy.RecoveryMode = "enabled"
			r.Resolved = &copy
		}},
		{"limits", func(r *runRecord) {
			copy := *r.Limits
			copy.Requests++
			r.Limits = &copy
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent := s.record
			test.change(&parent)
			if _, err := validateCaseReceipt(s.directory, parent, ref, result.Entry); err == nil {
				t.Fatal("changed static case identity was accepted")
			}
		})
	}
}

// full_only: false
func TestCaseReceiptSetRejectsMissingDuplicateAndOrphanLeaves(t *testing.T) {
	s, result := caseReceiptFixture(t, "live", "gcp", 0)
	if validateCaseReceiptSet(s.directory, s.record) == nil {
		t.Fatal("completed case without a receipt was accepted")
	}
	ref := writeControlledCaseReceipt(t, s, result)
	if validateCaseReceiptSet(s.directory, s.record) != nil {
		t.Fatal("complete controlled receipt set refused")
	}
	missing := s.record
	missing.CaseReceipts = nil
	if _, err := validateCaseReceipt(s.directory, missing, ref, result.Entry); err == nil {
		t.Fatal("unlinked leaf was accepted as a parent case receipt")
	}
	missing.Scenarios = nil // Crash after leaf publish, before run.json linked it.
	if validateCaseReceiptSet(s.directory, missing) == nil {
		t.Fatal("orphan receipt permitted silent Product replay")
	}
	duplicate := s.record
	duplicate.CaseReceipts = []caseReceiptRef{ref, ref}
	if validateCaseReceiptSet(s.directory, duplicate) == nil {
		t.Fatal("duplicate receipt reference was accepted")
	}
	incomplete := s.record
	incomplete.Scenarios = append([]scenarioResult(nil), incomplete.Scenarios...)
	incomplete.Scenarios[0].Outcome = "incomplete"
	if validateCaseReceiptSet(s.directory, incomplete) == nil {
		t.Fatal("pending case was accepted as terminal")
	}
}

// full_only: false
func TestCaseReceiptSetAcceptsOrderedMissingCaseSubset(t *testing.T) {
	s, result := caseReceiptFixture(t, "live", "gcp", 1)
	ref := writeControlledCaseReceipt(t, s, result)
	if ref.Sequence != 1 || validateCaseReceiptSet(s.directory, s.record) != nil {
		t.Fatal("original sequence of a newly executed missing case was lost")
	}
}

// full_only: false
func TestCaseReceiptSetRejectsReorderedReferences(t *testing.T) {
	s, first := caseReceiptFixture(t, "live", "gcp", 0)
	entry := s.record.Schedule.Entries[1]
	shape, err := recordedFixture(entry.Scenario, entry.Members)
	if err != nil {
		t.Fatal(err)
	}
	second := first
	second.Entry, second.Fixture = entry, shape
	s.record.Scenarios = []scenarioResult{first, second}
	identity, err := caseIdentitySHA256(s.record)
	if err != nil || s.writeCaseReceipt(first, identity) != nil || s.writeCaseReceipt(second, identity) != nil {
		t.Fatal("controlled pair unavailable", err)
	}
	if validateCaseReceiptSet(s.directory, s.record) != nil {
		t.Fatal("ordered pair refused")
	}
	changed := s.record
	changed.CaseReceipts = append([]caseReceiptRef(nil), changed.CaseReceipts...)
	changed.CaseReceipts[0], changed.CaseReceipts[1] = changed.CaseReceipts[1], changed.CaseReceipts[0]
	if validateCaseReceiptSet(s.directory, changed) == nil {
		t.Fatal("reordered terminal references were accepted")
	}
}

// full_only: false
func TestCaseReceiptRejectsRehashedNoncanonicalOrSymlinkedLeaf(t *testing.T) {
	s, result := caseReceiptFixture(t, "live", "gcp", 0)
	ref := writeControlledCaseReceipt(t, s, result)
	path := filepath.Join(s.directory, filepath.FromSlash(ref.Path))
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	altered := append(append([]byte(nil), original[:len(original)-1]...), ' ', '\n')
	if os.WriteFile(path, altered, 0600) != nil {
		t.Fatal("controlled byte change unavailable")
	}
	changed := s.record
	changed.CaseReceipts = append([]caseReceiptRef(nil), changed.CaseReceipts...)
	changed.CaseReceipts[0].SHA256 = digestBytes(altered)
	if _, err := validateCaseReceipt(s.directory, changed, changed.CaseReceipts[0], result.Entry); err == nil {
		t.Fatal("rehashed noncanonical receipt bytes were accepted")
	}
	outside := filepath.Join(t.TempDir(), "leaf.json")
	if os.WriteFile(outside, original, 0600) != nil || os.Remove(path) != nil || os.Symlink(outside, path) != nil {
		t.Fatal("controlled symlink unavailable")
	}
	if _, err := validateCaseReceipt(s.directory, s.record, ref, result.Entry); err == nil {
		t.Fatal("symlinked receipt was accepted")
	}
}

// full_only: false
func TestReconstructionReceiptRequiresDeclaredNonemptyCells(t *testing.T) {
	const scenario = "reconstruction.zero-secret-genesis/complete_loss_zero_secret_genesis"
	for _, recovery := range []string{"disabled", "enabled", "unsupported"} {
		t.Run(recovery, func(t *testing.T) {
			s, result := caseReceiptFixture(t, "hermetic", "memory", 0)
			// Start from a declared selection. The refused controls represent a
			// retained passed claim with no process proof for its requested mode.
			schedule, err := catalog.Resolve(catalog.Request{Include: []string{scenario}, RecoveryMode: "disabled", Repetitions: 1})
			if err != nil {
				t.Fatal("declared reconstruction schedule unavailable", err)
			}
			found := false
			for _, entry := range schedule.Entries {
				if entry.Scenario == scenario {
					result.Entry, found = entry, true
					break
				}
			}
			if !found {
				t.Fatal("declared reconstruction entry unavailable")
			}
			result.Fixture, err = catalog.FixtureShape(scenario)
			if err != nil {
				t.Fatal("declared reconstruction fixture unavailable", err)
			}
			schedule.RecoveryMode = recovery
			s.record.Schedule, s.record.Resolved.Schedule = schedule, schedule
			s.record.Resolved.RecoveryMode = recovery
			result.Cleanup = noCleanup()
			setRecoveryAssemblyFixture(&s.record)
			setScenarioReconstructionFixture(&result, s.record)
			if recovery == "disabled" && len(result.Reconstruction) != 1 || recovery != "disabled" && len(result.Reconstruction) != 0 {
				t.Fatal("control must contain exactly the declared proof or no proof")
			}
			s.record.Scenarios = []scenarioResult{result}
			ref := writeControlledCaseReceipt(t, s, result)
			path := filepath.Join(s.directory, filepath.FromSlash(ref.Path))
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			_, err = validateCaseReceipt(s.directory, s.record, ref, result.Entry)
			if (err == nil) != (recovery == "disabled") {
				t.Error("passed reconstruction receipt accepted an unsupported or unknown empty cell selection", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("receipt validation changed retained proof bytes", err)
			}
		})
	}
}

// full_only: false
func TestHistoricalReconstructionReceiptRequiresProcessProof(t *testing.T) {
	for _, damage := range []string{"none", "missing-proof", "unjoined-child", "changed-source"} {
		t.Run(damage, func(t *testing.T) {
			s, result := caseReceiptFixture(t, "hermetic", "memory", 0)
			result.Cleanup = noCleanup()
			result.Entry.Scenario = "reconstruction.zero-secret-genesis/complete_loss_zero_secret_genesis"
			setRecoveryAssemblyFixture(&s.record)
			setScenarioReconstructionFixture(&result, s.record)
			if len(result.Reconstruction) == 0 {
				t.Fatal("complete reconstruction fixture unavailable")
			}
			// The fixed process facts are unchanged. Retained evidence keeps the old
			// schedule, entry and fixture rather than adopting the current identity.
			schedule, err := catalog.HistoricalResolve(catalog.HistoricalRequest{
				Include: []string{"reconstruction.zero-secret-genesis"}, Repetitions: 1, RecoveryMode: "disabled",
			})
			if err != nil {
				t.Fatal("historical reconstruction selection unavailable", err)
			}
			found := false
			for _, entry := range schedule.Entries {
				if entry.Scenario == "reconstruction.zero-secret-genesis" {
					result.Entry, found = entry, true
					break
				}
			}
			if !found {
				t.Fatal("historical reconstruction entry unavailable")
			}
			result.Fixture, err = catalog.HistoricalFixtureShape(result.Scenario, result.Members)
			if err != nil {
				t.Fatal("historical reconstruction fixture unavailable", err)
			}
			s.record.Schedule, s.record.Resolved.Schedule = schedule, schedule
			switch damage {
			case "missing-proof":
				result.Reconstruction = nil
			case "unjoined-child":
				result.Reconstruction[0].Phases[len(result.Reconstruction[0].Phases)-1].Joined = false
			case "changed-source":
				result.Reconstruction[0].Source.Revision = strings.Repeat("f", 40)
			}
			s.record.Scenarios = []scenarioResult{result}
			ref := writeControlledCaseReceipt(t, s, result)
			path := filepath.Join(s.directory, filepath.FromSlash(ref.Path))
			before, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			_, err = validateCaseReceipt(s.directory, s.record, ref, result.Entry)
			if (err == nil) != (damage == "none") {
				t.Fatal("historical reconstruction proof qualification changed", err)
			}
			after, readErr := os.ReadFile(path)
			if readErr != nil || !bytes.Equal(before, after) {
				t.Fatal("validation changed historical receipt", readErr)
			}
		})
	}
}

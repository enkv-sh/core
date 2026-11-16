package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

func grantedRecoveryFixture(t *testing.T) (string, runRecord, caseReceiptRef, cleanupRequest, string, string) {
	return grantedRecoveryFixtureAt(t, 0, false)
}

func grantedRecoveryFixtureAt(t *testing.T, sequence int, overdraw bool) (string, runRecord, caseReceiptRef, cleanupRequest, string, string) {
	t.Helper()
	root, request, entries := recoveryFixture(t, 1)
	request.race = true
	entry := entries[0]
	if sequence > 0 {
		name := filepath.Base(entry.State)[5:]
		moved := filepath.Join(filepath.Dir(entry.State), fmt.Sprintf("%04d-%s", sequence, name))
		if os.Rename(entry.State, moved) != nil {
			t.Fatal("controlled case state unavailable")
		}
		entry.State, entry.InputPath = moved, filepath.Join(moved, "input.json")
		entry.Input.Prefix = fmt.Sprintf("enkv-test/%s/%04d", request.RunID, sequence)
		if records.WriteJSON(entry.InputPath, entry.Input, 0400) != nil {
			t.Fatal("controlled case input unavailable")
		}
	}
	schedule := catalog.Schedule{RecoveryMode: "disabled", Selected: []string{entry.Input.Scenarios[0]}, Repetitions: sequence + 2}
	for index := 0; index < sequence+2; index++ {
		schedule.Entries = append(schedule.Entries, catalog.Entry{Scenario: entry.Input.Scenarios[0],
			Members: entry.Input.MemberCount, Sequence: index, Repetition: index + 1})
	}
	s, err := newRunState(root, runRequest{Suite: "live", Provider: "gcp", Target: "gcp", Profile: "full", Schedule: schedule},
		records.Source{Revision: strings.Repeat("a", 40)}, "controlled-toolchain")
	if err != nil {
		t.Fatal(err)
	}
	s.directory = filepath.Dir(filepath.Dir(entry.State))
	s.record.RunID = request.RunID
	rootID := strings.Repeat("e", 32)
	s.record.ContinuationRootRunID = rootID
	s.record.CoverageScope = "live_scenarios"
	s.record.Outcome = "failed"
	s.record.Failure = &records.Failure{Class: "cleanup_unresolved", Stage: "cleanup"}
	s.record.Context = safeRunContext(entry.Input.Settings)
	allowance := testLimits()
	s.record.Limits = &allowance
	s.record.BuildClosure = &assemblyClosure{Suite: "live", Provider: "gcp", Race: true,
		RaceOptions: raceOptions, RaceExitSleepMillis: 1000,
		BinarySHA256: strings.Repeat("b", 64), OverlaySHA256: strings.Repeat("c", 64)}
	roles := map[string]string{}
	definition, known := recordedDefinition(entry.Input.Scenarios[0])
	if !known {
		t.Fatal("controlled scenario unavailable")
	}
	for index, role := range definition.RolesForRecovery("disabled") {
		actor := "actor_" + string(rune('a'+index))
		if role == "authority" {
			actor = "operator"
		}
		roles[role] = actor
	}
	s.record.Resolved = &resolvedRequest{Profile: "full", Race: true, Mode: "live", Provider: "gcp",
		RecoveryMode: "disabled", Resource: "gcp", Schedule: schedule, RoleBindings: roles}
	selected := schedule.Entries[sequence]
	shape, err := recordedFixture(selected.Scenario, selected.Members)
	if err != nil {
		t.Fatal(err)
	}
	index, one := uint32(0), int64(1)
	fact := records.HarnessFailure{Operation: "object_cleanup", Stage: "conditional_delete", Cause: "transport",
		Effect: "unknown", TargetKind: "inventory", TargetIndex: &index, Attempt: 1}
	cleanupFailure := &records.Failure{Class: "cleanup_run_failed", Stage: "cleanup"}
	budget := &records.BudgetReservation{Requests: 1}
	if overdraw {
		budget.Requests = allowance.Requests + 1
	}
	cleanup := records.Cleanup{Outcome: "unresolved", RemainingOwnedObjects: &one, UnknownEffects: &one,
		Failure: cleanupFailure, HarnessFailure: &fact, BudgetReserved: budget}
	execution, known := recordedExecution(selected.Scenario, "live")
	if !known {
		t.Fatal("controlled execution unavailable")
	}
	passedWorker := func(name, role string) workerEvidence {
		return workerEvidence{Worker: name, Role: role, Outcome: "passed", Process: "passed", Started: true, Joined: true}
	}
	writer := passedWorker("writer", "writer")
	result := scenarioResult{Entry: selected, Fixture: shape, Outcome: "failed", CorrectnessPassed: true,
		Writer: &writer, BudgetReserved: budget, Cleanup: cleanup,
		CleanupWorker: &workerEvidence{Worker: "cleanup", Role: "cleanup", Outcome: "failed", Process: "process_failed",
			Joined: true, HarnessFailure: &fact, Failure: cleanupFailure}}
	for index := range execution.ExpandedFreshBefore() {
		result.Children = append(result.Children, passedWorker("child_"+string(rune('a'+index)), "fresh_before"))
	}
	for index := range execution.ExpandedFreshAfter() {
		result.PostExit = append(result.PostExit, passedWorker("fresh_"+string(rune('a'+index)), "fresh_after"))
	}
	s.record.Scenarios = []scenarioResult{result}
	finished := time.Now().UTC()
	s.record.FinishedAt = &finished
	identity, err := caseIdentitySHA256(s.record)
	if err != nil || s.writeCaseReceipt(result, identity) != nil || records.WriteJSON(filepath.Join(s.directory, "run.json"), s.record, 0600) != nil {
		t.Fatal("controlled original receipt unavailable", err)
	}
	image := completeGrantInventoryFixture(request.RunID, entry.Input.Prefix, &fact, "gcp")
	inventoryPath := filepath.Join(entry.State, "inventory.json")
	if records.WriteJSON(inventoryPath, image, 0600) != nil {
		t.Fatal("controlled private attempt unavailable")
	}
	return root, s.record, s.record.CaseReceipts[0], request, rootID, inventoryPath
}

// full_only: false
func TestGrantedRecoveryBindsOriginalCaseAndPrivateAttempt(t *testing.T) {
	root, original, ref, request, rootID, inventoryPath := grantedRecoveryFixture(t)
	plan, basis, ordinal, err := prepareGrantedRecovery(root, original, ref, request, rootID)
	if err != nil || len(plan.Entries) != 1 || ordinal != 2 || basis.OriginalRunID != original.RunID ||
		basis.OriginalCaseReceiptSHA256 != ref.SHA256 || basis.Entry != original.Scenarios[0].Entry ||
		basis.Decision != "gcp_exact_generation_grant" || plan.OriginalBuild == nil {
		t.Fatal("exact original failed case was not admitted", err)
	}
	if _, err := os.Stat(inventoryPath); err != nil {
		t.Fatal("read-only preparation changed private inventory")
	}
	wrong := ref
	wrong.SHA256 = strings.Repeat("f", 64)
	if _, _, _, err := prepareGrantedRecovery(root, original, wrong, request, rootID); err == nil {
		t.Fatal("different case receipt obtained a grant")
	}
	if _, _, _, err := prepareGrantedRecovery(root, original, ref, request, strings.Repeat("f", 32)); err == nil {
		t.Fatal("different continuation root obtained a grant")
	}
}

// full_only: false
func TestGrantedRecoveryAdmitsSealedLaterCaseOnlyRun(t *testing.T) {
	root, original, ref, request, rootID, _ := grantedRecoveryFixtureAt(t, 2, false)
	plan, basis, ordinal, err := prepareGrantedRecovery(root, original, ref, request, rootID)
	if err != nil || len(original.Scenarios) != 1 || original.Scenarios[0].Sequence != 2 ||
		len(plan.Entries) != 1 || basis.Entry.Sequence != 2 || ordinal != 2 {
		t.Fatal("eligible later case-only cleanup was refused or reindexed", err)
	}
	root, original, ref, request, rootID, _ = grantedRecoveryFixtureAt(t, 2, true)
	if _, _, _, err := prepareGrantedRecovery(root, original, ref, request, rootID); err == nil {
		t.Fatal("case-only run exceeded its saved remaining Product allowance")
	}
}

// full_only: false
func TestGrantedRecoveryRefusesUnsettledOrChangedPrivateLineage(t *testing.T) {
	for _, mode := range []string{"unknown_create", "changed_ordinal", "missing_failure", "prior_grant", "changed_run"} {
		t.Run(mode, func(t *testing.T) {
			root, original, ref, request, rootID, path := grantedRecoveryFixture(t)
			var image grantInventory
			if records.ReadJSON(path, &image) != nil {
				t.Fatal("controlled inventory unavailable")
			}
			switch mode {
			case "unknown_create":
				image.Intents[0].State = "unknown"
			case "changed_ordinal":
				image.CleanupAttempts[0].Ordinal = 2
			case "missing_failure":
				image.CleanupAttempts[0].Failure = nil
			case "prior_grant":
				image.CleanupAttempts[0].Recovery = "gcp_exact_generation_grant"
			case "changed_run":
				image.RunID = strings.Repeat("f", 32)
			}
			if records.WriteJSON(path, image, 0600) != nil {
				t.Fatal("controlled inventory change unavailable")
			}
			if _, _, _, err := prepareGrantedRecovery(root, original, ref, request, rootID); err == nil {
				t.Fatal("changed private lineage obtained a cleanup grant")
			}
		})
	}
}

func awsGrantedRecoveryFixture(t *testing.T) (string, runRecord, caseReceiptRef, cleanupRequest, string) {
	t.Helper()
	root, original, _, request, _, inventoryPath := grantedRecoveryFixture(t)
	config, raw := configurationFixture(t, "aws")
	settings, err := validateSettings(raw, "aws", filepath.Dir(config))
	if err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(filepath.Dir(inventoryPath), "input.json")
	var input workerInput
	if records.ReadJSON(inputPath, &input) != nil {
		t.Fatal("input unavailable")
	}
	input.Settings = settings
	input.Prefix = "enkv-test/" + request.RunID + "/" + filepath.Base(filepath.Dir(inputPath))
	if records.WriteJSON(inputPath, input, 0400) != nil {
		t.Fatal("input unavailable")
	}
	original.Provider, original.Target = "aws", "aws"
	original.Resolved.Provider, original.Resolved.Resource = "aws", "aws"
	original.BuildClosure.Provider = "aws"
	original.Context = safeRunContext(settings)
	original.ContinuationRootRunID = ""
	finished := original.StartedAt.Add(time.Second)
	original.FinishedAt = &finished
	var image grantInventory
	if records.ReadJSON(inventoryPath, &image) != nil {
		t.Fatal("inventory unavailable")
	}
	image.Prefix = input.Prefix
	awsToken := contract.Token{Family: contract.AWS, Value: `"fixture-etag"`}
	image.Intents[0].ConditionToken = &awsToken
	image.CleanupAttempts[0].Token = awsToken
	if records.WriteJSON(inventoryPath, image, 0600) != nil {
		t.Fatal("inventory unavailable")
	}
	directory := filepath.Dir(filepath.Dir(filepath.Dir(inventoryPath)))
	s := &runState{directory: directory, record: original}
	if os.Remove(filepath.Join(directory, original.CaseReceipts[0].Path)) != nil {
		t.Fatal("receipt unavailable")
	}
	s.record.CaseReceipts = nil
	identity, err := caseIdentitySHA256(s.record)
	if err != nil || s.writeCaseReceipt(s.record.Scenarios[0], identity) != nil || records.WriteJSON(filepath.Join(s.directory, "run.json"), s.record, 0600) != nil {
		t.Fatal("AWS receipt unavailable", err)
	}
	return root, s.record, s.record.CaseReceipts[0], request, inventoryPath
}

// full_only: false
func TestAWSExplicitCleanupAdmitsOldSourceWithoutProductContinuation(t *testing.T) {
	t.Run("scheduled-publication", testGrantedPublicationCleanup)
	root, original, ref, request, path := awsGrantedRecoveryFixture(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	plan, basis, ordinal, err := prepareGrantedRecovery(root, original, ref, request, "")
	if err != nil || plan.Provider != "aws" || plan.OriginalBuild != nil || ordinal != 2 ||
		len(plan.Entries) != 1 || basis.Decision != "aws_retired_fixture_grant" || basis.OriginalCaseReceiptSHA256 != ref.SHA256 {
		t.Fatal("old AWS evidence did not admit standalone cleanup-only grant", err)
	}
	ordinary, err := prepareRecovery(root, request)
	if err != nil {
		t.Fatal(err)
	}
	routed, routedBasis, err := prepareFixtureRecovery(root, request, ordinary)
	if err != nil || routedBasis == nil || *routedBasis != basis || routed.Grant == nil || routed.Grant.Ordinal != ordinal {
		t.Fatal("maintained cleanup routing lost the uncertain DELETE grant", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("planning changed old inventory")
	}
	if _, _, _, err := prepareGrantedRecovery(root, original, ref, request, strings.Repeat("e", 32)); err == nil {
		t.Fatal("AWS obtained a Product continuation grant")
	}
}

// full_only: false
func TestAWSFixtureCleanupClaimIsExclusiveAndBindsBothSources(t *testing.T) {
	root, original, ref, request, path := awsGrantedRecoveryFixture(t)
	plan, basis, ordinal, err := prepareGrantedRecovery(root, original, ref, request, "")
	if err != nil {
		t.Fatal(err)
	}
	current := records.Source{Revision: strings.Repeat("b", 40)}
	record := runRecord{RunID: strings.Repeat("f", 32), RecoveryRunID: original.RunID, Source: current, Limits: &plan.Limits, CleanupRecoveryBasis: &basis}
	plan.Grant.TargetIndex, plan.Grant.Ordinal, plan.Grant.OriginalCaseReceiptSHA256 = basis.TargetIndex, ordinal, ref.SHA256
	limitsBody, err := json.Marshal(plan.Limits)
	if err != nil {
		t.Fatal(err)
	}
	plan.Grant.GrantRunID, plan.Grant.GrantLimitsSHA256 = record.RunID, digestBytes(limitsBody)
	lock, err := os.OpenFile(filepath.Join(filepath.Dir(path), "inventory.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil || syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		t.Fatal("lease unavailable", err)
	}
	if claimFixtureCleanup(plan, record) == nil {
		t.Fatal("claim bypassed active inventory lease")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := claimFixtureCleanup(plan, record); err != nil {
		t.Fatal("claim refused", err)
	}
	claimPath := filepath.Join(filepath.Dir(filepath.Dir(path)), "aws-cleanup-grant.json")
	var claim struct {
		Basis  cleanupRecoveryBasis `json:"basis"`
		Source records.Source       `json:"source"`
		Grant  cleanupGrantInput    `json:"grant"`
	}
	if records.ReadJSON(claimPath, &claim) != nil || !reflect.DeepEqual(claim.Source, current) || claim.Grant != *plan.Grant || claim.Basis.OriginalRunSHA256 == "" {
		t.Fatal("claim did not bind both evidence identities")
	}
	if claimFixtureCleanup(plan, record) == nil {
		t.Fatal("claim overwritten")
	}
	if _, _, _, err := prepareGrantedRecovery(root, original, ref, request, ""); err == nil {
		t.Fatal("issued grant planned again")
	}
	var output bytes.Buffer
	if err := runCommand(context.Background(), root, "must-not-build", []string{"cleanup", request.RunID, "--limits", request.Limits}, &output); err == nil {
		t.Fatal("maintained cleanup command reused grant", err)
	}
	assertCleanupRefusalHasOnlySourceObservation(t, output.String())
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("claim altered old inventory")
	}
}

// full_only: false
func TestAWSFixtureCleanupClaimRefusesChangedSnapshots(t *testing.T) {
	for _, which := range []string{"unchanged", "inventory", "original_run", "symlink_claim"} {
		t.Run(which, func(t *testing.T) {
			root, original, ref, request, path := awsGrantedRecoveryFixture(t)
			plan, basis, ordinal, err := prepareGrantedRecovery(root, original, ref, request, "")
			if err != nil {
				t.Fatal(err)
			}
			limitsBody, err := json.Marshal(plan.Limits)
			if err != nil {
				t.Fatal(err)
			}
			plan.Grant.TargetIndex, plan.Grant.Ordinal, plan.Grant.OriginalCaseReceiptSHA256 = basis.TargetIndex, ordinal, ref.SHA256
			plan.Grant.GrantRunID, plan.Grant.GrantLimitsSHA256 = strings.Repeat("f", 32), digestBytes(limitsBody)
			record := runRecord{RunID: plan.Grant.GrantRunID, RecoveryRunID: original.RunID, Source: records.Source{Revision: strings.Repeat("b", 40)}, Limits: &plan.Limits, CleanupRecoveryBasis: &basis}
			switch which {
			case "inventory":
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if os.WriteFile(path, append(body, ' '), 0600) != nil {
					t.Fatal("mutation unavailable")
				}
			case "original_run":
				runPath := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(path))), "run.json")
				body, err := os.ReadFile(runPath)
				if err != nil {
					t.Fatal(err)
				}
				if os.WriteFile(runPath, append(body, ' '), 0600) != nil {
					t.Fatal("mutation unavailable")
				}
			case "symlink_claim":
				if os.Symlink(path, filepath.Join(filepath.Dir(filepath.Dir(path)), "aws-cleanup-grant.json")) != nil {
					t.Fatal("mutation unavailable")
				}
			}
			if err := claimFixtureCleanup(plan, record); (err == nil) != (which == "unchanged") {
				t.Fatal("snapshot claim control differs", which, err)
			}
		})
	}
}

// full_only: false
func TestAWSFixtureCleanupAdmissionRefusesChangedEvidence(t *testing.T) {
	for _, which := range []string{"unjoined_writer", "unjoined_cleanup", "missing_child", "unjoined_child", "source", "receipt", "unknown_create", "changed_attempt", "permanent_failure", "prefix", "authority", "resource", "budget"} {
		t.Run(which, func(t *testing.T) {
			root, original, ref, request, path := awsGrantedRecoveryFixture(t)
			switch which {
			case "unjoined_writer":
				original.Scenarios[0].Writer.Joined = false
			case "unjoined_cleanup":
				original.Scenarios[0].CleanupWorker.Joined = false
			case "missing_child":
				original.Scenarios[0].PostExit = nil
			case "unjoined_child":
				original.Scenarios[0].PostExit[0].Joined = false
			case "source":
				original.Source.Revision = strings.Repeat("b", 40)
			case "receipt":
				ref.SHA256 = strings.Repeat("c", 64)
			case "unknown_create", "changed_attempt", "permanent_failure":
				var image grantInventory
				if records.ReadJSON(path, &image) != nil {
					t.Fatal("inventory unavailable")
				}
				if which == "unknown_create" {
					image.Intents[0].State = "unknown"
				}
				if which == "changed_attempt" {
					image.CleanupAttempts[0].Ordinal = 2
				}
				if which == "permanent_failure" {
					image.CleanupAttempts[0].Failure.Cause = "access_refused"
				}
				if records.WriteJSON(path, image, 0600) != nil {
					t.Fatal("mutation unavailable")
				}
			case "prefix", "authority", "resource":
				inputPath := filepath.Join(filepath.Dir(path), "input.json")
				var input workerInput
				if records.ReadJSON(inputPath, &input) != nil {
					t.Fatal("input unavailable")
				}
				if which == "prefix" {
					input.Prefix += "-changed"
				}
				if which == "authority" {
					input.Participants["authority"] = "another_actor"
				}
				if which == "resource" {
					input.Settings["bucket"] += "-changed"
				}
				if records.WriteJSON(inputPath, input, 0400) != nil {
					t.Fatal("mutation unavailable")
				}
			case "budget":
				limits := testLimits()
				limits.CleanupRequests = 0
				if records.WriteJSON(request.Limits, limits, 0600) != nil {
					t.Fatal("mutation unavailable")
				}
			}
			if strings.HasPrefix(which, "unjoined_") || which == "missing_child" {
				directory := filepath.Dir(filepath.Dir(filepath.Dir(path)))
				s := &runState{directory: directory, record: original}
				if os.Remove(filepath.Join(directory, s.record.CaseReceipts[0].Path)) != nil {
					t.Fatal("controlled receipt unavailable")
				}
				s.record.CaseReceipts = nil
				identity, err := caseIdentitySHA256(s.record)
				if err != nil || s.writeCaseReceipt(s.record.Scenarios[0], identity) != nil || records.WriteJSON(filepath.Join(s.directory, "run.json"), s.record, 0600) != nil {
					t.Fatal("controlled unjoined receipt unavailable", err)
				}
				original, ref = s.record, s.record.CaseReceipts[0]
			}
			if _, _, _, err := prepareGrantedRecovery(root, original, ref, request, ""); err == nil {
				t.Fatal("changed evidence acquired AWS grant")
			}
		})
	}
}

// full_only: false
func TestAWSFixtureCleanupClaimSurvivesSaveOrBuildFailure(t *testing.T) {
	for _, stage := range []string{"save", "build"} {
		t.Run(stage, func(t *testing.T) {
			root, original, ref, request, path := awsGrantedRecoveryFixture(t)
			plan, basis, ordinal, err := prepareGrantedRecovery(root, original, ref, request, "")
			if err != nil {
				t.Fatal(err)
			}
			s, err := newRunState(root, runRequest{Suite: "live", Provider: "aws", Target: "aws", Schedule: catalog.Schedule{Entries: []catalog.Entry{basis.Entry}, Selected: []string{basis.Entry.Scenario}, Repetitions: 1}}, records.Source{Revision: strings.Repeat("b", 40)}, "current-toolchain")
			if err != nil {
				t.Fatal(err)
			}
			s.record.RecoveryRunID, s.record.CleanupRecoveryBasis = original.RunID, &basis
			s.record.Limits = &plan.Limits
			plan.Grant.TargetIndex, plan.Grant.Ordinal, plan.Grant.OriginalCaseReceiptSHA256 = basis.TargetIndex, ordinal, ref.SHA256
			limitsBody, err := json.Marshal(plan.Limits)
			if err != nil {
				t.Fatal(err)
			}
			plan.Grant.GrantRunID, plan.Grant.GrantLimitsSHA256 = s.record.RunID, digestBytes(limitsBody)
			if err := claimFixtureCleanup(plan, s.record); err != nil {
				t.Fatal(err)
			}
			switch stage {
			case "save":
				if os.Mkdir(filepath.Join(s.directory, "run.json"), 0700) != nil {
					t.Fatal("controlled save failure unavailable")
				}
				if s.save() == nil {
					t.Fatal("controlled save succeeded")
				}
			case "build":
				if os.Mkdir(filepath.Join(s.private, "build"), 0700) != nil {
					t.Fatal("controlled build failure unavailable")
				}
				if executePreparedRecovery(context.Background(), root, "must-not-build", s, plan) == nil {
					t.Fatal("controlled build succeeded")
				}
			}
			if _, _, _, err := prepareGrantedRecovery(root, original, ref, request, ""); err == nil {
				t.Fatal("failed recovery obtained a second grant")
			}
			claimPath := filepath.Join(filepath.Dir(filepath.Dir(path)), "aws-cleanup-grant.json")
			if _, err := os.Stat(claimPath); err != nil {
				t.Fatal("failed recovery lost its claim", err)
			}
		})
	}
}

// full_only: false
func TestAWSFixtureCleanupAdmitsPriorJoinedExpectedControl(t *testing.T) {
	root, original, _, request, path := awsGrantedRecoveryFixture(t)
	state := filepath.Dir(path)
	nextState := filepath.Join(filepath.Dir(state), "0001-"+filepath.Base(state)[5:])
	if os.Rename(state, nextState) != nil {
		t.Fatal("later cleanup state unavailable")
	}
	var input workerInput
	if records.ReadJSON(filepath.Join(nextState, "input.json"), &input) != nil {
		t.Fatal("input unavailable")
	}
	input.Prefix = "enkv-test/" + input.RunID + "/" + filepath.Base(nextState)
	if records.WriteJSON(filepath.Join(nextState, "input.json"), input, 0400) != nil {
		t.Fatal("later input unavailable")
	}
	var image grantInventory
	if records.ReadJSON(filepath.Join(nextState, "inventory.json"), &image) != nil {
		t.Fatal("inventory unavailable")
	}
	image.Prefix = input.Prefix
	if records.WriteJSON(filepath.Join(nextState, "inventory.json"), image, 0600) != nil {
		t.Fatal("later inventory unavailable")
	}
	priorState := filepath.Join(filepath.Dir(nextState), "0000-state-transient-before-send-rerun")
	if os.Mkdir(priorState, 0700) != nil {
		t.Fatal("prior state unavailable")
	}
	priorInput := input
	priorInput.Scenarios = []string{"state.transient-before-send-rerun"}
	priorInput.Prefix = "enkv-test/" + input.RunID + "/" + filepath.Base(priorState)
	if records.WriteJSON(filepath.Join(priorState, "input.json"), priorInput, 0400) != nil {
		t.Fatal("prior input unavailable")
	}
	failed := original.Scenarios[0]
	failed.Sequence = 1
	entry := catalog.Entry{Scenario: "state.transient-before-send-rerun", Sequence: 0, Repetition: 1, Members: failed.Members}
	shape, err := recordedFixture(entry.Scenario, entry.Members)
	if err != nil {
		t.Fatal(err)
	}
	zero := int64(0)
	budget := &records.BudgetReservation{Requests: 1}
	prior := scenarioResult{Entry: entry, Fixture: shape, Outcome: "passed", CorrectnessPassed: true, BudgetReserved: budget, Cleanup: records.Cleanup{Outcome: "passed", RemainingOwnedObjects: &zero, UnknownEffects: &zero, BudgetReserved: budget}}
	// Generate unchanged phase facts, then seal the exact historical identity.
	prior.Entry.Scenario = sameDomainRecoveryScenario
	setScenarioWorkerEvidence(&prior, "live", original.Resolved.RoleBindings)
	prior.Entry = entry
	original.Scenarios = []scenarioResult{prior, failed}
	original.Schedule.Entries = []catalog.Entry{entry, failed.Entry}
	original.Schedule.Selected = []string{entry.Scenario, failed.Scenario}
	original.Resolved.Schedule = original.Schedule
	directory := filepath.Dir(filepath.Dir(nextState))
	seal := func() caseReceiptRef {
		for _, ref := range original.CaseReceipts {
			if os.Remove(filepath.Join(directory, ref.Path)) != nil {
				t.Fatal("receipt unavailable")
			}
		}
		s := &runState{directory: directory, record: original}
		s.record.CaseReceipts = nil
		identity, err := caseIdentitySHA256(s.record)
		if err != nil {
			t.Fatal(err)
		}
		for _, result := range s.record.Scenarios {
			if s.writeCaseReceipt(result, identity) != nil {
				t.Fatal("controlled receipt unavailable")
			}
		}
		if records.WriteJSON(filepath.Join(s.directory, "run.json"), s.record, 0600) != nil {
			t.Fatal("controlled run unavailable")
		}
		original = s.record
		return original.CaseReceipts[len(original.CaseReceipts)-1]
	}
	ref := seal()
	if _, _, _, err := prepareGrantedRecovery(root, original, ref, request, ""); err != nil {
		t.Fatal("joined expected control blocked later fixture cleanup", err)
	}
	original.Scenarios[0].Rerun.Joined = false
	ref = seal()
	if _, _, _, err := prepareGrantedRecovery(root, original, ref, request, ""); err == nil {
		t.Fatal("unjoined rerun acquired cleanup grant")
	}
}

// full_only: false
func TestAWSOrdinaryCleanupAfterNoSendFailureKeepsExistingRecovery(t *testing.T) {
	for _, cause := range []string{"authentication_refused", "budget_exhausted", "transport"} {
		t.Run(cause, func(t *testing.T) {
			root, original, _, request, path := awsGrantedRecoveryFixture(t)
			fact := original.Scenarios[0].Cleanup.HarnessFailure
			fact.Stage, fact.Cause, fact.Effect, fact.Attempt = "ownership_read", cause, "no_send", 0
			if cause == "authentication_refused" {
				fact.Stage = "authentication"
			} else if cause == "budget_exhausted" {
				fact.Stage = "admission"
			}
			var image grantInventory
			if records.ReadJSON(filepath.Join(filepath.Dir(path), "inventory.json"), &image) != nil {
				t.Fatal("ordinary inventory unavailable")
			}
			image.CleanupAttempts = nil
			if records.WriteJSON(filepath.Join(filepath.Dir(path), "inventory.json"), image, 0600) != nil {
				t.Fatal("ordinary inventory unavailable")
			}
			zero := int64(0)
			original.Scenarios[0].Cleanup.UnknownEffects = &zero
			original.Scenarios[0].CleanupWorker.HarnessFailure = fact
			directory := filepath.Dir(filepath.Dir(filepath.Dir(path)))
			if records.WriteJSON(filepath.Join(directory, "run.json"), original, 0600) != nil {
				t.Fatal("ordinary original run unavailable")
			}
			ordinary, err := prepareRecovery(root, request)
			if err != nil {
				t.Fatal(err)
			}
			plan, basis, err := prepareFixtureRecovery(root, request, ordinary)
			if err != nil || basis != nil || plan.Grant != nil || len(plan.Entries) != len(ordinary.Entries) {
				t.Fatal("ordinary no-send cleanup incorrectly required explicit grant", err)
			}
		})
	}
}

// This fixture uses the writer's complete wire keys independently of the
// grant reader, so strict schema omissions cannot hide behind its projection.
func completeGrantInventoryFixture(runID, prefix string, fact *records.HarnessFailure, provider string) map[string]any {
	token := contract.Token{Family: contract.GCP, Value: "17"}
	if provider == "aws" {
		token = contract.Token{Family: contract.AWS, Value: `"fixture-etag"`}
	}
	key, digest := prefix+"/object", strings.Repeat("d", 64)
	return map[string]any{
		"version": 1, "run_id": runID, "binding": strings.Repeat("c", 64), "prefix": prefix,
		"domain": contract.Hash([]byte("grant-domain")), "deleted": map[string]int{},
		"intents":          []any{map[string]any{"key": key, "digest": digest, "bytes": uint64(7), "kind": "compare_and_swap", "condition_token": token, "state": "acknowledged"}},
		"cleanup_attempts": []any{map[string]any{"target_intent": 0, "ordinal": 1, "recovery": "", "grant_run_id": "", "case_sha256": "", "limits_sha256": "", "key": key, "digest": digest, "bytes": uint64(7), "token": token, "cutoff": 1, "state": "failed", "failure": fact}},
	}
}

// full_only: false
func TestGrantedRecoveryAcceptsCompleteInventoryWireAndRefusesUnknownFields(t *testing.T) {
	for _, provider := range []string{"gcp", "aws"} {
		t.Run(provider, func(t *testing.T) {
			root, original, ref, request, rootID, path := grantedRecoveryFixture(t)
			if provider == "aws" {
				root, original, ref, request, path = awsGrantedRecoveryFixture(t)
				rootID = ""
			}
			var old grantInventory
			if records.ReadJSON(path, &old) != nil {
				t.Fatal("inventory unavailable")
			}
			image := completeGrantInventoryFixture(original.RunID, old.Prefix, original.Scenarios[0].Cleanup.HarnessFailure, provider)
			if records.WriteJSON(path, image, 0600) != nil {
				t.Fatal("complete inventory unavailable")
			}
			if _, _, _, err := prepareGrantedRecovery(root, original, ref, request, rootID); err != nil {
				t.Fatal("complete retained inventory refused", err)
			}
			for _, damage := range []string{"top_unknown", "intent_unknown", "attempt_unknown", "removed_operator_prefix", "malformed_attempt"} {
				t.Run(damage, func(t *testing.T) {
					body, _ := json.Marshal(image)
					var changed map[string]any
					if json.Unmarshal(body, &changed) != nil {
						t.Fatal("copy unavailable")
					}
					switch damage {
					case "top_unknown":
						changed["unexpected"] = true
					case "intent_unknown":
						changed["intents"].([]any)[0].(map[string]any)["unexpected"] = true
					case "attempt_unknown":
						changed["cleanup_attempts"].([]any)[0].(map[string]any)["unexpected"] = true
					case "removed_operator_prefix":
						changed["operator_prefix"] = map[string]any{"run_id": original.RunID, "prefix": old.Prefix}
					case "malformed_attempt":
						changed["cleanup_attempts"].([]any)[0].(map[string]any)["bytes"] = "invalid"
					}
					if records.WriteJSON(path, changed, 0600) != nil {
						t.Fatal("damage unavailable")
					}
					if _, _, _, err := prepareGrantedRecovery(root, original, ref, request, rootID); err == nil {
						t.Fatal("invalid strict inventory admitted")
					}
				})
			}
		})
	}
}

// full_only: false
func TestAWSFixtureCleanupAdmitsSelectedJoinedExpectedControl(t *testing.T) {
	for _, damage := range []string{"none", "unjoined_rerun", "failed_rerun", "invalid_first_proof"} {
		t.Run(damage, func(t *testing.T) {
			root, original, _, request, path := awsGrantedRecoveryFixture(t)
			oldState := filepath.Dir(path)
			state := filepath.Join(filepath.Dir(oldState), "0000-state-transient-before-send-rerun")
			if os.Rename(oldState, state) != nil {
				t.Fatal("control state unavailable")
			}
			var input workerInput
			if records.ReadJSON(filepath.Join(state, "input.json"), &input) != nil {
				t.Fatal("input unavailable")
			}
			input.Scenarios = []string{"state.transient-before-send-rerun"}
			input.Prefix = "enkv-test/" + input.RunID + "/" + filepath.Base(state)
			if records.WriteJSON(filepath.Join(state, "input.json"), input, 0400) != nil {
				t.Fatal("control input unavailable")
			}
			var image grantInventory
			if records.ReadJSON(filepath.Join(state, "inventory.json"), &image) != nil {
				t.Fatal("inventory unavailable")
			}
			image.Prefix = input.Prefix
			if records.WriteJSON(filepath.Join(state, "inventory.json"), image, 0600) != nil {
				t.Fatal("control inventory unavailable")
			}
			result := &original.Scenarios[0]
			result.Entry.Scenario = "state.transient-before-send-rerun"
			shape, err := recordedFixture(result.Scenario, result.Members)
			if err != nil {
				t.Fatal(err)
			}
			result.Fixture = shape
			cleanupWorker := result.CleanupWorker
			// Generate unchanged phase facts, then seal the exact historical identity.
			oldEntry := result.Entry
			result.Entry.Scenario = sameDomainRecoveryScenario
			setScenarioWorkerEvidence(result, "live", original.Resolved.RoleBindings)
			result.Entry = oldEntry
			result.CleanupWorker = cleanupWorker
			switch damage {
			case "unjoined_rerun":
				result.Rerun.Joined = false
			case "failed_rerun":
				result.Rerun.Outcome, result.Rerun.Process = "failed", "process_failed"
			case "invalid_first_proof":
				result.Writer.StoreFailure.StoreReason = "permanent"
			}
			original.Schedule.Entries[0] = result.Entry
			original.Schedule.Selected = []string{"state.transient-before-send-rerun"}
			original.Resolved.Schedule = original.Schedule
			directory := filepath.Dir(filepath.Dir(state))
			if os.Remove(filepath.Join(directory, original.CaseReceipts[0].Path)) != nil {
				t.Fatal("receipt unavailable")
			}
			s := &runState{directory: directory, record: original}
			s.record.CaseReceipts = nil
			identity, err := caseIdentitySHA256(s.record)
			if err != nil || s.writeCaseReceipt(*result, identity) != nil || records.WriteJSON(filepath.Join(s.directory, "run.json"), s.record, 0600) != nil {
				t.Fatal("control receipt unavailable", err)
			}
			_, _, _, err = prepareGrantedRecovery(root, s.record, s.record.CaseReceipts[0], request, "")
			if (err == nil) != (damage == "none") {
				t.Fatal("selected control cleanup admission differs", err)
			}
		})
	}
}

func admissionNoSendRecoveryFixture(t *testing.T, provider string) (string, runRecord, caseReceiptRef, cleanupRequest, string) {
	t.Helper()
	var root, path string
	var original runRecord
	var request cleanupRequest
	if provider == "aws" {
		root, original, _, request, path = awsGrantedRecoveryFixture(t)
	} else {
		root, original, _, request, _, path = grantedRecoveryFixture(t)
	}
	// This fixture requests a standalone cleanup grant for either provider.
	original.ContinuationRootRunID = ""
	inputPath := filepath.Join(filepath.Dir(path), "input.json")
	var input workerInput
	if records.ReadJSON(inputPath, &input) != nil {
		t.Fatal("input unavailable")
	}
	input.Prefix = "enkv-test/" + original.RunID + "/" + filepath.Base(filepath.Dir(path))
	if records.WriteJSON(inputPath, input, 0400) != nil {
		t.Fatal("input unavailable")
	}
	finished := original.StartedAt.Add(time.Second)
	original.FinishedAt = &finished
	fact := original.Scenarios[0].Cleanup.HarnessFailure
	fact.Stage, fact.Cause, fact.Effect, fact.Attempt = "admission", "invalid_request", "no_send", 0
	zero := int64(0)
	original.Scenarios[0].Cleanup.UnknownEffects = &zero
	original.Scenarios[0].CleanupWorker.HarnessFailure = fact
	var image grantInventory
	if records.ReadJSON(path, &image) != nil {
		t.Fatal("inventory unavailable")
	}
	image.Prefix = input.Prefix
	image.Intents[0].Key = input.Prefix + "/object"
	image.CleanupAttempts[0].Key = image.Intents[0].Key
	image.CleanupAttempts[0].Failure = fact
	image.CleanupAttempts[0].Cutoff = 0
	if records.WriteJSON(path, image, 0600) != nil {
		t.Fatal("inventory unavailable")
	}
	directory := filepath.Dir(filepath.Dir(filepath.Dir(path)))
	s := &runState{directory: directory, record: original}
	if os.Remove(filepath.Join(directory, original.CaseReceipts[0].Path)) != nil {
		t.Fatal("receipt unavailable")
	}
	s.record.CaseReceipts = nil
	identity, err := caseIdentitySHA256(s.record)
	if err != nil || s.writeCaseReceipt(s.record.Scenarios[0], identity) != nil || records.WriteJSON(filepath.Join(s.directory, "run.json"), s.record, 0600) != nil {
		t.Fatal("receipt unavailable", err)
	}
	return root, s.record, s.record.CaseReceipts[0], request, path
}

// full_only: false
func TestAdmissionNoSendCleanupGrantBindsOldEvidenceAndNewSource(t *testing.T) {
	for _, provider := range []string{"gcp", "aws"} {
		t.Run(provider, func(t *testing.T) {
			root, original, ref, request, path := admissionNoSendRecoveryFixture(t, provider)
			before, _ := os.ReadFile(path)
			plan, basis, ordinal, err := prepareGrantedRecovery(root, original, ref, request, "")
			if err != nil || ordinal != 2 || plan.OriginalBuild != nil || plan.Grant == nil || plan.Grant.InventorySHA256 == "" || basis.OriginalRunSHA256 == "" || basis.Decision != "admission_no_send_grant" {
				t.Fatal("typed no-send failure did not admit one cleanup-only grant", err)
			}
			ordinary, err := prepareRecovery(root, request)
			if err != nil {
				t.Fatal(err)
			}
			routed, routedBasis, err := prepareFixtureRecovery(root, request, ordinary)
			if err != nil || routedBasis == nil || *routedBasis != basis || routed.Grant == nil || routed.Grant.Ordinal != 2 || routed.Grant.TargetIndex != 0 {
				t.Fatal("maintained cleanup command did not route the exact no-send grant", err)
			}
			plan.Grant.TargetIndex, plan.Grant.Ordinal, plan.Grant.OriginalCaseReceiptSHA256 = basis.TargetIndex, ordinal, ref.SHA256
			limitsBody, err := json.Marshal(plan.Limits)
			if err != nil {
				t.Fatal(err)
			}
			plan.Grant.GrantRunID, plan.Grant.GrantLimitsSHA256 = strings.Repeat("f", 32), digestBytes(limitsBody)
			current := records.Source{Revision: strings.Repeat("b", 40)}
			if claimFixtureCleanup(plan, runRecord{RunID: plan.Grant.GrantRunID, RecoveryRunID: original.RunID, Source: current, Limits: &plan.Limits, CleanupRecoveryBasis: &basis}) != nil {
				t.Fatal("old fixture did not bind the new cleanup source")
			}
			if claimFixtureCleanup(plan, runRecord{RunID: plan.Grant.GrantRunID, RecoveryRunID: original.RunID, Source: current, Limits: &plan.Limits, CleanupRecoveryBasis: &basis}) == nil {
				t.Fatal("exclusive grant claim was used again")
			}
			if _, _, _, err := prepareGrantedRecovery(root, original, ref, request, ""); err == nil {
				t.Fatal("consumed grant was replanned")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("coordinator changed the failed inventory")
			}
			if _, _, _, err := prepareGrantedRecovery(root, original, ref, request, strings.Repeat("e", 32)); err == nil {
				t.Fatal("no-send cleanup granted Product continuation")
			}
		})
	}
}

// full_only: false
func TestAdmissionNoSendCleanupGrantRefusesChangedEvidence(t *testing.T) {
	for _, provider := range []string{"gcp", "aws"} {
		for _, damage := range []string{"unjoined-writer", "unjoined-cleanup", "unknown-effects", "unknown-write", "wrong-cause", "second-ordinal", "changed-target", "changed-body", "changed-token", "receipt", "limits"} {
			t.Run(provider+"/"+damage, func(t *testing.T) {
				root, original, _, request, path := admissionNoSendRecoveryFixture(t, provider)
				var image grantInventory
				if records.ReadJSON(path, &image) != nil {
					t.Fatal("inventory unavailable")
				}
				switch damage {
				case "unjoined-writer":
					original.Scenarios[0].Writer.Joined = false
				case "unjoined-cleanup":
					original.Scenarios[0].CleanupWorker.Joined = false
				case "unknown-effects":
					one := int64(1)
					original.Scenarios[0].Cleanup.UnknownEffects = &one
				case "unknown-write":
					image.Intents[0].State = "unknown"
				case "wrong-cause":
					original.Scenarios[0].Cleanup.HarnessFailure.Cause = "authentication_refused"
					image.CleanupAttempts[0].Failure = original.Scenarios[0].Cleanup.HarnessFailure
				case "second-ordinal":
					image.CleanupAttempts[0].Ordinal = 2
				case "changed-target":
					target := uint32(1)
					original.Scenarios[0].Cleanup.HarnessFailure.TargetIndex = &target
					image.CleanupAttempts[0].Failure = original.Scenarios[0].Cleanup.HarnessFailure
				case "changed-body":
					image.Intents[0].Digest = strings.Repeat("e", 64)
				case "changed-token":
					image.CleanupAttempts[0].Token.Value = "invalid token"
				case "limits":
					if os.WriteFile(request.Limits, []byte(`{"cleanup_requests":0}`), 0600) != nil {
						t.Fatal("limit control unavailable")
					}
				}
				if records.WriteJSON(path, image, 0600) != nil {
					t.Fatal("inventory unavailable")
				}
				directory := filepath.Dir(filepath.Dir(filepath.Dir(path)))
				s := &runState{directory: directory, record: original}
				if os.Remove(filepath.Join(directory, original.CaseReceipts[0].Path)) != nil {
					t.Fatal("receipt unavailable")
				}
				s.record.CaseReceipts = nil
				identity, err := caseIdentitySHA256(s.record)
				if err != nil || s.writeCaseReceipt(s.record.Scenarios[0], identity) != nil || records.WriteJSON(filepath.Join(s.directory, "run.json"), s.record, 0600) != nil {
					t.Fatal("receipt unavailable", err)
				}
				if damage == "receipt" {
					if os.WriteFile(filepath.Join(directory, s.record.CaseReceipts[0].Path), []byte("changed receipt"), 0600) != nil {
						t.Fatal("receipt control unavailable")
					}
				}
				if _, _, _, err := prepareGrantedRecovery(root, s.record, s.record.CaseReceipts[0], request, ""); err == nil {
					t.Fatal("damaged no-send evidence admitted a new action")
				}
			})
		}
	}
}

// full_only: false
func TestAdmissionNoSendCleanupClaimRefusesChangedSnapshots(t *testing.T) {
	for _, provider := range []string{"gcp", "aws"} {
		for _, damage := range []string{"inventory", "original-run", "symlink-claim"} {
			t.Run(provider+"/"+damage, func(t *testing.T) {
				root, original, ref, request, path := admissionNoSendRecoveryFixture(t, provider)
				plan, basis, ordinal, err := prepareGrantedRecovery(root, original, ref, request, "")
				if err != nil {
					t.Fatal(err)
				}
				plan.Grant.TargetIndex, plan.Grant.Ordinal, plan.Grant.OriginalCaseReceiptSHA256 = basis.TargetIndex, ordinal, ref.SHA256
				limitsBody, err := json.Marshal(plan.Limits)
				if err != nil {
					t.Fatal(err)
				}
				plan.Grant.GrantRunID, plan.Grant.GrantLimitsSHA256 = strings.Repeat("f", 32), digestBytes(limitsBody)
				mutate := path
				if damage == "original-run" {
					mutate = filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(path))), "run.json")
				}
				if damage == "symlink-claim" {
					if os.Symlink(path, filepath.Join(filepath.Dir(filepath.Dir(path)), "admission-cleanup-grant.json")) != nil {
						t.Fatal("claim control unavailable")
					}
				} else {
					body, err := os.ReadFile(mutate)
					if err != nil || os.WriteFile(mutate, append(body, ' '), 0600) != nil {
						t.Fatal("snapshot control unavailable", err)
					}
				}
				if claimFixtureCleanup(plan, runRecord{RunID: plan.Grant.GrantRunID, RecoveryRunID: original.RunID, Source: records.Source{Revision: strings.Repeat("b", 40)}, Limits: &plan.Limits, CleanupRecoveryBasis: &basis}) == nil {
					t.Fatal("changed snapshot acquired one-action claim")
				}
			})
		}
	}
}

// full_only: false
func TestAdmissionNoSendCleanupClaimSurvivesSaveOrBuildFailure(t *testing.T) {
	for _, provider := range []string{"gcp", "aws"} {
		for _, failedAt := range []string{"save", "build"} {
			t.Run(provider+"/"+failedAt, func(t *testing.T) {
				root, original, ref, request, _ := admissionNoSendRecoveryFixture(t, provider)
				plan, basis, ordinal, err := prepareGrantedRecovery(root, original, ref, request, "")
				if err != nil {
					t.Fatal(err)
				}
				plan.Grant.TargetIndex, plan.Grant.Ordinal, plan.Grant.OriginalCaseReceiptSHA256 = basis.TargetIndex, ordinal, ref.SHA256
				limitsBody, err := json.Marshal(plan.Limits)
				if err != nil {
					t.Fatal(err)
				}
				plan.Grant.GrantRunID, plan.Grant.GrantLimitsSHA256 = strings.Repeat("f", 32), digestBytes(limitsBody)
				s, err := newRunState(root, runRequest{Suite: "live", Provider: provider, Target: provider, Schedule: recoverySchedule(plan)}, records.Source{Revision: strings.Repeat("b", 40)}, "controlled")
				if err != nil {
					t.Fatal(err)
				}
				s.record.RecoveryRunID, s.record.CleanupRecoveryBasis = original.RunID, &basis
				s.record.Limits = &plan.Limits
				plan.Grant.GrantRunID = s.record.RunID
				if claimFixtureCleanup(plan, s.record) != nil {
					t.Fatal("claim unavailable")
				}
				if failedAt == "save" {
					if os.RemoveAll(s.directory) != nil || os.WriteFile(s.directory, []byte("blocked directory"), 0600) != nil || s.save() == nil {
						t.Fatal("controlled save did not fail")
					}
				} else {
					if os.Mkdir(filepath.Join(s.private, "build"), 0700) != nil || executePreparedRecovery(t.Context(), root, "must-not-build", s, plan) == nil {
						t.Fatal("controlled build did not fail")
					}
				}
				if _, _, _, err := prepareGrantedRecovery(root, original, ref, request, ""); err == nil {
					t.Fatal("failed invocation lost its consumed claim")
				}
			})
		}
	}
}

func testGrantedPublicationCleanup(t *testing.T) {
	for _, damage := range []string{"none", "recorded-count", "prior-count", "unresolved-output", "missing-join", "prior-missing-join"} {
		t.Run(damage, func(t *testing.T) {
			root, original, _, request, inventoryPath := awsGrantedRecoveryFixture(t)
			scenario := "publication.aws-secrets-manager.plain-secret-lifecycle/plain1_secret1_create_value_delete"
			selected, outputBuild, _, _ := publicationParentFixture(t, "aws", scenario)
			private := filepath.Dir(filepath.Dir(inventoryPath))
			directory := filepath.Dir(private)
			build := filepath.Join(private, "build")
			if os.MkdirAll(build, 0700) != nil {
				t.Fatal("publication build fixture")
			}
			original.BuildClosure.OutputArtifacts = outputBuild.OutputArtifacts
			var baseInput workerInput
			if records.ReadJSON(filepath.Join(filepath.Dir(inventoryPath), "input.json"), &baseInput) != nil {
				t.Fatal("original input")
			}
			final := original.Scenarios[0]
			schedule := catalog.Schedule{RecoveryMode: "disabled", Selected: []string{scenario}, Repetitions: 2}
			for i := 0; i < 2; i++ {
				schedule.Entries = append(schedule.Entries, catalog.Entry{Scenario: scenario, Sequence: i, Repetition: i + 1})
			}
			original.Schedule = schedule
			original.Resolved.Schedule = schedule
			original.Scenarios = nil
			var finalState string
			for i, entry := range schedule.Entries {
				name, err := recordedCaseDirectory(entry)
				if err != nil {
					t.Fatal(err)
				}
				state := filepath.Join(private, name)
				if i == 1 {
					if os.Rename(filepath.Dir(inventoryPath), state) != nil {
						t.Fatal("move Store fixture")
					}
					inventoryPath = filepath.Join(state, "inventory.json")
					finalState = state
				} else if os.Mkdir(state, 0700) != nil {
					t.Fatal("prior publication state")
				}
				writerName := fmt.Sprintf("publication-writer-%d", i)
				parent, err := preparePublicationInput(state, request.RunID, writerName, scenario, selected, build, *original.BuildClosure)
				if err != nil {
					t.Fatal("publication fixture", err)
				}
				w, _ := parent.WriterProjection()
				c, _ := parent.CleanerProjection()
				input := baseInput
				input.Prefix = "enkv-test/" + request.RunID + "/" + name
				input.Scenarios = []string{scenario}
				input.MemberCount = 0
				input.Outputs = w
				cleaner := input.authorityOnly()
				cleaner.Outputs = c
				if records.WriteJSON(filepath.Join(state, "input.json"), input, 0400) != nil || records.WriteJSON(filepath.Join(state, "cleanup-input.json"), cleaner, 0400) != nil {
					t.Fatal("publication inputs")
				}
				if records.SetOutputFixtureActors(w.InventoryPath, w.Scope, publicationCapturedActors(w.Profiles[0])) != nil {
					t.Fatal("publication actors")
				}
				create, del := strings.Repeat("c", 64), strings.Repeat("d", 64)
				owned := w.Profiles[0].Targets[0].PlannedSlot + "-Ab123Z"
				if records.BeginOutputFixtureAction(w.InventoryPath, w.Scope, 0, create, contract.PublicationCreateWithValue) != nil || records.RecordOutputFixtureAction(w.InventoryPath, w.Scope, 0, create, "acknowledged", owned) != nil {
					t.Fatal("publication birth")
				}
				if !(damage == "unresolved-output" && i == 1) {
					if records.BeginOutputFixtureAction(w.InventoryPath, w.Scope, 0, del, contract.PublicationDeleteOwned) != nil || records.RecordOutputFixtureAction(w.InventoryPath, w.Scope, 0, del, "acknowledged", "") != nil {
						t.Fatal("publication deletion")
					}
				}
				if !(damage == "missing-join" && i == 1 || damage == "prior-missing-join" && i == 0) {
					if records.WriteOutputFixtureJoined(w.JoinedPath, w.Scope) != nil {
						t.Fatal("publication join")
					}
				}
				digest, err := publicationEvidenceDigest(w, c)
				if err != nil {
					t.Fatal(err)
				}
				shape, err := recordedFixture(scenario, 0)
				if err != nil {
					t.Fatal(err)
				}
				r := final
				r.Entry = entry
				r.Fixture = shape
				r.OutputsSHA256 = digest
				writer := *final.Writer
				writer.Worker = writerName
				r.Writer = &writer
				r.Children = nil
				r.PostExit = nil
				execution, ok := recordedExecution(scenario, "live")
				if !ok {
					t.Fatal("publication execution")
				}
				for j := range execution.ExpandedFreshBefore() {
					r.Children = append(r.Children, workerEvidence{Worker: fmt.Sprintf("before-%d-%d", i, j), Role: "fresh_before", Outcome: "passed", Process: "passed", Started: true, Joined: true})
				}
				for j := range execution.ExpandedFreshAfter() {
					r.PostExit = append(r.PostExit, workerEvidence{Worker: fmt.Sprintf("after-%d-%d", i, j), Role: "fresh_after", Outcome: "passed", Process: "passed", Started: true, Joined: true})
				}
				one, zero, two := int64(1), int64(0), int64(2)
				if i == 0 {
					r.Outcome = "passed"
					r.OutputScheduled = 1
					r.Cleanup = records.Cleanup{Outcome: "passed", RemainingOwnedObjects: &one, UnknownEffects: &zero, BudgetReserved: &records.BudgetReservation{Requests: 1}}
					r.CleanupWorker = &workerEvidence{Worker: "prior-cleanup", Role: "cleanup", Outcome: "passed", Process: "passed", Started: true, Joined: true}
					if damage == "prior-count" {
						r.OutputScheduled = 2
						r.Cleanup.RemainingOwnedObjects = &two
					}
				} else {
					r.Cleanup.RemainingOwnedObjects = &two
					if damage == "recorded-count" {
						r.OutputScheduled = 2
					}
					var image grantInventory
					if records.ReadJSON(inventoryPath, &image) != nil {
						t.Fatal("Store inventory")
					}
					image.Prefix = input.Prefix
					if records.WriteJSON(inventoryPath, image, 0600) != nil {
						t.Fatal("Store inventory prefix")
					}
				}
				original.Scenarios = append(original.Scenarios, r)
			}
			for _, ref := range original.CaseReceipts {
				if os.Remove(filepath.Join(directory, ref.Path)) != nil {
					t.Fatal("old fixture receipt")
				}
			}
			original.CaseReceipts = nil
			saved := &runState{directory: directory, record: original}
			identity, err := caseIdentitySHA256(saved.record)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range saved.record.Scenarios {
				if saved.writeCaseReceipt(r, identity) != nil {
					t.Fatal("publication receipt")
				}
			}
			path := filepath.Join(directory, "run.json")
			if records.WriteJSON(path, saved.record, 0600) != nil {
				t.Fatal("publication run")
			}
			originals := map[string][]byte{}
			for _, name := range []string{path, inventoryPath, filepath.Join(finalState, "output-inventory.json")} {
				body, err := os.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				originals[name] = body
			}
			plan, _, ordinal, err := prepareGrantedRecovery(root, saved.record, saved.record.CaseReceipts[1], request, "")
			if (err == nil) != (damage == "none") {
				t.Fatal("publication grant admission differs", damage, err)
			}
			if err == nil && (ordinal != 2 || len(plan.Entries) != 1 || plan.Entries[0].OutputScheduled != 1 || plan.Entries[0].Input.authorityOnly().Outputs != nil) {
				t.Fatal("publication grant acquired wrong count or output authority")
			}
			for name, want := range originals {
				got, err := os.ReadFile(name)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatal("publication grant changed original bytes")
				}
			}
			if _, err := os.Lstat(filepath.Join(private, "aws-cleanup-grant.json")); !os.IsNotExist(err) {
				t.Fatal("admission consumed one-use grant")
			}
		})
	}
}

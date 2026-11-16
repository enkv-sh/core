package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"syscall"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
)

// A grant belongs to one new recovery run. It cannot extend the automatic
// retry count or grant another attempt after this recovery run fails.
type cleanupGrantInput struct {
	TargetIndex               uint32 `json:"target_index"`
	Ordinal                   uint8  `json:"ordinal"`
	OriginalCaseReceiptSHA256 string `json:"original_case_receipt_sha256"`
	GrantRunID                string `json:"grant_run_id"`
	GrantLimitsSHA256         string `json:"grant_limits_sha256"`
	InventorySHA256           string `json:"inventory_sha256,omitempty"`
}

// Mirror the complete private inventory wire schema. Strict decoding must
// reject unknown fields without rejecting evidence written by the live worker.
type grantInventory struct {
	Version int         `json:"version"`
	RunID   string      `json:"run_id"`
	Binding string      `json:"binding"`
	Prefix  string      `json:"prefix"`
	Domain  contract.ID `json:"domain"`
	Intents []struct {
		Key            string          `json:"key"`
		Digest         string          `json:"digest"`
		Bytes          uint64          `json:"bytes"`
		Kind           string          `json:"kind"`
		ConditionToken *contract.Token `json:"condition_token,omitempty"`
		State          string          `json:"state"`
	} `json:"intents"`
	Deleted         map[string]int `json:"deleted"`
	CleanupAttempts []grantAttempt `json:"cleanup_attempts,omitempty"`
}

type grantAttempt struct {
	TargetIntent int                     `json:"target_intent"`
	Ordinal      uint8                   `json:"ordinal"`
	Recovery     string                  `json:"recovery,omitempty"`
	GrantRunID   string                  `json:"grant_run_id,omitempty"`
	CaseSHA256   string                  `json:"case_sha256,omitempty"`
	LimitsSHA256 string                  `json:"limits_sha256,omitempty"`
	Key          string                  `json:"key"`
	Digest       string                  `json:"digest"`
	Bytes        uint64                  `json:"bytes"`
	Token        contract.Token          `json:"token"`
	Cutoff       int                     `json:"cutoff"`
	State        string                  `json:"state"`
	Failure      *records.HarnessFailure `json:"failure,omitempty"`
}

// A required first-failure control can finish Product checks in its rerun
// before either a prior or the selected case stops during fixture cleanup.
func awsCleanupProductPassed(result scenarioResult) bool {
	execution, known := recordedExecution(result.Scenario, "live")
	if !known || result.Writer == nil {
		return false
	}
	expectedChildren := len(execution.ExpandedFreshBefore())
	workers := append([]workerEvidence{}, result.Children...)
	if result.Rerun != nil {
		first := records.WorkerResult{Role: result.Writer.Role, Outcome: result.Writer.Outcome,
			Failure: result.Writer.Failure, StoreFailure: result.Writer.StoreFailure, Phases: result.Writer.Phases}
		process := processResult{Status: result.Writer.Process, Joined: result.Writer.Joined}
		if result.FirstFailure == nil || *result.FirstFailure != (records.Failure{Class: "store_transport_exhausted", Stage: "transition"}) ||
			!recordedSameDomainRecovery(result.Scenario) || !sameDomainRerunEvidence(process, first, result.Children) || result.Rerun.Role != "rerun" {
			return false
		}
		expectedChildren = 0
		workers = append(workers, *result.Rerun)
	} else {
		if result.FirstFailure != nil || recordedSameDomainRecovery(result.Scenario) {
			return false
		}
		workers = append(workers, *result.Writer)
	}
	if len(result.Children) != expectedChildren || len(result.PostExit) != len(execution.ExpandedFreshAfter()) {
		return false
	}
	workers = append(workers, result.PostExit...)
	for _, worker := range workers {
		if !worker.Joined || worker.Process != "passed" || worker.Outcome != "passed" || worker.Failure != nil {
			return false
		}
	}
	return true
}

func admissionNoSendCleanup(fact *records.HarnessFailure) bool {
	return fact != nil && fact.Validate() && fact.Operation == "object_cleanup" &&
		fact.Stage == "admission" && fact.Cause == "invalid_request" &&
		fact.Effect == "no_send" && fact.Attempt == 0
}

func prepareGrantedRecovery(root string, original runRecord, ref caseReceiptRef, request cleanupRequest, recordedWorkflowID string) (recoveryPlan, cleanupRecoveryBasis, uint8, error) {
	refused := errors.New("explicit cleanup grant refused")
	awsFixture := original.Provider == "aws"
	noSendFixture := (original.Provider == "gcp" || original.Provider == "aws") && len(original.Scenarios) != 0 && admissionNoSendCleanup(original.Scenarios[len(original.Scenarios)-1].Cleanup.HarnessFailure)
	retiredFixture := awsFixture || noSendFixture
	if original.Provider != "aws" && original.Provider != "gcp" || original.ContinuationRootRunID != recordedWorkflowID || recordedWorkflowID != "" && !records.ValidRunID(recordedWorkflowID) {
		return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
	}
	if request.RunID != original.RunID || original.Suite != "live" || !validSource(original.Source) ||
		original.FinishedAt == nil || original.FinishedAt.Before(original.StartedAt) ||
		original.Profile != "full" || original.Outcome != "failed" || original.Failure == nil || original.Failure.Stage != "cleanup" ||
		original.CoverageScope != "live_scenarios" || original.Resolved == nil || original.Resolved.Generator != nil ||
		original.Limits == nil || !original.Limits.valid() || len(original.Scenarios) == 0 ||
		original.BuildClosure == nil || original.BuildClosure.Suite != "live" || original.BuildClosure.Provider != original.Provider ||
		len(original.Scenarios) != len(original.CaseReceipts) || len(original.Scenarios) > len(original.Schedule.Entries) {
		return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
	}
	directory, err := runPath(root, "live", "runs", original.RunID)
	if err != nil {
		return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
	}
	path, err := records.SafePath(directory, "run.json")
	if err != nil {
		return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
	}
	var saved runRecord
	body, readErr := readRecordBytes(path)
	if readErr != nil || decodeCleanupRecord(body, &saved) != nil ||
		!reflect.DeepEqual(saved, original) || validateCaseReceiptSet(directory, saved) != nil {
		return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
	}
	if _, known := recordedRunRace(saved); !known {
		return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
	}
	for _, result := range saved.Scenarios {
		for _, worker := range scenarioWorkers(result) {
			if !worker.Joined {
				return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
			}
		}
		for _, attempt := range result.CleanupAttempts {
			if attempt.Worker == nil || !attempt.Worker.Joined {
				return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
			}
		}
		for _, reconstruction := range result.Reconstruction {
			for _, phase := range reconstruction.Phases {
				if phase.Started && !phase.Joined {
					return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
				}
			}
		}
	}
	failed := saved.Scenarios[len(saved.Scenarios)-1]
	caseOnly := len(saved.Scenarios) == 1 && failed.Sequence > 0
	if (!caseOnly && failed.Sequence != len(saved.Scenarios)-1) ||
		failed.Sequence < 0 || failed.Sequence >= len(saved.Schedule.Entries) || failed.Entry != saved.Schedule.Entries[failed.Sequence] ||
		failed.Outcome != "failed" || !failed.CorrectnessPassed || failed.Failure != nil ||
		failed.Writer == nil || !failed.Writer.Joined ||
		!retiredFixture && (failed.Rerun != nil || failed.Writer.Process != "passed" || failed.Writer.Outcome != "passed") ||
		failed.BudgetReserved == nil || failed.Cleanup.BudgetReserved == nil ||
		ref != saved.CaseReceipts[len(saved.CaseReceipts)-1] {
		return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
	}
	if retiredFixture {
		if saved.FinishedAt == nil || saved.FinishedAt.Before(saved.StartedAt) {
			return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
		}
		for _, result := range saved.Scenarios {
			if !awsCleanupProductPassed(result) || result.CleanupWorker == nil || !result.CleanupWorker.Joined {
				return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
			}
			for _, attempt := range result.CleanupAttempts {
				if attempt.Worker == nil || !attempt.Worker.Joined {
					return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
				}
			}
		}
	}
	remaining := *saved.Limits
	for index, result := range saved.Scenarios {
		if (!caseOnly && result.Sequence != index) || index < len(saved.Scenarios)-1 &&
			(result.Outcome != "passed" || !result.CorrectnessPassed || !scenarioCleanupPassed(result)) {
			return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
		}
		if result.OutputScheduled != 0 {
			state, stateErr := publicationScenarioState(directory, result)
			if stateErr != nil || validateRetainedPublication(state, saved, result) != nil {
				return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
			}
			var input workerInput
			if records.ReadJSON(filepath.Join(state, "input.json"), &input) != nil {
				return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
			}
			residue, residueErr := publicationResidueState(input.Outputs)
			if residueErr != nil || residue.Unknown != 0 || residue.Remaining != residue.Scheduled || residue.Scheduled != int64(result.OutputScheduled) {
				return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
			}
		}
		if result.BudgetReserved == nil || result.Cleanup.BudgetReserved == nil ||
			debitBudget(&remaining, result.BudgetReserved, result.Cleanup.BudgetReserved,
				result.WorkloadElapsed, result.CleanupElapsed) != nil {
			return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
		}
	}
	if _, err := validateCaseReceipt(directory, saved, ref, failed.Entry); err != nil {
		return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
	}
	if !retiredFixture {
		execution, known := recordedExecution(failed.Scenario, "live")
		if !known || len(failed.Children) != len(execution.ExpandedFreshBefore()) || len(failed.PostExit) != len(execution.ExpandedFreshAfter()) {
			return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
		}
		productWorkers := []workerEvidence{*failed.Writer}
		productWorkers = append(productWorkers, failed.Children...)
		productWorkers = append(productWorkers, failed.PostExit...)
		for _, worker := range productWorkers {
			if !worker.Joined || worker.Process != "passed" || worker.Outcome != "passed" || worker.Failure != nil {
				return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
			}
		}
	}
	fact := failed.Cleanup.HarnessFailure
	if fact == nil || (!noSendFixture && (fact.Attempt == 0 || fact.Attempt > 3)) || failed.CleanupWorker == nil ||
		!failed.CleanupWorker.Joined || failed.CleanupWorker.HarnessFailure == nil ||
		!reflect.DeepEqual(*failed.CleanupWorker.HarnessFailure, *fact) {
		return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
	}
	target, blocker := cleanupFailureTarget(&failed, true, fact.Attempt)
	if noSendFixture {
		if fact.TargetKind != "inventory" || fact.TargetIndex == nil || failed.Cleanup.Outcome != "unresolved" ||
			failed.Cleanup.RemainingOwnedObjects == nil || *failed.Cleanup.RemainingOwnedObjects < 1 ||
			failed.Cleanup.UnknownEffects == nil || *failed.Cleanup.UnknownEffects != 0 {
			return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
		}
		target, blocker = *fact.TargetIndex, ""
	}
	if blocker != "" || target > maximumCleanupCount {
		return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
	}
	plan, err := prepareRecovery(root, request)
	if err != nil || plan.Provider != original.Provider || plan.Generator != nil || !plan.Limits.valid() ||
		!reflect.DeepEqual(safeRunContext(plan.Settings), saved.Context) {
		return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
	}
	privateName, err := recordedCaseDirectory(failed.Entry)
	if err != nil {
		return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
	}
	var selected *recoveryEntry
	for i := range plan.Entries {
		if filepath.Base(plan.Entries[i].State) == privateName {
			selected = &plan.Entries[i]
			break
		}
	}
	if selected == nil || selected.Input.Scenarios[0] != failed.Scenario || selected.Input.MemberCount != failed.Members ||
		selected.Input.RunID != saved.RunID || selected.Input.Generator != nil ||
		!sameResources(selected.Input.Settings, plan.Settings) {
		return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
	}
	if selected.Input.Outputs != nil {
		if validateRetainedPublication(selected.State, saved, failed) != nil {
			return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
		}
		residue, residueErr := publicationResidueState(selected.Input.Outputs)
		if residueErr != nil || residue.Unknown != 0 || residue.Remaining != residue.Scheduled || failed.OutputScheduled != 0 && residue.Scheduled != int64(failed.OutputScheduled) || failed.Cleanup.RemainingOwnedObjects == nil || *failed.Cleanup.RemainingOwnedObjects < residue.Remaining {
			return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
		}
		// Older failed Store cleanups omitted the independent scheduled count.
		// Derive it from the qualified private rows; never change the old result.
		selected.OutputsSHA256, selected.OutputScheduled = failed.OutputsSHA256, uint32(residue.Scheduled)
		copy := saved.Source
		plan.OutputSource = &copy
	}
	participants, err := saved.Resolved.scenarioParticipants(failed.Scenario)
	if err != nil || selected.Input.Participants["authority"] != participants["authority"] {
		return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
	}
	inventoryPath, err := records.SafePath(selected.State, "inventory.json")
	if err != nil {
		return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
	}
	var image grantInventory
	if records.ReadJSON(inventoryPath, &image) != nil || image.Version != 1 ||
		image.RunID != saved.RunID || image.Prefix != selected.Input.Prefix || int(target) >= len(image.Intents) ||
		image.Intents[target].State != "acknowledged" && image.Intents[target].State != "observed" {
		return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
	}
	for _, intent := range image.Intents {
		if intent.State == "pending" || intent.State == "unknown" {
			return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
		}
	}
	var last *grantAttempt
	for i := range image.CleanupAttempts {
		attempt := &image.CleanupAttempts[i]
		if attempt.Recovery == "gcp_exact_generation_grant" || attempt.Recovery == "aws_retired_fixture_grant" || attempt.Recovery == "admission_no_send_grant" || attempt.TargetIntent != int(target) && (attempt.State == "pending" || attempt.State == "failed" && attempt.Failure != nil && attempt.Failure.Effect == "unknown") {
			return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
		}
		if attempt.TargetIntent == int(target) {
			last = attempt
		}
	}
	if last == nil || retiredFixture && (last.Ordinal != 1 || last.Recovery != "" || failed.CleanupWorker == nil || failed.CleanupWorker.Process != "process_failed") || (!noSendFixture && last.Ordinal != fact.Attempt) || last.State != "failed" || last.Failure == nil ||
		!reflect.DeepEqual(*last.Failure, *fact) {
		return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
	}
	if noSendFixture {
		intent := image.Intents[target]
		family := contract.GCP
		if original.Provider == "aws" {
			family = contract.AWS
		}
		if last.Key != intent.Key || last.Digest != intent.Digest || last.Bytes != intent.Bytes ||
			last.Bytes == 0 || !last.Token.Valid() || last.Token.Family != family ||
			last.Cutoff < 0 || last.Cutoff > int(target) || image.Deleted[last.Key] != last.Cutoff {
			return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
		}
	}
	plan.Entries = []recoveryEntry{*selected}
	if !retiredFixture || selected.Input.Outputs != nil {
		plan.OriginalBuild = saved.BuildClosure
	}
	inventoryBody, err := readRecordBytes(inventoryPath)
	if err != nil {
		return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
	}
	plan.Grant = &cleanupGrantInput{InventorySHA256: digestBytes(inventoryBody)}
	basis := cleanupRecoveryBasis{OriginalRunID: saved.RunID, OriginalRunSHA256: digestBytes(body), OriginalCaseReceiptSHA256: ref.SHA256,
		Entry: failed.Entry, TargetIndex: target, Decision: "gcp_exact_generation_grant"}
	claimName := "gcp-cleanup-grant.json"
	if retiredFixture {
		if selected.Input.Prefix != "enkv-test/"+saved.RunID+"/"+privateName || saved.RecoveryRunID != "" || saved.CleanupRecoveryBasis != nil {
			return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
		}
		claimName, basis.Decision = "aws-cleanup-grant.json", "aws_retired_fixture_grant"
		if noSendFixture {
			claimName, basis.Decision = "admission-cleanup-grant.json", "admission_no_send_grant"
		}
	}
	claimPath, pathErr := records.SafePath(filepath.Dir(selected.State), claimName)
	if pathErr != nil {
		return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
	}
	if _, err := os.Lstat(claimPath); !errors.Is(err, os.ErrNotExist) {
		return recoveryPlan{}, cleanupRecoveryBasis{}, 0, refused
	}
	return plan, basis, last.Ordinal + 1, nil
}

func executePreparedRecovery(ctx context.Context, root, bootstrap string, s *runState, plan recoveryPlan) error {
	return executePreparedRecoveryOwned(s.preparation, ctx, root, bootstrap, s, plan, io.Discard)
}

func cleanupOutputBindings(plan recoveryPlan) ([]outputProfileBinding, error) {
	if plan.OutputSource == nil {
		return nil, nil
	}
	if plan.OriginalBuild == nil {
		return nil, errPublicationInput
	}
	bindings, err := retainedOutputBindings(plan.OriginalBuild.OutputArtifacts)
	if err != nil {
		return nil, errPublicationInput
	}
	return bindings, nil
}

func cleanupExecutionCommands(preflight *preparedLivePreflight, bindings assemblyBindings) ([]checkCommandFacts, error) {
	if preflight == nil {
		return nil, errors.New("cleanup executable was not prepared")
	}
	return assemblyConstructionCommands(bindings)
}

func cleanupRuntimeCommands(plan recoveryPlan, preflight *preparedLivePreflight) ([]checkCommandFacts, error) {
	bindings, err := cleanupOutputBindings(plan)
	if err != nil {
		return nil, err
	}
	return cleanupExecutionCommands(preflight, assemblyBindings{Output: bindings})
}

func executePreparedRecoveryOwned(diagnostics *checkDiagnostics, ctx context.Context, root, bootstrap string, s *runState, plan recoveryPlan, output io.Writer) (err error) {
	ownsPreparation := true
	defer func() {
		if err != nil && ownsPreparation && diagnostics != nil {
			diagnostics.Preparation = "failed"
		}
		err = errors.Join(err, writeCheckDiagnostics(output, diagnostics))
	}()
	for _, entry := range plan.Entries {
		if entry.Input.Outputs != nil && (plan.Grant == nil || plan.OutputSource == nil || plan.OriginalBuild == nil || !sameSource(*plan.OutputSource, s.record.Source)) {
			return errPublicationInput
		}
	}
	ctx, err = s.privateOwner.protectedFixtureContext(ctx)
	if err != nil {
		return err
	}
	build := filepath.Join(s.private, "build")
	if os.Mkdir(build, 0700) != nil {
		return errors.New("cleanup assembly directory unavailable")
	}
	preflight := livePreflightFromContext(ctx, plan.Provider)
	if preflight == nil {
		return errors.New("cleanup controlled selection was not prepared")
	}
	outputBindings, err := cleanupOutputBindings(plan)
	if err != nil {
		return err
	}
	future, planErr := cleanupExecutionCommands(preflight, assemblyBindings{Output: outputBindings})
	if planErr != nil {
		return planErr
	}
	finishPlan, planErr := beginPreparationPlan(diagnostics, future)
	if planErr != nil {
		return planErr
	}
	defer finishPlan()

	var cloudflareBinding *cloudflareAssemblyBinding
	if plan.Generator != nil {
		var err error
		cloudflareBinding, err = prepareCloudflareAssemblyBinding(ctx, root, build, *plan.Generator)
		if err != nil {
			return err
		}
	}
	command := goEnvironmentCommand(runGoEnvironment)
	if diagnostics != nil {
		command = diagnostics.runGoEnvironment
	}
	assembled, err := buildBoundAssemblyMode(command, diagnostics, ctx, root, "live", plan.Provider, bootstrap, build, raceEnabled(ctx), assemblyBindings{Cloudflare: cloudflareBinding, Output: outputBindings})
	if err != nil {
		return safeCheckFailure("preparation", "none", err)
	}
	if err := linkInvocationDirectory(filepath.Dir(assembled.Binary), build); err != nil {
		return err
	}
	s.record.BuildClosure = &assembled.Closure
	s.failureSources = assembled.FailureSources
	assembled.currentPrefix = diagnostics
	assembled.preparationOwner, assembled.preparationKey = preflight, plan.Provider
	if err := preflight.bindActualOwned(diagnostics, ctx, root, &assembled); err != nil {
		return err
	}
	if diagnostics != nil {
		diagnostics.Preparation = "passed"
		if err := writeCheckDiagnostics(output, diagnostics); err != nil {
			return err
		}
	}
	ownsPreparation = false
	return s.executeRecovery(ctx, assembled.Binary, plan)
}

// The original run lock excludes a second coordinator; the inventory lease
// excludes a live worker while its snapshot is bound to the one durable grant.
func claimFixtureCleanup(plan recoveryPlan, record runRecord) error {
	if plan.StockRecovery != nil {
		return claimStockRecovery(plan, record)
	}
	refused := errors.New("fixture cleanup grant unavailable or consumed")
	if len(plan.Entries) != 1 || plan.Grant == nil || record.CleanupRecoveryBasis == nil {
		return refused
	}
	limitsBody, limitsErr := json.Marshal(plan.Limits)
	if limitsErr != nil || !plan.Limits.valid() || !records.ValidRunID(record.RunID) ||
		plan.Grant.GrantRunID != record.RunID || !validSource(record.Source) ||
		record.RecoveryRunID != record.CleanupRecoveryBasis.OriginalRunID || record.ContinuationRootRunID != "" ||
		record.Limits == nil || !reflect.DeepEqual(*record.Limits, plan.Limits) || digestBytes(limitsBody) != plan.Grant.GrantLimitsSHA256 ||
		plan.Grant.TargetIndex != record.CleanupRecoveryBasis.TargetIndex || plan.Grant.OriginalCaseReceiptSHA256 != record.CleanupRecoveryBasis.OriginalCaseReceiptSHA256 {
		return refused
	}
	claimName := ""
	switch record.CleanupRecoveryBasis.Decision {
	case "aws_retired_fixture_grant":
		if plan.Provider != "aws" || plan.Grant.Ordinal != 2 {
			return refused
		}
		claimName = "aws-cleanup-grant.json"
	case "admission_no_send_grant":
		if plan.Provider != "aws" && plan.Provider != "gcp" || plan.Grant.Ordinal != 2 {
			return refused
		}
		claimName = "admission-cleanup-grant.json"
	case "gcp_exact_generation_grant":
		if plan.Provider != "gcp" || plan.Grant.Ordinal < 2 || plan.Grant.Ordinal > 4 {
			return refused
		}
		claimName = "gcp-cleanup-grant.json"
	default:
		return refused
	}
	state := plan.Entries[0].State
	lockPath, err := records.SafePath(state, "inventory.lock")
	if err != nil {
		return refused
	}
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return refused
	}
	defer lock.Close()
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() || syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return refused
	}
	body, err := readRecordBytes(filepath.Join(state, "inventory.json"))
	if err != nil || digestBytes(body) != plan.Grant.InventorySHA256 {
		return refused
	}
	originalPath := filepath.Join(filepath.Dir(filepath.Dir(state)), "run.json")
	body, err = readRecordBytes(originalPath)
	if err != nil || digestBytes(body) != record.CleanupRecoveryBasis.OriginalRunSHA256 {
		return refused
	}
	claim := struct {
		Basis  cleanupRecoveryBasis `json:"basis"`
		Source records.Source       `json:"source"`
		Grant  cleanupGrantInput    `json:"grant"`
	}{*record.CleanupRecoveryBasis, record.Source, *plan.Grant}
	path, err := records.SafePath(filepath.Dir(state), claimName)
	if err != nil || records.WriteJSONExclusive(path, claim, records.MaximumJSONBytes) != nil {
		return refused
	}
	return nil
}

func prepareFixtureRecovery(root string, request cleanupRequest, ordinary recoveryPlan) (recoveryPlan, *cleanupRecoveryBasis, error) {
	directory, err := runPath(root, "live", "runs", request.RunID)
	if err != nil {
		return recoveryPlan{}, nil, err
	}
	path, err := records.SafePath(directory, "run.json")
	if err != nil {
		return recoveryPlan{}, nil, err
	}
	body, err := readRecordBytes(path)
	if err != nil {
		return recoveryPlan{}, nil, errors.New("retained fixture run unavailable")
	}
	var original runRecord
	if decodeCleanupRecord(body, &original) != nil || original.Provider != ordinary.Provider {
		return recoveryPlan{}, nil, errors.New("retained fixture run inconsistent")
	}
	if original.RunID != request.RunID || original.Suite != "live" || original.SchemaVersion != records.SchemaVersion || original.FinishedAt == nil || original.FinishedAt.Before(original.StartedAt) || !runProcessesJoined(original) {
		return recoveryPlan{}, nil, errors.New("retained fixture run is not settled")
	}
	for _, entry := range ordinary.Entries {
		if original.RunID != entry.Input.RunID {
			return recoveryPlan{}, nil, errors.New("retained fixture owner differs")
		}
		matched := false
		for _, result := range original.Scenarios {
			name, err := recordedCaseDirectory(result.Entry)
			if err != nil || name != filepath.Base(entry.State) || result.Scenario != entry.Input.Scenarios[0] {
				continue
			}
			if matched || result.Writer == nil || !result.Writer.Started || !result.Writer.Joined {
				return recoveryPlan{}, nil, errors.New("retained fixture workers are not joined")
			}
			for _, worker := range scenarioWorkers(result) {
				if !worker.Joined {
					return recoveryPlan{}, nil, errors.New("retained fixture workers are not joined")
				}
			}
			matched = true
		}
		if !matched {
			return recoveryPlan{}, nil, errors.New("retained fixture worker evidence unavailable")
		}
	}
	if original.Outcome != "failed" || original.Failure == nil || original.Failure.Stage != "cleanup" {
		if len(ordinary.Entries) == 1 && ordinary.Entries[0].Input.Scenarios[0] == records.StockPluginScenario {
			return prepareStockRecovery(root, directory, original, ordinary)
		}
		return ordinary, nil, nil
	}
	// A retained admission refusal needs one explicit grant. Failures before
	// an attempt was recorded remain ordinary cleanup.
	if len(original.Scenarios) == 0 {
		return ordinary, nil, nil
	}
	fact := original.Scenarios[len(original.Scenarios)-1].Cleanup.HarnessFailure
	if !admissionNoSendCleanup(fact) && (original.Provider != "aws" && original.Provider != "gcp" || fact == nil || fact.Effect != "unknown" || fact.Attempt == 0) {
		return ordinary, nil, nil
	}
	if len(original.CaseReceipts) == 0 {
		return recoveryPlan{}, nil, errors.New("retained fixture cleanup receipt unavailable")
	}
	plan, basis, ordinal, err := prepareGrantedRecovery(root, original, original.CaseReceipts[len(original.CaseReceipts)-1], request, original.ContinuationRootRunID)
	if err != nil {
		return recoveryPlan{}, nil, err
	}
	plan.Grant.TargetIndex, plan.Grant.Ordinal, plan.Grant.OriginalCaseReceiptSHA256 = basis.TargetIndex, ordinal, basis.OriginalCaseReceiptSHA256
	return plan, &basis, nil
}

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

type recoveryEntry struct {
	OriginalEntry    catalog.Entry
	OutputsSHA256    string
	OutputScheduled  uint32
	State, InputPath string
	Input            workerInput
}
type recoveryPlan struct {
	OutputSource  *records.Source
	Provider      string
	Authority     string
	Settings      liveSettings
	Generator     *generatorReference
	Limits        limits
	Entries       []recoveryEntry
	Grant         *cleanupGrantInput
	OriginalBuild *assemblyClosure
	StockRecovery *records.StockPluginRecoveryInput
}

var scenarioDirectory = regexp.MustCompile(`^[0-9]{4}-.+$`)
var currentScenarioDirectory = regexp.MustCompile(`^[0-9]{4,}-[a-f0-9]{64}$`)

func prepareRecovery(root string, request cleanupRequest) (recoveryPlan, error) {
	refused := errors.New("retained cleanup inputs unavailable or inconsistent")
	directory, err := runPath(root, "live", "runs", request.RunID)
	if err != nil {
		return recoveryPlan{}, refused
	}
	private, err := records.SafePath(directory, "private")
	if err != nil {
		return recoveryPlan{}, refused
	}
	files, err := os.ReadDir(private)
	if err != nil {
		return recoveryPlan{}, refused
	}
	var plan recoveryPlan
	for _, file := range files {
		if !scenarioDirectory.MatchString(file.Name()) && !currentScenarioDirectory.MatchString(file.Name()) {
			continue
		}
		if !file.IsDir() {
			return recoveryPlan{}, refused
		}
		state, err := records.SafePath(private, file.Name())
		if err != nil {
			return recoveryPlan{}, refused
		}
		path, err := records.SafePath(state, "input.json")
		var input workerInput
		body, readErr := readRecordBytes(path)
		if err != nil || readErr != nil || decodeCleanupRecord(body, &input) != nil || input.RunID != request.RunID || len(input.Scenarios) != 1 || input.Repetitions != 1 || input.Limits == nil || !input.Limits.valid() || !telemetryLabel.MatchString(input.Participants["authority"]) {
			return recoveryPlan{}, refused
		}
		sequenceText, _, _ := strings.Cut(file.Name(), "-")
		sequence, sequenceErr := strconv.Atoi(sequenceText)
		expectedDirectory, directoryErr := recordedCaseDirectory(catalog.Entry{Scenario: input.Scenarios[0], Members: input.MemberCount, Sequence: sequence})
		if sequenceErr != nil || directoryErr != nil || file.Name() != expectedDirectory {
			return recoveryPlan{}, refused
		}
		if _, err := recordedFixture(input.Scenarios[0], input.MemberCount); err != nil {
			return recoveryPlan{}, refused
		}
		if !strings.HasPrefix(input.Prefix, "enkv-test/"+request.RunID+"/") || filepath.Clean(input.Prefix) != input.Prefix || strings.Contains(input.Prefix, `\`) {
			return recoveryPlan{}, refused
		}
		generated := recordedHasFixture(input.Scenarios[0], catalog.FixtureGeneratedProcess)
		if generated != (input.Generator != nil) || generated && input.GeneratorCleanupLedger != filepath.Join(state, "generator-cleanup.json") {
			return recoveryPlan{}, refused
		}
		if generated {
			if !cloudflareAccount.MatchString(input.Generator.Account) || !cloudflareAccount.MatchString(input.Generator.PermissionGroup) ||
				plan.Generator != nil && (plan.Generator.Account != input.Generator.Account || plan.Generator.PermissionGroup != input.Generator.PermissionGroup) {
				return recoveryPlan{}, refused
			}
			plan.Generator = input.Generator
		}
		provider := input.Settings["provider"]
		public := recordedHasFixture(input.Scenarios[0], catalog.FixturePublicConfiguration)
		if public != (input.PublicConfiguration != nil) || public && (request.Environment != "" || !publicCleanupInputValid(input, provider)) {
			return recoveryPlan{}, refused
		}
		if provider != "gcp" && provider != "aws" || plan.Provider != "" && (provider != plan.Provider || !sameResources(plan.Entries[0].Input.Settings, input.Settings)) {
			return recoveryPlan{}, refused
		}
		if input.Outputs != nil && (input.Outputs.Scope.RunID != request.RunID || input.Outputs.Scope.Scenario != input.Scenarios[0] || input.Outputs.ValidateRecorded(input.Outputs.Scope, "writer") != nil || input.Outputs.InventoryPath != filepath.Join(state, "output-inventory.json") || input.Outputs.JoinedPath != filepath.Join(state, "output-joined.json")) {
			return recoveryPlan{}, refused
		}
		original := catalog.Entry{Scenario: input.Scenarios[0], Members: input.MemberCount, Sequence: sequence}
		if public {
			completed, recorded, err := publicOutputCaseCompleted(directory, original, input)
			if err != nil {
				return recoveryPlan{}, err
			}
			original = recorded
			if completed {
				continue
			}
		}
		plan.Provider = provider
		plan.Entries = append(plan.Entries, recoveryEntry{OriginalEntry: original, State: state, InputPath: path, Input: input})
	}
	if len(plan.Entries) == 0 {
		return recoveryPlan{}, refused
	}
	plan.Limits, err = loadLimits(request.Limits)
	if err != nil {
		return recoveryPlan{}, err
	}
	if request.Environment != "" {
		var environment environmentFile
		if readSelectionFile(request.Environment, &environment) != nil || environment.SchemaVersion != 1 || environment.Mode != "live" || environment.Provider != plan.Provider {
			return recoveryPlan{}, refused
		}
		directory, pathErr := filepath.Abs(filepath.Dir(request.Environment))
		if pathErr != nil {
			return recoveryPlan{}, refused
		}
		if err = validateEnvironment(&environment, directory); err == nil {
			err = selectRecoveryMode(&environment, plan.Entries[0].Input.Settings["recovery_mode"])
		}
		if err == nil {
			err = validateEnvironment(&environment, directory)
		}
		if err == nil {
			plan.Authority = environment.RoleBindings["authority"]
			plan.Settings, err = environment.settingsFor(plan.Authority)
		}
		if err == nil {
			plan.Settings, err = validateSettings(plan.Settings, plan.Provider, "")
		}
		if err == nil && (plan.Generator == nil) != (environment.Generator == nil) {
			return recoveryPlan{}, refused
		}
		if err == nil && plan.Generator != nil {
			if plan.Generator.Account != environment.Generator.Account || plan.Generator.PermissionGroup != environment.Generator.PermissionGroup {
				return recoveryPlan{}, refused
			}
			generator, generatorErr := validateGeneratorRoute(*environment.Generator, environment.PublicConfiguration)
			if generatorErr != nil {
				return recoveryPlan{}, generatorErr
			}
			plan.Generator = &generator
		}
	} else {
		first := plan.Entries[0]
		if first.Input.PublicConfiguration != nil {
			plan.Settings = first.Input.Settings
		} else {
			plan.Settings, err = validateSettings(first.Input.Settings, plan.Provider, filepath.Dir(first.InputPath))
		}
		if err == nil && plan.Generator != nil {
			generator, generatorErr := validateGeneratorRoute(*plan.Generator, first.Input.PublicConfiguration != nil)
			if generatorErr != nil {
				return recoveryPlan{}, generatorErr
			}
			plan.Generator = &generator
		}
	}
	if err != nil {
		return recoveryPlan{}, err
	}
	for _, entry := range plan.Entries {
		if !sameResources(plan.Settings, entry.Input.Settings) {
			return recoveryPlan{}, errors.New("cleanup resource identities changed")
		}
	}
	return plan, nil
}

func recoverySchedule(plan recoveryPlan) catalog.Schedule {
	value := catalog.Schedule{Repetitions: 1, Selected: []string{}, Entries: []catalog.Entry{}}
	for i, entry := range plan.Entries {
		name := entry.Input.Scenarios[0]
		if !slices.Contains(value.Selected, name) {
			value.Selected = append(value.Selected, name)
		}
		value.Entries = append(value.Entries, catalog.Entry{Scenario: name, Members: entry.Input.MemberCount, Sequence: i})
	}
	return value
}

func runCleanup(ctx context.Context, root, bootstrap string, request cleanupRequest, output io.Writer) (execution suiteExecution, err error) {
	return runCleanupOwned(nil, ctx, root, bootstrap, request, output)
}

func runCleanupOwned(initial *checkDiagnostics, ctx context.Context, root, bootstrap string, request cleanupRequest, output io.Writer) (execution suiteExecution, err error) {
	execution.preparation = initial
	if execution.preparation == nil {
		execution.preparation = &checkDiagnostics{Preparation: "pending"}
	}
	prepared, _ := ctx.Value(preparedCleanupContextKey{}).(*preparedCleanup)
	delegated := false
	defer func() {
		if err != nil && !delegated {
			execution.preparation.Preparation = "failed"
		}
		if prepared != nil {
			err = errors.Join(err, prepared.retainPreparation(&execution, output))
		} else {
			err = errors.Join(err, writeCheckDiagnostics(output, execution.preparation))
		}
	}()
	if prepared == nil {
		prepared, err = prepareCleanup(ctx, root, bootstrap, request, output)
		if prepared != nil {
			defer func() {
				tail, cancel := finalizationContext(ctx)
				defer cancel()
				err = errors.Join(err, prepared.close(tail))
			}()
		}
		if err != nil {
			return execution, err
		}
		delegated = true
		return runPreparedCleanupResult(ctx, root, bootstrap, prepared, output, execution)
	}
	if err := prepared.retainPreparation(&execution, output); err != nil {
		return execution, err
	}
	future, planErr := cleanupRuntimeCommands(prepared.plan, prepared.preflight)
	if planErr != nil {
		return execution, planErr
	}
	finishPlan, planErr := beginPreparationPlan(execution.preparation, future)
	if planErr != nil {
		return execution, planErr
	}
	defer finishPlan()
	if err := prepared.verifyOwned(execution.preparation, ctx, root); err != nil {
		return execution, err
	}
	ctx = prepared.preflight.binding.context(ctx)
	releaseArtifacts, borrowErr := borrowInvocationArtifacts(ctx)
	if borrowErr != nil {
		return execution, borrowErr
	}
	defer func() {
		releaseArtifacts(toolCommandsJoined(err) && (execution.Record == nil || runProcessesJoined(*execution.Record)))
	}()

	ctx = withRacePolicy(ctx, request.race)
	policy, err := executionWithinContext(ctx, request.execution)
	if err != nil {
		return execution, err
	}
	request.execution = policy
	ctx = withExecutionCapacity(ctx, policy)
	plan, basis := prepared.plan, prepared.basis
	schedule := recoverySchedule(plan)
	if basis != nil {
		schedule.Entries = []catalog.Entry{basis.Entry}
	}

	for _, entry := range schedule.Entries {
		if _, err := fmt.Fprintf(output, "Cleanup %04d %s from run %s\n", entry.Sequence, entry.Scenario, request.RunID); err != nil {
			return execution, errors.New("cleanup schedule output failed")
		}
	}
	raw, _, err := sourceObservation(ctx, root)
	if err != nil {
		return execution, err
	}
	source := raw
	if plan.OutputSource != nil {
		source = *plan.OutputSource
	}
	toolchain := prepared.preflight.binding.toolchain
	if toolchain == "" {
		return execution, errors.New("prepared cleanup toolchain unavailable")
	}
	s, err := newRunState(root, runRequest{execution: policy.clone(), Suite: "live", Provider: plan.Provider, Target: plan.Provider, Schedule: schedule}, source, toolchain)
	if err != nil {
		return execution, err
	}
	s.preparation = execution.preparation
	execution.Record, execution.Recovery = &s.record, s.recovery
	if relative, pathErr := filepath.Rel(root, filepath.Join(s.directory, "run.json")); pathErr == nil {
		execution.Evidence = filepath.ToSlash(relative)
	}
	s.recovery.executionSource = &raw
	s.record.ExecutionSource = &raw
	s.record.RecoveryRunID = request.RunID
	s.record.CleanupRecoveryBasis = basis
	if basis != nil {
		body, err := json.Marshal(plan.Limits)
		if err != nil {
			return execution, errors.New("cleanup limits unavailable")
		}
		plan.Grant.GrantRunID, plan.Grant.GrantLimitsSHA256 = s.record.RunID, digestBytes(body)
		if plan.StockRecovery != nil {
			plan.StockRecovery.RecoveryRunID = s.record.RunID
		}
	}
	s.record.Context, s.record.Limits = safeRunContext(plan.Settings), &plan.Limits
	defer func() {
		err = s.finalizeCleanupRun(ctx, root, output, err)
		relative, pathErr := filepath.Rel(root, filepath.Join(s.directory, "run.json"))
		err = errors.Join(err, pathErr)
		_, printErr := fmt.Fprintf(output, "Cleanup %s: %s\n", s.record.Outcome, filepath.ToSlash(relative))
		err = errors.Join(err, printErr)
		if err == nil && s.record.Outcome != "passed" {
			err = errors.New("cleanup remains unresolved; see retained run record")
		}
	}()
	if basis != nil {
		if err := claimFixtureCleanup(plan, s.record); err != nil {
			return execution, err
		}
	}
	if err := s.save(); err != nil {
		return execution, err
	}
	delegated = true
	return execution, executePreparedRecoveryOwned(execution.preparation, ctx, root, bootstrap, s, plan, output)
}

func (s *runState) finalizeCleanupRun(ctx context.Context, root string, output io.Writer, executionErr error) error {
	if executionErr != nil {
		s.fail("cleanup_run_failed", "cleanup")
	}
	s.finish()
	err := errors.Join(executionErr, s.finishCurrentRun(output, executionErr))
	if err != nil {
		s.record.Outcome = "failed"
		if s.record.Failure == nil {
			s.fail("cleanup_run_failed", "cleanup")
		}
		err = errors.Join(err, s.save())
	}
	return err
}

func (s *runState) executeRecovery(ctx context.Context, binary string, plan recoveryPlan) error {
	s.record.CoverageScope = "cleanup_recovery"
	remaining := plan.Limits
	for i, entry := range plan.Entries {
		if remaining.CleanupRequests == 0 || remaining.CleanupBytes == 0 || remaining.CleanupSeconds == 0 {
			s.fail("cleanup_budget_exhausted", "cleanup")
			break
		}
		if ctx.Err() != nil {
			s.fail("interrupted", "cleanup")
			break
		}
		selected := s.record.Schedule.Entries[i]
		shape, err := recordedFixture(selected.Scenario, selected.Members)
		if err != nil {
			return err
		}
		s.record.Scenarios = append(s.record.Scenarios, scenarioResult{Entry: selected, Fixture: shape, Outcome: "incomplete", Cleanup: unresolvedCleanup()})
		result := &s.record.Scenarios[len(s.record.Scenarios)-1]
		result.OutputsSHA256 = entry.OutputsSHA256
		result.OutputScheduled = entry.OutputScheduled
		if err := s.save(); err != nil {
			return err
		}
		name, err := recordedCaseDirectory(selected)
		if err != nil {
			return err
		}
		output := filepath.Join(s.private, name)
		if os.Mkdir(output, 0700) != nil {
			return errors.New("cleanup output unavailable")
		}
		input := entry.Input
		input.Settings, input.Limits = plan.Settings, &remaining
		input.CleanupGrant = plan.Grant
		if plan.StockRecovery != nil {
			input.StockRecovery = plan.StockRecovery
			input.CleanupGrant = nil
		}
		input.CleanupRetry = nil
		if input.Generator != nil {
			input.Generator = plan.Generator
		}
		input.RecoveryMode = plan.Settings["recovery_mode"]
		authority := input.Participants["authority"]
		if plan.Authority != "" {
			authority = plan.Authority
		}
		if input.PublicConfiguration == nil {
			input.Participants = map[string]string{"authority": authority}
		}
		if entry.Input.Outputs != nil && (plan.Grant == nil || plan.OutputSource == nil || !sameSource(*plan.OutputSource, s.record.Source)) {
			return errPublicationInput
		}
		input = input.authorityOnly()
		if input.Outputs.Validate(records.OutputFixtureScope{}, "rerun") != nil {
			return errPublicationInput
		}
		inputPath := filepath.Join(output, "input.json")
		state := entry.State
		if publicOutputRecoveryCase(selected.Scenario) && plan.Grant == nil {
			state = filepath.Join(output, "state")
			if os.Mkdir(state, 0700) != nil {
				return errPublicConfigurationEvidence
			}
			input.OutputRecovery, err = s.preparePublicOutputRecovery(entry, state, remaining)
			if err != nil {
				return err
			}
			if err := records.WriteJSON(filepath.Join(state, "public-output-recovery-input.json"), input.OutputRecovery, 0400); err != nil {
				return err
			}
		}
		if err := records.WriteJSON(inputPath, input, 0400); err != nil {
			return err
		}
		var publicBasis *publicCleanupEvidenceBasis
		if entry.Input.PublicConfiguration != nil && ordinaryPublicCleanupCase(selected.Scenario) && plan.Grant == nil {
			publicBasis, err = s.preparePublicCleanupEvidence(entry, *result)
			if err != nil {
				return err
			}
		}
		inv, err := makeInvocation(records.Invocation{
			Scenario: selected.Scenario, FailureSources: s.failureSources,
			TelemetrySettings: s.telemetrySettings,
			RunID:             s.record.RunID,
			Worker:            name + "-cleanup",
			Role:              "cleanup",
			Input:             inputPath,
			StateDir:          state,
			OutputDir:         filepath.Join(output, "cleanup"),
		}, s.record.Suite)
		if err != nil {
			return err
		}
		var outputInventoryHash string
		var outputResidue publicationResidue
		if entry.Input.Outputs != nil {
			var residueErr error
			outputResidue, residueErr = publicationResidueState(entry.Input.Outputs)
			before, readErr := readRecordBytes(entry.Input.Outputs.InventoryPath)
			if residueErr != nil || readErr != nil || len(before) > records.MaximumOutputFixtureInventoryBytes {
				return errPublicationInput
			}
			outputInventoryHash = digestBytes(before)
		}
		started := time.Now()
		result.CleanupWorker, result.Cleanup = s.executeCleanup(ctx, binary, inv, selected.Scenario, remaining)
		if input.OutputRecovery != nil && (result.CleanupWorker == nil || !result.CleanupWorker.Joined || input.OutputRecovery.VerifyFiles() != nil) {
			return errPublicConfigurationEvidence
		}
		if entry.Input.Outputs != nil {
			after, readErr := readRecordBytes(entry.Input.Outputs.InventoryPath)
			if result.CleanupWorker == nil || !result.CleanupWorker.Joined || readErr != nil || len(after) > records.MaximumOutputFixtureInventoryBytes || digestBytes(after) != outputInventoryHash {
				return errPublicationInput
			}
			result.OutputScheduled = uint32(outputResidue.Scheduled)
			result.Cleanup = preservePublicationResidue(result.Cleanup, outputResidue)
		}
		result.CleanupElapsed = time.Since(started)
		result.Outcome = "failed"
		if scenarioCleanupPassed(*result) {
			result.Outcome = "passed"
			if input.OutputRecovery != nil {
				if err := s.retainPublicOutputRecoveryEvidence(*input.OutputRecovery, inv, result); err != nil {
					result.Outcome = "failed"
					result.Cleanup.Outcome, result.Cleanup.Failure = "unresolved", &records.Failure{Class: "cleanup_evidence_unavailable", Stage: "cleanup"}
					return errors.Join(err, s.save())
				}
			}
			if publicBasis != nil {
				if err := s.retainPublicCleanupEvidence(publicBasis, inv, result); err != nil {
					result.Outcome = "failed"
					result.Cleanup.Outcome, result.Cleanup.Failure = "unresolved", &records.Failure{Class: "cleanup_evidence_unavailable", Stage: "cleanup"}
					return errors.Join(err, s.save())
				}
			}
		}
		if err := s.save(); err != nil {
			return err
		}
		if !scenarioCleanupPassed(*result) {
			s.fail("cleanup_unresolved", "cleanup")
			break
		}
		if err := debitBudget(&remaining, &records.BudgetReservation{}, result.Cleanup.BudgetReserved, 0, result.CleanupElapsed); err != nil {
			s.fail("budget_evidence_unavailable", "cleanup")
			break
		}
	}
	return nil
}

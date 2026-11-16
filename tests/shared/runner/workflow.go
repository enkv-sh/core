package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"time"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

type workflowRunIDContextKey struct{}

type workflowPlan struct {
	currentExecutions map[string]workflowStepExecution

	prepared      *preparedWorkflow
	Race          bool                   `json:"race"`
	Execution     executionPolicy        `json:"execution"`
	Profile       string                 `json:"profile"`
	SchemaVersion int                    `json:"schema_version"`
	Name          string                 `json:"name"`
	Steps         []resolvedWorkflowStep `json:"steps"`
}

type resolvedWorkflowStep struct {
	currentPrefix       *checkDiagnostics
	ParallelGroup       string                `json:"parallel_group,omitempty"`
	Responsibility      string                `json:"responsibility,omitempty"`
	AssemblyFocus       *assemblyFocus        `json:"assembly_focus,omitempty"`
	AssemblyPreparation *assemblyPreparation  `json:"assembly_preparation,omitempty"`
	OrdinarySelection   []ordinaryExecution   `json:"ordinary_selection,omitempty"`
	OrdinaryFocus       *ordinaryFocus        `json:"ordinary_focus,omitempty"`
	OrdinaryPreparation *ordinaryPreparation  `json:"ordinary_preparation,omitempty"`
	Focus               *componentFocus       `json:"focus,omitempty"`
	Preparation         *componentPreparation `json:"preparation,omitempty"`
	Tests               []string              `json:"tests,omitempty"`
	ID                  string                `json:"id"`
	ConfiguredStep      string                `json:"configured_step,omitempty"`
	Repetitions         int                   `json:"repetitions,omitempty"`
	Repetition          int                   `json:"repetition,omitempty"`
	Kind                string                `json:"kind"`
	Selected            bool                  `json:"selected"`
	Profile             string                `json:"profile,omitempty"`
	Race                *bool                 `json:"race,omitempty"`
	Packages            map[string][]string   `json:"packages,omitempty"`
	Targets             []string              `json:"targets,omitempty"`
	FuzzSeconds         int                   `json:"fuzz_seconds_per_target,omitempty"`
	Run                 *resolvedRequest      `json:"run,omitempty"`
	Limits              *limits               `json:"limits,omitempty"`

	request runRequest
}

func workflowArguments(args []string) (workflowRequest, error) {
	parsed, err := parsePlanRunArguments(args)
	if err != nil {
		return workflowRequest{}, err
	}
	return workflowRequestFromArguments(parsed)
}

func workflowRequestFromArguments(parsed planRunArguments) (workflowRequest, error) {
	request := parsed.request
	if !parsed.workflowPresent || request.Path == "" {
		return workflowRequest{}, errors.New("expected --workflow <file> with optional --step <id>")
	}
	if parsed.testCount != 0 &&
		(parsed.stepCount != 1 || request.SelectedStep == "" || !validOrdinaryFocusName(request.Test)) {
		return workflowRequest{}, errors.New("--test requires one literal test path and exactly one nonempty --step")
	}
	if parsed.packageCount != 0 && (parsed.stepCount != 1 || request.SelectedStep == "" || !validOrdinaryPackagePath(request.Package)) {
		return workflowRequest{}, errors.New("--package requires one exact repository package and exactly one nonempty --step")
	}
	if len(request.Scenarios) != 0 || parsed.recoveryCount != 0 {
		if parsed.stepCount != 1 || request.SelectedStep == "" || parsed.testCount != 0 || parsed.packageCount != 0 {
			return workflowRequest{}, errors.New("scenario and recovery focus require one run step without test, package focus")
		}
		for _, selector := range request.Scenarios {
			if !validScenarioSelector(selector) {
				return workflowRequest{}, errors.New("--scenario requires a literal known case or group")
			}
		}
		if request.RecoveryMode != "" && request.RecoveryMode != "both" && request.RecoveryMode != "enabled" && request.RecoveryMode != "disabled" {
			return workflowRequest{}, errors.New("--recovery-mode requires both, enabled or disabled")
		}
	}
	return request, nil
}

func resolveWorkflow(ctx context.Context, root string, request workflowRequest) (workflowPlan, error) {
	scenarioFocus := len(request.Scenarios) != 0 || request.RecoveryMode != ""
	if scenarioFocus && (request.SelectedStep == "" || request.Test != "" || request.Package != "") {
		return workflowPlan{}, errors.New("scenario and recovery focus require one run step")
	}
	if request.Test != "" && (request.SelectedStep == "" || !validOrdinaryFocusName(request.Test)) || request.Package != "" && (request.SelectedStep == "" || !validOrdinaryPackagePath(request.Package)) {
		return workflowPlan{}, errors.New("focus requires one explicit step and literal package/test paths")
	}

	file, policy, err := readWorkflowConfiguration(request)
	if err != nil {
		return workflowPlan{}, err
	}
	if err := validateConfiguredParallelGroups(file.Steps); err != nil {
		return workflowPlan{}, err
	}
	policy, err = executionWithinContext(ctx, policy)
	if err != nil {
		return workflowPlan{}, err
	}
	ctx = withExecutionCapacity(ctx, policy)
	directory, err := filepath.Abs(filepath.Dir(request.Path))
	if err != nil {
		return workflowPlan{}, err
	}
	relative := func(path string) string {
		if path == "" || filepath.IsAbs(path) {
			return path
		}
		return filepath.Join(directory, path)
	}
	profile, err := resolveVerificationProfile(file.Profile)
	if err != nil {
		return workflowPlan{}, err
	}
	if _, present := ctx.Value(racePolicyContextKey{}).(bool); !present {
		ctx = withRacePolicy(ctx, request.Race)
	}
	plan := workflowPlan{Race: raceEnabled(ctx), Execution: policy, SchemaVersion: 1, Name: file.Name, Profile: profile}
	seen := map[string]bool{}
	for _, step := range file.Steps {
		if !telemetryLabel.MatchString(step.ID) || seen[step.ID] {
			return workflowPlan{}, errors.New("workflow step IDs must be known labels and unique")
		}
		seen[step.ID] = true
		resolved := resolvedWorkflowStep{ID: step.ID, Kind: step.Kind, Selected: request.SelectedStep == "" || request.SelectedStep == step.ID}
		if resolved.Selected {
			resolved.ParallelGroup = step.ParallelGroup
		}
		repetitions := 1
		if step.Repetitions != nil {
			if step.Kind != "unit" && step.Kind != "runner-tests" && step.Kind != "component-tests" && step.Kind != "run" {
				return workflowPlan{}, fmt.Errorf("step %s: repetitions do not apply to its kind", step.ID)
			}
			repetitions = *step.Repetitions
			if repetitions < 1 || repetitions > 100 {
				return workflowPlan{}, fmt.Errorf("step %s: repetitions must be from 1 through 100", step.ID)
			}
		}
		if scenarioFocus && resolved.Selected && step.Kind != "run" {
			return workflowPlan{}, errors.New("scenario and recovery focus apply only to a run step")
		}
		if err := resolveWorkflowFocus(step, request, &resolved); err != nil {
			return workflowPlan{}, fmt.Errorf("step %s: %w", step.ID, err)
		}
		if step.Kind != "component-tests" && step.Profile != "" {
			return workflowPlan{}, fmt.Errorf("step %s: profile does not apply to its kind", step.ID)
		}
		if step.Kind != "assembly-checks" && step.Responsibility != "" {
			return workflowPlan{}, fmt.Errorf("step %s: responsibility does not apply to its kind", step.ID)
		}
		if step.Kind != "unit" && step.Packages != nil || step.Kind != "fuzz" && step.Targets != nil || step.Kind != "run" && (step.Scenarios != nil || step.Suites != nil || step.Environment != "" || step.AdditionalProviders != nil || step.RecoveryMode != "" || step.Limits != "" || step.SmokePolicy != "" || step.TelemetryConfig != "" || step.LogLevel != "") {
			return workflowPlan{}, fmt.Errorf("step %s: fields do not apply to its kind", step.ID)
		}
		switch step.Kind {
		case "component-tests":
			if step.Profile == "" {
				return workflowPlan{}, fmt.Errorf("step %s: component-tests requires an explicit profile", step.ID)
			}
			resolved.Profile, err = resolveVerificationProfile(step.Profile)

		case "unit":
			resolved.Packages, err = resolveUnitPackages(step.Packages)
			if err == nil && resolved.Selected {
				err = validateUnitPackages(ctx, root, resolved.Packages)
				if err == nil && resolved.OrdinaryFocus != nil {
					_, err = resolveOrdinaryUnitPackage(ctx, root, resolved.Packages, resolved.OrdinaryFocus.PackagePath)
				}
			}
		case "fuzz":
			var targets []fuzzSpecification
			targets, err = selectFuzzTargets(step.Targets)
			for _, target := range targets {
				resolved.Targets = append(resolved.Targets, target.Name)
			}
			resolved.FuzzSeconds = int(fuzzDuration / time.Second)
		case "run":
			generatorPath := ""
			if step.AdditionalProviders != nil {
				var known bool
				generatorPath, known = step.AdditionalProviders["cloudflare"]
				if !known || len(step.AdditionalProviders) != 1 || generatorPath == "" {
					return workflowPlan{}, fmt.Errorf("step %s: unsupported additional provider configuration", step.ID)
				}
			}
			if step.RecoveryMode != "enabled" && step.RecoveryMode != "disabled" && step.RecoveryMode != "both" {
				return workflowPlan{}, fmt.Errorf("step %s: explicit recovery_mode required", step.ID)
			}
			if !resolved.Selected {
				break
			}
			if request.RecoveryMode != "" {
				if step.RecoveryMode != "both" && step.RecoveryMode != request.RecoveryMode {
					return workflowPlan{}, errors.New("requested recovery mode widens or replaces the selected step")
				}
				step.RecoveryMode = request.RecoveryMode
			}
			paths := make([]string, len(step.Suites))
			for i, path := range step.Suites {
				paths[i] = relative(path)
			}
			configuration := request.TelemetryConfig
			if configuration == "" {
				configuration = relative(step.TelemetryConfig)
			}
			logLevel := request.LogLevel
			if logLevel == "" {
				logLevel = step.LogLevel
			}

			var runs []resolvedWorkflowStep
			runs, err = resolveWorkflowRuns(step, paths, relative(step.Environment), relative(generatorPath), relative(step.Limits), configuration, logLevel, request.Scenarios)
			if err == nil {
				for i := range runs {
					runs[i].request.execution = policy.clone()
					summary := runs[i].request.effectiveTelemetry
					if request.TelemetryConfig != "" {
						summary.ConfigurationSource = "command"
					} else if step.TelemetryConfig != "" {
						summary.ConfigurationSource = "workflow"
					}
					if request.LogLevel != "" {
						summary.LevelOverrideSource = "command"
					} else if step.LogLevel != "" {
						summary.LevelOverrideSource = "workflow"
					}
					if err := setVerificationProfile(&runs[i].request, profile); err != nil {
						return workflowPlan{}, err
					}
					runs[i].Run.Race = plan.Race
				}
				plan.Steps = append(plan.Steps, runs...)
				continue
			}
		case "assembly-checks":
			if !validAssemblyResponsibility(step.Responsibility) {
				err = errors.New("assembly-checks requires responsibility common, aws or gcp")
			}
			resolved.Responsibility = step.Responsibility
		case "lint", "runner-tests":
		default:
			err = errors.New("unknown workflow step kind")
		}
		if err != nil {
			return workflowPlan{}, fmt.Errorf("step %s: %w", step.ID, err)
		}
		plan.Steps = append(plan.Steps, expandWorkflowRepetitions(resolved, repetitions)...)
	}
	if request.SelectedStep != "" && !seen[request.SelectedStep] {
		return workflowPlan{}, errors.New("selected workflow step does not exist")
	}
	resolvedIDs := map[string]bool{}
	for _, step := range plan.Steps {
		if step.ConfiguredStep != "" && seen[step.ID] {
			return workflowPlan{}, fmt.Errorf("expanded step ID %s conflicts with a configured step", step.ID)
		}
		if resolvedIDs[step.ID] {
			return workflowPlan{}, fmt.Errorf("resolved step ID %s is repeated", step.ID)
		}
		resolvedIDs[step.ID] = true
	}
	if err := validateResolvedParallelGroups(plan); err != nil {
		return workflowPlan{}, err
	}
	return plan, nil
}

// Saved and command focus share one admission path. A command can narrow a
// saved literal subtree or package; it cannot replace its configured bounds.
func resolveWorkflowFocus(step workflowStep, request workflowRequest, resolved *resolvedWorkflowStep) error {
	var err error
	if resolved.Selected {
		step, err = requestedWorkflowStep(step, request)
		if err != nil {
			return err
		}
	}
	if err := validateWorkflowStepConfiguration(step); err != nil {
		return err
	}
	resolved.Tests = slices.Clone(step.Tests)
	if len(step.Tests) == 0 && step.Package == "" {
		return nil
	}
	switch step.Kind {
	case "assembly-checks":
		if len(step.Tests) != 1 {
			return errors.New("provider assembly focus requires one literal test path")
		}
		resolved.AssemblyFocus = &assemblyFocus{Requested: step.Tests[0], Provider: step.Responsibility}
		resolved.AssemblyPreparation = &assemblyPreparation{}
	case "component-tests":
		resolved.Focus = &componentFocus{Tests: slices.Clone(step.Tests), Package: componentPackage}
	case "unit", "runner-tests":
		resolved.OrdinaryFocus = &ordinaryFocus{PackagePath: step.Package, Tests: slices.Clone(step.Tests)}
		resolved.OrdinaryPreparation = &ordinaryPreparation{}
		resolved.OrdinarySelection = []ordinaryExecution{}
	default:
		return errors.New("test selection does not apply to this step kind")
	}
	return nil
}

func expandWorkflowRepetitions(step resolvedWorkflowStep, repetitions int) []resolvedWorkflowStep {
	if repetitions == 1 || step.Kind == "run" {
		return []resolvedWorkflowStep{step}
	}
	prefix := step.ID
	// Keep every formerly valid configured label usable at the upper bound.
	// ConfiguredStep retains the exact original even when its suffix needs room.
	if len(prefix)+len("-r100") > 96 {
		digest := sha256.Sum256([]byte(prefix))
		prefix = prefix[:64] + "-" + hex.EncodeToString(digest[:8])
	}
	steps := make([]resolvedWorkflowStep, 0, repetitions)
	for repetition := 1; repetition <= repetitions; repetition++ {
		execution := step
		execution.Tests = slices.Clone(step.Tests)
		execution.ID = fmt.Sprintf("%s-r%d", prefix, repetition)
		execution.ConfiguredStep, execution.Repetitions, execution.Repetition = step.ID, repetitions, repetition
		if step.OrdinaryFocus != nil {
			focus := *step.OrdinaryFocus
			focus.Tests = slices.Clone(focus.Tests)
			execution.OrdinaryFocus = &focus
			execution.OrdinaryPreparation = &ordinaryPreparation{}
			execution.OrdinarySelection = []ordinaryExecution{}
		}
		if step.Focus != nil {
			focus := *step.Focus
			focus.Tests = slices.Clone(focus.Tests)
			execution.Focus = &focus
		}
		steps = append(steps, execution)
	}
	return steps
}

// Expand a cloud step before execution so each mode keeps the existing run
// ownership, budget, evidence and cleanup lifecycle. Resolve both before either
// starts; a missing recovery bundle must not leave a partially executed step.
func resolveWorkflowRuns(step workflowStep, suites []string, environmentPath, generatorPath, limitsPath, telemetryConfig, logLevel string, focus []string) ([]resolvedWorkflowStep, error) {
	modes := []string{step.RecoveryMode}
	if step.RecoveryMode == "both" {
		var environment environmentFile
		if err := readSelectionFile(environmentPath, &environment); err != nil {
			return nil, errors.New("invalid workflow environment")
		}
		if environment.Mode == "live" {
			modes = []string{"enabled", "disabled"}
		}
	}
	repetitions := 1
	if step.Repetitions != nil {
		repetitions = *step.Repetitions
	}
	var runs []resolvedWorkflowStep
	for _, mode := range modes {
		run := resolvedWorkflowStep{ID: step.ID, Kind: "run", Selected: true, ParallelGroup: step.ParallelGroup}
		if len(modes) > 1 {
			run.ID += "-" + mode
			run.ConfiguredStep = step.ID
		}
		var err error
		run.request, err = resolveSavedRun(suites, environmentPath, generatorPath, limitsPath, mode, telemetryConfig, logLevel, catalog.SmokePolicy(step.SmokePolicy), repetitions, true, scenarioSelection{Saved: step.Scenarios, Focus: focus})
		if err != nil {
			return nil, fmt.Errorf("recovery_mode %s: %w", mode, err)
		}
		if run.request.Suite == "live" {
			allowance, err := loadLimits(run.request.Limits)
			if err != nil {
				return nil, err
			}
			run.Limits, run.request.Allowance = &allowance, &allowance
		}
		run.Run = run.request.Resolved
		runs = append(runs, run)
	}
	return runs, nil
}

type workflowResult struct {
	SourceChanged     bool            `json:"source_changed,omitempty"`
	SourceObservation *records.Source `json:"source_observation,omitempty"`
	Race              *bool           `json:"race,omitempty"`
	ExecutionSource   *records.Source `json:"execution_source,omitempty"`
	executions        map[string]workflowStepExecution
	RepetitionGroups  []workflowRepetitionGroup `json:"repetition_groups,omitempty"`
	Supervisor        *recordedSupervisor       `json:"supervisor,omitempty"`
	Execution         recordedExecutionPolicy   `json:"execution"`
	Profile           string                    `json:"profile"`
	SchemaVersion     int                       `json:"schema_version"`
	RunID             string                    `json:"run_id"`
	Name              string                    `json:"name"`
	Source            records.Source            `json:"source"`
	Native            *nativeTuple              `json:"native,omitempty"`
	StartedAt         time.Time                 `json:"started_at"`
	FinishedAt        *time.Time                `json:"finished_at,omitempty"`
	Outcome           string                    `json:"outcome"`
	Failure           string                    `json:"failure,omitempty"`
	Steps             []workflowStepResult      `json:"steps"`
}

type workflowStepExecution struct {
	finishedAt     time.Time
	componentOwner *componentRun
	Err            error
	NotRunReason   string
	Recovery       *liveRecovery
	Evidence       string
	Preparation    *checkDiagnostics
	Ordinary       *ordinaryStepEvidence
	Component      *componentRunRecord
	Assembly       *offlineEvidence
	Fuzz           []*fuzzEvidence
	Suite          *runRecord
}

type workflowStepResult struct {
	resolvedWorkflowStep
	EffectiveTelemetry *effectiveTelemetry `json:"effective_telemetry,omitempty"`
	Outcome            string              `json:"outcome"`
	NotRunReason       string              `json:"not_run_reason,omitempty"`
	StartedAt          *time.Time          `json:"started_at,omitempty"`
	FinishedAt         *time.Time          `json:"finished_at,omitempty"`
	ElapsedSeconds     float64             `json:"elapsed_seconds"`
	Log                string              `json:"log,omitempty"`
	Evidence           string              `json:"evidence,omitempty"`
}

func (execution workflowStepExecution) diagnostics() *checkDiagnostics {
	if execution.Ordinary != nil {
		return execution.Ordinary.Diagnostics
	}
	if execution.Component != nil {
		if execution.Component.Checks != nil {
			return execution.Component.Checks.Diagnostics
		}
		return execution.Component.preparation
	}
	if execution.Assembly != nil {
		return execution.Assembly.Diagnostics
	}
	if execution.Suite != nil && execution.Suite.BuildClosure != nil && execution.Suite.BuildClosure.LocalChecks != nil {
		return execution.Suite.BuildClosure.LocalChecks.Diagnostics
	}
	return execution.Preparation
}

func workflowPreparationTransferred(execution workflowStepExecution) bool {
	d := execution.Preparation
	if d == nil {
		return false
	}
	return execution.Ordinary != nil && execution.Ordinary.Diagnostics == d || execution.Component != nil && execution.Component.Checks != nil && execution.Component.Checks.Diagnostics == d || execution.Assembly != nil && execution.Assembly.Diagnostics == d || execution.Suite != nil && suiteOwnsPreparation(execution.Suite, d)
}
func workflowExecutionJoined(execution workflowStepExecution, err error) bool {
	joined := toolCommandsJoined(err)
	if execution.Preparation != nil {
		for _, command := range execution.Preparation.Commands {
			joined = joined && command.Joined && (command.ModulePreparation == nil || command.ModulePreparation.Joined)
		}
	}
	if diagnostics := execution.diagnostics(); diagnostics != nil {
		for _, command := range diagnostics.Commands {
			joined = joined && command.Joined && (command.ModulePreparation == nil || command.ModulePreparation.Joined)
		}
	}
	if execution.Suite != nil {
		joined = joined && runProcessesJoined(*execution.Suite)
	}
	return joined
}

func runWorkflow(ctx context.Context, root, bootstrap string, plan workflowPlan, output io.Writer) (workflowResult, error) {
	if plan.prepared == nil {
		prepared, prepareErr := prepareWorkflow(ctx, root, bootstrap, plan, output)
		if prepareErr != nil {
			return executeCommandWorkflow(ctx, root, bootstrap, prepared, prepareErr, output)
		}
		result, runErr := runPreparedWorkflow(ctx, root, bootstrap, prepared, output)
		tail, cancel := finalizationContext(ctx)
		defer cancel()
		return result, errors.Join(runErr, prepared.close(tail))
	}
	policy, policyErr := executionWithinContext(ctx, plan.Execution)
	if policyErr != nil {
		return workflowResult{executions: maps.Clone(plan.currentExecutions)}, policyErr
	}
	plan.Execution = policy
	ctx = withRacePolicy(ctx, plan.Race)
	ctx = withExecutionCapacity(ctx, plan.Execution)
	var owned []privateDirectory
	ordinary := plan.prepared.ordinary
	componentGroups := plan.prepared.components
	defer func() {
		for _, group := range componentGroups {
			group.cancel()
		}
	}()
	var checkedModules *moduleCheckFacts
	execute := func(ctx context.Context, step resolvedWorkflowStep, output io.Writer, directory string) (execution workflowStepExecution, err error) {
		prefix := step.currentPrefix
		if prefix == nil {
			prefix = plan.currentExecutions[step.ID].Preparation
		}
		if prefix == nil {
			prefix = &checkDiagnostics{Preparation: "passed"}
		}
		defer func() {
			if execution.Preparation == nil {
				execution.Preparation = prefix
			}
			if execution.Ordinary != nil && execution.Ordinary.Diagnostics == execution.Preparation {
				execution.Preparation = nil
			}
			if execution.Component != nil && execution.Component.Checks != nil && execution.Component.Checks.Diagnostics == execution.Preparation {
				execution.Preparation = nil
			}
			if execution.Assembly != nil && execution.Assembly.Diagnostics == execution.Preparation {
				execution.Preparation = nil
			}
			if execution.Suite != nil && suiteOwnsPreparation(execution.Suite, execution.Preparation) {
				execution.Preparation = nil
			}

			err = errors.Join(err, writeCheckDiagnostics(output, prefix))
		}()

		if failure := plan.prepared.preparationFailures[workflowPreparationKey(step)]; failure != nil && step.Kind != "unit" && step.Kind != "runner-tests" {
			reason := "preparation_failed"
			var shared *sharedArtifactFailure
			if errors.As(failure, &shared) {
				reason = "shared_preparation_failed"
			}
			return workflowStepExecution{NotRunReason: reason}, failure
		}
		switch step.Kind {
		case "unit", "runner-tests":
			var evidence ordinaryStepEvidence
			var err error
			prepared := ordinary[workflowPreparationKey(step)]
			if prepared == nil {
				return workflowStepExecution{}, errors.New("ordinary step was not prepared")
			}
			err = prepared.execute(ctx, root, plan.Profile, &evidence, output)
			if err == nil {
				err = validateOrdinaryStepResult(evidence)
				if err == nil && (evidence.Race == nil || *evidence.Race != raceEnabled(ctx)) {
					err = errors.New("ordinary build race policy differs from invocation")
				}
			}
			if err != nil {
				err = errors.Join(err, writeAssemblyDiagnosticBody(output, err))
			}
			err = errors.Join(err, writeCheckDiagnostics(output, evidence.Diagnostics))
			err = errors.Join(err, writeOrdinaryRelations(output, evidence.Tests))
			path := ""
			return workflowStepExecution{Evidence: path, Ordinary: &evidence}, err
		case "lint":
			var err error
			checkedModules, err = runLint(ctx, root, bootstrap, output)
			if err != nil {
				err = errors.Join(err, writeAssemblyDiagnosticBody(output, err))
			}
			diagnostics := prefix
			err = errors.Join(err, writeCheckDiagnostics(output, diagnostics))
			return workflowStepExecution{Preparation: diagnostics}, err
		case "assembly-checks":
			requested := ""
			if step.AssemblyFocus != nil {
				requested = step.AssemblyFocus.Requested
			}
			var value *assembly
			if stored, exists := plan.prepared.providers[step.ID]; exists {
				value = &stored
			}
			initial := prefix
			if step.Responsibility != "common" && value != nil {
				value.currentPrefix = prefix
				initial = nil
			}
			record, err := runOfflineResponsibilityPrepared(initial, ctx, root, bootstrap, plan.Profile, step.Responsibility, requested, output, value, checkedModules)
			return workflowStepExecution{Assembly: record}, err
		case "component-tests":
			var err error
			requested := slices.Clone(step.Tests)
			group := componentGroups[workflowPreparationKey(step)]
			if group == nil {
				return workflowStepExecution{}, errors.New("component step was not prepared")
			}
			component, err := runComponentsOwned(prefix, ctx, root, bootstrap, step.Profile, requested, executionCapacityFromContext(ctx).Parallel, output, group)
			if component == nil {
				return workflowStepExecution{}, err
			}
			return workflowStepExecution{Evidence: component.evidencePath, Component: &component.record, componentOwner: component}, err
		case "fuzz":
			selection := plan.prepared.fuzz[step.ID]
			if selection == nil {
				return workflowStepExecution{}, errors.New("fuzz step was not prepared")
			}
			records, err := runPreparedFuzz(ctx, root, selection, output)
			execution := workflowStepExecution{Fuzz: records}
			if len(records) == 0 {
				execution.Preparation = selection.preparation.snapshot()
				err = errors.Join(err, writeCheckDiagnostics(output, execution.Preparation))
			}
			return execution, err
		case "run":
			selection := plan.prepared.suites[step.ID]
			if selection == nil {
				return workflowStepExecution{}, errors.New("scenario step was not prepared")
			}
			result, err := selection.executeOwned(prefix, ctx, root, bootstrap, step.request.components, output)
			return workflowStepExecution{Evidence: result.Evidence, Suite: result.Record, Recovery: result.Recovery, Preparation: result.preparation}, err
		}
		return workflowStepExecution{}, errors.New("unknown workflow step kind")
	}
	return executeWorkflow(ctx, root, plan, output, &owned, ordinary, execute)
}

func validateOrdinaryStepResult(evidence ordinaryStepEvidence) error {
	if (evidence.Focus != nil || evidence.Preparation != nil || evidence.Execution != nil || evidence.SelectedComplete) && !validOrdinaryFocusedEvidence(evidence) {
		return errors.New("ordinary selected completion evidence is incomplete")
	}
	if evidence.Complete && !completeOrdinaryEvidence(evidence) {
		return errors.New("selected ordinary evidence cannot establish complete scope")
	}
	if evidence.Race == nil || !validRaceOptions(*evidence.Race, evidence.RaceOptions) {
		return errors.New("ordinary step lacks the accepted race policy")
	}
	return nil
}

func writeOrdinaryRelations(output io.Writer, tests []ordinaryTest) error {
	for _, test := range tests {
		if test.Relation != nil {
			if _, err := fmt.Fprintf(output, "Check relation: %s\n", retainedSecretMaterialDescription(test.Package, test.Name, test.Relation)); err != nil {
				return err
			}
		}
	}
	return nil
}

func executeWorkflow(ctx context.Context, root string, plan workflowPlan, output io.Writer, owned *[]privateDirectory, ordinary map[string]*preparedOrdinaryGroup, execute func(context.Context, resolvedWorkflowStep, io.Writer, string) (workflowStepExecution, error)) (result workflowResult, err error) {
	result.executions = maps.Clone(plan.currentExecutions)
	if plan.prepared != nil {
		if err := plan.prepared.retainWorkflowPreparation(&result, nil, output); err != nil {
			return result, err
		}
		plan.currentExecutions = maps.Clone(result.executions)
	}
	plan.Steps = slices.Clone(plan.Steps)
	if plan.currentExecutions == nil {
		plan.currentExecutions = map[string]workflowStepExecution{}
	}
	priorClaims := map[checkAcquisition]*checkDiagnostics{}
	for index := range plan.Steps {
		step := &plan.Steps[index]
		if !step.Selected {
			continue
		}
		execution := plan.currentExecutions[step.ID]
		if execution.Preparation == nil {
			execution.Preparation = &checkDiagnostics{Preparation: "passed"}
		}
		if plan.prepared != nil {
			key := workflowPreparationKey(*step)
			var owner any
			if group := plan.prepared.components[key]; group != nil {
				owner = group
			} else if group := plan.prepared.ordinary[key]; group != nil {
				owner = group
			}
			if owner != nil {
				token := checkAcquisition{owner, key}
				if previous := priorClaims[token]; previous != nil {
					if err := execution.Preparation.inheritAcquisitionClaim(owner, key, previous); err != nil {
						return result, err
					}
				} else if execution.Preparation.hasAcquisition(owner, key) {
					priorClaims[token] = execution.Preparation
				}
			}
		}
		plan.currentExecutions[step.ID] = execution
		step.currentPrefix = execution.Preparation
	}
	result.executions = maps.Clone(plan.currentExecutions)
	reportedPreparations := map[string]*checkDiagnostics{}
	if plan.prepared != nil {
		defer func() {
			err = errors.Join(err, plan.prepared.retainWorkflowPreparation(&result, reportedPreparations, output))
		}()
	}
	if err := validateResolvedParallelGroups(plan); err != nil {
		return result, safeCheckFailure("preparation", "none", err)
	}
	ctx = withExecutionCapacity(ctx, plan.Execution)
	ctx = withRacePolicy(ctx, plan.Race)
	ctx = context.WithValue(ctx, workflowTestBarrierContextKey{}, &repetitionBarrier{})
	live := false
	for _, step := range plan.Steps {
		live = live || step.Selected && step.Kind == "run" && step.request.Suite == "live"
	}
	observedSource, _, err := sourceObservation(ctx, root)
	if err != nil {
		return result, err
	}
	source := records.Source{Revision: observedSource.Revision, ObservationIncomplete: observedSource.ObservationIncomplete}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return result, err
	}
	started := time.Now().UTC()
	id := hex.EncodeToString(random[:])
	var directory string
	var recoveryOwner *currentDirectory
	current, err := newCurrentDirectory("enkv-workflow-")
	if err != nil {
		return result, err
	}
	setupComplete := false
	defer func() {
		if !setupComplete {
			err = errors.Join(err, current.remove(true))
		}
	}()
	scratch := current.path
	if live {
		relative, pathErr := records.RunRelative(id, started)
		if pathErr != nil {
			return result, pathErr
		}
		directory, err = records.SafePath(root, filepath.Join("tests/workflows/runs", relative))
		if err != nil {
			return result, err
		}
		if err = os.MkdirAll(filepath.Dir(directory), 0700); err == nil {
			err = os.Mkdir(directory, 0700)
		}
		if err == nil {
			err = os.Mkdir(filepath.Join(directory, "private"), 0700)
		}
		if err == nil {
			identity, statErr := os.Lstat(directory)
			if statErr != nil {
				err = statErr
			} else {
				recoveryOwner = &currentDirectory{path: directory, identity: identity}
			}
		}

	} else {
		directory = scratch
	}
	if err != nil {
		return result, err
	}
	private, err := createPrivateDirectory("", "hermetic", id, scratch)
	if err != nil {
		return result, err
	}
	ctx, err = private.protectedFixtureContext(ctx)
	if err != nil {
		return result, err
	}
	ctx = context.WithValue(ctx, workflowScratchContextKey{}, current)
	result = workflowResult{Race: raceSetting(plan.Race), executions: maps.Clone(plan.currentExecutions), Execution: recordExecutionPolicy(plan.Execution), SchemaVersion: 1, RunID: id, Name: plan.Name, Profile: plan.Profile, Source: source, SourceObservation: &observedSource, Native: &nativeTuple{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}, StartedAt: started, Outcome: "incomplete"}
	if result.executions == nil {
		result.executions = map[string]workflowStepExecution{}
	}
	ctx = context.WithValue(ctx, workflowRunIDContextKey{}, result.RunID)
	for _, step := range plan.Steps {
		outcome := "not_run"
		if !step.Selected {
			outcome = "not_selected"
		}
		result.Steps = append(result.Steps, workflowStepResult{resolvedWorkflowStep: step, EffectiveTelemetry: step.request.effectiveTelemetry.clone(), Outcome: outcome})
	}
	path := filepath.Join(directory, "workflow.json")
	save := func() error {
		groups, groupErr := workflowRepetitionGroups(root, result)
		result.RepetitionGroups = groups
		if groupErr != nil {
			return groupErr
		}
		if live {
			return records.WriteJSON(path, result, 0600)
		}
		return nil
	}
	joined, completed := true, false
	var failures []error
	defer func() {
		failures = append(failures, err)
		for _, group := range ordinary {
			failures = append(failures, group.close())
		}
		err = errors.Join(failures...)
		if !completed && err == nil {
			joined = false
			err = errors.New("workflow execution did not complete")
		}
		var observationErr error
		result.SourceChanged, observationErr = finishSourceObservation(ctx, root, observedSource, output)
		err = errors.Join(err, observationErr)
		finished := time.Now().UTC()
		result.FinishedAt, result.Outcome = &finished, "passed"
		if err != nil {
			result.Outcome = "failed"
			if result.Failure == "" {
				result.Failure = "workflow_failed"
			}
			for i := range result.Steps {
				if result.Steps[i].Outcome == "running" {
					result.Steps[i].Outcome = "failed"
					result.Steps[i].FinishedAt = &finished
				}
				if result.Steps[i].Outcome == "not_run" && result.Steps[i].NotRunReason == "" {
					result.Steps[i].NotRunReason = "execution_stopped"
					if ctx.Err() != nil {
						result.Steps[i].NotRunReason = "interrupted"
					}
				}
			}
		}
		err = errors.Join(err, save())
		joined = joined && toolCommandsJoined(err)
		if owned != nil && joined {
			cleanupErrors := []error{err}
			for _, owner := range *owned {
				cleanupErrors = append(cleanupErrors, owner.remove())
			}
			err = errors.Join(cleanupErrors...)
		}
		if current != nil {
			err = errors.Join(err, current.remove(joined))
		}
		if recoveryOwner != nil && result.Outcome == "passed" && err == nil && joined {
			var cleanupErrors []error
			for _, execution := range result.executions {
				if execution.Recovery != nil && execution.Suite != nil {
					cleanupErrors = append(cleanupErrors, execution.Recovery.complete(*execution.Suite))
				}
			}
			err = errors.Join(cleanupErrors...)
			if err == nil {
				err = recoveryOwner.remove(true)
			}
		}

		if err != nil {
			result.Outcome = "failed"
			if result.Failure == "" {
				result.Failure = "workflow_failed"
			}
			if live {
				err = errors.Join(err, save())
			}
		}
		_, printErr := fmt.Fprintf(output, "Workflow %s\n", result.Outcome)
		err = errors.Join(err, printErr)
		if err != nil {
			result.Outcome = "failed"
			err = safeCheckFailure("workflow", "none", err)
		}
	}()
	setupComplete = true
	if err := save(); err != nil {
		return result, err
	}
	var components *componentRun
	startStep := func(i int) (io.Writer, error) {
		step := &result.Steps[i]
		if err := ctx.Err(); err != nil {
			result.Failure = "interrupted"
			return nil, err
		}
		if _, err := fmt.Fprintf(output, "Step %s (%s)\n", step.ID, step.Kind); err != nil {
			return nil, err
		}
		key := workflowPreparationKey(step.resolvedWorkflowStep)
		preparation := plan.currentExecutions[step.ID].Preparation
		reportedPreparations[key] = preparation
		if err := writeCheckDiagnostics(output, preparation); err != nil {
			return nil, err
		}
		now := time.Now().UTC()
		step.StartedAt, step.Outcome = &now, "running"
		if err := save(); err != nil {
			return nil, err
		}
		return output, nil
	}
	finishStep := func(i int, execution workflowStepExecution, stepErr error) error {
		step := &result.Steps[i]
		step.Evidence = execution.Evidence
		key := workflowPreparationKey(step.resolvedWorkflowStep)
		prefix := result.executions[step.ID].Preparation
		if prefix == nil {
			prefix = plan.currentExecutions[step.ID].Preparation
		}
		if execution.Preparation == nil {
			execution.Preparation = prefix
		} else if prefix != nil && execution.Preparation != prefix {
			incoming := execution.Preparation
			prefixBefore := len(prefix.Commands)
			deliveryErr := errors.Join(writeCheckDiagnostics(output, prefix), writeCheckDiagnostics(output, incoming))
			finish, e := beginPreparationPlan(prefix, incoming.Commands)
			if e == nil {
				e = prefix.consumeCommands(incoming.Commands)
			}
			copied := 0
			if e == nil {
				for _, fact := range incoming.Commands {
					if e = prefix.append(fact); e != nil {
						break
					}
					copied++
				}
			}
			if e != nil {
				// Both inputs are already acquired. Preserve them even when final admission refuses the union.
				prefix.Commands = append(prefix.Commands, incoming.Commands[copied:]...)
				prefix.weightsValid = false
				prefix.planned = true
				prefix.plannedCommandLimit = len(prefix.Commands)
			}
			if prefix.attempted == prefixBefore {
				prefix.attempted += incoming.attempted
			}
			if incoming.deliveryFailed {
				prefix.deliveryFailed = true
				prefix.deliveryError = errors.Join(prefix.deliveryError, incoming.deliveryError)
			}
			for claim := range incoming.acquisitions {
				if prefix.acquisitions == nil {
					prefix.acquisitions = map[checkAcquisition]struct{}{}
				}
				prefix.acquisitions[claim] = struct{}{}
			}
			if finish != nil {
				finish()
			}
			stepErr = errors.Join(stepErr, deliveryErr, e)
			if incoming.Preparation != "passed" {
				prefix.Preparation = incoming.Preparation
			}
			execution.Preparation = prefix
		}
		if workflowPreparationTransferred(execution) {
			execution.Preparation = nil
		}
		stepErr = errors.Join(stepErr, writeCheckDiagnostics(output, execution.Preparation))

		if execution.componentOwner != nil {
			if owned != nil {
				*owned = append(*owned, execution.componentOwner.privateOwner)
			}
			if step.ParallelGroup == "" {
				components = nil
				owner := execution.componentOwner
				if stepErr == nil && owner.record.passedFor(source, owner.record.Toolchain) && owner.record.BuildClosure.Race == plan.Race {
					components = owner
				}
			}
		}
		executionJoined := workflowExecutionJoined(execution, stepErr)
		joined = joined && executionJoined
		if plan.prepared != nil {
			plan.prepared.joined = plan.prepared.joined && executionJoined
		}
		if group := ordinary[key]; group != nil {
			group.joined = group.joined && executionJoined
		}
		if !executionJoined {
			stepErr = errors.Join(stepErr, errors.New("workflow has an unjoined consumer"))
		}
		finished := execution.finishedAt
		if finished.IsZero() {
			finished = time.Now().UTC()
		}
		step.FinishedAt, step.ElapsedSeconds = &finished, finished.Sub(*step.StartedAt).Seconds()
		step.Outcome = "passed"
		if stepErr != nil {
			step.Outcome, result.Failure = "failed", "step_failed"
		}
		if execution.NotRunReason != "" {
			step.Outcome, step.NotRunReason = "not_run", execution.NotRunReason
			step.StartedAt, step.FinishedAt, step.ElapsedSeconds = nil, nil, 0
		}
		if err := writeCurrentTestResult(output, step.ID, step.Kind, step.Outcome, execution); err != nil {
			stepErr = errors.Join(stepErr, err)
			step.Outcome, result.Failure = "failed", "result_output_failed"
		}
		execution.Err = stepErr
		result.executions[step.ID] = execution
		if err := errors.Join(stepErr, save()); err != nil {
			return fmt.Errorf("step %s: %w", step.ID, err)
		}
		return nil
	}
	for i := 0; i < len(plan.Steps); i++ {
		step := plan.Steps[i]
		if !step.Selected {
			continue
		}
		end := workflowReadyEnd(plan.Steps, i)
		if plan.prepared != nil && plan.prepared.ready != nil {
			// The prior group has returned and joined. Compile the next ready
			// group with normal resources before admitting its effects.
			var phaseErr error
			ctx, phaseErr = admitPreparedExecution(ctx, rootAdmission{Execution: plan.Execution})
			if phaseErr != nil {
				return result, phaseErr
			}
			for index := i; index < end; index++ {
				if plan.Steps[index].Kind == "run" && plan.Steps[index].request.Suite == "hermetic" {
					plan.prepared.plan.Steps[index].request.components = components
				}
			}
			prepareErr := plan.prepared.prepareSteps(ctx, root, i, end, output)
			for index := i; index < end; index++ {
				plan.Steps[index] = plan.prepared.plan.Steps[index]
				result.Steps[index].resolvedWorkflowStep = plan.Steps[index]
			}
			if err := plan.prepared.retainWorkflowPreparation(&result, reportedPreparations, output); err != nil {
				return result, errors.Join(prepareErr, err)
			}
			plan.currentExecutions = maps.Clone(result.executions)
			for index := i; index < end; index++ {
				plan.Steps[index].currentPrefix = result.executions[plan.Steps[index].ID].Preparation
			}
			if prepareErr != nil && (!containedCheckFailure(ctx, prepareErr)) {
				if !plan.prepared.class.Live {
					return result, errors.Join(prepareErr, writeAssemblyDiagnosticBody(output, prepareErr))
				}
				return result, prepareErr
			}
			request := rootAdmission{Execution: plan.Execution}
			for index := i; index < end; index++ {
				if suite := plan.prepared.suites[plan.Steps[index].ID]; suite != nil {
					request.Big = request.Big || suite.class.Big
					request.Live = request.Live || suite.class.Live
					request.CleanupSeconds = max(request.CleanupSeconds, suite.class.CleanupSeconds)
				}
				if fuzz := plan.prepared.fuzz[plan.Steps[index].ID]; fuzz != nil {
					request.Big = request.Big || fuzz.class.Big
				}
			}
			ctx, phaseErr = admitPreparedExecution(ctx, request)
			if phaseErr != nil {
				return result, phaseErr
			}
		}
		if step.Kind == "run" && step.request.Suite == "hermetic" {
			plan.Steps[i].request.components = components
		}
		for index := i; index < end; index++ {
			if plan.Steps[index].Kind == "run" && plan.Steps[index].request.Suite == "live" {
				plan.Steps[index].request.workflowRunID = result.RunID
			}
		}
		step = plan.Steps[i]
		if end-i > 1 {
			groupJoined, err := executeWorkflowGroup(ctx, root, plan.Steps[i:end], i, scratch, startStep, finishStep, execute)
			joined = joined && groupJoined
			if plan.prepared != nil {
				plan.prepared.joined = plan.prepared.joined && groupJoined
			}
			if group := ordinary[workflowPreparationKey(step)]; group != nil {
				group.joined = group.joined && groupJoined
			}
			if err != nil {
				if !containedCheckFailure(ctx, err) {
					return result, err
				}
				failures = append(failures, err)
			}
			i = end - 1
			continue
		}
		out, err := startStep(i)
		if err != nil {
			return result, err
		}
		evidence, stepErr := execute(ctx, step, out, scratch)
		evidence.finishedAt = time.Now().UTC()
		if err := finishStep(i, evidence, stepErr); err != nil {
			if !containedCheckFailure(ctx, err) {
				return result, err
			}
			failures = append(failures, err)
		}
	}
	completed = true
	return result, nil
}

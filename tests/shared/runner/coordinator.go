package main

import (
	"context"
	"encoding/json"
	"enkv.sh/crypto/testsupport/installedarchive"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

const defaultWorkDuration = 5 * time.Minute

type workerInput struct {
	PublicConfiguration    *publicConfigurationInput             `json:"public_configuration,omitempty"`
	Outputs                *records.OutputFixtureInput           `json:"outputs,omitempty"`
	ConfigurationRecovery  *installedarchive.RecoveryWriterInput `json:"configuration_recovery,omitempty"`
	RecoveryMode           string                                `json:"recovery_mode"`
	Settings               liveSettings                          `json:"settings,omitempty"`
	Limits                 *limits                               `json:"limits,omitempty"`
	Scenarios              []string                              `json:"scenarios"`
	MemberCount            int                                   `json:"member_count,omitempty"`
	Repetitions            int                                   `json:"repetitions"`
	RunID                  string                                `json:"run_id"`
	Prefix                 string                                `json:"prefix,omitempty"`
	ObserverSettings       liveSettings                          `json:"observer_settings,omitempty"`
	DeniedObserverSettings liveSettings                          `json:"denied_observer_settings,omitempty"`
	ReaderSettings         liveSettings                          `json:"reader_settings,omitempty"`
	RecoverySettings       liveSettings                          `json:"recovery_settings,omitempty"`
	DeniedReaderSettings   liveSettings                          `json:"denied_reader_settings,omitempty"`
	ReplacementSettings    map[string]liveSettings               `json:"replacement_settings,omitempty"`
	Generator              *generatorReference                   `json:"generator,omitempty"`
	GeneratorCleanupLedger string                                `json:"generator_cleanup_ledger,omitempty"`
	CleanupRetry           *cleanupRetryInput                    `json:"cleanup_retry,omitempty"`
	CleanupGrant           *cleanupGrantInput                    `json:"cleanup_grant,omitempty"`
	StockRecovery          *records.StockPluginRecoveryInput     `json:"stock_recovery,omitempty"`
	OutputRecovery         *records.PublicOutputRecoveryInput    `json:"output_recovery,omitempty"`

	Participants map[string]string `json:"participants"`
}

type cleanupRetryInput struct {
	TargetIndex uint32 `json:"target_index"`
	Ordinal     uint8  `json:"ordinal"`
}

type suiteExecution struct {
	preparation *checkDiagnostics
	Recovery    *liveRecovery
	Evidence    string
	Record      *runRecord
}

func runSuite(ctx context.Context, root, bootstrap string, request runRequest, output io.Writer) (suiteExecution, error) {
	return runSuiteOwned(nil, ctx, root, bootstrap, request, output)
}
func runSuiteOwned(initial *checkDiagnostics, ctx context.Context, root, bootstrap string, request runRequest, output io.Writer) (execution suiteExecution, err error) {
	d := initial
	if d == nil {
		d = &checkDiagnostics{Preparation: "pending"}
	}
	execution.preparation = d
	setupComplete, printsPreparation := false, true
	defer func() {
		d.cancelReservations()
		if err != nil && !setupComplete {
			d.Preparation = "failed"
		}
		if printsPreparation {
			err = errors.Join(err, writeCheckDiagnostics(output, d))
		}
	}()

	prepared, _ := ctx.Value(preparedSuiteContextKey{}).(*preparedSuite)
	defer func() {
		if err != nil && prepared != nil {
			err = errors.Join(err, prepared.retainPreparation(&execution, output))
		}
	}()
	var componentReuseErr error
	var componentSource records.Source
	var componentToolchain string
	// Refuse an unusable supplied owner before compiling another inventory.
	// Keep its resolved facts for the normal failed-run finalization below.
	if prepared == nil && request.Suite == "hermetic" && request.components != nil && request.Resolved != nil && !request.Resolved.raceMissing {
		if accepted, present := ctx.Value(racePolicyContextKey{}).(bool); present && accepted != request.Resolved.Race {
			return execution, errors.New("scenario race policy differs from invocation")
		}
		reuseContext := withRacePolicy(ctx, request.Resolved.Race)
		source, sourceErr := sourceRevision(reuseContext, root)
		if sourceErr != nil {
			return execution, sourceErr
		}
		var reuseFuture []checkCommandFacts
		reuseFuture = append([]checkCommandFacts{preparationReservationFact("core", false)}, reuseFuture...)
		if e := d.reserveCommands(reuseFuture); e != nil {
			return execution, e
		}
		version, versionErr := d.runGo(reuseContext, root, "core", "version")
		if versionErr != nil {
			return execution, versionErr
		}
		componentSource, componentToolchain = source, strings.TrimSpace(string(version))
		componentReuseErr = verifyScenarioComponentsOwned(d, reuseContext, root, bootstrap, request, componentSource, componentToolchain)
		d.cancelReservations()
	}
	preserveComponentReuseError := func() {
		if componentReuseErr != nil && !errors.Is(err, componentReuseErr) {
			err = errors.Join(componentReuseErr, err)
		}
	}
	defer preserveComponentReuseError()
	if prepared == nil && componentReuseErr == nil {
		if preflight := livePreflightFromContext(ctx, request.Provider); preflight != nil && request.Suite == "live" {
			prepared, err = suiteFromPreflight(request, preflight)
			if err != nil {
				return execution, err
			}
			setupComplete, printsPreparation = true, false
			return runPreparedSuiteResult(ctx, root, bootstrap, prepared, output, execution)
		}
		prepared, err = prepareSuite(nil, ctx, root, bootstrap, request, output)
		if prepared != nil {
			defer func() {
				tail, cancel := finalizationContext(ctx)
				defer cancel()
				err = errors.Join(err, prepared.close(tail))
			}()
		}
		if err != nil {
			var refusal *componentReuseFailure
			if prepared == nil || !errors.As(err, &refusal) {
				return execution, err
			}
			componentReuseErr = err
			componentSource, componentToolchain = prepared.binding.source, prepared.binding.toolchain
			err = nil
		} else {
			setupComplete, printsPreparation = true, false
			return runPreparedSuiteResult(ctx, root, bootstrap, prepared, output, execution)
		}
	}
	if prepared != nil && componentReuseErr == nil {
		if err := prepared.verifyOwned(d, ctx, root); err != nil {
			return execution, err
		}
	}

	if prepared != nil {
		ctx = prepared.binding.context(ctx)
	}
	releaseArtifacts, borrowErr := borrowInvocationArtifacts(ctx)
	if borrowErr != nil {
		return execution, borrowErr
	}
	defer func() {
		releaseArtifacts(toolCommandsJoined(err) && (execution.Record == nil || runProcessesJoined(*execution.Record)))
	}()
	policy, policyErr := executionWithinContext(ctx, request.execution)
	if policyErr != nil {
		return execution, policyErr
	}
	request.execution = policy
	if request.Resolved == nil || request.Resolved.raceMissing {
		return execution, errors.New("accepted scenario race policy unavailable")
	}
	if accepted, present := ctx.Value(racePolicyContextKey{}).(bool); present && accepted != request.Resolved.Race {
		return execution, errors.New("scenario race policy differs from invocation")
	}
	ctx = withRacePolicy(ctx, request.Resolved.Race)
	var environment environmentFile
	if request.environment != nil {
		environment = *request.environment
	}
	selectedOutputs, selectionErr := selectPublicationOutputs(request.Schedule, environment)
	if selectionErr != nil {
		return execution, selectionErr
	}
	// Resolve and display every planned entry before creating run state or fixtures.
	for _, entry := range request.Schedule.Entries {
		if _, err := fmt.Fprintf(output, "%04d %s repetition=%d smoke=%t\n", entry.Sequence, entry.Scenario, entry.Repetition, entry.Smoke); err != nil {
			return execution, errors.New("run schedule output failed")
		}
	}
	var settings liveSettings
	var actorSettings map[string]liveSettings
	var actors *actorIdentityEvidence
	var allowance limits
	if request.Suite == "live" {
		actorSettings, actors, err = loadRunSettings(request)
		if err != nil {
			return execution, err
		}
		if request.environment.Generator != nil {
			var generator generatorReference
			var validateErr error
			if request.environment.PluginAcceptance != nil {
				generator, validateErr = validateStockGenerator(*request.environment.Generator)
			} else {
				generator, validateErr = validateGeneratorRoute(*request.environment.Generator, request.environment.PublicConfiguration)
			}
			if validateErr != nil {
				return execution, validateErr
			}
			request.environment = &environment
			request.environment.Generator = &generator
		}
		settings = actorSettings["authority"]
		if request.Allowance != nil {
			allowance = *request.Allowance
		} else {
			allowance, err = loadLimits(request.Limits)
		}
		if err != nil {
			return execution, err
		}
	}
	binding, bindingErr := prepareBindingOwned(nil, ctx, root, request.Suite == "live")
	if bindingErr != nil {
		return execution, bindingErr
	}
	source, toolchain := binding.source, binding.toolchain
	var rawExecutionSource *records.Source
	if request.Suite == "live" {
		raw := source
		rawExecutionSource = &raw
	}
	if componentReuseErr != nil {
		source, toolchain = componentSource, componentToolchain
	}
	s, err := newRunState(root, request, source, toolchain)
	if err != nil {
		return execution, err
	}
	s.preparation = d
	execution.Record, execution.Recovery = &s.record, s.recovery
	if s.recovery != nil {
		s.recovery.executionSource = rawExecutionSource
		s.record.ExecutionSource = rawExecutionSource
	}
	if request.Suite == "live" {
		s.record.Context, s.record.Limits = safeRunContext(settings), &allowance
	}
	if s.recovery != nil {
		execution.Evidence, err = filepath.Rel(root, filepath.Join(s.directory, "run.json"))
		if err != nil {
			return execution, err
		}
	}
	s.actorSettings, s.record.ActorIdentities = actorSettings, actors
	s.publicationProfiles = selectedOutputs
	if request.environment != nil {
		s.generator = request.environment.Generator
		s.publicOutputs = request.environment.PublicOutputs
	}
	defer func() {
		preserveComponentReuseError()
		if err != nil {
			s.fail("run_failed", "execution")
		}
		s.finish()
		err = errors.Join(err, s.finishCurrentRun(output, err))
		if err != nil {
			s.record.Outcome = "failed"
			if s.record.Failure == nil {
				s.fail("run_failed", "execution")
			}
			if s.recovery != nil {
				err = errors.Join(err, s.save())
			}
		}
		_, printErr := fmt.Fprintf(output, "Run %s\n", s.record.Outcome)
		err = errors.Join(err, printErr)
		if printErr != nil {
			s.record.Outcome = "failed"
		}
		if err == nil && s.record.Outcome != "passed" {
			err = errors.New("run did not pass")
			if s.record.Suite == "live" && len(s.record.Scenarios) == len(s.record.Schedule.Entries) && s.liveCasesSettled() {
				err = &liveCheckFailure{cause: err}
			}
		}
	}()
	if err := s.save(); err != nil {
		return execution, err
	}
	if componentReuseErr != nil {
		if request.components.record.passedFor(source, s.record.Toolchain) && request.components.record.BuildClosure.Race == request.Resolved.Race {
			s.record.Correctness.ComponentRun = &request.components.record
		}
		return execution, componentReuseErr
	}
	ctx, err = s.privateOwner.protectedFixtureContext(ctx)
	if err != nil {
		return execution, err
	}
	build := filepath.Join(s.private, "build")
	if os.Mkdir(build, 0700) != nil {
		return execution, errors.New("assembly directory unavailable")
	}
	stockCase := request.Suite == "live" && scheduleNeedsStockPlugins(request.Schedule)
	if stockCase {
		construction, cancel := context.WithTimeout(ctx, 15*time.Minute)
		binding := prepared.binding
		artifact, buildErr := prepareStockPluginArtifact(construction, root, filepath.Join(build, "stock-plugins"), request.Provider, binding)
		cancel()
		if buildErr != nil {
			return execution, s.retainAssemblyFailure(buildErr)
		}
		if err := linkInvocationDirectory(filepath.Dir(artifact.CLI.Path), filepath.Join(build, "stock-plugins")); err != nil {
			return execution, err
		}
		originalBase := filepath.Dir(artifact.CLI.Path)
		if err := stockPluginPaths(&artifact, func(path string) (string, error) {
			relative, err := filepath.Rel(originalBase, path)
			if err != nil {
				return "", err
			}
			return filepath.Join(build, "stock-plugins", relative), nil
		}); err != nil {
			return execution, err
		}
		s.stockPlugins = &records.StockPluginAcceptanceInput{Fixture: *request.environment.PluginAcceptance, Artifact: artifact, CloudflareAccount: request.environment.Generator.Account, CloudflarePermissionGroup: request.environment.Generator.PermissionGroup}
	}
	var cloudflareBinding *cloudflareAssemblyBinding
	if request.Suite == "live" && request.environment.Generator != nil && !stockCase {
		cloudflareBinding, err = prepareCloudflareAssemblyBinding(ctx, root, build, *request.environment.Generator)
		if err != nil {
			s.fail("assembly_failed", "build")
			return execution, err
		}
	}
	outputBindings, bindingErr := publicationAssemblyBindings(s.record.RunID, selectedOutputs)
	if bindingErr != nil {
		return execution, bindingErr
	}
	s.publicationBuild = build
	future, e := assemblyConstructionCommands(assemblyBindings{Cloudflare: cloudflareBinding, Output: outputBindings})
	if e != nil {
		return execution, e
	}
	if request.components != nil {
		future = nil
	}
	if e := d.reserveCommands(future); e != nil {
		return execution, e
	}
	s.reconstructionReserved = request.Suite == "hermetic"
	var assembled assembly
	if request.components != nil {
		components := request.components
		if request.Suite != "hermetic" || components.assembled.Binary == "" || components.assembled.Closure.Race != request.Resolved.Race {
			return execution, errors.New("component step evidence does not match this scenario run")
		}
		if components.record.passedFor(source, s.record.Toolchain) {
			s.record.Correctness.ComponentRun = &components.record
		}
		assembled = components.assembled
		assembled.Closure.VetElapsedSeconds, assembled.Closure.BuildElapsedSeconds = 0, 0
		if _, err := fmt.Fprintln(output, "Reusing build preparation from the component step"); err != nil {
			return execution, err
		}
		if err := checkAssemblyRace(ctx, assembled); err != nil {
			return execution, err
		}
		if assembled.Closure.Race != request.Resolved.Race {
			assembled, err = compileAssembly(d.runGoEnvironment, d, ctx, root, build, assembled.buildFlags, assembled.Closure, request.Resolved.Race)
		}
	} else {
		assembled, err = buildBoundAssemblyMode(d.runGoEnvironment, d, ctx, root, request.Suite, request.Provider, bootstrap, build, request.Resolved.Race, assemblyBindings{Cloudflare: cloudflareBinding, Output: outputBindings})
	}
	if err != nil {
		s.fail("assembly_failed", "build")
		return execution, s.retainAssemblyFailure(err)
	}
	if err := linkInvocationDirectory(filepath.Dir(assembled.Binary), build); err != nil {
		return execution, err
	}
	for _, artifact := range assembled.Closure.OutputArtifacts {
		binding, bindingErr := outputBinding(artifact.Artifact)
		if bindingErr != nil {
			return execution, bindingErr
		}
		command, _ := outputCommand(binding.StoredProfileID)
		sourceDirectory := artifact.directory
		if sourceDirectory == "" {
			sourceDirectory = filepath.Dir(assembled.Binary)
		}
		for _, suffix := range []string{"", ".installation.json", ".dependency"} {
			if err := linkInvocationFile(filepath.Join(sourceDirectory, command.command)+suffix, filepath.Join(build, command.command)+suffix); err != nil {
				return execution, err
			}
		}
	}
	if stockCase {
		assembled.StockPluginsDirectory = build
		assembled.Closure.StockPlugins, err = stockPluginClosureFromArtifact(build, s.stockPlugins.Artifact)
		if err != nil {
			return execution, err
		}
	}
	if request.Suite == "live" && scheduleNeedsPublicConfiguration(request.Schedule) && !stockCase {
		var publicOutputArtifacts []*outputArtifactClosure
		if outputBindings != nil {
			publicOutputArtifacts = assembled.Closure.OutputArtifacts
		}
		artifact, buildErr := buildPublicConfigurationArtifact(ctx, root, build, publicOutputArtifacts, cloudflareBinding)
		if buildErr != nil {
			s.fail("assembly_failed", "build")
			return execution, s.retainAssemblyFailure(buildErr)
		}
		if err := linkInvocationDirectory(filepath.Dir(artifact.CLI), build); err != nil {
			return execution, err
		}
		artifact = publicConfigurationArtifactFromClosure(build, artifact.closure(), request.Resolved.Race)
		plugins, renderer, pluginErr := preparePublicConfigurationPlugins(ctx, root, build, request.Schedule, publicOutputArtifacts)
		if pluginErr != nil {
			s.fail("assembly_failed", "build")
			return execution, s.retainAssemblyFailure(pluginErr)
		}
		artifact.Plugins = append(artifact.Plugins, plugins...)
		slices.SortFunc(artifact.Plugins, func(a, b records.StockPluginBuild) int { return strings.Compare(a.Metadata.Name, b.Metadata.Name) })
		artifact.ManifestRenderer = renderer
		s.publicConfiguration = &artifact
		assembled.PublicConfigurationCLI = artifact.CLI
		assembled.PublicConfigurationConsumer = artifact.Consumer
		assembled.Closure.PublicConfiguration = artifact.closure()
	}
	if len(prepared.reconstruction) != 0 {
		s.recoverySetup = &assembled
		s.recoveryArtifacts = make(map[string]configurationRecoveryArtifact)
		for _, provider := range slices.Sorted(maps.Keys(prepared.reconstruction)) {
			artifact := prepared.reconstruction[provider]
			retained := filepath.Join(build, filepath.Base(artifact.Path))
			if err := linkInvocationFile(artifact.Path, retained); err != nil {
				return execution, err
			}
			artifact.Path = retained
			s.recoveryArtifacts[provider] = artifact
			assembled.Closure.ReconstructionArtifacts = append(assembled.Closure.ReconstructionArtifacts, artifact.Closure)
		}
	}
	s.record.BuildClosure = &assembled.Closure
	s.failureSources = assembled.FailureSources
	if err := prepared.bindActualOwned(d, ctx, root, &assembled); err != nil {
		return execution, err
	}
	if err := s.save(); err != nil {
		return execution, err
	}
	d.Preparation = "passed"
	if e := writeCheckDiagnostics(output, d); e != nil {
		return execution, e
	}
	setupComplete = true
	return execution, s.executeSchedule(ctx, assembled.Binary, settings, allowance)
}

func sameAssemblyBuild(actual, original assemblyClosure) bool {
	return actual.Suite == original.Suite && actual.Provider == original.Provider &&
		actual.Race == original.Race && actual.RaceOptions == original.RaceOptions &&
		actual.RaceExitSleepMillis == original.RaceExitSleepMillis &&
		actual.BinarySHA256 != "" && actual.BinarySHA256 == original.BinarySHA256 &&
		actual.OverlaySHA256 != "" && actual.OverlaySHA256 == original.OverlaySHA256 &&
		actual.FailureSourcesSHA256 == original.FailureSourcesSHA256 &&
		reflect.DeepEqual(actual.PublicConfiguration, original.PublicConfiguration) &&
		reflect.DeepEqual(actual.StockPlugins, original.StockPlugins) &&
		reflect.DeepEqual(actual.OutputArtifacts, original.OutputArtifacts) &&
		slices.Equal(actual.BuildTags, original.BuildTags) &&
		slices.Equal(actual.ResolvedModules, original.ResolvedModules) &&
		slices.Equal(actual.CompiledImports, original.CompiledImports)
}

func (s *runState) executeSchedule(ctx context.Context, binary string, settings liveSettings, allowance limits) error {
	if s.record.CoverageScope != "" && s.record.CoverageScope != s.record.Suite+"_scenarios" {
		return errors.New("case coverage scope changed")
	}
	s.record.CoverageScope = s.record.Suite + "_scenarios"
	if s.record.Suite == "hermetic" {
		return s.executeHermeticSchedule(ctx, binary)
	}
	identitySHA256, err := caseIdentitySHA256(s.record)
	if err != nil {
		return err
	}
	remaining := allowance
	for _, entry := range s.record.Schedule.Entries {
		if s.record.Suite == "live" && !remaining.valid() {
			s.fail("budget_exhausted", "schedule")
			break
		}
		if ctx.Err() != nil {
			s.fail("interrupted", "schedule")
			break
		}
		shape, err := recordedFixture(entry.Scenario, entry.Members)
		if err != nil {
			return err
		}
		s.record.Scenarios = append(s.record.Scenarios, scenarioResult{Entry: entry, Fixture: shape, Outcome: "incomplete", Children: []workerEvidence{}, PostExit: []workerEvidence{}, Cleanup: unresolvedCleanup()})
		result := &s.record.Scenarios[len(s.record.Scenarios)-1]
		if definition, ok := catalog.DefinitionFor(entry.Scenario); ok {
			result.Title = definition.Title
		}
		if err := s.save(); err != nil {
			return err
		}
		executionErr := s.executeScenario(ctx, binary, settings, remaining, result)
		if executionErr != nil {
			s.failScenario(*result)
		}
		var budgetErr error
		if s.record.Suite == "live" {
			budgetErr = debitBudget(&remaining, result.BudgetReserved, result.Cleanup.BudgetReserved, result.WorkloadElapsed, result.CleanupElapsed)
			if budgetErr != nil {
				s.fail("budget_evidence_unavailable", "budget")
			}
		}
		if err := s.saveLiveCase(*result, identitySHA256); err != nil {
			return errors.Join(executionErr, budgetErr, err)
		}
		if err := s.save(); err != nil {
			return errors.Join(executionErr, budgetErr, err)
		}
		if budgetErr != nil {
			return errors.Join(executionErr, budgetErr)
		}
		if !s.liveCasesSettled() {
			break
		}
	}
	return nil
}

func (s *runState) liveCasesSettled() bool {
	if len(s.record.Scenarios) == 0 {
		return false
	}
	for _, result := range s.record.Scenarios {
		if result.Outcome != "passed" && result.Outcome != "failed" || !scenarioRepetitionCompleted(result) || !scenarioCleanupPassed(result) || result.CleanupWorker == nil || result.CleanupWorker.Outcome != "passed" || result.CleanupWorker.Process != "passed" {
			return false
		}
		for _, worker := range scenarioWorkers(result) {
			if !s.workerRecords[worker.Worker] || !worker.Joined || worker.Outcome != "passed" && worker.Outcome != "failed" {
				return false
			}
		}
		for _, attempt := range result.CleanupAttempts {
			if attempt.Worker == nil || !s.workerRecords[attempt.Worker.Worker] || !attempt.Worker.Joined {
				return false
			}
		}
	}
	return true
}

func (s *runState) failScenario(result scenarioResult) {
	if result.CorrectnessPassed && result.Failure != nil && result.Failure.Stage == "cleanup" {
		s.fail("cleanup_unresolved", "cleanup")
	} else if result.Failure != nil {
		s.fail("scenario_failed", "execution")
	} else {
		s.fail("cleanup_unresolved", "cleanup")
	}
}

type hermeticCaseCompletion struct {
	index    int
	share    int
	state    *runState
	err      error
	returned bool
}

func (s *runState) prepareHermeticDiagnostics(entries []catalog.Entry) ([]*runState, [][]checkCommandFacts, error) {
	if s.preparation == nil {
		s.preparation = &checkDiagnostics{Preparation: "passed"}
	}
	children := make([]*runState, len(entries))
	forecasts := make([][]checkCommandFacts, len(entries))
	var aggregate []checkCommandFacts
	for index := range entries {
		local := s.hermeticCaseState(s.record.Scenarios[index])
		local.preparation = &checkDiagnostics{Preparation: "passed"}
		if catalog.HasFixtureCapability(entries[index].Scenario, catalog.FixtureConfigurationRecovery) && (s.recoverySetup == nil || s.record.Resolved == nil) {
			return nil, nil, errors.New("recovery process assembly unavailable")
		}
		var future []checkCommandFacts
		if err := local.preparation.reserveCommands(future); err != nil {
			return nil, nil, err
		}
		children[index], forecasts[index] = local, future
		aggregate = append(aggregate, future...)
	}
	if !s.reconstructionReserved {
		if err := s.preparation.reserveCommands(aggregate); err != nil {
			return nil, nil, err
		}
		s.reconstructionReserved = true
	}
	return children, forecasts, nil
}
func (s *runState) foldHermeticPreparation(local *runState, future []checkCommandFacts) error {
	if local.preparation == nil || local.preparationFolded {
		return nil
	}
	local.preparationFolded = true
	if local.preparation.Preparation != "passed" {
		s.preparation.Preparation = "failed"
	}
	count := len(local.preparation.Commands)
	var err error
	if count > len(future) {
		err = errors.New("reconstruction command forecast was exceeded")
	}
	err = errors.Join(err, s.preparation.consumeCommands(future[:min(count, len(future))]))
	err = errors.Join(err, s.preparation.retainAcquisition(local, "closed-reconstruction", local.preparation))
	local.preparation.cancelReservations()
	return err
}

func (s *runState) executeHermeticSchedule(parent context.Context, binary string) error {
	capacity := executionCapacityFromContext(parent)
	if err := validateExecutionCapacity(capacity); err != nil {
		return err
	}
	entries := s.record.Schedule.Entries
	s.record.Scenarios = make([]scenarioResult, len(entries))
	for index, entry := range entries {
		shape, err := recordedFixture(entry.Scenario, entry.Members)
		if err != nil {
			return err
		}
		result := scenarioResult{Entry: entry, Fixture: shape, Outcome: "not_run", Children: []workerEvidence{}, PostExit: []workerEvidence{}, Cleanup: noCleanup()}
		if definition, ok := catalog.DefinitionFor(entry.Scenario); ok {
			result.Title = definition.Title
		}
		s.record.Scenarios[index] = result
	}
	if len(entries) == 0 {
		return s.save()
	}
	children, forecasts, err := s.prepareHermeticDiagnostics(entries)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	workers := min(capacity.Parallel, len(entries))
	shares := make([]int, workers)
	for index := range shares {
		shares[index] = capacity.Parallel / workers
		if index < capacity.Parallel%workers {
			shares[index]++
		}
	}
	completed := make(chan hermeticCaseCompletion, workers)
	results := make([]hermeticCaseCompletion, len(entries))
	next, active := 0, 0
	for next < len(entries) || active != 0 {
		for next < len(entries) && len(shares) != 0 && ctx.Err() == nil {
			index, share := next, shares[0]
			shares = shares[1:]
			s.record.Scenarios[index].Outcome = "incomplete"
			local := children[index]
			local.record.Scenarios[0].Outcome = "incomplete"
			next++
			active++
			go func() {
				result := hermeticCaseCompletion{index: index, share: share, state: local}
				defer func() {
					if !result.returned {
						result.err = &toolFailure{operation: "hermetic case", process: processResult{Status: "unknown", Cause: fmt.Errorf("case callback did not return: %v", recover())}}
						local.record.Scenarios[0].Outcome = "failed"
						local.record.Scenarios[0].Failure = &records.Failure{Class: "scenario_failed", Stage: "execution"}
					}
					if result.err != nil && !containedCheckFailure(parent, result.err) {
						cancel()
					}
					completed <- result
				}()
				child := withExecutionParallel(ctx, share)
				result.err = local.executeScenario(child, binary, nil, limits{}, &local.record.Scenarios[0])
				result.returned = true
			}()
		}
		if active == 0 {
			break
		}
		result := <-completed
		active--
		shares = append(shares, result.share)
		results[result.index] = result
	}
	var executionErrors []error
	for index, result := range results {
		if result.state == nil {
			continue
		}
		local := result.state
		executionErrors = append(executionErrors, s.foldHermeticPreparation(local, forecasts[index]))
		s.record.Scenarios[index] = local.record.Scenarios[0]
		s.snapshots = append(s.snapshots, local.snapshots...)
		s.diagnostics = append(s.diagnostics, local.diagnostics...)
		s.telemetryIncomplete = s.telemetryIncomplete || local.telemetryIncomplete
		executionErrors = append(executionErrors, result.err)
		if result.err != nil {
			s.failScenario(s.record.Scenarios[index])
		}
	}
	if parent.Err() != nil {
		s.fail("interrupted", "schedule")
	}
	return errors.Join(append(executionErrors, parent.Err(), s.save())...)
}

func (s *runState) executeScenario(ctx context.Context, binary string, settings liveSettings, allowance limits, result *scenarioResult) (err error) {
	completion := scenarioCompletion{}
	defer func() { err = s.completeScenario(ctx, binary, allowance, result, &completion, err) }()

	name, err := currentCaseDirectory(result.Entry)
	if err != nil {
		return err
	}
	state := filepath.Join(s.private, name)
	if os.Mkdir(state, 0700) != nil {
		return errors.New("scenario directory unavailable")
	}
	if os.Mkdir(filepath.Join(state, "workers"), 0700) != nil {
		return errors.New("scenario directory unavailable")
	}
	if catalog.HasFixtureCapability(result.Scenario, catalog.FixtureConfigurationRecovery) && s.record.Suite == "hermetic" {
		return s.executeConfigurationRecovery(ctx, state, result, &completion)
	}
	input := workerInput{Scenarios: []string{result.Scenario}, MemberCount: result.Members, Repetitions: 1, RunID: s.record.RunID}
	if result.Scenario == records.StockPluginScenario {
		if s.stockPlugins == nil {
			return errors.New("stock executable identity unavailable")
		}
		input.PublicConfiguration = &publicConfigurationInput{Stock: s.stockPlugins, Actors: map[string]liveSettings{}, Outputs: s.publicOutputs}
	} else if catalog.HasFixtureCapability(result.Scenario, catalog.FixturePublicConfiguration) {
		if s.publicConfiguration == nil {
			return errors.New("public executable identity unavailable")
		}
		input.PublicConfiguration = &publicConfigurationInput{Artifact: *s.publicConfiguration, Actors: map[string]liveSettings{}}
		if row, ok := catalog.PublicConfiguration(result.Scenario); ok && row.Output {
			input.PublicConfiguration.Outputs = s.publicOutputs
		}
	}
	definition, known := catalog.DefinitionFor(result.Scenario)
	if !known {
		return errors.New("scenario actor definition unavailable")
	}
	input.RecoveryMode = "both"
	if s.record.Suite == "live" {
		input.RecoveryMode = settings["recovery_mode"]
	} else if s.record.Resolved != nil {
		input.RecoveryMode = s.record.Resolved.RecoveryMode
	}
	if s.record.Resolved != nil && input.RecoveryMode != s.record.Resolved.RecoveryMode {
		return errors.New("worker recovery mode differs from resolved plan")
	}
	execution, executionKnown := catalog.ExecutionForRecovery(result.Scenario, s.record.Suite, input.RecoveryMode)
	if !executionKnown {
		return errors.New("worker execution unavailable")
	}
	if execution.HasFixtureCapability(catalog.FixtureGeneratedProcess) {
		input.Generator = s.generator
	}
	roles := definition.RolesForRecovery(input.RecoveryMode)
	if len(roles) == 0 {
		return errors.New("worker recovery mode refused")
	}
	input.Participants, err = s.record.Resolved.scenarioParticipants(result.Scenario)
	if err != nil {
		return err
	}
	for _, role := range roles {
		if input.PublicConfiguration != nil {
			input.PublicConfiguration.Actors[role] = s.actorSettings[role]
			continue
		}
		switch role {
		case "observer":
			input.ObserverSettings = s.actorSettings[role]
		case "denied-observer":
			input.DeniedObserverSettings = s.actorSettings[role]
		case "reader":
			input.ReaderSettings = s.actorSettings[role]
		case "recovery":
			input.RecoverySettings = s.actorSettings[role]
		case "denied-reader":
			input.DeniedReaderSettings = s.actorSettings[role]
		default:
			if _, replacement := replacementRoles[role]; replacement && s.record.Suite == "live" {
				if input.ReplacementSettings == nil {
					input.ReplacementSettings = make(map[string]liveSettings)
				}
				input.ReplacementSettings[role] = s.actorSettings[role]
			}
		}
	}
	workTime := defaultWorkDuration
	if s.record.Suite == "live" {
		input.Settings, input.Limits, input.Prefix = settings, &allowance, "enkv-test/"+s.record.RunID+"/"+name
		if input.Generator != nil {
			input.GeneratorCleanupLedger, err = createGeneratorFixtureLedger(state, s.record.RunID, *input.Generator)
			if err != nil {
				return err
			}
		}
		workTime = time.Duration(allowance.ElapsedSeconds) * time.Second
	}
	var recoveryOwner *installedarchive.LiveRecoveryParentInput
	if s.record.Suite == "live" && execution.HasFixtureCapability(catalog.FixtureConfigurationRecovery) {
		recoveryOwner, input.ConfigurationRecovery, err = s.prepareLiveConfigurationRecovery(state, input, allowance)
		if err != nil {
			return err
		}
		completion.oracleDirectory = input.ConfigurationRecovery.OracleDirectory
	}
	var cleanupInput workerInput
	cleanupInput = input.authorityOnly()
	if _, publication := catalog.LivePublication(result.Scenario); publication {
		if s.record.Suite != "live" || s.record.BuildClosure == nil {
			return errPublicationInput
		}
		parent, prepareErr := preparePublicationInput(state, input.RunID, name+"-writer", result.Scenario, s.publicationProfiles, s.publicationBuild, *s.record.BuildClosure)
		if prepareErr != nil {
			return prepareErr
		}
		input.Outputs, err = parent.WriterProjection()
		if err != nil {
			return errPublicationInput
		}
		cleanupInput.Outputs, err = parent.CleanerProjection()
		if err != nil {
			return errPublicationInput
		}
		result.OutputsSHA256, err = publicationEvidenceDigest(input.Outputs, cleanupInput.Outputs)
		if err != nil {
			return err
		}
		if records.WriteJSONExclusive(filepath.Join(state, "cleanup-input.json"), cleanupInput, records.MaximumJSONBytes) != nil {
			return errPublicationInput
		}
	}
	inputPath := filepath.Join(state, "input.json")
	if err := records.WriteJSON(inputPath, input, 0400); err != nil {
		return err
	}
	writerRecovery := ""
	if s.record.Suite == "hermetic" && input.RecoveryMode != "both" {
		writerRecovery = input.RecoveryMode
	}
	inv, err := makeInvocation(records.Invocation{
		Scenario: result.Scenario, FailureSources: s.failureSources,
		TelemetrySettings: s.telemetrySettings,
		RunID:             s.record.RunID,
		Worker:            name + "-writer",
		Role:              "writer",
		RecoveryMode:      writerRecovery,
		Input:             inputPath,
		StateDir:          state,
		OutputDir:         filepath.Join(state, "workers", "writer"),
	}, s.record.Suite)
	if err != nil {
		return err
	}
	started := time.Now()
	deadline := started.Add(workTime)
	completion.entered, completion.started = true, started
	completion.participants = &scenarioParticipants{state: state, input: input, cleanupInput: cleanupInput, writer: inv}

	process := runInvocation(ctx, binary, s.root, s.record.Suite, inv, time.Until(deadline), s.record.Telemetry.Enabled)
	completion.participants.writerProcess = process
	completion.joined = process.Joined
	evidence, writer, writerErr := s.importWorkerOwned(ctx, inv, result.Scenario, process, nil)
	if s.record.Suite == "hermetic" {
		writerErr = errors.Join(writerErr, verifyHermeticWorkerInput(inv, input))
	}
	result.Writer = &evidence
	if s.record.Suite == "live" {
		result.BudgetReserved, err = workerReservation(inv, false)
		if err != nil {
			writerErr = errors.Join(writerErr, err)
		}
	}
	writerSettled := writerErr == nil && process.Started && process.Joined && process.Status == "passed" && process.Cause == nil || containedCheckFailure(ctx, writerErr)
	// Each registered reader owns a separate record. Preserve earlier history
	// readers even if a later phase or the writer fails.
	for index, child := range writer.Children {
		childInv, step, childErr := childInvocation(s.record.Suite, result.Scenario, s.private, inv, child, index)
		if childErr != nil {
			writerErr = errors.Join(writerErr, childErr)
			continue
		}
		childProcess := processResult{Status: "unknown"}
		if child.Process != nil && child.Process.Validate() == nil {
			childProcess.Status = child.Process.Outcome
			childProcess.Started = child.Process.Started
			childProcess.Joined = child.Process.Joined && process.Joined
		}
		var writerAnchor *processResult
		if writerSettled {
			writerAnchor = &process
		}
		childEvidence, _, childErr := s.importWorkerWithAnchor(ctx, childInv, result.Scenario, childProcess, &step, writerAnchor)
		result.Children = append(result.Children, childEvidence)
		if s.record.Suite == "live" {
			reservation, reservationErr := workerReservation(childInv, false)
			if reservationErr == nil {
				result.BudgetReserved, reservationErr = addReservations(result.BudgetReserved, reservation)
			}
			childErr = errors.Join(childErr, reservationErr)
		}
		writerErr = errors.Join(writerErr, childErr)
	}
	if err := s.save(); err != nil {
		return errors.Join(writerErr, err)
	}
	if writerErr != nil && input.Outputs == nil && s.record.Suite == "live" && eligibleSameDomainRerun(result.Scenario, process, writer, result.Children) && (!evidence.Telemetry.Enabled || evidence.Telemetry.Status == "complete") {
		rerun, rerunInput, rerunJoined, rerunErr := s.executeSameDomainRerun(ctx, binary, inv, input, allowance, deadline, time.Since(started), result, writer)
		completion.joined = completion.joined && rerunJoined
		if rerunErr != nil {
			completion.failure = &records.Failure{Class: "same_domain_rerun_failed", Stage: "rerun"}
			return errors.Join(writerErr, rerunErr)
		}
		writer, writerErr, inputPath = rerun, nil, rerunInput
	}
	if writerErr != nil {
		completion.failure = &records.Failure{Class: "writer_failed", Stage: "writer"}
		return writerErr
	}
	if recoveryOwner != nil {
		recoveryErr := s.executeLiveConfigurationRecovery(ctx, state, input, *recoveryOwner, deadline, result, &completion.joined)
		completion.completed = recoveryErr == nil
		return recoveryErr
	}
	if len(writer.FreshChecks) == 0 {
		completion.failure = &records.Failure{Class: "fresh_evidence_unavailable", Stage: "fresh_after"}
		return errors.New("fresh evidence unavailable")
	}
	seenFacts := make(map[string]bool)
	for index, check := range writer.FreshChecks {
		if seenFacts[check.Facts] {
			return errors.New("duplicate fresh evidence")
		}
		seenFacts[check.Facts] = true
		freshInputPath := inputPath
		if s.record.Suite == "live" && (input.Generator != nil || input.Outputs != nil) {
			freshInput := input.freshAfterInput()
			freshInputPath = filepath.Join(state, fmt.Sprintf("fresh-after-input-%d.json", index))
			if err := records.WriteJSON(freshInputPath, freshInput, 0400); err != nil {
				return errors.New("generated fresh input could not be isolated")
			}
		}
		fresh, err := makeInvocation(records.Invocation{
			Scenario: result.Scenario, FailureSources: s.failureSources,
			TelemetrySettings: s.telemetrySettings,
			RunID:             s.record.RunID,
			Worker:            fmt.Sprintf("%s-fresh-%04d-after", name, index),
			Role:              "fresh_after",
			Input:             freshInputPath,
			StateDir:          state,
			OutputDir:         filepath.Join(state, "workers", fmt.Sprintf("fresh-%04d-after", index)),
			Facts:             check.Facts,
			RecoveryMode:      expectedFreshMode(result.Scenario, s.record.Suite, "fresh_after", index, input.RecoveryMode),
		}, s.record.Suite)
		if err != nil {
			return errors.New("fresh invocation refused")
		}
		process := runInvocation(ctx, binary, s.root, s.record.Suite, fresh, time.Until(deadline), s.record.Telemetry.Enabled)
		completion.joined = completion.joined && process.Joined
		evidence, _, err := s.importWorkerOwned(ctx, fresh, result.Scenario, process, nil)
		if s.record.Suite == "hermetic" {
			err = errors.Join(err, verifyHermeticWorkerInput(fresh, input))
		}
		result.PostExit = append(result.PostExit, evidence)
		if err == nil && s.record.Suite == "live" {
			reservation, reservationErr := workerReservation(fresh, false)
			if reservationErr == nil {
				result.BudgetReserved, reservationErr = addReservations(result.BudgetReserved, reservation)
			}
			err = reservationErr
		}
		if err != nil {
			completion.failure = &records.Failure{Class: "fresh_read_failed", Stage: "fresh_after"}
			return err
		}
	}
	completion.completed = true
	return nil
}

func verifyHermeticWorkerInput(inv records.Invocation, expected workerInput) error {
	var observed workerInput
	if records.ReadJSON(inv.Input, &observed) != nil {
		return errors.New("hermetic worker input changed during execution")
	}
	expectedBody, expectedErr := json.Marshal(expected)
	observedBody, observedErr := json.Marshal(observed)
	if expectedErr != nil || observedErr != nil || string(expectedBody) != string(observedBody) {
		return errors.Join(errors.New("hermetic worker input changed during execution"), expectedErr, observedErr)
	}
	return nil
}

func (s *runState) executeCleanup(ctx context.Context, binary string, inv records.Invocation, scenario string, allowance limits) (*workerEvidence, records.Cleanup) {
	// The worker owns validation of exact keys, versions and settled effects.
	// A missing inventory cannot prove that no cloud objects remain.
	ledger := "inventory.json"
	if scenario == records.StockPluginScenario {
		ledger = "stock-plugin-grant.json"
	} else if recordedHasFixture(scenario, catalog.FixturePublicConfiguration) {
		ledger = "public-ownership.json"
		if publicOutputRecoveryCase(scenario) {
			var input workerInput
			body, err := readRecordBytes(inv.Input)
			if err != nil || decodeCleanupRecord(body, &input) != nil {
				return nil, unresolvedCleanup()
			}
			if input.OutputRecovery != nil {
				if input.OutputRecovery.VerifyFiles() != nil || input.OutputRecovery.StateDir != inv.StateDir || input.OutputRecovery.RecoveryRunID != inv.RunID {
					return nil, unresolvedCleanup()
				}
				ledger = "public-output-recovery-input.json"
			}
		}
	}
	inventory, err := records.SafePath(inv.StateDir, ledger)
	if err != nil {
		return nil, unresolvedCleanup()
	}
	info, err := os.Lstat(inventory)
	if err != nil || !info.Mode().IsRegular() {
		return nil, unresolvedCleanup()
	}
	process := runInvocation(ctx, binary, s.root, "live", inv, time.Duration(allowance.CleanupSeconds)*time.Second, s.record.Telemetry.Enabled)
	evidence, raw, _ := s.importWorker(inv, scenario, process, nil)
	cleanup := safeCleanup(raw, evidence)
	if scenario == records.StockPluginScenario {
		cleanup.Outcome = "unresolved"
		cleanup.Failure = &records.Failure{Class: "cleanup_unresolved", Stage: "cleanup"}
	}
	if scenario == records.StockPluginScenario && evidence.Outcome == "passed" && evidence.Process == "passed" && evidence.Started && evidence.Joined && evidence.Failure == nil {
		if recovered, proofErr := s.stockRecoveryCleanupEvidence(inv, raw.Cleanup); proofErr == nil {
			cleanup = *raw.Cleanup
			for i := range s.record.Scenarios {
				result := &s.record.Scenarios[i]
				if result.Scenario == scenario {
					result.StockPluginRecovery = recovered
					result.BudgetReserved = recovered.ProductReserved
					result.WorkloadElapsed = time.Duration(recovered.ProductElapsedSeconds) * time.Second
				}
			}
		} else if stock, proofErr := s.stockCleanupEvidence(inv, raw.Cleanup); proofErr == nil {
			cleanup = *raw.Cleanup
			for i := range s.record.Scenarios {
				result := &s.record.Scenarios[i]
				if result.Scenario == scenario {
					result.OutputScheduled = stockScheduledOutputs(stock)
					result.OutputsSHA256 = stockOutputDigest(stock)
				}
			}
		}
	}
	if _, publication := catalog.LivePublication(scenario); publication {
		residue, proofErr := s.publicationCleanupEvidence(inv, scenario, raw.Cleanup)
		if proofErr == nil && evidence.Started && evidence.Joined {
			if raw.Cleanup.Outcome == "passed" && evidence.Outcome == "passed" && evidence.Process == "passed" && evidence.Failure == nil {
				cleanup.Outcome, cleanup.Failure = "passed", nil
			}
			for i := range s.record.Scenarios {
				result := &s.record.Scenarios[i]
				state, stateErr := publicationScenarioState(s.directory, *result)
				if result.Scenario == scenario && stateErr == nil && state == inv.StateDir {
					result.OutputScheduled = uint32(residue.Scheduled)
					break
				}
			}
		}
	}

	cleanup.BudgetReserved, err = workerReservation(inv, true)
	if err != nil {
		cleanup.Outcome, cleanup.Failure = "unresolved", &records.Failure{Class: "budget_evidence_unavailable", Stage: "cleanup"}
	}
	return &evidence, cleanup
}

func (s *runState) publicationCleanupEvidence(inv records.Invocation, scenario string, cleanup *records.Cleanup) (publicationResidue, error) {
	if inv.Role != "cleanup" || inv.Scenario != scenario || inv.RunID != s.record.RunID || inv.Input != filepath.Join(inv.StateDir, "cleanup-input.json") || cleanup == nil || cleanup.RemainingOwnedObjects == nil || cleanup.UnknownEffects == nil {
		return publicationResidue{}, errPublicationInput
	}
	for _, result := range s.record.Scenarios {
		state, err := publicationScenarioState(s.directory, result)
		if result.Scenario != scenario || err != nil || state != inv.StateDir {
			continue
		}
		if validateRetainedPublication(state, s.record, result) != nil {
			return publicationResidue{}, errPublicationInput
		}
		var input workerInput
		if records.ReadJSON(filepath.Join(state, "input.json"), &input) != nil {
			return publicationResidue{}, errPublicationInput
		}
		residue, err := publicationResidueState(input.Outputs)
		if err != nil || *cleanup.RemainingOwnedObjects < residue.Remaining || *cleanup.UnknownEffects < residue.Unknown {
			return publicationResidue{}, errPublicationInput
		}
		if cleanup.Outcome == "passed" {
			if cleanup.Failure != nil || cleanup.HarnessFailure != nil || residue.Unknown != 0 || residue.Remaining != residue.Scheduled || *cleanup.RemainingOwnedObjects != residue.Remaining || *cleanup.UnknownEffects != residue.Unknown {
				return publicationResidue{}, errPublicationInput
			}
		} else {
			fact := cleanup.HarnessFailure
			if cleanup.Outcome != "unresolved" || fact == nil || !fact.Validate() || fact.Operation != "object_cleanup" || fact.TargetKind != "inventory" {
				return publicationResidue{}, errPublicationInput
			}
		}
		return residue, nil
	}
	return publicationResidue{}, errPublicationInput
}

func makeInvocation(inv records.Invocation, suite string) (records.Invocation, error) {
	inv.SchemaVersion = records.SchemaVersion
	if suite != "hermetic" && suite != "live" {
		return inv, errors.New("worker suite refused")
	}
	var err error
	inv.Nonce, err = records.NewInvocationNonce()
	if err != nil {
		return inv, err
	}
	if inv.Role == "writer" {
		inv.FreshBefore, err = issueFreshBefore(inv, suite)
		if err != nil {
			return inv, err
		}
	}
	if _, err := records.SafePath(inv.StateDir, "."); err != nil {
		return inv, err
	}
	if os.Mkdir(inv.OutputDir, 0700) != nil {
		return inv, errors.New("worker directory unavailable")
	}
	if inv.Validate() != nil {
		return inv, errors.New("worker invocation refused")
	}
	return inv, records.WriteJSON(filepath.Join(inv.OutputDir, "invocation.json"), inv, 0400)
}

func runInvocation(ctx context.Context, binary, root, suite string, inv records.Invocation, timeout time.Duration, enabled bool) processResult {
	name := "TestHermeticRun"
	if suite == "live" {
		name = "TestLiveRun"
	}
	if inv.Role == "fresh_before" || inv.Role == "fresh_after" {
		name = "TestHermeticChild"
		if suite == "live" {
			name = "TestLiveChild"
		}
	}
	if inv.Role == "cleanup" {
		name = "TestLiveCleanup"
	}
	if inv.Role == "rerun" {
		name = "TestLiveRecovery"
	}
	alarm := "1h"
	if suite == "hermetic" {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
		deadline, _ := ctx.Deadline()
		timeout = time.Until(deadline)
		alarm = timeout.String()
	}
	args := []string{"-test.run=^" + name + "$", "-test.timeout=" + alarm, "-test.parallel=1"}
	env := workerEnvironment(filepath.Join(inv.OutputDir, "invocation.json"))
	if suite != "hermetic" {
		return runProcess(ctx, binary, root, args, env, timeout)
	}
	stdout, stderr := &limitedOutput{}, &limitedOutput{}
	process := runProcessOutput(ctx, binary, root, args, env, timeout, stdout, stderr)
	if !process.Joined {
		process.diagnostic = &toolFailure{operation: "hermetic " + inv.Role, process: process}
		return process
	}
	if process.Status != "passed" || stdout.overflow || stderr.overflow {
		if process.Status == "passed" && (stdout.overflow || stderr.overflow) {
			process.Status = "output_limit_exceeded"
		}
		failure := &toolFailure{operation: "hermetic " + inv.Role, process: process}
		failure.stdout, failure.stderr = stdout.Bytes(), stderr.Bytes()
		failure.overflow = stdout.overflow || stderr.overflow
		process.diagnostic = failure
	}
	return process
}

func workerEnvironment(invocation string) []string {
	environment := make([]string, 0, len(os.Environ())+1)
	for _, value := range goEnvironment() {
		if !strings.HasPrefix(value, "ENKV_TEST_INVOCATION=") && !strings.HasPrefix(value, "ENKV_DIAGNOSTICS=") && !strings.HasPrefix(value, "ENKV_LIVE_") && !strings.HasPrefix(value, "ENKV_PROCESS_") && !strings.HasPrefix(value, "ENKV_MEASUREMENTS=") && !strings.HasPrefix(value, "ENKV_SCENARIO_REPORT=") {
			environment = append(environment, value)
		}
	}
	if invocation != "" {
		environment = append(environment, "ENKV_TEST_INVOCATION="+invocation)
	}
	return environment
}

func (s *runState) finish() {
	defer func() {
		groups, err := scenarioRepetitionGroups(s.record)
		if err != nil {
			s.fail("scenario_failed", "execution")
		}
		s.record.RepetitionGroups = groups
		s.record.FullCoverage = fullCoverage(s.record)
	}()
	complete := len(s.record.Scenarios) == len(s.record.Schedule.Entries) && len(s.record.Scenarios) != 0
	correct := complete && (s.record.Failure == nil || s.record.Failure.Stage == "cleanup")
	passed := complete && s.record.Failure == nil
	cleanup := records.Cleanup{Outcome: "passed", RemainingOwnedObjects: new(int64), UnknownEffects: new(int64)}
	for _, item := range s.record.Scenarios {
		passed = passed && item.Outcome == "passed"
		correct = correct && item.CorrectnessPassed
		if s.record.Suite == "live" && !scenarioCleanupPassed(item) {
			cleanup = unresolvedCleanup()
		}
		if s.record.Suite == "live" && cleanup.Outcome == "passed" {
			*cleanup.RemainingOwnedObjects += int64(item.OutputScheduled)
		}
	}
	if s.record.Suite == "hermetic" {
		cleanup = noCleanup()
	}
	if s.record.Suite == "live" && len(s.record.Scenarios) == 0 {
		cleanup = unresolvedCleanup()
	}
	s.record.Cleanup = cleanup
	if s.record.RecoveryRunID != "" {
		// Recovery starts with inventories from every retained entry. An entry
		// not reached still has unknown cleanup, even if earlier entries passed.
		if !complete {
			cleanup = unresolvedCleanup()
			s.record.Cleanup = cleanup
		}
		passed = complete && s.record.Failure == nil && runCleanupPassed(s.record)
		correct = false
	}
	s.record.Correctness.Passed, s.record.Correctness.EvidenceComplete = correct, complete && correct
	s.record.CoverageScope = s.record.Suite + "_scenarios"
	if s.record.RecoveryRunID != "" {
		s.record.CoverageScope = "cleanup_recovery"
	}
	s.record.ScenarioCoverage = passed && s.record.Schedule.FullCoverage
	s.record.FullCoverage = s.record.ScenarioCoverage && s.record.Profile == "full"
	s.record.Outcome = "failed"
	if passed {
		s.record.Outcome = "passed"
	}
	now := time.Now().UTC()
	s.record.FinishedAt = &now
}

func (input workerInput) authorityOnly() workerInput {
	// Public test cleanup owns its exact separately selected cleanup context.
	// The worker never uses an authority credential fallback for that route.
	if input.PublicConfiguration != nil {
		return input
	}
	input.Participants = map[string]string{"authority": input.Participants["authority"]}
	input.ObserverSettings, input.ReaderSettings, input.RecoverySettings, input.DeniedReaderSettings = nil, nil, nil, nil
	input.DeniedObserverSettings = nil
	input.ReplacementSettings = nil
	input.ConfigurationRecovery = nil
	input.Outputs = nil
	return input
}

func issueFreshBefore(inv records.Invocation, suite string) ([]records.InvocationBinding, error) {
	execution, known := catalog.ExecutionForRecovery(inv.Scenario, suite, inv.RecoveryMode)
	if !known {
		return nil, errors.New("worker scenario unavailable")
	}
	children := execution.ExpandedFreshBefore()
	if len(children) > records.MaximumWorkerChildren {
		return nil, errors.New("fresh child list exceeds its bound")
	}
	bindings := make([]records.InvocationBinding, len(children))
	for index := range children {
		worker := fmt.Sprintf("fresh-before-%s-%d", digestBytes([]byte(inv.Worker))[:childWorkerDigestPrefixLength], index)
		if suite == "hermetic" {
			worker = fmt.Sprintf("%s-fresh-%04d-before", filepath.Base(inv.StateDir), index)
		}
		nonce, err := records.NewInvocationNonce()
		if err != nil {
			return nil, err
		}
		bindings[index] = records.InvocationBinding{Worker: worker, Nonce: nonce}
	}
	return bindings, nil
}

func (input workerInput) freshAfterInput() workerInput {
	input.Outputs = nil
	input.Generator, input.GeneratorCleanupLedger = nil, ""
	return input
}

func suiteOwnsPreparation(record *runRecord, d *checkDiagnostics) bool {
	return d != nil && record != nil && record.BuildClosure != nil && record.BuildClosure.LocalChecks != nil && record.BuildClosure.LocalChecks.Diagnostics == d
}

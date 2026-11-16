package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

// Preparation does not own diagnostic storage. Keep an existing closed
// failure and its delivery facts; diagnostic writers can still publish a new
// status through safeCheckFailure after they save the original cause.
func safePreparationFailure(cause error) error {
	if _, closed := cause.(*checkFailure); closed {
		return cause
	}
	return safeCheckFailure("preparation", "none", cause)
}

type preparationBootstrapKey struct{}
type preparationBootstrap struct {
	root, path, identity string
	contents             []byte
}

func withPreparationBootstrap(ctx context.Context, root, bootstrap string) (context.Context, error) {
	if bootstrap == "" {
		return ctx, nil
	}
	if previous, exists := ctx.Value(preparationBootstrapKey{}).(preparationBootstrap); exists && previous.root == root && previous.path == bootstrap {
		return ctx, nil
	}
	key := root + "\x00" + bootstrap
	owner := invocationArtifactsFrom(ctx)
	if owner != nil {
		owner.mu.Lock()
		defer owner.mu.Unlock()
		if captured, exists := owner.bootstraps[key]; exists {
			return context.WithValue(ctx, preparationBootstrapKey{}, captured), nil
		}
	}
	body, err := os.ReadFile(bootstrap)
	if err != nil {
		return ctx, err
	}
	identity, err := componentBootstrapContentsIdentity(root, body)
	if err != nil {
		return ctx, err
	}
	captured := preparationBootstrap{root: root, path: bootstrap, identity: identity, contents: body}
	if owner != nil {
		owner.bootstraps[key] = captured
	}
	return context.WithValue(ctx, preparationBootstrapKey{}, captured), nil
}

// The caller retains its assigned values and cancellation. Only the earlier
// preparation lifetime deadline is borrowed; replacing the caller with the
// preparation context would restore its larger parallel allowance.
func preparedExecutionContext(ctx, prepared context.Context) (context.Context, context.CancelFunc) {
	var cancel context.CancelFunc
	if deadline, ok := prepared.Deadline(); ok {
		ctx, cancel = context.WithDeadline(ctx, deadline)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	// The copied deadline owns expiry. Plain cancellation at that same instant
	// can otherwise replace DeadlineExceeded with Canceled.
	cancelPrepared := func() {
		if prepared.Err() != context.DeadlineExceeded {
			cancel()
		}
	}
	stop := context.AfterFunc(prepared, cancelPrepared)
	if prepared.Err() != nil {
		cancelPrepared()
	}
	return ctx, func() { stop(); cancel() }
}

// One configured group spends its own preparation time before dispatch, then
// keeps one fixed remaining deadline across its executions and partitions.
// The coordinator finishes each preparation scope before another scope or the
// first dispatch; the mutex protects bookkeeping, not overlapping phase use.
type preparedGroupDuration struct {
	ctx           context.Context
	stop          context.CancelFunc
	mu            sync.Mutex
	bounded       bool
	remaining     time.Duration
	execution     context.Context
	stopExecution context.CancelFunc
}

func cumulativeContext(parent context.Context, allowance time.Duration) (context.Context, context.CancelFunc) {
	if allowance == 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, allowance)
}

func newPreparedGroupDuration(parent context.Context, allowance time.Duration) *preparedGroupDuration {
	ctx, stop := context.WithCancel(parent)
	return &preparedGroupDuration{ctx: ctx, stop: stop, bounded: allowance != 0, remaining: allowance}
}

func (duration *preparedGroupDuration) preparationContext(ctx context.Context) (context.Context, func()) {
	duration.mu.Lock()
	execution, remaining := duration.execution, duration.remaining
	duration.mu.Unlock()
	if execution != nil {
		return preparedExecutionContext(ctx, execution)
	}
	ctx, release := preparedExecutionContext(ctx, duration.ctx)
	if !duration.bounded {
		return ctx, release
	}
	started := time.Now()
	ctx, stop := context.WithTimeout(ctx, max(remaining, 0))
	var once sync.Once
	return ctx, func() {
		once.Do(func() {
			stop()
			release()
			duration.mu.Lock()
			duration.remaining = max(0, duration.remaining-time.Since(started))
			duration.mu.Unlock()
		})
	}
}

func (duration *preparedGroupDuration) executionContext(ctx context.Context) (context.Context, context.CancelFunc) {
	duration.mu.Lock()
	if duration.execution == nil {
		if duration.bounded {
			duration.execution, duration.stopExecution = context.WithTimeout(duration.ctx, max(duration.remaining, 0))
		} else {
			duration.execution = duration.ctx
		}
	}
	execution := duration.execution
	duration.mu.Unlock()
	return preparedExecutionContext(ctx, execution)
}

func (duration *preparedGroupDuration) cancel() {
	duration.stop()
	duration.mu.Lock()
	if duration.stopExecution != nil {
		duration.stopExecution()
	}
	duration.mu.Unlock()
}

func localPreparationPhase(ctx context.Context, root string) (context.Context, *toolDirectoryPhase, error) {
	report, borrowed, err := borrowToolDirectoryPhase(ctx, root)
	if err != nil {
		return ctx, nil, err
	}
	if borrowed {
		report(true)
		return ctx, nil, nil
	}
	locks, err := resourceLocksFromContext(ctx)
	if err != nil {
		return ctx, nil, err
	}
	return prepareToolDirectoryPhase(ctx, locks, root)
}
func useLocalPreparationPhase(ctx context.Context, phase *toolDirectoryPhase) context.Context {
	if phase != nil {
		return context.WithValue(ctx, toolDirectoryPhaseContextKey{}, phase)
	}
	return ctx
}
func closeLocalPreparationPhase(ctx context.Context, phase *toolDirectoryPhase, joined bool) error {
	if phase == nil {
		return nil
	}
	tail, cancel := finalizationContext(ctx)
	defer cancel()
	return phase.Release(tail, joined)
}

func selectedRootsBig(pkg string, selected []string, classifications []testClassification) (bool, error) {
	rows := make(map[string]bool, len(classifications))
	seen := map[string]bool{}
	for _, row := range classifications {
		if seen[row.Name] {
			return false, errors.New("selected test has repeated classification")
		}
		seen[row.Name] = true
		if row.Unavailable {
			if row.FullOnly != nil || row.Exclusive {
				return false, errors.New("unavailable test classification is inconsistent")
			}
			continue
		}
		if row.FullOnly == nil {
			return false, errors.New("selected test classification missing")
		}
		rows[row.Name] = row.Exclusive
	}
	big := false
	for _, name := range selected {
		exclusive, exists := rows[name]
		if !exists {
			return false, errors.New("selected test classification unavailable")
		}
		big = big || exclusive || ordinaryExclusiveProcess(pkg, name) || pkg == componentPackage && slices.Contains(ordinaryMemoryComponents, name)
	}
	return big, nil
}

type preparationBinding struct {
	ctx       context.Context
	bootstrap preparationBootstrap

	toolchain   string
	environment map[string]string
	source      records.Source
	live        bool
	race        bool
}

func prepareBinding(command goEnvironmentCommand, ctx context.Context, root string, live bool) (preparationBinding, error) {
	bootstrap, _ := ctx.Value(preparationBootstrapKey{}).(preparationBootstrap)
	value := preparationBinding{ctx: ctx, bootstrap: bootstrap, live: live, race: raceEnabled(ctx)}
	var err error
	value.source, err = sourceRevision(ctx, root)
	if err != nil {
		return value, err
	}
	body, err := command(ctx, root, "core", nil, "version")
	if err != nil {
		return value, err
	}
	value.toolchain = strings.TrimSpace(string(body))
	value.environment, err = testBuildEnvironment(command, ctx, root)
	if err != nil {
		return value, err
	}
	return value, nil
}
func (value preparationBinding) context(ctx context.Context) context.Context {
	ctx = useInvocationArtifacts(ctx, value.ctx)
	if _, present := ctx.Value(racePolicyContextKey{}).(bool); !present {
		return withRacePolicy(ctx, value.race)
	}
	return ctx
}

func beginPreparationPlan(d *checkDiagnostics, future []checkCommandFacts) (func(), error) {
	if d == nil || d.hasPlan() {
		return func() {}, nil
	}
	if err := d.reserveCommands(future); err != nil {
		return nil, err
	}
	var once sync.Once
	return func() { once.Do(d.cancelReservations) }, nil
}
func inventoryPreparationCommands(scope string) []checkCommandFacts {
	return []checkCommandFacts{preparationReservationFact(scope, false)}
}
func suiteConstructionCommands(request runRequest) ([]checkCommandFacts, error) {
	commands := []checkCommandFacts{preparationReservationFact("core", false)}
	if request.components == nil {
		var environment environmentFile
		if request.environment != nil {
			environment = *request.environment
		}
		selected, err := selectPublicationOutputs(request.Schedule, environment)
		if err != nil {
			return nil, err
		}
		bindings, err := selectedPublicationBindings(selected)
		if err != nil {
			return nil, err
		}
		construction, err := assemblyConstructionCommands(assemblyBindings{Output: bindings})
		commands = append(commands, construction...)
		if err != nil {
			return nil, err
		}
	}
	commands = append(commands, inventoryPreparationCommands("scenario-inventory")...)
	helpers, err := selectedReconstructionHelpers(request)
	if err != nil {
		return nil, err
	}
	for provider := range helpers {
		construction, err := reconstructionConstructionCommands(provider)
		if err != nil {
			return nil, err
		}
		commands = append(commands, construction...)
	}
	return commands, nil
}

func prepareBindingOwned(d *checkDiagnostics, ctx context.Context, root string, live bool) (preparationBinding, error) {
	ctx = context.WithValue(ctx, artifactDiagnosticsKey{}, d)
	if owner := invocationArtifactsFrom(ctx); owner != nil {
		value, _, err := invocationArtifactValue(ctx, root, root, "binding", "build-observation", func(string) (preparationBinding, error) {
			compiler, err := invocationCompiler(ctx, owner, root)
			if err != nil {
				return preparationBinding{}, err
			}
			env := compiler.(map[string]string)
			source, err := sourceRevision(ctx, root)
			bootstrap, _ := ctx.Value(preparationBootstrapKey{}).(preparationBootstrap)
			value := preparationBinding{bootstrap: bootstrap, environment: env, source: source, race: raceEnabled(ctx), toolchain: "go version " + env["GOVERSION"] + " " + env["GOOS"] + "/" + env["GOARCH"]}
			return value, err
		})
		value.ctx, value.live = ctx, live
		return value, err
	}
	command := goEnvironmentCommand(runGoEnvironment)
	if d != nil {
		command = d.runGoEnvironment
	}
	return prepareBinding(command, ctx, root, live)
}

func (value preparationBinding) checkRace(ctx context.Context) error {
	if raceEnabled(value.context(ctx)) != value.race {
		return errors.New("prepared invocation race policy changed")
	}
	return ctx.Err()
}

type preparedWorkflow struct {
	artifactOwner        *invocationArtifacts
	planIdentity         string
	plan                 workflowPlan
	bootstrap            string
	binding              preparationBinding
	current              *currentDirectory
	phase                *toolDirectoryPhase
	ordinary             map[string]*preparedOrdinaryGroup
	preparations         map[string]*checkDiagnostics
	preparationFailures  map[string]error
	assemblyPreparations context.Context
	components           map[string]*preparedComponentGroup
	providers            map[string]assembly
	suites               map[string]*preparedSuite
	fuzz                 map[string]*preparedFuzz
	class                rootAdmission
	joined               bool
	closed               bool
	ready                map[int]bool
}

func workflowPreparationKey(step resolvedWorkflowStep) string {
	if step.ConfiguredStep != "" {
		return step.ConfiguredStep
	}
	return step.ID
}

func prepareWorkflow(ctx context.Context, root, bootstrap string, plan workflowPlan, output io.Writer) (prepared *preparedWorkflow, err error) {
	ctx, artifactOwner := withInvocationArtifacts(ctx)

	live := false
	for _, step := range plan.Steps {
		live = live || step.Selected && step.Run != nil && step.Run.Mode == "live"
	}
	defer func() {
		if live {
			err = safePreparationFailure(err)
		}
	}()
	ctx, bootstrapErr := withPreparationBootstrap(ctx, root, bootstrap)
	if bootstrapErr != nil {
		return nil, bootstrapErr
	}

	if err := validateResolvedParallelGroups(plan); err != nil {
		return nil, err
	}
	policy, err := executionWithinContext(ctx, plan.Execution)
	if err != nil {
		return nil, err
	}
	plan.Execution = policy
	ctx = withExecutionCapacity(withRacePolicy(ctx, plan.Race), policy)

	ctx, phase, err := localPreparationPhase(ctx, root)
	defer func() {
		if err != nil && prepared == nil {
			err = errors.Join(err, closeLocalPreparationPhase(ctx, phase, toolCommandsJoined(err)))
		}
	}()
	if err != nil {
		return nil, err
	}
	prepared = &preparedWorkflow{assemblyPreparations: ctx, plan: plan, bootstrap: bootstrap, phase: phase, ordinary: map[string]*preparedOrdinaryGroup{}, preparations: map[string]*checkDiagnostics{}, preparationFailures: map[string]error{}, components: map[string]*preparedComponentGroup{}, providers: map[string]assembly{}, suites: map[string]*preparedSuite{}, fuzz: map[string]*preparedFuzz{}, class: rootAdmission{Live: live, Execution: policy}, joined: true}
	prepared.artifactOwner = artifactOwner
	defer func() { prepared.joined = prepared.joined && toolCommandsJoined(err) }()
	diagnostics := &checkDiagnostics{Preparation: "pending"}
	for _, step := range plan.Steps {
		if step.Selected {
			prepared.preparations[workflowPreparationKey(step)] = diagnostics
			break
		}
	}
	binding, err := prepareBindingOwned(diagnostics, ctx, root, live)
	prepared.binding = binding
	if err != nil {
		diagnostics.Preparation = "failed"
		return prepared, err
	}
	current, err := newCurrentDirectory("enkv-workflow-preparation-")
	if err != nil {
		return prepared, err
	}
	prepared.current = current
	private := filepath.Join(current.path, "private")
	if err := os.Mkdir(private, 0700); err != nil {
		return prepared, err
	}
	prepared.ready = map[int]bool{}
	for i, step := range prepared.plan.Steps {
		if step.Selected {
			err = prepared.prepareSteps(ctx, root, i, workflowReadyEnd(prepared.plan.Steps, i), output)
			return prepared, err
		}
	}
	body, marshalErr := json.Marshal(prepared.plan)
	prepared.planIdentity = digestBytes(body)
	return prepared, marshalErr
}

func workflowReadyEnd(steps []resolvedWorkflowStep, first int) int {
	step := steps[first]
	end := first + 1
	for end < len(steps) && steps[end].Selected {
		next := steps[end]
		grouped := step.ParallelGroup != "" && next.ParallelGroup == step.ParallelGroup
		repeated := step.Repetitions > 1 && step.ConfiguredStep != "" && next.ConfiguredStep == step.ConfiguredStep
		if !grouped && !repeated {
			break
		}
		end++
	}
	return end
}

func (prepared *preparedWorkflow) prepareSteps(ctx context.Context, root string, start, end int, output io.Writer) (err error) {
	if prepared.closed || !prepared.joined {
		return errors.New("prepared workflow is closed or unsettled")
	}
	ctx = prepared.binding.context(ctx)
	ctx = useLocalPreparationPhase(ctx, prepared.phase)
	ctx = context.WithValue(ctx, workflowScratchContextKey{}, prepared.current)
	plan, binding := prepared.plan, prepared.binding
	bootstrap, current := prepared.bootstrap, prepared.current
	private := filepath.Join(current.path, "private")
	policy := plan.Execution
	defer func() {
		prepared.joined = prepared.joined && toolCommandsJoined(err)
		body, marshalErr := json.Marshal(prepared.plan)
		prepared.planIdentity = digestBytes(body)
		err = errors.Join(err, marshalErr)
	}()
	var failures []error
	for i := start; i < end; i++ {
		if prepared.ready[i] {
			continue
		}
		step := &prepared.plan.Steps[i]
		if !step.Selected {
			continue
		}
		key := workflowPreparationKey(*step)
		diagnostics := prepared.preparations[key]
		if diagnostics == nil {
			diagnostics = &checkDiagnostics{Preparation: "pending"}
			prepared.preparations[key] = diagnostics
		}
		prepareErr := func() error {
			switch step.Kind {
			case "unit", "runner-tests":
				group := prepared.ordinary[key]
				if previous := prepared.preparationFailures[key]; previous != nil {
					return previous
				}
				if group == nil {
					evidence := ordinaryStepEvidence{Diagnostics: diagnostics}
					group, err = prepareOrdinaryGroup(ctx, root, bootstrap, plan.Profile, current.path, *step, &evidence, output)
					if group != nil {
						prepared.ordinary[key] = group
					}
					if err != nil && !containedCheckFailure(ctx, err) {
						return err
					}
				}
				if group.step.OrdinaryFocus != nil && group.step.OrdinaryPreparation != nil {
					step.OrdinaryFocus, step.OrdinaryPreparation, step.OrdinarySelection = group.step.OrdinaryFocus, group.step.OrdinaryPreparation, group.step.OrdinarySelection
				}
				for _, artifact := range group.artifacts {
					big, err := selectedRootsBig(artifact.Package, artifact.Tests, artifact.Classifications)
					if err != nil {
						return err
					}
					prepared.class.Big = prepared.class.Big || big
				}
				return group.preparationFailure
			case "component-tests":
				if previous := prepared.preparationFailures[key]; previous != nil {
					return previous
				}
				group := prepared.components[key]
				requested := slices.Clone(step.Tests)
				if group == nil {
					group = newPreparedComponentGroup(ctx)
					prepared.components[key] = group
					build := filepath.Join(private, "component-"+key)
					if err := os.Mkdir(build, 0700); err != nil {
						return err
					}
					future, planErr := assemblyConstructionCommands(assemblyBindings{})
					if planErr != nil {
						return planErr
					}
					future = append(future, preparationReservationFact("test2json", true))
					future = append(future, inventoryPreparationCommands("inventory")...)
					finishPlan, planErr := beginPreparationPlan(diagnostics, future)
					if planErr != nil {
						return planErr
					}
					defer finishPlan()
					value, buildErr := group.prepareContext(diagnostics.runGoEnvironment, diagnostics, ctx, root, bootstrap, step.Profile, requested, binding.source, binding.toolchain, build)
					if buildErr != nil {
						return diagnostics.recordPreparationFailure(buildErr)
					}
					value.preparationOwner, value.preparationKey = group, key
					group.assembled.preparationOwner, group.assembled.preparationKey = group, key
					env := append(workerEnvironment(""), failureSourcesEnvironment(value.FailureSources)...)
					selectionCtx, finishSelection := group.duration.preparationContext(ctx)
					if len(requested) != 0 {
						selectionCtx = cacheOnlyGoContext(selectionCtx)
					}
					selection, diagnostics, prepareErr := prepareComponentChecks(diagnostics, selectionCtx, root, value.Binary, value.buildFlags, env, step.Profile, requested, &value)
					finishSelection()
					if value.converter.preparation != nil && !value.converterRecorded {
						prepareErr = errors.Join(prepareErr, diagnostics.append(*value.converter.preparation))
					}
					prepared.preparations[key] = diagnostics
					if prepareErr != nil {
						return prepareErr
					}
					group.assembled.componentSelection = selection
					finishPlan()
				}
				selected := group.assembled.componentSelection
				roots := selected.selected
				if selected.focus != nil {
					roots = requestedTestRoots(selected.focus.Tests)
				}
				big, err := selectedRootsBig(componentPackage, roots, selected.evidence.Classifications)
				if err != nil {
					return err
				}
				prepared.class.Big = prepared.class.Big || big
				if step.Focus != nil {
					step.Focus = selected.focus
					step.Preparation = &componentPreparation{Source: binding.source, Toolchain: binding.toolchain, BuildClosure: group.assembled.Closure, Inventory: selected.evidence.Inventory, Classifications: selected.evidence.Classifications, NotSelected: selected.evidence.NotSelected, ExecutionProof: "pending; the exact requested node must start and pass", ParentPreparation: "Required parent setup and selected subtree assertions execute; dynamic child existence is verified during run."}
				}
			case "assembly-checks":
				if step.Responsibility == "common" {
					return nil
				}
				directory := filepath.Join(private, "provider-"+key)
				if err := os.Mkdir(directory, 0700); err != nil {
					return err
				}
				future, planErr := assemblyConstructionCommands(assemblyBindings{})
				if planErr != nil {
					return planErr
				}
				future = append(future, inventoryPreparationCommands("assembly-inventory")...)
				future = append(future, preparationReservationFact("test2json", true))
				finishPlan, planErr := beginPreparationPlan(diagnostics, future)
				if planErr != nil {
					return planErr
				}
				defer finishPlan()
				value, buildErr := buildAssembly(diagnostics.runGoEnvironment, diagnostics, ctx, root, "live", step.Responsibility, bootstrap, directory)
				if buildErr != nil {
					return diagnostics.recordPreparationFailure(buildErr)
				}
				requested := ""
				if step.AssemblyFocus != nil {
					requested = step.AssemblyFocus.Requested
				}
				selection, diagnostics, prepareErr := prepareProviderChecks(diagnostics, ctx, root, value, plan.Profile, step.Responsibility == "gcp", requested, binding.source, binding.toolchain)
				prepared.preparations[key] = diagnostics
				if prepareErr != nil {
					return prepareErr
				}
				value.providerSelection = selection
				value.preparationOwner, value.preparationKey = prepared, key
				prepared.providers[step.ID] = value
				finishPlan()
				step.AssemblyFocus, step.AssemblyPreparation = selection.focus, selection.preparation
				roots := selection.selected
				if selection.focus != nil {
					roots = []string{selection.focus.Owner}
				}
				big, err := selectedRootsBig(componentPackage, roots, selection.evidence.Classifications)
				if err != nil {
					return err
				}
				prepared.class.Big = prepared.class.Big || big
			case "run":
				selection, prepareErr := prepareSuite(diagnostics, ctx, root, bootstrap, step.request, output)
				if selection != nil {
					prepared.suites[step.ID] = selection
				}
				if prepareErr != nil {
					return prepareErr
				}
				prepared.class.Big = prepared.class.Big || selection.class.Big
				prepared.class.CleanupSeconds = max(prepared.class.CleanupSeconds, selection.class.CleanupSeconds)
			case "fuzz":
				selection, prepareErr := prepareFuzz(diagnostics, ctx, root, step.Targets, policy, output)
				if selection != nil {
					prepared.fuzz[step.ID] = selection
				}
				if prepareErr != nil {
					return prepareErr
				}
				prepared.class.Big = prepared.class.Big || selection.class.Big
			case "lint":
				diagnostics.Preparation = "passed"
			default:
				return errors.New("unknown prepared activity")
			}
			return nil
		}()
		if prepareErr != nil {
			diagnostics.Preparation = "failed"
			if step.Kind == "fuzz" || !containedCheckFailure(ctx, prepareErr) {
				return errors.Join(append(failures, prepareErr)...)
			}
			prepared.preparationFailures[key] = prepareErr
			failures = append(failures, prepareErr)
		}
		prepared.ready[i] = true
	}
	for _, diagnostics := range prepared.preparations {
		if diagnostics.Preparation == "pending" {
			diagnostics.Preparation = "passed"
		}
	}
	return errors.Join(failures...)
}

func (prepared *preparedWorkflow) preparationError() error {
	var failures []error
	seen := map[string]bool{}
	for _, step := range prepared.plan.Steps {
		key := workflowPreparationKey(step)
		if failure := prepared.preparationFailures[key]; failure != nil && !seen[key] {
			seen[key] = true
			failures = append(failures, failure)
		}
	}
	return errors.Join(failures...)
}

func (prepared *preparedWorkflow) admission() rootAdmission {
	return rootAdmission{Execution: executionForClass(prepared.plan.Execution, false)}
}
func commandForDiagnostics(d *checkDiagnostics) goEnvironmentCommand {
	if d != nil {
		return d.runGoEnvironment
	}
	return runGoEnvironment
}
func (prepared *preparedWorkflow) verify(ctx context.Context, root string) error {
	return prepared.verifyOwners(ctx, root, func(string) *checkDiagnostics { return nil }, nil)
}
func (prepared *preparedWorkflow) verifyAcquisition(ctx context.Context, root string) error {
	currentFor := func(key string) *checkDiagnostics {
		if d := prepared.preparations[key]; d != nil {
			return d
		}
		for _, step := range prepared.plan.Steps {
			if step.ID == key {
				return prepared.preparations[workflowPreparationKey(step)]
			}
		}
		return nil
	}
	var first *checkDiagnostics
	for _, step := range prepared.plan.Steps {
		if step.Selected {
			first = currentFor(workflowPreparationKey(step))
			break
		}
	}
	return prepared.verifyOwners(ctx, root, currentFor, first)
}
func (prepared *preparedWorkflow) verifyResult(ctx context.Context, root string, result *workflowResult, output io.Writer) (err error) {
	if err = prepared.retainWorkflowPreparation(result, nil, output); err != nil {
		for _, execution := range result.executions {
			if execution.Preparation != nil {
				execution.Preparation.Preparation = "failed"
			}
		}
		return err
	}
	for _, step := range result.Steps {
		if step.Selected {
			execution := result.executions[step.ID]
			if execution.Preparation == nil {
				execution.Preparation = &checkDiagnostics{Preparation: "passed"}
				result.executions[step.ID] = execution
			}
		}
	}
	currentFor := func(key string) *checkDiagnostics {
		for _, step := range result.Steps {
			if step.Selected && (step.ID == key || workflowPreparationKey(step.resolvedWorkflowStep) == key) {
				return result.executions[step.ID].Preparation
			}
		}
		return nil
	}
	var first *checkDiagnostics
	for _, step := range result.Steps {
		if step.Selected {
			first = currentFor(step.ID)
			break
		}
	}
	defer func() {
		var failures []error
		if err != nil {
			failures = append(failures, err)
		}
		for _, execution := range result.executions {
			if writeErr := writeCheckDiagnostics(output, execution.Preparation); writeErr != nil {
				failures = append(failures, writeErr)
			}
		}
		err = errors.Join(failures...)
	}()
	return prepared.verifyOwners(ctx, root, currentFor, first)
}
func (prepared *preparedWorkflow) verifyOwners(ctx context.Context, root string, currentFor func(string) *checkDiagnostics, first *checkDiagnostics) (err error) {
	ctx = useInvocationArtifacts(ctx, prepared.assemblyPreparations)
	active := first
	defer func() {
		if err != nil && active != nil {
			active.Preparation = "failed"
		}
	}()
	active = first
	defer func() {
		if prepared.class.Live {
			err = safePreparationFailure(err)
		}
	}()
	defer func() { prepared.joined = prepared.joined && toolCommandsJoined(err) }()
	ctx = prepared.binding.context(ctx)
	ctx = useLocalPreparationPhase(ctx, prepared.phase)
	if prepared.closed || !prepared.joined {
		return errors.New("prepared workflow is closed or unsettled")
	}
	body, err := json.Marshal(prepared.plan)
	if err != nil || digestBytes(body) != prepared.planIdentity {
		return errors.Join(err, errors.New("prepared workflow selection changed"))
	}
	if err := prepared.binding.checkRace(ctx); err != nil {
		return err
	}
	for _, group := range prepared.ordinary {
		if err := group.verify(ctx, root, prepared.plan.Profile); err != nil {
			return err
		}
	}
	for key, group := range prepared.components {
		if prepared.preparationFailures[key] != nil {
			continue
		}
		active = currentFor(key)
		step := prepared.stepForKey(key)
		requested := slices.Clone(step.Tests)
		if _, err := group.prepareContext(commandForDiagnostics(currentFor(key)), currentFor(key), ctx, root, prepared.bootstrap, step.Profile, requested, prepared.binding.source, prepared.binding.toolchain, filepath.Dir(group.assembled.Binary)); err != nil {
			return err
		}
	}
	for key, value := range prepared.providers {
		if prepared.preparationFailures[workflowPreparationKey(prepared.stepForKey(key))] != nil {
			continue
		}
		active = currentFor(key)
		if value.providerSelection == nil {
			return errors.New("prepared provider selection unavailable")
		}
		if err := checkAssemblyRace(ctx, value); err != nil {
			return err
		}
	}
	for key, suite := range prepared.suites {
		if prepared.preparationFailures[workflowPreparationKey(prepared.stepForKey(key))] != nil {
			continue
		}
		active = currentFor(key)
		if err := suite.verify(ctx, root); err != nil {
			return err
		}
	}
	for key, fuzz := range prepared.fuzz {
		if prepared.preparationFailures[workflowPreparationKey(prepared.stepForKey(key))] != nil {
			continue
		}
		if err := fuzz.verify(ctx, root); err != nil {
			return err
		}
	}
	return nil
}
func (prepared *preparedWorkflow) stepForKey(key string) resolvedWorkflowStep {
	for _, step := range prepared.plan.Steps {
		if step.ID == key || workflowPreparationKey(step) == key {
			return step
		}
	}
	return resolvedWorkflowStep{}
}

// Preparation can close before any activity returns a result. Keep its acquired
// facts on the first selected repetition without claiming test execution.
func (prepared *preparedWorkflow) retainWorkflowPreparation(result *workflowResult, reported map[string]*checkDiagnostics, output io.Writer) (err error) {
	if prepared.class.Live {
		defer func() { err = safePreparationFailure(err) }()
	}
	if result.Name == "" {
		plan := prepared.plan
		executions := result.executions
		*result = workflowResult{executions: executions, SchemaVersion: 1, Name: plan.Name, Profile: plan.Profile, Race: raceSetting(plan.Race), Execution: recordExecutionPolicy(plan.Execution), Source: prepared.binding.source, Outcome: "incomplete"}
		for _, step := range plan.Steps {
			outcome := "not_run"
			if !step.Selected {
				outcome = "not_selected"
			}
			result.Steps = append(result.Steps, workflowStepResult{resolvedWorkflowStep: step, EffectiveTelemetry: step.request.effectiveTelemetry.clone(), Outcome: outcome})
		}
	}
	if result.executions == nil {
		result.executions = map[string]workflowStepExecution{}
	}
	attached := map[string]bool{}
	var failures []error
	for _, step := range result.Steps {
		key := workflowPreparationKey(step.resolvedWorkflowStep)
		if !step.Selected || attached[key] {
			continue
		}
		attached[key] = true
		execution := result.executions[step.ID]
		var owner any = prepared
		claimKey := key
		preparation := prepared.preparations[key]
		if group := prepared.ordinary[key]; group != nil {
			preparation = group.preparation
			owner = group
		}
		if group := prepared.components[key]; group != nil && group.assembled.componentSelection != nil {
			preparation = group.assembled.componentSelection.evidence.Diagnostics
			owner = group
		}
		if value, exists := prepared.providers[step.ID]; exists && value.providerSelection != nil {
			preparation = value.providerSelection.evidence.Diagnostics
		}
		if suite := prepared.suites[step.ID]; suite != nil {
			owner, claimKey = suite, suite.requestIdentity
			if suite.preparationOwner != nil {
				owner, claimKey = suite.preparationOwner, suite.preparationKey
			}
			if suite.preparation != nil {
				preparation = suite.preparation
			}
			if suite.inventory.providerSelection != nil {
				preparation = suite.inventory.providerSelection.evidence.Diagnostics
			}
			if suite.inventory.Closure.LocalChecks != nil {
				preparation = suite.inventory.Closure.LocalChecks.Diagnostics
			}
		}
		if fuzz := prepared.fuzz[step.ID]; fuzz != nil && fuzz.preparation != nil {
			preparation = fuzz.preparation
		}
		if preparation == nil {
			if writeErr := writeCheckDiagnostics(output, execution.Preparation); writeErr != nil {
				failures = append(failures, writeErr)
			}
			continue
		}
		if execution.Preparation == nil {
			actual := execution.diagnostics()
			if actual != nil && actual.hasAcquisition(owner, claimKey) {
				if writeErr := writeCheckDiagnostics(output, actual); writeErr != nil {
					failures = append(failures, writeErr)
				}
				continue
			}
		}
		if execution.Preparation == nil {
			execution.Preparation = &checkDiagnostics{Preparation: "passed"}
		}
		if retainErr := execution.Preparation.retainAcquisition(owner, claimKey, preparation); retainErr != nil {
			failures = append(failures, retainErr)
		}
		result.executions[step.ID] = execution
		if writeErr := writeCheckDiagnostics(output, execution.Preparation); writeErr != nil {
			failures = append(failures, writeErr)
		}
	}
	return errors.Join(failures...)
}

func (prepared *preparedWorkflow) close(ctx context.Context) (err error) {
	defer func() {
		err = errors.Join(err, prepared.artifactOwner.close(ctx, prepared.joined && toolCommandsJoined(err)))
	}()
	defer func() {
		if prepared.class.Live {
			err = safePreparationFailure(err)
		}
	}()
	if prepared.closed {
		return nil
	}
	prepared.closed = true
	var errs []error
	for _, group := range prepared.ordinary {
		group.joined = group.joined && prepared.joined
		errs = append(errs, group.close())
	}
	for _, group := range prepared.components {
		group.cancel()
	}
	for _, suite := range prepared.suites {
		errs = append(errs, suite.close(ctx))
	}
	for _, fuzz := range prepared.fuzz {
		errs = append(errs, fuzz.close(ctx))
	}
	if prepared.current != nil {
		errs = append(errs, prepared.current.remove(prepared.joined && toolCommandsJoined(errors.Join(errs...))))
	}
	errs = append(errs, closeLocalPreparationPhase(ctx, prepared.phase, prepared.joined && toolCommandsJoined(errors.Join(errs...))))
	return errors.Join(errs...)
}
func runPreparedWorkflow(ctx context.Context, root, bootstrap string, prepared *preparedWorkflow, output io.Writer) (workflowResult, error) {
	return runPreparedWorkflowResult(ctx, root, bootstrap, prepared, output, workflowResult{})
}
func runPreparedWorkflowResult(ctx context.Context, root, bootstrap string, prepared *preparedWorkflow, output io.Writer, initial workflowResult) (result workflowResult, err error) {
	ctx = prepared.binding.context(ctx)
	releaseArtifacts, borrowErr := borrowInvocationArtifacts(ctx)
	if borrowErr != nil {
		return result, borrowErr
	}
	defer func() { releaseArtifacts(prepared.joined && toolCommandsJoined(err)) }()

	ctx = useInvocationArtifacts(ctx, prepared.assemblyPreparations)
	result = initial
	defer func() {
		err = errors.Join(prepared.preparationError(), err, prepared.retainWorkflowPreparation(&result, nil, output))
		prepared.joined = prepared.joined && toolCommandsJoined(err)
	}()
	ctx = prepared.binding.context(ctx)
	ctx = useLocalPreparationPhase(ctx, prepared.phase)
	if err := prepared.verifyResult(ctx, root, &result, output); err != nil {
		return result, err
	}
	plan := prepared.plan
	plan.prepared = prepared
	plan.currentExecutions = maps.Clone(result.executions)
	return runWorkflow(ctx, root, bootstrap, plan, output)
}
func prepareLocalWorkflow(ctx context.Context, root, bootstrap, name string, execution executionRequest, output io.Writer) (*preparedWorkflow, error) {
	profile := "full"
	if name == "dev" {
		profile = "dev"
	} else if name != "check" {
		return nil, errors.New("unknown local verification workflow")
	}
	plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: filepath.Join(root, "tests/workflows", name+".json"), Execution: execution})
	if err != nil {
		return nil, err
	}
	err = validateLocalWorkflow(plan, profile)
	if err != nil {
		return nil, err
	}
	return prepareWorkflow(ctx, root, bootstrap, plan, output)
}

type preparedSuite struct {
	artifactOwner        *invocationArtifacts
	assemblyPreparations context.Context
	preparationOwner     any
	preparationKey       string
	preparation          *checkDiagnostics
	request              runRequest
	binding              preparationBinding
	current              *currentDirectory
	phase                *toolDirectoryPhase
	inventory            assembly
	workers              []string
	compiled             []string
	classifications      []testClassification
	reconstruction       map[string]configurationRecoveryArtifact
	requestIdentity      string
	class                rootAdmission
	joined, closed       bool
}

func suiteRequestIdentity(request runRequest) (string, error) {
	value := struct {
		Suite, Provider, Target, Profile, Limits string
		Allowance                                *limits
		Resolved                                 *resolvedRequest
		Environment                              *environmentFile
	}{request.Suite, request.Provider, request.Target, request.Profile, request.Limits, request.Allowance, request.Resolved, request.environment}
	body, err := json.Marshal(value)
	return digestBytes(body), err
}

type componentReuseFailure struct{ cause error }

func (failure *componentReuseFailure) Error() string { return failure.cause.Error() }
func (failure *componentReuseFailure) Unwrap() error { return failure.cause }

func verifyScenarioComponentsOwned(diagnostics *checkDiagnostics, ctx context.Context, root, bootstrap string, request runRequest, source records.Source, toolchain string) error {
	if request.Resolved == nil || request.Resolved.raceMissing {
		return errors.New("accepted scenario selection unavailable")
	}
	if accepted, present := ctx.Value(racePolicyContextKey{}).(bool); present && accepted != request.Resolved.Race {
		return errors.New("scenario race policy differs from invocation")
	}
	components := request.components
	if request.Suite != "hermetic" || request.Provider != "memory" || components == nil || components.assembled.Binary == "" || components.assembled.Closure.Suite != "hermetic" || components.assembled.Closure.Provider != "memory" || components.assembled.Closure.Race != request.Resolved.Race {
		return errors.New("component step evidence does not match this scenario run")
	}
	if components.assembled.root != root {
		return errors.New("component prepared source root changed")
	}
	if components.record.BuildClosure != nil && !sameAssemblyBuild(components.assembled.Closure, *components.record.BuildClosure) {
		return errors.New("component step assembly does not match its evidence")
	}
	return checkAssemblyRace(withRacePolicy(ctx, request.Resolved.Race), components.assembled)
}

func prepareSuite(initial *checkDiagnostics, ctx context.Context, root, bootstrap string, request runRequest, output io.Writer) (prepared *preparedSuite, err error) {
	ctx, artifactOwner := withInvocationArtifacts(ctx)

	defer func() {
		if request.Suite == "live" {
			err = safePreparationFailure(err)
		}
	}()
	ctx, bootstrapErr := withPreparationBootstrap(ctx, root, bootstrap)
	if bootstrapErr != nil {
		return nil, bootstrapErr
	}

	if request.Resolved == nil || request.Resolved.raceMissing {
		return nil, errors.New("accepted scenario selection unavailable")
	}
	if accepted, present := ctx.Value(racePolicyContextKey{}).(bool); present && accepted != request.Resolved.Race {
		return nil, errors.New("scenario race policy differs from invocation")
	}
	ctx = withRacePolicy(ctx, request.Resolved.Race)
	policy, err := executionWithinContext(ctx, request.execution)
	if err != nil {
		return nil, err
	}
	request.execution = policy
	ctx = withExecutionCapacity(ctx, policy)
	if request.Limits != "" {

	}
	ctx, phase, err := localPreparationPhase(ctx, root)
	defer func() {
		if err != nil && prepared == nil {
			err = errors.Join(err, closeLocalPreparationPhase(ctx, phase, toolCommandsJoined(err)))
		}
	}()
	if err != nil {
		return nil, err
	}
	diagnostics := initial
	if diagnostics == nil {
		diagnostics = &checkDiagnostics{Preparation: "pending"}
	}
	prepared = &preparedSuite{assemblyPreparations: ctx, preparation: diagnostics, request: request, phase: phase, class: rootAdmission{Execution: policy, Live: request.Suite == "live"}, joined: true}
	prepared.artifactOwner = artifactOwner
	future, planErr := suiteConstructionCommands(request)
	if planErr != nil {
		return prepared, planErr
	}
	finishPlan, planErr := beginPreparationPlan(diagnostics, future)
	if planErr != nil {
		return prepared, planErr
	}
	defer finishPlan()
	defer func() { prepared.joined = prepared.joined && toolCommandsJoined(err) }()
	binding, err := prepareBindingOwned(diagnostics, ctx, root, request.Suite == "live")
	prepared.binding = binding
	if err != nil {
		prepared.inventory.Closure.LocalChecks = &checkEvidence{raceMissing: true, Diagnostics: diagnostics}
		return prepared, err
	}
	identity, err := suiteRequestIdentity(request)
	if err != nil {
		return prepared, err
	}
	current, err := newCurrentDirectory("enkv-scenario-preparation-")
	if err != nil {
		return prepared, err
	}
	prepared.current, prepared.requestIdentity = current, identity
	if request.Suite == "live" && (request.Allowance != nil || request.Limits != "") {
		allowance := request.Allowance
		if allowance == nil {
			value, loadErr := loadLimits(request.Limits)
			if loadErr != nil {
				return prepared, loadErr
			}
			allowance = &value
		}
		if !allowance.valid() {
			return prepared, errors.New("live limits invalid during preparation")
		}
		prepared.class.CleanupSeconds = int(allowance.CleanupSeconds)
	}
	build := filepath.Join(current.path, "build")
	if err := os.Mkdir(build, 0700); err != nil {
		return prepared, err
	}
	var value assembly
	if request.components != nil {
		if err := verifyScenarioComponentsOwned(diagnostics, ctx, root, bootstrap, request, binding.source, binding.toolchain); err != nil {
			return prepared, &componentReuseFailure{cause: err}
		}
		value = request.components.assembled
	} else {
		bindings, bindingErr := prepareScenarioAssemblyBindings(ctx, root, build, request)
		if bindingErr != nil {
			return prepared, bindingErr
		}
		value, err = buildBoundAssemblyMode(diagnostics.runGoEnvironment, diagnostics, ctx, root, request.Suite, request.Provider, bootstrap, build, request.Resolved.Race, bindings)
		if err != nil {
			prepared.inventory.Closure.LocalChecks = &checkEvidence{raceMissing: true, Profile: "full", Outcome: "process_failed", Diagnostics: diagnostics}
			err = diagnostics.recordPreparationFailure(err)
			return prepared, err
		}
	}
	prepared.inventory = value
	prepared.inventory.currentPrefix = nil
	prepared.inventory.preparationOwner, prepared.inventory.preparationKey = prepared, prepared.requestIdentity
	environment := append(workerEnvironment(""), failureSourcesEnvironment(value.FailureSources)...)
	inventory, inventoryErr := prepareCompiledInventory(ctx, root, value, environment, "scenario-inventory", diagnostics)
	if inventoryErr != nil {
		return prepared, inventoryErr
	}
	prepared.compiled, prepared.classifications = inventory.names, inventory.classifications
	helpers, err := selectedReconstructionHelpers(request)
	if err != nil {
		return prepared, err
	}
	prepared.reconstruction = make(map[string]configurationRecoveryArtifact)
	artifactSource := binding.source
	for _, provider := range slices.Sorted(maps.Keys(helpers)) {
		directory := filepath.Join(current.path, "reconstruction-"+provider)
		if err := os.Mkdir(directory, 0700); err != nil {
			return prepared, err
		}
		artifact, big, err := prepareConfigurationRecoveryArtifactOwned(diagnostics, ctx, root, directory, provider, artifactSource, helpers[provider])
		if err != nil {
			return prepared, err
		}
		prepared.reconstruction[provider] = artifact
		prepared.class.Big = prepared.class.Big || big
	}
	workers, err := scenarioWorkerRoots(request)
	if err != nil {
		return prepared, err
	}
	prepared.workers = workers
	for _, worker := range workers {
		if !slices.Contains(prepared.compiled, worker) {
			return prepared, errors.New("scenario worker missing from compiled inventory")
		}
	}
	big, err := selectedRootsBig(componentPackage, workers, prepared.classifications)
	if err != nil {
		return prepared, err
	}
	prepared.class.Big = prepared.class.Big || big
	if err := prepared.verify(ctx, root); err != nil {
		return prepared, err
	}
	diagnostics.Preparation = "passed"
	return prepared, nil
}

func selectedReconstructionHelpers(request runRequest) (map[string][]string, error) {
	helpers := make(map[string][]string)
	for _, entry := range request.Schedule.Entries {
		if !catalog.HasFixtureCapability(entry.Scenario, catalog.FixtureConfigurationRecovery) {
			continue
		}
		providers := []string{request.Provider}
		if request.Suite == "hermetic" {
			if request.Resolved == nil {
				return nil, errors.New("reconstruction selection unavailable")
			}
			providers = nil
			cells := recordedReconstructionCells(entry.Scenario, request.Resolved.RecoveryMode)
			if len(cells) == 0 {
				return nil, errors.New("reconstruction selection has no process cells")
			}
			for _, cell := range cells {
				if !slices.Contains(providers, cell.Provider) {
					providers = append(providers, cell.Provider)
				}
			}
		}
		for _, provider := range providers {
			if provider != "aws" && provider != "gcp" {
				return nil, errors.New("reconstruction provider refused")
			}
			roots := []string{recoveryPhaseHelper(provider, "reconstruction-parent")}
			if request.Suite == "hermetic" {
				roots = append([]string{recoveryPhaseHelper(provider, "resource-owner")}, roots...)
			}
			for _, root := range roots {
				if !slices.Contains(helpers[provider], root) {
					helpers[provider] = append(helpers[provider], root)
				}
			}
		}
	}
	return helpers, nil
}

func scenarioWorkerRoots(request runRequest) ([]string, error) {
	prefix := "TestHermetic"
	if request.Suite == "live" {
		prefix = "TestLive"
	}
	var roots []string
	add := func(name string) {
		if !slices.Contains(roots, name) {
			roots = append(roots, name)
		}
	}
	for _, entry := range request.Schedule.Entries {
		if request.Suite == "hermetic" && catalog.HasFixtureCapability(entry.Scenario, catalog.FixtureConfigurationRecovery) {
			add(recoveryPhaseHelper("", "setup"))
			continue
		}
		execution, known := recordedExecution(entry.Scenario, request.Suite)
		if !known {
			return nil, errors.New("scenario process selection unavailable")
		}
		add(prefix + "Run")
		if len(execution.ExpandedFreshBefore()) != 0 || len(execution.ExpandedFreshAfter()) != 0 {
			add(prefix + "Child")
		}
		if request.Suite == "live" {
			add("TestLiveCleanup")
			if entry.Scenario == sameDomainRecoveryScenario {
				add("TestLiveRecovery")
			}
		}
	}
	return roots, nil
}
func (prepared *preparedSuite) admission() rootAdmission {
	value := prepared.class
	value.Execution = executionForClass(value.Execution, value.Big)
	return value
}
func (prepared *preparedSuite) verify(ctx context.Context, root string) error {
	return prepared.verifyOwned(nil, ctx, root)
}
func (prepared *preparedSuite) verifyOwned(diagnostics *checkDiagnostics, ctx context.Context, root string) (err error) {
	defer func() {
		if err != nil && diagnostics != nil {
			diagnostics.Preparation = "failed"
		}
	}()
	defer func() {
		if prepared.request.Suite == "live" {
			err = safePreparationFailure(err)
		}
	}()
	defer func() { prepared.joined = prepared.joined && toolCommandsJoined(err) }()
	ctx = prepared.binding.context(ctx)
	ctx = useLocalPreparationPhase(ctx, prepared.phase)
	if prepared.closed || !prepared.joined {
		return errors.New("scenario preparation is closed or unsettled")
	}
	if err := prepared.binding.checkRace(ctx); err != nil {
		return err
	}
	identity, err := suiteRequestIdentity(prepared.request)
	if err != nil || identity != prepared.requestIdentity {
		return errors.Join(err, errors.New("prepared scenario selection changed"))
	}
	for _, artifact := range prepared.reconstruction {
		if err := checkRecoveryRace(ctx, artifact); err != nil {
			return err
		}
	}
	return checkAssemblyRace(ctx, prepared.inventory)
}
func (prepared *preparedSuite) close(ctx context.Context) (err error) {
	defer func() {
		err = errors.Join(err, prepared.artifactOwner.close(ctx, prepared.joined && toolCommandsJoined(err)))
	}()
	defer func() {
		if prepared.request.Suite == "live" {
			err = safePreparationFailure(err)
		}
	}()
	if prepared.closed {
		return nil
	}
	prepared.closed = true
	if prepared.current != nil {
		err = prepared.current.remove(prepared.joined)
	}
	return errors.Join(err, closeLocalPreparationPhase(ctx, prepared.phase, prepared.joined && toolCommandsJoined(err)))
}

func (prepared *preparedSuite) bindActual(ctx context.Context, root string, actual *assembly) error {
	return prepared.bindActualOwned(nil, ctx, root, actual)
}
func (prepared *preparedSuite) bindActualOwned(diagnostics *checkDiagnostics, ctx context.Context, root string, actual *assembly) error {
	if err := prepared.verify(ctx, root); err != nil {
		return err
	}
	if actual.Binary != prepared.inventory.Binary || actual.Closure.Suite != prepared.inventory.Closure.Suite || actual.Closure.Provider != prepared.inventory.Closure.Provider || actual.Closure.Race != prepared.inventory.Closure.Race {
		return errors.New("actual scenario executable differs from selected executable")
	}
	actual.preparationOwner, actual.preparationKey = prepared.inventory.preparationOwner, prepared.inventory.preparationKey
	return nil
}

type preparedSuiteContextKey struct{}

func (value assembly) preparationDiagnostics() *checkDiagnostics {
	if value.Closure.LocalChecks != nil {
		return value.Closure.LocalChecks.Diagnostics
	}
	if value.providerSelection != nil {
		return value.providerSelection.evidence.Diagnostics
	}
	if value.componentSelection != nil {
		return value.componentSelection.evidence.Diagnostics
	}
	return nil
}

func (prepared *preparedSuite) retainPreparation(result *suiteExecution, output io.Writer) error {
	diagnostics := prepared.preparation
	if diagnostics == nil {
		diagnostics = prepared.inventory.preparationDiagnostics()
	}
	if result.preparation == nil {
		result.preparation = &checkDiagnostics{Preparation: "passed"}
	}
	var owner any = prepared
	key := prepared.requestIdentity
	if prepared.preparationOwner != nil {
		owner, key = prepared.preparationOwner, prepared.preparationKey
	}
	err := result.preparation.retainAcquisition(owner, key, diagnostics)
	err = errors.Join(err, writeCheckDiagnostics(output, result.preparation))
	if prepared.request.Suite == "live" {
		return safePreparationFailure(err)
	}
	return err
}

func runPreparedSuite(ctx context.Context, root, bootstrap string, prepared *preparedSuite, output io.Writer) (suiteExecution, error) {
	return prepared.execute(ctx, root, bootstrap, prepared.request.components, output)
}

func (prepared *preparedSuite) execute(ctx context.Context, root, bootstrap string, components *componentRun, output io.Writer) (suiteExecution, error) {
	return prepared.executeOwned(nil, ctx, root, bootstrap, components, output)
}
func runPreparedSuiteResult(ctx context.Context, root, bootstrap string, prepared *preparedSuite, output io.Writer, initial suiteExecution) (suiteExecution, error) {
	result, err := prepared.executeOwned(initial.preparation, ctx, root, bootstrap, prepared.request.components, output)
	if result.Record == nil {
		result.Record = initial.Record
	}
	if result.Recovery == nil {
		result.Recovery = initial.Recovery
	}
	if result.Evidence == "" {
		result.Evidence = initial.Evidence
	}
	return result, err
}
func (prepared *preparedSuite) executeOwned(initial *checkDiagnostics, ctx context.Context, root, bootstrap string, components *componentRun, output io.Writer) (result suiteExecution, err error) {
	ctx = useInvocationArtifacts(ctx, prepared.assemblyPreparations)
	result.preparation = initial
	if err := prepared.retainPreparation(&result, output); err != nil {
		return result, err
	}
	defer func() {

		err = errors.Join(err, prepared.retainPreparation(&result, output))
	}()
	ctx = prepared.binding.context(ctx)
	ctx = useLocalPreparationPhase(ctx, prepared.phase)
	if err := prepared.verifyOwned(result.preparation, ctx, root); err != nil {
		return result, err
	}
	request := prepared.request
	request.components = components
	if owner, present := ctx.Value(workflowRunIDContextKey{}).(string); present && request.Suite == "live" {
		if !records.ValidRunID(owner) || request.workflowRunID != "" && request.workflowRunID != owner {
			return result, errors.New("prepared scenario workflow owner differs")
		}
		request.workflowRunID = owner
	}
	ctx = context.WithValue(ctx, preparedSuiteContextKey{}, prepared)
	result, err = runSuiteOwned(result.preparation, ctx, root, bootstrap, request, output)
	prepared.joined = prepared.joined && toolCommandsJoined(err)
	return result, err
}

type preparedFuzzTarget struct {
	names []string
	spec  fuzzSpecification
}

type preparedFuzz struct {
	artifactOwner  *invocationArtifacts
	preparation    *checkDiagnostics
	names          []string
	targets        []preparedFuzzTarget
	policy         executionPolicy
	binding        preparationBinding
	current        *currentDirectory
	phase          *toolDirectoryPhase
	class          rootAdmission
	joined, closed bool
}
type preparedFuzzContextKey struct{}

func prepareFuzz(initial *checkDiagnostics, ctx context.Context, root string, names []string, policy executionPolicy, output io.Writer) (prepared *preparedFuzz, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, artifactOwner := withInvocationArtifacts(ctx)
	defer func() {
		if prepared == nil && artifactOwner != nil {
			err = errors.Join(err, artifactOwner.close(ctx, toolCommandsJoined(err)))
		}
	}()
	policy, err = executionWithinContext(ctx, policy)
	if err != nil {
		return nil, err
	}
	selected, err := selectFuzzTargets(names)
	if err != nil {
		return nil, err
	}
	ctx = withExecutionCapacity(ctx, policy)
	ctx, phase, err := localPreparationPhase(ctx, root)
	defer func() {
		if err != nil && prepared == nil {
			err = errors.Join(err, closeLocalPreparationPhase(ctx, phase, toolCommandsJoined(err)))
		}
	}()
	if err != nil {
		return nil, err
	}
	diagnostics := initial
	if diagnostics == nil {
		diagnostics = &checkDiagnostics{Preparation: "pending"}
	}
	prepared = &preparedFuzz{artifactOwner: artifactOwner, preparation: diagnostics, names: slices.Clone(names), policy: policy, phase: phase, class: rootAdmission{Execution: policy}, joined: true}
	defer func() { prepared.joined = prepared.joined && toolCommandsJoined(err) }()
	binding, err := prepareBindingOwned(diagnostics, ctx, root, false)
	prepared.binding = binding
	if err != nil {
		return prepared, err
	}
	current, err := newCurrentDirectory("enkv-fuzz-preparation-")
	if err != nil {
		return prepared, err
	}
	prepared.current = current
	for _, spec := range selected {
		artifact, artifactErr := prepareFuzzArtifact(ctx, root, current.path, spec, diagnostics)
		if artifactErr != nil {
			return prepared, artifactErr
		}
		names, classifications := artifact.executable.inventory.Inventory, artifact.executable.inventory.Classifications
		if !slices.Contains(names, spec.Target) {
			return prepared, errors.New("selected fuzz target missing from compiled inventory")
		}
		big, classifyErr := selectedRootsBig(spec.importPath(), []string{spec.Target}, classifications)
		if classifyErr != nil {
			return prepared, classifyErr
		}
		prepared.class.Big = prepared.class.Big || big
		prepared.targets = append(prepared.targets, preparedFuzzTarget{spec: spec, names: slices.Clone(names)})
	}
	if err := prepared.verify(ctx, root); err != nil {
		return prepared, err
	}
	diagnostics.Preparation = "passed"
	return prepared, nil
}
func (prepared *preparedFuzz) admission() rootAdmission {
	value := prepared.class
	value.Execution = executionForClass(value.Execution, value.Big)
	return value
}
func (prepared *preparedFuzz) verify(ctx context.Context, root string) (err error) {
	defer func() { prepared.joined = prepared.joined && toolCommandsJoined(err) }()
	ctx = prepared.binding.context(ctx)
	ctx = useLocalPreparationPhase(ctx, prepared.phase)
	if prepared.closed || !prepared.joined {
		return errors.New("fuzz preparation closed or unsettled")
	}
	if err := prepared.binding.checkRace(ctx); err != nil {
		return err
	}
	selected, err := selectFuzzTargets(prepared.names)
	if err != nil {
		return err
	}
	if len(selected) != len(prepared.targets) {
		return errors.New("prepared fuzz selection changed")
	}
	for i, target := range prepared.targets {
		if target.spec != selected[i] {
			return errors.New("prepared fuzz target changed")
		}

	}
	return nil
}
func (prepared *preparedFuzz) close(ctx context.Context) error {
	if prepared.closed {
		return nil
	}
	prepared.closed = true
	var err error
	if prepared.current != nil {
		err = prepared.current.remove(prepared.joined)
	}
	err = errors.Join(err, closeLocalPreparationPhase(ctx, prepared.phase, prepared.joined && toolCommandsJoined(err)))
	if prepared.artifactOwner != nil {
		err = errors.Join(err, prepared.artifactOwner.close(ctx, prepared.joined && toolCommandsJoined(err)))
	}
	return err
}
func runPreparedFuzz(ctx context.Context, root string, prepared *preparedFuzz, output io.Writer) ([]*fuzzEvidence, error) {
	ctx = prepared.binding.context(ctx)
	ctx = useLocalPreparationPhase(ctx, prepared.phase)
	if err := prepared.verify(ctx, root); err != nil {
		return nil, err
	}
	ctx = context.WithValue(ctx, preparedFuzzContextKey{}, prepared)
	policy, err := executionWithinContext(ctx, prepared.policy)
	if err != nil {
		return nil, err
	}
	result, err := runFuzz(ctx, root, prepared.names, policy, output)
	prepared.joined = prepared.joined && toolCommandsJoined(err)
	return result, err
}

type preparedLivePreflight struct {
	compiled        []string
	classifications []testClassification
	artifactOwner   *invocationArtifacts
	reconstruction  *configurationRecoveryArtifact
	binding         preparationBinding
	current         *currentDirectory
	inventory       assembly
	class           rootAdmission
	joined, closed  bool
}
type preparedLivePreflightsContextKey struct{}

func prepareLivePreflight(ctx context.Context, root, bootstrap, provider string, policy executionPolicy, requestedBindings ...assemblyBindings) (prepared *preparedLivePreflight, err error) {
	ctx, artifactOwner := withInvocationArtifacts(ctx)
	defer func() { err = safePreparationFailure(err) }()
	if len(requestedBindings) > 1 {
		return nil, errors.New("cleanup requires one actual assembly binding")
	}
	var bindings assemblyBindings
	if len(requestedBindings) == 1 {
		bindings = requestedBindings[0]
	}
	ctx, err = withPreparationBootstrap(ctx, root, bootstrap)
	if err != nil {
		return nil, err
	}
	current, err := newCurrentDirectory("enkv-cleanup-preparation-")
	if err != nil {
		return nil, err
	}
	diagnostics := &checkDiagnostics{Preparation: "pending"}
	prepared = &preparedLivePreflight{artifactOwner: artifactOwner, current: current, class: rootAdmission{Live: true, Execution: policy}, joined: true}
	prepared.inventory.currentPrefix = diagnostics
	defer func() { prepared.joined = prepared.joined && toolCommandsJoined(err) }()
	binding, err := prepareBindingOwned(diagnostics, ctx, root, true)
	prepared.binding = binding
	if err != nil {
		return prepared, err
	}
	value, err := buildBoundAssemblyMode(diagnostics.runGoEnvironment, diagnostics, ctx, root, "live", provider, bootstrap, current.path, raceEnabled(ctx), bindings)
	if err != nil {
		return prepared, diagnostics.recordPreparationFailure(err)
	}
	prepared.inventory = value
	prepared.inventory.currentPrefix = diagnostics
	prepared.inventory.preparationOwner, prepared.inventory.preparationKey = prepared, provider
	if err := diagnostics.reserveCommands(inventoryPreparationCommands("cleanup-inventory")); err != nil {
		return prepared, err
	}
	defer diagnostics.cancelReservations()
	environment := append(workerEnvironment(""), failureSourcesEnvironment(value.FailureSources)...)
	inventory, err := prepareCompiledInventory(ctx, root, value, environment, "cleanup-inventory", diagnostics)
	if err != nil {
		return prepared, err
	}
	prepared.compiled, prepared.classifications = inventory.names, inventory.classifications
	big, err := selectedRootsBig(componentPackage, []string{"TestLiveCleanup"}, inventory.classifications)
	if err != nil {
		return prepared, err
	}
	prepared.class.Big = big
	diagnostics.Preparation = "passed"
	return prepared, prepared.verify(ctx, root)
}

func (prepared *preparedLivePreflight) verify(ctx context.Context, root string) error {
	return prepared.verifyOwned(nil, ctx, root)
}
func (prepared *preparedLivePreflight) verifyOwned(diagnostics *checkDiagnostics, ctx context.Context, root string) (err error) {
	defer func() {
		if err != nil && diagnostics != nil {
			diagnostics.Preparation = "failed"
		}
	}()
	defer func() { err = safePreparationFailure(err) }()
	defer func() { prepared.joined = prepared.joined && toolCommandsJoined(err) }()
	ctx = prepared.binding.context(ctx)
	if prepared.closed || !prepared.joined {
		return errors.New("live preflight preparation closed or unsettled")
	}
	if err := prepared.binding.checkRace(ctx); err != nil {
		return err
	}
	if prepared.reconstruction != nil {
		if err := checkRecoveryRace(ctx, *prepared.reconstruction); err != nil {
			return err
		}
	}
	return checkAssemblyRace(ctx, prepared.inventory)
}
func (prepared *preparedLivePreflight) close(ctx context.Context) (err error) {
	defer func() {
		err = errors.Join(err, prepared.artifactOwner.close(ctx, prepared.joined && toolCommandsJoined(err)))
	}()
	defer func() { err = safePreparationFailure(err) }()
	if prepared.closed {
		return nil
	}
	prepared.closed = true
	return prepared.current.remove(prepared.joined)
}
func (prepared *preparedLivePreflight) bindActual(ctx context.Context, root string, actual *assembly) error {
	return prepared.bindActualOwned(nil, ctx, root, actual)
}
func (prepared *preparedLivePreflight) bindActualOwned(diagnostics *checkDiagnostics, ctx context.Context, root string, actual *assembly) error {
	if err := prepared.verify(ctx, root); err != nil {
		return err
	}
	actual.preparationOwner, actual.preparationKey = prepared.inventory.preparationOwner, prepared.inventory.preparationKey
	return checkAssemblyRace(ctx, *actual)
}

func livePreflightFromContext(ctx context.Context, provider string) *preparedLivePreflight {
	values, _ := ctx.Value(preparedLivePreflightsContextKey{}).(map[string]*preparedLivePreflight)
	return values[provider]
}
func suiteFromPreflight(request runRequest, live *preparedLivePreflight) (*preparedSuite, error) {
	identity, err := suiteRequestIdentity(request)
	if err != nil {
		return nil, err
	}
	workers, err := scenarioWorkerRoots(request)
	if err != nil {
		return nil, err
	}
	for _, root := range workers {
		if !slices.Contains(live.compiled, root) {
			return nil, errors.New("selected worker absent from prepared inventory")
		}
	}
	helpers, err := selectedReconstructionHelpers(request)
	if err != nil {
		return nil, err
	}
	reconstruction := make(map[string]configurationRecoveryArtifact)
	class := live.class
	big, err := selectedRootsBig(componentPackage, workers, live.classifications)
	if err != nil {
		return nil, err
	}
	class.Big = class.Big || big
	for provider, roots := range helpers {
		artifact := live.reconstruction
		if artifact == nil || artifact.Provider != provider {
			return nil, errors.New("selected reconstruction artifact was not prepared")
		}
		for _, root := range roots {
			if !slices.Contains(artifact.selected, root) {
				return nil, errors.New("selected reconstruction helper was not prepared")
			}
		}
		big, err := selectedRootsBig(modulePath(artifact.module), roots, artifact.classifications)
		if err != nil {
			return nil, err
		}
		class.Big = class.Big || big
		reconstruction[provider] = *artifact
	}
	inventory := live.inventory
	inventory.currentPrefix = nil
	inventory.preparationOwner, inventory.preparationKey = live, live.inventory.Closure.Provider
	return &preparedSuite{preparationOwner: live, preparationKey: live.inventory.Closure.Provider, request: request, reconstruction: reconstruction, binding: live.binding, inventory: inventory, workers: workers, compiled: live.compiled, classifications: live.classifications, requestIdentity: identity, class: class, joined: true}, nil
}

type preparedCleanup struct {
	artifactOwner *invocationArtifacts
	phase         *toolDirectoryPhase
	request       cleanupRequest
	preflight     *preparedLivePreflight
	plan          recoveryPlan
	basis         *cleanupRecoveryBasis
	class         rootAdmission

	closed bool
}
type preparedCleanupContextKey struct{}

func prepareCleanup(ctx context.Context, root, bootstrap string, request cleanupRequest, output io.Writer) (prepared *preparedCleanup, err error) {
	ctx, artifactOwner := withInvocationArtifacts(ctx)

	defer func() { err = safePreparationFailure(err) }()
	ctx, bootstrapErr := withPreparationBootstrap(ctx, root, bootstrap)
	if bootstrapErr != nil {
		return nil, bootstrapErr
	}

	policy, err := executionWithinContext(ctx, request.execution)
	if err != nil {
		return nil, err
	}
	request.execution = policy
	ctx = withRacePolicy(withExecutionCapacity(ctx, policy), request.race)

	plan, err := prepareRecovery(root, request)
	if err != nil {
		return nil, err
	}
	plan, basis, err := prepareFixtureRecovery(root, request, plan)
	if err != nil {
		return nil, err
	}
	ctx, phase, err := localPreparationPhase(ctx, root)
	if err != nil {
		return nil, err
	}
	prepared = &preparedCleanup{phase: phase, request: request, plan: plan, basis: basis, class: rootAdmission{Live: true, Execution: policy, CleanupSeconds: int(plan.Limits.CleanupSeconds)}}
	prepared.artifactOwner = artifactOwner
	outputs, bindingErr := cleanupOutputBindings(plan)
	if bindingErr != nil {
		return prepared, bindingErr
	}
	var generator *cloudflareAssemblyBinding
	if plan.Generator != nil {
		generator, err = prepareCloudflareAssemblyBinding(ctx, root, "", *plan.Generator)
		if err != nil {
			return prepared, err
		}
	}
	prepared.preflight, err = prepareLivePreflight(ctx, root, bootstrap, plan.Provider, policy, assemblyBindings{Output: outputs, Cloudflare: generator})
	if err != nil {
		return prepared, err
	}
	prepared.class.Big = prepared.preflight.class.Big
	return prepared, prepared.verifyOwned(prepared.preflight.inventory.preparationDiagnostics(), ctx, root)
}
func (prepared *preparedCleanup) admission() rootAdmission {
	value := prepared.class
	value.Execution = executionForClass(value.Execution, value.Big)
	return value
}
func (prepared *preparedCleanup) verify(ctx context.Context, root string) error {
	return prepared.verifyOwned(nil, ctx, root)
}
func (prepared *preparedCleanup) verifyOwned(diagnostics *checkDiagnostics, ctx context.Context, root string) (err error) {
	defer func() {
		if err != nil && diagnostics != nil {
			diagnostics.Preparation = "failed"
		}
	}()
	defer func() { err = safePreparationFailure(err) }()
	ctx = useLocalPreparationPhase(ctx, prepared.phase)
	if prepared.closed {
		return errors.New("cleanup preparation closed")
	}
	if err := prepared.preflight.verify(ctx, root); err != nil {
		return err
	}
	plan, err := prepareRecovery(root, prepared.request)
	if err != nil {
		return err
	}
	plan, basis, err := prepareFixtureRecovery(root, prepared.request, plan)
	if err != nil {
		return err
	}
	if plan.Provider != prepared.plan.Provider || int(plan.Limits.CleanupSeconds) > prepared.class.CleanupSeconds {
		return errors.New("prepared cleanup selection or allowance changed")
	}
	prepared.plan, prepared.basis = plan, basis
	return nil
}
func (prepared *preparedCleanup) close(ctx context.Context) (err error) {
	defer func() {
		err = errors.Join(err, prepared.artifactOwner.close(ctx, toolCommandsJoined(err)))
	}()
	defer func() { err = safePreparationFailure(err) }()
	if prepared.closed {
		return nil
	}
	prepared.closed = true
	if prepared.preflight != nil {
		err = prepared.preflight.close(ctx)
	}
	joined := prepared.preflight == nil || prepared.preflight.joined
	return errors.Join(err, closeLocalPreparationPhase(ctx, prepared.phase, joined && toolCommandsJoined(err)))
}
func (prepared *preparedCleanup) retainPreparation(result *suiteExecution, output io.Writer) error {
	if result.preparation == nil {
		result.preparation = &checkDiagnostics{Preparation: "passed"}
	}
	var err error
	if prepared.preflight != nil {
		err = result.preparation.retainAcquisition(prepared.preflight, prepared.preflight.inventory.Closure.Provider, prepared.preflight.inventory.preparationDiagnostics())
	}
	return safePreparationFailure(errors.Join(err, writeCheckDiagnostics(output, result.preparation)))
}

func runPreparedCleanup(ctx context.Context, root, bootstrap string, prepared *preparedCleanup, output io.Writer) (suiteExecution, error) {
	return runPreparedCleanupResult(ctx, root, bootstrap, prepared, output, suiteExecution{})
}
func runPreparedCleanupResult(ctx context.Context, root, bootstrap string, prepared *preparedCleanup, output io.Writer, initial suiteExecution) (result suiteExecution, err error) {
	result = initial
	if err := prepared.retainPreparation(&result, output); err != nil {
		return result, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, prepared.retainPreparation(&result, output))
		}
	}()
	ctx = useLocalPreparationPhase(ctx, prepared.phase)
	if err := prepared.verifyOwned(result.preparation, ctx, root); err != nil {
		return result, err
	}
	ctx = context.WithValue(ctx, preparedCleanupContextKey{}, prepared)
	ctx = context.WithValue(ctx, preparedLivePreflightsContextKey{}, map[string]*preparedLivePreflight{prepared.plan.Provider: prepared.preflight})
	result, err = runCleanupOwned(result.preparation, ctx, root, bootstrap, prepared.request, output)
	prepared.preflight.joined = prepared.preflight.joined && toolCommandsJoined(err)
	return result, err
}

func prepareScenarioAssemblyBindings(ctx context.Context, root, build string, request runRequest) (assemblyBindings, error) {
	var environment environmentFile
	if request.environment != nil {
		environment = *request.environment
	}
	profiles, err := selectPublicationOutputs(request.Schedule, environment)
	if err != nil {
		return assemblyBindings{}, err
	}
	outputs, err := selectedPublicationBindings(profiles)
	if err != nil {
		return assemblyBindings{}, err
	}
	bindings := assemblyBindings{Output: outputs}
	if request.Suite == "live" && environment.Generator != nil && !scheduleNeedsStockPlugins(request.Schedule) {
		generator, err := validateGenerator(*environment.Generator)
		if err != nil {
			return assemblyBindings{}, err
		}
		bindings.Cloudflare, err = prepareCloudflareAssemblyBinding(ctx, root, build, generator)
		if err != nil {
			return assemblyBindings{}, err
		}
	}
	return bindings, nil
}

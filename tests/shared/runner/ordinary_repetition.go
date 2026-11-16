package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	records "enkv.sh/core/internal/testrecords"
)

type workflowScratchContextKey struct{}

type preparedOrdinaryGroup struct {
	preparationFailure  error
	preparationFailures []ordinaryPreparationFailure
	blockedInventory    []ordinaryPackage
	preparation         *checkDiagnostics
	ctx                 context.Context
	cancel              context.CancelFunc
	duration            *preparedGroupDuration
	lease               func(context.Context, bool) error
	joined              bool
	source              records.Source
	profile             string
	toolchain           string
	goenv               map[string]string
	step                resolvedWorkflowStep
	artifacts           []preparedOrdinaryArtifact
	estimates           map[string]float64
	barrier             repetitionBarrier
	closed              bool
}

type preparedOrdinaryArtifact struct {
	ordinaryArtifact
	binary, binaryHash, cwd string
	converter               preparedTestEventConverter
	selection               string
	requests                []string
	barrier                 *repetitionBarrier
	owner                   *preparedOrdinaryGroup
	unit                    bool
	stops                   *ordinaryPackageStops
}

func prepareOrdinaryGroup(parent context.Context, root, bootstrap, profile, workflowDirectory string, step resolvedWorkflowStep, evidence *ordinaryStepEvidence, output io.Writer) (group *preparedOrdinaryGroup, err error) {
	allowance := time.Duration(0)
	if step.Kind == "unit" {
		allowance = unitGroupAllowance
	}
	if step.Kind == "runner-tests" {
		allowance = runnerGroupAllowance
	}
	duration := newPreparedGroupDuration(cacheOnlyGoContext(parent), allowance)
	group = &preparedOrdinaryGroup{ctx: duration.ctx, cancel: duration.cancel, duration: duration, joined: true, profile: profile, step: step}
	ctx, finishPreparation := duration.preparationContext(duration.ctx)
	defer finishPreparation()
	if evidence.Diagnostics == nil {
		evidence.Diagnostics = &checkDiagnostics{Preparation: "pending"}
	}
	group.preparation = evidence.Diagnostics
	var preparationErrors []error
	defer func() {
		// Returns add only the new failure; this owner adds retained failures once.
		group.preparationFailure = errors.Join(preparationErrors...)
		err = errors.Join(group.preparationFailure, err)
		if err != nil {
			evidence.Diagnostics.Preparation = "failed"
			group.joined = toolCommandsJoined(err)
			if !containedCheckFailure(parent, err) {
				err = errors.Join(err, group.close())
			}
		}
	}()
	files, ok := parent.Value(workflowScratchContextKey{}).(*currentDirectory)
	if !ok || files.path != workflowDirectory || files.verify() != nil {
		return group, errors.New("ordinary build owner unavailable")
	}
	builds := filepath.Join(workflowDirectory, "private", "ordinary-builds")
	if _, statErr := os.Lstat(builds); errors.Is(statErr, os.ErrNotExist) {
		if err := os.Mkdir(builds, 0700); err != nil {
			return group, err
		}

	} else if statErr != nil {
		return group, statErr
	}
	key := step.ConfiguredStep
	if key == "" {
		key = step.ID
	}
	directory := filepath.Join(builds, key)
	if err := os.Mkdir(directory, 0700); err != nil {
		return group, err
	}
	report, borrowed, leaseErr := borrowToolDirectoryPhase(ctx, root)
	if leaseErr != nil {
		return group, leaseErr
	}
	if borrowed {
		defer func() { report(toolCommandsJoined(err)) }()
	} else {
		locks, lockErr := resourceLocksFromContext(ctx)
		if lockErr != nil {
			return group, lockErr
		}
		lease, leaseErr := prepareToolDirectories(ctx, locks, root)
		if leaseErr != nil {
			return group, leaseErr
		}
		group.lease = lease.Release
	}
	binding, err := prepareBindingOwned(nil, ctx, root, false)
	if err != nil {
		return group, err
	}
	group.source, group.toolchain, group.goenv = binding.source, binding.toolchain, binding.environment
	var artifacts []ordinaryArtifact
	var focused []preparedOrdinaryArtifact
	if step.OrdinaryFocus != nil {
		selected, prepareErr := prepareOrdinaryFocusSelection(ctx, root, bootstrap, profile, directory, group.source, &group.step, evidence, output)
		if prepareErr != nil {
			if containedCheckFailure(parent, prepareErr) {
				preparationErrors = append(preparationErrors, prepareErr)
				for _, module := range moduleRoots {
					if len(step.Packages[module]) != 0 {
						group.preparationFailures = append(group.preparationFailures, ordinaryPreparationFailure{Directory: module, Patterns: slices.Clone(step.Packages[module]), Inventory: "unavailable", Reason: "module_preparation_failed"})
					}
				}
				return group, nil
			}
			return group, prepareErr
		}
		focused = selected
		for _, artifact := range focused {
			artifacts = append(artifacts, artifact.ordinaryArtifact)
		}
	} else if step.Kind == "unit" {
		overlay, overlayErr := prepareCryptoOverlay(ctx, root, directory)
		if overlayErr != nil {
			return group, overlayErr
		}
		for _, module := range moduleRoots {
			if len(step.Packages[module]) != 0 {
				artifacts = append(artifacts, ordinaryArtifact{Directory: module, BuildFlags: moduleTestFlags(root, module, overlay), Patterns: step.Packages[module]})
			}
		}
	} else {
		flags := []string{"-mod=readonly", "-modfile=" + assemblyModfile(root, "hermetic", "memory"), "-overlay=" + bootstrap}
		patterns := []string{"./internal/testmain", "./internal/testrecords", "./internal/testcatalog"}
		testFlags := []string{"-timeout=15m"}
		artifacts = append(artifacts, ordinaryArtifact{Directory: "core", BuildFlags: flags, Patterns: patterns, TestFlags: testFlags})
		artifacts = append(artifacts, ordinaryArtifact{Directory: "core", Package: "command-line-arguments", BuildFlags: []string{"-mod=readonly"}, Patterns: []string{"../tests/scripts/bootstrap.go", "../tests/scripts/bootstrap_test.go"}, TestFlags: testFlags})
	}
	for index, artifact := range artifacts {
		if step.OrdinaryFocus != nil {
			selected := focused[index]
			selected.barrier, selected.unit = &group.barrier, step.Kind == "unit"
			group.artifacts = append(group.artifacts, selected)
			continue
		}
		packages, listErr := listOrdinaryPackages(ctx, root, artifact.Directory, artifact.BuildFlags, artifact.Patterns, evidence.Diagnostics)
		if listErr != nil {
			if !containedCheckFailure(parent, listErr) {
				return group, listErr
			}
			preparationErrors = append(preparationErrors, listErr)
			group.preparationFailures = append(group.preparationFailures, ordinaryPreparationFailure{Directory: artifact.Directory, Patterns: slices.Clone(artifact.Patterns), Inventory: "unavailable", Reason: "package_discovery_failed"})
			continue
		}
		sort.Slice(packages, func(i, j int) bool { return packages[i].ImportPath < packages[j].ImportPath })
		for _, pkg := range packages {
			patterns := []string{pkg.ImportPath}
			if pkg.ImportPath == "command-line-arguments" {
				patterns = slices.Clone(artifact.Patterns)
			}
			compiled, compileErr := prepareOrdinaryPackage(ctx, root, artifact.Directory, artifact.BuildFlags, patterns, pkg, directory, evidence.Diagnostics)
			if compileErr != nil {
				if !containedCheckFailure(parent, compileErr) {
					return group, compileErr
				}
				preparationErrors = append(preparationErrors, compileErr)
				group.preparationFailures = append(group.preparationFailures, ordinaryPreparationFailure{Directory: artifact.Directory, Patterns: patterns, Inventory: "unavailable", Reason: "package_preparation_failed"})
				continue
			}
			selected, retained, selectionErr := selectOrdinaryProfile(map[string][]string{pkg.ImportPath: compiled.inventory.Inventory}, []ordinaryPackage{compiled.inventory}, profile)
			if selectionErr != nil {
				return group, selectionErr
			}
			prepared := preparedOrdinaryArtifact{ordinaryArtifact: artifact, barrier: &group.barrier, unit: step.Kind == "unit"}
			prepared.Package, prepared.Patterns, prepared.Profile = pkg.ImportPath, patterns, profile
			prepared.Tests = slices.Clone(selected[pkg.ImportPath])
			prepared.CompiledTests = slices.Clone(retained[0].Inventory)
			prepared.Classifications = slices.Clone(retained[0].Classifications)
			prepared.cwd, prepared.binary, prepared.binaryHash = compiled.cwd, compiled.binary, compiled.hash
			group.artifacts = append(group.artifacts, prepared)
		}
	}

	if slices.ContainsFunc(group.artifacts, func(artifact preparedOrdinaryArtifact) bool { return artifact.binary != "" }) {
		converter, facts, prepareErr := prepareTestEventConverter(ctx, root, directory)
		if facts.Process != "" {
			prepareErr = errors.Join(prepareErr, evidence.Diagnostics.append(facts))
		}
		if err := prepareErr; err != nil {
			return group, err
		}
		for index := range group.artifacts {
			group.artifacts[index].converter = converter
		}
	}
	for _, artifact := range group.artifacts {
		if err := appendOrdinaryInventory(evidence, map[string][]string{artifact.Package: artifact.Tests}, []ordinaryPackage{{Name: artifact.Package, Inventory: artifact.CompiledTests, Classifications: artifact.Classifications}}); err != nil {
			return group, err
		}
	}
	group.estimates = maps.Clone(runnerEstimates)
	for index := range group.artifacts {
		group.artifacts[index].owner = group
	}
	evidence.Diagnostics.Preparation = "passed"
	group.preparation = evidence.Diagnostics
	return group, nil
}

func (group *preparedOrdinaryGroup) close() error {
	if group.closed {
		return nil
	}
	group.closed = true
	group.cancel()
	if group.lease != nil {
		tail, cancel := finalizationContext(group.ctx)
		defer cancel()
		return group.lease(tail, group.joined)
	}
	return nil
}

func (group *preparedOrdinaryGroup) execute(ctx context.Context, root, profile string, evidence *ordinaryStepEvidence, output io.Writer) (err error) {
	evidence.Toolchain = group.toolchain
	evidence.PreparationFailures = slices.Clone(group.preparationFailures)
	ctx, cancel := group.duration.executionContext(ctx)
	defer cancel()
	if raceEnabled(ctx) != raceEnabled(group.ctx) {
		return errors.New("ordinary prepared race policy changed")
	}
	if evidence.Diagnostics == nil {
		evidence.Diagnostics = &checkDiagnostics{Preparation: "pending"}
	}
	placement, planErr := prepareOrdinaryPlacement(group.artifacts, executionCapacityFromContext(ctx).Parallel, group.step.Kind == "runner-tests" && group.step.OrdinaryFocus == nil, group.estimates)
	if planErr != nil {
		return planErr
	}
	if err := evidence.Diagnostics.reserveOrdinaryCommands(placement.commands()); err != nil {
		return err
	}
	returned := false
	defer func() {
		err = errors.Join(group.preparationFailure, err)
		if (!returned || err != nil) && !containedCheckFailure(ctx, err) {
			repetitionBarrierFromContext(ctx, &group.barrier).stopped.Store(true)
		}
		if err != nil && evidence.Diagnostics.Preparation == "pending" {
			evidence.Diagnostics.Preparation = "failed"
		}
		// Admitted testless commands have no test timestamp rows. If one
		// fails after a binary ran, preserve those earlier converted times.
		if len(evidence.Tests) != 0 {
			evidence.EventTimeSource = "post_join_test2json"
		}
	}()
	if err := group.verify(ctx, root, profile); err != nil {
		return err
	}
	evidence.Diagnostics.Preparation = "passed"
	evidence.Race = raceSetting(raceEnabled(ctx))
	evidence.Profile, evidence.RaceOptions, evidence.EventTimeSource = profile, acceptedRaceOptions(raceEnabled(ctx)), "post_join_test2json"
	for _, pkg := range group.blockedInventory {
		if err := appendOrdinaryInventory(evidence, map[string][]string{pkg.Name: pkg.Tests}, []ordinaryPackage{pkg}); err != nil {
			return err
		}
	}
	if group.preparationFailure != nil && len(group.artifacts) == 0 {
		evidence.Diagnostics.Preparation = "failed"
		returned = true
		return nil
	}
	if group.step.OrdinaryFocus != nil {
		focus, preparation := *group.step.OrdinaryFocus, *group.step.OrdinaryPreparation
		focus.Tests = slices.Clone(focus.Tests)
		evidence.Focus, evidence.Preparation = &focus, &preparation
		evidence.Execution = slices.Clone(group.step.OrdinarySelection)
		for index := range evidence.Execution {
			evidence.Execution[index].Tests = slices.Clone(evidence.Execution[index].Tests)
		}
	}
	if err := group.executePlacement(ctx, root, group.artifacts, placement, evidence, output); err != nil {
		return err
	}
	if group.preparationFailure != nil {
		evidence.Diagnostics.Preparation = "failed"
		returned = true
		return nil
	}
	if evidence.Focus == nil || len(evidence.Focus.Tests) == 0 {
		for _, pkg := range evidence.Packages {
			if hasUnavailableClassifications(pkg.Classifications) {
				returned = true
				return &localCheckFailure{cause: errors.New("compiled test classification is unavailable; complete profile cannot be reported")}
			}
		}
	}
	if evidence.Focus == nil {
		evidence.Complete = true
	} else {
		evidence.SelectedComplete = true
		evidence.Preparation.ExecutionProof = "selected execution completed with structured terminal proof; omitted scope remains unqualified"
		if !validOrdinaryFocusedEvidence(*evidence) {
			return errors.New("prepared ordinary focus lacks exact selected completion")
		}
	}
	returned = true
	return nil
}

func (group *preparedOrdinaryGroup) executeArtifacts(ctx context.Context, root string, artifacts []preparedOrdinaryArtifact, evidence *ordinaryStepEvidence, output io.Writer) error {
	placement, err := prepareOrdinaryPlacement(artifacts, executionCapacityFromContext(ctx).Parallel, false, group.estimates)
	if err != nil {
		return err
	}
	return group.executePlacement(ctx, root, artifacts, placement, evidence, output)
}

type preparedOrdinaryProcess struct {
	artifact preparedOrdinaryArtifact
	group    ordinaryProcessGroup
}

func preparedOrdinaryProcesses(artifact preparedOrdinaryArtifact, helpers map[string]string) ([]preparedOrdinaryProcess, error) {
	groups, err := ordinaryProcessGroups(artifact.ordinaryArtifact, helpers)
	if err != nil {
		return nil, err
	}
	var planned []preparedOrdinaryProcess
	for _, group := range groups {
		if len(artifact.requests) == 0 {
			part := artifact
			part.Tests = slices.Clone(group.tests)
			if len(groups) > 1 || part.selection == "" {
				part.selection = "^$"
				if len(part.Tests) != 0 {
					part.selection = runnerGroupSelection(part.Tests)
				}
			}
			planned = append(planned, preparedOrdinaryProcess{part, group})
			continue
		}
		var requests []string
		for _, request := range artifact.requests {
			root, _, _ := strings.Cut(request, "/")
			if slices.Contains(group.tests, root) {
				requests = append(requests, request)
			}
		}
		partitions, err := literalTestGroups(requests)
		if err != nil {
			return nil, err
		}
		for _, partition := range partitions {
			part := artifact
			part.Tests, part.requests, part.selection = slices.Clone(partition.Roots), slices.Clone(partition.Tests), partition.Selection
			partGroup := group
			partGroup.tests = slices.Clone(partition.Roots)
			planned = append(planned, preparedOrdinaryProcess{part, partGroup})
		}
	}
	return planned, nil
}

func executePreparedOrdinary(parent context.Context, root string, artifact preparedOrdinaryArtifact, goroot string, want map[string][]string, evidence *ordinaryStepEvidence) error {
	if len(want) != 1 || !slices.Equal(want[artifact.Package], artifact.Tests) {
		return errors.New("ordinary process differs from its selected package inventory")
	}
	placement, err := prepareOrdinaryPlacement([]preparedOrdinaryArtifact{artifact}, executionCapacityFromContext(parent).Parallel, false, nil)
	if err != nil {
		return err
	}
	group := preparedOrdinaryGroup{goenv: map[string]string{"GOROOT": goroot}}
	return group.executePlacement(parent, root, []preparedOrdinaryArtifact{artifact}, placement, evidence, io.Discard)
}

func unstartedOrdinaryProcess(artifact preparedOrdinaryArtifact) []ordinaryTest {
	var rows []ordinaryTest
	for _, name := range artifact.Tests {
		rows = append(rows, ordinaryTest{Package: artifact.Package, Name: name, Outcome: "not_run"})
	}
	return ordinaryUnstartedRequests(rows, ordinaryFocus{Package: artifact.Package, Tests: artifact.requests}, "not_run")
}

func executePreparedOrdinaryProcess(parent context.Context, root string, artifact preparedOrdinaryArtifact, group ordinaryProcessGroup, goroot string, helpers map[string]string, evidence *ordinaryStepEvidence) (err error) {
	want := map[string][]string{artifact.Package: slices.Clone(artifact.Tests)}
	var focus *ordinaryFocus
	if evidence.Focus != nil && len(artifact.requests) != 0 {
		selected := *evidence.Focus
		selected.Tests = slices.Clone(artifact.requests)
		selected.Package, selected.Artifact = artifact.Package, artifact.Owner
		focus = &selected
	}

	if artifact.selection == "" {
		artifact.selection = "^$"
		if len(artifact.Tests) != 0 {
			artifact.selection = runnerGroupSelection(artifact.Tests)
		}
	}
	allowances, idle, err := ordinaryRootTimeouts(artifact, group, helpers)
	if err != nil {
		return err
	}
	ctx := parent
	canContinue := false
	big := group.big
	if barrier := repetitionBarrierFromContext(ctx, artifact.barrier); barrier != nil {
		started := time.Now()
		leave, waitErr := barrier.enter(ctx, big)
		if waitErr != nil {
			requested := ""
			if evidence.Focus != nil {
				requested = strings.Join(evidence.Focus.Tests, ",")
			}
			process := recordTestDispatchFailure(evidence.Diagnostics, artifact.Package, requested, waitErr, time.Since(started))
			evidence.Tests = append(evidence.Tests, unstartedOrdinaryProcess(artifact)...)
			return process.Cause
		}
		defer func() { leave(canContinue) }()
	}
	ctx, err = admitTestExecution(ctx, big)
	if err != nil {
		evidence.Tests = append(evidence.Tests, unstartedOrdinaryProcess(artifact)...)
		return recordTestDispatchFailure(evidence.Diagnostics, artifact.Package, strings.Join(artifact.requests, ","), err, 0).Cause
	}
	if big {
		ctx = withExecutionParallel(ctx, 1)
	}
	if artifact.stops != nil && artifact.stops.isStopped(artifact.Package) {
		evidence.Tests = append(evidence.Tests, unstartedOrdinaryProcess(artifact)...)
		canContinue = true
		return &localCheckFailure{cause: errors.New("ordinary package stopped after an unfinished process")}
	}
	if err := artifact.verifyInputs(ctx, root); err != nil {
		evidence.Diagnostics.Preparation = "failed"
		return err
	}

	stdout, stderr := &limitedOutput{}, &limitedOutput{}
	deadline, err := newNativeTestDeadline(ctx, allowances, idle, stdout)
	if err != nil {
		return err
	}
	defer deadline.cancel(context.Canceled)
	ctx = deadline.ctx
	args := []string{"-test.v=test2json", "-test.count=1", "-test.paniconexit0", "-test.timeout=" + deadline.backstop.String(), fmt.Sprintf("-test.parallel=%d", executionCapacityFromContext(ctx).Parallel)}
	if artifact.selection != "" {
		args = append(args, "-test.run="+artifact.selection)
	}
	command := exec.Command(artifact.binary, args...)
	command.Dir = artifact.cwd
	command.Env = environment(goEnvironment(), map[string]string{"PWD": artifact.cwd, "PATH": filepath.Join(goroot, "bin") + string(os.PathListSeparator) + os.Getenv("PATH")})
	command.Stdout, command.Stderr = deadline, stderr
	started := time.Now()
	process := deadline.joined(superviseProcess(ctx, command))
	facts := commandFacts("test", artifact.Package, process, time.Since(started))
	facts.Events = "unavailable"
	if process.Joined {
		facts.RaceObservation = observedRace(true, stdout.Bytes(), stderr.Bytes())
	}
	var runErr error
	if process.Status != "passed" || !process.Started || !process.Joined || stdout.overflow || stderr.overflow {
		failure := &toolFailure{operation: "prepared ordinary test", process: process}
		if process.Joined {
			failure.stdout, failure.stderr = stdout.Bytes(), stderr.Bytes()
			failure.overflow = stdout.overflow || stderr.overflow
		}
		runErr = failure
	}
	if !process.Joined {
		return errors.Join(runErr, evidence.Diagnostics.append(facts))
	}
	converted, conversionErrors := &limitedOutput{}, &limitedOutput{}
	converter := exec.Command(artifact.converter.binary, "-t", "-p", artifact.Package)
	converter.Dir, converter.Env = root, goEnvironment()
	converter.Stdin, converter.Stdout, converter.Stderr = bytes.NewReader(stdout.Bytes()), converted, conversionErrors
	conversionStarted := time.Now()
	conversionContext, cancelConversion := deadline.conversionContext()
	defer cancelConversion()
	conversion := deadline.converted(conversionContext, superviseTestEventConversion(conversionContext, converter))
	conversionFacts := commandFacts("conversion", artifact.Package, conversion, time.Since(conversionStarted))
	var results []ordinaryTest
	events := "unavailable"
	var validationErr error
	if conversion.Joined {
		results, events, validationErr = parseOrdinarySelectedEvents(converted.Bytes(), want, helpers, evidence, stdout)
		conversionFacts.RaceObservation = observedRace(true, nil, conversionErrors.Bytes())
	}
	facts.Events, conversionFacts.Events = events, events
	captureComplete := conversion.Joined && conversion.Status == "passed" && !converted.overflow && !conversionErrors.overflow && !stdout.overflow && !stderr.overflow
	unobserved := ordinaryUnobservedOutcome(events, captureComplete)
	if unobserved == "incomplete" {
		ordinaryIncompleteStarts(results)
	}
	if focus != nil {
		facts.RequestedNode = ordinaryRequestedNode(results, *focus)
		if facts.RequestedNode == "missing" && unobserved == "incomplete" {
			facts.RequestedNode = "unavailable"
		}
		results = ordinaryUnstartedRequests(results, *focus, unobserved)
		validationErr = ordinaryFocusEventError(results, *focus, validationErr)
	}
	if runErr != nil || validationErr != nil {
		failure, ok := runErr.(*toolFailure)
		if !ok {
			failure = &toolFailure{operation: "prepared ordinary test", process: process}
			runErr = failure
		}
		captured := &limitedOutput{}
		appendFailedComponentCapture(captured, artifact.Package, stdout, assemblyDiagnosticOutputLimit)
		failure.stdout, failure.stderr = captured.Bytes(), stderr.Bytes()
		failure.overflow = stdout.overflow || stderr.overflow
	}
	testErr := containTestFailure(parent, runErr, validationErr)
	var conversionErr error
	if conversion.Status != "passed" || !conversion.Started || !conversion.Joined || converted.overflow || conversionErrors.overflow {
		failure := &toolFailure{operation: "ordinary test2json", process: conversion}
		if conversion.Joined {
			failure.overflow = converted.overflow || conversionErrors.overflow
			failure.stderr = conversionErrors.Bytes()
		}
		conversionErr = failure
	}
	if !conversion.Joined {
		facts.Events, facts.RequestedNode, conversionFacts.Events = "unavailable", "unavailable", "unavailable"
	}
	evidence.Tests = append(evidence.Tests, results...)
	lifetimeErr := ctx.Err()
	if containedCheckFailure(parent, testErr) {
		lifetimeErr = nil
	}
	err = errors.Join(testErr, conversionErr, lifetimeErr, deadline.shutdownError(conversionContext), parent.Err(), evidence.Diagnostics.append(facts), evidence.Diagnostics.append(conversionFacts))
	canContinue = err == nil || containedCheckFailure(parent, err)
	return err
}

func (artifact preparedOrdinaryArtifact) verifyInputs(ctx context.Context, root string) error {
	if artifact.owner != nil {
		index := slices.IndexFunc(artifact.owner.artifacts, func(original preparedOrdinaryArtifact) bool {
			return original.Directory == artifact.Directory && original.Package == artifact.Package
		})
		if index < 0 || !slices.Equal(artifact.BuildFlags, artifact.owner.artifacts[index].BuildFlags) || !slices.Equal(artifact.Patterns, artifact.owner.artifacts[index].Patterns) {
			return errors.New("ordinary prepared build selection changed")
		}
		return artifact.owner.verifyInputs(ctx, root, artifact.owner.profile)
	}
	return nil
}

func (group *preparedOrdinaryGroup) verify(ctx context.Context, root, profile string) error {
	return group.verifyInputs(ctx, root, profile)
}

func (group *preparedOrdinaryGroup) verifyInputs(ctx context.Context, root, profile string) error {
	if err := group.ctx.Err(); err != nil {
		return err
	}
	if raceEnabled(ctx) != raceEnabled(group.ctx) {
		return errors.New("ordinary prepared race policy changed")
	}
	if group.profile != profile {
		return errors.New("ordinary prepared profile changed")
	}
	return nil
}

func preparedOrdinaryCommands(artifacts []preparedOrdinaryArtifact, prefix string, parallel int) ([]ordinaryCommandReservation, error) {
	placement, err := prepareOrdinaryPlacement(artifacts, parallel, false, nil)
	if err != nil {
		return nil, err
	}
	commands := placement.commands()
	for index := range commands {
		commands[index].scope = prefix + commands[index].scope
	}
	return commands, nil
}

func preparedRunnerCommands(artifacts []preparedOrdinaryArtifact, parallel int) ([]ordinaryCommandReservation, error) {
	placement, err := prepareOrdinaryPlacement(artifacts, parallel, true, runnerEstimates)
	if err != nil {
		return nil, err
	}
	return placement.commands(), nil
}

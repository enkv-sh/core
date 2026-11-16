package main

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"time"
)

type preparedOrdinaryWorker struct {
	group     runnerGroup
	artifacts []preparedOrdinaryArtifact
	processes [][]preparedOrdinaryProcess
}

type preparedOrdinaryPlacement struct {
	workers  []preparedOrdinaryWorker
	trailing []preparedOrdinaryWorker
	runner   bool
}

func prepareOrdinaryPlacement(artifacts []preparedOrdinaryArtifact, parallel int, runner bool, estimates map[string]float64) (preparedOrdinaryPlacement, error) {
	placement := preparedOrdinaryPlacement{runner: runner}
	selected := map[string][]string{}
	byPackage := map[string]preparedOrdinaryArtifact{}
	helpers := ordinaryRunnerHelperProofs
	for _, artifact := range artifacts {
		if artifact.Package == "" {
			return placement, errors.New("ordinary artifact package ownership is invalid")
		}
		if _, repeated := byPackage[artifact.Package]; repeated {
			return placement, errors.New("ordinary artifact package ownership is repeated")
		}
		byPackage[artifact.Package] = artifact
		if artifact.unit {
			helpers = ordinaryProviderHelperProofs
		}
		if runner && artifact.Package == "command-line-arguments" {
			worker, err := prepareOrdinaryWorker(runnerGroup{Packages: []ordinaryPackage{{Name: artifact.Package, Tests: artifact.Tests}}}, byPackage)
			if err != nil {
				return placement, err
			}
			placement.trailing = append(placement.trailing, worker)
			continue
		}
		selected[artifact.Package] = artifact.Tests
	}
	var groups []runnerGroup
	var err error
	if len(selected) != 0 {
		if runner {
			nonempty := map[string][]string{}
			for pkg, names := range selected {
				if len(names) != 0 {
					nonempty[pkg] = names
				}
			}
			if len(nonempty) != 0 {
				if err = validateRunnerTestInventory(nonempty); err != nil {
					return placement, err
				}
			}
		}
		groups, err = ordinaryTestGroups(selected, helpers, estimates, parallel)
		if err != nil {
			return placement, err
		}
	}
	for _, group := range groups {
		worker, err := prepareOrdinaryWorker(group, byPackage)
		if err != nil {
			return placement, err
		}
		placement.workers = append(placement.workers, worker)
	}
	return placement, nil
}

func prepareOrdinaryWorker(group runnerGroup, artifacts map[string]preparedOrdinaryArtifact) (preparedOrdinaryWorker, error) {
	worker := preparedOrdinaryWorker{group: group}
	for _, pkg := range group.Packages {
		artifact := artifacts[pkg.Name]
		artifact.Tests = slices.Clone(pkg.Tests)
		artifact.selection = "^$"
		if len(artifact.Tests) != 0 {
			artifact.selection = runnerGroupSelection(artifact.Tests)
		}
		if len(artifact.requests) != 0 {
			var requests []string
			for _, request := range artifact.requests {
				root, _, _ := strings.Cut(request, "/")
				if slices.Contains(artifact.Tests, root) {
					requests = append(requests, request)
				}
			}
			artifact.requests = requests
		}
		processes, err := preparedOrdinaryProcesses(artifact, ordinaryArtifactHelpers(artifact))
		if err != nil {
			return worker, err
		}
		worker.artifacts = append(worker.artifacts, artifact)
		worker.processes = append(worker.processes, processes)
	}
	return worker, nil
}

func ordinaryArtifactHelpers(artifact preparedOrdinaryArtifact) map[string]string {
	if artifact.Package == "command-line-arguments" {
		return nil
	}
	if artifact.unit {
		return ordinaryProviderHelperProofs
	}
	return ordinaryRunnerHelperProofs
}

func (placement preparedOrdinaryPlacement) commands() []ordinaryCommandReservation {
	var commands []ordinaryCommandReservation
	appendWorker := func(worker preparedOrdinaryWorker, prefix string) {
		for index, artifact := range worker.artifacts {
			scope, facts := artifact.Package, 2
			if artifact.binary == "" {
				scope, facts = artifact.Directory, 1
			}
			commands = append(commands, ordinaryCommandReservation{scope: prefix + scope, processes: len(worker.processes[index]), factsPerProcess: facts})
		}
	}
	for _, worker := range placement.workers {
		prefix := ""
		if placement.runner {
			prefix = worker.group.Name + "/"
		}
		appendWorker(worker, prefix)
	}
	for _, worker := range placement.trailing {
		appendWorker(worker, "")
	}
	return commands
}

type ordinaryPackageStops struct {
	mutex   sync.Mutex
	stopped map[string]bool
}

func (stops *ordinaryPackageStops) isStopped(pkg string) bool {
	stops.mutex.Lock()
	defer stops.mutex.Unlock()
	return stops.stopped[pkg]
}

func (stops *ordinaryPackageStops) stop(pkg string) {
	stops.mutex.Lock()
	defer stops.mutex.Unlock()
	stops.stopped[pkg] = true
}

func (group *preparedOrdinaryGroup) executePlacement(ctx context.Context, root string, artifacts []preparedOrdinaryArtifact, placement preparedOrdinaryPlacement, evidence *ordinaryStepEvidence, output io.Writer) error {
	if evidence.Diagnostics == nil {
		evidence.Diagnostics = &checkDiagnostics{Preparation: "passed"}
	}
	for _, artifact := range artifacts {
		index := slices.IndexFunc(evidence.Packages, func(pkg ordinaryPackage) bool { return pkg.Name == artifact.Package })
		if index < 0 {
			if err := appendOrdinaryInventory(evidence, map[string][]string{artifact.Package: artifact.Tests}, []ordinaryPackage{{Name: artifact.Package, Inventory: artifact.CompiledTests, Classifications: artifact.Classifications}}); err != nil {
				return err
			}
		} else if pkg := evidence.Packages[index]; !slices.Equal(pkg.Tests, artifact.Tests) || !slices.Equal(pkg.Inventory, artifact.CompiledTests) || !sameTestClassifications(pkg.Classifications, artifact.Classifications) {
			return errors.New("ordinary prepared package inventory changed")
		}
	}
	if evidence.Diagnostics.ordinaryCommandLimit == 0 {
		if err := evidence.Diagnostics.reserveOrdinaryCommands(placement.commands()); err != nil {
			return err
		}
	}
	stops := &ordinaryPackageStops{stopped: map[string]bool{}}
	started := make([]bool, len(placement.workers))
	run := func(child context.Context, index int) (ordinaryStepEvidence, error) {
		started[index] = true
		local := ordinaryStepEvidence{Profile: evidence.Profile, Packages: evidence.Packages, Focus: evidence.Focus, EventTimeSource: "post_join_test2json", Diagnostics: &checkDiagnostics{Preparation: "passed"}}
		worker := placement.workers[index]
		commands := (preparedOrdinaryPlacement{workers: []preparedOrdinaryWorker{worker}}).commands()
		if err := local.Diagnostics.reserveOrdinaryCommands(commands); err != nil {
			return local, err
		}
		workerOutput := io.Writer(io.Discard)
		if !placement.runner && len(placement.workers) == 1 {
			workerOutput = output
		}
		err := group.executeWorker(child, root, worker, stops, &local, workerOutput)
		return local, err
	}
	var runErr error
	if placement.runner {
		scheduled := make([]runnerGroup, len(placement.workers))
		for index, worker := range placement.workers {
			scheduled[index] = worker.group
		}
		runErr = runRunnerGroups(ctx, scheduled, output, evidence, func(child context.Context, scheduled runnerGroup) (ordinaryStepEvidence, error) {
			index := slices.IndexFunc(placement.workers, func(worker preparedOrdinaryWorker) bool { return worker.group.Name == scheduled.Name })
			return run(child, index)
		})
	} else {
		names := make([]string, len(placement.workers))
		for index, worker := range placement.workers {
			names[index] = worker.group.Name
		}
		var runs []unitPackageRun
		if len(names) == 1 {
			local, err := run(withExecutionParallel(ctx, 1), 0)
			runs = []unitPackageRun{{evidence: local, started: true, err: err}}
			runErr = err
		} else {
			var err error
			runs, err = runUnitPackages(ctx, names, output, func(child context.Context, name string) (ordinaryStepEvidence, error) {
				return run(child, slices.Index(names, name))
			})
			runErr = err
		}
		failures := []error{runErr}
		for _, result := range runs {
			evidence.Tests = append(evidence.Tests, result.evidence.Tests...)
			if result.evidence.Diagnostics != nil {
				if result.evidence.Diagnostics.Preparation != "passed" {
					evidence.Diagnostics.Preparation = "failed"
				}
				for _, command := range result.evidence.Diagnostics.Commands {
					if err := evidence.Diagnostics.append(command); err != nil {
						failures = append(failures, err)
					}
				}
			}
		}
		runErr = errors.Join(failures...)
	}
	for index, worker := range placement.workers {
		if !started[index] {
			for _, processes := range worker.processes {
				for _, process := range processes {
					evidence.Tests = append(evidence.Tests, unstartedOrdinaryProcess(process.artifact)...)
				}
			}
		}
	}
	if runErr != nil && !containedCheckFailure(ctx, runErr) {
		return runErr
	}
	for _, worker := range placement.trailing {
		runErr = errors.Join(runErr, group.executeWorker(ctx, root, worker, stops, evidence, output))
		if runErr != nil && !containedCheckFailure(ctx, runErr) {
			return runErr
		}
	}
	return runErr
}

func (group *preparedOrdinaryGroup) executeWorker(ctx context.Context, root string, worker preparedOrdinaryWorker, stops *ordinaryPackageStops, evidence *ordinaryStepEvidence, output io.Writer) (err error) {
	var planned []preparedOrdinaryProcess
	for _, processes := range worker.processes {
		planned = append(planned, processes...)
	}
	completed := 0
	defer func() {
		if err != nil && !containedCheckFailure(ctx, err) {
			for _, process := range planned[completed:] {
				evidence.Tests = append(evidence.Tests, unstartedOrdinaryProcess(process.artifact)...)
			}
		}
	}()
	var failures []error
	previous := ""
	for index, process := range planned {
		artifact := process.artifact
		artifact.stops = stops
		if artifact.Package != previous {
			if err := checkProgress(output, "test", artifact.Package); err != nil {
				return errors.Join(append(failures, err)...)
			}
			previous = artifact.Package
		}
		if stops.isStopped(artifact.Package) {
			evidence.Tests = append(evidence.Tests, unstartedOrdinaryProcess(artifact)...)
			completed = index + 1
			continue
		}
		before := len(evidence.Tests)
		var runErr error
		if artifact.binary == "" {
			runErr = group.executeTestless(ctx, root, artifact, evidence)
		} else {
			runErr = executePreparedOrdinaryProcess(ctx, root, artifact, process.group, group.goenv["GOROOT"], ordinaryArtifactHelpers(artifact), evidence)
		}
		completed = index + 1
		if runErr == nil {
			continue
		}
		failures = append(failures, runErr)
		if !containedCheckFailure(ctx, runErr) {
			return errors.Join(failures...)
		}
		var failure *toolFailure
		terminated := errors.As(runErr, &failure) && packageProcessTerminated(failure.process)
		unfinished := slices.ContainsFunc(evidence.Tests[before:], func(row ordinaryTest) bool { return row.Outcome == "incomplete" || row.Outcome == "not_run" })
		if terminated || unfinished {
			stops.stop(artifact.Package)
		}
	}
	return errors.Join(failures...)
}

func (group *preparedOrdinaryGroup) executeTestless(ctx context.Context, root string, artifact preparedOrdinaryArtifact, evidence *ordinaryStepEvidence) (runErr error) {
	started := time.Now()
	leave, waitErr := repetitionBarrierFromContext(ctx, &group.barrier).enter(ctx, false)
	if waitErr != nil {
		return recordTestDispatchFailure(evidence.Diagnostics, artifact.Directory, "", waitErr, time.Since(started)).Cause
	}
	canContinue := false
	defer func() { leave(canContinue) }()
	if err := artifact.verifyInputs(ctx, root); err != nil {
		evidence.Diagnostics.Preparation = "failed"
		return err
	}
	timeout, err := ordinaryProcessTimeout(artifact.TestFlags, ordinaryProcessMaximum(artifact.unit, ordinaryProcessGroup{}))
	if err != nil {
		return err
	}
	child, cancel := context.WithTimeout(ctx, timeout+max(time.Minute, timeout/10))
	defer cancel()
	runErr = executeOrdinaryInventory(ctx, child, root, artifact.Directory, artifact.BuildFlags, artifact.Patterns, artifact.selection, map[string][]string{artifact.Package: artifact.Tests}, ordinaryArtifactHelpers(artifact), evidence.Focus, evidence, artifact.TestFlags...)
	canContinue = runErr == nil || containedCheckFailure(ctx, runErr)
	return runErr
}

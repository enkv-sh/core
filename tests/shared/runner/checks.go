package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
)

func runUnitProfileEvidence(ctx context.Context, root string, selection map[string][]string, profile string, output io.Writer, evidence *ordinaryStepEvidence) (err error) {
	step := resolvedWorkflowStep{ID: "unit", Kind: "unit", Selected: true, Packages: selection}
	return runOrdinarySelection(ctx, root, "", profile, &step, evidence, output)
}

func toolCommandsJoined(cause error) bool {
	if !sourceCommandsJoined(cause) {
		return false
	}
	// A joined first error does not authorize removal when another
	// command is unjoined. Inspect all branches, including cleanup wrappers.
	pending := []error{cause}
	for len(pending) != 0 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if current == nil {
			continue
		}
		if failure, ok := current.(*toolFailure); ok && !failure.process.Joined {
			return false
		}
		switch wrapped := current.(type) {
		case interface{ Unwrap() []error }:
			pending = append(pending, wrapped.Unwrap()...)
		case interface{ Unwrap() error }:
			pending = append(pending, wrapped.Unwrap())
		}
	}
	return true
}

type unitPackageRun struct {
	pkg      string
	evidence ordinaryStepEvidence
	started  bool
	err      error
}

// runUnitPackages admits independent packages within the invocation lane bound. Each started command
// finishes or is cancelled and joined before its evidence is returned.
func runUnitPackages(ctx context.Context, packages []string, output io.Writer,
	run func(context.Context, string) (ordinaryStepEvidence, error)) ([]unitPackageRun, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	runs := make([]unitPackageRun, len(packages))
	var queue sync.Mutex
	var outputLock sync.Mutex
	next, stopped := 0, false
	stop := func() {
		queue.Lock()
		stopped = true
		queue.Unlock()
		cancel()
	}
	write := func(format string, args ...any) error {
		outputLock.Lock()
		defer outputLock.Unlock()
		if _, err := fmt.Fprintf(output, format, args...); err != nil {
			return errors.New("verification output failed")
		}
		return nil
	}
	var joined sync.WaitGroup
	parallel := min(executionCapacityFromContext(ctx).Parallel, len(packages))
	joined.Add(parallel)
	for range parallel {
		go func() {
			defer joined.Done()
			for {
				queue.Lock()
				if stopped || next == len(packages) || ctx.Err() != nil {
					queue.Unlock()
					return
				}
				index := next
				next++
				queue.Unlock()
				item := &runs[index]
				item.pkg, item.started = packages[index], true
				if err := write("Testing %s; phase=test scope=%s\n", item.pkg, item.pkg); err != nil {
					item.err = err
					stop()
					return
				}
				item.evidence, item.err = run(withExecutionParallel(ctx, 1), item.pkg)
				if item.err == nil {
					item.err = write("Validated %d test terminals in %s\n", len(item.evidence.Tests), item.pkg)
				}
				if item.err != nil && !containedCheckFailure(ctx, item.err) {
					stop()
					return
				}
			}
		}()
	}
	joined.Wait()
	var errs []error
	for _, item := range runs {
		if item.err != nil && item.err != context.Canceled {
			errs = append(errs, item.err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return runs, err
	}
	if ctx.Err() != nil {
		return runs, ctx.Err()
	}
	for _, item := range runs {
		errs = append(errs, item.err)
	}
	return runs, errors.Join(errs...)
}

func validateUnitPackages(ctx context.Context, root string, selection map[string][]string) error {
	for _, module := range moduleRoots {
		patterns := selection[module]
		if len(patterns) == 0 {
			continue
		}
		// Go owns build constraints and module-aware pattern matching. Package
		// discovery needs neither dependency loading nor the test-only overlay.
		args := append(compilerBuildFlags([]string{"list", "-mod=readonly", "-find", "-json=Match"}, raceEnabled(ctx)), patterns...)
		body, err := runGo(ctx, root, module, args...)
		if err != nil {
			return safeCheckFailure("preparation", "none", fmt.Errorf("unit package discovery in %s: %w", module, err))
		}
		packages, err := decodeObjects[struct{ Match []string }](body)
		if err != nil {
			return err
		}
		matched := map[string]bool{}
		for _, pkg := range packages {
			for _, pattern := range pkg.Match {
				matched[pattern] = true
			}
		}
		for _, pattern := range patterns {
			if !matched[pattern] {
				return fmt.Errorf("unit package selector %s in %s matches no packages", pattern, module)
			}
		}
	}
	return nil
}

func runToolTestsProfileEvidence(ctx context.Context, root, toolOverlay, profile string, output io.Writer, evidence *ordinaryStepEvidence) error {
	step := resolvedWorkflowStep{ID: "runner", Kind: "runner-tests", Selected: true}
	return runOrdinarySelection(ctx, root, toolOverlay, profile, &step, evidence, output)
}

var closedModuleDependencies = map[string][]string{
	"protocols/output":                    nil,
	"sdk/output":                          {"protocols/output", "sdk/artifact"},
	"plugins/output-contract-test":        {"protocols/output", "sdk/output", "sdk/artifact"},
	"plugins/github-output":               {"protocols/output", "sdk/output", "sdk/artifact"},
	"plugins/aws-output":                  {"protocols/output", "sdk/output", "sdk/artifact"},
	"plugins/gcp-output":                  {"protocols/output", "sdk/output", "sdk/artifact"},
	"compositions/internal/nativeprocess": nil,
	"compositions/outputhost":             {"compositions/internal/nativeprocess", "protocols/output", "sdk/artifact", "telemetry"},
	"compositions/manifesthost":           {"compositions/internal/nativeprocess", "sdk/artifact", "sdk/manifest-generator", "protocols/manifest-generator", "telemetry"},
}

func checkClosedModuleDependencies(root string, modules []resolvedModule, module string) error {
	required, ok := closedModuleDependencies[module]
	if !ok {
		return errors.New("closed module policy missing")
	}
	source, known := registeredModule(module)
	if !known {
		return errors.New("closed module source is not registered")
	}
	allowed := map[string]bool{source.Module: true}
	for _, dependency := range required {
		source, known := registeredModule(dependency)
		if !known {
			return errors.New("closed dependency source is not registered")
		}
		allowed[source.Module] = true
		if err := checkModuleSource(root, modules, dependency); err != nil {
			return err
		}
	}
	for _, candidate := range modules {
		if (strings.HasPrefix(candidate.Path, modulePrefix) || strings.HasPrefix(candidate.Path, "enkv.sh/")) && !allowed[candidate.Path] {
			return fmt.Errorf("unreviewed ENKV dependency %s in %s", candidate.Path, module)
		}
	}
	return nil
}

type checkedModule struct {
	closure    assemblyClosure
	borrowable bool
}

func registeredModuleReplacements(graphs ...[]resolvedModule) bool {
	for _, graph := range graphs {
		for _, module := range graph {
			if module.Replace != nil && module.Replace.Version == "" {
				if _, known := registeredModule(module.Path); !known {
					return false
				}
			}
		}
	}
	return true
}

func copyModuleCheckClosure(value assemblyClosure) assemblyClosure {
	return assemblyClosure{
		Suite: value.Suite, Provider: value.Provider, Race: value.Race,
		RaceOptions: value.RaceOptions, RaceExitSleepMillis: value.RaceExitSleepMillis,
		ResolvedModules: slices.Clone(value.ResolvedModules), CompiledImports: slices.Clone(value.CompiledImports),
	}
}

func checkModule(ctx context.Context, root, module string) (checked checkedModule, err error) {
	if module == "core" {
		if err := checkCustodySources(ctx, root); err != nil {
			return checkedModule{}, err
		}
	}
	if module == cloudflareModule {
		if err := checkCloudflareModuleDefinition(ctx, root); err != nil {
			return checkedModule{}, err
		}
	}
	directory, err := os.MkdirTemp("", "enkv-module-check-")
	if err != nil {
		return checkedModule{}, err
	}
	defer func() {
		if !toolCommandsJoined(err) {
			err = errors.Join(err, errors.New("module overlay retained after an unsettled command"))
		} else {
			err = errors.Join(err, os.RemoveAll(directory))
		}
		if err != nil {
			checked = checkedModule{}
		}
	}()
	overlay, err := buildCryptoOverlay(root, directory)
	if err != nil {
		return checkedModule{}, err
	}
	flags := compilerBuildFlags(moduleTestFlags(root, module, overlay), raceEnabled(ctx))
	if _, err := runGo(ctx, root, module, append(append([]string{"vet"}, flags...), "./...")...); err != nil {
		return checkedModule{}, containProcessFailure(ctx, err)
	}
	testModules, testPackages, err := listClosure(localDiscoveryCommand(runGoEnvironment), ctx, root, module, flags, true, "./...")
	if err != nil {
		return checkedModule{}, err
	}
	if err := checkNeutralPins(testModules); err != nil {
		return checkedModule{}, err
	}
	if module == "core" || module == "crypto" || module == "providers/aws" || module == "providers/gcp" || module == "compositions/observability" {
		if err := checkObservabilityPins(testModules); err != nil {
			return checkedModule{}, err
		}
	}
	if err := checkCustodyImports(testPackages, true, ""); err != nil {
		return checkedModule{}, err
	}
	if _, err := runGo(ctx, root, module, "mod", "verify"); err != nil {
		return checkedModule{}, err
	}
	modules, packages, err := listClosure(localDiscoveryCommand(runGoEnvironment), ctx, root, module, compilerBuildFlags([]string{"-mod=readonly"}, raceEnabled(ctx)), false)
	if err != nil {
		return checkedModule{}, err
	}
	if err := checkModuleSource(root, modules, module); err != nil {
		return checkedModule{}, err
	}
	if module == "compositions/configuration" {
		for _, dependency := range []string{"core", "telemetry", "protocols/generator"} {
			if err := checkModuleSource(root, modules, dependency); err != nil {
				return checkedModule{}, err
			}
		}
	} else if _, closedModule := closedModuleDependencies[module]; closedModule {
		for _, graph := range [][]resolvedModule{modules, testModules} {
			if err := checkClosedModuleDependencies(root, graph, module); err != nil {
				return checkedModule{}, err
			}
		}
	} else if source, _ := registeredModule(module); source.Sibling == "" && module != "compositions/manifesthost" {
		if module != "telemetry" && module != "compositions/observability" {
			if err := checkModuleSource(root, modules, "core"); err != nil {
				return checkedModule{}, err
			}
		}
		if err := checkModuleSource(root, modules, "telemetry"); err != nil {
			return checkedModule{}, err
		}
		if module != "core" && module != "telemetry" && module != "compositions/observability" && module != "compositions/generatorhost" {
			if err := checkModuleSource(root, modules, "crypto"); err != nil {
				return checkedModule{}, err
			}
		}
		if module == "crypto" || strings.HasPrefix(module, "compositions/") && module != "compositions/observability" {
			for _, dependency := range []string{"compositions/generatorhost", "protocols/generator"} {
				if dependency == "compositions/generatorhost" && module == dependency {
					continue
				}
				if err := checkModuleSource(root, modules, dependency); err != nil {
					return checkedModule{}, err
				}
			}
		}
	}
	if module == "compositions/full" {
		if err := checkModuleSource(root, modules, "protocols/output"); err != nil {
			return checkedModule{}, err
		}
	}
	if module == cloudflareModule {
		if err := checkModuleSource(root, modules, cloudflareProtocolModule); err != nil {
			return checkedModule{}, err
		}
		if err := checkCloudflareConstructions(ctx, root, packages); err != nil {
			return checkedModule{}, err
		}
	}
	for _, graph := range [][]resolvedModule{modules, testModules} {
		for _, dependency := range graph {
			if owner, known := registeredModule(dependency.Path); known {
				if err := checkModuleSource(root, graph, owner.Selector); err != nil {
					return checkedModule{}, err
				}
			}
		}
	}
	if err := checkCompiledCustody(append(slices.Clone(packages), testPackages...)); err != nil {
		return checkedModule{}, err
	}
	if err := checkBoundary(module, modules, packages); err != nil {
		return checkedModule{}, err
	}
	closure := makeClosure("unit", module, modules, packages)
	closure.Race, closure.RaceOptions = raceEnabled(ctx), acceptedRaceOptions(raceEnabled(ctx))
	if closure.Race {
		closure.RaceExitSleepMillis = 1000
	}
	return checkedModule{closure: closure, borrowable: registeredModuleReplacements(modules, testModules)}, nil
}

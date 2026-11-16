package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

type offlineEvidence struct {
	Diagnostics    *checkDiagnostics           `json:"diagnostics,omitempty"`
	Responsibility string                      `json:"responsibility"`
	Focus          *assemblyFocus              `json:"focus,omitempty"`
	Profile        string                      `json:"profile"`
	SchemaVersion  int                         `json:"schema_version"`
	Source         records.Source              `json:"source"`
	Supervisor     *recordedSupervisor         `json:"supervisor,omitempty"`
	Toolchain      string                      `json:"toolchain"`
	Outcome        string                      `json:"outcome"`
	Modules        map[string]assemblyClosure  `json:"modules"`
	ModuleFailures map[string]string           `json:"module_failures,omitempty"`
	Assemblies     []assemblyClosure           `json:"assemblies"`
	Cloudflare     *cloudflareArtifactEvidence `json:"cloudflare,omitempty"`
	Failure        *records.Failure            `json:"failure,omitempty"`
}

func runLocalWorkflow(ctx context.Context, root, bootstrap, name string, execution executionRequest, output io.Writer) (workflowResult, error) {
	profile := "full"
	if name == "dev" {
		profile = "dev"
	} else if name != "check" {
		return workflowResult{}, errors.New("unknown local verification workflow")
	}
	plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: filepath.Join(root, "tests/workflows", name+".json"), Execution: execution})
	if err != nil {
		return workflowResult{}, err
	}
	err = validateLocalWorkflow(plan, profile)
	if err != nil {
		return workflowResult{}, err
	}
	return runWorkflow(ctx, root, bootstrap, plan, output)
}

func validateCheckWorkflow(plan workflowPlan) error {
	return validateLocalWorkflow(plan, "full")
}

func validateLocalWorkflow(plan workflowPlan, profile string) error {
	if err := validateExecutionCapacity(plan.Execution.Resolved); err != nil {
		return err
	}
	actual, err := resolveVerificationProfile(plan.Profile)
	if err != nil || actual != profile {
		return errors.New("local workflow verification profile differs")
	}
	want := map[string]bool{"lint": true, "runner-tests": true, "unit": true, "component-tests": true, "run": true}
	all, err := resolveUnitPackages(nil)
	if err != nil {
		return err
	}
	assemblies := map[string]bool{"common": true, "gcp": true, "aws": true}
	var hermeticNames []string
	for _, name := range catalog.OrdinaryNames() {
		definition, _ := catalog.DefinitionFor(name)
		if slices.Contains(definition.Modes, "hermetic") {
			hermeticNames = append(hermeticNames, definition.Name)
		}
	}
	for _, step := range plan.Steps {
		if (step.Kind != "assembly-checks" && !want[step.Kind]) || !step.Selected || step.Focus != nil || step.Preparation != nil || step.OrdinaryFocus != nil || step.OrdinaryPreparation != nil || step.OrdinarySelection != nil || step.AssemblyFocus != nil || step.AssemblyPreparation != nil {
			return errors.New("local verification requires every workflow step")
		}
		if step.Kind == "assembly-checks" {
			if !assemblies[step.Responsibility] {
				return errors.New("local verification requires each assembly responsibility exactly once")
			}
			delete(assemblies, step.Responsibility)
		} else {
			delete(want, step.Kind)
		}
		if step.Kind == "unit" && !reflect.DeepEqual(step.Packages, all) {
			return errors.New("local verification requires every product module")
		}
		if step.Kind == "component-tests" && (step.Profile != profile) {
			return errors.New("local verification requires its declared component profile with the invocation race policy")
		}
		if step.Kind == "run" && (want["component-tests"] || step.Run == nil || step.Run.Mode != "hermetic" || !step.Run.Schedule.FullCoverage || !sameStrings(step.Run.Schedule.Selected, hermeticNames) || step.Run.Profile != profile || step.Run.Race != plan.Race) {
			return errors.New("local verification requires the complete hermetic catalog and its declared execution profile")
		}
	}
	if len(want) != 0 || len(assemblies) != 0 {
		return errors.New("local verification requires every workflow step")
	}
	return nil
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for _, value := range left {
		if !slices.Contains(right, value) {
			return false
		}
	}
	return true
}

func runOfflineResponsibility(ctx context.Context, root, bootstrap, profile, responsibility, requested string, output io.Writer) (record *offlineEvidence, err error) {
	return runOfflineResponsibilityPrepared(nil, ctx, root, bootstrap, profile, responsibility, requested, output, nil, nil)
}

func runOfflineResponsibilityPrepared(initial *checkDiagnostics, ctx context.Context, root, bootstrap, profile, responsibility, requested string, output io.Writer, prepared *assembly, checkedModules *moduleCheckFacts) (record *offlineEvidence, err error) {
	if !validAssemblyResponsibility(responsibility) || requested != "" && (responsibility == "common" || !validComponentName(requested)) {
		return record, errors.New("offline assembly responsibility or focus refused")
	}
	profile, err = resolveVerificationProfile(profile)
	if err != nil {
		return record, err
	}

	source, err := sourceRevision(ctx, root)
	if err != nil {
		return record, err
	}
	record = &offlineEvidence{Responsibility: responsibility, Profile: profile, SchemaVersion: records.SchemaVersion, Source: source, Outcome: "incomplete", Modules: map[string]assemblyClosure{}, Assemblies: []assemblyClosure{}, Diagnostics: initial}
	if record.Diagnostics == nil {
		record.Diagnostics = &checkDiagnostics{Preparation: "pending"}
	}
	printsDiagnostics := true
	defer func() {
		if printsDiagnostics {
			if err != nil && record.Diagnostics.Preparation == "pending" {
				record.Diagnostics.Preparation = "failed"
			}
			err = errors.Join(err, writeCheckDiagnostics(output, record.Diagnostics))
		}
	}()
	d := record.Diagnostics
	if prepared != nil && prepared.providerSelection != nil {
		owner, key := prepared.preparationOwner, prepared.preparationKey
		if owner == nil {
			owner = prepared.providerSelection
			key = responsibility
		}
		if e := d.retainAcquisition(owner, key, prepared.providerSelection.evidence.Diagnostics); e != nil {
			return record, e
		}
	}
	var future []checkCommandFacts
	if responsibility != "common" {
		future = append(future, preparationReservationFact("core", false))
		if prepared != nil {
			future = append(future, preparationReservationFact("core", true))
			checks, e := providerCheckCommands(*prepared)
			if e != nil {
				return record, e
			}
			future = append(future, checks...)
		} else {
			construction, e := assemblyConstructionCommands(assemblyBindings{})
			if e != nil {
				return record, e
			}
			future = append(future, construction...)
			future = append(future, preparationReservationFact("core", true))
			future = append(future, preparationReservationFact("assembly-inventory", false), preparationReservationFact("core", true), preparationReservationFact("test2json", true), componentReservationFact("test", responsibility), componentReservationFact("conversion", responsibility))
		}
		future = append(future, preparationReservationFact("core", true), preparationReservationFact("core", true))
		if e := d.reserveCommands(future); e != nil {
			return record, e
		}
		defer d.cancelReservations()
	}
	command := goEnvironmentCommand(runGoEnvironment)
	if responsibility != "common" {
		command = d.runGoEnvironment
	}
	version, e := command(ctx, root, "core", nil, "version")
	if e != nil {
		return record, e
	}
	record.Toolchain = strings.TrimSpace(string(version))
	current, err := newCurrentDirectory("enkv-offline-")
	if err != nil {
		return record, err
	}
	directory := current.path
	defer func() {
		err = errors.Join(err, writeAssemblyDiagnosticBody(output, err), current.remove(toolCommandsJoined(err)))
		if record != nil {
			if err != nil {
				record.Outcome = "failed"
			}
			_, printErr := fmt.Fprintf(output, "Offline check %s\n", record.Outcome)
			err = errors.Join(err, printErr)
			if printErr != nil {
				record.Outcome = "failed"
			}
		}
	}()
	private := filepath.Join(directory, "private")
	if err := os.Mkdir(private, 0700); err != nil {
		return record, err
	}
	if requested != "" {
		record.Focus = &assemblyFocus{Requested: requested, Provider: responsibility}
	}
	stage := "modules"
	defer func() {
		if err != nil {
			if record.Diagnostics.Preparation == "pending" {
				record.Diagnostics.Preparation = "failed"
			}
			record.Outcome = "failed"
			record.Failure = &records.Failure{Class: "offline_check_failed", Stage: stage}
		}
	}()
	if err := checkProgress(output, "preparation", responsibility); err != nil {
		return record, err
	}
	var collectionErr error
	defer func() { err = errors.Join(collectionErr, err) }()
	if responsibility == "common" {
		current, err := checkedModules.current(ctx, root)
		if err != nil {
			return record, err
		}
		if checkedModules != nil && !current {
			return record, errors.New("module check inputs changed during offline verification")
		}
		borrowed := false
		record.ModuleFailures = make(map[string]string)
		for _, module := range moduleRoots {
			if current && checkedModules.failed[module] != nil {
				record.ModuleFailures[module] = "prerequisite_failed"
				collectionErr = errors.Join(collectionErr, fmt.Errorf("module %s blocked by failed lint prerequisite: %w", module, checkedModules.failed[module]))
				if _, err := fmt.Fprintln(output, "Not running module checks", module, "(lint prerequisite failed)"); err != nil {
					return record, err
				}
				continue
			}
			if _, err := fmt.Fprintln(output, "Checking dependencies and vet", module); err != nil {
				return record, err
			}
			if current {
				if closure, exists := checkedModules.modules[module]; exists {
					// Earlier boundary/vet facts do not cover mutable module-cache bytes.
					if _, err := runGo(ctx, root, module, "mod", "verify"); err != nil {
						return record, err
					}
					record.Modules[module] = copyModuleCheckClosure(closure)
					borrowed = true
					continue
				}
			}
			checked, err := checkModule(ctx, root, module)
			if err != nil {
				if !containedCheckFailure(ctx, err) {
					return record, err
				}
				record.ModuleFailures[module] = "module_check_failed"
				collectionErr = errors.Join(collectionErr, fmt.Errorf("module %s: %w", module, err))
				continue
			}
			record.Modules[module] = checked.closure
		}
		if borrowed || checkedModules != nil && len(checkedModules.failed) != 0 {
			current, err := checkedModules.current(ctx, root)
			if err != nil {
				return record, err
			}
			if !current {
				return record, errors.New("module check inputs changed during offline verification")
			}
		}
		stage = "cloudflare_artifact"
		blocked := false
		for _, module := range []string{cloudflareModule, cloudflareProtocolModule, cloudflareSDKModule} {
			blocked = blocked || record.ModuleFailures[module] != ""
		}
		if blocked {
			if _, err := fmt.Fprintln(output, "Not running offline Cloudflare plugin artifact (module prerequisite failed)"); err != nil {
				return record, err
			}
		} else {
			if _, err := fmt.Fprintln(output, "Checking offline Cloudflare plugin artifact"); err != nil {
				return record, err
			}
			cloudflareBuild := filepath.Join(private, "cloudflare")
			if err := os.Mkdir(cloudflareBuild, 0700); err != nil {
				return record, err
			}
			cloudflare, err := buildCloudflareArtifacts(ctx, root, cloudflareBuild)
			if err != nil {
				return record, err
			}
			record.Cloudflare = &cloudflare
		}
	} else {
		provider := responsibility
		stage = provider + "_assembly"
		if _, err := fmt.Fprintln(output, "Checking offline provider assembly", provider); err != nil {
			return record, err
		}
		build := filepath.Join(private, provider)
		if err := os.Mkdir(build, 0700); err != nil {
			return record, err
		}
		var value assembly
		if prepared != nil {
			value = *prepared
			err = checkAssemblyRace(ctx, value)
		} else {
			value, err = buildAssembly(d.runGoEnvironment, d, ctx, root, "live", provider, bootstrap, build)
		}
		if err != nil {
			return record, err
		}
		modules, packages, boundaryErr := listClosure(d.runGoEnvironment, ctx, root, "core", compilerBuildFlags(value.buildFlags, raceEnabled(ctx)), true)
		if boundaryErr != nil {
			return record, boundaryErr
		}
		if err := checkCompiledCustody(packages); err != nil {
			return record, err
		}
		if err := checkLiveBoundary(provider, modules, packages); err != nil {
			return record, err
		}
		record.Assemblies = append(record.Assemblies, value.Closure)
		if _, err := d.runGo(ctx, root, "core", "mod", "verify", "-modfile="+filepath.Join(root, "tests/live/providers", provider, "live.mod")); err != nil {
			return record, err
		}
		// The inner check now owns one diagnostic write on every return,
		// including its preparation failures. A partial write is not retried.
		printsDiagnostics = false
		value.currentPrefix = d
		err = checkLiveAssemblySelectionOwned(d, ctx, root, directory, &value, profile, provider == "gcp", requested, source, record.Toolchain, output)
		if value.Closure.LocalChecks != nil && value.Closure.LocalChecks.Diagnostics != nil {
			record.Diagnostics = value.Closure.LocalChecks.Diagnostics
		}
		record.Assemblies[0] = value.Closure
		if value.Closure.LocalChecks != nil && value.Closure.LocalChecks.AssemblyFocus != nil {
			record.Focus = value.Closure.LocalChecks.AssemblyFocus
		}
		if err != nil {
			return record, err
		}
	}
	if collectionErr == nil {
		record.Outcome = "passed"
		record.Diagnostics.Preparation = "passed"
	}
	return record, nil
}

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/crypto/testsupport/installedarchive"
)

type reconstructionArtifactClosure struct {
	Race            *bool            `json:"race,omitempty"`
	Provider        string           `json:"provider"`
	Source          records.Source   `json:"source"`
	BinarySHA256    string           `json:"binary_sha256"`
	RaceOptions     string           `json:"race_options"`
	VetPassed       bool             `json:"vet_passed,omitempty"`
	NoCoreOverlay   bool             `json:"no_core_overlay"`
	ResolvedModules []moduleIdentity `json:"resolved_modules"`
	CompiledImports []string         `json:"compiled_imports"`
}

type configurationRecoveryArtifact struct {
	declarations           capturedTestDeclarations
	module, overlay        string
	buildFlags             []string
	inventory              []string
	classifications        []testClassification
	testSources            map[string]string
	selected               []string
	Path, SHA256, Provider string
	Source                 records.Source
	Closure                reconstructionArtifactClosure
}

func buildConfigurationRecoveryArtifact(ctx context.Context, root, directory, provider string, source records.Source) (configurationRecoveryArtifact, error) {
	return buildConfigurationRecoveryArtifactOwned(nil, ctx, root, directory, provider, source)
}

func reconstructionModule(provider string) (string, error) {
	module := "compositions/aws"
	if provider == "gcp" {
		module = "providers/gcp"
	} else if provider != "aws" {
		return "", errors.New("recovery artifact provider refused")
	}
	return module, nil
}

func reconstructionBuildCommands(module string) []checkCommandFacts {
	commands := make([]checkCommandFacts, 3)
	for index := range commands {
		commands[index] = preparationReservationFact(module, true)
	}
	return commands
}

func reconstructionConstructionCommands(provider string) ([]checkCommandFacts, error) {
	module, err := reconstructionModule(provider)
	if err != nil {
		return nil, err
	}
	return append(reconstructionBuildCommands(module), preparationReservationFact("reconstruction-inventory", false)), nil
}

func buildConfigurationRecoveryArtifactOwned(diagnostics *checkDiagnostics, ctx context.Context, root, directory, provider string, source records.Source) (configurationRecoveryArtifact, error) {
	value, _, err := invocationArtifactValue(ctx, root, directory, "reconstruction", provider, func(build string) (configurationRecoveryArtifact, error) {
		return constructConfigurationRecoveryArtifactOwned(diagnostics, ctx, root, build, provider, source)
	})
	return value, err
}

func constructConfigurationRecoveryArtifactOwned(diagnostics *checkDiagnostics, ctx context.Context, root, directory, provider string, source records.Source) (configurationRecoveryArtifact, error) {
	module, err := reconstructionModule(provider)
	if err != nil {
		return configurationRecoveryArtifact{}, err
	}
	if diagnostics != nil && !diagnostics.hasPlan() {
		if err := diagnostics.reserveCommands(reconstructionBuildCommands(module)); err != nil {
			return configurationRecoveryArtifact{}, err
		}
		defer diagnostics.cancelReservations()
	}
	execute := runGoEnvironment
	if diagnostics != nil {
		execute = diagnostics.runGoEnvironment
	}
	overlay, err := buildCryptoOverlay(root, directory)
	if err != nil {
		return configurationRecoveryArtifact{}, err
	}
	path := filepath.Join(directory, provider+"-reconstruction.test")
	flags := append(compilerBuildFlags(moduleTestFlags(root, module, overlay), raceEnabled(ctx)), "-buildvcs=false")
	modules, packages, err := listClosure(execute, ctx, root, module, flags, true, ".")
	if err != nil {
		return configurationRecoveryArtifact{}, err
	}
	for _, p := range packages {
		name, _, _ := strings.Cut(p.ImportPath, " [")
		if withinModule(name, modulePrefix+"core") && (p.ForTest != "" || strings.Contains(name, "/internal/test") || slicesContainsTestFile(p.GoFiles)) {
			return configurationRecoveryArtifact{}, errors.New("private Core test source reached reconstruction artifact")
		}
	}
	declarations, err := captureCompiledTestDeclarations(root, packages, flags, modulePath(module))
	if err != nil {
		return configurationRecoveryArtifact{}, err
	}
	flags, err = declarations.compilerFlags(flags, directory)
	if err != nil {
		return configurationRecoveryArtifact{}, err
	}
	args := append([]string{"test"}, flags...)
	args = append(args, "-c", "-o", path, ".")
	if _, err := execute(ctx, root, module, nil, args...); err != nil {
		return configurationRecoveryArtifact{}, err
	}
	observed, raceErr := binaryRace(path)
	if raceErr != nil || observed != raceEnabled(ctx) {
		return configurationRecoveryArtifact{}, errors.Join(raceErr, errors.New("recovery executable race policy differs"))
	}
	digest, err := assemblyFileSHA256(path)
	if err != nil {
		return configurationRecoveryArtifact{}, err
	}
	closure := makeClosure("reconstruction", provider, modules, packages)
	return configurationRecoveryArtifact{declarations: declarations, module: module, overlay: overlay, buildFlags: slices.Clone(flags), Path: path, SHA256: digest, Provider: provider, Source: source, Closure: reconstructionArtifactClosure{Race: raceSetting(raceEnabled(ctx)), Provider: provider, Source: source, BinarySHA256: digest, RaceOptions: acceptedRaceOptions(raceEnabled(ctx)), NoCoreOverlay: true, ResolvedModules: closure.ResolvedModules, CompiledImports: closure.CompiledImports}}, nil
}

func prepareConfigurationRecoveryArtifact(ctx context.Context, root, directory, provider string, source records.Source, selected []string) (configurationRecoveryArtifact, bool, error) {
	return prepareConfigurationRecoveryArtifactOwned(nil, ctx, root, directory, provider, source, selected)
}

func prepareConfigurationRecoveryArtifactOwned(diagnostics *checkDiagnostics, ctx context.Context, root, directory, provider string, source records.Source, selected []string) (configurationRecoveryArtifact, bool, error) {
	if diagnostics != nil && !diagnostics.hasPlan() {
		commands, err := reconstructionConstructionCommands(provider)
		if err != nil {
			return configurationRecoveryArtifact{}, false, err
		}
		if err := diagnostics.reserveCommands(commands); err != nil {
			return configurationRecoveryArtifact{}, false, err
		}
		defer diagnostics.cancelReservations()
	}
	artifact, err := buildConfigurationRecoveryArtifactOwned(diagnostics, ctx, root, directory, provider, source)
	if err != nil {
		return artifact, false, err
	}
	artifact, _, err = invocationArtifactValue(ctx, root, directory, "reconstruction-inventory", artifact.Path, func(string) (configurationRecoveryArtifact, error) {
		if diagnostics != nil {
			if err := diagnostics.consumeCommands([]checkCommandFacts{preparationReservationFact("reconstruction-inventory", false)}); err != nil {
				return artifact, err
			}
		}
		started := time.Now()
		process, names, stdout, stderr := executeComponentInventory(ctx, root, artifact.Path, goEnvironment())
		if diagnostics != nil {
			facts := commandFacts("preparation", "reconstruction-inventory", process, time.Since(started))
			if process.Joined {
				facts.RaceObservation = observedRace(true, stdout.Bytes(), stderr.Bytes())
			}
			if err := diagnostics.append(facts); err != nil {
				failure := &toolFailure{operation: "reconstruction inventory", process: process}
				if process.Joined {
					failure.stdout, failure.stderr = stdout.Bytes(), stderr.Bytes()
				}
				if process.Status == "passed" && process.Joined {
					return artifact, err
				}
				return artifact, errors.Join(failure, err)
			}
		}
		if process.Status != "passed" || !process.Joined {
			failure := &toolFailure{operation: "reconstruction inventory", process: process}
			if process.Joined {
				failure.stdout, failure.stderr = stdout.Bytes(), stderr.Bytes()
			}
			return artifact, failure
		}
		pkg := modulePath(artifact.module)
		rows, sources, err := artifact.declarations.classify(map[string][]string{pkg: names})
		if err != nil {
			return artifact, err
		}
		artifact.inventory, artifact.classifications, artifact.testSources = names, rows[pkg], sources[pkg]
		return artifact, nil
	})
	if err != nil {
		return artifact, false, err
	}
	artifact.selected = slices.Clone(selected)
	names := artifact.inventory
	pkg := modulePath(artifact.module)
	for _, name := range selected {
		if !slices.Contains(names, name) {
			return artifact, false, fmt.Errorf("selected reconstruction helper %s missing from compiled inventory", name)
		}
	}
	big, err := selectedRootsBig(pkg, selected, artifact.classifications)
	if err != nil {
		return artifact, false, err
	}
	return artifact, big, checkRecoveryRace(ctx, artifact)
}

func checkRecoveryRace(ctx context.Context, artifact configurationRecoveryArtifact) error {
	if artifact.Closure.Race == nil || *artifact.Closure.Race != raceEnabled(ctx) || artifact.Closure.RaceOptions != acceptedRaceOptions(raceEnabled(ctx)) {
		return errors.New("prepared reconstruction race policy changed")
	}
	return ctx.Err()
}

type configurationRecoveryPhase struct {
	Phase        string
	Process      processResult
	Terminals    string
	BinarySHA256 string
}

type configurationRecoveryProcessEvidence struct {
	Provider    string
	Recovery    bool
	Phases      []configurationRecoveryPhase
	LossBarrier bool
	Report      installedarchive.RecoveryReport
}

func runConfigurationRecoveryProcesses(ctx context.Context, root, directory string, setup assembly, driver configurationRecoveryArtifact, recovery bool, condition string, privateOracle ...bool) (configurationRecoveryProcessEvidence, error) {
	return runConfigurationRecoveryProcessesWithPublication(ctx, root, directory, setup, driver, recovery, condition, "", privateOracle...)
}

func runConfigurationRecoveryProcessesWithPublication(ctx context.Context, root, directory string, setup assembly, driver configurationRecoveryArtifact, recovery bool, condition, history string, privateOracle ...bool) (evidence configurationRecoveryProcessEvidence, err error) {
	return runConfigurationRecoveryProcessesOwned(nil, ctx, root, directory, setup, driver, recovery, condition, history, privateOracle...)
}

func runConfigurationRecoveryProcessesOwned(diagnostics *checkDiagnostics, ctx context.Context, root, directory string, setup assembly, driver configurationRecoveryArtifact, recovery bool, condition, history string, privateOracle ...bool) (evidence configurationRecoveryProcessEvidence, err error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	evidence.Provider, evidence.Recovery = driver.Provider, recovery
	if err := checkAssemblyRace(ctx, setup); err != nil {
		return evidence, err
	}
	if history != "" && (condition != "complete" || len(privateOracle) != 0) {
		return evidence, errors.New("publication continuation requires the complete seven-value fixture")
	}
	capture := len(privateOracle) == 1 && privateOracle[0]
	if len(privateOracle) > 1 || capture && condition != "complete" {
		return evidence, errors.New("private handoff control refused")
	}
	oracleDirectory := ""
	if capture {
		oracleDirectory = filepath.Join(directory, "parent-oracle")
		if err := os.Mkdir(oracleDirectory, 0700); err != nil {
			return evidence, err
		}
		defer func() {
			if cleanupErr := os.RemoveAll(oracleDirectory); cleanupErr != nil {
				err = errors.Join(err, errors.New("private oracle cleanup failed"))
			}
			if _, statErr := os.Lstat(oracleDirectory); !os.IsNotExist(statErr) {
				err = errors.Join(err, errors.New("private oracle survived cleanup"))
			}
		}()
	}
	local := filepath.Join(directory, "local-configuration")
	if err := os.Mkdir(local, 0700); err != nil {
		return evidence, err
	}
	configuration, remote := filepath.Join(local, "configuration.json"), filepath.Join(directory, "remote-parent.json")
	resources, descriptor := filepath.Join(directory, "resources-parent.json"), filepath.Join(local, "provider-setup.json")
	location := contract.StoreLocation{Provider: contract.AWS, Region: "us-east-1", Bucket: "fixture-bucket", PrefixBeforeHEAD: "fixture", ExpectedOwner: "123456789012"}
	if driver.Provider == "gcp" {
		location.Provider, location.Region, location.ExpectedOwner = contract.GCP, "australia-southeast1", ""
	}
	resourceInput := filepath.Join(local, "resource-input.json")
	if err := records.WriteJSON(resourceInput, installedarchive.RecoveryResourceInput{Recovery: recovery, Location: location, Resources: resources, Setup: descriptor}, 0600); err != nil {
		return evidence, err
	}
	resourcePhase, err := runConfigurationRecoveryPhase(ctx, directory, driver.Path, driver.SHA256, "resource-owner", "TestConfigurationRecoveryResourceOwner", environment(os.Environ(), map[string]string{"ENKV_RECOVERY_RESOURCES_INPUT": resourceInput}))
	evidence.Phases = append(evidence.Phases, resourcePhase)
	if err != nil {
		return evidence, err
	}
	for _, phase := range []string{"setup", "writer"} {
		input := struct {
			Phase, Provider                                    string
			Recovery                                           bool
			Configuration, Output, Setup, Resources, Condition string
			Plain                                              bool
			OracleDirectory                                    string
			PublicationHistory, PublicationExpectation         string
		}{phase, driver.Provider, recovery, configuration, remote, descriptor, resources, condition, capture, oracleDirectory, history, filepath.Join(directory, "loss-history-expectation.json")}
		path := filepath.Join(local, phase+"-input.json")
		if err := records.WriteJSON(path, input, 0600); err != nil {
			return evidence, err
		}
		value, err := runConfigurationRecoveryPhase(ctx, directory, setup.Binary, setup.Closure.BinarySHA256, phase, "TestConfigurationRecoveryFixtureProcess", environment(os.Environ(), map[string]string{"ENKV_CONFIGURATION_RECOVERY_FIXTURE": path}))
		evidence.Phases = append(evidence.Phases, value)
		if err != nil {
			return evidence, err
		}
	}
	// Only the parent-owned remote carrier survives. Neither joined process can
	// use the saved basis again, and the ordinary driver cannot see its path.
	if err := os.RemoveAll(local); err != nil {
		return evidence, err
	}
	if _, err := os.Lstat(local); !os.IsNotExist(err) {
		return evidence, errors.New("complete-loss barrier missing")
	}
	evidence.LossBarrier = true
	report := filepath.Join(directory, "parent-report.json")
	child := filepath.Join(directory, "restricted-child.txt")
	name := "TestRestrictedAWSReconstructionFromConsoleInputs"
	if driver.Provider == "gcp" {
		name = "TestRestrictedGCPReconstructionFromConsoleInputs"
	}
	parentEnvironment := map[string]string{
		"ENKV_RECOVERY_RETAINED_OBSERVATIONS": directory, "ENKV_RECOVERY_PARENT_FIXTURE": remote, "ENKV_RECOVERY_PARENT_RESOURCES": resources, "ENKV_RECOVERY_PARENT_CONDITION": condition, "ENKV_RECOVERY_PARENT_REPORT": report, "ENKV_RECOVERY_CHILD_TERMINALS": child,
	}
	if history != "" {
		parentEnvironment["ENKV_RECOVERY_PUBLICATION_CONTINUATION"] = filepath.Join(directory, "verified-publication-continuation.json")
	}
	value, err := runConfigurationRecoveryPhase(ctx, directory, driver.Path, driver.SHA256, "reconstruction-parent", name, environment(os.Environ(), parentEnvironment))
	evidence.Phases = append(evidence.Phases, value)
	if err != nil {
		return evidence, err
	}
	var terminals installedarchive.ChildOutput
	body, err := os.ReadFile(child)
	if err != nil {
		return evidence, err
	}
	if _, err := terminals.Write(body); err != nil {
		return evidence, err
	}
	if err := terminals.Completed(name); err != nil {
		return evidence, err
	}
	if err := records.ReadJSON(report, &evidence.Report); err != nil {
		return evidence, err
	}
	wantOpened := installedarchive.RecoverySecretCount(condition)
	if capture {
		wantOpened = 3
		if evidence.Report.OracleCounts.AuthorityDecrypts != 3 {
			return evidence, errors.New("private provider epoch incomplete")
		}
	}
	if !evidence.Report.Refused && evidence.Report.Opened != wantOpened || evidence.Report.Refused && evidence.Report.Opened != 0 || !evidence.Report.RemoteEffectsZero || !evidence.Report.OracleEpochSeparate {
		return evidence, errors.New("complete-loss parent verification incomplete")
	}
	if _, err := os.Lstat(remote); !os.IsNotExist(err) {
		return evidence, errors.New("parent carrier was not retired")
	}
	if _, err := os.Lstat(resources); !os.IsNotExist(err) {
		return evidence, errors.New("parent resource carrier was not retired")
	}
	return evidence, nil
}

func runConfigurationRecoveryPhase(parent context.Context, directory, binary, digest, phase, name string, environment []string, workingDirectory ...string) (configurationRecoveryPhase, error) {
	value := configurationRecoveryPhase{Phase: phase, BinarySHA256: digest, Terminals: filepath.Join(directory, phase+".txt")}
	ctx, cancel := context.WithTimeout(parent, time.Minute)
	defer cancel()
	command := exec.Command(binary, "-test.v=test2json", "-test.count=1", "-test.timeout=50s", "-test.run=^"+name+"$", "-test.parallel=1")
	command.Dir, command.Env = directory, environment
	if len(workingDirectory) > 1 {
		return value, errors.New("process working directory selection refused")
	}
	if len(workingDirectory) == 1 {
		command.Dir = workingDirectory[0]
	}
	var output installedarchive.ChildOutput
	command.Stdout, command.Stderr = &output, &output
	value.Process = superviseProcess(ctx, command)
	if !value.Process.Joined {
		return value, &toolFailure{operation: "configuration recovery " + phase, process: value.Process}
	}
	var phaseErr error
	if value.Process.Status != "passed" || !value.Process.Started || value.Process.Cause != nil {
		phaseErr = &toolFailure{operation: "configuration recovery " + phase, process: value.Process, stdout: output.Bytes()}
		if prefixErr := output.FailedPrefix(name); prefixErr != nil {
			phaseErr = errors.Join(phaseErr, prefixErr)
		} else {
			phaseErr = containProcessFailure(parent, phaseErr)
		}
	} else {
		completionErr := output.Completed(name)
		if bytes.Contains(output.Bytes(), []byte("WARNING: DATA RACE")) {
			completionErr = errors.Join(completionErr, errors.New("recovery phase race report"))
		}
		if completionErr != nil {
			failed := value.Process
			failed.Cause = errors.Join(failed.Cause, completionErr)
			phaseErr = &toolFailure{operation: "configuration recovery " + phase, process: failed, stdout: output.Bytes()}
		}
	}
	if err := os.WriteFile(value.Terminals, output.Bytes(), 0600); err != nil {
		return value, errors.Join(phaseErr, err)
	}
	if phaseErr != nil {
		return value, phaseErr
	}
	return value, nil
}

func slicesContainsTestFile(files []string) bool {
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			return true
		}
	}
	return false
}

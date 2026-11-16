package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	records "enkv.sh/core/internal/testrecords"
)

type moduleIdentity struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}

type checkEvidence struct {
	raceMissing         bool
	EventTimeSource     string                   `json:"event_time_source,omitempty"`
	Diagnostics         *checkDiagnostics        `json:"diagnostics,omitempty"`
	AssemblyFocus       *assemblyFocus           `json:"assembly_focus,omitempty"`
	AssemblyPreparation *assemblyPreparation     `json:"assembly_preparation,omitempty"`
	Focus               *componentFocus          `json:"focus,omitempty"`
	Profile             string                   `json:"profile,omitempty"`
	Race                bool                     `json:"race"`
	RaceOptions         string                   `json:"race_options,omitempty"`
	Parallelism         int                      `json:"parallelism,omitempty"`
	CompiledInventory   []string                 `json:"compiled_inventory,omitempty"`
	AssemblySources     map[string]string        `json:"assembly_sources,omitempty"`
	AssemblyNeutral     *bool                    `json:"assembly_neutral,omitempty"`
	Classifications     []testClassification     `json:"classifications,omitempty"`
	Inventory           []string                 `json:"inventory,omitempty"`
	NotSelected         []string                 `json:"not_selected,omitempty"`
	Groups              []componentGroupEvidence `json:"groups,omitempty"`
	Timings             []componentTiming        `json:"timings,omitempty"`
	ElapsedSeconds      float64                  `json:"elapsed_seconds"`
	Outcome             string                   `json:"outcome"`
	Selection           string                   `json:"selection"`
	Tests               []componentTest          `json:"tests,omitempty"`
	TestsComplete       bool                     `json:"tests_complete,omitempty"`
}

type assemblyClosure struct {
	declarations            capturedTestDeclarations
	capturedFailureSources  *records.FailureSources
	StockPlugins            *stockPluginClosure `json:"stock_plugins,omitempty"`
	raceMissing             bool
	PublicConfiguration     *publicConfigurationClosure     `json:"public_configuration,omitempty"`
	OutputArtifacts         []*outputArtifactClosure        `json:"output_artifacts,omitempty"`
	ReconstructionArtifacts []reconstructionArtifactClosure `json:"reconstruction_artifacts,omitempty"`
	FailureSourcesSHA256    string                          `json:"failure_sources_sha256,omitempty"`
	Race                    bool                            `json:"race"`
	BinarySHA256            string                          `json:"binary_sha256,omitempty"`
	OverlaySHA256           string                          `json:"overlay_sha256,omitempty"`
	BuildTags               []string                        `json:"build_tags,omitempty"`
	RaceOptions             string                          `json:"race_options,omitempty"`
	RaceExitSleepMillis     int                             `json:"race_exit_sleep_ms"`
	VetElapsedSeconds       float64                         `json:"vet_elapsed_seconds"`
	BuildElapsedSeconds     float64                         `json:"build_elapsed_seconds"`
	Suite                   string                          `json:"suite"`
	Provider                string                          `json:"provider"`
	ResolvedModules         []moduleIdentity                `json:"resolved_modules"`
	CompiledImports         []string                        `json:"compiled_imports"`
	LocalChecks             *checkEvidence                  `json:"local_checks,omitempty"`
}

type assembly struct {
	currentPrefix      *checkDiagnostics
	converterRecorded  bool
	preparationOwner   any
	preparationKey     string
	bootstrap          string
	componentSelection *preparedComponentChecks
	providerSelection  *preparedProviderChecks
	converter          preparedTestEventConverter

	root                        string
	FailureSources              *records.FailureSourceBinding
	Binary                      string
	StockPluginsDirectory       string
	PublicConfigurationCLI      string
	PublicConfigurationConsumer string
	Closure                     assemblyClosure
	buildFlags                  []string
}

func buildOverlay(root, suite, provider, bootstrap, directory string) (string, error) {
	if suite != "hermetic" && suite != "live" || suite == "hermetic" && provider != "memory" || suite == "live" && provider != "aws" && provider != "gcp" {
		return "", errors.New("unknown test assembly")
	}
	bootstrap, err := filepath.EvalSymlinks(bootstrap)
	if err != nil {
		return "", fmt.Errorf("test tool overlay unavailable: %w", err)
	}
	var overlay struct{ Replace map[string]string }
	if err := records.ReadJSON(bootstrap, &overlay); err != nil {
		return "", fmt.Errorf("test tool overlay unavailable at %s: %w", bootstrap, err)
	}
	if overlay.Replace == nil {
		return "", fmt.Errorf("test tool overlay unavailable at %s: replacement map missing", bootstrap)
	}
	for target := range overlay.Replace {
		relative, err := filepath.Rel(filepath.Join(root, "core/internal"), target)
		if err != nil || strings.HasPrefix(relative, "..") || filepath.IsAbs(relative) {
			return "", errors.New("test tool overlay escaped its package owner")
		}
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			return "", errors.New("test tool overlay would replace Core source")
		}
	}
	if err := addTestAdmissions(root, overlay.Replace); err != nil {
		return "", err
	}
	groups := []string{"tests/shared"}
	if suite == "hermetic" {
		groups = append(groups, "tests/hermetic")
	} else {
		if err := addTestSourceOverlays(root, overlay.Replace, records.LiveTestSupportOverlays()); err != nil {
			return "", err
		}
		groups = append(groups, "tests/live/shared", "tests/live/runner", "tests/live/providers/"+provider)
	}
	if err := addCoreTestGroups(root, groups, overlay.Replace); err != nil {
		return "", err
	}
	path, err := records.SafePath(directory, "overlay.json")
	if err != nil {
		return "", fmt.Errorf("test assembly overlay could not be saved in %s: %w", directory, err)
	}
	if err := records.WriteJSON(path, overlay, 0600); err != nil {
		return "", fmt.Errorf("test assembly overlay could not be saved at %s: %w", path, err)
	}
	return path, nil
}

// Both the execution overlay and the physical lint assembly use these exact
// source groups and collision checks.
func addCoreTestGroups(root string, groups []string, replacements map[string]string) error {
	for _, group := range groups {
		sourceDirectory, err := records.SafePath(root, group)
		if err != nil {
			return errors.New("test source directory refused")
		}
		entries, err := os.ReadDir(sourceDirectory)
		if err != nil {
			return fmt.Errorf("test source directory unavailable: %w", err)
		}
		count := 0
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			source, err := records.SafePath(root, filepath.Join(group, entry.Name()))
			if err != nil {
				return errors.New("test source path refused")
			}
			name := strings.ReplaceAll(group, "/", "_") + "_" + entry.Name()
			target := filepath.Join(root, "core", name)
			if _, err := os.Lstat(target); !os.IsNotExist(err) || replacements[target] != "" {
				return errors.New("test overlay would replace Core source")
			}
			replacements[target] = source
			count++
		}
		if count == 0 {
			return errors.New("test assembly source group is empty")
		}
	}
	return nil
}

func addTestAdmissions(root string, replacements map[string]string) error {
	return addTestSourceOverlays(root, replacements, records.TestAdmissionOverlays())
}

func addTestSourceOverlays(root string, replacements map[string]string, sources []records.TestSourceOverlay) error {
	for _, overlay := range sources {
		source, err := records.SafePath(root, overlay.Source)
		if err != nil {
			return fmt.Errorf("%s admission source path refused", overlay.Owner)
		}
		info, err := os.Lstat(source)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("%s admission source unavailable", overlay.Owner)
		}
		target := filepath.Join(root, overlay.Target)
		if _, err := os.Lstat(target); !os.IsNotExist(err) || replacements[target] != "" {
			return fmt.Errorf("test overlay would replace %s source", overlay.Owner)
		}
		replacements[target] = source
	}
	return nil
}

func addCryptoTests(root string, replacements map[string]string) error {
	directory, err := records.SafePath(root, "tests/crypto")
	if err != nil {
		return errors.New("Crypto test source path refused")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return errors.New("Crypto test source unavailable")
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		source, err := records.SafePath(root, filepath.Join("tests/crypto", entry.Name()))
		if err != nil {
			return errors.New("Crypto test source path refused")
		}
		target := filepath.Join(root, "crypto", "zz_test_"+entry.Name())
		if _, err := os.Lstat(target); !os.IsNotExist(err) || replacements[target] != "" {
			return errors.New("test overlay would replace Crypto source")
		}
		replacements[target] = source
	}
	return nil
}

func buildCryptoOverlay(root, directory string) (string, error) {
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		return "", err
	}
	var overlay struct{ Replace map[string]string }
	overlay.Replace = make(map[string]string)
	if err := addTestAdmissions(root, overlay.Replace); err != nil {
		return "", err
	}
	if err := addCryptoTests(root, overlay.Replace); err != nil {
		return "", err
	}
	path := filepath.Join(directory, "crypto-overlay.json")
	if err := records.WriteJSON(path, overlay, 0600); err != nil {
		return "", err
	}
	return path, nil
}

func assemblyModfile(root, suite, provider string) string {
	if suite == "hermetic" {
		return filepath.Join(root, "tests/hermetic/hermetic.mod")
	}
	return filepath.Join(root, "tests/live/providers", provider, "live.mod")
}

func moduleTestFlags(root, module, overlay string) []string {
	if source, known := registeredModule(module); known && source.Sibling != "" {
		return []string{"-mod=readonly"}
	}
	flags := []string{"-mod=readonly", "-overlay=" + overlay}
	if module == "core" {
		flags = append(flags, "-modfile="+assemblyModfile(root, "hermetic", "memory"))
	} else if module == "crypto" || module == "providers/aws" || module == "providers/gcp" {
		flags = append(flags, "-modfile="+filepath.Join(root, module, "telemetry_test.mod"))
	}
	return flags
}

func requiredAssemblyModules(suite, provider string) []string {
	modules := []string{"core", "crypto", "telemetry", "compositions/generatorhost", "compositions/internal/nativeprocess", "compositions/observability", "protocols/generator", "compositions/outputhost", "protocols/output", "plugins/cloudflare", "plugins/local-random-secret", "sdk/generator", "sdk/manifest-generator", "protocols/manifest-generator", "plugins/manifest-generators/generic-json"}
	if suite == "hermetic" {
		return append(modules, "compositions/configuration", "compositions/manifesthost")
	}
	return append(modules, "providers/"+provider, "plugins/"+provider+"-output", "plugins/github-output")
}

func discoverAssembly(command goEnvironmentCommand, ctx context.Context, root, suite, provider, bootstrap, directory string) ([]string, assemblyClosure, error) {
	if captured, ok := ctx.Value(preparationBootstrapKey{}).(preparationBootstrap); ok && captured.root == root && captured.path == bootstrap {
		bootstrap = filepath.Join(directory, "bootstrap.json")
		if err := os.WriteFile(bootstrap, captured.contents, 0o400); err != nil {
			return nil, assemblyClosure{}, err
		}
	}
	overlay, err := buildOverlay(root, suite, provider, bootstrap, directory)
	if err != nil {
		return nil, assemblyClosure{}, err
	}
	flags := []string{"-mod=readonly", "-overlay=" + overlay, "-modfile=" + assemblyModfile(root, suite, provider)}
	if suite == "live" {
		// Darwin's native resolver can leave an inheritable pipe after provider setup.
		// The child must still reject every descriptor outside its fixed wire set.
		flags = append(flags, "-tags=netgo")
	}
	modules, packages, err := listClosure(localDiscoveryCommand(command), ctx, root, "core", compilerBuildFlags(flags, raceEnabled(ctx)), true)
	if err != nil {
		return nil, assemblyClosure{}, err
	}
	closure := makeClosure(suite, provider, modules, packages)
	failedSources, err := captureFailureSources(root, overlay, closure)
	if err != nil {
		return nil, assemblyClosure{}, err
	}
	closure.capturedFailureSources = &failedSources
	closure.declarations, err = captureCompiledTestDeclarations(root, packages, flags, componentPackage)
	if err != nil {
		return nil, assemblyClosure{}, err
	}
	flags, err = closure.declarations.compilerFlags(flags, directory)
	if err != nil {
		return nil, assemblyClosure{}, err
	}
	for _, flag := range flags {
		if path, found := strings.CutPrefix(flag, "-overlay="); found {
			overlay = path
		}
	}
	overlayDigest, err := assemblyFileSHA256(overlay)
	if err != nil {
		return nil, assemblyClosure{}, errors.New("assembly overlay identity unavailable")
	}
	closure.OverlaySHA256 = overlayDigest
	if suite == "live" {
		closure.BuildTags = []string{"netgo"}
	}
	return flags, closure, nil
}

func vetAssembly(command goEnvironmentCommand, ctx context.Context, root, suite, provider, bootstrap, directory string) ([]string, assemblyClosure, error) {
	flags, closure, err := discoverAssembly(command, ctx, root, suite, provider, bootstrap, directory)
	if err != nil {
		return nil, assemblyClosure{}, err
	}
	args := append([]string{"vet"}, compilerBuildFlags(flags, raceEnabled(ctx))...)
	_, err = command(ctx, root, "core", nil, append(args, ".")...)
	return flags, closure, containProcessFailure(ctx, err)
}

func buildAssembly(command goEnvironmentCommand, diagnostics *checkDiagnostics, ctx context.Context, root, suite, provider, bootstrap, directory string) (assembly, error) {
	return buildAssemblyMode(command, diagnostics, ctx, root, suite, provider, bootstrap, directory, raceEnabled(ctx))
}

type assemblyBindings struct {
	Cloudflare *cloudflareAssemblyBinding
	Output     []outputProfileBinding
}

func buildAssemblyMode(command goEnvironmentCommand, diagnostics *checkDiagnostics, ctx context.Context, root, suite, provider, bootstrap, directory string, race bool, binding ...*cloudflareAssemblyBinding) (assembly, error) {
	if len(binding) > 1 {
		return assembly{}, errors.New("Cloudflare binding requires one live assembly")
	}
	var bindings assemblyBindings
	if len(binding) == 1 {
		bindings.Cloudflare = binding[0]
	}
	return buildBoundAssemblyMode(command, diagnostics, ctx, root, suite, provider, bootstrap, directory, race, bindings)
}

func copyAssemblyBindings(bindings assemblyBindings) (assemblyBindings, error) {
	if bindings.Output != nil {
		selected, err := validateOutputBindings(bindings.Output)
		if err != nil {
			return assemblyBindings{}, err
		}
		bindings.Output = selected
	}
	if bindings.Cloudflare != nil {
		cloudflare := *bindings.Cloudflare
		cloudflare.Installation = slices.Clone(cloudflare.Installation)
		cloudflare.Dependency = slices.Clone(cloudflare.Dependency)
		bindings.Cloudflare = &cloudflare
	}
	return bindings, nil
}

func buildBoundAssemblyMode(command goEnvironmentCommand, diagnostics *checkDiagnostics, ctx context.Context, root, suite, provider, bootstrap, directory string, race bool, bindings assemblyBindings) (assembly, error) {
	ctx = withRacePolicy(ctx, race)
	var err error
	ctx, err = withPreparationBootstrap(ctx, root, bootstrap)
	if err != nil {
		return assembly{}, err
	}
	captured, _ := ctx.Value(preparationBootstrapKey{}).(preparationBootstrap)
	bindings, err = copyAssemblyBindings(bindings)
	if err != nil {
		return assembly{}, err
	}
	recipe := struct {
		Suite, Provider, Bootstrap string
		Bindings                   assemblyBindings
	}{suite, provider, captured.identity, bindings}
	value, _, err := invocationArtifactValue(ctx, root, directory, "assembly", recipe, func(build string) (assembly, error) {
		return constructBoundAssembly(command, diagnostics, ctx, root, suite, provider, bootstrap, build, race, bindings)
	})
	return value, err
}

func constructBoundAssembly(command goEnvironmentCommand, diagnostics *checkDiagnostics, ctx context.Context, root, suite, provider, bootstrap, directory string, race bool, bindings assemblyBindings) (value assembly, err error) {
	if diagnostics != nil && !diagnostics.hasPlan() {
		future, e := assemblyConstructionCommands(bindings)
		if e != nil {
			return assembly{}, e
		}
		if e = diagnostics.reserveCommands(future); e != nil {
			return assembly{}, e
		}
		defer diagnostics.cancelReservations()
	}
	ctx = withRacePolicy(ctx, race)
	bindings, err = copyAssemblyBindings(bindings)
	if err != nil {
		return assembly{}, err
	}
	ctx, err = withPreparationBootstrap(ctx, root, bootstrap)
	if err != nil {
		return assembly{}, err
	}

	flags, closure, err := discoverAssembly(command, ctx, root, suite, provider, bootstrap, directory)
	if err != nil {
		return assembly{}, err
	}
	value, err = compileBoundAssembly(command, diagnostics, ctx, root, directory, flags, closure, race, bindings)
	value.bootstrap = bootstrap
	return value, err
}

func compileAssembly(command goEnvironmentCommand, diagnostics *checkDiagnostics, ctx context.Context, root, directory string, flags []string, closure assemblyClosure, race bool, binding ...*cloudflareAssemblyBinding) (assembly, error) {
	if len(binding) > 1 {
		return assembly{}, errors.New("Cloudflare binding requires one live assembly")
	}
	var bindings assemblyBindings
	if len(binding) == 1 {
		bindings.Cloudflare = binding[0]
	}
	return compileBoundAssembly(command, diagnostics, ctx, root, directory, flags, closure, race, bindings)
}

func compileBoundAssembly(command goEnvironmentCommand, diagnostics *checkDiagnostics, ctx context.Context, root, directory string, flags []string, closure assemblyClosure, race bool, bindings assemblyBindings) (assembly, error) {
	if diagnostics != nil && !diagnostics.hasPlan() {
		future, e := assemblyCompilationCommands(bindings)
		if e != nil {
			return assembly{}, e
		}
		if e = diagnostics.reserveCommands(future); e != nil {
			return assembly{}, e
		}
		defer diagnostics.cancelReservations()
	}
	ctx = withRacePolicy(ctx, race)
	bindings, err := copyAssemblyBindings(bindings)
	if err != nil {
		return assembly{}, err
	}
	if bindings.Cloudflare != nil && closure.Suite != "live" {
		return assembly{}, errors.New("Cloudflare binding requires one live assembly")
	}
	overlay := ""
	for _, flag := range flags {
		if path, ok := strings.CutPrefix(flag, "-overlay="); ok {
			overlay = path
		}
	}
	currentOverlay, err := assemblyFileSHA256(overlay)
	if err != nil || currentOverlay != closure.OverlaySHA256 || len(closure.OverlaySHA256) != sha256.Size*2 {
		return assembly{}, errors.New("assembly overlay identity unavailable")
	}
	actualFlags := compilerBuildFlags(flags, race)
	binary := filepath.Join(directory, "state.test")
	if len(closure.OutputArtifacts) != 0 {
		if err := validateOutputArtifactClosures(closure.OutputArtifacts); err != nil {
			return assembly{}, err
		}
		if bindings.Output == nil {
			bindings.Output, err = retainedOutputBindings(closure.OutputArtifacts)
			if err != nil {
				return assembly{}, err
			}
		}
	}
	outputRace := race && bindings.Output == nil
	rebuild := len(closure.OutputArtifacts) == 0 || closure.OutputArtifacts[0].Race != outputRace || closure.OutputArtifacts[0].directory == ""
	if bindings.Output != nil {
		selected, err := validateOutputBindings(bindings.Output)
		if err != nil {
			return assembly{}, err
		}
		retained, err := retainedOutputBindings(closure.OutputArtifacts)
		if len(closure.OutputArtifacts) == 0 || err != nil || !slices.Equal(selected, retained) {
			rebuild = true
		}
		bindings.Output = selected
	}
	if rebuild {
		closure.OutputArtifacts, err = buildOutputArtifactsOwned(diagnostics, ctx, root, directory, race, bindings.Output)
		if err != nil {
			return assembly{}, err
		}
	}
	for _, output := range closure.OutputArtifacts {
		binding, err := outputBinding(output.Artifact)
		if err != nil {
			return assembly{}, err
		}
		command, _ := outputCommand(binding.StoredProfileID)
		for _, suffix := range []string{"", ".installation.json", ".dependency"} {
			if err := linkInvocationFile(filepath.Join(output.directory, command.command)+suffix, filepath.Join(directory, command.command)+suffix); err != nil {
				return assembly{}, err
			}
		}
	}
	if err := validateOutputArtifactClosures(closure.OutputArtifacts); err != nil {
		return assembly{}, err
	}
	args := append([]string{"test"}, actualFlags...)
	closure.Race = race
	closure.RaceOptions, closure.RaceExitSleepMillis = "", 0
	if race {
		closure.RaceOptions = raceOptions
		closure.RaceExitSleepMillis = 1000
	}
	if bindings.Cloudflare != nil {
		v := bindings.Cloudflare
		if len(v.ArtifactSHA256) != sha256HexLength || v.ArtifactLength <= 0 || len(v.DependencyManifest) != sha256HexLength {
			return assembly{}, errors.New("Cloudflare assembly binding refused")
		}
	}
	fixtureFlag, err := outputFixtureLinkerFlag(closure.OutputArtifacts)
	if err != nil {
		return assembly{}, err
	}
	generatorFlag, err := cloudflareFixtureLinkerFlag(directory, bindings.Cloudflare)
	if err != nil {
		return assembly{}, err
	}
	fixtureFlag = strings.TrimSpace(fixtureFlag + " " + generatorFlag)
	args = append(args, "-ldflags="+fixtureFlag, "-c", "-o", binary, ".")
	failureSources := closure.capturedFailureSources
	if failureSources == nil {
		captured, captureErr := captureFailureSources(root, overlay, closure)
		if captureErr != nil {
			return assembly{}, captureErr
		}
		failureSources = &captured
	}
	started := time.Now()
	if _, err := command(ctx, root, "core", nil, args...); err != nil {
		return assembly{}, containProcessFailure(ctx, err)
	}
	if os.Chmod(binary, 0700) != nil {
		return assembly{}, errors.New("assembly executable permissions unavailable")
	}
	binaryDigest, err := assemblyFileSHA256(binary)
	if err != nil {
		return assembly{}, errors.New("assembly executable identity unavailable")
	}
	closure.BinarySHA256 = binaryDigest
	closure.BuildElapsedSeconds = time.Since(started).Seconds()
	sources, err := writeFailureSources(directory, *failureSources, closure)
	if err != nil {
		return assembly{}, err
	}
	closure.FailureSourcesSHA256 = sources.SHA256
	result := assembly{currentPrefix: diagnostics, root: root, Binary: binary, Closure: closure, buildFlags: flags, FailureSources: sources}
	observed, raceErr := binaryRace(binary)
	if raceErr != nil || observed != race {
		return assembly{}, errors.Join(raceErr, errors.New("compiled assembly race policy differs"))
	}
	return result, nil
}

func assemblyFileSHA256(path string) (string, error) {
	return assemblyFileSHA256Buffer(path, nil)
}

func assemblyFileSHA256Buffer(path string, buffer []byte) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	// Hide File.WriteTo so CopyBuffer uses the caller's scratch buffer.
	_, readErr := io.CopyBuffer(digest, struct{ io.Reader }{file}, buffer)
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func checkAssemblyRace(ctx context.Context, value assembly) error {
	for _, output := range value.Closure.OutputArtifacts {
		if output == nil {
			return errors.New("assembly output artifact missing")
		}
		binding, err := outputBinding(output.Artifact)
		if err != nil {
			return err
		}
		command, _ := outputCommand(binding.StoredProfileID)
		if output.Race != (value.Closure.Race && command.module == outputTestModule) {
			return errors.New("assembly output artifact race mode differs")
		}
	}

	if value.Closure.raceMissing || value.Closure.Race != raceEnabled(ctx) || !validRaceSettings(value.Closure.Race, value.Closure.RaceOptions, value.Closure.RaceExitSleepMillis) {
		return errors.New("assembly race policy differs")
	}
	return ctx.Err()
}

func assemblyConstructionCommands(bindings assemblyBindings) ([]checkCommandFacts, error) {
	future := []checkCommandFacts{preparationReservationFact("core", true), preparationReservationFact("core", true)}
	compile, err := assemblyCompilationCommands(bindings)
	if err != nil {
		return nil, err
	}
	return append(future, compile...), nil
}
func assemblyCompilationCommands(bindings assemblyBindings) ([]checkCommandFacts, error) {
	outputs, err := outputConstructionCommands(bindings.Output)
	if err != nil {
		return nil, err
	}
	return append(outputs, preparationReservationFact("core", true)), nil
}

func makeClosure(suite, provider string, modules []resolvedModule, packages []compiledPackage) assemblyClosure {
	closure := assemblyClosure{Suite: suite, Provider: provider, ResolvedModules: []moduleIdentity{}, CompiledImports: []string{}}
	for _, module := range modules {
		version := module.Version
		if version == "" {
			version = "local"
		}
		closure.ResolvedModules = append(closure.ResolvedModules, moduleIdentity{Path: module.Path, Version: version})
	}
	for _, p := range packages {
		closure.CompiledImports = append(closure.CompiledImports, p.ImportPath)
	}
	slices.Sort(closure.CompiledImports)
	closure.CompiledImports = slices.Compact(closure.CompiledImports)
	return closure
}

func checkHermeticBoundary(modules []resolvedModule, packages []compiledPackage) error {
	if err := checkSDKBoundaries("hermetic", modules, packages); err != nil {
		return err
	}
	if err := checkGeneratorServingBoundary("hermetic", modules, packages); err != nil {
		return err
	}
	if err := checkNeutralPins(modules); err != nil {
		return err
	}
	if err := checkObservabilityPins(modules); err != nil {
		return err
	}
	if err := checkCustodyImports(packages, true, ""); err != nil {
		return err
	}
	core := 0
	for _, module := range modules {
		if module.Path == modulePrefix+"core" {
			core++
		} else if module.Path != modulePrefix+"telemetry" && module.Path != modulePrefix+"crypto" && module.Path != modulePrefix+"compositions/generatorhost" && module.Path != modulePrefix+"compositions/configuration" && module.Path != modulePrefix+"compositions/manifesthost" && module.Path != modulePrefix+"compositions/observability" && module.Path != "enkv.sh/sdk/protocols/generator" && module.Path != modulePrefix+"compositions/outputhost" && module.Path != nativeProcessPath && module.Path != "enkv.sh/sdk/protocols/output" && module.Path != "enkv.sh/sdk/protocols/manifest-generator" && module.Path != "enkv.sh/sdk/artifact" && module.Path != "enkv.sh/plugins/generators/cloudflare-account-token" && module.Path != "enkv.sh/plugins/generators/local-random-secret" && module.Path != generatorSDKPath && module.Path != outputSDKPath && module.Path != manifestSDKPath && module.Path != genericJSONPath && module.Path != openTofuJSONPath && neutralModules[module.Path] == "" && !observabilityModule(module.Path) {
			return errors.New("hermetic assembly has an unreviewed dependency")
		}
	}
	if core != 1 {
		return errors.New("hermetic Core identity differs")
	}
	for _, p := range packages {
		name, _, _ := strings.Cut(p.ImportPath, " [")
		if !p.Standard && !withinModule(name, modulePrefix+"core") && !withinModule(name, modulePrefix+"crypto") && !withinModule(name, modulePrefix+"telemetry") &&
			name != modulePrefix+"compositions/generatorhost" && name != modulePrefix+"compositions/observability" && name != "enkv.sh/sdk/protocols/generator" && name != "enkv.sh/sdk/protocols/generator/retained" && name != modulePrefix+"compositions/outputhost" && name != nativeProcessPath && name != "enkv.sh/sdk/protocols/output" && name != "enkv.sh/sdk/protocols/manifest-generator" && name != "enkv.sh/sdk/artifact" && name != "enkv.sh/sdk/artifact/credentialroute" && name != modulePrefix+"core.test" && name != "enkv.sh/plugins/generators/cloudflare-account-token/profile" && name != "enkv.sh/plugins/generators/local-random-secret/profile" && name != "enkv.sh/plugins/generators/cloudflare-account-token/artifact" && name != manifestSDKPath && name != manifestSDKPath+"/jsonwriter" && name != genericJSONPath && name != openTofuJSONPath && !neutral(name) && !observabilityDependency(name) {
			return fmt.Errorf("external package %s reached hermetic assembly", name)
		}
	}
	return nil
}

func liveCommonTestSource(path string) bool {
	return strings.HasSuffix(path, "_test.go") && (strings.HasPrefix(path, "tests/live/shared/") || strings.HasPrefix(path, "tests/live/runner/"))
}

func liveAssemblyTestSources(active map[string]string, provider string) (map[string]string, error) {
	sources := make(map[string]string)
	for name, relative := range active {
		if filepath.IsAbs(relative) || filepath.ToSlash(filepath.Clean(relative)) != relative || !strings.HasSuffix(relative, "_test.go") {
			return nil, errors.New("live assembly test source ownership is malformed")
		}
		if strings.HasPrefix(relative, "tests/live/") && !liveCommonTestSource(relative) && !strings.HasPrefix(relative, "tests/live/providers/"+provider+"/") {
			return nil, errors.New("live assembly contains an unowned provider test source")
		}
		sharedChild := relative == "tests/shared/process_fixture_test.go" && name == "TestFreshProcessChild"
		if strings.HasPrefix(relative, "tests/live/") || sharedChild {
			sources[name] = relative
		}
	}
	if len(sources) == 0 {
		return nil, errors.New("live assembly has no owned tests")
	}
	return sources, nil
}

func liveAssemblyCheckNames(names []string, sources map[string]string, classifications []testClassification, profile string, neutral bool) ([]string, error) {
	if len(names) == 0 || len(names) > maximumComponentInventory {
		return nil, errors.New("live assembly compiled inventory is empty or exceeds its bound")
	}
	profile, err := resolveVerificationProfile(profile)
	if err != nil {
		return nil, err
	}
	eligible, _, err := selectClassifiedTests(names, classifications, profile)
	if err != nil {
		return nil, err
	}
	var selected []string
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if seen[name] {
			return nil, errors.New("live assembly inventory repeats a test")
		}
		seen[name] = true
		source, owned := sources[name]
		if !owned || !slices.Contains(eligible, name) {
			continue
		}
		switch name {
		case "TestLiveRun", "TestLiveChild", "TestLiveCleanup", "TestLiveRecovery":
			continue
		}
		if source == "tests/live/runner/inventory_checks_test.go" {
			switch name {
			case "TestLiveInventoryFreshProcess", "TestRunBudgetStopsBeforeConcurrentSends", "TestFreshReadsReserveAuthenticationBeforeEveryRead":
			default:
				if neutral {
					selected = append(selected, name)
				}
				continue
			}
		}
		selected = append(selected, name)
	}
	for name := range sources {
		if !seen[name] {
			return nil, fmt.Errorf("live assembly inventory omits owned test %s", name)
		}
	}
	if !slices.Contains(selected, "TestLiveInventoryFreshProcess") || !slices.Contains(selected, "TestFreshProcessChild") {
		return nil, errors.New("provider assembly lacks its focused inventory and fresh-process proof")
	}
	return selected, nil
}

func providerCheckCommands(value assembly) ([]checkCommandFacts, error) {
	var future []checkCommandFacts
	if value.providerSelection == nil {
		var err error
		future, err = providerPreparationCommands(value)
		if err != nil {
			return nil, err
		}
	}
	return append(future, componentReservationFact("test", value.Closure.Provider), componentReservationFact("conversion", value.Closure.Provider)), nil
}

func checkLiveAssemblySelection(ctx context.Context, root, directory string, value *assembly, profile string, neutral bool, requested string, source records.Source, toolchain string, output io.Writer) error {
	return checkLiveAssemblySelectionOwned(value.currentPrefix, ctx, root, directory, value, profile, neutral, requested, source, toolchain, output)
}
func checkLiveAssemblySelectionOwned(initial *checkDiagnostics, ctx context.Context, root, directory string, value *assembly, profile string, neutral bool, requested string, source records.Source, toolchain string, output io.Writer) (err error) {
	diagnostics := initial
	if diagnostics == nil {
		diagnostics = &checkDiagnostics{Preparation: "pending"}
	}
	if value.providerSelection != nil && value.providerSelection.evidence.Diagnostics != diagnostics {
		owner, key := value.preparationOwner, value.preparationKey
		if owner == nil {
			owner = value.providerSelection
			key = value.Closure.Provider
		}
		if e := diagnostics.retainAcquisition(owner, key, value.providerSelection.evidence.Diagnostics); e != nil {
			return e
		}
	}
	if !diagnostics.hasPlan() {
		future, e := providerCheckCommands(*value)
		if e != nil {
			return e
		}
		if e = diagnostics.reserveCommands(future); e != nil {
			return e
		}
		defer diagnostics.cancelReservations()
	}
	value.Closure.LocalChecks = nil
	phase := "preparation"
	preparationStage := true
	var leave func(bool)
	passed := false
	defer func() {
		completed := false
		defer func() {
			if leave != nil {
				leave(completed)
			}
		}()
		if err != nil && preparationStage {
			diagnostics.Preparation = "failed"
		}
		diagnosticErr := writeCheckDiagnostics(output, diagnostics)
		if diagnosticErr != nil {
			diagnostics.Preparation = "failed"
		}
		err = errors.Join(err, diagnosticErr)
		if err != nil {
			if diagnostics.Preparation == "pending" {
				diagnostics.Preparation = "failed"
			}
			if value.Closure.LocalChecks == nil {
				value.Closure.LocalChecks = &checkEvidence{raceMissing: true, Profile: profile, Outcome: "process_failed", Diagnostics: diagnostics}
			} else if diagnosticErr != nil {
				value.Closure.LocalChecks.Outcome = "process_failed"
			}
			err = retainCheckFailure(directory, "assembly-checks.log", phase, err)
		}
		completed = passed && err == nil || containedCheckFailure(ctx, err)
	}()
	if value.providerSelection != nil {
		if err := checkAssemblyRace(ctx, *value); err != nil {
			return err
		}
	}
	if err := checkAssemblyRace(ctx, *value); err != nil {
		return safeCheckFailure("preparation", "none", err)
	}
	if err := checkProgress(output, "preparation", "assembly-inventory"); err != nil {
		return err
	}
	prepared := value.providerSelection
	if prepared == nil {
		var prepareErr error
		prepared, diagnostics, prepareErr = prepareProviderChecks(diagnostics, ctx, root, *value, profile, neutral, requested, source, toolchain)
		if prepareErr != nil {
			return prepareErr
		}
	}
	if prepared.profile != profile || prepared.neutral != neutral || prepared.requested != requested {
		return errors.New("provider prepared selection changed")
	}
	classificationEvidence := prepared.evidence
	selected, focus, preparation := slices.Clone(prepared.selected), prepared.focus, prepared.preparation
	diagnostics.Preparation = "passed"
	environment := append(workerEnvironment(""), failureSourcesEnvironment(value.FailureSources)...)
	selection, err := componentSelection(selected)
	if focus != nil {
		selected = []string{focus.Owner}
		selection = literalTestSelection(focus.Requested)
	}
	if err != nil {
		return err
	}
	if focus == nil {
		if _, err := fmt.Fprintf(output, "Provider %s: %d controlled tests; neutral inventory=%t; catalog inventory=%t\n", value.Closure.Provider, len(selected), neutral, neutral && profile == "full"); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintf(output, "Provider %s: %d admitted controlled tests; focused request %s; %d roots omitted; parent setup and selected subtree assertions remain required; complete coverage unavailable\n", value.Closure.Provider, len(preparation.Inventory), focus.Requested, len(preparation.NotSelected)); err != nil {
			return err
		}
	}
	phase = "test"
	if err := checkProgress(output, "test", value.Closure.Provider); err != nil {
		return err
	}
	big, classErr := selectedRootsBig(componentPackage, selected, classificationEvidence.Classifications)
	if classErr != nil {
		return classErr
	}
	barrier := repetitionBarrierFromContext(ctx, &repetitionBarrier{})
	dispatchStarted := time.Now()
	var waitErr error
	if err := diagnostics.consumeCommands([]checkCommandFacts{componentReservationFact("test", value.Closure.Provider), componentReservationFact("conversion", value.Closure.Provider)}); err != nil {
		return err
	}
	leave, waitErr = barrier.enter(ctx, big)
	if waitErr == nil {
		ctx, waitErr = admitTestExecution(ctx, big)
	}
	var result processResult
	evidence := checkEvidence{Selection: selection, EventTimeSource: "post_join_test2json", Diagnostics: &checkDiagnostics{Preparation: "passed"}}
	stdout, stderr := &limitedOutput{}, &limitedOutput{}
	if waitErr != nil {
		result = recordTestDispatchFailure(evidence.Diagnostics, componentPackage, requested, waitErr, time.Since(dispatchStarted))
		evidence.Outcome, evidence.ElapsedSeconds = result.Status, time.Since(dispatchStarted).Seconds()
	} else {
		preparationStage = false
		processContext := ctx
		if big {
			processContext = withExecutionParallel(ctx, 1)
		}
		result, evidence, stdout, stderr = executeComponentChecks(processContext, root, value.Binary, prepared.converter, selection, selected, environment)
	}
	for _, facts := range evidence.Diagnostics.Commands {
		if focus != nil && facts.Phase == "test" {
			facts.RequestedNode = componentRequestedNode(evidence.Tests, requested, result, evidence.Diagnostics)
		}
		if appendErr := diagnostics.append(facts); appendErr != nil {
			result.Status, result.Cause = "process_failed", errors.Join(result.Cause, appendErr)
		}
	}
	evidence.Diagnostics = diagnostics
	evidence.CompiledInventory, evidence.Classifications = classificationEvidence.CompiledInventory, classificationEvidence.Classifications
	evidence.AssemblySources, evidence.AssemblyNeutral = classificationEvidence.AssemblySources, classificationEvidence.AssemblyNeutral
	evidence.NotSelected = classificationEvidence.NotSelected
	evidence.Profile, evidence.Race, evidence.Inventory = profile, value.Closure.Race, selected
	if value.Closure.Race {
		evidence.RaceOptions = raceOptions
	}
	evidence.AssemblyFocus, evidence.AssemblyPreparation = focus, preparation
	if preparation != nil {
		evidence.Inventory, evidence.NotSelected = preparation.Inventory, preparation.NotSelected
	}
	evidence.TestsComplete = evidence.TestsComplete && componentEvidenceMatchesInventory(selected, evidence.Tests)
	if focus != nil {
		evidence.TestsComplete = evidence.TestsComplete && completeFocusedAssemblyEvidence(evidence, value.Closure.Provider)
	}
	complete := completeComponentEvidence(evidence, "live", value.Closure.Provider)
	if focus != nil {
		complete = completeFocusedAssemblyEvidence(evidence, value.Closure.Provider)
	}
	preparationStage = true
	identityErr := checkAssemblyRace(ctx, *value)
	if identityErr == nil {
		preparationStage = false
	}
	if identityErr != nil || result.Status == "passed" && (!result.Joined || !evidence.TestsComplete || !complete) {
		evidence.Outcome = "process_failed"
	}
	if evidence.Outcome == "passed" && preparation != nil {
		preparation.ExecutionProof = "the exact requested node started and passed"
	}
	value.Closure.LocalChecks = &evidence
	var checkErr error
	if identityErr != nil || result.Status != "passed" || !result.Joined || !evidence.TestsComplete || !complete {
		failure := &toolFailure{operation: "controlled live assembly checks", process: result}
		if result.Joined {
			failure.stdout, failure.stderr, failure.overflow = stdout.Bytes(), stderr.Bytes(), stdout.overflow || stderr.overflow
		}
		checkErr = errors.Join(identityErr, fmt.Errorf("controlled live assembly check evidence did not qualify: %w", failure))
	}
	if checkErr != nil {
		return checkErr
	}
	_, err = fmt.Fprintf(output, "Provider %s timing: vet %.3fs, build %.3fs, checks %.3fs\n", value.Closure.Provider, value.Closure.VetElapsedSeconds, value.Closure.BuildElapsedSeconds, evidence.ElapsedSeconds)
	passed = err == nil && result.Status == "passed" && result.Joined
	return err
}

func prepareCryptoOverlay(ctx context.Context, root, directory string) (string, error) {
	value, _, err := invocationArtifactValue(ctx, root, directory, "crypto-overlay", "test-admissions", func(build string) (string, error) { return buildCryptoOverlay(root, build) })
	return value, err
}

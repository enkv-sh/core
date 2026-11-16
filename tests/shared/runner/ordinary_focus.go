package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	records "enkv.sh/core/internal/testrecords"
)

// Ordinary focus retains its configured scope. A selected pass supplies no
// complete-workflow credit, even when the selected package has only one root.
type ordinaryFocus struct {
	PackagePath string   `json:"package_path,omitempty"`
	Tests       []string `json:"tests,omitempty"`
	Package     string   `json:"package,omitempty"`
	Artifact    string   `json:"artifact,omitempty"`
}

type ordinaryArtifact struct {
	Profile         string               `json:"profile"`
	Classifications []testClassification `json:"classifications"`
	Owner           string               `json:"owner"`
	Package         string               `json:"package"`
	Directory       string               `json:"directory"`
	Patterns        []string             `json:"patterns"`
	BuildFlags      []string             `json:"-"`
	BuildInputs     []string             `json:"build_inputs"`
	TestFlags       []string             `json:"test_flags,omitempty"`
	Tests           []string             `json:"tests"`
	CompiledTests   []string             `json:"compiled_tests,omitempty"`
}

type ordinaryPreparation struct {
	Source              records.Source     `json:"source"`
	Toolchain           string             `json:"toolchain"`
	Artifacts           []ordinaryArtifact `json:"artifacts"`
	AdmittedPackages    []string           `json:"admitted_packages"`
	NotSelected         []ordinaryPackage  `json:"not_selected,omitempty"`
	NotSelectedPackages []string           `json:"not_selected_packages,omitempty"`
	ExecutionProof      string             `json:"execution_proof"`
	ParentPreparation   string             `json:"parent_preparation"`
}

type ordinaryExecution struct {
	Artifact string   `json:"artifact"`
	Package  string   `json:"package"`
	Tests    []string `json:"tests"`
}

// Go owns membership of configured patterns. Prefix guesses cannot admit a
// package excluded by build constraints or an exact configured package scope.
func resolveOrdinaryUnitPackage(ctx context.Context, root string, configured map[string][]string, path string) (ordinaryPreparation, error) {
	if !validOrdinaryPackagePath(path) {
		return ordinaryPreparation{}, errors.New("unit focus requires an exact logical package selector")
	}
	value, _, err := invocationArtifactValue(ctx, root, root, "ordinary-membership", struct {
		Scope map[string][]string
	}{configured}, func(string) (ordinaryPreparation, error) {
		return discoverOrdinaryUnitPackages(ctx, root, configured)
	})
	if err != nil {
		return ordinaryPreparation{}, err
	}
	var selected []ordinaryArtifact
	for _, artifact := range value.Artifacts {
		if artifact.Owner == path {
			artifact.Patterns = slices.Clone(artifact.Patterns)
			selected = append(selected, artifact)
		}
	}
	value.Artifacts = selected
	value.AdmittedPackages = slices.Clone(value.AdmittedPackages)
	if len(selected) != 1 {
		return value, errors.New("unit package is not uniquely admitted by the configured step")
	}
	return value, err
}

func discoverOrdinaryUnitPackages(ctx context.Context, root string, configured map[string][]string) (ordinaryPreparation, error) {
	root, err := filepath.EvalSymlinks(root)
	if err != nil || !filepath.IsAbs(root) {
		return ordinaryPreparation{}, errors.New("ordinary package root is unavailable")
	}
	var preparation ordinaryPreparation
	for _, module := range moduleRoots {
		if len(configured[module]) == 0 {
			continue
		}
		args := append(compilerBuildFlags([]string{"list", "-mod=readonly", "-find", "-json=ImportPath,Dir"}, raceEnabled(ctx)), configured[module]...)
		body, err := runGo(ctx, root, module, args...)
		if err != nil {
			return preparation, err
		}
		packages, err := decodeObjects[struct{ ImportPath, Dir string }](body)
		if err != nil || len(packages) == 0 {
			return preparation, errors.New("configured ordinary package membership is incomplete")
		}
		for _, pkg := range packages {
			if pkg.ImportPath == "" || pkg.Dir == "" {
				return preparation, errors.New("configured ordinary package lacks identity")
			}
			directory, err := filepath.EvalSymlinks(pkg.Dir)
			if err != nil {
				return preparation, errors.New("configured ordinary package directory is unavailable")
			}
			relative, err := sourceLabel(root, directory)
			if err != nil || !validOrdinaryPackagePath(filepath.ToSlash(relative)) {
				return preparation, errors.New("configured ordinary package is outside product modules")
			}
			relative = filepath.ToSlash(relative)
			if slices.Contains(preparation.AdmittedPackages, relative) {
				return preparation, errors.New("configured ordinary package has repeated ownership")
			}
			preparation.AdmittedPackages = append(preparation.AdmittedPackages, relative)
			pattern := "."
			if relative != module {
				pattern = "./" + strings.TrimPrefix(relative, module+"/")
			}
			preparation.Artifacts = append(preparation.Artifacts, ordinaryArtifact{Owner: relative, Package: pkg.ImportPath, Directory: module, Patterns: []string{pattern}})
		}
	}
	sort.Strings(preparation.AdmittedPackages)
	return preparation, nil
}

func resolveOrdinaryFocusSet(artifacts []ordinaryArtifact, requested ordinaryFocus) ([]ordinaryFocus, error) {
	if err := validateRequestedTests(requested.Tests); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	owners := map[string][]int{}
	var admitted []int
	for index, artifact := range artifacts {
		if artifact.Owner == "" || artifact.Package == "" || seen[artifact.Owner] {
			return nil, errors.New("ordinary artifact inventory has invalid ownership")
		}
		seen[artifact.Owner] = true
		if !validOrdinaryArtifactProfile(artifact) {
			return nil, errors.New("ordinary artifact has inconsistent profile classification")
		}
		if _, err := newTestEventState(map[string][]string{artifact.Package: artifact.Tests}, maximumOrdinaryTests, validOrdinaryName, ordinaryArtifactEmptyPackages(artifact)); err != nil {
			return nil, err
		}
		if requested.PackagePath != "" && artifact.Owner != requested.PackagePath {
			continue
		}
		admitted = append(admitted, index)
		for _, name := range artifact.Tests {
			owners[name] = append(owners[name], index)
		}
	}
	selected := map[int][]string{}
	if len(requested.Tests) == 0 {
		if requested.PackagePath == "" || len(admitted) != 1 {
			return nil, errors.New("ordinary package must resolve exactly one admitted artifact")
		}
		selected[admitted[0]] = nil
	}
	for _, request := range requested.Tests {
		name, _, _ := strings.Cut(request, "/")
		matches := owners[name]
		if len(matches) != 1 {
			return nil, errors.New("ordinary test must resolve exactly one admitted artifact")
		}
		index := matches[0]
		artifact := artifacts[index]
		if ordinaryRunnerHelperProofs[artifact.Package+"\x00"+name] != "" || ordinaryProviderHelperProofs[artifact.Package+"\x00"+name] != "" {
			return nil, errors.New("ordinary helper cannot run independently; select its invoking parent")
		}
		selected[index] = append(selected[index], request)
	}
	var selections []ordinaryFocus
	for index, artifact := range artifacts {
		if tests, found := selected[index]; found {
			selections = append(selections, ordinaryFocus{PackagePath: requested.PackagePath, Tests: slices.Clone(tests), Package: artifact.Package, Artifact: artifact.Owner})
		}
	}
	return selections, nil
}

// Planning and running have one preparation and narrowing path. Unit focus
// inventories only its exact package after validating all configured membership;
// runner focus inventories every possible owner before partitioning paths.
func prepareOrdinaryFocus(ctx context.Context, root, bootstrap, profile string, step *resolvedWorkflowStep, evidence *ordinaryStepEvidence, output io.Writer) error {
	return runOrdinarySelection(ctx, root, bootstrap, profile, step, evidence, output)
}

func runOrdinarySelection(ctx context.Context, root, bootstrap, profile string, step *resolvedWorkflowStep, evidence *ordinaryStepEvidence, output io.Writer) (err error) {
	ctx, artifactOwner := withInvocationArtifacts(ctx)
	defer func() {
		tail, cancel := finalizationContext(ctx)
		defer cancel()
		err = errors.Join(err, artifactOwner.close(tail, toolCommandsJoined(err)))
	}()
	current, err := newCurrentDirectory("enkv-ordinary-selection-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, current.remove(toolCommandsJoined(err))) }()
	if err := os.Mkdir(filepath.Join(current.path, "private"), 0700); err != nil {
		return err
	}
	ctx = context.WithValue(ctx, workflowScratchContextKey{}, current)
	preparation := ordinaryStepEvidence{Diagnostics: evidence.Diagnostics}
	group, prepareErr := prepareOrdinaryGroup(ctx, root, bootstrap, profile, current.path, *step, &preparation, output)
	evidence.Diagnostics = preparation.Diagnostics
	if group != nil {
		defer func() { group.joined = group.joined && toolCommandsJoined(err); err = errors.Join(err, group.close()) }()
	}
	if prepareErr != nil && (group == nil || !containedCheckFailure(ctx, prepareErr)) {
		return prepareErr
	}
	*step = group.step
	return errors.Join(prepareErr, group.execute(ctx, root, profile, evidence, output))
}

// The caller owns the preparation directory and its last consumer.
func prepareOrdinaryFocusSelection(ctx context.Context, root, bootstrap, profile, directory string, source records.Source, step *resolvedWorkflowStep, evidence *ordinaryStepEvidence, output io.Writer) ([]preparedOrdinaryArtifact, error) {
	binding, err := prepareBindingOwned(nil, ctx, root, false)
	if err != nil {
		return nil, err
	}
	if evidence != nil {
		evidence.Toolchain = binding.toolchain
	}
	preparation := ordinaryPreparation{Source: source, Toolchain: binding.toolchain, ExecutionProof: "pending; the requested test node must start and pass", ParentPreparation: "Parent setup and suffix assertions execute. Dynamic child existence is checked during run."}
	switch step.Kind {
	case "unit":
		membership, membershipErr := resolveOrdinaryUnitPackage(ctx, root, step.Packages, step.OrdinaryFocus.PackagePath)
		if membershipErr != nil {
			return nil, membershipErr
		}
		preparation.AdmittedPackages, preparation.Artifacts = membership.AdmittedPackages, membership.Artifacts
		overlay, overlayErr := prepareCryptoOverlay(ctx, root, directory)
		if overlayErr != nil {
			return nil, overlayErr
		}
		artifact := &preparation.Artifacts[0]
		artifact.BuildFlags = moduleTestFlags(root, artifact.Directory, overlay)
	case "runner-tests":
		flags := []string{"-mod=readonly", "-modfile=" + assemblyModfile(root, "hermetic", "memory"), "-overlay=" + bootstrap}
		for _, name := range []string{"testmain", "testrecords", "testcatalog"} {
			owner := "tests/shared/" + map[string]string{"testmain": "runner", "testrecords": "records", "testcatalog": "catalog"}[name]
			preparation.Artifacts = append(preparation.Artifacts, ordinaryArtifact{Owner: owner, Package: "enkv.sh/core/internal/" + name, Directory: "core", Patterns: []string{"./internal/" + name}, BuildFlags: flags, TestFlags: []string{"-timeout=15m"}})
		}
		preparation.Artifacts = append(preparation.Artifacts, ordinaryArtifact{Owner: "tests/scripts/bootstrap.go+bootstrap_test.go", Package: "command-line-arguments", Directory: "core", Patterns: []string{"../tests/scripts/bootstrap.go", "../tests/scripts/bootstrap_test.go"}, BuildFlags: []string{"-mod=readonly"}, TestFlags: []string{"-timeout=15m"}})
	default:
		return nil, errors.New("ordinary focus does not apply to this step")
	}
	var diagnostics *checkDiagnostics
	if evidence != nil {
		diagnostics = evidence.Diagnostics
	}
	var candidates []preparedOrdinaryArtifact
	for i := range preparation.Artifacts {
		artifact := &preparation.Artifacts[i]
		artifact.TestFlags = ordinaryCapacityFlags(ctx, artifact.TestFlags)
		for _, buildFlag := range artifact.BuildFlags {
			if strings.HasPrefix(buildFlag, "-overlay=") {
				if step.Kind == "unit" {
					sources := []string{"tests/crypto/*_test.go"}
					for _, overlay := range records.TestAdmissionOverlays() {
						sources = append(sources, overlay.Source)
					}
					artifact.BuildInputs = append(artifact.BuildInputs, strings.Join(sources, "+")+" overlay")
				} else {
					artifact.BuildInputs = append(artifact.BuildInputs, "tests/shared/runner+tests/shared/records+tests/shared/catalog launcher overlay")
				}
			} else if path, found := strings.CutPrefix(buildFlag, "-modfile="); found {
				relative, relErr := filepath.Rel(root, path)
				if relErr != nil || strings.HasPrefix(relative, "..") {
					return nil, errors.New("ordinary module input is outside the checkout")
				}
				artifact.BuildInputs = append(artifact.BuildInputs, "-modfile="+filepath.ToSlash(relative))
			} else {
				artifact.BuildInputs = append(artifact.BuildInputs, buildFlag)
			}
		}
		if err := checkProgress(output, "preparation", artifact.Owner); err != nil {
			return nil, err
		}
		packages, listErr := listOrdinaryPackages(ctx, root, artifact.Directory, artifact.BuildFlags, artifact.Patterns, diagnostics)
		if listErr != nil {
			return nil, listErr
		}
		if len(packages) != 1 || packages[0].ImportPath != artifact.Package || !filepath.IsAbs(packages[0].Dir) {
			return nil, errors.New("ordinary focused package placement changed")
		}
		candidate := preparedOrdinaryArtifact{}
		candidate.ordinaryArtifact = *artifact
		candidate.cwd = packages[0].Dir
		candidate.binary = filepath.Join(directory, fmt.Sprintf("inventory-%d.test", i))
		flags := append(slices.Clone(artifact.TestFlags), "-o", candidate.binary)
		want, retained, inventoryErr := discoverListedOrdinaryInventory(ctx, root, artifact.Directory, artifact.BuildFlags, artifact.Patterns, "", packages, diagnostics, flags...)
		if inventoryErr != nil {
			return nil, inventoryErr
		}
		want, retained, inventoryErr = selectOrdinaryProfile(want, retained, profile)
		if inventoryErr != nil {
			return nil, inventoryErr
		}
		if len(want) != 1 {
			return nil, errors.New("ordinary focused artifact has multiple package owners")
		}
		names, found := want[artifact.Package]
		if !found {
			return nil, errors.New("ordinary focused artifact package identity changed")
		}
		artifact.Profile = profile
		artifact.Tests = slices.Clone(names)
		artifact.CompiledTests = slices.Clone(retained[0].Inventory)
		artifact.Classifications = slices.Clone(retained[0].Classifications)
		candidate.ordinaryArtifact = *artifact
		compiled, buildErr := prepareOrdinaryPackage(ctx, root, artifact.Directory, artifact.BuildFlags, artifact.Patterns, packages[0], directory, diagnostics)
		if buildErr != nil {
			return nil, buildErr
		}
		candidate.binary, candidate.binaryHash = compiled.binary, compiled.hash
		candidates = append(candidates, candidate)
		if step.Kind == "runner-tests" {
			preparation.AdmittedPackages = append(preparation.AdmittedPackages, artifact.Owner)
		}
	}
	selections, err := resolveOrdinaryFocusSet(preparation.Artifacts, *step.OrdinaryFocus)
	if err != nil {
		return nil, err
	}
	selectedOwners := map[string][]string{}
	var selectedArtifacts []preparedOrdinaryArtifact
	step.OrdinarySelection = nil
	for _, focus := range selections {
		index := slices.IndexFunc(candidates, func(candidate preparedOrdinaryArtifact) bool { return candidate.Owner == focus.Artifact })
		if index < 0 {
			return nil, errors.New("ordinary focused inventory artifact missing")
		}
		selected := candidates[index]
		names := ordinaryFocusedRoots(selected.ordinaryArtifact, focus)
		selected.Tests, selected.requests = slices.Clone(names), slices.Clone(focus.Tests)
		selectedArtifacts = append(selectedArtifacts, selected)
		selectedOwners[focus.Artifact] = names
		step.OrdinarySelection = append(step.OrdinarySelection, ordinaryExecution{Artifact: focus.Artifact, Package: focus.Package, Tests: slices.Clone(names)})
	}
	for _, admitted := range preparation.AdmittedPackages {
		if _, selected := selectedOwners[admitted]; !selected {
			preparation.NotSelectedPackages = append(preparation.NotSelectedPackages, admitted)
		}
	}
	for _, item := range preparation.Artifacts {
		names := slices.DeleteFunc(slices.Clone(item.CompiledTests), func(name string) bool { return slices.Contains(selectedOwners[item.Owner], name) })
		if len(names) != 0 {
			preparation.NotSelected = append(preparation.NotSelected, ordinaryPackage{Name: item.Package, Tests: names})
		}
	}
	step.OrdinaryFocus.Package, step.OrdinaryFocus.Artifact = "", ""
	if len(selections) == 1 {
		step.OrdinaryFocus.Package, step.OrdinaryFocus.Artifact = selections[0].Package, selections[0].Artifact
	}
	step.OrdinaryFocus.Tests = slices.Clone(step.OrdinaryFocus.Tests)
	if step.OrdinaryPreparation == nil {
		step.OrdinaryPreparation = &ordinaryPreparation{}
	}
	*step.OrdinaryPreparation = preparation
	return selectedArtifacts, nil
}

func validateOrdinaryFocusedEvents(body []byte, want map[string][]string, helperProofs map[string]string, focus ordinaryFocus) ([]ordinaryTest, error) {
	results, err := validateOrdinaryEvents(body, want, helperProofs)
	if err != nil {
		return results, err
	}
	if len(focus.Tests) == 0 {
		return results, nil
	}
	if !ordinaryFocusedTerminals(results, focus) {
		return results, errors.New("ordinary focus lacks exact requested pass or ran outside the requested subtree")
	}
	return results, nil
}

func ordinaryFocusedTerminals(results []ordinaryTest, focus ordinaryFocus) bool {
	names := make([]string, 0, len(results))
	for _, result := range results {
		if result.Package != focus.Package || result.Outcome != "pass" {
			return false
		}
		names = append(names, result.Name)
	}
	return validRequestedTestNames(focus.Tests, names)
}

func ordinaryFocusedRoots(artifact ordinaryArtifact, focus ordinaryFocus) []string {
	if len(focus.Tests) == 0 {
		return slices.Clone(artifact.Tests)
	}
	return requestedTestRoots(focus.Tests)
}

func validOrdinaryFocusedEvidence(evidence ordinaryStepEvidence) bool {
	if evidence.Focus == nil || evidence.Preparation == nil || len(evidence.Execution) == 0 || !evidence.SelectedComplete || evidence.Complete || (evidence.Race == nil || !validRaceOptions(*evidence.Race, evidence.RaceOptions)) {
		return false
	}
	if len(evidence.Focus.Tests) == 0 {
		for _, pkg := range evidence.Packages {
			if hasUnavailableClassifications(pkg.Classifications) {
				return false
			}
		}
	}
	selections, err := resolveOrdinaryFocusSet(evidence.Preparation.Artifacts, *evidence.Focus)
	if err != nil || len(selections) != len(evidence.Execution) || len(selections) != len(evidence.Packages) {
		return false
	}
	resolvedPackage, resolvedArtifact := "", ""
	if len(selections) == 1 {
		resolvedPackage, resolvedArtifact = selections[0].Package, selections[0].Artifact
	}
	if evidence.Focus.Package != resolvedPackage || evidence.Focus.Artifact != resolvedArtifact {
		return false
	}
	selectedOwners, selectedPackages := map[string][]string{}, map[string]bool{}
	for index, focus := range selections {
		artifactIndex := slices.IndexFunc(evidence.Preparation.Artifacts, func(artifact ordinaryArtifact) bool { return artifact.Owner == focus.Artifact })
		artifact := evidence.Preparation.Artifacts[artifactIndex]
		if artifact.Profile != evidence.Profile || selectedPackages[artifact.Package] {
			return false
		}
		selectedPackages[artifact.Package] = true
		names := ordinaryFocusedRoots(artifact, focus)
		selectedOwners[artifact.Owner] = names
		execution, pkg := evidence.Execution[index], evidence.Packages[index]
		if execution.Artifact != artifact.Owner || execution.Package != artifact.Package || !slices.Equal(execution.Tests, names) || pkg.Name != artifact.Package || !slices.Equal(pkg.Tests, names) || !slices.Equal(pkg.Inventory, artifact.CompiledTests) || !sameTestClassifications(pkg.Classifications, artifact.Classifications) {
			return false
		}
		omitted := slices.DeleteFunc(slices.Clone(artifact.CompiledTests), func(name string) bool { return slices.Contains(names, name) })
		if !slices.Equal(omitted, pkg.NotSelected) {
			return false
		}
		var results []ordinaryTest
		for _, result := range evidence.Tests {
			if result.Package == artifact.Package {
				results = append(results, result)
			}
		}
		if len(focus.Tests) != 0 {
			if !ordinaryFocusedTerminals(results, focus) {
				return false
			}
			continue
		}
		outcomes := map[string]string{}
		for _, test := range results {
			if outcomes[test.Name] != "" {
				return false
			}
			top, _, _ := strings.Cut(test.Name, "/")
			if !slices.Contains(names, top) {
				return false
			}
			outcomes[test.Name] = test.Outcome
		}
		for name, outcome := range outcomes {
			if outcome == "pass" {
				continue
			}
			proof := ordinaryProviderHelperProofs[artifact.Package+"\x00"+name]
			if proof == "" {
				proof = ordinaryRunnerHelperProofs[artifact.Package+"\x00"+name]
			}
			if outcome != "skip" || proof == "" || outcomes[proof] != "pass" {
				return false
			}
		}
		for _, name := range names {
			if outcomes[name] != "pass" && outcomes[name] != "skip" {
				return false
			}
		}
		if len(names) == 0 && !ordinaryArtifactEmptyPackages(artifact)[artifact.Package] {
			return false
		}
	}
	for _, result := range evidence.Tests {
		if !selectedPackages[result.Package] {
			return false
		}
	}
	var allOmitted []ordinaryPackage
	for _, item := range evidence.Preparation.Artifacts {
		other := slices.DeleteFunc(slices.Clone(item.CompiledTests), func(name string) bool { return slices.Contains(selectedOwners[item.Owner], name) })
		if len(other) != 0 {
			allOmitted = append(allOmitted, ordinaryPackage{Name: item.Package, Tests: other})
		}
	}
	omittedOwners := slices.DeleteFunc(slices.Clone(evidence.Preparation.AdmittedPackages), func(owner string) bool { _, selected := selectedOwners[owner]; return selected })
	return sameOrdinaryOmissions(allOmitted, evidence.Preparation.NotSelected) && slices.Equal(omittedOwners, evidence.Preparation.NotSelectedPackages)
}

func completeOrdinaryEvidence(evidence ordinaryStepEvidence) bool {
	for _, pkg := range evidence.Packages {
		if hasUnavailableClassifications(pkg.Classifications) {
			return false
		}
	}
	return evidence.Complete && evidence.Race != nil && validRaceOptions(*evidence.Race, evidence.RaceOptions) && evidence.Focus == nil && evidence.Preparation == nil && evidence.Execution == nil && !evidence.SelectedComplete && validOrdinaryProfileEvidence(evidence)
}

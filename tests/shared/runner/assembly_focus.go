package main

import (
	"context"
	"errors"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	records "enkv.sh/core/internal/testrecords"
)

type assemblyFocus struct {
	Requested string `json:"requested"`
	Provider  string `json:"provider"`
	Package   string `json:"package"`
	Owner     string `json:"owner"`
}

type assemblyPreparation struct {
	CompiledInventory    []string             `json:"compiled_inventory"`
	Classifications      []testClassification `json:"classifications"`
	AssemblySources      map[string]string    `json:"assembly_sources"`
	AssemblyNeutral      *bool                `json:"assembly_neutral"`
	Source               records.Source       `json:"source"`
	Toolchain            string               `json:"toolchain"`
	BinarySHA256         string               `json:"binary_sha256"`
	OverlaySHA256        string               `json:"overlay_sha256"`
	FailureSourcesSHA256 string               `json:"failure_sources_sha256"`
	Inventory            []string             `json:"inventory"`
	NotSelected          []string             `json:"not_selected"`
	Selection            string               `json:"selection"`
	ExecutionProof       string               `json:"execution_proof"`
	ParentPreparation    string               `json:"parent_preparation"`
}

func assemblyFocusOwnerAllowed(name string) bool {
	switch name {
	case "TestFreshProcessChild", "TestOperatorCaptureCrashChild", "TestOperatorCaptureReadOnlyChild":
		return false
	default:
		return true
	}
}

func resolveAssemblyFocus(names []string, sources map[string]string, classifications []testClassification, provider, profile string, neutral bool, request string) ([]string, *assemblyFocus, error) {
	if provider != "aws" && provider != "gcp" {
		return nil, nil, errors.New("assembly focus requires one known provider")
	}
	admitted, err := liveAssemblyCheckNames(names, sources, classifications, profile, neutral)
	if err != nil || request == "" {
		return admitted, nil, err
	}
	if !validComponentName(request) {
		return nil, nil, errors.New("assembly focus requires a literal test or subtest name")
	}
	owner, _, _ := strings.Cut(request, "/")
	if !slices.Contains(admitted, owner) || !assemblyFocusOwnerAllowed(owner) {
		return nil, nil, errors.New("assembly focus requires an admitted controlled test; helpers and coordinator entrypoints cannot run independently")
	}
	source := sources[owner]
	if !strings.HasPrefix(source, "tests/live/shared/") && !strings.HasPrefix(source, "tests/live/runner/") && !strings.HasPrefix(source, "tests/live/providers/"+provider+"/") {
		return nil, nil, errors.New("assembly focus test belongs to another provider or execution owner")
	}
	return admitted, &assemblyFocus{Requested: request, Provider: provider, Package: componentPackage, Owner: owner}, nil
}

// Both plan and run discover the complete controlled inventory from the bound binary.
func prepareAssemblySelection(ctx context.Context, root string, value assembly, profile string, neutral bool, request string, source records.Source, toolchain string, diagnostics *checkDiagnostics, evidence *checkEvidence) ([]string, *assemblyFocus, *assemblyPreparation, error) {
	if diagnostics != nil && !diagnostics.hasPlan() {
		future := inventoryPreparationCommands("assembly-inventory")
		if e := diagnostics.reserveCommands(future); e != nil {
			return nil, nil, nil, e
		}
		defer diagnostics.cancelReservations()
	}

	environment := append(workerEnvironment(""), failureSourcesEnvironment(value.FailureSources)...)
	inventory, err := prepareCompiledInventory(ctx, root, value, environment, "assembly-inventory", diagnostics)
	if err != nil {
		return nil, nil, nil, err
	}
	names := inventory.names
	sources, err := liveAssemblyTestSources(inventory.sources, value.Closure.Provider)
	if err != nil {
		return nil, nil, nil, err
	}
	classifications := map[string][]testClassification{componentPackage: inventory.classifications}
	if evidence != nil {
		evidence.CompiledInventory = slices.Clone(names)
		evidence.Classifications = classifications[componentPackage]
		evidence.AssemblySources = sources
		evidence.AssemblyNeutral = &neutral
	}
	admitted, focus, err := resolveAssemblyFocus(names, sources, classifications[componentPackage], value.Closure.Provider, profile, neutral, request)
	if evidence != nil && err == nil {
		executed := admitted
		if focus != nil {
			executed = []string{focus.Owner}
		}
		evidence.NotSelected = slices.DeleteFunc(slices.Clone(names), func(name string) bool { return slices.Contains(executed, name) })
	}
	if err != nil || focus == nil {
		return admitted, focus, nil, err
	}
	omitted := slices.DeleteFunc(slices.Clone(names), func(name string) bool { return name == focus.Owner })
	preparation := &assemblyPreparation{
		Source: source, Toolchain: toolchain, BinarySHA256: value.Closure.BinarySHA256,
		OverlaySHA256: value.Closure.OverlaySHA256, FailureSourcesSHA256: value.Closure.FailureSourcesSHA256,
		CompiledInventory: names, Classifications: classifications[componentPackage], AssemblySources: sources, AssemblyNeutral: &neutral,
		Inventory: admitted, NotSelected: omitted, Selection: literalTestSelection(request),
		ExecutionProof:    "pending; the exact requested node must start and pass",
		ParentPreparation: "Required parent setup and selected subtree assertions execute; dynamic child existence is verified only during run.",
	}
	return admitted, focus, preparation, nil
}

func completeFocusedAssemblyEvidence(checks checkEvidence, provider string) bool {
	focus, preparation := checks.AssemblyFocus, checks.AssemblyPreparation
	if focus == nil || preparation == nil || checks.Focus != nil || checks.Outcome != "passed" || !checks.TestsComplete || !validRaceOptions(checks.Race, checks.RaceOptions) ||
		(provider != "gcp" && provider != "aws") || focus.Provider != provider || focus.Package != componentPackage || !validComponentName(focus.Requested) || !assemblyFocusOwnerAllowed(focus.Owner) {
		return false
	}
	if checks.AssemblyNeutral == nil || preparation.AssemblyNeutral == nil || *checks.AssemblyNeutral != *preparation.AssemblyNeutral || !slices.Equal(checks.CompiledInventory, preparation.CompiledInventory) || !sameTestClassifications(checks.Classifications, preparation.Classifications) {
		return false
	}
	owned, ownershipErr := liveAssemblyTestSources(checks.AssemblySources, provider)
	if ownershipErr != nil || !maps.Equal(owned, checks.AssemblySources) || !maps.Equal(checks.AssemblySources, preparation.AssemblySources) {
		return false
	}
	admitted, classificationErr := liveAssemblyCheckNames(checks.CompiledInventory, checks.AssemblySources, checks.Classifications, checks.Profile, *checks.AssemblyNeutral)
	if classificationErr != nil || !slices.Equal(admitted, checks.Inventory) {
		return false
	}
	owner, _, _ := strings.Cut(focus.Requested, "/")
	if owner != focus.Owner || !slices.Contains(checks.Inventory, owner) || !slices.Equal(checks.Inventory, preparation.Inventory) ||
		!hexString(preparation.BinarySHA256, sha256HexLength) || !hexString(preparation.OverlaySHA256, sha256HexLength) || !hexString(preparation.FailureSourcesSHA256, sha256HexLength) || preparation.Toolchain == "" || !validSource(preparation.Source) {
		return false
	}
	selection, err := componentSelection(checks.Inventory)
	if err != nil || selection == "" || checks.Selection != literalTestSelection(focus.Requested) || preparation.Selection != checks.Selection {
		return false
	}
	omitted := slices.DeleteFunc(slices.Clone(checks.CompiledInventory), func(name string) bool { return name == owner })
	return slices.Equal(omitted, checks.NotSelected) && slices.Equal(omitted, preparation.NotSelected) &&
		componentEvidenceMatchesInventory([]string{owner}, checks.Tests) && exactFocusedTestEvidence(focus.Requested, checks.Tests, nil)
}

// This is the same compiled selection used by both preparation and controlled checks.
type preparedProviderChecks struct {
	profile     string
	neutral     bool
	requested   string
	selected    []string
	focus       *assemblyFocus
	preparation *assemblyPreparation
	evidence    checkEvidence
	converter   preparedTestEventConverter
}

func providerPreparationCommands(value assembly) ([]checkCommandFacts, error) {
	future := inventoryPreparationCommands("assembly-inventory")
	if value.providerSelection == nil && value.converter.binary == "" {
		future = append(future, preparationReservationFact("test2json", true))
	}
	return future, nil
}

func prepareProviderChecks(initial *checkDiagnostics, ctx context.Context, root string, value assembly, profile string, neutral bool, requested string, source records.Source, toolchain string) (prepared *preparedProviderChecks, diagnostics *checkDiagnostics, err error) {
	diagnostics = initial
	if diagnostics == nil {
		diagnostics = &checkDiagnostics{Preparation: "pending"}
	}
	if !diagnostics.hasPlan() {
		future, e := providerPreparationCommands(value)
		if e != nil {
			return nil, diagnostics, e
		}
		if e := diagnostics.reserveCommands(future); e != nil {
			return nil, diagnostics, e
		}
		defer diagnostics.cancelReservations()
	}
	defer func() {
		if err != nil {
			diagnostics.Preparation = "failed"
		}
	}()
	if err := checkAssemblyRace(ctx, value); err != nil {
		return nil, diagnostics, err
	}
	var evidence checkEvidence
	selected, focus, preparation, err := prepareAssemblySelection(ctx, root, value, profile, neutral, requested, source, toolchain, diagnostics, &evidence)
	if err != nil {
		return nil, diagnostics, err
	}
	if err := checkAssemblyRace(ctx, value); err != nil {
		return nil, diagnostics, err
	}
	var converter preparedTestEventConverter
	if value.providerSelection != nil {
		converter = value.providerSelection.converter
	} else if value.converter.binary != "" {
		converter = value.converter
	} else {
		if err := diagnostics.consumeCommands([]checkCommandFacts{preparationReservationFact("test2json", true)}); err != nil {
			return nil, diagnostics, err
		}
		var facts checkCommandFacts
		converter, facts, err = prepareTestEventConverter(ctx, root, filepath.Dir(value.Binary))
		if facts.Process != "" {
			err = errors.Join(err, diagnostics.append(facts))
		}
		if err != nil {
			return nil, diagnostics, err
		}
	}
	diagnostics.Preparation = "passed"
	evidence.Diagnostics = diagnostics
	return &preparedProviderChecks{profile: profile, neutral: neutral, requested: requested, selected: slices.Clone(selected), focus: focus, preparation: preparation, evidence: evidence, converter: converter}, diagnostics, nil
}

func samePreparedProviderChecks(left, right *preparedProviderChecks) bool {
	return left != nil && right != nil && left.profile == right.profile && left.neutral == right.neutral && left.requested == right.requested &&
		left.converter.sha256 == right.converter.sha256 &&
		slices.Equal(left.selected, right.selected) && slices.Equal(left.evidence.CompiledInventory, right.evidence.CompiledInventory) &&
		sameTestClassifications(left.evidence.Classifications, right.evidence.Classifications) && maps.Equal(left.evidence.AssemblySources, right.evidence.AssemblySources) &&
		slices.Equal(left.evidence.NotSelected, right.evidence.NotSelected) && (left.focus == nil && right.focus == nil || left.focus != nil && right.focus != nil && *left.focus == *right.focus)
}

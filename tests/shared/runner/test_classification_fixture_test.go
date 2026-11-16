package main

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

// These are classifications of empty controlled fixture bodies, not a profile
// membership registry. Their deliberate true values exercise omitted proofs.
func componentProfileFixtureClassifications(names []string) []testClassification {
	fullOnly := []string{
		"TestSuccessionJointMaximumMemory", "TestGeneratedRecordPrefixPerformance",
		"TestGeneratedMaximumSelectedSetFitsAccessReplacementOverlap",
		"TestGeneratedPurpose3CleanupAtJointMemberAndGenerationMaximum",
		"TestGeneratedMaximumDeclarationReservationMemory", "TestInventoryRepresentativeScenarios",
	}
	for _, name := range ordinaryMemoryTestInventory() {
		if name != "TestOrdinaryOutputMemoryNativeArtifact" {
			fullOnly = append(fullOnly, name)
		}
	}
	var classifications []testClassification
	for _, name := range names {
		value := slices.Contains(fullOnly, name)
		classifications = append(classifications, testClassification{Name: name, FullOnly: &value})
	}
	return classifications
}

func componentFixtureClassifications(names []string) []testClassification {
	var classifications []testClassification
	for _, name := range names {
		value := false
		classifications = append(classifications, testClassification{Name: name, FullOnly: &value})
	}
	return classifications
}

func componentMetadataBuildFlags(t *testing.T, root string, classifications []testClassification) []string {
	t.Helper()
	directory := filepath.Join(root, "core")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "go.mod"), []byte("module "+componentPackage+"\n\ngo 1.27.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var body strings.Builder
	body.WriteString("package core\nimport \"testing\"\n")
	for _, classification := range classifications {
		fmt.Fprintf(&body, "// full_only: %t\n// exclusive: %t\nfunc %s(t *testing.T) {}\n", *classification.FullOnly, classification.Exclusive, classification.Name)
	}
	if err := os.WriteFile(filepath.Join(directory, "classification_test.go"), []byte(body.String()), 0600); err != nil {
		t.Fatal(err)
	}
	return []string{"-mod=readonly"}
}

func assemblyMetadataFixtureSources(t *testing.T, root, provider string, flags []string) (map[string]string, error) {
	t.Helper()
	var overlay struct{ Replace map[string]string }
	for _, flag := range flags {
		if path, found := strings.CutPrefix(flag, "-overlay="); found {
			if err := records.ReadJSON(path, &overlay); err != nil {
				return nil, err
			}
		}
	}
	var names []string
	var files []string
	for target, source := range overlay.Replace {
		if filepath.Dir(target) != filepath.Join(root, "core") || !strings.HasSuffix(target, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), source, nil, parser.ParseComments)
		if err != nil {
			return nil, err
		}
		files = append(files, filepath.Base(target))
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if ok && function.Recv == nil && validOrdinaryName(function.Name.Name) && !slices.Contains(names, function.Name.Name) {
				names = append(names, function.Name.Name)
			}
		}
	}
	_, active, err := classifyTestPackages(root, []listedOrdinaryPackage{{ImportPath: componentPackage, Dir: filepath.Join(root, "core"), TestGoFiles: files}}, flags, map[string][]string{componentPackage: names})
	if err != nil {
		return nil, err
	}
	return liveAssemblyTestSources(active[componentPackage], provider)
}

func setOrdinaryArtifactFixtureMetadata(artifact *ordinaryArtifact) {
	artifact.Profile = "full"
	artifact.CompiledTests = slices.Clone(artifact.Tests)
	artifact.Classifications = componentFixtureClassifications(artifact.Tests)
}

func setPreparedOrdinaryFixtureMetadata(t *testing.T, artifact *preparedOrdinaryArtifact) {
	t.Helper()
	setOrdinaryArtifactFixtureMetadata(&artifact.ordinaryArtifact)
	digest, err := assemblyFileSHA256(artifact.binary)
	if err != nil {
		t.Fatal(err)
	}
	artifact.binaryHash = digest
}

func setFocusedAssemblyFixtureMetadata(checks *checkEvidence) {
	checks.CompiledInventory = slices.Clone(checks.Inventory)
	checks.Classifications = componentFixtureClassifications(checks.CompiledInventory)
	checks.AssemblySources = map[string]string{}
	for _, name := range checks.CompiledInventory {
		checks.AssemblySources[name] = "tests/live/providers/" + checks.AssemblyFocus.Provider + "/fixture_test.go"
	}
	neutral := false
	checks.AssemblyNeutral = &neutral
	checks.AssemblyPreparation.CompiledInventory = slices.Clone(checks.CompiledInventory)
	checks.AssemblyPreparation.Classifications = slices.Clone(checks.Classifications)
	checks.AssemblyPreparation.AssemblySources = checks.AssemblySources
	checks.AssemblyPreparation.AssemblyNeutral = &neutral
}

// Raw process fixtures supply the metadata that normal constructors capture.
func executeFixtureProfileComponentChecks(t *testing.T, initial *checkDiagnostics, ctx context.Context, root, binary string, converter preparedTestEventConverter, flags, environment []string, profile string, requested []string, parallelism int, output io.Writer, owner *assembly) (processResult, checkEvidence, *limitedOutput, *limitedOutput) {
	t.Helper()
	if owner == nil {
		owner = capturedComponentFixtureOwner(t, ctx, root, binary, converter, flags)
	}
	return executeProfileComponentChecks(initial, ctx, root, binary, converter, flags, environment, profile, requested, parallelism, output, owner)
}

func capturedComponentFixtureOwner(t *testing.T, ctx context.Context, root, binary string, converter preparedTestEventConverter, flags []string) *assembly {
	t.Helper()
	args := append([]string{"list"}, compilerBuildFlags(flags, raceEnabled(ctx))...)
	args = append(args, "-json=ImportPath,Dir,GoFiles,TestGoFiles,XTestGoFiles", ".")
	body, err := runGo(ctx, root, "core", args...)
	if err != nil {
		t.Fatal("capture raw fixture active files", err)
	}
	packages, err := decodeObjects[listedOrdinaryPackage](body)
	if err != nil {
		t.Fatal(err)
	}
	captured, err := captureTestDeclarations(root, packages, flags)
	if err != nil {
		t.Fatal(err)
	}
	wait := 0
	if raceEnabled(ctx) {
		wait = 1000
	}
	return &assembly{root: root, Binary: binary, converter: converter, buildFlags: flags, Closure: assemblyClosure{declarations: captured, Race: raceEnabled(ctx), RaceOptions: acceptedRaceOptions(raceEnabled(ctx)), RaceExitSleepMillis: wait}}
}

package main

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// full_only: false
func TestVerificationRejectsRetiredPlatformSelection(t *testing.T) {
	const retired = "linux-native"
	t.Run("verification-profile", func(t *testing.T) {
		if _, err := resolveVerificationProfile(retired); err == nil {
			t.Fatal("retired platform profile was accepted")
		}
	})
	t.Run("test-profile", func(t *testing.T) {
		names := []string{"TestSmall"}
		if _, _, err := selectClassifiedTests(names, componentFixtureClassifications(names), retired); err == nil {
			t.Fatal("retired test profile was accepted")
		}
	})
	t.Run("workflow-profile", func(t *testing.T) {
		root, _, _ := savedSelectionFixture(t)
		path := filepath.Join(root, "workflow.json")
		saveSelection(t, path, workflowFile{SchemaVersion: 1, Name: "retired", Profile: retired, Steps: []workflowStep{{ID: "components", Kind: "component-tests", Profile: "full"}}})
		if _, err := resolveWorkflow(t.Context(), root, workflowRequest{Path: path}); err == nil {
			t.Fatal("retired workflow profile was accepted")
		}
	})
	t.Run("local-preparation", func(t *testing.T) {
		_, err := prepareLocalWorkflow(t.Context(), t.TempDir(), "", retired, executionRequest{}, io.Discard)
		if err == nil || err.Error() != "unknown local verification workflow" {
			t.Fatal("retired preparation route reached saved workflow lookup", err)
		}
	})
	t.Run("local-run", func(t *testing.T) {
		_, err := runLocalWorkflow(t.Context(), t.TempDir(), "", retired, executionRequest{}, io.Discard)
		if err == nil || err.Error() != "unknown local verification workflow" {
			t.Fatal("retired run route reached saved workflow lookup", err)
		}
	})
	t.Run("supervisor-command", func(t *testing.T) {
		if _, err := preflightSupervisorExecution(t.TempDir(), []string{retired}); err == nil || err.Error() != testCommandUsage {
			t.Fatal("retired shortcut reached saved workflow lookup", err)
		}
	})
}

// full_only: false
func TestOrdinaryMemoryChecksUseActiveInventory(t *testing.T) {
	const native = "TestOrdinaryOutputMemoryNativeArtifact"
	const generated = "TestOutputConfigurationGeneratedMaximumTransitionMemory"
	for _, row := range []struct {
		name, profile             string
		memory, selected, omitted []string
		ordinary                  []string
		memoryGroups, exclusive   int
		big                       bool
	}{
		{"darwin-full", "full", ordinaryMemoryTestInventory(), append(ordinaryMemoryTestInventory(), maximumCapacityComponent, "TestControlPlain"), nil, []string{"TestControlPlain", maximumCapacityComponent}, 12, 12, true},
		{"darwin-dev", "dev", ordinaryMemoryTestInventory(), []string{native, "TestControlPlain"}, append(append([]string{}, ordinaryMemoryTestInventory()[:10]...), generated, maximumCapacityComponent), []string{"TestControlPlain"}, 1, 1, true},
		{"linux-full", "full", []string{generated}, []string{generated, maximumCapacityComponent, "TestControlPlain"}, nil, []string{"TestControlPlain", maximumCapacityComponent}, 1, 1, true},
		{"linux-dev", "dev", []string{generated}, []string{"TestControlPlain"}, []string{generated, maximumCapacityComponent}, []string{"TestControlPlain"}, 0, 0, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			inventory := append(slices.Clone(row.memory), maximumCapacityComponent, "TestControlPlain")
			before := slices.Clone(inventory)
			classifications := componentProfileFixtureClassifications(inventory)
			selected, omitted, groups, focus, err := resolveComponentGroups(inventory, classifications, row.profile, singleTestRequest(""), 4, componentEstimates)
			if err != nil || focus != nil || !slices.Equal(selected, row.selected) || !slices.Equal(omitted, row.omitted) || len(groups) != row.memoryGroups+len(row.ordinary) {
				t.Fatal("active inventory lost its exact profile partition", selected, omitted, groups, err)
			}
			seen := map[string]bool{}
			memoryGroups, exclusive, ordinaryGroups := 0, 0, 0
			for _, group := range groups {
				if group.Exclusive {
					exclusive++
					if len(group.Tests) != 1 || !slices.Contains(row.memory, group.Tests[0]) {
						t.Fatal("exclusive group changed its active memory owner", group)
					}
				} else {
					ordinaryGroups++
					if len(group.Tests) != 1 || !slices.Contains(row.ordinary, group.Tests[0]) {
						t.Fatal("normal profile roots lost their assigned worker", group)
					}
				}
				for _, owner := range group.Tests {
					if seen[owner] || !slices.Contains(row.selected, owner) {
						t.Fatal("active root was duplicated or excluded", owner, group)
					}
					seen[owner] = true
					if !slices.Contains(row.memory, owner) {
						continue
					}
					memoryGroups++
					if !group.Exclusive {
						t.Fatal("active memory owner lost exclusive placement", owner)
					}
					for _, request := range []string{owner, owner + "/literal[a]+b"} {
						_, _, focusedGroups, focused, err := resolveComponentGroups(inventory, classifications, row.profile, singleTestRequest(request), 4, componentEstimates)
						if err != nil || focused == nil || focused.Tests[0] != request || requestedTestRoots(focused.Tests)[0] != owner || componentFocusProcessClass(focused.Tests[0]) != "fresh-exclusive" || len(focusedGroups) != 1 || !focusedGroups[0].Exclusive || !slices.Equal(focusedGroups[0].Tests, []string{owner}) {
							t.Fatal("active memory focus lost its process owner", request, focused, focusedGroups, err)
						}
					}
				}
			}
			if memoryGroups != row.memoryGroups || exclusive != row.exclusive || ordinaryGroups != len(row.ordinary) || len(seen) != len(row.selected) || !slices.Equal(inventory, before) {
				t.Fatal("active placement cardinality or caller input changed", memoryGroups, exclusive, inventory)
			}
			big, err := selectedRootsBig(componentPackage, selected, classifications)
			if err != nil || big != row.big {
				t.Fatal("active selection changed resource admission", big, err)
			}
			if strings.HasPrefix(row.name, "linux-") {
				for _, request := range []string{native, native + "/child"} {
					if _, _, _, _, err := resolveComponentGroups(inventory, classifications, row.profile, singleTestRequest(request), 4, componentEstimates); err == nil || !strings.Contains(err.Error(), "not in the compiled inventory") {
						t.Fatal("inactive native root acquired a process owner", request, err)
					}
				}
			}
			if row.profile == "dev" {
				if _, _, _, _, err := resolveComponentGroups(inventory, classifications, row.profile, singleTestRequest(generated+"/child"), 4, componentEstimates); err == nil || !strings.Contains(err.Error(), "excluded from profile dev") {
					t.Fatal("excluded generated maximum focus was admitted", err)
				}
			}
			if _, _, _, _, err := resolveComponentGroups(inventory, classifications, row.profile, singleTestRequest("TestUnknown/child"), 4, componentEstimates); err == nil {
				t.Fatal("unknown active focus was admitted")
			}
			root := t.TempDir()
			binary := filepath.Join(root, "active-inventory")
			script := "#!/bin/sh\ncase \"$*\" in *-test.list=^Test*) printf '%s\\n' " + strings.Join(inventory, " ") + "; exit 0 ;; esac\nfor name in " + strings.Join(inventory, " ") + "; do\n case \"$*\" in " + componentShellSelectedName + ") printf '%s\\n' \"=== RUN   $name\" \"--- PASS: $name (0.01s)\" ;; esac\ndone\nprintf '%s\\n' PASS\n"
			if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			process, evidence, _, _ := executeFixtureProfileComponentChecks(t, nil, t.Context(), root, binary, testEventConverterFixture(t, root), componentMetadataBuildFlags(t, root, classifications), os.Environ(), row.profile, singleTestRequest(""), 1, nil, nil)
			if process.Status != "passed" || !process.Joined || !evidence.TestsComplete || !slices.Equal(evidence.Inventory, inventory) || !slices.Equal(evidence.NotSelected, row.omitted) || !componentEvidenceMatchesInventory(row.selected, evidence.Tests) || !completeComponentEvidence(evidence, "hermetic", "memory") {
				t.Fatal("active inventory did not retain exact successful terminals", process, evidence)
			}
		})
	}
}

// full_only: false
func TestTestClassificationMatchesActivePlatformFiles(t *testing.T) {
	const pkg = "example.org/platformclassification"
	for _, row := range []struct {
		name, goos, goarch, nativeFile string
		full, dev, omitted             []string
	}{
		{"darwin-arm64", "darwin", "arm64", "native_darwin_arm64_test.go", []string{"TestPortableSmall", "TestPortableMaximum", "TestDarwinSmall", "TestDarwinMaximum"}, []string{"TestPortableSmall", "TestDarwinSmall"}, []string{"TestPortableMaximum", "TestDarwinMaximum"}},
		{"linux-amd64", "linux", "amd64", "native_linux_amd64_test.go", []string{"TestPortableSmall", "TestPortableMaximum", "TestLinuxSmall", "TestLinuxMaximum"}, []string{"TestPortableSmall", "TestLinuxSmall"}, []string{"TestPortableMaximum", "TestLinuxMaximum"}},
	} {
		t.Run(row.name, func(t *testing.T) {
			directory := sourceFixtureRoot(t)
			writeLocalGoFixture(t, directory, "go.mod", "module "+pkg+"\n\ngo 1.27.0\n")
			for _, file := range []struct{ name, body string }{
				{"portable_test.go", "package sample\nimport \"testing\"\n// full_only: false\nfunc TestPortableSmall(t *testing.T) {}\n// full_only: true\nfunc TestPortableMaximum(t *testing.T) {}\n"},
				{"native_darwin_arm64_test.go", "package sample\nimport \"testing\"\n// full_only: false\nfunc TestDarwinSmall(t *testing.T) {}\n// full_only: true\nfunc TestDarwinMaximum(t *testing.T) {}\n"},
				{"native_linux_amd64_test.go", "package sample\nimport \"testing\"\n// full_only: false\nfunc TestLinuxSmall(t *testing.T) {}\n// full_only: true\nfunc TestLinuxMaximum(t *testing.T) {}\n"},
			} {
				writeLocalGoFixture(t, directory, file.name, file.body)
			}
			t.Setenv("GOOS", row.goos)
			t.Setenv("GOARCH", row.goarch)
			t.Setenv("CGO_ENABLED", "0")
			t.Setenv("GOPROXY", "off")
			t.Setenv("GOSUMDB", "off")
			// List active source only. No foreign binary is compiled or executed.
			body, err := runGo(t.Context(), directory, ".", "list", "-mod=readonly", "-json=ImportPath,Dir,GoFiles,TestGoFiles,XTestGoFiles", ".")
			if err != nil {
				t.Fatal("platform source listing failed", err)
			}
			packages, err := decodeObjects[listedOrdinaryPackage](body)
			if err != nil || len(packages) != 1 || packages[0].ImportPath != pkg || packages[0].Dir != directory || len(packages[0].GoFiles) != 0 || len(packages[0].XTestGoFiles) != 0 {
				t.Fatal("source listing changed package ownership", packages, err)
			}
			files := slices.Clone(packages[0].TestGoFiles)
			slices.Sort(files)
			if !slices.Equal(files, []string{row.nativeFile, "portable_test.go"}) {
				t.Fatal("platform source file set differs", files)
			}
			classifications, sources, err := classifyTestPackages(directory, packages, nil, map[string][]string{pkg: row.full})
			if err != nil || len(classifications) != 1 || len(classifications[pkg]) != 4 || len(sources) != 1 || len(sources[pkg]) != 4 {
				t.Fatal("active source roots differ", classifications, sources, err)
			}
			for _, name := range row.full {
				want := row.nativeFile
				if strings.HasPrefix(name, "TestPortable") {
					want = "portable_test.go"
				}
				if sources[pkg][name] != want {
					t.Fatal("active root lost its exact declaration source", name, sources[pkg][name], want)
				}
			}
			for _, profile := range []string{"full", "dev"} {
				selected, omitted, err := selectClassifiedTests(row.full, classifications[pkg], profile)
				want, excluded := row.full, []string(nil)
				if profile == "dev" {
					want, excluded = row.dev, row.omitted
				}
				if err != nil || !slices.Equal(selected, want) || !slices.Equal(omitted, excluded) {
					t.Fatal("platform changed profile membership", profile, selected, omitted, err)
				}
			}
			artifact := ordinaryArtifact{Owner: "core/sample", Package: pkg, Profile: "full", Tests: row.full, CompiledTests: row.full, Classifications: classifications[pkg]}
			inactive := "TestLinuxSmall"
			if row.goos == "linux" {
				inactive = "TestDarwinSmall"
			}
			for _, request := range []string{inactive, inactive + "/child"} {
				if _, _, err := resolveOneOrdinaryFocusFixture([]ordinaryArtifact{artifact}, ordinaryFocus{Tests: singleTestRequest(request)}); err == nil {
					t.Fatal("inactive source root acquired exact focus", request)
				}
			}
			if _, _, err := classifyTestPackages(directory, packages, nil, map[string][]string{pkg: append(slices.Clone(row.full), inactive)}); err == nil {
				t.Fatal("inactive declaration supplied compiled-root metadata")
			}
		})
	}
}

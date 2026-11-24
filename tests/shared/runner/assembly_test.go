package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

func overlayFixture(t *testing.T) (string, string, string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(sourceFixtureRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	publicSourceFixtureOwners(t, root)
	for _, directory := range []string{"core", "crypto", "compositions/generatorhost", "compositions/outputhost", "compositions/full", "providers/gcp/credentials", "tests/crypto", "tests/gcp", "tests/gcpcredentials", "tests/full", "tests/shared", "tests/hermetic", "tests/live/shared", "tests/live/runner", "tests/live/providers/aws", "tests/live/providers/gcp", "tests/live/custody", "crypto/testsupport/custody", "build"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "core/go.mod"), []byte("module "+componentPackage+"\n\ngo 1.27.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	writeLocalGoFixture(t, root, "tests/generatorhost/environment.go", "package generatorhost\n")
	if err := os.WriteFile(filepath.Join(root, "tests/crypto/admission.go"), []byte("package crypto\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tests/crypto/cloudflare_process_test.go"), []byte("package crypto\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tests/gcp/admission.go"), []byte("package gcp\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tests/gcpcredentials/admission.go"), []byte("package credentials\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tests/full/admission.go"), []byte("package compositionfull\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tests/shared/fixture_test.go", "tests/shared/ignored.go", "tests/hermetic/component_test.go", "tests/live/shared/assembly_test.go", "tests/live/runner/worker_test.go", "tests/live/providers/aws/provider_test.go", "tests/live/providers/gcp/provider_test.go"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("package core\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "tests/live/custody/output_box.go"), []byte("package custody\n"), 0600); err != nil {
		t.Fatal(err)
	}
	bootstrap := filepath.Join(root, "bootstrap.json")
	if err := os.WriteFile(bootstrap, []byte(`{"Replace":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	return root, bootstrap, filepath.Join(root, "build")
}

// full_only: false
func TestAssemblyOverlaySeparatesHermeticAndEachProvider(t *testing.T) {
	for _, spec := range []struct{ suite, provider string }{{"hermetic", "memory"}, {"live", "aws"}, {"live", "gcp"}} {
		root, bootstrap, build := overlayFixture(t)
		path, err := buildOverlay(root, spec.suite, spec.provider, bootstrap, build)
		if err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var overlay struct{ Replace map[string]string }
		if json.Unmarshal(body, &overlay) != nil {
			t.Fatal("overlay record invalid")
		}
		want := 7
		if spec.suite == "live" {
			want = 10
		}
		if len(overlay.Replace) != want {
			t.Fatalf("assembly source count: %d", len(overlay.Replace))
		}
		for target, source := range overlay.Replace {
			if target == filepath.Join(root, "crypto/testsupport/custody/zz_test_output_box.go") && source == filepath.Join(root, "tests/live/custody/output_box.go") {
				if spec.suite != "live" {
					t.Fatal("live custody reached hermetic assembly")
				}
				continue
			}
			if target == filepath.Join(root, "compositions/generatorhost/zz_test_environment.go") && source == filepath.Join(root, "tests/generatorhost/environment.go") {
				continue
			}
			if target == filepath.Join(root, "crypto/zz_test_admission.go") && source == filepath.Join(root, "tests/crypto/admission.go") {
				continue
			}
			if target == filepath.Join(root, "providers/gcp/zz_test_admission.go") && source == filepath.Join(root, "tests/gcp/admission.go") {
				continue
			}
			if target == filepath.Join(root, "providers/gcp/credentials/zz_test_admission.go") && source == filepath.Join(root, "tests/gcpcredentials/admission.go") {
				continue
			}
			if target == filepath.Join(root, "compositions/full/zz_test_admission.go") && source == filepath.Join(root, "tests/full/admission.go") {
				continue
			}
			if !strings.HasSuffix(target, "_test.go") || !strings.HasSuffix(source, "_test.go") {
				t.Fatal("non-test source reached the component assembly")
			}
			if filepath.Dir(target) != filepath.Join(root, "core") {
				t.Fatal("fixture escaped the private Core assembly")
			}
			if _, err := os.Lstat(target); !os.IsNotExist(err) {
				t.Fatal("overlay copied fixture source")
			}
			if spec.suite == "hermetic" && strings.Contains(source, "/tests/live/") || spec.suite == "live" && strings.Contains(source, "/tests/hermetic/") {
				t.Fatal("environment-specific fixtures crossed assemblies")
			}
			if spec.provider == "aws" && strings.Contains(source, "/providers/gcp/") || spec.provider == "gcp" && strings.Contains(source, "/providers/aws/") {
				t.Fatal("sibling provider reached the assembly")
			}
		}
	}
}

// full_only: false
func TestLiveAssemblyDiscoversUnprefixedOwnedTestFromOverlay(t *testing.T) {
	root, bootstrap, build := overlayFixture(t)
	for path, body := range map[string]string{
		"tests/live/runner/worker_test.go":           "package core\nimport \"testing\"\n// full_only: false\nfunc TestUnprefixedLiveOnlyCheck(t *testing.T) {}\n// full_only: false\nfunc TestLiveRun(t *testing.T) {}\n",
		"tests/live/runner/inventory_checks_test.go": "package core\nimport \"testing\"\n// full_only: false\nfunc TestLiveInventoryFreshProcess(t *testing.T) {}\n// full_only: false\nfunc TestInventoryOwnedOnce(t *testing.T) {}\n",
		"tests/shared/process_fixture_test.go":       "package core\nimport \"testing\"\n// full_only: false\nfunc TestFreshProcessChild(t *testing.T) {}\n// full_only: false\nfunc TestFreshProcessOther(t *testing.T) {}\n",
	} {
		if err := os.WriteFile(filepath.Join(root, path), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	overlay, err := buildOverlay(root, "live", "gcp", bootstrap, build)
	if err != nil {
		t.Fatal(err)
	}
	sources, err := assemblyMetadataFixtureSources(t, root, "gcp", []string{"-overlay=" + overlay})
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"TestUnprefixedLiveOnlyCheck", "TestLiveRun", "TestLiveInventoryFreshProcess", "TestInventoryOwnedOnce", "TestFreshProcessChild", "TestFreshProcessOther", "TestCoreUnrelated"}
	selected, err := liveAssemblyCheckNames(names, sources, componentProfileFixtureClassifications(names), "full", false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(selected, []string{"TestUnprefixedLiveOnlyCheck", "TestLiveInventoryFreshProcess", "TestFreshProcessChild"}) {
		t.Fatal("live source ownership selection differs", selected)
	}
	if _, err := liveAssemblyCheckNames(names[1:], sources, componentProfileFixtureClassifications(names[1:]), "full", false); err == nil {
		t.Fatal("missing owned source test was accepted")
	}
}

// full_only: false
func TestLiveAssemblyOwnerInventoryMatchesReviewedExclusions(t *testing.T) {
	root := testRepositoryRoot(t)
	coordinatorOnly := []string{"TestLiveRun", "TestLiveChild", "TestLiveCleanup", "TestLiveRecovery"}
	neutralOnce := []string{
		"TestFreshReadReservationsRejectOverflow",
		"TestFreshSelectedReadAllowanceCoversGeneratedBorrows",
		"TestFreshSelectedReadAllowanceRejectsIncompleteGeneratedIndex",
		"TestFreshSelectedReadAllowanceRejectsMalformedFacts",
		"TestCleanupRecoveryRequiresTypedTransientGCPCause",
		"TestCleanupRecoveryRetriesOnlyEligibleExactTarget",
		"TestCleanupRecoveryRejectsChangedGenerationAndGenericReplay",
		"TestCleanupRecoveryStopsAfterThirdFailedAttempt",
		"TestCleanupRecoveryRejectsCorruptOrUnprovedRecord",
		"TestSetupCallRetainsClosedFailureDiagnostics",
		"TestInventoryLeaseRequiresExclusiveAccess",
		"TestInventoryRetainsCleanupFailureStage",
		"TestInventoryCleanupPersistenceFailureKeepsEffectUnresolved",
		"TestInventoryCleanupBudgetRefusalIsNoSend",
		"TestInventoryKnownBeforeSendFailureDoesNotBlockOwnedCleanup",
		"TestInventorySettlesOnlyUniqueUnknownImmutableCreateWithExactReadback",
		"TestInventoryRepresentativeScenarios",
		"TestRecordedStoreAccountsForEveryPhysicalOperation",
		"TestInventoryPrecedesEveryPossibleWrite",
		"TestInventoryUnsettledWritePreventsCleanup",
		"TestInventoryRetainsUnknownAfterLaterSuccessAndRecognizesNotSent",
		"TestInventoryPersistsOriginalCASConditionBeforeSend",
		"TestInventoryFailureCannotStartWrite",
		"TestInventoryPersistenceFailureMakesOwnershipUnknown",
		"TestInventoryCleanupChecksOwnershipAndRetainsFailure",
		"TestInventoryRefusedRecreateCannotRestoreOwnership",
		"TestInventoryCleanupRequiresExactRecordedBodySize",
		"TestInventoryCleanupRetriesOnlyTransportReadWithoutRepeatingDelete",
		"TestInventoryRejectsSymlinkEvidence",
		"TestInventoryUnknownEffectsRequireValidEvidence",
		"TestGenesisHEADUsesBudgetAndInventory",
	}
	for _, provider := range []string{"gcp", "aws"} {
		t.Run(provider, func(t *testing.T) {
			build, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			bootstrap := filepath.Join(build, "bootstrap.json")
			if err := records.WriteJSON(bootstrap, struct{ Replace map[string]string }{Replace: map[string]string{}}, 0600); err != nil {
				t.Fatal(err)
			}
			overlay, err := buildOverlay(root, "live", provider, bootstrap, build)
			if err != nil {
				t.Fatal(err)
			}
			sources, err := assemblyMetadataFixtureSources(t, root, provider, []string{"-overlay=" + overlay})
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for name := range sources {
				names = append(names, name)
			}
			names = append(names, "TestCoreUnrelated", "TestFreshProcessOther")
			slices.Sort(names)
			for _, profile := range []string{"dev", "full"} {
				for _, neutral := range []bool{false, true} {
					selected, err := liveAssemblyCheckNames(names, sources, componentProfileFixtureClassifications(names), profile, neutral)
					if err != nil {
						t.Fatal(err)
					}
					var excluded []string
					for name := range sources {
						if !slices.Contains(selected, name) {
							excluded = append(excluded, name)
						}
					}
					slices.Sort(excluded)
					want := append([]string{}, coordinatorOnly...)
					if !neutral {
						want = append(want, neutralOnce...)
					} else if profile == "dev" {
						want = append(want, "TestInventoryRepresentativeScenarios")
					}
					slices.Sort(want)
					if !slices.Equal(excluded, want) {
						t.Fatalf("excluded live tests differ for %s neutral=%t: got %v, want %v", profile, neutral, excluded, want)
					}
					if slices.Contains(selected, "TestCoreUnrelated") || slices.Contains(selected, "TestFreshProcessOther") {
						t.Fatal("test with another owner entered live assembly")
					}
				}
			}
		})
	}
}

// full_only: false
func TestAssemblyOverlayRejectsInvalidSelectionAndSourceReplacement(t *testing.T) {
	root, bootstrap, build := overlayFixture(t)
	if _, err := buildOverlay(root, "live", "unknown", bootstrap, build); err == nil {
		t.Fatal("unknown provider admitted")
	}
	if entries, err := os.ReadDir(build); err != nil || len(entries) != 0 {
		t.Fatal("invalid selection created build files")
	}
	path, err := buildOverlay(root, "hermetic", "memory", bootstrap, build)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var overlay struct{ Replace map[string]string }
	if json.Unmarshal(body, &overlay) != nil {
		t.Fatal("overlay record invalid")
	}
	for target := range overlay.Replace {
		if err := os.WriteFile(target, []byte("original source"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := buildOverlay(root, "hermetic", "memory", bootstrap, build); err == nil {
			t.Fatal("existing Core file was replaced")
		}
		body, err := os.ReadFile(target)
		if err != nil || string(body) != "original source" {
			t.Fatal("refused overlay changed Core source")
		}
		break
	}
}

// full_only: false
func TestCryptoOverlayOwnsOnlyExactAdmissionSources(t *testing.T) {
	root, _, build := overlayFixture(t)
	path, err := buildCryptoOverlay(root, build)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	var overlay struct{ Replace map[string]string }
	if err != nil || json.Unmarshal(body, &overlay) != nil || len(overlay.Replace) != 6 ||
		overlay.Replace[filepath.Join(root, "compositions/generatorhost/zz_test_environment.go")] != filepath.Join(root, "tests/generatorhost/environment.go") ||
		overlay.Replace[filepath.Join(root, "crypto/zz_test_admission.go")] != filepath.Join(root, "tests/crypto/admission.go") ||
		overlay.Replace[filepath.Join(root, "crypto/zz_test_cloudflare_process_test.go")] != filepath.Join(root, "tests/crypto/cloudflare_process_test.go") ||
		overlay.Replace[filepath.Join(root, "providers/gcp/zz_test_admission.go")] != filepath.Join(root, "tests/gcp/admission.go") ||
		overlay.Replace[filepath.Join(root, "providers/gcp/credentials/zz_test_admission.go")] != filepath.Join(root, "tests/gcpcredentials/admission.go") ||
		overlay.Replace[filepath.Join(root, "compositions/full/zz_test_admission.go")] != filepath.Join(root, "tests/full/admission.go") {
		t.Fatal("Crypto overlay contains an unreviewed source")
	}
	target := filepath.Join(root, "crypto/zz_test_admission.go")
	if err := os.WriteFile(target, []byte("package crypto\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := buildCryptoOverlay(root, build); err == nil {
		t.Fatal("Crypto overlay replaced existing source")
	}
}

// full_only: false
func TestAssemblyFileHashObservesChangedBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(path, []byte("original executable"), 0700); err != nil {
		t.Fatal(err)
	}
	before, err := assemblyFileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("changed executable"), 0700); err != nil {
		t.Fatal(err)
	}
	after, err := assemblyFileSHA256(path)
	if err != nil || before == after {
		t.Fatal("artifact hash did not observe byte change", err)
	}
}

// full_only: false
func TestHermeticAssemblyAdmitsSDKStartupButRefusesCloudModules(t *testing.T) {
	modules := []resolvedModule{{Path: modulePrefix + "core"}, {Path: modulePrefix + "telemetry", Version: "v0.1.0"}, {Path: "enkv.sh/sdk/artifact", Version: "v0.1.0"}, {Path: "go.opentelemetry.io/otel/sdk", Version: "v1.36.0"}, {Path: "enkv.sh/sdk/protocols/manifest-generator", Version: "v0.1.0"}}
	packages := []compiledPackage{{ImportPath: modulePrefix + "core"}, {ImportPath: modulePrefix + "telemetry"}, {ImportPath: modulePrefix + "core.test"}, {ImportPath: modulePrefix + "core [" + modulePrefix + "core.test]"}, {ImportPath: "enkv.sh/sdk/artifact"}, {ImportPath: "go.opentelemetry.io/otel/sdk/metric"}}
	if err := checkHermeticBoundary(modules, packages); err != nil {
		t.Fatal(err)
	}
	for _, owner := range []string{"compositions/configuration", "compositions/manifesthost"} {
		t.Run("runner-module/"+owner, func(t *testing.T) {
			path := modulePrefix + owner
			expanded := append(slices.Clone(modules), resolvedModule{Path: path, Version: "v0.1.0"})
			if err := checkHermeticBoundary(expanded, packages); err != nil {
				t.Fatal("runner preparation module refused", err)
			}
			if checkHermeticBoundary(append(slices.Clone(modules), resolvedModule{Path: path + "/internal", Version: "v0.1.0"}), packages) == nil {
				t.Fatal("runner preparation submodule admitted")
			}
			for _, compiled := range []string{path, path + "/internal"} {
				if checkHermeticBoundary(expanded, append(slices.Clone(packages), compiledPackage{ImportPath: compiled})) == nil {
					t.Fatal("runner preparation package reached Core assembly", compiled)
				}
			}
		})
	}
	for _, renderer := range []string{genericJSONPath, openTofuJSONPath} {
		t.Run(renderer, func(t *testing.T) {
			rendererModules := append(slices.Clone(modules), resolvedModule{Path: manifestSDKPath, Version: "v0.1.0"}, resolvedModule{Path: renderer, Version: "v0.1.0"})
			rendererPackages := append(slices.Clone(packages),
				compiledPackage{ImportPath: manifestSDKPath},
				compiledPackage{ImportPath: "enkv.sh/sdk/artifact/credentialroute"},
				compiledPackage{ImportPath: "enkv.sh/sdk/protocols/manifest-generator", Imports: []string{manifestSDKPath}},
				compiledPackage{ImportPath: manifestSDKPath + "/jsonwriter", Imports: []string{manifestSDKPath}},
				compiledPackage{ImportPath: renderer, Imports: []string{manifestSDKPath, manifestSDKPath + "/jsonwriter", "enkv.sh/sdk/artifact", "enkv.sh/sdk/protocols/manifest-generator"}})
			rendererPackages[3].ForTest = modulePrefix + "core"
			rendererPackages[3].Imports = []string{renderer}
			if err := checkHermeticBoundary(rendererModules, rendererPackages); err != nil {
				t.Fatal("reviewed renderer fixture refused", err)
			}
			for _, provider := range []string{"aws", "gcp"} {
				liveModules := append(slices.Clone(rendererModules), resolvedModule{Path: modulePrefix + "providers/" + provider, Version: "v0.1.0"})
				livePackages := append(slices.Clone(rendererPackages), compiledPackage{ImportPath: modulePrefix + "providers/" + provider})
				if err := checkLiveBoundary(provider, liveModules, livePackages); err != nil {
					t.Fatal("reviewed live renderer fixture refused", provider, err)
				}
			}
			for _, damage := range []string{"native", "conformance", "renderer-subpackage", "wire-subpackage"} {
				t.Run(damage, func(t *testing.T) {
					changed := slices.Clone(rendererPackages)
					switch damage {
					case "native", "conformance":
						changed = append(changed, compiledPackage{ImportPath: manifestSDKPath + "/" + damage})
					case "renderer-subpackage":
						changed = append(changed, compiledPackage{ImportPath: renderer + "/internal"})
					case "wire-subpackage":
						changed = append(changed, compiledPackage{ImportPath: "enkv.sh/sdk/protocols/manifest-generator/private"})
					}
					if checkHermeticBoundary(rendererModules, changed) == nil {
						t.Fatal("unreviewed manifest closure admitted")
					}
					for _, provider := range []string{"aws", "gcp"} {
						liveModules := append(slices.Clone(rendererModules), resolvedModule{Path: modulePrefix + "providers/" + provider, Version: "v0.1.0"})
						livePackages := append(slices.Clone(changed), compiledPackage{ImportPath: modulePrefix + "providers/" + provider})
						if checkLiveBoundary(provider, liveModules, livePackages) == nil {
							t.Fatal("unreviewed live manifest closure admitted", provider)
						}
					}
				})
			}
		})
	}
	for _, dependency := range []string{modulePrefix + "providers/aws", modulePrefix + "providers/gcp", "enkv.sh/sdk/artifact/build", "google.golang.org/api", "github.com/aws/aws-sdk-go-v2", "example.invalid/unreviewed"} {
		if checkHermeticBoundary(append(modules, resolvedModule{Path: dependency}), packages) == nil || checkHermeticBoundary(modules, append(packages, compiledPackage{ImportPath: dependency})) == nil {
			t.Fatal("hermetic assembly admitted an external fixture or service dependency")
		}
	}
	for _, path := range []string{"enkv.sh/sdk/protocols/manifest-generator", "enkv.sh/sdk/protocols/manifest-generator/private"} {
		want := path == "enkv.sh/sdk/protocols/manifest-generator"
		if err := checkHermeticBoundary(modules, append(slices.Clone(packages), compiledPackage{ImportPath: path})); (err == nil) != want {
			t.Fatal("manifest wire closure differs from its exact public owner", path, err)
		}
	}
	if checkHermeticBoundary(append(slices.Clone(modules), resolvedModule{Path: "enkv.sh/sdk/protocols/manifest-generator/private", Version: "v0.1.0"}), packages) == nil {
		t.Fatal("unregistered manifest wire submodule admitted")
	}
	for _, version := range []string{"", "v0.0.1"} {
		changed := slices.Clone(modules)
		changed[len(changed)-1].Version = version
		if checkHermeticBoundary(changed, packages) == nil {
			t.Fatal("manifest wire version drift admitted", version)
		}
	}
	for _, imported := range []string{"enkv.sh/sdk/artifact", "enkv.sh/sdk/protocols/manifest-generator"} {
		for _, forTest := range []string{"", modulePrefix + "core"} {
			core := compiledPackage{ImportPath: modulePrefix + "core", ForTest: forTest, Imports: []string{imported}}
			want := imported == "enkv.sh/sdk/artifact" && forTest == modulePrefix+"core"
			if err := checkCustodyImports([]compiledPackage{core}, true, ""); (err == nil) != want {
				t.Fatal("Core metadata dependency differs from its exact owner", imported, forTest, err)
			}
		}
	}
}

// full_only: false
func TestProductTestsSelectOnlyTestSideTelemetryModfiles(t *testing.T) {
	root := "/synthetic-repository"
	for _, tc := range []struct{ module, suffix string }{
		{"core", "tests/hermetic/hermetic.mod"},
		{"crypto", "crypto/telemetry_test.mod"},
		{"providers/aws", "providers/aws/telemetry_test.mod"},
		{"providers/gcp", "providers/gcp/telemetry_test.mod"},
	} {
		flags := moduleTestFlags(root, tc.module, "/synthetic-overlay.json")
		if !slices.Contains(flags, "-modfile="+filepath.Join(root, tc.suffix)) {
			t.Fatalf("test module %s did not select its test-only dependency graph: %v", tc.module, flags)
		}
	}
}

func bindAssemblyFailureSources(t *testing.T, value *assembly, directory string) {
	t.Helper()
	if value.root != "" && value.Closure.declarations.packages == nil {
		pkg := listedOrdinaryPackage{ImportPath: componentPackage, Dir: filepath.Join(value.root, "core")}
		entries, err := os.ReadDir(pkg.Dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), "_test.go") {
				pkg.TestGoFiles = append(pkg.TestGoFiles, entry.Name())
			}
		}
		for _, flag := range value.buildFlags {
			path, ok := strings.CutPrefix(flag, "-overlay=")
			if !ok {
				continue
			}
			var overlay struct{ Replace map[string]string }
			if err := records.ReadJSON(path, &overlay); err != nil {
				t.Fatal(err)
			}
			for target, source := range overlay.Replace {
				if source != "" && filepath.Dir(target) == pkg.Dir && strings.HasSuffix(target, "_test.go") {
					pkg.TestGoFiles = append(pkg.TestGoFiles, filepath.Base(target))
				}
			}
		}
		value.Closure.declarations, err = captureTestDeclarations(value.root, []listedOrdinaryPackage{pkg}, value.buildFlags)
		if err != nil {
			t.Fatal("capture fixture declarations", err)
		}
	}
	directory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, "failure-sources.json")
	sources := records.FailureSources{SchemaVersion: records.FailureSchemaVersion, BinarySHA256: value.Closure.BinarySHA256, OverlaySHA256: value.Closure.OverlaySHA256, Paths: map[string]string{modulePrefix + "core/tests_shared_fixture_test.go": "tests/shared/fixture_test.go"}}
	if records.WriteJSON(file, sources, 0400) != nil {
		t.Fatal("assembly source fixture")
	}
	digest, err := assemblyFileSHA256(file)
	if err != nil {
		t.Fatal(err)
	}
	value.FailureSources = &records.FailureSourceBinding{Path: file, SHA256: digest}
	value.Closure.FailureSourcesSHA256 = digest
}

// full_only: false
func TestLiveAssemblyFailureSourcesUseExactOverlayAndModuleIdentity(t *testing.T) {
	root, bootstrap, build := overlayFixture(t)
	for _, name := range []string{"tests/shared/file_with_underscores_test.go", "crypto/testsupport/custody/live.go"} {
		file := filepath.Join(root, name)
		if os.MkdirAll(filepath.Dir(file), 0700) != nil || os.WriteFile(file, []byte("package fixture\n"), 0600) != nil {
			t.Fatal("source mapping fixture")
		}
	}
	overlay, err := buildOverlay(root, "live", "gcp", bootstrap, build)
	if err != nil {
		t.Fatal(err)
	}
	overlayHash, err := assemblyFileSHA256(overlay)
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(build, "state.test")
	if os.WriteFile(binary, []byte("bound executable"), 0700) != nil {
		t.Fatal("binary fixture")
	}
	binaryHash, err := assemblyFileSHA256(binary)
	if err != nil {
		t.Fatal(err)
	}
	closure := assemblyClosure{BinarySHA256: binaryHash, OverlaySHA256: overlayHash, ResolvedModules: []moduleIdentity{{Path: modulePrefix + "core", Version: "local"}, {Path: modulePrefix + "crypto", Version: "v0.0.0"}, {Path: modulePrefix + "compositions/full", Version: "v0.0.0"}}, CompiledImports: []string{modulePrefix + "core [" + modulePrefix + "core.test]", modulePrefix + "crypto", modulePrefix + "crypto/testsupport/custody", modulePrefix + "compositions/full"}}
	closure.ResolvedModules = append(closure.ResolvedModules, moduleIdentity{Path: modulePrefix + "providers/gcp", Version: "v0.0.0"}, moduleIdentity{Path: modulePrefix + "compositions/generatorhost", Version: "v0.0.0"})
	closure.CompiledImports = append(closure.CompiledImports, modulePrefix+"providers/gcp/credentials", modulePrefix+"compositions/generatorhost")
	binding, err := buildFailureSources(root, overlay, build, closure)
	if err != nil {
		t.Fatal(err)
	}
	sources, err := records.ReadFailureSources(*binding)
	if err != nil {
		t.Fatal(err)
	}
	for caller, want := range map[string]string{
		modulePrefix + "compositions/generatorhost@v0.0.0/zz_test_environment.go": "tests/generatorhost/environment.go",
		modulePrefix + "crypto@v0.0.0/testsupport/custody/zz_test_output_box.go":  "tests/live/custody/output_box.go",
		modulePrefix + "providers/gcp@v0.0.0/credentials/zz_test_admission.go":    "tests/gcpcredentials/admission.go",
		modulePrefix + "core/tests_shared_file_with_underscores_test.go":          "tests/shared/file_with_underscores_test.go",
		modulePrefix + "crypto@v0.0.0/testsupport/custody/live.go":                "crypto/testsupport/custody/live.go",
		modulePrefix + "crypto@v0.0.0/zz_test_admission.go":                       "tests/crypto/admission.go",
		modulePrefix + "compositions/full@v0.0.0/zz_test_admission.go":            "tests/full/admission.go",
	} {
		if sources.Paths[caller] != want {
			t.Fatal("exact overlay or resolved module source was lost", caller)
		}
	}
	if _, guessed := sources.Paths[modulePrefix+"core/tests/shared/file/with/underscores/test.go"]; guessed {
		t.Fatal("underscores were guessed as directory boundaries")
	}
	if _, unqualified := sources.Paths[modulePrefix+"crypto/testsupport/custody/live.go"]; unqualified {
		t.Fatal("resolved module version was discarded")
	}
	if _, wrongVersion := sources.Paths[modulePrefix+"crypto@v0.0.1/testsupport/custody/live.go"]; wrongVersion {
		t.Fatal("unselected module version was admitted")
	}
	for _, source := range sources.Paths {
		if filepath.IsAbs(source) || strings.Contains(source, root) || strings.Contains(source, "..") {
			t.Fatal("private source root entered portable mapping")
		}
	}
	closure.FailureSourcesSHA256 = binding.SHA256
	if _, err := records.ReadFailureSources(*binding); err != nil {
		t.Fatal("source mapping refused", err)
	}
	sources.Paths[modulePrefix+"core/tests_shared_file_with_underscores_test.go"] = "tests/shared/fixture_test.go"
	if records.WriteJSON(binding.Path, sources, 0400) != nil {
		t.Fatal("source-map mutation fixture")
	}
	if _, err := records.ReadFailureSources(*binding); err == nil {
		t.Fatal("changed source mapping retained its original digest")
	}
}

// full_only: false
func TestAssemblyFailureSourcesDoNotReadUncompiledDirectories(t *testing.T) {
	for _, name := range []string{".private", "_private", "testdata", "vendor", "unselected", "nested/unselected"} {
		t.Run(name, func(t *testing.T) {
			root, overlay, build := overlayFixture(t)
			selected := filepath.Join(root, "core/nested/.selected")
			if err := os.MkdirAll(selected, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(selected, "source.go"), []byte("package fixture\n"), 0600); err != nil {
				t.Fatal(err)
			}
			unselected := filepath.Join(root, "core", name)
			if err := os.MkdirAll(unselected, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(unselected, "source.go"), []byte("package fixture\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(unselected, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.Chmod(unselected, 0700); err != nil {
					t.Error(err)
				}
			})
			closure := assemblyClosure{BinarySHA256: strings.Repeat("a", 64), OverlaySHA256: strings.Repeat("b", 64), ResolvedModules: []moduleIdentity{{Path: modulePrefix + "core", Version: "local"}}, CompiledImports: []string{modulePrefix + "core/nested/.selected [" + modulePrefix + "core.test]"}}
			binding, err := buildFailureSources(root, overlay, build, closure)
			if err != nil {
				t.Fatal("uncompiled directory prevented source mapping", err)
			}
			sources, err := records.ReadFailureSources(*binding)
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]string{modulePrefix + "core/nested/.selected/source.go": "core/nested/.selected/source.go"}
			if !maps.Equal(sources.Paths, want) {
				t.Fatal("compiled source mapping changed", sources.Paths)
			}
		})
	}
}

// full_only: false
func TestAssemblyFailureSourcesKeepRequiredSourceErrors(t *testing.T) {
	root, overlay, build := overlayFixture(t)
	if err := os.Symlink("missing.go", filepath.Join(root, "core/source.go")); err != nil {
		t.Fatal(err)
	}
	closure := assemblyClosure{BinarySHA256: strings.Repeat("a", 64), OverlaySHA256: strings.Repeat("b", 64), ResolvedModules: []moduleIdentity{{Path: modulePrefix + "core", Version: "local"}}, CompiledImports: []string{modulePrefix + "core"}}
	if _, err := buildFailureSources(root, overlay, build, closure); err == nil {
		t.Fatal("invalid required source was silently omitted")
	}
}

// full_only: false
func TestOutputAssemblyEdgesAreExact(t *testing.T) {
	modules := []resolvedModule{{Path: modulePrefix + "core"}, {Path: modulePrefix + "compositions/outputhost"}, {Path: "enkv.sh/sdk/protocols/output"}, {Path: nativeProcessPath, Version: "v0.0.0"}}
	packages := []compiledPackage{{ImportPath: modulePrefix + "core", ForTest: modulePrefix + "core", Imports: []string{modulePrefix + "compositions/outputhost", "enkv.sh/sdk/protocols/output"}}, {ImportPath: modulePrefix + "compositions/outputhost"}, {ImportPath: "enkv.sh/sdk/protocols/output"}, {ImportPath: nativeProcessPath}}
	if err := checkHermeticBoundary(modules, packages); err != nil {
		t.Fatal(err)
	}
	for _, provider := range []string{"aws", "gcp"} {
		livePackages := append(slices.Clone(packages), compiledPackage{ImportPath: modulePrefix + "providers/" + provider})
		if err := checkLiveBoundary(provider, modules, livePackages); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{modulePrefix + "compositions/outputhost/private", nativeProcessPath + "/private", "enkv.sh/sdk/protocols/output/private"} {
			if checkLiveBoundary(provider, append(slices.Clone(modules), resolvedModule{Path: path}), livePackages) == nil {
				t.Fatal("live admitted private output module", path)
			}
			if checkLiveBoundary(provider, modules, append(slices.Clone(livePackages), compiledPackage{ImportPath: path})) == nil {
				t.Fatal("live admitted private output package", path)
			}
		}
	}
	for _, path := range []string{modulePrefix + "compositions/outputhost/private", nativeProcessPath + "/private", "enkv.sh/sdk/protocols/output/private", "enkv.sh/plugins/outputs/aws-secrets-manager", modulePrefix + "providers/aws"} {
		if checkHermeticBoundary(append(slices.Clone(modules), resolvedModule{Path: path}), packages) == nil {
			t.Fatal("hermetic admitted module", path)
		}
		if checkHermeticBoundary(modules, append(slices.Clone(packages), compiledPackage{ImportPath: path})) == nil {
			t.Fatal("hermetic admitted package", path)
		}
	}
}

// full_only: false
func TestMovedPublicFailureSourcesKeepLogicalLabels(t *testing.T) {
	root := t.TempDir()
	writeLocalGoFixture(t, root, "plugins/cloudflare/profile/semantics.go", "package profile\n")
	writeLocalGoFixture(t, root, "plugins/cloudflare/artifact/manifest.go", "package artifact\n")
	writeLocalGoFixture(t, root, "plugins/cloudflare/artifact/nested/manifest.go", "package nested\n")
	writeLocalGoFixture(t, root, "sdk/artifact/types.go", "package artifact\n")
	writeLocalGoFixture(t, root, "sdk/artifact/build/build.go", "package build\n")
	writeLocalGoFixture(t, root, "sdk/artifact/cmd/enkv-plugin-build/main.go", "package main\n")
	writeLocalGoFixture(t, root, "sdk/manifest-generator/view.go", "package manifest\n")
	writeLocalGoFixture(t, root, "plugins/manifest-generators/generic-json/encode.go", "package genericjson\n")
	writeLocalGoFixture(t, root, "plugins/manifest-generators/opentofu-tfvars-json/encode.go", "package opentofutfvars\n")
	writeLocalGoFixture(t, root, "sdk/manifest-generator/jsonwriter/writer.go", "package jsonwriter\n")
	writeLocalGoFixture(t, root, "sdk/manifest-generator/conformance/check.go", "package conformance\n")
	writeLocalGoFixture(t, root, "sdk/examples/ini-reference-manifest/main.go", "package main\n")
	writeLocalGoFixture(t, root, "sdk/examples/ini-reference-manifest/renderer/read.go", "package renderer\n")
	writeLocalGoFixture(t, root, "sdk/examples/ini-reference-manifest/consumer/read.go", "package consumer\n")
	writeLocalGoFixture(t, root, "sdk/examples/ini-reference-manifest/consumer/read_test.go", "package consumer\n")
	writeLocalGoFixture(t, root, "sdk/examples/ini-reference-manifest/consumer/nested/read.go", "package nested\n")
	build := t.TempDir()
	overlay := filepath.Join(build, "overlay.json")
	if err := records.WriteJSON(overlay, struct{ Replace map[string]string }{map[string]string{}}, 0600); err != nil {
		t.Fatal(err)
	}
	closure := assemblyClosure{BinarySHA256: strings.Repeat("a", 64), OverlaySHA256: strings.Repeat("b", 64), ResolvedModules: []moduleIdentity{{Path: cloudflareModulePath, Version: "v0.0.0"}, {Path: "enkv.sh/sdk/artifact", Version: "v0.0.0"}, {Path: manifestSDKPath, Version: "v0.0.0"}, {Path: genericJSONPath, Version: "v0.0.0"}, {Path: openTofuJSONPath, Version: "v0.0.0"}}, CompiledImports: []string{cloudflareModulePath + "/profile", cloudflareModulePath + "/artifact", "enkv.sh/sdk/artifact", manifestSDKPath, manifestSDKPath + "/jsonwriter", genericJSONPath, openTofuJSONPath}}
	closure.ResolvedModules = append(closure.ResolvedModules, moduleIdentity{Path: manifestExamplePath, Version: "v0.0.0"})
	closure.CompiledImports = append(closure.CompiledImports, liveManifestConsumerPath)
	binding, err := buildFailureSources(root, overlay, build, closure)
	if err != nil {
		t.Fatal(err)
	}
	sources, err := records.ReadFailureSources(*binding)
	want := map[string]string{
		"enkv.sh/plugins/generators/cloudflare-account-token@v0.0.0/profile/semantics.go": "plugins/cloudflare/profile/semantics.go",
		"enkv.sh/sdk/manifest-generator@v0.0.0/view.go":                                   "sdk/manifest-generator/view.go",
		"enkv.sh/plugins/manifest-generators/generic-json@v0.0.0/encode.go":               "plugins/manifest-generators/generic-json/encode.go",
		"enkv.sh/plugins/manifest-generators/opentofu-tfvars-json@v0.0.0/encode.go":       "plugins/manifest-generators/opentofu-tfvars-json/encode.go",
		"enkv.sh/sdk/manifest-generator@v0.0.0/jsonwriter/writer.go":                      "sdk/manifest-generator/jsonwriter/writer.go",
	}
	want[manifestExamplePath+"@v0.0.0/consumer/read.go"] = "sdk/examples/ini-reference-manifest/consumer/read.go"
	want[manifestExamplePath+"@v0.0.0/consumer/read_test.go"] = "sdk/examples/ini-reference-manifest/consumer/read_test.go"
	withArtifacts := maps.Clone(want)
	withArtifacts["enkv.sh/sdk/artifact@v0.0.0/types.go"] = "sdk/artifact/types.go"
	withArtifacts["enkv.sh/plugins/generators/cloudflare-account-token@v0.0.0/artifact/manifest.go"] = "plugins/cloudflare/artifact/manifest.go"
	if err != nil || !maps.Equal(sources.Paths, withArtifacts) {
		t.Fatal("moved source leaked a physical path or lost its compiler identity", sources, err)
	}
	for _, refused := range []string{manifestExamplePath, manifestExamplePath + "/renderer", liveManifestConsumerPath + "/nested"} {
		damaged := closure
		damaged.CompiledImports = append(slices.Clone(closure.CompiledImports), refused)
		if _, err := buildFailureSources(root, overlay, t.TempDir(), damaged); err == nil {
			t.Fatal("source map admitted an example package outside the independent consumer", refused)
		}
	}
	delete(want, manifestExamplePath+"@v0.0.0/consumer/read.go")
	delete(want, manifestExamplePath+"@v0.0.0/consumer/read_test.go")
	// Resolved metadata does not make either passive package compiled. Its
	// files and the uncompiled nested/build/command packages must all stay out.
	closure.CompiledImports = []string{cloudflareModulePath + "/profile", manifestSDKPath, manifestSDKPath + "/jsonwriter", genericJSONPath, openTofuJSONPath}
	binding, err = buildFailureSources(root, overlay, t.TempDir(), closure)
	if err != nil {
		t.Fatal("metadata-only passive package changed source mapping", err)
	}
	sources, err = records.ReadFailureSources(*binding)
	if err != nil || !maps.Equal(sources.Paths, want) {
		t.Fatal("uncompiled passive package entered source mapping", sources, err)
	}
	closure.CompiledImports = []string{cloudflareModulePath + "/profile", manifestSDKPath, genericJSONPath}
	binding, err = buildFailureSources(root, overlay, t.TempDir(), closure)
	if err != nil {
		t.Fatal("metadata-only manifest owner changed source mapping", err)
	}
	sources, err = records.ReadFailureSources(*binding)
	delete(want, "enkv.sh/sdk/manifest-generator@v0.0.0/jsonwriter/writer.go")
	delete(want, "enkv.sh/plugins/manifest-generators/opentofu-tfvars-json@v0.0.0/encode.go")
	if err != nil || !maps.Equal(sources.Paths, want) {
		t.Fatal("uncompiled manifest writer or renderer entered source mapping", sources, err)
	}
}

type assemblyScheduleFailureOutput struct{ failed bool }

func (output *assemblyScheduleFailureOutput) Write(body []byte) (int, error) {
	if strings.HasPrefix(string(body), "0000 ") {
		output.failed = true
		return 0, errors.New("controlled schedule output failure")
	}
	return len(body), nil
}

// full_only: false
func TestCurrentAssemblyReuseKeepsBuildAfterSourceEdits(t *testing.T) {
	root := sourceFixtureRoot(t)
	ctx, bootstrap, _ := copyPreparationAssemblyFixture(t, root)
	compiles := observePreparationCompiles(t)
	build := t.TempDir()
	const input = "telemetry/current_assembly_input.go"
	writeLocalGoFixture(t, root, input, "package telemetry\n// current assembly input A\n")
	entered := filepath.Join(t.TempDir(), "worker-entered")
	writeLocalGoFixture(t, root, "tests/hermetic/current_assembly_entry_test.go", fmt.Sprintf(`package core
import "os"
func init() {
 if os.Getenv("ENKV_TEST_INVOCATION") != "" {
  if err := os.WriteFile(%q, []byte("entered"), 0600); err != nil { panic(err) }
 }
}
`, entered))
	source, err := sourceRevision(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	version, err := runGo(ctx, root, "core", "version")
	if err != nil {
		t.Fatal(err)
	}
	toolchain := strings.TrimSpace(string(version))
	group := newPreparedComponentGroup(ctx)
	defer group.cancel()
	assembled, err := group.prepare(root, bootstrap, "full", nil, source, toolchain, build)
	if err != nil {
		t.Fatal("prepare complete current assembly control", err)
	}
	if !slices.Contains(assembled.Closure.CompiledImports, modulePrefix+"telemetry") {
		t.Fatal("compiler-input fixture is absent from the actual assembly closure")
	}
	if err := checkAssemblyRace(ctx, assembled); err != nil {
		t.Fatal("unchanged current compiler inputs were refused", err)
	}
	reused, err := group.prepare(root, bootstrap, "full", nil, source, toolchain, build)
	if err != nil || reused.Binary != assembled.Binary || reused.Closure.BinarySHA256 != assembled.Closure.BinarySHA256 {
		t.Fatal("unchanged prepared component owner was not reused", err)
	}
	t.Run("source-root", func(t *testing.T) {
		if _, err := group.prepare(t.TempDir(), bootstrap, "full", nil, source, toolchain, build); err == nil || err.Error() != "component prepared selection changed" {
			t.Fatal("prepared component accepted another source root", err)
		}
		if _, err := os.Stat(entered); !os.IsNotExist(err) {
			t.Fatal("another source root reached worker entry", err)
		}
	})
	_, full := completeRunFixture(t, "memory")
	component := full.Correctness.ComponentRun
	component.Source, component.Toolchain, component.BuildClosure = source, toolchain, &assembled.Closure
	if !component.passedFor(source, toolchain) {
		t.Fatal("complete same-run component control was refused")
	}
	suite, environment := filepath.Join(root, "selected-suite.json"), filepath.Join(root, "selected-environment.json")
	saveSelection(t, suite, suiteFixture("current-assembly-reuse", []string{"state.single-value-update-preserves-other-values/members_32"}))
	saveSelection(t, environment, memoryEnvironment())
	request, err := parseRunRequest([]string{"run", "--race", "--suite", suite, "--environment", environment})
	if err != nil {
		t.Fatal(err)
	}
	request.components = &componentRun{record: *component, assembled: assembled}
	assigned, err := executionWithinContext(ctx, request.execution)
	if err != nil {
		t.Fatal(err)
	}
	beforeReuse, err := os.ReadFile(compiles)
	if err != nil {
		t.Fatal("completed owner compiles unavailable", err)
	}
	var control strings.Builder
	result, err := runSuite(ctx, root, bootstrap, request, &control)
	if err != nil || result.Record == nil || result.Record.Outcome != "passed" || len(result.Record.Scenarios) == 0 || result.Record.Correctness.ComponentRun != &request.components.record || !strings.Contains(control.String(), "Reusing build preparation from the component step") {
		t.Fatal("unchanged component owner did not complete actual scenario reuse", err)
	}
	if _, err := os.Stat(entered); err != nil {
		t.Fatal("unchanged reuse did not reach the actual worker", err)
	}
	if err := os.Remove(entered); err != nil {
		t.Fatal(err)
	}
	if afterReuse, err := os.ReadFile(compiles); err != nil || string(afterReuse) != string(beforeReuse) {
		t.Fatal("valid component-to-scenario reuse compiled another assembly", err)
	}
	if err := checkAssemblyRace(ctx, assembled); err != nil {
		t.Fatal("completed suite invalidated the borrowed owner", err)
	}

	writeLocalGoFixture(t, root, input, "package telemetry\ninvalid source after the build\n")
	reused, err = group.prepare(root, bootstrap, "full", nil, source, toolchain, build)
	if err != nil || reused.Binary != assembled.Binary {
		t.Fatal("source edit invalidated the completed component build", err)
	}
	result, err = runSuite(ctx, root, bootstrap, request, io.Discard)
	if err != nil || result.Record == nil || result.Record.Outcome != "passed" || len(result.Record.Scenarios) == 0 {
		t.Fatal("source edit blocked scenario execution with the borrowed build", err)
	}
	if result.Record.FinishedAt == nil || result.Record.FinishedAt.Before(result.Record.StartedAt) || !records.ValidRunID(result.Record.RunID) ||
		!sameSource(result.Record.Source, source) || result.Record.Toolchain != toolchain || result.Record.Resolved != request.Resolved ||
		result.Record.Execution.Resolved != assigned.Resolved || !result.Record.Resolved.Race || result.Record.Resolved.raceMissing ||
		!slices.Equal(result.Record.Schedule.Entries, request.Schedule.Entries) || result.Record.Correctness.ComponentRun != &request.components.record {
		t.Fatal("source edit changed captured scenario configuration or its finalized result", result.Record)
	}
	t.Run("schedule-output-failure", func(t *testing.T) {
		output := &assemblyScheduleFailureOutput{}
		result, err := runSuite(ctx, root, bootstrap, request, output)
		if !output.failed || err == nil || !strings.Contains(err.Error(), "run schedule output failed") || result.Record != nil {
			t.Fatal("pre-record output failure was lost", err)
		}
	})
	if afterReuse, err := os.ReadFile(compiles); err != nil || string(afterReuse) != string(beforeReuse) {
		t.Fatal("source edit caused scenario dispatch to rebuild", err)
	}
	if _, err := os.Stat(entered); err != nil {
		t.Fatal("borrowed assembly did not execute after the source edit", err)
	}
}

// full_only: false
func TestLiveCustodyOverlayRequiresExactSourceAndEmptyTarget(t *testing.T) {
	for _, damage := range []string{"missing", "directory", "symlink", "existing-target"} {
		t.Run(damage, func(t *testing.T) {
			root, bootstrap, build := overlayFixture(t)
			source := filepath.Join(root, "tests/live/custody/output_box.go")
			if damage == "existing-target" {
				if err := os.WriteFile(filepath.Join(root, "crypto/testsupport/custody/zz_test_output_box.go"), []byte("package custody\n"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Remove(source); err != nil {
					t.Fatal(err)
				}
				switch damage {
				case "directory":
					if err := os.Mkdir(source, 0700); err != nil {
						t.Fatal(err)
					}
				case "symlink":
					if err := os.Symlink(filepath.Join(root, "tests/crypto/admission.go"), source); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := buildOverlay(root, "live", "aws", bootstrap, build); err == nil {
				t.Fatal("damaged live custody source admitted")
			}
			if _, err := buildOverlay(root, "hermetic", "memory", bootstrap, build); err != nil {
				t.Fatal("live-only source affected hermetic assembly", err)
			}
		})
	}
}

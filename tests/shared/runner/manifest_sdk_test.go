package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// full_only: false
func TestIndependentManifestExampleBuildsFromPublicKit(t *testing.T) {
	outer, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	outerRace, err := binaryRace(outer)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		selector, module string
		tests            []string
	}{
		{"sdk/examples/ini-reference-manifest", manifestExamplePath, []string{"TestSettingsOwnDefaultsCanonicalizationAndRejection", "TestINIReferenceCompleteBytesAndConsumer", "TestDefectivePlainEncodingFailsAuthorAndConsumerChecks", "TestLargeOpaquePolicyRemainsConsumable", "TestINIReferenceEmptyAndExcludedPartitions", "TestAuthorCallbacksReturnClosedFailures"}},
	} {
		t.Run(test.selector, func(t *testing.T) {
			kit := t.TempDir()
			root := filepath.Join(kit, "implementation")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			selectors := []string{"sdk/artifact", "protocols/manifest-generator", "sdk/manifest-generator", test.selector}
			copyPublicModuleKit(t, maintainedCloudflareRoot(t), root, selectors)
			ctx, cancel := context.WithTimeout(cacheOnlyGoContext(testRaceContext(t, t.Context())), 2*time.Minute)
			defer cancel()
			flags := compilerBuildFlags([]string{"-mod=readonly"}, raceEnabled(ctx))
			modules, packages, err := listClosure(runGoEnvironment, ctx, root, test.selector, flags, false, ".")
			if err != nil {
				t.Fatal(err)
			}
			if err := checkBoundary(test.selector, modules, packages); err != nil {
				t.Fatal(err)
			}
			for _, selector := range selectors {
				if err := checkModuleSource(root, modules, selector); err != nil {
					t.Fatal(err)
				}
			}
			runPublicKitTests(t, ctx, root, test.selector, ".", test.module, test.tests)
			runPublicKitTests(t, ctx, root, test.selector, "./consumer", test.module+"/consumer", []string{"TestConsumerRejectsDuplicateAndMalformedFields"})
			binary := filepath.Join(kit, "manifest-example")
			args := compilerBuildFlags([]string{"build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", binary}, raceEnabled(ctx))
			if _, err := runGo(ctx, root, test.selector, append(args, ".")...); err != nil {
				t.Fatal(err)
			}
			observed, err := binaryRace(binary)
			if err != nil || observed != outerRace {
				t.Fatalf("public example lost the outer race setting: compiled=%t want=%t error=%v", observed, outerRace, err)
			}
			checkPublicKitBuildInfo(t, binary, test.module, map[string]string{
				"enkv.sh/sdk/artifact":                     "../../artifact",
				manifestSDKPath:                            "../../manifest-generator",
				"enkv.sh/sdk/protocols/manifest-generator": "../../protocols/manifest-generator",
			}, nil)
			for _, selector := range selectors[:len(selectors)-1] {
				owner, err := sourcePath(root, selector)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(owner, owner+"-missing"); err != nil {
					t.Fatal(err)
				}
				_, _, missingErr := listClosure(runGoEnvironment, ctx, root, test.selector, flags, false, ".")
				if err := os.Rename(owner+"-missing", owner); err != nil {
					t.Fatal(err)
				}
				if missingErr == nil {
					t.Fatal("kit resolved missing public source", selector)
				}
			}
		})
	}
}

// full_only: false
func TestProductionManifestRenderersRunFromPublicKit(t *testing.T) {
	for _, test := range []struct{ selector, module, test string }{
		{"plugins/manifest-generators/generic-json", genericJSONPath, "TestPublicConformance"},
		{"plugins/manifest-generators/opentofu-tfvars-json", openTofuJSONPath, "TestOpenTofuPublicRendererExactMixedVector"},
	} {
		t.Run(test.selector, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "implementation")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			selectors := []string{"sdk/artifact", "protocols/manifest-generator", "sdk/manifest-generator", test.selector}
			copyPublicModuleKit(t, maintainedCloudflareRoot(t), root, selectors)
			ctx, cancel := context.WithTimeout(cacheOnlyGoContext(testRaceContext(t, t.Context())), 2*time.Minute)
			defer cancel()
			flags := compilerBuildFlags([]string{"-mod=readonly"}, raceEnabled(ctx))
			modules, packages, err := listClosure(runGoEnvironment, ctx, root, test.selector, flags, false, ".")
			if err != nil {
				t.Fatal(err)
			}
			if err := checkBoundary(test.selector, modules, packages); err != nil {
				t.Fatal(err)
			}
			for _, selector := range selectors {
				if err := checkModuleSource(root, modules, selector); err != nil {
					t.Fatal(err)
				}
			}
			if test.module == genericJSONPath {
				runPublicKitTests(t, ctx, root, "sdk/manifest-generator", "./conformance", manifestSDKPath+"/conformance", []string{
					"TestCheckImplementationInvokesActualRendererAndRejectsRawNormalization",
					"TestCheckImplementationRejectsIncompleteSerializedExchange",
					"TestCheckImplementationRejectsIgnoredWriterOverflow",
					"TestCheckImplementationRefusesInvalidFixturesAndDetectsCallerMutation",
					"TestCheckImplementationRefusesCallbackBeforeJoin",
					"TestCheckImplementationClosesAdmissionBeforeDelayedUse",
					"TestCheckImplementationRejectsConcurrentDuplicateAuthorEntry",
					"TestCheckSettingsImplementationInvokesAuthorAndRejectsRawNormalization",
				})
			}
			runPublicKitTests(t, ctx, root, test.selector, ".", test.module, []string{test.test})
		})
	}
}

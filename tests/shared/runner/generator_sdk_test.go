package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// full_only: false
func TestIndependentGeneratorExampleBuildsFromPublicKit(t *testing.T) {
	maintained := maintainedCloudflareRoot(t)
	kit := t.TempDir()
	root := filepath.Join(kit, "implementation")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	selectors := []string{"sdk/artifact", "protocols/generator", "sdk/generator", "sdk/examples/testservice", "sdk/examples/local-token-generator"}
	copyPublicModuleKit(t, maintained, root, selectors)
	ctx, cancel := context.WithTimeout(cacheOnlyGoContext(testRaceContext(t, t.Context())), 2*time.Minute)
	defer cancel()
	const example = "sdk/examples/local-token-generator"
	flags := compilerBuildFlags([]string{"-mod=readonly"}, raceEnabled(ctx))
	modules, packages, err := listClosure(runGoEnvironment, ctx, root, example, flags, false, ".")
	if err != nil {
		t.Fatal(err)
	}
	if err := checkBoundary(example, modules, packages); err != nil {
		t.Fatal(err)
	}
	for _, selector := range selectors {
		if err := checkModuleSource(root, modules, selector); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(kit, "local-token-generator-example")
	buildFlags := compilerBuildFlags([]string{"-mod=readonly", "-trimpath", "-buildvcs=false"}, raceEnabled(ctx))
	if _, err := runGo(ctx, root, example, append(append([]string{"build"}, buildFlags...), "-o", binary, ".")...); err != nil {
		t.Fatal(err)
	}
	if observed, err := binaryRace(binary); err != nil || observed != raceEnabled(ctx) {
		t.Fatal("independent example race mode differs from executing test binary", observed, err)
	}
	checkPublicKitBuildInfo(t, binary, generatorExamplePath, map[string]string{
		"enkv.sh/sdk/artifact": "../../artifact",
		generatorSDKPath:       "../../generator",
		cloudflareProtocolPath: "../../protocols/generator",
	}, nil)
	runPublicKitTests(t, ctx, root, "sdk/generator", "./conformance", generatorSDKPath+"/conformance", []string{"TestSemanticFixtureReportsSafeBindingFailures", "TestAuthorCheckRandomValuePropertyAndExactWire", "TestAuthorCheckComparesProtocolMeaning", "TestServingConformanceUsesGenericImplementation", "TestAuthorCheckDetectsWrongRawReturnEvenWhenServingRefuses"})
	runPublicKitTests(t, ctx, root, example, ".", generatorExamplePath, []string{
		"TestCancelledCreateHasNoServiceEffect",
		"TestNormalizerOwnsDefaultsAndCanonicalSettings",
		"TestManagedTokenAuthorCheckUsesOwnHTTPBehavior",
		"TestManagedTokenRetiresExactOriginalResource",
		"TestCreateChecksResolvedNamespaceBeforeEffect",
		"TestLostCreateReplyRemainsUnknownWithoutRetry",
		"TestMalformedReturnedValueRetainsOwnedResource",
		"TestAuthorCheckDetectsChangedSubjectRequest",
	})
	plugin, err := sourcePath(root, "sdk/generator")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(plugin, plugin+"-missing"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := listClosure(runGoEnvironment, ctx, root, example, flags, false, "."); err == nil {
		t.Fatal("independent example escaped copied kit after a required module was removed")
	}
}

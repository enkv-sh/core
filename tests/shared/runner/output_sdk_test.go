package main

import (
	"context"
	"debug/buildinfo"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// full_only: false
func TestIndependentOutputExampleBuildsFromPublicKit(t *testing.T) {
	outer, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	outerRace, err := binaryRace(outer)
	if err != nil {
		t.Fatal(err)
	}
	kit := t.TempDir()
	root := filepath.Join(kit, "implementation")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	selectors := []string{"sdk/artifact", "protocols/output", "sdk/output", "sdk/examples/testservice", "sdk/examples/local-value-output"}
	copyPublicModuleKit(t, maintainedCloudflareRoot(t), root, selectors)
	ctx, cancel := context.WithTimeout(cacheOnlyGoContext(testRaceContext(t, t.Context())), 2*time.Minute)
	defer cancel()
	const example = "sdk/examples/local-value-output"
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
	runPublicKitTests(t, ctx, root, "sdk/output", "./conformance", outputSDKPath+"/conformance", []string{"TestCheckAcceptsSharedServing", "TestCheckRejectsInvalidServing", "TestSemanticFixtureOwnsHostCorrelation", "TestPublicAuthorCheckCoversSemanticOperations", "TestCheckImplementationRunsAuthorAndRejectsBadReturns", "TestCheckImplementationRejectsIgnoredResultOverflow"})
	runPublicKitTests(t, ctx, root, example, ".", outputExamplePath, []string{"TestLocalOutputOwnsCanonicalSettingsAndPhysicalIdentity", "TestLocalOutputCreatesWritesAndDeletesExactOwnedValue", "TestAuthorConformanceAndConsumerDetectWrongRequestPayload", "TestLocalOutputLostAcknowledgementDoesNotResend", "TestLocalOutputChecksCredentialNamespaceBeforePayload"})
	binary := filepath.Join(kit, "local-value-output-example")
	args := compilerBuildFlags([]string{"build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", binary}, raceEnabled(ctx))
	if _, err := runGo(ctx, root, example, append(args, ".")...); err != nil {
		t.Fatal(err)
	}
	observed, err := binaryRace(binary)
	if err != nil || observed != outerRace {
		t.Fatalf("public example lost the outer race setting: compiled=%t want=%t error=%v", observed, outerRace, err)
	}
	if err := os.Chmod(binary, 0700); err != nil {
		t.Fatal(err)
	}
	checkPublicKitBuildInfo(t, binary, outputExamplePath, map[string]string{
		"enkv.sh/sdk/artifact":         "../../artifact",
		outputSDKPath:                  "../../output",
		"enkv.sh/sdk/protocols/output": "../../protocols/output",
	}, nil)

	for _, selector := range selectors[:len(selectors)-1] {
		owner, err := sourcePath(root, selector)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(owner, owner+"-missing"); err != nil {
			t.Fatal(err)
		}
		_, _, missingErr := listClosure(runGoEnvironment, ctx, root, example, flags, false, ".")
		if err := os.Rename(owner+"-missing", owner); err != nil {
			t.Fatal(err)
		}
		if missingErr == nil {
			t.Fatal("kit resolved missing public source", selector)
		}
	}
}

func checkPublicKitBuildInfo(t *testing.T, binary, main string, local, remote map[string]string) {
	t.Helper()
	info, err := buildinfo.ReadFile(binary)
	if err != nil || info.GoVersion != "go1.27.3" || info.Path != main || info.Main.Path != main || info.Main.Version != "(devel)" || info.Main.Sum != "" || info.Main.Replace != nil {
		t.Fatal("public example build identity differs", err)
	}
	seen := make(map[string]bool, len(info.Deps))
	for _, dependency := range info.Deps {
		if seen[dependency.Path] {
			t.Fatal("duplicate public example dependency")
		}
		seen[dependency.Path] = true
		if replacement, ok := local[dependency.Path]; ok {
			version := "v0.1.1"
			if dependency.Path == "enkv.sh/sdk/protocols/output" || dependency.Path == "enkv.sh/sdk/examples/testservice" {
				version = "v0.1.0"
			}
			if dependency.Version != version || dependency.Sum != "" || dependency.Replace == nil || dependency.Replace.Path != replacement || dependency.Replace.Version != "(devel)" || dependency.Replace.Sum != "" || dependency.Replace.Replace != nil {
				t.Fatalf("public example local dependency differs: %+v", dependency)
			}
		} else if remote[dependency.Path] == "" || dependency.Version != remote[dependency.Path] || dependency.Sum == "" || dependency.Replace != nil {
			t.Fatalf("public example compiled dependency differs: %+v", dependency)
		}
	}
	for path := range local {
		if !seen[path] {
			t.Fatal("public example omitted required compiled dependency", path)
		}
	}
	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	if settings["-trimpath"] != "true" || settings["-tags"] != "" || settings["GOOS"] != runtime.GOOS || settings["GOARCH"] != runtime.GOARCH {
		t.Fatal("public example build settings differ")
	}
}

func runPublicKitTests(t *testing.T, ctx context.Context, root, selector, pattern, pkg string, tests []string) {
	t.Helper()
	ctx = testRaceContext(t, ctx)
	args := compilerBuildFlags([]string{"test", "-json", "-count=1", "-mod=readonly", "-run", "^(" + strings.Join(tests, "|") + ")$"}, raceEnabled(ctx))
	body, err := runGo(ctx, root, selector, append(args, pattern)...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateOrdinaryEvents(body, map[string][]string{pkg: tests}, nil); err != nil {
		t.Fatal("public kit conformance test evidence differs", err)
	}
}

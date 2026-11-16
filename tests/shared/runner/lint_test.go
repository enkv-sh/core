package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	records "enkv.sh/core/internal/testrecords"
	"errors"
	"fmt"
	"go/format"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func lintFixture(t *testing.T, directory string) (string, string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	root = filepath.Join(root, "implementation")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(filepath.Join("..", "..", "..", ".golangci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	writeLocalGoFixture(t, root, ".golangci.yml", string(config))
	moduleFiles := []string{
		"crypto/telemetry_test.mod", "providers/aws/telemetry_test.mod", "providers/gcp/telemetry_test.mod",
		"tests/hermetic/hermetic.mod", "tests/live/providers/aws/live.mod", "tests/live/providers/gcp/live.mod",
	}
	for _, module := range moduleRoots {
		moduleFiles = append(moduleFiles, module+"/go.mod")
		code := "package fixture\n"
		switch module {
		case "telemetry", "sdk/manifest-generator":
		case "sdk/output":
			code = "package output\n\nimport _ \"" + "enkv.sh/sdk/protocols/output\"\n"
		case "plugins/manifest-generators/generic-json", "plugins/manifest-generators/opentofu-tfvars-json":
			code = "package genericjson\n\nimport _ \"enkv.sh/sdk/manifest-generator\"\n"
		case "sdk/examples/local-value-output":
			code = "package main\n\nimport (\n _ \"enkv.sh/sdk/output\"\n _ \"" + "enkv.sh/sdk/examples/testservice\"\n)\n\nfunc main() {}\n"
		case "sdk/examples/ini-reference-manifest":
			code = "package main\n\nimport _ \"enkv.sh/sdk/manifest-generator\"\n\nfunc main() {}\n"
		case "sdk/generator":
			code = "package generator\n\nimport _ \"" + "enkv.sh/sdk/protocols/generator\"\n"
		case "sdk/examples/local-token-generator":
			code = "package main\n\nimport (\n\t_ \"enkv.sh/sdk/generator\"\n\t_ \"" + "enkv.sh/sdk/examples/testservice\"\n)\n\nfunc main() {}\n"
		case "protocols/generator":
			code = "package generator\n"
		case "protocols/output":
			code = "package output\n"
		case "plugins/cloudflare":
			code = "package cloudflare\n\nimport _ \"" + "enkv.sh/sdk/protocols/generator\"\n"
		case "plugins/output-contract-test":
			code = "package outputcontracttest\n\nimport _ \"" + "enkv.sh/sdk/protocols/output\"\n"
		case "plugins/github-output":
			code = "package githuboutput\n\nimport _ \"" + "enkv.sh/sdk/protocols/output\"\n"
		case "plugins/aws-output", "plugins/gcp-output":
			code = "package outputprovider\n\nimport _ \"" + "enkv.sh/sdk/protocols/output\"\n"
		case "core":
			code = "package core\n\nimport _ \"" + modulePrefix + "telemetry\"\n"
		case "crypto":
			code = "package crypto\n\nimport (\n\t_ \"" + modulePrefix + "compositions/generatorhost\"\n\t_ \"" + modulePrefix + "core/contract\"\n\t_ \"" + modulePrefix + "core/format\"\n\t_ \"" + "enkv.sh/sdk/protocols/generator\"\n\t_ \"" + modulePrefix + "telemetry\"\n)\n"
		case "compositions/generatorhost":
			code = "package generatorhost\n\nimport (\n\t_ \"" + modulePrefix + "core/contract\"\n\t_ \"" + "enkv.sh/sdk/protocols/generator\"\n)\n"
		case "compositions/outputhost":
			code = "package outputhost\n\nimport (\n\t_ \"" + "enkv.sh/sdk/protocols/output\"\n\t_ \"" + modulePrefix + "telemetry\"\n)\n"
		case "compositions/manifesthost":
			code = "package manifesthost\n\nimport (\n\t_ \"enkv.sh/sdk/artifact\"\n\t_ \"enkv.sh/sdk/manifest-generator\"\n\t_ \"enkv.sh/sdk/protocols/manifest-generator\"\n\t_ \"enkv.sh/telemetry\"\n)\n"
		case "compositions/configuration":
			code = "package configuration\n\nimport _ \"" + modulePrefix + "core/contract\"\n"
		case "compositions/observability":
			code = "package observability\n\nimport _ \"" + modulePrefix + "telemetry\"\n"
		default:
			if strings.HasPrefix(module, "compositions/") {
				code += "\nimport (\n\t_ \"" + modulePrefix + "compositions/generatorhost\"\n\t_ \"" + modulePrefix + "core\"\n\t_ \"" + modulePrefix + "core/contract\"\n\t_ \"" + modulePrefix + "core/format\"\n\t_ \"" + modulePrefix + "crypto\"\n)\n"
			} else if strings.HasPrefix(module, "providers/") {
				code += "\nimport _ \"" + modulePrefix + "core/contract\"\n"
			}
		}
		if module == "compositions/full" {
			code = strings.Replace(code, "package fixture\n", "package compositionfull\n", 1)
		}
		if module == "providers/gcp" {
			code = strings.Replace(code, "package fixture\n", "package gcp\n", 1)
		}
		// Analysis must type-check these packages without running application code.
		code += "\nfunc init() { panic(\"lint executed package code\") }\n"
		formatted, err := format.Source([]byte(code))
		if err != nil {
			t.Fatal(err)
		}
		writeLocalGoFixture(t, root, module+"/fixture.go", string(formatted))
	}
	// Module checks need the pinned graph; fixture source stays small and inert.
	for _, name := range moduleFiles {
		for _, source := range []string{name, strings.TrimSuffix(name, ".mod") + ".sum"} {
			physical, err := sourcePath(rootRepositoryForFixture(t), source)
			if err != nil {
				t.Fatal(err)
			}
			pinned, err := os.ReadFile(physical)
			if source != name && os.IsNotExist(err) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			writeLocalGoFixture(t, root, source, string(pinned))
		}
	}
	for _, module := range []string{"plugins/cloudflare", "plugins/aws-output", "plugins/gcp-output", "plugins/github-output"} {
		protocol := "output"
		if module == "plugins/cloudflare" {
			protocol = "generator"
		}
		writeLocalGoFixture(t, root, module+"/profile/fixture.go", "package profile\n\nimport _ \""+modulePath("protocols/"+protocol)+"\"\n\nfunc init() { panic(\"lint executed a profile\") }\n")
	}
	license := "Apache License\n                           Version 2.0\n"
	for _, source := range moduleSources {
		if source.Sibling == "enkv-extensions" {
			writeLocalGoFixture(t, root, source.Selector+"/LICENSE", license)
		}
	}
	writeLocalGoFixture(t, root, "plugins/cloudflare/internal/cloudflare/cloudflare.go", "package cloudflare\n")
	writeLocalGoFixture(t, root, "plugins/cloudflare/internal/cloudflare/testartifact.go", "//go:build enkv_cloudflare_testartifact\n\npackage cloudflare\n")
	writeLocalGoFixture(t, root, "plugins/cloudflare/cmd/enkv-generator-cloudflare/main.go", "package main\n\nimport _ \""+"enkv.sh/plugins/generators/cloudflare-account-token/internal/cloudflare\"\n\nfunc main() {}\n")
	writeLocalGoFixture(t, root, "plugins/cloudflare/cmd/enkv-generator-cloudflare-test/main.go", "//go:build enkv_cloudflare_testartifact\n\npackage main\n\nimport _ \""+"enkv.sh/plugins/generators/cloudflare-account-token/internal/cloudflare\"\n\nfunc main() {}\n")
	writeLocalGoFixture(t, root, "tests/crypto/admission.go", "package crypto\n")
	writeLocalGoFixture(t, root, "tests/crypto/cloudflare_process_test.go", "package crypto\n")
	writeLocalGoFixture(t, root, "tests/gcp/admission.go", "package gcp\n")
	writeLocalGoFixture(t, root, "tests/gcpcredentials/admission.go", "package credentials\n")
	writeLocalGoFixture(t, root, "providers/gcp/credentials/fixture.go", "package credentials\n\nfunc init() { panic(\"lint executed credentials\") }\n")
	writeLocalGoFixture(t, root, "tests/full/admission.go", "package compositionfull\n")
	writeLocalGoFixture(t, root, "tests/live/custody/output_box.go", "package custody\n")
	for _, admission := range records.TestAdmissionOverlays() {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, admission.Target)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"contract", "format"} {
		writeLocalGoFixture(t, root, "core/"+name+"/fixture.go", "package "+name+"\n")
	}
	for _, group := range []string{"tests/shared", "tests/hermetic", "tests/live/shared", "tests/live/runner"} {
		writeLocalGoFixture(t, root, group+"/fixture_test.go", "package core\n\nimport \"testing\"\n\nfunc TestFixture_"+strings.ReplaceAll(group, "/", "_")+"(t *testing.T) { panic(\"lint executed a test\") }\n")
	}
	for _, provider := range []string{"aws", "gcp"} {
		base := "tests/live/providers/" + provider
		writeLocalGoFixture(t, root, base+"/fixture_test.go", "package core\n\nimport _ \""+modulePrefix+"providers/"+provider+"\"\n")
	}
	replacements := map[string]string{}
	for _, item := range []struct{ source, target, name string }{
		{"runner", "testmain", "main"}, {"records", "testrecords", "records"}, {"catalog", "testcatalog", "catalog"},
	} {
		source := writeLocalGoFixture(t, root, "tests/shared/"+item.source+"/fixture.go", "package "+item.name+"\n\nfunc init() { panic(\"lint executed a tool\") }\n")
		replacements[filepath.Join(root, "core/internal", item.target, "fixture.go")] = source
	}
	cgo := writeLocalGoFixture(t, root, "tests/shared/runner/process_memory_darwin.go", "//go:build darwin && cgo\n\npackage main\n\n/*\nstatic int enkv_lint_cgo(void) { return 1; }\n*/\nimport \"C\"\n\nvar lintCgoValue = C.enkv_lint_cgo()\n")
	replacements[filepath.Join(root, "core/internal/testmain/process_memory_darwin.go")] = cgo
	for _, name := range []string{"tests/scripts/bootstrap.go", "tests/examples/telemetry/main.go"} {
		writeLocalGoFixture(t, root, name, "package main\n\nfunc main() { panic(\"lint executed a command\") }\n")
	}
	body, err := json.Marshal(struct{ Replace map[string]string }{replacements})
	if err != nil {
		t.Fatal(err)
	}
	overlay := filepath.Join(root, "bootstrap.json")
	if err := os.WriteFile(overlay, body, 0600); err != nil {
		t.Fatal(err)
	}
	return root, overlay
}

// A private Core operation may have its only caller in the hermetic source
// group. Lint must analyze that real test source without running it or init.
// full_only: false
func TestLintCoreHermeticCallerReachability(t *testing.T) {
	version, err := runGolangciLint(t.Context(), "", "", "version", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var tool struct{ Version string }
	if json.Unmarshal(version, &tool) != nil || tool.Version != golangciLintVersion {
		t.Fatal("lint tool version differs", string(version))
	}
	for _, unused := range []bool{false, true} {
		t.Run(fmt.Sprintf("unused=%t", unused), func(t *testing.T) {
			root, _ := lintFixture(t, t.TempDir())
			operation := "package core\n\nfunc sumPair(left, right int) int { return left + right }\n"
			if unused {
				operation += "\nfunc neverCalled(value int) int { return value + 1 }\n"
			}
			writeLocalGoFixture(t, root, "core/operation.go", operation)
			writeLocalGoFixture(t, root, "tests/shared/records/fixture.go", "package records\n\nconst Value = 2\n\nfunc init() { panic(\"lint executed a dependency\") }\n")
			writeLocalGoFixture(t, root, "tests/shared/catalog/fixture.go", "package catalog\n\nconst Value = 3\n\nfunc init() { panic(\"lint executed a dependency\") }\n")
			writeLocalGoFixture(t, root, "tests/hermetic/operation_test.go", "package core\n\nimport (\n\"testing\"\n\""+modulePrefix+"core/internal/testrecords\"\n\""+modulePrefix+"core/internal/testcatalog\"\n)\n\nfunc TestSumPair(t *testing.T) { if sumPair(records.Value, catalog.Value) != 5 { t.Fatal(\"sum differs\") }; panic(\"lint executed a test\") }\n")
			copyRoot, sources, err := buildLintAssembly(t.Context(), root, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			_, err = runGolangciLintWithFlags(t.Context(), copyRoot, "core", []string{"-mod=readonly", "-modfile=" + assemblyModfile(copyRoot, "hermetic", "memory")}, "run", "--config="+filepath.Join(copyRoot, ".golangci.yml"), "./...")
			if !unused && err != nil {
				t.Fatal("hermetic caller was not analyzed:", err)
			}
			if unused && (err == nil || !strings.Contains(err.Error(), "neverCalled is unused")) {
				t.Fatal("truly unused operation was not reported:", err)
			}
			if unused && strings.Contains(err.Error(), "sumPair is unused") {
				t.Fatal("hermetic caller disappeared in unused control:", err)
			}
			if err := verifyLintAssembly(t.Context(), root, copyRoot, sources); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// full_only: false
func TestLintCoreCgoCacheSurvivesRemovedPhysicalCopy(t *testing.T) {
	version, err := runGolangciLint(t.Context(), "", "", "version", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var tool struct{ Version string }
	if json.Unmarshal(version, &tool) != nil || tool.Version != golangciLintVersion {
		t.Fatal("lint tool version differs", string(version))
	}
	root, _ := lintFixture(t, t.TempDir())
	writeLocalGoFixture(t, root, "core/cgo_fixture.go", "package core\n\n/*\nstatic int enkv_lint_sum(int left, int right) { return left + right; }\n*/\nimport \"C\"\n\nfunc cgoSumPair(left, right int) int { return int(C.enkv_lint_sum(C.int(left), C.int(right))) }\n")
	writeLocalGoFixture(t, root, "tests/hermetic/cgo_fixture_test.go", "package core\n\nimport \"testing\"\n\nfunc TestCgoSumPair(t *testing.T) { if cgoSumPair(2, 3) != 5 { t.Fatal(\"sum differs\") }; panic(\"lint executed a CGo test\") }\n")
	directory, err := os.MkdirTemp("", "enkv-lint-cgo-cache-")
	if err != nil {
		t.Fatal(err)
	}
	var lastToolError error
	defer func() {
		if cleanupErr := finishLintAssembly(directory, lastToolError); cleanupErr != nil {
			t.Error("CGo cache fixture cleanup", cleanupErr)
		}
	}()
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	directory = canonical
	cache := filepath.Join(directory, "go-cache")
	if err := os.Mkdir(cache, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOCACHE", cache)
	t.Setenv("GOCACHEPROG", "")
	t.Setenv("GOLANGCI_LINT_CACHEPROG", "")
	var firstSources, firstDirectory, firstCopy string
	for i, phase := range []string{"first", "second", "unused"} {
		if phase == "unused" {
			writeLocalGoFixture(t, root, "core/unused_control.go", "package core\n\nfunc neverCalled(value int) int { return value + 1 }\n")
		}
		stage := filepath.Join(directory, phase)
		analysisCache := filepath.Join(directory, "analysis-"+phase)
		for _, path := range []string{stage, analysisCache} {
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
		}
		// A fresh analysis cache forces real analyzers to consume the shared
		// Go build cache; a prior successful lint result cannot hide the bug.
		t.Setenv("GOLANGCI_LINT_CACHE", analysisCache)
		copyRoot, sources, err := buildLintAssembly(t.Context(), root, stage)
		if err != nil {
			t.Fatal(err)
		}
		switch i {
		case 0:
			firstSources, firstDirectory, firstCopy = lintSourcesDigest(sources), stage, copyRoot
		case 1:
			if copyRoot == firstCopy || lintSourcesDigest(sources) != firstSources {
				t.Fatal("second CGo source copy is not identical at a different physical path")
			}
			if _, err := os.Lstat(firstDirectory); !os.IsNotExist(err) {
				t.Fatal("first joined CGo source copy was not removed", err)
			}
		}
		_, lastToolError = runGolangciLintWithFlags(t.Context(), copyRoot, "core", []string{"-mod=readonly", "-modfile=" + assemblyModfile(copyRoot, "hermetic", "memory")}, "run", "--config="+filepath.Join(copyRoot, ".golangci.yml"), "./...")
		if phase != "unused" && lastToolError != nil {
			t.Fatal("current physical CGo copy could not be analyzed", phase, lastToolError)
		}
		if phase == "unused" && (lastToolError == nil || !strings.Contains(lastToolError.Error(), "neverCalled is unused") || strings.Contains(lastToolError.Error(), "cgoSumPair is unused") || strings.Contains(lastToolError.Error(), "can't parse raw cgo file")) {
			t.Fatal("real unused control or hermetic CGo caller was not analyzed", lastToolError)
		}
		if !toolCommandsJoined(lastToolError) {
			t.Fatal("CGo lint tool did not join", lastToolError)
		}
		if err := verifyLintAssembly(t.Context(), root, copyRoot, sources); err != nil {
			t.Fatal(err)
		}
		lastToolError = nil // Any joined expected diagnostic is fully checked.
		if i == 0 {
			if err := finishLintAssembly(stage, nil); err != nil {
				t.Fatal("remove first joined CGo source copy", err)
			}
		}
	}
}

// full_only: false
func TestVetAssemblyCgoCacheSurvivesRemovedPhysicalCopy(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	directory, err := os.MkdirTemp("", "enkv-vet-cgo-cache-")
	if err != nil {
		t.Fatal(err)
	}
	var lastToolError error
	defer func() {
		if cleanupErr := finishLintAssembly(directory, lastToolError); cleanupErr != nil {
			t.Error("vet CGo cache fixture cleanup", cleanupErr)
		}
	}()
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	directory = canonical
	for _, name := range []string{"fixture", "warm", "vet", "control", "go-cache"} {
		if err := os.Mkdir(filepath.Join(directory, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	root, bootstrap := lintFixture(t, filepath.Join(directory, "fixture"))
	writeLocalGoFixture(t, root, "core/cgo_fixture.go", "package core\n\n/*\nstatic int enkv_vet_sum(int left, int right) { return left + right; }\n*/\nimport \"C\"\n\nfunc cgoSumPair(left, right int) int { return int(C.enkv_vet_sum(C.int(left), C.int(right))) }\n")
	writeLocalGoFixture(t, root, "tests/hermetic/cgo_fixture_test.go", "package core\n\nimport \"testing\"\n\nfunc TestCgoSumPair(t *testing.T) { if cgoSumPair(2, 3) != 5 { t.Fatal(\"sum differs\") }; panic(\"vet executed a CGo test\") }\n")
	t.Setenv("GOCACHE", filepath.Join(directory, "go-cache"))
	t.Setenv("GOCACHEPROG", "")
	warmDirectory := filepath.Join(directory, "warm")
	copyRoot, sources, err := buildLintAssembly(t.Context(), root, warmDirectory)
	if err != nil {
		t.Fatal(err)
	}
	// Warm the actual producer's compiled-source cache without any vet facts.
	var packages []compiledPackage
	_, packages, lastToolError = listClosure(runGoEnvironment, ctx, copyRoot, "core", []string{"-mod=readonly", "-modfile=" + assemblyModfile(copyRoot, "hermetic", "memory")}, true, ".")
	if lastToolError != nil {
		t.Fatal("physical CGo cache producer failed", lastToolError)
	}
	if !toolCommandsJoined(lastToolError) {
		t.Fatal("physical CGo cache producer did not join", lastToolError)
	}
	rawSourceCached := false
	for _, pkg := range packages {
		if pkg.ImportPath != componentPackage {
			continue
		}
		if len(pkg.CgoFiles) != 1 {
			t.Fatal("cache producer did not compile the actual Core CGo source")
		}
		for _, name := range pkg.CompiledGoFiles {
			if !filepath.IsAbs(name) {
				name = filepath.Join(pkg.Dir, name)
			}
			body, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			rawSourceCached = rawSourceCached || bytes.Contains(body, []byte(filepath.Join(copyRoot, "core/cgo_fixture.go")))
		}
	}
	if !rawSourceCached {
		t.Fatal("cache producer did not retain the physical raw CGo source path")
	}
	if err := verifyLintAssembly(t.Context(), root, copyRoot, sources); err != nil {
		t.Fatal(err)
	}
	if err := finishLintAssembly(warmDirectory, nil); err != nil {
		t.Fatal("remove joined physical CGo cache producer", err)
	}
	if _, err := os.Lstat(warmDirectory); !os.IsNotExist(err) {
		t.Fatal("physical CGo cache producer source remained", err)
	}
	_, _, lastToolError = vetAssembly(runGoEnvironment, ctx, root, "hermetic", "memory", bootstrap, filepath.Join(directory, "vet"))
	if lastToolError != nil {
		t.Fatal("current assembly could not analyze the shared CGo cache", lastToolError)
	}
	if !toolCommandsJoined(lastToolError) {
		t.Fatal("current assembly vet did not join", lastToolError)
	}
	for _, source := range sources {
		body, err := lintSourceBytes(root, source.Path)
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(body)) != source.SHA256 {
			t.Fatal("current fixture source changed during vet", err)
		}
	}
	writeLocalGoFixture(t, root, "tests/hermetic/vet_control_test.go", "package core\n\nimport (\"fmt\"; \"testing\")\n\nfunc TestInvalidPrintf(*testing.T) { fmt.Printf(\"%d\", \"wrong\") }\n")
	_, _, lastToolError = vetAssembly(runGoEnvironment, ctx, root, "hermetic", "memory", bootstrap, filepath.Join(directory, "control"))
	if lastToolError == nil || !strings.Contains(lastToolError.Error(), "fmt.Printf format %d") || strings.Contains(lastToolError.Error(), "can't parse raw cgo file") {
		t.Fatal("current assembly did not retain the real vet diagnostic", lastToolError)
	}
	if !toolCommandsJoined(lastToolError) {
		t.Fatal("current assembly diagnostic control did not join", lastToolError)
	}
	lastToolError = nil // The joined expected diagnostic is fully checked.
}

// full_only: false
func TestLintVetsDarwinCgoToolFromPhysicalAssembly(t *testing.T) {
	root, overlay := lintFixture(t, t.TempDir())
	copyRoot, sources, err := buildLintAssembly(t.Context(), root, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(copyRoot, "core/internal/testmain/process_memory_darwin.go")
	if err := vetLintTools(t.Context(), root, copyRoot, overlay); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatal("private cgo tool source remained after vet", err)
	}
	if err := verifyLintAssembly(t.Context(), root, copyRoot, sources); err != nil {
		t.Fatal(err)
	}
	for _, dependency := range []string{"core/internal/testrecords/fixture.go", "core/internal/testcatalog/fixture.go"} {
		path := filepath.Join(copyRoot, dependency)
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(body, []byte("\n// changed\n")...), 0600); err != nil {
			t.Fatal(err)
		}
		if err := vetLintTools(t.Context(), root, copyRoot, overlay); err == nil {
			t.Fatal("changed borrowed dependency accepted", dependency)
		}
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		if err := verifyLintAssembly(t.Context(), root, copyRoot, sources); err != nil {
			t.Fatal(err)
		}
	}

}

// full_only: false
func TestLintAssemblyCleanupRetainsUnjoinedToolFailure(t *testing.T) {
	for _, mode := range []string{"unjoined", "joined", "joined-first-unjoined-second"} {
		t.Run(mode, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "private-lint")
			if err := os.Mkdir(directory, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "physical-tool.go")
			if err := os.WriteFile(path, []byte("package main\n"), 0600); err != nil {
				t.Fatal(err)
			}
			failure := &toolFailure{operation: "go vet", process: processResult{
				Status: "group_stop_failed", Joined: mode == "joined", Cause: errors.New("settlement failed"),
			}}
			var cause error = failure
			if mode == "joined-first-unjoined-second" {
				cause = errors.Join(&toolFailure{operation: "earlier joined tool", process: processResult{Status: "process_failed", Joined: true}}, fmt.Errorf("later tool: %w", failure))
			}
			err := finishLintAssembly(directory, cause)
			if !errors.Is(err, failure) {
				t.Fatalf("vet failure lost: %v", err)
			}
			_, statErr := os.Lstat(path)
			if mode == "joined" {
				if !os.IsNotExist(statErr) {
					t.Fatalf("joined source remained: %v", statErr)
				}
			} else if statErr != nil || !strings.Contains(err.Error(), directory) {
				t.Fatalf("unjoined source or its location lost: %v; %v", statErr, err)
			}
		})
	}
}

// full_only: false
func TestLintResultPreservesProcessJoinThroughAssemblyCleanup(t *testing.T) {
	for _, joined := range []bool{false, true} {
		t.Run(fmt.Sprint("joined=", joined), func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "private-lint")
			if err := os.Mkdir(directory, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "physical-lint.go")
			body := []byte("package core\n")
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			cause := errors.New("controlled linter failure")
			process := processResult{Status: "group_stop_failed", Started: true, Joined: joined, Cause: cause}
			var stdout, stderr limitedOutput
			_, _ = stdout.Write([]byte("captured lint finding\n"))
			_, _ = stderr.Write([]byte("captured lint diagnostic\n"))
			_, conversion := golangciLintResult("core", process, &stdout, &stderr)
			err := finishLintAssembly(directory, conversion)
			if !errors.Is(err, cause) {
				t.Fatalf("linter cause lost: %v", err)
			}
			if joined {
				if _, statErr := os.Lstat(directory); !os.IsNotExist(statErr) {
					t.Fatalf("joined assembly remained: %v", statErr)
				}
				if !strings.Contains(err.Error(), stdout.String()) || !strings.Contains(err.Error(), stderr.String()) {
					t.Fatalf("joined linter diagnostics lost: %v", err)
				}
				return
			}
			retained, readErr := os.ReadFile(path)
			if readErr != nil || !bytes.Equal(retained, body) || !strings.Contains(err.Error(), directory) {
				t.Fatalf("unjoined assembly or its location lost: %v; %v", readErr, err)
			}
			var failure *toolFailure
			if !errors.As(err, &failure) || failure.process != process {
				t.Fatalf("linter process result lost: %v", err)
			}
		})
	}
}

// full_only: false
func TestLintVetsEverySourceOwnerWithoutExecutingFixtures(t *testing.T) {
	root, overlay := lintFixture(t, t.TempDir())
	temporary := t.TempDir()
	alias := filepath.Join(t.TempDir(), "temporary-alias")
	if err := os.Symlink(temporary, alias); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", alias)
	t.Setenv("GOWORK", "must-not-be-used.work")
	t.Run("prepared-bootstrap", func(t *testing.T) {
		ctx, err := withPreparationBootstrap(t.Context(), root, overlay)
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		if err := runCommand(ctx, root, overlay, []string{"lint"}, &output); err != nil {
			t.Fatalf("%v\n%s", err, output.String())
		}
		for _, module := range moduleRoots {
			if !strings.Contains(output.String(), "Checking golangci-lint "+module+" (including unit tests)") {
				t.Errorf("linter omitted module %s", module)
			}
		}
		for _, assembly := range []string{"hermetic memory", "live gcp", "live aws"} {
			if !strings.Contains(output.String(), "Checking vet for "+assembly+" assembly") {
				t.Errorf("linter omitted assembly %s", assembly)
			}
		}
	})
	// Each defect is a reachable test with a Printf mismatch for vet to reject.
	for _, item := range []struct{ path, name string }{
		{"telemetry/vet_test.go", "fixture"},
		{"compositions/full/vet_test.go", "compositionfull"},
		{"plugins/cloudflare/profile/vet_test.go", "profile"},
		{"tests/shared/runner/vet_test.go", "main"},
		{"tests/scripts/new_test.go", "main"},
		{"tests/examples/telemetry/new_test.go", "main"},
		{"tests/hermetic/vet_test.go", "core"},
		{"tests/live/providers/aws/vet_test.go", "core"},
		{"tests/live/providers/gcp/vet_test.go", "core"},
	} {
		t.Run(item.path, func(t *testing.T) {
			path, err := sourcePath(root, item.path)
			if err != nil {
				t.Fatal(err)
			}
			previous, readErr := os.ReadFile(path)
			if readErr != nil && !os.IsNotExist(readErr) {
				t.Fatal(readErr)
			}
			writeLocalGoFixture(t, root, item.path, "package "+item.name+"\n\nimport (\n\t\"fmt\"\n\t\"testing\"\n)\n\nfunc TestInvalidPrintf(*testing.T) { fmt.Printf(\"%d\", \"wrong\") }\n")
			if strings.Contains(item.path, "shared/runner/") {
				var record struct{ Replace map[string]string }
				body, err := os.ReadFile(overlay)
				if err != nil || json.Unmarshal(body, &record) != nil {
					t.Fatal("tool overlay fixture")
				}
				record.Replace[filepath.Join(root, "core/internal/testmain/vet_test.go")] = path
				updated, err := json.Marshal(record)
				if err != nil || os.WriteFile(overlay, updated, 0600) != nil {
					t.Fatal("tool overlay update")
				}
				t.Cleanup(func() {
					if err := os.WriteFile(overlay, body, 0600); err != nil {
						t.Error(err)
					}
				})
			}
			t.Cleanup(func() {
				if readErr == nil {
					if err := os.WriteFile(path, previous, 0600); err != nil {
						t.Error(err)
					}
				} else if err := os.Remove(path); err != nil {
					t.Error(err)
				}
			})
			err = runCommand(context.Background(), root, overlay, []string{"lint"}, io.Discard)
			if err == nil || !strings.Contains(err.Error(), "Printf format %d") {
				t.Fatalf("vet defect in %s was not reported: %v", item.path, err)
			}
			if _, err := os.Lstat(filepath.Join(root, "core/internal")); !os.IsNotExist(err) {
				t.Fatal("failed lint retained temporary Core directories")
			}
		})
	}
	for _, name := range []string{"core/internal", "tests/hermetic/runs", "tests/live/runs", "build"} {
		if _, err := os.Lstat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatalf("lint retained repository artifact %s", name)
		}
	}
	entries, err := os.ReadDir(temporary)
	if err != nil || len(entries) != 0 {
		t.Fatalf("lint retained current files under the temporary directory alias: entries=%v; read_error=%v", entries, err)
	}
}

// full_only: false
func TestLintCommandUsesResolvedExecutionCapacity(t *testing.T) {
	for _, row := range []struct {
		name                      string
		assigned, requested, want int
	}{
		{"parallel_1", 1, 1, 1},
		{"parallel_2", 2, 2, 2},
		{"parallel_3", 3, 3, 3},
		{"parallel_4", 4, 4, 4},
		{"parent_share_limits_request", 1, 4, 1},
	} {
		t.Run(row.name, func(t *testing.T) {
			root, overlay := lintFixture(t, t.TempDir())
			bin := t.TempDir()
			arguments := filepath.Join(bin, "arguments")
			goFlagsPath := filepath.Join(bin, "go-flags")
			tool := `#!/bin/sh
case "$1" in
 version) printf '%s\n' '{"version":"2.14.0"}' ;;
 run) printf '%s\n' "$@" > "$ENKV_TEST_LINT_ARGUMENTS"; printf '%s\n' "$GOFLAGS" > "$ENKV_TEST_LINT_GOFLAGS"; exit 7 ;;
 *) exit 8 ;;
esac
`
			if err := os.WriteFile(filepath.Join(bin, "golangci-lint"), []byte(tool), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("ENKV_TEST_LINT_ARGUMENTS", arguments)
			t.Setenv("ENKV_TEST_LINT_GOFLAGS", goFlagsPath)
			ctx := withExecutionParallel(t.Context(), row.assigned)
			err := runCommand(ctx, root, overlay, []string{"lint", fmt.Sprintf("--parallel=%d", row.requested)}, io.Discard)
			if err == nil || !toolCommandsJoined(err) || !strings.Contains(err.Error(), "exit status 7") {
				t.Fatal("lint did not reach the controlled, joined run refusal", err)
			}
			body, err := os.ReadFile(arguments)
			if err != nil {
				t.Fatal("lint run arguments unavailable", err)
			}
			args := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
			if len(args) != 4 || args[0] != "run" || args[1] != fmt.Sprintf("--concurrency=%d", row.want) || !strings.HasPrefix(args[2], "--config=") || filepath.Base(strings.TrimPrefix(args[2], "--config=")) != ".golangci.yml" || args[3] != "./..." {
				t.Fatalf("linter command does not apply the resolved parallel allowance: %q", args)
			}
			flagsBody, err := os.ReadFile(goFlagsPath)
			if err != nil {
				t.Fatal("linter Go build flags unavailable", err)
			}
			physicalPaths := false
			packageParallel := ""
			for _, value := range strings.Fields(string(flagsBody)) {
				if value == "-trimpath=false" {
					physicalPaths = true
				}
				if strings.HasPrefix(value, "-p=") {
					packageParallel = value
				}
			}
			if !physicalPaths || packageParallel != fmt.Sprintf("-p=%d", row.want) {
				t.Fatalf("linter Go flags lost physical paths or assigned parallel allowance: %q", flagsBody)
			}
		})
	}
}

// full_only: false
func TestLintRequiresPinnedStandaloneTool(t *testing.T) {
	for _, version := range []string{`{"version":"2.13.2"}`, `not-json`} {
		t.Run(version, func(t *testing.T) {
			root, bin := sourceFixtureRoot(t), t.TempDir()
			publicSourceFixtureOwners(t, root)
			tool := "#!/bin/sh\nprintf '%s\\n' '" + version + "'\n"
			if err := os.WriteFile(filepath.Join(bin, "golangci-lint"), []byte(tool), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin)
			if facts, err := runLint(context.Background(), root, "", io.Discard); facts != nil || err == nil || !strings.Contains(err.Error(), "v2.14.0 required") {
				t.Fatalf("invalid tool version accepted: %v", err)
			}
		})
	}
	t.Setenv("PATH", t.TempDir())
	root := sourceFixtureRoot(t)
	publicSourceFixtureOwners(t, root)
	if facts, err := runLint(context.Background(), root, "", io.Discard); facts != nil || err == nil || !strings.Contains(err.Error(), "v2.14.0 required") {
		t.Fatalf("missing tool accepted: %v", err)
	}
}

// full_only: false
func TestLintAssemblyIsExactPrivateSourceCopy(t *testing.T) {
	root, _ := lintFixture(t, t.TempDir())
	dependencies := []string{"tests/fixtures/consumer/node_modules", "protocols/generator/node_modules"}
	for _, directory := range dependencies {
		asset := writeLocalGoFixture(t, root, directory+"/installed/index.cjs", "module.exports = 'installed dependency';\n")
		link := filepath.Join(filepath.Dir(filepath.Dir(asset)), ".bin", "dotenv")
		if err := os.MkdirAll(filepath.Dir(link), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(asset, link); err != nil {
			t.Fatal(err)
		}
	}
	adjacent := []string{"tests/fixtures/consumer/node_modules-extra/fixture.go", "protocols/generator/node_modules-extra/fixture.go"}
	for _, name := range adjacent {
		writeLocalGoFixture(t, root, name, "package fixture\n\nconst Installed = false\n")
	}
	writeLocalGoFixture(t, root, "tests/live/runs/private/credential.go", "excluded run data")
	writeLocalGoFixture(t, root, "tests/workflows/runs/previous/snapshot/crypto/copied.go", "excluded workflow run data")
	writeLocalGoFixture(t, root, ".git/private.go", "excluded Git data")
	writeLocalGoFixture(t, root, "credentials.json", "excluded credential reference")
	copyRoot, sources, err := buildLintAssembly(t.Context(), root, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tests/live/runs", "tests/workflows/runs", ".git", "credentials.json", "core/internal/testmain"} {
		if _, err := os.Lstat(filepath.Join(copyRoot, name)); !os.IsNotExist(err) {
			t.Fatalf("copied excluded input %s", name)
		}
	}
	for _, name := range dependencies {
		path, err := sourcePath(copyRoot, name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("copied installed dependency tree %s", name)
		}
		for _, source := range sources {
			if strings.HasPrefix(source.Path, name+"/") {
				t.Fatalf("installed dependency entered lint source inventory: %s", source.Path)
			}
		}
	}
	for _, name := range adjacent {
		path, err := sourcePath(copyRoot, name)
		if err != nil {
			t.Fatal(err)
		}
		if body, err := os.ReadFile(path); err != nil || string(body) != "package fixture\n\nconst Installed = false\n" {
			t.Fatalf("adjacent maintained source was not copied: %s: %v", name, err)
		}
	}
	if len(lintSourcesDigest(sources)) != 64 {
		t.Fatal("source digest unavailable")
	}
	if err := verifyLintAssembly(t.Context(), root, copyRoot, sources); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ owner, path string }{
		{root, "protocols/generator/fixture.go"}, {copyRoot, "protocols/generator/fixture.go"},
		{root, "plugins/cloudflare/profile/fixture.go"}, {copyRoot, "plugins/cloudflare/profile/fixture.go"},
		{root, "crypto/fixture.go"}, {copyRoot, "crypto/fixture.go"}, {copyRoot, "crypto/zz_test_admission.go"},
		{copyRoot, "crypto/zz_test_cloudflare_process_test.go"},
		{copyRoot, "providers/gcp/zz_test_admission.go"},
		{copyRoot, "providers/gcp/credentials/zz_test_admission.go"},
		{copyRoot, "compositions/full/zz_test_admission.go"},
		{root, "tests/shared/fixture_test.go"}, {root, "tests/hermetic/fixture_test.go"},
		{copyRoot, "core/tests_shared_fixture_test.go"}, {copyRoot, "core/tests_hermetic_fixture_test.go"},
		{root, "tests/shared/records/fixture.go"}, {root, "tests/shared/catalog/fixture.go"},
		{copyRoot, "core/internal/testrecords/fixture.go"}, {copyRoot, "core/internal/testcatalog/fixture.go"},
	} {
		path, err := sourcePath(item.owner, item.path)
		if err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(body, []byte("\n// changed\n")...), 0600); err != nil {
			t.Fatal(err)
		}
		if err := verifyLintAssembly(t.Context(), root, copyRoot, sources); err == nil {
			t.Fatalf("source mutation accepted: %s", item.path)
		}
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeLocalGoFixture(t, copyRoot, "crypto/extra.go", "package crypto\n")
	if err := verifyLintAssembly(t.Context(), root, copyRoot, sources); err == nil {
		t.Fatal("extra assembled source accepted")
	}
	if _, _, err := buildLintAssembly(t.Context(), root, root); err == nil {
		t.Fatal("lint copy allowed inside checkout")
	}
	for _, target := range []string{
		"core/tests_shared_fixture_test.go", "core/tests_hermetic_fixture_test.go",
		"core/internal/testrecords/fixture.go", "core/internal/testcatalog/fixture.go",
	} {
		t.Run("collision/"+target, func(t *testing.T) {
			root, _ := lintFixture(t, t.TempDir())
			writeLocalGoFixture(t, root, target, "package core\n")
			if _, _, err := buildLintAssembly(t.Context(), root, t.TempDir()); err == nil {
				t.Fatal("lint source collision accepted", target)
			}
		})
	}

}

// full_only: false
func TestLintAssemblyRetainsEmbeddedArchiveSources(t *testing.T) {
	root, _ := lintFixture(t, t.TempDir())
	writeLocalGoFixture(t, root, "crypto/testsupport/installedarchive/archive.go", "package installedarchive\nimport \"embed\"\n//go:embed testdata/aws.json\nvar aws []byte\n//go:embed testdata/gcp.json\nvar gcp []byte\n//go:embed current.snapshot assets/*.chunk tree\nvar selected embed.FS\nfunc init() { panic(\"lint executed archive\") }\n")
	writeLocalGoFixture(t, root, "providers/gcp/embedded_test.go", "package gcp\nimport _ \"embed\"\n//go:embed testdata/trust-v8-gcp.json\nvar trustFixture []byte\n//go:embed internal.fixture\nvar internalFixture []byte\n")
	writeLocalGoFixture(t, root, "providers/gcp/embedded_external_test.go", "package gcp_test\nimport _ \"embed\"\n//go:embed external.fixture\nvar externalFixture []byte\nfunc init() { panic(\"lint executed external test\") }\n")
	fixtures := map[string]string{
		"crypto/testsupport/installedarchive/testdata/aws.json":       "{\"synthetic_archive\":\"aws\"}\n",
		"crypto/testsupport/installedarchive/testdata/gcp.json":       "{\"synthetic_archive\":\"gcp\"}\n",
		"crypto/testsupport/installedarchive/current.snapshot":        "synthetic extension-independent embed\x00\xff\n",
		"crypto/testsupport/installedarchive/assets/first.chunk":      "synthetic first glob asset\n",
		"crypto/testsupport/installedarchive/assets/second.chunk":     "synthetic second glob asset\n",
		"crypto/testsupport/installedarchive/tree/one.content":        "synthetic directory asset\n",
		"crypto/testsupport/installedarchive/tree/deeper/two.content": "synthetic recursive directory asset\n",
		"providers/gcp/internal.fixture":                              "synthetic internal test embed\n",
		"providers/gcp/external.fixture":                              "synthetic external test embed\n",
		"providers/gcp/testdata/trust-v8-gcp.json":                    "{\"synthetic_provider\":true}\n",
		"providers/gcp/testdata/nested/fixture.txt":                   "synthetic nested asset\n",
		// This Go source is already returned by maintainedGoFiles. Its
		// containing package and ancestor testdata walk must not duplicate it.
		"providers/gcp/testdata/helper/main.go": "package main\nfunc main() {}\n",
	}
	for path, body := range fixtures {
		writeLocalGoFixture(t, root, path, body)
	}
	unrelated := []string{"crypto/testsupport/installedarchive/unselected.credential", "providers/gcp/unselected.credential"}
	for _, path := range unrelated {
		writeLocalGoFixture(t, root, path, "unselected synthetic bytes\n")
	}
	copyRoot, sources, err := buildLintAssembly(t.Context(), root, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for path, expected := range fixtures {
		copied, err := os.ReadFile(filepath.Join(copyRoot, path))
		if err != nil || string(copied) != expected {
			t.Fatal("testdata source omitted or changed", path, err)
		}
		count := 0
		digest := sha256.Sum256([]byte(expected))
		for _, item := range sources {
			if item.Path == path {
				count++
				if item.SHA256 != fmt.Sprintf("%x", digest) {
					t.Fatal("testdata source hash changed", path)
				}
			}
		}
		if count != 1 {
			t.Fatal("testdata source must have exactly one hash manifest row", path, count)
		}
	}
	for _, path := range unrelated {
		if _, err := os.Lstat(filepath.Join(copyRoot, path)); !os.IsNotExist(err) {
			t.Fatal("unselected sibling asset copied", path, err)
		}
		for _, source := range sources {
			if source.Path == path {
				t.Fatal("unselected sibling asset entered source manifest", path)
			}
		}
	}
	if err := verifyLintAssembly(t.Context(), root, copyRoot, sources); err != nil {
		t.Fatal(err)
	}
	for path, expected := range fixtures {
		for _, owner := range []string{root, copyRoot} {
			physical := filepath.Join(owner, path)
			if err := os.WriteFile(physical, []byte("changed"), 0600); err != nil {
				t.Fatal(err)
			}
			if verifyLintAssembly(t.Context(), root, copyRoot, sources) == nil {
				t.Fatal("testdata source mutation admitted", owner, path)
			}
			if err := os.WriteFile(physical, []byte(expected), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, extra := range []string{"providers/gcp/testdata/nested/extra.txt", "crypto/testsupport/installedarchive/assets/extra.chunk"} {
		for _, owner := range []string{root, copyRoot} {
			path := filepath.Join(owner, extra)
			if err := os.WriteFile(path, []byte("synthetic extra"), 0600); err != nil {
				t.Fatal(err)
			}
			if verifyLintAssembly(t.Context(), root, copyRoot, sources) == nil {
				t.Fatal("extra selected asset admitted", owner, extra)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := verifyLintAssembly(t.Context(), root, copyRoot, sources); err != nil {
		t.Fatal("restored testdata source refused", err)
	}
}

func rootRepositoryForFixture(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func verifyLintAssembly(ctx context.Context, root, assemblyRoot string, sources []lintSource) error {
	return verifyLintAssemblyWithFailures(ctx, root, assemblyRoot, sources, nil)
}

func verifyLintAssemblyWithFailures(ctx context.Context, root, assemblyRoot string, sources []lintSource, unavailable map[string]error) error {
	files, err := lintSourcePathsForModules(ctx, root, unavailable, nil)
	if err != nil {
		return fmt.Errorf("lint source set unavailable: %w", err)
	}
	if len(files) != len(sources) {
		return errors.New("lint source set changed")
	}
	assembled, err := lintSourcePathsForModules(ctx, assemblyRoot, unavailable, nil)
	if err != nil {
		return fmt.Errorf("lint assembly source set unavailable: %w", err)
	}
	replacements, replacementErr := lintReplacements(root)
	if replacementErr != nil {
		return replacementErr
	}
	expected := slices.Clone(files)
	for target := range replacements {
		relative, relativeErr := filepath.Rel(root, target)
		if relativeErr != nil {
			return relativeErr
		}
		expected = append(expected, filepath.ToSlash(relative))
	}
	slices.Sort(expected)
	if !slices.Equal(assembled, expected) {
		return errors.New("lint assembly source set changed")
	}
	for i, source := range sources {
		if files[i] != source.Path {
			return errors.New("lint source set changed")
		}
		for _, owner := range []string{root, assemblyRoot} {
			body, err := lintSourceBytes(owner, source.Path)
			sum := sha256.Sum256(body)
			if err != nil || hex.EncodeToString(sum[:]) != source.SHA256 {
				return errors.New("lint source changed")
			}
		}
	}
	for target, source := range replacements {
		relativeTarget, relativeErr := filepath.Rel(root, target)
		relativeSource, sourceRelativeErr := filepath.Rel(root, source)
		if relativeErr != nil || sourceRelativeErr != nil {
			return errors.New("lint overlay path differs")
		}
		admission, err := lintSourceBytes(assemblyRoot, relativeTarget)
		original, sourceErr := lintSourceBytes(root, relativeSource)
		if err != nil || sourceErr != nil || string(admission) != string(original) {
			return errors.New("lint source differs from exact overlay")
		}
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			return errors.New("lint overlay reached checkout")
		}
	}
	return nil
}

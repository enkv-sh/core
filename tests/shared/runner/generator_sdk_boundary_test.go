package main

import (
	"maps"
	"path/filepath"
	"strings"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestGeneratorServingStaysOutsidePrivateComponents(t *testing.T) {
	modules := []resolvedModule{{Path: generatorSDKPath, Version: "v0.1.1"}}
	for _, owner := range []string{"core", "crypto", "compositions/generatorhost", "compositions/full", "live", "hermetic"} {
		if err := checkGeneratorServingBoundary(owner, modules, nil); err != nil {
			t.Fatal("passive module metadata refused", err)
		}
		for _, imported := range []string{generatorSDKPath, generatorSDKPath + "/conformance", generatorExamplePath} {
			if checkGeneratorServingBoundary(owner, modules, []compiledPackage{{ImportPath: imported}}) == nil {
				t.Fatalf("%s admitted child serving %s", owner, imported)
			}
		}
	}
	modules[0].Version = "v0.1.0"
	if checkGeneratorServingBoundary("crypto", modules, nil) == nil {
		t.Fatal("passive SDK metadata version drift admitted")
	}
}

// full_only: false
func TestGeneratorAuthorBoundaryRequiresCompletePublicClosure(t *testing.T) {
	modules := []resolvedModule{
		{Path: generatorSDKPath},
		{Path: "enkv.sh/sdk/artifact", Version: "v0.1.1", Replace: &resolvedModule{Path: "../artifact"}},
		{Path: cloudflareProtocolPath, Version: "v0.1.1", Replace: &resolvedModule{Path: "../protocols/generator"}},
	}
	packages := []compiledPackage{{ImportPath: generatorSDKPath}, {ImportPath: cloudflareProtocolPath}, {ImportPath: "context", Standard: true}}
	if err := checkBoundary("sdk/generator", modules, packages); err != nil {
		t.Fatal(err)
	}
	if checkBoundary("sdk/generator", modules[:1], packages) == nil {
		t.Fatal("missing protocol admitted")
	}
	for _, name := range []string{modulePrefix + "core/contract", "enkv.sh/plugins/generators/cloudflare-account-token", "go.opentelemetry.io/otel/sdk", "example.invalid/third-party"} {
		if checkBoundary("sdk/generator", modules, append(packages, compiledPackage{ImportPath: name})) == nil {
			t.Fatal("SDK imported a nonpublic dependency", name)
		}
	}
	for _, owner := range []string{"plugins/local-random-secret", "sdk/examples/local-token-generator"} {
		t.Run(owner, func(t *testing.T) {
			main, local, _ := authorModuleDependencies(owner)
			mods := []resolvedModule{{Path: main}}
			pkgs := []compiledPackage{{ImportPath: main}, {ImportPath: generatorSDKPath}, {ImportPath: generatorSDKPath + "/conformance"}, {ImportPath: cloudflareProtocolPath}}
			for path, replacement := range local {
				version := "v0.1.1"
				if path == "enkv.sh/sdk/examples/testservice" {
					version = "v0.1.0"
				}
				mods = append(mods, resolvedModule{Path: path, Version: version, Replace: &resolvedModule{Path: replacement}})
			}
			if err := checkBoundary(owner, mods, pkgs); err != nil {
				t.Fatal("local author closure refused", err)
			}
			if checkBoundary(owner, mods[:len(mods)-1], pkgs) == nil {
				t.Fatal("missing local author owner admitted")
			}
			for _, name := range []string{modulePrefix + "core/contract", "enkv.sh/plugins/generators/cloudflare-account-token/profile", "example.invalid/dependency"} {
				if checkBoundary(owner, mods, append(pkgs, compiledPackage{ImportPath: name})) == nil {
					t.Fatal("local author gained another owner", name)
				}
			}
			mods[1].Version = "v0.0.1"
			if checkBoundary(owner, mods, pkgs) == nil {
				t.Fatal("local author SDK pin changed")
			}
		})
	}
	modules[2].Replace.Path = "../other-protocol"
	if checkBoundary("sdk/generator", modules, packages) == nil {
		t.Fatal("substituted protocol replacement admitted")
	}
}

// full_only: false
func TestAssemblyFailureSourcesSkipMetadataOnlyModules(t *testing.T) {
	root, overlay, build := overlayFixture(t)
	writeLocalGoFixture(t, root, "core/selected.go", "package core\n")
	writeLocalGoFixture(t, root, "sdk/generator/process.go", "package generator\n")
	writeLocalGoFixture(t, root, "plugins/cloudflare/execute.go", "package cloudflare\n")
	closure := assemblyClosure{
		BinarySHA256: strings.Repeat("a", 64), OverlaySHA256: strings.Repeat("b", 64),
		ResolvedModules: []moduleIdentity{{Path: modulePrefix + "core", Version: "local"}, {Path: generatorSDKPath, Version: "v0.1.0"}, {Path: cloudflareModulePath, Version: "v0.1.0"}},
		CompiledImports: []string{modulePrefix + "core"},
	}
	binding, err := buildFailureSources(root, overlay, build, closure)
	if err != nil {
		t.Fatal("metadata-only module changed failure source evidence", err)
	}
	sources, err := records.ReadFailureSources(*binding)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{modulePrefix + "core/selected.go": "core/selected.go"}
	if !maps.Equal(sources.Paths, want) {
		t.Fatalf("uncompiled module files entered failure mapping: %v", sources.Paths)
	}
	if !strings.HasPrefix(binding.Path, filepath.Clean(build)) {
		t.Fatal("source map escaped build owner")
	}
}

// full_only: false
func TestAssemblyFailureSourcesSkipUncompiledPackageRoots(t *testing.T) {
	root, overlay, build := overlayFixture(t)
	writeLocalGoFixture(t, root, "plugins/cloudflare/execute.go", "package cloudflare\n")
	writeLocalGoFixture(t, root, "plugins/cloudflare/profile/semantics.go", "package profile\n")
	closure := assemblyClosure{
		BinarySHA256: strings.Repeat("a", 64), OverlaySHA256: strings.Repeat("b", 64),
		ResolvedModules: []moduleIdentity{{Path: cloudflareModulePath, Version: "v0.1.0"}},
		CompiledImports: []string{cloudflareModulePath + "/profile"},
	}
	binding, err := buildFailureSources(root, overlay, build, closure)
	if err != nil {
		t.Fatal(err)
	}
	sources, err := records.ReadFailureSources(*binding)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{cloudflareModulePath + "@v0.1.0/profile/semantics.go": "plugins/cloudflare/profile/semantics.go"}
	if !maps.Equal(sources.Paths, want) {
		t.Fatal("uncompiled executable package entered passive mapping", sources.Paths)
	}
}

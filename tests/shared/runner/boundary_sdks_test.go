package main

import "testing"

// full_only: false
func TestLiveManifestConsumerBoundaryRequiresIndependentTestLeaf(t *testing.T) {
	consumer := manifestExamplePath + "/consumer"
	fixture := func() []compiledPackage {
		return []compiledPackage{
			{ImportPath: modulePrefix + "core [enkv.sh/core.test]", ForTest: modulePrefix + "core", Imports: []string{consumer}},
			{ImportPath: consumer, Imports: []string{"io"}},
			{ImportPath: "io", Standard: true},
		}
	}
	if err := checkSDKBoundaries("live", nil, fixture()); err != nil {
		t.Fatal("independent live qualification consumer refused", err)
	}
	for _, provider := range []string{"aws", "gcp"} {
		t.Run("combined-gates/"+provider, func(t *testing.T) {
			modules := []resolvedModule{{Path: modulePrefix + "core"}, {Path: modulePrefix + "providers/" + provider, Version: "v0.1.0"}, {Path: manifestExamplePath, Version: "v0.1.0"}, {Path: "enkv.sh/sdk/artifact", Version: "v0.1.0"}}
			packages := append(fixture(), compiledPackage{ImportPath: modulePrefix + "providers/" + provider},
				compiledPackage{ImportPath: modulePrefix + "core/internal/testrecords", Imports: []string{"enkv.sh/sdk/artifact"}}, compiledPackage{ImportPath: "enkv.sh/sdk/artifact"})
			if err := checkLiveBoundary(provider, modules, packages); err != nil {
				t.Fatal("approved live graph failed a combined admission owner", err)
			}
			if err := checkCustodyImports(packages, true, provider); err != nil {
				t.Fatal("approved Core test edge failed direct custody admission", err)
			}
			if checkCustodyImports(packages, false, provider) == nil || checkCustodyImports(packages, true, "") == nil || checkHermeticBoundary(modules, packages) == nil || checkBoundary("core", modules, packages) == nil {
				t.Fatal("live consumer escaped to production or hermetic admission")
			}
			for _, caller := range []compiledPackage{
				{ImportPath: modulePrefix + "core", Imports: []string{consumer}},
				{ImportPath: modulePrefix + "core", ForTest: modulePrefix + "other", Imports: []string{consumer}},
				{ImportPath: modulePrefix + "core/internal/testrecords", ForTest: modulePrefix + "core/internal/testrecords", Imports: []string{consumer}},
			} {
				changed := append([]compiledPackage(nil), packages...)
				changed[0] = caller
				if checkCustodyImports(changed, true, provider) == nil || checkLiveBoundary(provider, modules, changed) == nil {
					t.Fatal("combined live gates admitted the wrong consumer caller", caller.ImportPath, caller.ForTest)
				}
			}
			for _, imported := range []string{manifestExamplePath, consumer + "/nested", outputExamplePath + "/consumer"} {
				changed := append([]compiledPackage(nil), packages...)
				changed[0].Imports = []string{imported}
				changed[1].ImportPath = imported
				if checkCustodyImports(changed, true, provider) == nil || checkLiveBoundary(provider, modules, changed) == nil {
					t.Fatal("combined live gates admitted another example package", imported)
				}
			}
			for _, imported := range []string{manifestSDKPath, manifestSDKPath + "/native", "example.invalid/parser"} {
				changed := append([]compiledPackage(nil), packages...)
				changed[1].Imports = []string{imported}
				changed = append(changed, compiledPackage{ImportPath: imported})
				if checkCustodyImports(changed, true, provider) == nil || checkLiveBoundary(provider, modules, changed) == nil {
					t.Fatal("a later gate lost the consumer's standard-only closure", imported)
				}
			}
		})
	}
	for _, owner := range []string{"core", "crypto", "providers/aws", "providers/gcp", "compositions/full", "compositions/manifesthost", "hermetic", "sdk/generator", "sdk/output", "sdk/manifest-generator", "sdk/artifact", "protocols/manifest-generator", "sdk/examples/local-token-generator"} {
		if checkSDKBoundaries(owner, nil, fixture()) == nil {
			t.Fatal("independent live consumer reached another owner", owner)
		}
	}
	for _, path := range []string{manifestExamplePath, manifestExamplePath + "/sibling", consumer + "/nested", outputExamplePath + "/consumer", generatorExamplePath + "/consumer"} {
		packages := fixture()
		packages[0].Imports = []string{path}
		packages[1].ImportPath = path
		if checkSDKBoundaries("live", nil, packages) == nil {
			t.Fatal("live leaf exemption widened to an example or subpackage", path)
		}
	}
	for _, helper := range []string{manifestExamplePath, manifestSDKPath, manifestSDKPath + "/native", manifestSDKPath + "/jsonwriter", "example.invalid/provider-client"} {
		packages := fixture()
		packages[1].Imports = []string{helper}
		packages = append(packages, compiledPackage{ImportPath: helper})
		if checkSDKBoundaries("live", nil, packages) == nil {
			t.Fatal("independent parser acquired a renderer, SDK or other helper", helper)
		}
	}
	missing := fixture()[:2]
	if checkSDKBoundaries("live", nil, missing) == nil {
		t.Fatal("consumer dependency was assumed standard without compiled facts")
	}
	for _, caller := range []compiledPackage{
		{ImportPath: modulePrefix + "core", Imports: []string{consumer}},
		{ImportPath: modulePrefix + "providers/aws", ForTest: modulePrefix + "providers/aws", Imports: []string{consumer}},
		{ImportPath: manifestSDKPath, Imports: []string{consumer}},
	} {
		packages := fixture()
		packages[0] = caller
		if checkSDKBoundaries("live", nil, packages) == nil {
			t.Fatal("live consumer exemption reached a production or unrelated test caller", caller.ImportPath)
		}
	}
}

// full_only: false
func TestTestRecordsArtifactMetadataBoundaryIsExact(t *testing.T) {
	const records = modulePrefix + "core/internal/testrecords"
	const metadata = "enkv.sh/sdk/artifact"
	for _, provider := range []string{"", "aws", "gcp"} {
		for _, variant := range []bool{false, true} {
			pkg := compiledPackage{ImportPath: records, Imports: []string{metadata}}
			if variant {
				pkg.ImportPath += " [" + records + ".test]"
				pkg.ForTest = records
			}
			packages := []compiledPackage{pkg, {ImportPath: metadata}}
			if err := checkCustodyImports(packages, true, provider); err != nil {
				t.Fatal("test-only records metadata refused", provider, variant, err)
			}
			if checkCustodyImports(packages, false, provider) == nil {
				t.Fatal("records metadata became a production import", provider, variant)
			}
			for _, owner := range []string{records + "/nested", modulePrefix + "core/internal/otherrecords", modulePrefix + "core/internal/testcatalog"} {
				changed := pkg
				changed.ImportPath, changed.ForTest = owner, owner
				if checkCustodyImports([]compiledPackage{changed, {ImportPath: metadata}}, true, provider) == nil {
					t.Fatal("records metadata allowance reached a different test owner", owner)
				}
			}
			for _, imported := range []string{metadata + "/build", metadata + "/sign", metadata + "/cmd/enkv-plugin-build", metadata + "/cmd/enkv-artifact-sign", metadata + "/unreviewed"} {
				changed := pkg
				changed.Imports = []string{imported}
				if checkCustodyImports([]compiledPackage{changed, {ImportPath: imported}}, true, provider) == nil || checkSDKBoundaries("live", nil, []compiledPackage{changed, {ImportPath: imported}}) == nil {
					t.Fatal("passive metadata allowance reached an author tool or subpackage", imported)
				}
			}
		}
	}
}

// full_only: false
func TestSDKModulesUseExactRegisteredSourceOwners(t *testing.T) {
	for _, row := range []struct{ selector, module string }{
		{"sdk/artifact", "enkv.sh/sdk/artifact"},
		{"sdk/output", "enkv.sh/sdk/output"},
		{"sdk/manifest-generator", "enkv.sh/sdk/manifest-generator"},
		{"plugins/manifest-generators/generic-json", "enkv.sh/plugins/manifest-generators/generic-json"},
		{"plugins/manifest-generators/opentofu-tfvars-json", "enkv.sh/plugins/manifest-generators/opentofu-tfvars-json"},
		{"sdk/examples/local-token-generator", "enkv.sh/sdk/examples/local-token-generator"},
		{"sdk/examples/testservice", "enkv.sh/sdk/examples/testservice"},
		{"sdk/examples/local-value-output", "enkv.sh/sdk/examples/local-value-output"},
		{"sdk/examples/ini-reference-manifest", "enkv.sh/sdk/examples/ini-reference-manifest"},
	} {
		source, ok := registeredModule(row.selector)
		if !ok || source.Module != row.module || source.Sibling != "enkv-extensions" || source.Directory != row.selector {
			t.Fatal("public SDK source registration differs", row.selector)
		}
	}
}

// full_only: false
func TestSDKAuthorBoundariesRequireCompletePublicClosures(t *testing.T) {
	for _, test := range []struct {
		owner, main   string
		local, remote map[string]string
	}{
		{"sdk/artifact", "enkv.sh/sdk/artifact", nil, nil},
		{"protocols/generator", "enkv.sh/sdk/protocols/generator", nil, nil},
		{"protocols/output", "enkv.sh/sdk/protocols/output", nil, nil},
		{"sdk/examples/testservice", "enkv.sh/sdk/examples/testservice", nil, nil},
		{"sdk/output", "enkv.sh/sdk/output", map[string]string{"enkv.sh/sdk/artifact": "../artifact", "enkv.sh/sdk/protocols/output": "../protocols/output"}, nil},
		{"sdk/manifest-generator", "enkv.sh/sdk/manifest-generator", map[string]string{"enkv.sh/sdk/artifact": "../artifact", "enkv.sh/sdk/protocols/manifest-generator": "../protocols/manifest-generator"}, nil},
		{"protocols/manifest-generator", "enkv.sh/sdk/protocols/manifest-generator", map[string]string{"enkv.sh/sdk/artifact": "../../artifact", "enkv.sh/sdk/manifest-generator": "../../manifest-generator"}, nil},
		{"plugins/manifest-generators/generic-json", "enkv.sh/plugins/manifest-generators/generic-json", map[string]string{"enkv.sh/sdk/artifact": "../../../sdk/artifact", "enkv.sh/sdk/manifest-generator": "../../../sdk/manifest-generator", "enkv.sh/sdk/protocols/manifest-generator": "../../../sdk/protocols/manifest-generator"}, nil},
		{"plugins/manifest-generators/opentofu-tfvars-json", "enkv.sh/plugins/manifest-generators/opentofu-tfvars-json", map[string]string{"enkv.sh/sdk/artifact": "../../../sdk/artifact", "enkv.sh/sdk/manifest-generator": "../../../sdk/manifest-generator", "enkv.sh/sdk/protocols/manifest-generator": "../../../sdk/protocols/manifest-generator"}, nil},
		{"sdk/examples/local-value-output", "enkv.sh/sdk/examples/local-value-output", map[string]string{"enkv.sh/sdk/artifact": "../../artifact", "enkv.sh/sdk/output": "../../output", "enkv.sh/sdk/protocols/output": "../../protocols/output", "enkv.sh/sdk/examples/testservice": "../testservice"}, nil},
		{"sdk/examples/ini-reference-manifest", "enkv.sh/sdk/examples/ini-reference-manifest", map[string]string{"enkv.sh/sdk/artifact": "../../artifact", "enkv.sh/sdk/manifest-generator": "../../manifest-generator", "enkv.sh/sdk/protocols/manifest-generator": "../../protocols/manifest-generator"}, nil},
	} {
		t.Run(test.owner, func(t *testing.T) {
			owner, main, local, remote := test.owner, test.main, test.local, test.remote
			modules := []resolvedModule{{Path: main}}
			packages := []compiledPackage{{ImportPath: main}, {ImportPath: "context", Standard: true}}
			for path, replacement := range local {
				modules = append(modules, resolvedModule{Path: path, Version: "v0.1.0", Replace: &resolvedModule{Path: replacement}})
				packages = append(packages, compiledPackage{ImportPath: path})
			}
			for path, version := range remote {
				modules = append(modules, resolvedModule{Path: path, Version: version})
			}
			if err := checkBoundary(owner, modules, packages); err != nil {
				t.Fatal(err)
			}
			if checkBoundary(owner, append(modules, modules[0]), packages) == nil {
				t.Fatal("duplicate module admitted")
			}
			if checkBoundary(owner, modules[1:], packages) == nil {
				t.Fatal("missing main module admitted")
			}
			for _, path := range []string{modulePrefix + "core/contract", modulePrefix + "crypto", modulePrefix + "compositions/outputhost", "enkv.sh/tests/fixtures/output-contract-test", modulePrefix + "core/internal/testrecords", "example.invalid/dependency"} {
				if checkBoundary(owner, append(modules, resolvedModule{Path: path}), packages) == nil {
					t.Fatal("private or unreviewed resolved dependency admitted", path)
				}
				if checkBoundary(owner, modules, append(packages, compiledPackage{ImportPath: path})) == nil {
					t.Fatal("private or unreviewed compiled dependency admitted", path)
				}
			}
			for i := 1; i < len(modules); i++ {
				bad := append([]resolvedModule(nil), modules...)
				bad[i].Version = "v0.0.1"
				if checkBoundary(owner, bad, packages) == nil {
					t.Fatal("version drift admitted", bad[i].Path)
				}
				bad = append([]resolvedModule(nil), modules...)
				bad[i].Replace = &resolvedModule{Path: "../substituted"}
				if checkBoundary(owner, bad, packages) == nil {
					t.Fatal("replacement drift admitted", bad[i].Path)
				}
				bad = append([]resolvedModule(nil), modules...)
				bad = append(bad[:i], bad[i+1:]...)
				if checkBoundary(owner, bad, packages) == nil {
					t.Fatal("missing dependency admitted", modules[i].Path)
				}
			}
		})
	}
}

// full_only: false
func TestPublicSDKClosuresExcludeOfficialAndPrivateImplementations(t *testing.T) {
	for _, owner := range []string{"sdk/generator", "sdk/output", "sdk/manifest-generator", "sdk/artifact", "protocols/generator", "protocols/output", "protocols/manifest-generator", "sdk/examples/local-token-generator", "sdk/examples/local-value-output", "sdk/examples/ini-reference-manifest", "sdk/examples/testservice"} {
		for _, path := range []string{"enkv.sh/plugins/generators/local-random-secret/profile", "enkv.sh/plugins/generators/cloudflare-account-token", "enkv.sh/plugins/outputs/aws-secrets-manager", "enkv.sh/plugins/manifest-generators/generic-json", "enkv.sh/plugins/manifest-generators/opentofu-tfvars-json", "enkv.sh/plugins/unlisted/implementation", "enkv.sh/core/contract", "enkv.sh/compositions/full", "enkv.sh/crypto"} {
			t.Run(owner+"/"+path, func(t *testing.T) {
				if checkSDKBoundaries(owner, []resolvedModule{{Path: path}}, nil) == nil {
					t.Fatal("public closure admitted implementation module", path)
				}
				if checkSDKBoundaries(owner, nil, []compiledPackage{{ImportPath: path}}) == nil {
					t.Fatal("public closure admitted transitive implementation package", path)
				}
			})
		}
	}
}

// full_only: false
func TestOutputServingAndManifestRendererStayAtReviewedOwners(t *testing.T) {
	for _, owner := range []string{"core", "crypto", "compositions/outputhost", "compositions/generatorhost", "compositions/manifesthost", "compositions/full", "hermetic", "live"} {
		for _, imported := range []string{outputSDKPath, outputSDKPath + "/conformance", outputExamplePath, manifestExamplePath, generatorExamplePath} {
			if checkSDKBoundaries(owner, nil, []compiledPackage{{ImportPath: imported}}) == nil {
				t.Fatal("private component admitted author serving/example", owner, imported)
			}
		}
	}
	for _, owner := range []string{"core", "crypto", "providers/aws", "compositions/outputhost", "compositions/generatorhost", "compositions/manifesthost", "compositions/full", "compositions/aws", "compositions/gcp", "compositions/configuration"} {
		for _, renderer := range []string{genericJSONPath, openTofuJSONPath, "enkv.sh/plugins/generators/local-random-secret/profile", "enkv.sh/plugins/generators/cloudflare-account-token/artifact", "enkv.sh/plugins/outputs/aws-secrets-manager/credential", "enkv.sh/plugins/unlisted/implementation"} {
			if checkSDKBoundaries(owner, nil, []compiledPackage{{ImportPath: renderer}}) == nil {
				t.Fatal("renderer reached unreviewed production owner", owner, renderer)
			}
		}
	}
	for _, path := range []string{genericJSONPath, manifestExamplePath, testServicePath, generatorSDKPath, outputSDKPath} {
		if err := checkSDKBoundaries("compositions/full", []resolvedModule{{Path: path, Version: "v0.1.0"}}, nil); err != nil {
			t.Fatal("unused test dependency entered production claim", path, err)
		}
	}
	for _, path := range []string{manifestSDKPath, "enkv.sh/sdk/artifact", "enkv.sh/sdk/artifact/credentialroute", "enkv.sh/sdk/protocols/generator", "enkv.sh/sdk/protocols/output", "enkv.sh/sdk/protocols/manifest-generator"} {
		for _, owner := range []string{"core", "crypto", "compositions/generatorhost", "compositions/outputhost", "compositions/manifesthost", "compositions/full"} {
			if err := checkSDKBoundaries(owner, nil, []compiledPackage{{ImportPath: path}}); err != nil {
				t.Fatal("common public runtime contract refused", owner, path, err)
			}
		}
	}
	for _, imported := range []string{manifestSDKPath, genericJSONPath, openTofuJSONPath} {
		core := compiledPackage{ImportPath: modulePrefix + "core", Imports: []string{imported}}
		if err := checkCustodyImports([]compiledPackage{core}, false, ""); (err == nil) != (imported == manifestSDKPath) {
			t.Fatal("Core production SDK boundary differs", imported, err)
		}
		core.ForTest = modulePrefix + "core"
		if err := checkCustodyImports([]compiledPackage{core}, true, ""); err != nil {
			t.Fatal("Core test renderer fixture refused", err)
		}
	}
	for _, consumer := range []struct {
		name  string
		check func([]compiledPackage) error
	}{{"generatorhost", checkGeneratorHost}, {"configuration", checkConfiguration}} {
		if err := consumer.check([]compiledPackage{{ImportPath: manifestSDKPath}}); err != nil {
			t.Fatal("manifest domain dependency refused", consumer.name, err)
		}
		if consumer.check([]compiledPackage{{ImportPath: manifestSDKPath + "/conformance"}}) == nil {
			t.Fatal("manifest conformance reached production consumer", consumer.name)
		}
	}
	for _, owner := range []string{"core", "crypto", "compositions/full", "sdk/generator", "sdk/output", "sdk/manifest-generator"} {
		if err := checkSDKBoundaries(owner, nil, []compiledPackage{{ImportPath: "enkv.sh/sdk/artifact/credentialroute"}}); err != nil {
			t.Fatal("neutral credential route codec refused", err)
		}
		for _, imported := range []string{"enkv.sh/sdk/artifact/build", "enkv.sh/sdk/artifact/cmd/enkv-plugin-build", "enkv.sh/sdk/artifact/cmd/enkv-artifact-sign"} {
			if checkSDKBoundaries(owner, nil, []compiledPackage{{ImportPath: imported}}) == nil {
				t.Fatal("artifact author tool reached another owner", owner, imported)
			}
		}
	}
	if err := checkSDKBoundaries("sdk/artifact", nil, []compiledPackage{{ImportPath: "enkv.sh/sdk/artifact/build"}}); err != nil {
		t.Fatal("artifact build tool refused at its owner", err)
	}
	for _, path := range []string{outputSDKPath, manifestSDKPath, genericJSONPath, openTofuJSONPath, "enkv.sh/sdk/artifact"} {
		if checkSDKBoundaries("crypto", []resolvedModule{{Path: path, Version: "v0.0.1"}}, nil) == nil {
			t.Fatal("SDK metadata version drift admitted", path)
		}
		if checkSDKBoundaries("crypto", []resolvedModule{{Path: path + "/unregistered", Version: "v0.1.0"}}, nil) == nil {
			t.Fatal("unregistered public submodule admitted", path)
		}
	}
	for _, path := range []string{manifestSDKPath + "/native", manifestSDKPath + "/conformance"} {
		if checkSDKBoundaries("protocols/manifest-generator", nil, []compiledPackage{{ImportPath: path}}) == nil {
			t.Fatal("manifest protocol imported author serving or conformance", path)
		}
	}
}

// full_only: false
func TestManifestWriterAndRendererClosuresAreExact(t *testing.T) {
	for _, owner := range []string{"core", "crypto", "providers/aws", "providers/gcp", "compositions/generatorhost", "compositions/outputhost", "compositions/full", "compositions/aws", "compositions/gcp", "compositions/configuration", "hermetic", "live", "protocols/manifest-generator"} {
		for _, path := range []string{manifestSDKPath + "/jsonwriter", manifestSDKPath + "/jsonwriter/internal", manifestSDKPath + "/native", manifestSDKPath + "/conformance"} {
			if checkSDKBoundaries(owner, nil, []compiledPackage{{ImportPath: path}}) == nil {
				t.Fatal("author helper reached a runtime consumer", owner, path)
			}
		}
	}
	for _, owner := range []string{"hermetic", "live"} {
		for _, renderer := range []string{genericJSONPath, openTofuJSONPath} {
			t.Run(owner+"/"+renderer, func(t *testing.T) {
				const writer = "enkv.sh/sdk/manifest-generator/jsonwriter"
				fixture := []compiledPackage{
					{ImportPath: modulePrefix + "core", ForTest: modulePrefix + "core", Imports: []string{renderer}},
					{ImportPath: renderer, Imports: []string{writer}},
					{ImportPath: writer, Imports: []string{manifestSDKPath}},
					{ImportPath: manifestSDKPath},
				}
				if err := checkSDKBoundaries(owner, nil, fixture); err != nil {
					t.Fatal("reviewed renderer fixture lost its public encoding helper", err)
				}
				if err := checkCustodyImports(fixture, true, ""); err != nil {
					t.Fatal("test-only renderer import refused", err)
				}
				for _, production := range []string{"core", "crypto", "providers/aws", "compositions/full", "compositions/generatorhost", "compositions/outputhost", "compositions/manifesthost"} {
					if checkSDKBoundaries(production, nil, fixture) == nil {
						t.Fatal("renderer fixture reached a production graph", production)
					}
				}
				for _, caller := range []string{modulePrefix + "core", modulePrefix + "crypto", modulePrefix + "compositions/full", modulePrefix + "providers/aws", renderer + "/nested", "enkv.sh/plugins/manifest-generators/unreviewed"} {
					for _, forTest := range []string{"", caller} {
						direct := compiledPackage{ImportPath: caller, ForTest: forTest, Imports: []string{writer}}
						if checkSDKBoundaries(owner, nil, append(append([]compiledPackage(nil), fixture...), direct)) == nil {
							t.Fatal("reviewed fixture permitted a direct writer caller", caller, forTest)
						}
						if checkSDKBoundaries(owner, nil, []compiledPackage{direct, {ImportPath: writer}}) == nil {
							t.Fatal("direct writer caller passed without a renderer fixture", caller, forTest)
						}
					}
				}
				for _, path := range []string{writer + "/internal", manifestSDKPath + "/native", manifestSDKPath + "/conformance"} {
					bad := append(append([]compiledPackage(nil), fixture...), compiledPackage{ImportPath: path})
					if checkSDKBoundaries(owner, nil, bad) == nil {
						t.Fatal("reviewed fixture permitted an author serving helper", path)
					}
				}
			})
		}
	}
	for _, owner := range []string{"sdk/manifest-generator", "sdk/examples/ini-reference-manifest", "plugins/manifest-generators/generic-json", "plugins/manifest-generators/opentofu-tfvars-json"} {
		if err := checkSDKBoundaries(owner, nil, []compiledPackage{{ImportPath: manifestSDKPath + "/jsonwriter"}}); err != nil {
			t.Fatal("optional author encoding helper refused", owner, err)
		}
	}
}

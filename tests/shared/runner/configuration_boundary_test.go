package main

import (
	"context"
	"testing"
	"time"
)

// full_only: false
func TestConfigurationMaintainedModuleRequiresOnlyPublicDependencies(t *testing.T) {
	root := maintainedCloudflareRoot(t)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	checked, err := checkModule(ctx, root, "compositions/configuration")
	if err != nil {
		t.Fatal(err)
	}
	closure := checked.closure
	if closure.Provider != "compositions/configuration" || len(closure.CompiledImports) == 0 {
		t.Fatal("configuration closure absent")
	}
	for _, path := range closure.CompiledImports {
		if path == modulePrefix+"core" || withinModule(path, modulePrefix+"crypto") || withinModule(path, modulePrefix+"providers") || withinModule(path, modulePrefix+"compositions/generatorhost") {
			t.Fatal("configuration acquired operation authority", path)
		}
	}
}

// full_only: false
func TestNativeProcessObserverCannotEnterProduction(t *testing.T) {
	helper := modulePrefix + "core/testsupport/nativeprocess"
	for _, owner := range []string{"core", "compositions/full", "providers/aws"} {
		p := compiledPackage{ImportPath: modulePrefix + owner, Imports: []string{helper}}
		if err := checkCustodyImports([]compiledPackage{p}, false, ""); err == nil {
			t.Fatal("production imported native process observer", owner)
		}
		p.ForTest = modulePrefix + owner
		if err := checkCustodyImports([]compiledPackage{p}, true, ""); err != nil {
			t.Fatal("test observer import refused", owner, err)
		}
	}
	if err := checkCustodyImports([]compiledPackage{{ImportPath: helper, Imports: []string{"os", "encoding/json", "crypto/sha256"}},
		{ImportPath: "os", Standard: true}, {ImportPath: "encoding/json", Standard: true}, {ImportPath: "crypto/sha256", Standard: true}}, true, ""); err != nil {
		t.Fatal(err)
	}
	for _, testPackage := range []compiledPackage{
		{ImportPath: helper, ForTest: helper, Imports: []string{helper, modulePrefix + "core/contract"}},
		{ImportPath: helper + ".test", Imports: []string{helper}},
	} {
		if err := checkCustodyImports([]compiledPackage{testPackage}, true, ""); err != nil {
			t.Fatal("native observer test-only dependency refused", err)
		}
	}
	for _, imported := range []string{modulePrefix + "core/contract", modulePrefix + "providers/aws", "example.com/observer"} {
		if err := checkCustodyImports([]compiledPackage{{ImportPath: helper, Imports: []string{imported}}}, true, ""); err == nil {
			t.Fatal("native process helper acquired nonstandard dependency", imported)
		}
	}
}

// full_only: false
func TestConfigurationBoundaryKeepsParsingOutsideOperationAuthority(t *testing.T) {
	modules := []resolvedModule{{Path: modulePrefix + "compositions/configuration"}, {Path: modulePrefix + "core", Version: "v0.1.0"}, {Path: "enkv.sh/sdk/artifact", Version: "v0.1.0"}}
	packages := []compiledPackage{{ImportPath: modulePrefix + "compositions/configuration"}, {ImportPath: modulePrefix + "core/contract"}, {ImportPath: "enkv.sh/sdk/artifact/credentialroute"}, {ImportPath: "enkv.sh/sdk/artifact"}}
	packages = append(packages, compiledPackage{ImportPath: "enkv.sh/sdk/protocols/generator/retained"})
	if err := checkBoundary("compositions/configuration", modules, packages); err != nil {
		t.Fatal("shared source contracts refused", err)
	}
	for _, path := range []string{"enkv.sh/plugins/generators/cloudflare-account-token/profile", "enkv.sh/plugins/generators/local-random-secret/profile", "enkv.sh/plugins/unlisted/profile", modulePath("core"), modulePath("crypto"), modulePath("providers/aws"), modulePath("providers/gcp"), modulePath("compositions/full"), cloudflareModulePath + "/internal/cloudflare", "enkv.sh/plugins/generators/local-random-secret", "enkv.sh/plugins/generators/local-random-secret/profile/child", modulePath("plugins/aws-output") + "/credential", modulePath("plugins/gcp-output") + "/credential", modulePath("plugins/github-output") + "/credential", "enkv.sh/sdk/protocols/generator/retained/private", "enkv.sh/sdk/generator/retained", "enkv.sh/sdk/artifact/build", "enkv.sh/sdk/artifact/cmd/enkv-plugin-build"} {
		if checkBoundary("compositions/configuration", modules, append(packages, compiledPackage{ImportPath: path})) == nil {
			t.Fatal("configuration acquired operation or credential reach", path)
		}
	}
	for _, path := range []string{"github.com/aws/aws-sdk-go-v2/service/kms", "google.golang.org/api/storage/v1"} {
		if checkBoundary("compositions/configuration", modules, append(packages, compiledPackage{ImportPath: path})) == nil {
			t.Fatal("configuration acquired provider SDK", path)
		}
	}
}

// full_only: false
func TestNativeProcessDependencyUsesResolvedStandardFacts(t *testing.T) {
	helper := modulePrefix + "core/testsupport/nativeprocess"
	for _, imported := range []string{"localobserver/helper", "localobserver"} {
		packages := []compiledPackage{{ImportPath: helper, Imports: []string{imported}}, {ImportPath: imported, Standard: false}}
		if err := checkCustodyImports(packages, true, ""); err == nil {
			t.Fatalf("nonstandard observer dependency accepted: %s", imported)
		}
	}
}

// full_only: false
func TestOutputCredentialDependencyRefusesNonstandardLocalPaths(t *testing.T) {
	for _, provider := range []string{"aws", "gcp", "github"} {
		t.Run(provider, func(t *testing.T) {
			p := compiledPackage{ImportPath: modulePath("plugins/"+provider+"-output") + "/credential", Imports: []string{"localobserver/helper"}}
			if err := checkOutputCredentialImports(p, nil); err == nil {
				t.Fatal("nonstandard credential codec dependency accepted")
			}
		})
	}
}

// full_only: false
func TestOutputCredentialDependencyAllowsOnlyResolvedStandardAndWirePackages(t *testing.T) {
	for _, provider := range []string{"aws", "gcp", "github"} {
		t.Run(provider, func(t *testing.T) {
			p := compiledPackage{ImportPath: modulePath("plugins/"+provider+"-output") + "/credential", Imports: []string{"encoding/json", "enkv.sh/sdk/protocols/output", "enkv.sh/sdk/artifact/credentialroute"}}
			standard := resolvedStandardPackages([]compiledPackage{{ImportPath: "encoding/json", Standard: true}, {ImportPath: "localobserver/helper"}})
			if err := checkOutputCredentialImports(p, standard); err != nil {
				t.Fatal("credential wire and standard dependency refused", err)
			}
			for _, imported := range []string{"localobserver/helper", modulePrefix + "core", modulePrefix + "compositions/outputhost", "enkv.sh/sdk/protocols/output/child", "enkv.sh/sdk/artifact/build", "enkv.sh/sdk/artifact/credentialroute/child", "github.com/aws/aws-sdk-go-v2/aws", "cloud.google.com/go/auth"} {
				unsafe := p
				unsafe.Imports = []string{imported}
				if err := checkOutputCredentialImports(unsafe, standard); err == nil {
					t.Fatal("nonstandard closure dependency accepted", imported)
				}
			}
		})
	}
}

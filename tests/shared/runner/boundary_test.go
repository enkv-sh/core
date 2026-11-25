package main

import (
	"bytes"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"testing"
)

// full_only: false
func TestTelemetryBoundaryAllowsAPIAndTestModulePinsOnly(t *testing.T) {
	modules := []resolvedModule{{Path: modulePrefix + "telemetry"},
		{Path: "go.opentelemetry.io/otel", Version: "v1.36.0"},
		{Path: "go.opentelemetry.io/otel/sdk", Version: "v1.36.0"}}
	packages := []compiledPackage{{ImportPath: modulePrefix + "telemetry"},
		{ImportPath: "context", Standard: true}, {ImportPath: "go.opentelemetry.io/otel/metric"}}
	if err := checkBoundary("telemetry", modules, packages); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"go.opentelemetry.io/otel", "go.opentelemetry.io/otel/trace/embedded", "go.opentelemetry.io/otel/metric/embedded", "go.opentelemetry.io/otel/attribute", "go.opentelemetry.io/otel/codes", "go.opentelemetry.io/otel/internal/global", "github.com/go-logr/logr", "github.com/go-logr/stdr", "go.opentelemetry.io/auto/sdk"} {
		if err := checkBoundary("telemetry", modules, append(packages, compiledPackage{ImportPath: path})); err != nil {
			t.Errorf("telemetry refused API closure %s: %v", path, err)
		}
	}
	for _, path := range []string{modulePrefix + "core", modulePrefix + "core/contract", modulePrefix + "providers/aws", modulePrefix + "providers/gcp", manifestSDKPath, genericJSONPath, "example.invalid/service"} {
		if checkBoundary("telemetry", append(modules, resolvedModule{Path: path}), packages) == nil {
			t.Errorf("telemetry admitted module %s", path)
		}
	}
	for _, path := range []string{modulePrefix + "core/contract", modulePrefix + "providers/aws", "go.opentelemetry.io/otel/sdk", "go.opentelemetry.io/otel/sdk/metric", "go.opentelemetry.io/otel/exporters", "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp", "go.opentelemetry.io/otel/log", "go.opentelemetry.io/otel/log/embedded", "github.com/stretchr/testify/assert", "github.com/google/uuid", "golang.org/x/sys/unix"} {
		if checkBoundary("telemetry", modules, append(packages, compiledPackage{ImportPath: path})) == nil {
			t.Errorf("telemetry admitted production import %s", path)
		}
	}
	if err := checkBoundary("core", append(modules, resolvedModule{Path: modulePrefix + "core"}), packages); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestOutputBoundaryKeepsProtocolAndHostSeparate(t *testing.T) {
	protocolModules := []resolvedModule{{Path: "enkv.sh/sdk/protocols/output"}}
	protocolPackages := []compiledPackage{{ImportPath: "enkv.sh/sdk/protocols/output"}, {ImportPath: "bytes", Standard: true}}
	if err := checkBoundary("protocols/output", protocolModules, protocolPackages); err != nil {
		t.Fatal(err)
	}
	withArtifact := append(append([]resolvedModule(nil), protocolModules...), resolvedModule{Path: "enkv.sh/sdk/artifact", Version: "v0.1.1", Replace: &resolvedModule{Path: "../../artifact"}})
	if checkBoundary("protocols/output", withArtifact, protocolPackages) == nil {
		t.Fatal("output protocol admitted artifact dependency")
	}
	if checkBoundary("protocols/output", protocolModules, append(protocolPackages, compiledPackage{ImportPath: modulePrefix + "core/contract"})) == nil {
		t.Fatal("output protocol imported Core")
	}
	hostModules := []resolvedModule{{Path: modulePrefix + "compositions/outputhost"},
		{Path: "enkv.sh/sdk/protocols/output", Version: "v0.1.0", Replace: &resolvedModule{Path: "../../../enkv-extensions/sdk/protocols/output"}},
		{Path: modulePrefix + "telemetry", Version: "v0.1.1", Replace: &resolvedModule{Path: "../../telemetry"}},
		{Path: nativeProcessPath, Version: "v0.1.0", Replace: &resolvedModule{Path: "../internal/nativeprocess"}},
		{Path: "golang.org/x/sys", Version: "v0.33.0"},
		{Path: "enkv.sh/sdk/artifact", Version: "v0.1.1", Replace: &resolvedModule{Path: "../../../enkv-extensions/sdk/artifact"}}}
	hostPackages := []compiledPackage{{ImportPath: modulePrefix + "compositions/outputhost"}, {ImportPath: "enkv.sh/sdk/protocols/output"},
		{ImportPath: modulePrefix + "telemetry"}, {ImportPath: "go.opentelemetry.io/otel/trace"}, {ImportPath: nativeProcessPath},
		{ImportPath: "golang.org/x/sys/unix"}, {ImportPath: "enkv.sh/sdk/artifact"}, {ImportPath: "os", Standard: true}}
	if err := checkBoundary("compositions/outputhost", hostModules, hostPackages); err != nil {
		t.Fatal(err)
	}
	if checkBoundary("compositions/outputhost", hostModules, append(hostPackages, compiledPackage{ImportPath: "github.com/aws/aws-sdk-go-v2/service/secretsmanager"})) == nil {
		t.Fatal("provider SDK reached output host")
	}
	bad := append([]resolvedModule(nil), hostModules...)
	bad[1].Replace = &resolvedModule{Path: "../wrong"}
	if checkBoundary("compositions/outputhost", bad, hostPackages) == nil {
		t.Fatal("wrong protocol source admitted")
	}
	bad = append([]resolvedModule(nil), hostModules...)
	bad[2].Replace = &resolvedModule{Path: "../wrong"}
	if checkBoundary("compositions/outputhost", bad, hostPackages) == nil {
		t.Fatal("wrong telemetry source admitted")
	}
	for _, path := range []string{"go.opentelemetry.io/otel/sdk", "go.opentelemetry.io/otel/sdk/trace", "go.opentelemetry.io/auto/sdk", "go.opentelemetry.io/auto/sdk/internal/telemetry", "go.opentelemetry.io/otel/exporters", "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp", "go.opentelemetry.io/otel/log", "go.opentelemetry.io/otel/log/embedded"} {
		if checkBoundary("compositions/outputhost", hostModules, append(hostPackages, compiledPackage{ImportPath: path})) == nil {
			t.Fatal("telemetry collection reached output host", path)
		}
	}
	for _, dependency := range []struct {
		name  string
		index int
	}{{"artifact", len(hostModules) - 1}, {"native-process", 3}} {
		for _, condition := range []string{"version", "missing_source", "wrong_source", "versioned_replacement", "nested_replacement"} {
			t.Run(dependency.name+"_"+condition, func(t *testing.T) {
				bad := append([]resolvedModule(nil), hostModules...)
				row := &bad[dependency.index]
				replacement := *row.Replace
				row.Replace = &replacement
				switch condition {
				case "version":
					row.Version = "v0.0.1"
				case "missing_source":
					row.Replace = nil
				case "wrong_source":
					row.Replace.Path = "../wrong"
				case "versioned_replacement":
					row.Replace.Version = "v0.0.1"
				case "nested_replacement":
					row.Replace.Replace = &resolvedModule{Path: "../wrong"}
				}
				if checkBoundary("compositions/outputhost", bad, hostPackages) == nil {
					t.Fatal("output host admitted a different local dependency source")
				}
			})
		}
	}
}

// full_only: false
func TestClosedModuleDependencyContracts(t *testing.T) {
	root := sourceFixtureRoot(t)
	module := func(name string) resolvedModule {
		path, err := sourcePath(root, name)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
		source, known := registeredModule(name)
		if !known {
			t.Fatal("unregistered module fixture", name)
		}
		return resolvedModule{Path: source.Module, GoVersion: "1.27.0", Dir: path}
	}
	protocol, telemetryModule, core := module("protocols/output"), module("telemetry"), module("core")
	plugin, host, sdk, artifact := module("plugins/aws-output"), module("compositions/outputhost"), module("sdk/output"), module("sdk/artifact")
	native := module("compositions/internal/nativeprocess")
	if err := checkClosedModuleDependencies(root, []resolvedModule{native}, "compositions/internal/nativeprocess"); err != nil {
		t.Fatal(err)
	}
	if err := checkClosedModuleDependencies(root, []resolvedModule{protocol}, "protocols/output"); err != nil {
		t.Fatal(err)
	}
	if err := checkClosedModuleDependencies(root, []resolvedModule{plugin, protocol, sdk, artifact}, "plugins/aws-output"); err != nil {
		t.Fatal(err)
	}
	if err := checkClosedModuleDependencies(root, []resolvedModule{sdk, protocol, artifact}, "sdk/output"); err != nil {
		t.Fatal(err)
	}
	if err := checkClosedModuleDependencies(root, []resolvedModule{host, protocol, telemetryModule, artifact, native}, "compositions/outputhost"); err != nil {
		t.Fatal(err)
	}
	manifestModules := []resolvedModule{module("compositions/manifesthost"), artifact, module("sdk/manifest-generator"), module("protocols/manifest-generator"), telemetryModule, native}
	if err := checkClosedModuleDependencies(root, manifestModules, "compositions/manifesthost"); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(manifestModules); i++ {
		t.Run("manifest missing "+manifestModules[i].Path, func(t *testing.T) {
			missing := append([]resolvedModule(nil), manifestModules[:i]...)
			missing = append(missing, manifestModules[i+1:]...)
			if checkClosedModuleDependencies(root, missing, "compositions/manifesthost") == nil {
				t.Fatal("manifest host admitted missing dependency")
			}
		})
		t.Run("manifest substituted "+manifestModules[i].Path, func(t *testing.T) {
			changed := append([]resolvedModule(nil), manifestModules...)
			changed[i].Dir = t.TempDir()
			if checkClosedModuleDependencies(root, changed, "compositions/manifesthost") == nil {
				t.Fatal("manifest host admitted substituted source")
			}
		})
	}
	for _, name := range []string{"core", "crypto", "plugins/manifest-generators/generic-json", "plugins/manifest-generators/opentofu-tfvars-json"} {
		t.Run("manifest gained "+name, func(t *testing.T) {
			changed := append(append([]resolvedModule(nil), manifestModules...), module(name))
			if checkClosedModuleDependencies(root, changed, "compositions/manifesthost") == nil {
				t.Fatal("manifest host admitted forbidden dependency")
			}
		})
	}
	for _, test := range []struct {
		name    string
		module  string
		closure []resolvedModule
	}{
		{"protocol gained Core", "protocols/output", []resolvedModule{protocol, core}},
		{"protocol gained artifact", "protocols/output", []resolvedModule{protocol, artifact}},
		{"plugin lost protocol", "plugins/aws-output", []resolvedModule{plugin, sdk}},
		{"plugin lost SDK", "plugins/aws-output", []resolvedModule{plugin, protocol}},
		{"SDK lost protocol", "sdk/output", []resolvedModule{sdk}},
		{"SDK gained Core", "sdk/output", []resolvedModule{sdk, protocol, core}},
		{"plugin gained Core", "plugins/aws-output", []resolvedModule{plugin, protocol, sdk, core}},
		{"plugin gained manifest SDK", "plugins/aws-output", []resolvedModule{plugin, protocol, sdk, module("sdk/manifest-generator")}},
		{"host lost telemetry", "compositions/outputhost", []resolvedModule{host, protocol, artifact, native}},
		{"host lost artifact codec", "compositions/outputhost", []resolvedModule{host, protocol, telemetryModule, native}},
		{"host lost native process", "compositions/outputhost", []resolvedModule{host, protocol, telemetryModule, artifact}},
		{"native process gained host", "compositions/internal/nativeprocess", []resolvedModule{native, host}},
		{"host gained Crypto", "compositions/outputhost", []resolvedModule{host, protocol, telemetryModule, artifact, native, module("crypto")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := checkClosedModuleDependencies(root, test.closure, test.module); err == nil {
				t.Fatal("unreviewed output module graph admitted")
			}
		})
	}
}

// full_only: false
func TestNativeProcessLeafBoundaryIsExact(t *testing.T) {
	modules := []resolvedModule{{Path: nativeProcessPath}, {Path: "golang.org/x/sys", Version: "v0.33.0"}}
	packages := []compiledPackage{{ImportPath: nativeProcessPath}, {ImportPath: "golang.org/x/sys/unix"}, {ImportPath: "os", Standard: true}}
	if err := checkBoundary("compositions/internal/nativeprocess", modules, packages); err != nil {
		t.Fatal("native process leaf refused", err)
	}
	for _, path := range []string{modulePrefix + "core", modulePrefix + "telemetry", modulePrefix + "compositions/outputhost", modulePrefix + "compositions/manifesthost", "enkv.sh/sdk/artifact", nativeProcessPath + "/private", "example.invalid/client"} {
		if checkBoundary("compositions/internal/nativeprocess", append(append([]resolvedModule(nil), modules...), resolvedModule{Path: path}), packages) == nil {
			t.Fatal("native process admitted a non-leaf module", path)
		}
	}
	for _, path := range []string{modulePrefix + "core/contract", modulePrefix + "telemetry", modulePrefix + "compositions/outputhost", modulePrefix + "compositions/manifesthost", "enkv.sh/sdk/artifact", nativeProcessPath + "/private", "golang.org/x/sys/windows", "golang.org/x/sys/unix/private", "example.invalid/client"} {
		if checkBoundary("compositions/internal/nativeprocess", modules, append(append([]compiledPackage(nil), packages...), compiledPackage{ImportPath: path})) == nil {
			t.Fatal("native process admitted an unreviewed import", path)
		}
	}
	for i := range modules {
		missing := append([]resolvedModule(nil), modules[:i]...)
		missing = append(missing, modules[i+1:]...)
		if checkBoundary("compositions/internal/nativeprocess", missing, packages) == nil {
			t.Fatal("native process admitted a missing module", modules[i].Path)
		}
		if checkBoundary("compositions/internal/nativeprocess", append(append([]resolvedModule(nil), modules...), modules[i]), packages) == nil {
			t.Fatal("native process admitted a duplicate module", modules[i].Path)
		}
		changed := append([]resolvedModule(nil), modules...)
		changed[i].Version = "v0.0.1"
		if checkBoundary("compositions/internal/nativeprocess", changed, packages) == nil {
			t.Fatal("native process admitted a changed module version", modules[i].Path)
		}
		changed = append([]resolvedModule(nil), modules...)
		changed[i].Replace = &resolvedModule{Path: "../substitute"}
		if checkBoundary("compositions/internal/nativeprocess", changed, packages) == nil {
			t.Fatal("native process admitted a substituted module", modules[i].Path)
		}
	}
}

// full_only: false
func TestGitHubOutputBoundaryPinsSealedBoxOnly(t *testing.T) {
	modules := []resolvedModule{{Path: "enkv.sh/plugins/outputs/github-actions"},
		{Path: "enkv.sh/sdk/artifact", Version: "v0.1.1", Replace: &resolvedModule{Path: "../../../sdk/artifact"}},
		{Path: outputSDKPath, Version: "v0.1.1", Replace: &resolvedModule{Path: "../../../sdk/output"}},
		{Path: "enkv.sh/sdk/protocols/output", Version: "v0.1.0", Replace: &resolvedModule{Path: "../../../sdk/protocols/output"}},
		{Path: "golang.org/x/crypto", Version: "v0.33.0"}, {Path: "golang.org/x/net", Version: "v0.35.0"},
		{Path: "golang.org/x/sys", Version: "v0.33.0"}, {Path: "golang.org/x/term", Version: "v0.29.0"},
		{Path: "golang.org/x/text", Version: "v0.22.0"}}
	packages := []compiledPackage{{ImportPath: "enkv.sh/plugins/outputs/github-actions/internal/github", Imports: []string{"enkv.sh/sdk/protocols/output", "golang.org/x/crypto/nacl/box", "net/http"}},
		{ImportPath: "enkv.sh/sdk/protocols/output"}, {ImportPath: "golang.org/x/crypto/nacl/box"}, {ImportPath: "net/http", Standard: true}}
	if err := checkBoundary("plugins/github-output", modules, packages); err != nil {
		t.Fatal(err)
	}
	bad := append([]compiledPackage(nil), packages...)
	bad[0].Imports = append([]string(nil), bad[0].Imports...)
	bad[0].Imports = append(bad[0].Imports, "github.com/aws/aws-sdk-go-v2/service/secretsmanager")
	if checkBoundary("plugins/github-output", modules, bad) == nil {
		t.Fatal("GitHub plugin admitted an unrelated SDK")
	}
}

// full_only: false
func TestProviderOutputBoundaryPinsOneSendClients(t *testing.T) {
	for _, tc := range []struct {
		directory, direct string
		pins              map[string]string
	}{
		{"plugins/aws-output", "github.com/aws/aws-sdk-go-v2/aws/signer/v4", awsOutputPins},
		{"plugins/gcp-output", "google.golang.org/api/secretmanager/v1", gcpOutputPins},
		{"plugins/github-output", "golang.org/x/crypto/nacl/box", githubOutputPins},
	} {
		t.Run(tc.directory, func(t *testing.T) {
			modules := []resolvedModule{{Path: modulePath(tc.directory)},
				{Path: "enkv.sh/sdk/artifact", Version: "v0.1.1", Replace: &resolvedModule{Path: "../../../sdk/artifact"}},
				{Path: outputSDKPath, Version: "v0.1.1", Replace: &resolvedModule{Path: "../../../sdk/output"}},
				{Path: "enkv.sh/sdk/protocols/output", Version: "v0.1.0", Replace: &resolvedModule{Path: "../../../sdk/protocols/output"}}}
			for path, version := range tc.pins {
				modules = append(modules, resolvedModule{Path: path, Version: version})
			}
			packages := []compiledPackage{{ImportPath: modulePath(tc.directory) + "/internal/provider", Imports: []string{"enkv.sh/sdk/protocols/output", tc.direct}},
				{ImportPath: tc.direct}, {ImportPath: "enkv.sh/sdk/protocols/output"}}
			if err := checkBoundary(tc.directory, modules, packages); err != nil {
				t.Fatal(err)
			}
			var discovery []string
			switch tc.directory {
			case "plugins/aws-output":
				discovery = []string{"github.com/aws/aws-sdk-go-v2/config", "github.com/aws/aws-sdk-go-v2/credentials/endpointcreds", "github.com/aws/aws-sdk-go-v2/aws/retry", "github.com/aws/aws-sdk-go-v2/aws/transport/http", "github.com/aws/smithy-go/logging", "github.com/aws/smithy-go/middleware", "github.com/aws/smithy-go/transport/http"}
			case "plugins/gcp-output":
				discovery = []string{"cloud.google.com/go/auth", "cloud.google.com/go/auth/credentials"}
			}
			for _, imported := range discovery {
				withDiscovery := append([]compiledPackage(nil), packages...)
				withDiscovery[0].Imports = append(append([]string(nil), packages[0].Imports...), imported)
				withDiscovery = append(withDiscovery, compiledPackage{ImportPath: imported})
				if err := checkBoundary(tc.directory, modules, withDiscovery); err != nil {
					t.Fatal("pinned credential discovery dependency refused", imported, err)
				}
			}
			bad := append([]resolvedModule(nil), modules...)
			bad[2].Version = "v999.0.0"
			if checkBoundary(tc.directory, bad, packages) == nil {
				t.Fatal("dependency drift admitted")
			}
			for _, condition := range []string{"missing", "duplicate", "version", "replacement", "unknown"} {
				changed := append([]resolvedModule(nil), modules...)
				switch condition {
				case "missing":
					changed = changed[:len(changed)-1]
				case "duplicate":
					changed = append(changed, changed[3])
				case "version":
					changed[3].Version = "v999.0.0"
				case "replacement":
					changed[3].Replace = &resolvedModule{Path: "../substituted"}
				case "unknown":
					changed[3].Path = "example.invalid/dependency"
				}
				if checkBoundary(tc.directory, changed, packages) == nil {
					t.Fatal("output resolved graph drift admitted", condition)
				}
			}
			badPackages := append([]compiledPackage(nil), packages...)
			badPackages[0].Imports = append(append([]string(nil), packages[0].Imports...), "github.com/aws/aws-sdk-go-v2/service/secretsmanager")
			if checkBoundary(tc.directory, modules, badPackages) == nil {
				t.Fatal("unreviewed service client admitted")
			}
		})
	}
}

// full_only: false
func TestTelemetryDirectImportsExcludeAPITransitivesAndSDK(t *testing.T) {
	for _, imported := range []string{"context", "go.opentelemetry.io/otel", "go.opentelemetry.io/otel/attribute", "go.opentelemetry.io/otel/metric", "go.opentelemetry.io/otel/trace", "github.com/go-logr/logr", "go.opentelemetry.io/auto/sdk", "go.opentelemetry.io/otel/sdk/metric", modulePrefix + "core/contract"} {
		packages := []compiledPackage{{ImportPath: modulePrefix + "telemetry", Imports: []string{imported}}, {ImportPath: "context", Standard: true}}
		allowed := imported == "context" || imported == "go.opentelemetry.io/otel" || imported == "go.opentelemetry.io/otel/attribute" || imported == "go.opentelemetry.io/otel/metric" || imported == "go.opentelemetry.io/otel/trace"
		if err := checkTelemetryImports(packages); (err == nil) != allowed {
			t.Errorf("direct import %s: %v", imported, err)
		}
	}
}

// full_only: false
func TestBoundaryRejectsCrossProviderAndProductionSDK(t *testing.T) {
	for _, tc := range []struct {
		directory, module, imported string
	}{
		{"core", "cloud.google.com/go/auth", ""},
		{"core", "github.com/aws/aws-sdk-go-v2", ""},
		{"core", "", "enkv.sh/providers/gcp"},
		{"providers/aws", "google.golang.org/api", ""},
		{"providers/gcp", "github.com/aws/aws-sdk-go-v2", ""},
		{"providers/aws", "", "google.golang.org/api/storage/v1"},
		{"providers/aws", "cloud.google.com/go/compute/metadata", ""},
		{"providers/gcp", "", "enkv.sh/providers/aws"},
		{"core", "", "go.opentelemetry.io/otel/sdk/metric"},
		{"core", "", "go.opentelemetry.io/otel/log"},
		{"core", "", "go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"},
		{"providers/aws", "", "go.opentelemetry.io/otel/sdk/resource"},
		{"providers/gcp", "", "go.opentelemetry.io/otel/sdk/trace"},
		{"core", "", "enkv.sh/outputs/example"},
		{"providers/aws", "enkv.sh/unregistered", ""},
		{"providers/gcp", "", "enkv.sh/unregistered/package"},
	} {
		t.Run(tc.directory+"/"+tc.module+tc.imported, func(t *testing.T) {
			modules := []resolvedModule{{Path: "enkv.sh/" + tc.directory}}
			if tc.module != "" {
				modules = append(modules, resolvedModule{Path: tc.module})
			}
			packages := []compiledPackage{{ImportPath: "enkv.sh/" + tc.directory}}
			if tc.imported != "" {
				packages = append(packages, compiledPackage{ImportPath: tc.imported})
			}
			if err := checkBoundary(tc.directory, modules, packages); err == nil {
				t.Fatal("unsafe dependency or compiled import admitted")
			}
		})
	}
}

// full_only: false
func TestBoundaryRequiresExactNeutralPinsWithoutReplacement(t *testing.T) {
	for _, dependency := range []resolvedModule{
		{Path: "go.opentelemetry.io/otel", Version: "v99.0.0"},
		{Path: "github.com/google/uuid", Version: "v1.6.0", Replace: &resolvedModule{Path: "../unreviewed"}},
		{Path: "go.opentelemetry.io/otel", Version: "v1.36.0", Replace: &resolvedModule{Path: "go.opentelemetry.io/otel", Version: "v99.0.0"}},
		{Path: "github.com/google/uuid/service", Version: "v1.0.0"},
		{Path: "go.opentelemetry.io/otel/unreviewed", Version: "v1.0.0"},
	} {
		t.Run(dependency.Path, func(t *testing.T) {
			modules := []resolvedModule{{Path: "enkv.sh/providers/aws"}, dependency}
			if checkBoundary("providers/aws", modules, nil) == nil {
				t.Fatal("unreviewed neutral dependency admitted")
			}
		})
	}
}

// full_only: false
func TestObservabilityDependencyPinsAndNamespaceAreExact(t *testing.T) {
	base := []resolvedModule{{Path: modulePrefix + "compositions/observability"}, {Path: modulePrefix + "telemetry", Version: "v0.1.1"}}
	for _, module := range []resolvedModule{
		{Path: "go.opentelemetry.io/otel/sdk/log", Version: "v0.12.0"},
		{Path: "go.opentelemetry.io/otel/sdk/log", Version: "v0.12.1", Replace: &resolvedModule{Path: "../unreviewed"}},
		{Path: "google.golang.org/grpc/unreviewed", Version: "v1.0.0"},
		{Path: "go.opentelemetry.io/otel/exporters/otlp/otlplog/unreviewed", Version: "v0.12.1"},
	} {
		if checkObservabilityBoundary(append(base, module), nil) == nil {
			t.Fatalf("unreviewed module admitted: %s", module.Path)
		}
	}
	valid := append(base, resolvedModule{Path: "go.opentelemetry.io/otel/sdk/log", Version: "v0.12.1"})
	if err := checkObservabilityBoundary(valid, []compiledPackage{{ImportPath: modulePrefix + "compositions/observability"}, {ImportPath: "go.opentelemetry.io/otel/sdk/log"}}); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestBoundaryAllowsNeutralUtilitiesButNotCloudServices(t *testing.T) {
	modules := []resolvedModule{
		{Path: "enkv.sh/core"},
		{Path: "go.opentelemetry.io/otel", Version: "v1.36.0"},
		{Path: "go.opentelemetry.io/otel/sdk", Version: "v1.36.0"},
		{Path: "github.com/google/uuid", Version: "v1.6.0"},
	}
	packages := []compiledPackage{
		{ImportPath: "enkv.sh/core"},
		{ImportPath: "bytes", Standard: true},
		{ImportPath: "github.com/google/uuid"},
		{ImportPath: "go.opentelemetry.io/otel/metric"},
	}
	if err := checkBoundary("core", modules, packages); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"github.com/google/service-sdk", "go.opentelemetry.io/unreviewed", "google.golang.org/api/storage/v1"} {
		if checkBoundary("core", modules, append(packages, compiledPackage{ImportPath: path})) == nil {
			t.Fatal("neutral utilities admitted a cloud service")
		}
	}
}

// full_only: false
func TestCompositionRequiresSharedModulesAndNoTestSources(t *testing.T) {
	modules := []resolvedModule{{Path: modulePrefix + "compositions/full"}, {Path: modulePrefix + "core", Version: "v0.1.1"}, {Path: modulePrefix + "telemetry", Version: "v0.1.1"}, {Path: modulePrefix + "crypto", Version: "v0.1.1"}}
	packages := []compiledPackage{{ImportPath: modulePrefix + "core"}, {ImportPath: modulePrefix + "core/contract"}, {ImportPath: modulePrefix + "core/format"}, {ImportPath: modulePrefix + "telemetry"}, {ImportPath: modulePrefix + "crypto"}}
	if err := checkBoundary("compositions/full", modules, packages); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct {
		modules  []resolvedModule
		packages []compiledPackage
	}{
		{modules[:1], packages},
		{modules[:2], packages},
		{modules[:3], packages},
		{modules, packages[:4]},
		{[]resolvedModule{modules[0], modules[1], {Path: modules[2].Path, Version: "v0.0.1"}}, packages},
		{append(append([]resolvedModule{}, modules...), modules[2]), packages},
		{modules, packages[:3]},
		{append(append([]resolvedModule{}, modules...), modules[1]), packages},
		{[]resolvedModule{modules[0], {Path: modules[1].Path, Version: "v0.0.1"}}, packages},
		{modules, packages[:2]},
		{modules, append(append([]compiledPackage{}, packages...), compiledPackage{ImportPath: "synthetic", ForTest: "core"})},
		{modules, append(append([]compiledPackage{}, packages...), compiledPackage{ImportPath: "synthetic", GoFiles: []string{"fixture_test.go"}})},
	} {
		if checkBoundary("compositions/full", mutation.modules, mutation.packages) == nil {
			t.Fatal("invalid production composition admitted")
		}
	}
	for _, composition := range []string{"aws", "gcp", "full"} {
		t.Run(composition, func(t *testing.T) {
			directory := "compositions/" + composition
			modules := []resolvedModule{{Path: modulePrefix + directory},
				{Path: modulePrefix + "core", Version: "v0.1.1"},
				{Path: modulePrefix + "telemetry", Version: "v0.1.1"},
				{Path: modulePrefix + "crypto", Version: "v0.1.1"}}
			packages := []compiledPackage{{ImportPath: modulePrefix + "core"},
				{ImportPath: modulePrefix + "core/contract"}, {ImportPath: modulePrefix + "core/format"},
				{ImportPath: modulePrefix + "telemetry"}, {ImportPath: modulePrefix + "crypto"}}
			t.Run("clean", func(t *testing.T) {
				if err := checkBoundary(directory, modules, packages); err != nil {
					t.Fatal(err)
				}
			})
			t.Run("output_host_and_protocol", func(t *testing.T) {
				allowedModules := append(append([]resolvedModule(nil), modules...),
					resolvedModule{Path: modulePrefix + "compositions/outputhost", Version: "v0.1.1"},
					resolvedModule{Path: "enkv.sh/sdk/protocols/output", Version: "v0.1.0"})
				allowedPackages := append(append([]compiledPackage(nil), packages...),
					compiledPackage{ImportPath: modulePrefix + "compositions/outputhost"},
					compiledPackage{ImportPath: "enkv.sh/sdk/protocols/output"})
				if err := checkBoundary(directory, allowedModules, allowedPackages); err != nil {
					t.Fatal(err)
				}
			})
			for _, provider := range []string{"aws", "gcp", "github"} {
				t.Run(provider+"_credential_codec", func(t *testing.T) {
					module := modulePath("plugins/" + provider + "-output")
					codecModules := append(append([]resolvedModule(nil), modules...),
						resolvedModule{Path: module, Version: "v0.1.1"},
						resolvedModule{Path: "enkv.sh/sdk/protocols/output", Version: "v0.1.0"})
					codecPackages := append(append([]compiledPackage(nil), packages...),
						compiledPackage{ImportPath: module + "/credential", Imports: []string{"encoding/json", "enkv.sh/sdk/protocols/output"}},
						compiledPackage{ImportPath: "encoding/json", Standard: true},
						compiledPackage{ImportPath: "enkv.sh/sdk/protocols/output"})
					allowed := false
					if err := checkBoundary(directory, codecModules, codecPackages); (err == nil) != allowed {
						t.Fatalf("credential codec admission differs: allowed=%t: %v", allowed, err)
					}
					for _, suffix := range []string{"", "/internal/client", "/profile/child", "/credential/child", "/cmd/child"} {
						if checkBoundary(directory, codecModules, append(codecPackages, compiledPackage{ImportPath: module + suffix})) == nil {
							t.Fatal("credential codec allowance admitted plugin implementation", suffix)
						}
					}
					for _, imported := range []string{modulePrefix + "core", modulePrefix + "compositions/outputhost", "github.com/aws/aws-sdk-go-v2/aws"} {
						unsafeCodec := compiledPackage{ImportPath: module + "/credential", Imports: []string{imported}}
						if checkBoundary(directory, codecModules, append(codecPackages, unsafeCodec)) == nil {
							t.Fatal("credential codec acquired a non-wire dependency", imported)
						}
					}
				})
			}
			t.Run("legacy_output_package", func(t *testing.T) {
				legacy := modulePrefix + "outputs/legacy"
				if checkBoundary(directory, modules, append(packages, compiledPackage{ImportPath: legacy})) == nil {
					t.Fatalf("trust composition admitted output package %s", legacy)
				}
			})
			for _, plugin := range []struct {
				name, internal string
			}{
				{"aws-output", "awssm"},
				{"gcp-output", "gcpsm"},
				{"github-output", "github"},
			} {
				path := modulePath("plugins/" + plugin.name)
				t.Run(plugin.name+"_module", func(t *testing.T) {
					if err := checkBoundary(directory, append(modules, resolvedModule{Path: path, Version: "v0.1.1"}), packages); err != nil {
						t.Fatalf("unused test module changed production compilation: %v", err)
					}
				})
				t.Run(plugin.name+"_root_package", func(t *testing.T) {
					if checkBoundary(directory, modules, append(packages, compiledPackage{ImportPath: path})) == nil {
						t.Fatalf("trust composition admitted output package %s", path)
					}
				})
				t.Run(plugin.name+"_internal_package", func(t *testing.T) {
					internal := path + "/internal/" + plugin.internal
					if checkBoundary(directory, modules, append(packages, compiledPackage{ImportPath: internal})) == nil {
						t.Fatalf("trust composition admitted output package %s", internal)
					}
				})
			}
		})
	}
}

// full_only: false
func TestCryptoBoundaryAdmitsOnlyPublicCorePackages(t *testing.T) {
	modules := []resolvedModule{{Path: modulePrefix + "crypto"}, {Path: modulePrefix + "core", Version: "v0.1.1"}, {Path: modulePrefix + "telemetry", Version: "v0.1.1"}, {Path: modulePrefix + "compositions/generatorhost", Version: "v0.1.1"}, {Path: "enkv.sh/sdk/protocols/generator", Version: "v0.1.1"}, {Path: modulePrefix + "compositions/outputhost", Version: "v0.1.1"}, {Path: "enkv.sh/sdk/protocols/output", Version: "v0.1.0"}, {Path: nativeProcessPath, Version: "v0.1.0"}}
	packages := []compiledPackage{{ImportPath: modulePrefix + "crypto", Imports: []string{modulePrefix + "core/contract", modulePrefix + "core/format", modulePrefix + "compositions/generatorhost", "enkv.sh/sdk/protocols/generator", modulePrefix + "compositions/outputhost", "enkv.sh/sdk/protocols/output"}}, {ImportPath: modulePrefix + "core/contract"}, {ImportPath: modulePrefix + "core/format"}, {ImportPath: modulePrefix + "compositions/generatorhost"}, {ImportPath: "enkv.sh/sdk/protocols/generator"}, {ImportPath: modulePrefix + "compositions/outputhost"}, {ImportPath: "enkv.sh/sdk/protocols/output"}, {ImportPath: "crypto/rsa", Standard: true}, {ImportPath: nativeProcessPath}}
	if err := checkBoundary("crypto", modules, packages); err != nil {
		t.Fatal(err)
	}
	packages = append(packages, compiledPackage{ImportPath: "enkv.sh/sdk/artifact/credentialroute"}, compiledPackage{ImportPath: "enkv.sh/sdk/artifact"}, compiledPackage{ImportPath: "enkv.sh/sdk/protocols/generator/retained"})
	if err := checkBoundary("crypto", modules, packages); err != nil {
		t.Fatal("common public codecs refused", err)
	}
	for _, imported := range []string{"enkv.sh/plugins/generators/local-random-secret", "enkv.sh/plugins/generators/local-random-secret/profile", "enkv.sh/plugins/generators/local-random-secret/profile/child", "enkv.sh/plugins/generators/cloudflare-account-token/artifact", "enkv.sh/plugins/unlisted/profile", "enkv.sh/sdk/generator/retained", "enkv.sh/sdk/protocols/generator/retained/private"} {
		if checkBoundary("crypto", modules, append(packages, compiledPackage{ImportPath: imported})) == nil {
			t.Fatal("Crypto admitted concrete plugin or serving dependency", imported)
		}
	}
	for _, path := range []string{modulePrefix + "core", modulePrefix + "core/private", modulePrefix + "providers/aws", modulePrefix + "compositions/full", modulePrefix + "compositions/generatorhost/testsupport", modulePrefix + "compositions/outputhost/private", nativeProcessPath + "/private", "enkv.sh/sdk/protocols/output/private", "enkv.sh/plugins/outputs/aws-secrets-manager", "github.com/aws/aws-sdk-go-v2/service/kms", "cloud.google.com/go/auth"} {
		if checkBoundary("crypto", modules, append(packages, compiledPackage{ImportPath: path})) == nil {
			t.Errorf("Crypto admitted %s", path)
		}
	}
	for _, path := range []string{modulePrefix + "compositions/outputhost/private", nativeProcessPath + "/private", "enkv.sh/sdk/protocols/output/private", "enkv.sh/plugins/outputs/aws-secrets-manager"} {
		if checkBoundary("crypto", append(modules, resolvedModule{Path: path}), packages) == nil {
			t.Errorf("Crypto admitted module %s", path)
		}
	}
}

// full_only: false
func TestGeneratorProtocolAndHostBoundariesAreClosed(t *testing.T) {
	protocol := []compiledPackage{{ImportPath: "enkv.sh/sdk/protocols/generator"}, {ImportPath: "encoding/binary", Standard: true}}
	if err := checkBoundary("protocols/generator", []resolvedModule{{Path: "enkv.sh/sdk/protocols/generator"}}, protocol); err != nil {
		t.Fatal(err)
	}
	if checkBoundary("protocols/generator", []resolvedModule{{Path: "enkv.sh/sdk/protocols/generator"}}, append(protocol, compiledPackage{ImportPath: "example.com/dependency"})) == nil {
		t.Fatal("open protocol admitted a non-standard dependency")
	}
	host := []compiledPackage{{ImportPath: modulePrefix + "compositions/generatorhost"}, {ImportPath: modulePrefix + "core/contract"}, {ImportPath: "enkv.sh/sdk/protocols/generator"}, {ImportPath: modulePrefix + "telemetry"}, {ImportPath: "golang.org/x/sys/unix"}, {ImportPath: "os/exec", Standard: true}, {ImportPath: "enkv.sh/sdk/artifact"}, {ImportPath: "enkv.sh/sdk/artifact/credentialroute"}, {ImportPath: "enkv.sh/sdk/protocols/output"}}
	if err := checkBoundary("compositions/generatorhost", []resolvedModule{{Path: modulePrefix + "compositions/generatorhost"}}, host); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"go.opentelemetry.io/otel/attribute/internal", "go.opentelemetry.io/otel/attribute", "go.opentelemetry.io/otel/codes", "go.opentelemetry.io/otel/semconv/v1.26.0", "go.opentelemetry.io/otel/trace/embedded", "go.opentelemetry.io/otel/trace/internal/telemetry", "go.opentelemetry.io/otel/trace"} {
		if err := checkBoundary("compositions/generatorhost", []resolvedModule{{Path: modulePrefix + "compositions/generatorhost"}}, append(host, compiledPackage{ImportPath: path})); err != nil {
			t.Fatalf("generator host rejected reviewed trace API %s: %v", path, err)
		}
	}
	for _, path := range []string{modulePrefix + "crypto", modulePrefix + "providers/aws", modulePrefix + "compositions/full", "go.opentelemetry.io/otel/sdk/log", "enkv.sh/sdk/artifact/build", "enkv.sh/plugins/generators/cloudflare-account-token/artifact/private"} {
		if checkBoundary("compositions/generatorhost", []resolvedModule{{Path: modulePrefix + "compositions/generatorhost"}}, append(host, compiledPackage{ImportPath: path})) == nil {
			t.Fatal("generator host admitted", path)
		}
	}
}

// full_only: false
func TestProductionGraphRejectsCoreCustodyAndFixtureImports(t *testing.T) {
	for _, owner := range []string{"core", "core/contract", "core/format", "core/other", "providers/aws", "crypto"} {
		for _, imported := range []string{"crypto", "crypto/testsupport/trust", "crypto/testsupport/custody"} {
			if imported == "crypto" && (owner == "providers/aws" || owner == "crypto") {
				continue
			}
			packages := []compiledPackage{{ImportPath: modulePrefix + owner, Imports: []string{modulePrefix + imported}}, {ImportPath: modulePrefix + imported}}
			if checkBoundary("providers/aws", []resolvedModule{{Path: modulePrefix + "providers/aws"}}, packages) == nil {
				t.Errorf("production edge %s -> %s admitted", owner, imported)
			}
		}
	}
}

// full_only: false
func TestStateOracleDoesNotConsumeProductionTransitionPlan(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(root, "tests/shared/state_oracle_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("transitionPlan")) {
		t.Fatal("state oracle consumes the production transition plan")
	}
}

// full_only: false
func TestCoreCustodySourcesRejectPrivateAPIUses(t *testing.T) {
	for _, owner := range []string{"core", "core/contract", "core/format", "core/internal/testmain"} {
		for _, fixture := range []struct{ imported, expression string }{
			{"r \"crypto/rsa\"", "var _ *r.PrivateKey"},
			{"r \"crypto/rsa\"", "var _ = r.GenerateKey"},
			{"r \"crypto/rsa\"", "var _ = r.SignPSS"},
			{"r \"crypto/rsa\"", "var _ = r.DecryptOAEP"},
			{"x \"crypto/x509\"", "var _ = x.ParsePKCS8PrivateKey"},
			{"x \"crypto/x509\"", "var _ = x.MarshalPKCS1PrivateKey"},
			{"e \"crypto/ed25519\"", "var _ = e.NewKeyFromSeed"},
			{". \"crypto/ecdsa\"", "var _ = GenerateKey"},
			{"c \"crypto\"", "var _ c.Signer"},
			{"b \"golang.org/x/crypto/nacl/box\"", "var _ = b.GenerateKey"},
			{"b \"golang.org/x/crypto/nacl/box\"", "var _ = b.Open"},
			{"b \"golang.org/x/crypto/nacl/box\"", "var _ = b.OpenAfterPrecomputation"},
			{"b \"golang.org/x/crypto/nacl/box\"", "var _ = b.OpenAnonymous"},
			{". \"golang.org/x/crypto/nacl/box\"", "var _ = OpenAnonymous"},
		} {
			for _, filename := range []string{"fixture.go", "fixture_test.go"} {
				t.Run(owner+"/"+filename+"/"+fixture.expression, func(t *testing.T) {
					dir := t.TempDir()
					body := "package fixture\nimport " + fixture.imported + "\n" + fixture.expression + "\n"
					if err := os.WriteFile(filepath.Join(dir, filename), []byte(body), 0600); err != nil {
						t.Fatal(err)
					}
					packages := []compiledPackage{{ImportPath: modulePrefix + owner, Dir: dir, GoFiles: []string{filename}}}
					if checkBoundary("core", []resolvedModule{{Path: modulePrefix + "core"}}, packages) == nil {
						t.Fatal("Core private-key use admitted")
					}
				})
			}
		}
	}
}

// full_only: false
func TestCoreCustodyAllowsPublicParsingVerificationAndLocalNames(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "public.go")
	body := "package core\nimport (r \"crypto/rsa\"; x \"crypto/x509\")\nvar _ *r.PublicKey\nvar _ = r.VerifyPSS\nvar _ = x.ParsePKIXPublicKey\nfunc public() { r := struct{PrivateKey int}{1}; _ = r.PrivateKey }\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkCoreCustodyFile(path); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestCoreTestImportsAllowExactFacadeEdgesOnly(t *testing.T) {
	for _, imported := range []string{modulePrefix + "compositions/configuration", modulePrefix + "compositions/manifesthost", "enkv.sh/sdk/artifact", cloudflareModulePath + "/profile"} {
		t.Run("runner/"+imported, func(t *testing.T) {
			runner := compiledPackage{ImportPath: modulePrefix + "core/internal/testmain", Imports: []string{imported}}
			if err := checkCustodyImports([]compiledPackage{runner}, true, ""); err != nil {
				t.Fatal("runner input owner refused", err)
			}
			if checkCustodyImports([]compiledPackage{runner}, false, "") == nil {
				t.Fatal("runner input owner entered production compilation")
			}
			for _, owner := range []string{"core", "core/contract", "core/format", "core/internal/testrecords", "core/internal/testcatalog", "core/internal/testmain/nested"} {
				other := compiledPackage{ImportPath: modulePrefix + owner, ForTest: modulePrefix + owner, Imports: []string{imported}}
				wantAllowed := imported == "enkv.sh/sdk/artifact" && (owner == "core" || owner == "core/contract" || owner == "core/internal/testrecords")
				err := checkCustodyImports([]compiledPackage{other}, true, "")
				if (err == nil) != wantAllowed {
					t.Fatal("runner input allowance differs for test package", owner, imported, err)
				}
			}
			for _, dependency := range []string{imported + "/internal", modulePrefix + "compositions/full", modulePrefix + "compositions/aws", modulePrefix + "providers/aws"} {
				other := runner
				other.Imports = []string{dependency}
				if checkCustodyImports([]compiledPackage{other}, true, "") == nil {
					t.Fatal("runner input owner allowance admitted another dependency", dependency)
				}
			}
		})
	}
	for _, owner := range []string{"core", "core/contract", "core/format"} {
		for _, imported := range []string{"crypto/testsupport/trust", "crypto/testsupport/custody", "crypto/testsupport/installedarchive", "crypto", "crypto/testsupport/trust/private", "crypto/testsupport/installedarchive/private", "crypto/testsupport/installedarchive/recovery", "crypto/internal/custody"} {
			p := compiledPackage{ImportPath: modulePrefix + owner, ForTest: modulePrefix + owner, Imports: []string{modulePrefix + imported}}
			packages := []compiledPackage{p, {ImportPath: modulePrefix + "crypto/testsupport/custody", Imports: []string{modulePrefix + "crypto"}}, {ImportPath: modulePrefix + "crypto"}}
			err := checkCustodyImports(packages, true, "")
			if (err == nil) != cryptoFacade(modulePrefix+imported) {
				t.Fatalf("Core test edge %s -> %s: %v", owner, imported, err)
			}
			p.ForTest = ""
			if checkCustodyImports([]compiledPackage{p}, true, "") == nil {
				t.Fatal("test assembly admitted a production Core custody edge")
			}
		}
	}
}

// full_only: false
func TestCoreProcessTestImportsOnlyExactGeneratorHostAndWireProtocol(t *testing.T) {
	host := compiledPackage{ImportPath: modulePrefix + "core", ForTest: modulePrefix + "core", Imports: []string{modulePrefix + "compositions/generatorhost"}}
	if err := checkCustodyImports([]compiledPackage{host}, true, ""); err != nil {
		t.Fatal(err)
	}
	host.Imports = []string{modulePrefix + "compositions/generatorhost/testsupport"}
	if checkCustodyImports([]compiledPackage{host}, true, "") == nil {
		t.Fatal("Core test imported the host artifact-admission facade")
	}
	host.Imports = []string{modulePrefix + "compositions/generatorhost"}
	host.ForTest = ""
	if checkCustodyImports([]compiledPackage{host}, true, "") == nil {
		t.Fatal("production Core admitted the process host")
	}
	host.ForTest = modulePrefix + "core"
	host.Imports = []string{"enkv.sh/sdk/protocols/generator"}
	if err := checkCustodyImports([]compiledPackage{host}, true, ""); err != nil {
		t.Fatal("Core test refused the public generator wire contract", err)
	}
	host.Imports = []string{"enkv.sh/sdk/protocols/generator/internal"}
	if checkCustodyImports([]compiledPackage{host}, true, "") == nil {
		t.Fatal("Core test admitted private generator wire internals")
	}
	host.Imports = []string{"enkv.sh/sdk/protocols/generator"}
	host.ForTest = ""
	if err := checkCustodyImports([]compiledPackage{host}, true, ""); err != nil {
		t.Fatal("production Core refused the public generator contract", err)
	}
	host.ForTest = modulePrefix + "core"
	composition := compiledPackage{ImportPath: modulePrefix + "core", ForTest: modulePrefix + "core", Imports: []string{modulePrefix + "compositions/aws"}}
	if checkCustodyImports([]compiledPackage{composition}, true, "") == nil {
		t.Fatal("Core test admitted a trust composition")
	}
}

// full_only: false
func TestCoreTestTelemetryWireImportsAreExactAndTestOnly(t *testing.T) {
	for _, imported := range []string{
		"go.opentelemetry.io/proto/otlp/collector/logs/v1",
		"go.opentelemetry.io/proto/otlp/collector/metrics/v1",
		"go.opentelemetry.io/proto/otlp/collector/trace/v1",
		"google.golang.org/protobuf/encoding/protojson",
		"google.golang.org/protobuf/proto",
	} {
		fixture := compiledPackage{ImportPath: modulePrefix + "core", ForTest: modulePrefix + "core", Imports: []string{imported}}
		if err := checkCustodyImports([]compiledPackage{fixture}, true, ""); err != nil {
			t.Fatal("test refused a reviewed telemetry decoder", imported, err)
		}
		if checkCustodyImports([]compiledPackage{fixture}, false, "") == nil {
			t.Fatal("production assembly admitted telemetry wire imports", imported)
		}
		fixture.ForTest = ""
		if checkCustodyImports([]compiledPackage{fixture}, true, "") == nil {
			t.Fatal("production Core imported telemetry wire code", imported)
		}
	}
	for _, imported := range []string{
		"go.opentelemetry.io/proto/otlp/collector/logs/v1/internal",
		"go.opentelemetry.io/proto/otlp/collector/logs/v2",
		"google.golang.org/protobuf/encoding/protojson/internal",
		"google.golang.org/protobuf/reflect/protoreflect",
		"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp",
		"go.opentelemetry.io/otel/log",
		"go.opentelemetry.io/otel/sdk/log",
		"google.golang.org/grpc",
	} {
		fixture := compiledPackage{ImportPath: modulePrefix + "core", ForTest: modulePrefix + "core", Imports: []string{imported}}
		if checkCustodyImports([]compiledPackage{fixture}, true, "") == nil {
			t.Fatal("test admitted an unreviewed telemetry dependency", imported)
		}
	}
}

// full_only: false
func TestCryptoTestImportsOnlyExactObservabilitySetup(t *testing.T) {
	packagePath := modulePrefix + "crypto"
	setup := modulePrefix + "compositions/observability"
	fixture := compiledPackage{ImportPath: packagePath, ForTest: packagePath, Imports: []string{setup}}
	if err := checkCustodyImports([]compiledPackage{fixture}, true, ""); err != nil {
		t.Fatal(err)
	}
	for _, imported := range []string{setup + "/internal", modulePrefix + "compositions/aws"} {
		fixture.Imports = []string{imported}
		if checkCustodyImports([]compiledPackage{fixture}, true, "") == nil {
			t.Fatal("Crypto test admitted a private composition")
		}
	}
	fixture.Imports = []string{setup}
	fixture.ForTest = ""
	if checkCustodyImports([]compiledPackage{fixture}, true, "") == nil {
		t.Fatal("production Crypto admitted observability setup")
	}
}

// full_only: false
func TestLiveBoundaryAdmitsOnlySelectedProviderAndNeutralSDK(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		modules := []resolvedModule{{Path: "enkv.sh/core"}, {Path: "go.opentelemetry.io/otel/sdk", Version: "v1.36.0"}, {Path: "github.com/google/uuid", Version: "v1.6.0"}}
		packages := []compiledPackage{{ImportPath: "enkv.sh/providers/" + provider}, {ImportPath: "go.opentelemetry.io/otel/sdk/metric"}}
		if err := checkLiveBoundary(provider, modules, packages); err != nil {
			t.Fatal(err)
		}
		t.Run(provider+"/retained-decoder", func(t *testing.T) {
			const retained = "enkv.sh/sdk/protocols/generator/retained"
			fixture := compiledPackage{ImportPath: modulePrefix + "core", ForTest: modulePrefix + "core", Imports: []string{retained}}
			t.Run("selected-live-test", func(t *testing.T) {
				if err := checkLiveBoundary(provider, modules, append(packages, fixture, compiledPackage{ImportPath: retained})); err != nil {
					t.Fatal("live retained decoder refused", err)
				}
			})
			t.Run("production-and-hermetic", func(t *testing.T) {
				if checkCustodyImports([]compiledPackage{fixture}, false, provider) == nil || checkCustodyImports([]compiledPackage{fixture}, true, "") == nil {
					t.Fatal("retained decoder escaped selected live tests")
				}
				production := fixture
				production.ForTest = ""
				if checkCustodyImports([]compiledPackage{production}, true, provider) == nil {
					t.Fatal("production Core imported retained decoder")
				}
			})
			for _, imported := range []string{retained + "/private", "enkv.sh/sdk/generator/retained"} {
				t.Run(imported, func(t *testing.T) {
					changed := fixture
					changed.Imports = []string{imported}
					if checkCustodyImports([]compiledPackage{changed}, true, provider) == nil {
						t.Fatal("live decoder allowance admitted another package")
					}
				})
			}
		})
		if checkLiveBoundary(provider, modules, packages[1:]) == nil {
			t.Fatal("missing provider admitted")
		}
		if checkLiveBoundary(provider, modules, append(packages, compiledPackage{ImportPath: "enkv.sh/compositions/full"})) == nil {
			t.Fatal("composition entered private test assembly")
		}
	}
	if checkLiveBoundary("gcp", []resolvedModule{{Path: "github.com/aws/aws-sdk-go-v2"}}, []compiledPackage{{ImportPath: "enkv.sh/providers/gcp"}}) == nil {
		t.Fatal("sibling module admitted")
	}
	if checkLiveBoundary("aws", nil, []compiledPackage{{ImportPath: "enkv.sh/providers/aws"}, {ImportPath: "google.golang.org/api/storage/v1"}}) == nil {
		t.Fatal("sibling compiled package admitted")
	}
}

// full_only: false
func TestCoreOutputImportsAreExactAndTestOnly(t *testing.T) {
	for _, owner := range []string{"core", "core/contract", "core/format"} {
		for _, imported := range []string{"enkv.sh/compositions/outputhost", "enkv.sh/sdk/protocols/output", "enkv.sh/compositions/outputhost/private", "enkv.sh/sdk/protocols/output/private", "enkv.sh/plugins/outputs/aws-secrets-manager"} {
			t.Run(owner+"/"+imported, func(t *testing.T) {
				p := compiledPackage{ImportPath: modulePrefix + owner, ForTest: modulePrefix + owner, Imports: []string{imported}}
				exact := imported == "enkv.sh/compositions/outputhost" || imported == "enkv.sh/sdk/protocols/output"
				if err := checkCustodyImports([]compiledPackage{p}, true, ""); (err == nil) != exact {
					t.Fatalf("test edge: %v", err)
				}
				production := imported == "enkv.sh/sdk/protocols/output" && (owner == "core" || owner == "core/contract")
				if err := checkCustodyImports([]compiledPackage{p}, false, ""); (err == nil) != production {
					t.Fatal("production output contract edge differs", err)
				}
				p.ForTest = ""
				if err := checkCustodyImports([]compiledPackage{p}, true, ""); (err == nil) != production {
					t.Fatal("production output edge changed in a test graph", err)
				}
			})
		}
	}
}

// full_only: false
func TestFacadeOutputMetadataTypesAreExactAndRecursive(t *testing.T) {
	named := func(path, name string, underlying types.Type) *types.Named {
		p := types.NewPackage(path, "fixture")
		return types.NewNamed(types.NewTypeName(token.NoPos, p, name, nil), underlying, nil)
	}
	field := func(value types.Type) *types.Struct {
		return types.NewStruct([]*types.Var{types.NewField(token.NoPos, nil, "Value", value, false)}, nil)
	}
	id := named("enkv.sh/sdk/protocols/output", "ID", types.NewArray(types.Typ[types.Byte], 32))
	safe := field(id)
	for _, tc := range []struct {
		path, importPath, name string
		value                  types.Type
		allowed                bool
	}{
		{"compositions/generatorhost", "enkv.sh/compositions/generatorhost", "Installation", safe, false},
		{"compositions/generatorhost", "enkv.sh/compositions/generatorhost", "Config", safe, false},
		{"sdk/artifact", "enkv.sh/sdk/artifact", "Metadata", safe, false},
		{"sdk/artifact", "enkv.sh/sdk/artifact", "GeneratorFacts", safe, false},
		{"compositions/outputhost", "enkv.sh/compositions/outputhost", "Config", safe, false},
		{"compositions/outputhost", "enkv.sh/compositions/outputhost", "Installation", safe, false},
		{"compositions/outputhost", "enkv.sh/compositions/outputhost", "Artifact", safe, true},
		{"compositions/outputhost", "enkv.sh/compositions/outputhost", "CredentialRoute", safe, false},
		{"compositions/outputhost", "enkv.sh/compositions/outputhost", "PublicationActionFacts", safe, false},
		{"protocols/output", "enkv.sh/sdk/protocols/output", "ProfileResult", safe, false},
		{"protocols/output", "enkv.sh/sdk/protocols/output", "ActionCheckResult", safe, true},
		{"protocols/output", "enkv.sh/sdk/protocols/output", "PayloadBounds", safe, true},
		{"protocols/output", "enkv.sh/sdk/protocols/output", "ID", types.NewArray(types.Typ[types.Byte], 32), true},
		{"compositions/outputhost", "enkv.sh/compositions/outputhost", "Native", safe, false},
		{"compositions/outputhost", "enkv.sh/compositions/outputhost", "PublicValidator", safe, false},
		{"protocols/output", "enkv.sh/sdk/protocols/output", "Credential", safe, false},
		{"protocols/output", "enkv.sh/sdk/protocols/output", "Command", safe, false},
		{"protocols/output", "enkv.sh/sdk/protocols/output", "Policy", safe, false},
		{"compositions/outputhost/private", "enkv.sh/compositions/outputhost/private", "Config", safe, false},
		{"protocols/output/private", "enkv.sh/sdk/protocols/output/private", "ProfileResult", safe, false},
	} {
		t.Run(tc.path+"/"+tc.name, func(t *testing.T) {
			p := types.NewPackage(modulePrefix+"crypto/testsupport/custody", "custody")
			p.Scope().Insert(types.NewVar(token.NoPos, p, "Metadata", named(tc.importPath, tc.name, tc.value)))
			if err := checkFacadeSurface(p); (err == nil) != tc.allowed {
				t.Fatalf("allowed=%t: %v", tc.allowed, err)
			}
		})
	}
	callback := types.NewSignatureType(nil, nil, nil, types.NewTuple(), types.NewTuple(), false)
	rawBytes := types.NewSlice(types.Typ[types.Byte])
	for _, tc := range []struct {
		name  string
		value types.Type
	}{
		{"callback", callback},
		{"nested_callback", types.NewArray(callback, 1)},
		{"interface", types.NewInterfaceType(nil, nil).Complete()},
		{"error_interface", types.Universe.Lookup("error").Type()},
		{"bytes", rawBytes},
		{"pointer", types.NewPointer(id)},
		{"installation_pointer", types.NewPointer(named(modulePrefix+"compositions/outputhost", "Installation", safe))},
		{"native", named(modulePrefix+"compositions/outputhost", "Native", safe)},
		{"private", named(modulePrefix+"crypto", "PublicationOwner", safe)},
		{"map", types.NewMap(types.Typ[types.String], id)},
		{"channel", types.NewChan(types.SendRecv, id)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := types.NewPackage(modulePrefix+"crypto/testsupport/custody", "custody")
			// Ordinary facade bytes must not exempt a later metadata field of the same type.
			p.Scope().Insert(types.NewVar(token.NoPos, p, "ABytes", rawBytes))
			artifact := named(modulePrefix+"compositions/outputhost", "Artifact", field(tc.value))
			metadata := named("enkv.sh/sdk/protocols/output", "ActionCheckResult", field(artifact))
			p.Scope().Insert(types.NewVar(token.NoPos, p, "Metadata", metadata))
			if checkFacadeSurface(p) == nil {
				t.Fatal("unsafe nested metadata admitted")
			}
		})
	}
}

// full_only: false
func TestFacadeOutputMetadataMethodsKeepPrivateTypesOutsideCore(t *testing.T) {
	for _, tc := range []struct {
		name    string
		result  types.Type
		allowed bool
	}{
		{"public", types.Typ[types.Bool], true},
		{"callback", types.NewSignatureType(nil, nil, nil, types.NewTuple(), types.NewTuple(), false), false},
		{"bytes", types.NewSlice(types.Typ[types.Byte]), false},
		{"private", types.NewPointer(types.NewNamed(types.NewTypeName(token.NoPos, types.NewPackage(modulePrefix+"compositions/outputhost", "outputhost"), "Native", nil), types.NewStruct(nil, nil), nil)), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := types.NewPackage(modulePrefix+"compositions/outputhost", "outputhost")
			metadata := types.NewNamed(types.NewTypeName(token.NoPos, host, "Artifact", nil), types.NewStruct(nil, nil), nil)
			receiver := types.NewVar(token.NoPos, host, "a", metadata)
			result := types.NewVar(token.NoPos, host, "", tc.result)
			metadata.AddMethod(types.NewFunc(token.NoPos, host, "Result", types.NewSignatureType(receiver, nil, nil, types.NewTuple(), types.NewTuple(result), false)))
			facade := types.NewPackage(modulePrefix+"crypto/testsupport/custody", "custody")
			facade.Scope().Insert(types.NewVar(token.NoPos, facade, "Metadata", metadata))
			if err := checkFacadeSurface(facade); (err == nil) != tc.allowed {
				t.Fatalf("allowed=%t: %v", tc.allowed, err)
			}
		})
	}
}

// full_only: false
func TestPureProfileBoundaryKeepsEffectsOutsideSharedReaders(t *testing.T) {
	modules := []resolvedModule{{Path: modulePrefix + "core"}, {Path: "enkv.sh/plugins/generators/cloudflare-account-token", Version: "v0.1.1"}}
	packages := []compiledPackage{{ImportPath: modulePrefix + "core"}, {ImportPath: "enkv.sh/plugins/generators/cloudflare-account-token/profile"}, {ImportPath: "enkv.sh/plugins/generators/local-random-secret/profile"}, {ImportPath: "enkv.sh/plugins/generators/cloudflare-account-token/artifact"}}
	if err := checkHermeticBoundary(modules, packages); err != nil {
		t.Fatal("pure generator profile refused", err)
	}
	if checkGeneratorHost(packages[1:]) == nil {
		t.Fatal("generator host admitted concrete plugin profiles")
	}
	for _, suffix := range []string{"", "/internal/cloudflare", "/profile/child", "/artifact/child", "/cmd/enkv-generator-cloudflare"} {
		name := cloudflareModulePath + suffix
		unsafe := []compiledPackage{{ImportPath: name}}
		if checkHermeticBoundary(modules, unsafe) == nil || checkGeneratorHost(unsafe) == nil {
			t.Fatal("effect package admitted", name)
		}
	}
}

// full_only: false
func TestPassiveProfileCompositionAndLiveBoundariesRefuseEffects(t *testing.T) {
	modules := []resolvedModule{{Path: modulePrefix + "core", Version: "v0.1.1"}, {Path: modulePrefix + "crypto", Version: "v0.1.1"}, {Path: modulePrefix + "telemetry", Version: "v0.1.1"}}
	packages := []compiledPackage{{ImportPath: modulePrefix + "core"}, {ImportPath: modulePrefix + "core/contract"}, {ImportPath: modulePrefix + "core/format"}, {ImportPath: modulePrefix + "crypto"}, {ImportPath: modulePrefix + "telemetry"}}
	packages = append(packages, compiledPackage{ImportPath: "enkv.sh/sdk/artifact/credentialroute"})
	if err := checkComposition("compositions/full", modules, packages); err != nil {
		t.Fatal("common public composition refused", err)
	}
	for _, owner := range []string{"cloudflare", "local-random-secret", "aws-output", "gcp-output", "github-output"} {
		for _, suffix := range []string{"", "/profile", "/artifact", "/credential", "/internal/client", "/profile/child", "/artifact/child", "/credential/child", "/cmd/child"} {
			if checkComposition("compositions/full", modules, append(packages, compiledPackage{ImportPath: modulePath("plugins/"+owner) + suffix})) == nil {
				t.Fatal("composition admitted plugin effects", owner, suffix)
			}
		}
	}
	for _, provider := range []string{"aws", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			sibling, siblingSDK := "gcp", "google.golang.org/api"
			if provider == "gcp" {
				sibling, siblingSDK = "aws", "github.com/aws/aws-sdk-go-v2"
			}
			live := []compiledPackage{{ImportPath: modulePrefix + "providers/" + provider}, {ImportPath: "enkv.sh/plugins/generators/cloudflare-account-token/profile"}, {ImportPath: "enkv.sh/plugins/generators/local-random-secret/profile"}, {ImportPath: "enkv.sh/plugins/generators/cloudflare-account-token/artifact"}}
			if err := checkLiveBoundary(provider, nil, live); err != nil {
				t.Fatal("live passive generator profile refused", err)
			}
			for _, suffix := range []string{"/artifact/private", "/cmd/enkv-generator-cloudflare", "/internal/cloudflare"} {
				if checkLiveBoundary(provider, nil, append(append([]compiledPackage(nil), live...), compiledPackage{ImportPath: cloudflareModulePath + suffix})) == nil {
					t.Fatal("live passive decoder allowance admitted an effect package", suffix)
				}
			}
			liveModules := []resolvedModule{
				{Path: "enkv.sh/plugins/generators/cloudflare-account-token", Version: "v0.1.1"},
				{Path: "enkv.sh/plugins/generators/local-random-secret", Version: "v0.1.1"},
				{Path: modulePath("plugins/" + provider + "-output"), Version: "v0.1.1"},
				{Path: "enkv.sh/plugins/outputs/github-actions", Version: "v0.1.1"},
			}
			live = append(live, compiledPackage{ImportPath: modulePath("plugins/"+provider+"-output") + "/profile"}, compiledPackage{ImportPath: "enkv.sh/plugins/outputs/github-actions/profile"})
			live = append(live, compiledPackage{ImportPath: modulePath("plugins/"+provider+"-output") + "/credential", Imports: []string{"encoding/binary", "enkv.sh/sdk/protocols/output"}}, compiledPackage{ImportPath: "encoding/binary", Standard: true})
			coreProfileImports := compiledPackage{ImportPath: modulePrefix + "core", ForTest: modulePrefix + "core", Imports: []string{
				"enkv.sh/plugins/generators/cloudflare-account-token/profile",
				modulePath("plugins/"+provider+"-output") + "/profile",
				modulePath("plugins/"+provider+"-output") + "/credential",
				"enkv.sh/plugins/outputs/github-actions/profile",
			}}
			live = append(live, coreProfileImports)
			if err := checkLiveBoundary(provider, liveModules, live); err != nil {
				t.Fatal("live own cloud and GitHub passive profiles refused", err)
			}
			t.Run("manifest-renderer", func(t *testing.T) {
				rendererModules := append(append([]resolvedModule(nil), liveModules...), resolvedModule{Path: genericJSONPath, Version: "v0.1.1"}, resolvedModule{Path: manifestSDKPath, Version: "v0.1.1"})
				rendererPackages := append([]compiledPackage(nil), live...)
				rendererCore := coreProfileImports
				rendererCore.Imports = append(append([]string(nil), coreProfileImports.Imports...), genericJSONPath)
				rendererPackages[len(live)-1] = rendererCore
				rendererPackages = append(rendererPackages, compiledPackage{ImportPath: genericJSONPath, Imports: []string{manifestSDKPath}}, compiledPackage{ImportPath: manifestSDKPath})
				t.Run("exact-owner-and-test-importer", func(t *testing.T) {
					if err := checkLiveBoundary(provider, rendererModules, rendererPackages); err != nil {
						t.Error("live public manifest renderer refused", err)
					}
				})
				t.Run("compiled-root-and-test-importer", func(t *testing.T) {
					// Exercise the compiled-package gate independently of the
					// resolved renderer row, whose gate has its own control.
					if err := checkLiveBoundary(provider, liveModules, rendererPackages); err != nil {
						t.Error("live compiled renderer root refused", err)
					}
				})
				for _, version := range []string{"", "v0.0.1", "v1.0.0"} {
					t.Run("resolved-version="+version, func(t *testing.T) {
						bad := append(append([]resolvedModule(nil), liveModules...), resolvedModule{Path: genericJSONPath, Version: version})
						if checkLiveBoundary(provider, bad, live) == nil {
							t.Fatal("live renderer admitted wrong selected version", version)
						}
					})
				}
				for _, suffix := range []string{"child", "conformance", "native", "cmd/helper", "helper"} {
					t.Run("resolved-child/"+suffix, func(t *testing.T) {
						bad := append(append([]resolvedModule(nil), liveModules...), resolvedModule{Path: genericJSONPath + "/" + suffix, Version: "v0.1.0"})
						if checkLiveBoundary(provider, bad, live) == nil {
							t.Fatal("live renderer admitted a nested module", suffix)
						}
					})
					t.Run("compiled-child/"+suffix, func(t *testing.T) {
						bad := append(append([]compiledPackage(nil), live...), compiledPackage{ImportPath: genericJSONPath + "/" + suffix})
						if checkLiveBoundary(provider, liveModules, bad) == nil {
							t.Fatal("live renderer admitted a nested package", suffix)
						}
					})
				}
				const unknown = "enkv.sh/plugins/manifest-generators/unreviewed"
				t.Run("unknown-resolved-plugin", func(t *testing.T) {
					bad := append(append([]resolvedModule(nil), liveModules...), resolvedModule{Path: unknown, Version: "v0.1.0"})
					if checkLiveBoundary(provider, bad, live) == nil {
						t.Fatal("live renderer allowance admitted an unknown plugin module")
					}
				})
				t.Run("unknown-compiled-plugin", func(t *testing.T) {
					bad := append(append([]compiledPackage(nil), live...), compiledPackage{ImportPath: unknown})
					if checkLiveBoundary(provider, liveModules, bad) == nil {
						t.Fatal("live renderer allowance admitted an unknown plugin package")
					}
				})
				t.Run("production-Core-importer", func(t *testing.T) {
					bad := append([]compiledPackage(nil), rendererPackages...)
					bad[len(live)-1] = compiledPackage{ImportPath: modulePrefix + "core", Imports: []string{genericJSONPath}}
					if checkLiveBoundary(provider, liveModules, bad) == nil {
						t.Fatal("production Core imported the test renderer")
					}
				})
			})
			ownCredential := modulePath("plugins/"+provider+"-output") + "/credential"
			if !liveOutputCredential(provider, ownCredential) {
				t.Fatal("live own credential codec refused")
			}
			for _, credential := range []string{modulePath("plugins/"+sibling+"-output") + "/credential", "enkv.sh/plugins/outputs/github-actions/credential"} {
				if liveOutputCredential(provider, credential) {
					t.Fatal("live credential allowance crossed provider boundary", credential)
				}
				codec := compiledPackage{ImportPath: credential, Imports: []string{"enkv.sh/sdk/protocols/output"}}
				if checkLiveBoundary(provider, liveModules, append(live, codec)) == nil {
					t.Fatal("live assembly admitted an unselected credential codec", credential)
				}
				core := compiledPackage{ImportPath: modulePrefix + "core", ForTest: modulePrefix + "core", Imports: []string{credential}}
				if checkCustodyImports([]compiledPackage{core}, true, provider) == nil {
					t.Fatal("Core live tests imported an unselected credential codec", credential)
				}
			}
			for _, imported := range []string{modulePrefix + "providers/" + provider, modulePrefix + "core", "github.com/aws/aws-sdk-go-v2/aws", "cloud.google.com/go/auth"} {
				unsafeCodec := compiledPackage{ImportPath: modulePath("plugins/"+provider+"-output") + "/credential", Imports: []string{imported}}
				if checkLiveBoundary(provider, liveModules, append(live, unsafeCodec)) == nil || checkComposition("compositions/full", modules, append(packages, unsafeCodec)) == nil {
					t.Fatal("credential codec acquired non-wire dependency", imported)
				}
			}
			for _, owner := range []string{"cloudflare", "local-random-secret", "aws-output", "gcp-output", "github-output"} {
				for _, suffix := range []string{"", "/internal/client", "/profile/child", "/credential/child", "/cmd/child"} {
					name := modulePath("plugins/"+owner) + suffix
					if checkLiveBoundary(provider, liveModules, append(live, compiledPackage{ImportPath: name})) == nil {
						t.Fatal("live assembly admitted plugin effects", name)
					}
					unsafeCore := compiledPackage{ImportPath: modulePrefix + "core", ForTest: modulePrefix + "core", Imports: []string{name}}
					if checkCustodyImports([]compiledPackage{unsafeCore}, true, provider) == nil {
						t.Fatal("Core live tests directly imported plugin effects", name)
					}
				}
			}
			if checkLiveBoundary(provider, liveModules, append(live, compiledPackage{ImportPath: "enkv.sh/plugins/generators/cloudflare-account-token/internal/cloudflare"})) == nil {
				t.Fatal("live assembly admitted Cloudflare effects")
			}
			for _, name := range []string{modulePath("plugins/"+sibling+"-output") + "/profile", modulePath("plugins/"+sibling+"-output") + "/credential", modulePrefix + "providers/" + sibling, siblingSDK + "/internal/client"} {
				if checkLiveBoundary(provider, liveModules, append(live, compiledPackage{ImportPath: name})) == nil {
					t.Fatal("live assembly admitted sibling compiled package", name)
				}
			}
			for _, name := range []string{modulePath("plugins/" + sibling + "-output"), modulePath("plugins/"+provider+"-output") + "/child", "enkv.sh/plugins/outputs/github-actions/child", "enkv.sh/plugins/generators/cloudflare-account-token/child", modulePrefix + "providers/" + sibling, siblingSDK} {
				if checkLiveBoundary(provider, append(liveModules, resolvedModule{Path: name, Version: "v0.1.0"}), live) == nil {
					t.Fatal("live assembly admitted sibling resolved module", name)
				}
			}
			for _, imported := range coreProfileImports.Imports {
				singleProfileImport := coreProfileImports
				singleProfileImport.Imports = []string{imported}
				production := compiledPackage{ImportPath: modulePrefix + "core", Imports: []string{imported}}
				if checkCustodyImports([]compiledPackage{production}, true, provider) == nil || checkCustodyImports([]compiledPackage{singleProfileImport}, false, provider) == nil {
					t.Fatal("production Core imported passive test profile", imported)
				}
				if checkCustodyImports([]compiledPackage{singleProfileImport}, true, "") == nil {
					t.Fatal("hermetic Core tests imported live passive profiles")
				}
			}
			siblingCore := compiledPackage{ImportPath: modulePrefix + "core", ForTest: modulePrefix + "core", Imports: []string{modulePath("plugins/"+sibling+"-output") + "/profile"}}
			if checkCustodyImports([]compiledPackage{siblingCore}, true, provider) == nil {
				t.Fatal("Core live tests directly imported sibling passive profile")
			}
			for _, owner := range []string{"cloudflare", provider + "-output", "github-output"} {
				for _, version := range []string{"", "v0.0.1", "v1.0.0"} {
					unpinned := append([]resolvedModule(nil), liveModules...)
					for i := range unpinned {
						if unpinned[i].Path == modulePath("plugins/"+owner) {
							unpinned[i].Version = version
						}
					}
					if checkLiveBoundary(provider, unpinned, live) == nil {
						t.Fatal("live assembly admitted unpinned passive module", owner, version)
					}
				}
			}
		})
	}
}

// full_only: false
func TestCoreArtifactMetadataKeepsExactTestOwner(t *testing.T) {
	for _, provider := range []string{"", "aws", "gcp"} {
		for _, owner := range []string{"core", "core/contract", "core/format", "core/internal/testrecords", "core/internal/testrecords/nested", "core/internal/testcatalog", "core/internal/testmain/nested"} {
			for _, forTest := range []string{"", modulePrefix + owner, modulePrefix + "core/other"} {
				for _, imported := range []string{"enkv.sh/sdk/artifact", "enkv.sh/sdk/artifact/build", "enkv.sh/sdk/artifact/cmd", "enkv.sh/sdk/artifact/internal"} {
					pkg := compiledPackage{ImportPath: modulePrefix + owner, ForTest: forTest, Imports: []string{imported}}
					production := owner == "core/contract" && imported == "enkv.sh/sdk/artifact"
					want := production || imported == "enkv.sh/sdk/artifact" && (owner == "core" && forTest == modulePrefix+"core" || owner == "core/internal/testrecords")
					if got := checkCustodyImports([]compiledPackage{pkg}, true, provider); (got == nil) != want {
						t.Fatalf("metadata edge owner=%s provider=%s test=%s import=%s: %v", owner, provider, forTest, imported, got)
					}
					if err := checkCustodyImports([]compiledPackage{pkg}, false, provider); (err == nil) != production {
						t.Fatal("metadata production owner differs", err)
					}
				}
			}
		}
	}
}

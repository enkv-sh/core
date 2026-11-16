package main

import "testing"

// full_only: false
func TestManifestHostBoundaryKeepsNativeServingOutsideHost(t *testing.T) {
	modules := []resolvedModule{
		{Path: "enkv.sh/compositions/manifesthost"},
		{Path: nativeProcessPath, Version: "v0.1.0", Replace: &resolvedModule{Path: "../internal/nativeprocess"}},
		{Path: "enkv.sh/sdk/artifact", Version: "v0.1.0", Replace: &resolvedModule{Path: "../../../enkv-extensions/sdk/artifact"}},
		{Path: manifestSDKPath, Version: "v0.1.0", Replace: &resolvedModule{Path: "../../../enkv-extensions/sdk/manifest-generator"}},
		{Path: "enkv.sh/sdk/protocols/manifest-generator", Version: "v0.1.0", Replace: &resolvedModule{Path: "../../../enkv-extensions/sdk/protocols/manifest-generator"}},
		{Path: "enkv.sh/telemetry", Version: "v0.1.0", Replace: &resolvedModule{Path: "../../telemetry"}},
		{Path: "golang.org/x/sys", Version: "v0.33.0"},
	}
	packages := []compiledPackage{{ImportPath: "enkv.sh/compositions/manifesthost"}, {ImportPath: nativeProcessPath}, {ImportPath: manifestSDKPath}, {ImportPath: "enkv.sh/sdk/protocols/manifest-generator"}, {ImportPath: "enkv.sh/sdk/artifact"}, {ImportPath: "enkv.sh/sdk/artifact/credentialroute"}, {ImportPath: "golang.org/x/sys/unix"}, {ImportPath: "context", Standard: true}}
	if err := checkBoundary("compositions/manifesthost", modules, packages); err != nil {
		t.Fatal(err)
	}
	for i := range modules {
		missing := append([]resolvedModule(nil), modules[:i]...)
		missing = append(missing, modules[i+1:]...)
		if checkBoundary("compositions/manifesthost", missing, packages) == nil {
			t.Fatal("missing module accepted", modules[i].Path)
		}
	}
	for _, path := range []string{manifestSDKPath + "/native", manifestSDKPath + "/conformance", manifestSDKPath + "/jsonwriter", genericJSONPath, "enkv.sh/sdk/artifact/build", "enkv.sh/sdk/artifact/cmd/enkv-plugin-build", "enkv.sh/sdk/artifact/credentialroute/unreviewed", "enkv.sh/plugins/unlisted/implementation", "enkv.sh/compositions/full/plugininstallation", "enkv.sh/core", "enkv.sh/crypto", "go.opentelemetry.io/otel/sdk", "go.opentelemetry.io/otel/sdk/trace", "go.opentelemetry.io/auto/sdk", "go.opentelemetry.io/auto/sdk/internal/telemetry", "go.opentelemetry.io/otel/exporters", "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp", "go.opentelemetry.io/otel/log", "go.opentelemetry.io/otel/log/embedded", "example.invalid/helper"} {
		if checkBoundary("compositions/manifesthost", modules, append(packages, compiledPackage{ImportPath: path})) == nil {
			t.Fatal("unreviewed compiled package accepted", path)
		}
	}
	if checkBoundary("compositions/manifesthost", append(modules, modules[1]), packages) == nil {
		t.Fatal("duplicate module accepted")
	}
	wrong := append([]resolvedModule(nil), modules...)
	wrong[4].Replace = &resolvedModule{Path: "../substitute"}
	if checkBoundary("compositions/manifesthost", wrong, packages) == nil {
		t.Fatal("substituted wire module accepted")
	}
}

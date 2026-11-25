package main

import "errors"

func checkManifestHost(modules []resolvedModule, packages []compiledPackage) error {
	const main = "enkv.sh/compositions/manifesthost"
	local := map[string]string{
		nativeProcessPath:                          "../internal/nativeprocess",
		"enkv.sh/sdk/artifact":                     "../../../enkv-extensions/sdk/artifact",
		manifestSDKPath:                            "../../../enkv-extensions/sdk/manifest-generator",
		"enkv.sh/sdk/protocols/manifest-generator": "../../../enkv-extensions/sdk/protocols/manifest-generator",
		"enkv.sh/telemetry":                        "../../telemetry",
	}
	seen := make(map[string]bool, len(modules))
	for _, module := range modules {
		if seen[module.Path] {
			return errors.New("manifest host module duplicated")
		}
		seen[module.Path] = true
		if module.Path == main {
			if module.Version != "" || module.Replace != nil {
				return errors.New("manifest host main identity differs")
			}
		} else if replacement, ok := local[module.Path]; ok {
			version := reviewedLocalModuleVersion(module.Path)
			if version == "" || module.Version != version || module.Replace == nil || module.Replace.Path != replacement || module.Replace.Version != "" || module.Replace.Replace != nil {
				return errors.New("manifest host local dependency differs")
			}
		} else if version := neutralModules[module.Path]; version == "" || version != module.Version || module.Replace != nil {
			return errors.New("manifest host dependency differs")
		}
	}
	if !seen[main] || !seen["golang.org/x/sys"] {
		return errors.New("manifest host required module missing")
	}
	for path := range local {
		if !seen[path] {
			return errors.New("manifest host local module missing")
		}
	}
	for _, pkg := range packages {
		if withinModule(pkg.ImportPath, "go.opentelemetry.io/otel/sdk") || withinModule(pkg.ImportPath, "go.opentelemetry.io/auto/sdk") {
			return errors.New("telemetry SDK reached manifest host")
		}
		if pkg.Standard || withinModule(pkg.ImportPath, main) || pkg.ImportPath == nativeProcessPath || pkg.ImportPath == manifestSDKPath || pkg.ImportPath == "enkv.sh/sdk/protocols/manifest-generator" || pkg.ImportPath == "enkv.sh/sdk/artifact" || pkg.ImportPath == "enkv.sh/sdk/artifact/credentialroute" || withinModule(pkg.ImportPath, "enkv.sh/telemetry") || telemetryAPIClosure(pkg.ImportPath) || pkg.ImportPath == "golang.org/x/sys/unix" {
			continue
		}
		return errors.New("manifest host imports an unreviewed package")
	}
	return nil
}

package main

import (
	"errors"
	"strings"
)

const liveManifestConsumerPath = manifestExamplePath + "/consumer"

// The independent live oracle is one standard-library-only leaf. Both the
// assembly SDK gate and the Core test import gate enforce the same edge law.
func checkLiveManifestConsumerImports(packages []compiledPackage) error {
	standard := map[string]bool{}
	for _, pkg := range packages {
		name, _, _ := strings.Cut(pkg.ImportPath, " [")
		standard[name] = pkg.Standard
	}
	for _, pkg := range packages {
		name, _, _ := strings.Cut(pkg.ImportPath, " [")
		for _, imported := range pkg.Imports {
			imported, _, _ = strings.Cut(imported, " [")
			if name == liveManifestConsumerPath && !standard[imported] {
				return errors.New("independent manifest consumer imports a nonstandard package")
			}
			if imported == liveManifestConsumerPath && (name != modulePrefix+"core" || pkg.ForTest != modulePrefix+"core") {
				return errors.New("independent manifest consumer reached a non-test caller")
			}
		}
	}
	return nil
}

func checkSDKBoundaries(owner string, modules []resolvedModule, packages []compiledPackage) error {
	source, _ := registeredModule(owner)
	public := strings.HasPrefix(owner, "sdk/") || strings.HasPrefix(owner, "protocols/")
	consumer := liveManifestConsumerPath
	if owner == "live" {
		if err := checkLiveManifestConsumerImports(packages); err != nil {
			return err
		}
	}
	for _, module := range modules {
		if public && strings.HasPrefix(module.Path, modulePrefix) && !strings.HasPrefix(module.Path, "enkv.sh/sdk/") {
			return errors.New("public SDK module imports a private or official implementation")
		}
		for _, path := range []string{outputSDKPath, manifestSDKPath, genericJSONPath, openTofuJSONPath, outputExamplePath, manifestExamplePath, generatorExamplePath, testServicePath, "enkv.sh/sdk/artifact", "enkv.sh/sdk/protocols/manifest-generator"} {
			if withinModule(module.Path, path) && module.Path != path {
				return errors.New("unregistered public SDK submodule")
			}
		}
		if public && strings.HasPrefix(module.Path, "enkv.sh/sdk/examples/") && module.Path != source.Module && !(module.Path == testServicePath && (owner == "sdk/examples/local-token-generator" || owner == "sdk/examples/local-value-output")) {
			return errors.New("public example dependency reached another component")
		}
		if module.Path != outputSDKPath && module.Path != manifestSDKPath && module.Path != genericJSONPath && module.Path != openTofuJSONPath && module.Path != "enkv.sh/sdk/artifact" && module.Path != "enkv.sh/sdk/protocols/manifest-generator" {
			continue
		}
		if module.Path == source.Module && module.Version == "" && module.Replace == nil {
			continue
		}
		if module.Version != "v0.1.0" {
			return errors.New("public SDK module version differs")
		}
	}
	output := owner == "sdk/output" || owner == "sdk/examples/local-value-output" || owner == "plugins/aws-output" || owner == "plugins/gcp-output" || owner == "plugins/github-output" || owner == "plugins/output-contract-test"
	manifestAuthor := owner == "sdk/manifest-generator" || owner == "plugins/manifest-generators/generic-json" || owner == "plugins/manifest-generators/opentofu-tfvars-json" || owner == "sdk/examples/ini-reference-manifest"
	renderer := manifestAuthor && owner != "sdk/manifest-generator" || owner == "hermetic" || owner == "live"
	production := owner == "core" || owner == "crypto" || strings.HasPrefix(owner, "compositions/") || strings.HasPrefix(owner, "providers/")
	fixtureWriter := false
	if owner == "hermetic" || owner == "live" {
		for _, pkg := range packages {
			for _, imported := range pkg.Imports {
				imported, _, _ = strings.Cut(imported, " [")
				if imported != manifestSDKPath+"/jsonwriter" {
					continue
				}
				name, _, _ := strings.Cut(pkg.ImportPath, " [")
				if name != genericJSONPath && name != openTofuJSONPath {
					return errors.New("manifest writer imports are outside the reviewed renderer fixtures")
				}
				fixtureWriter = true
			}
		}
	}
	for _, pkg := range packages {
		name, _, _ := strings.Cut(pkg.ImportPath, " [")
		if production && withinModule(name, "enkv.sh/plugins") {
			return errors.New("concrete plugin reached production compilation")
		}
		if public && strings.HasPrefix(name, modulePrefix) && !strings.HasPrefix(name, "enkv.sh/sdk/") {
			return errors.New("public SDK package imports a private or official implementation")
		}
		if withinModule(name, "enkv.sh/sdk/artifact") && name != "enkv.sh/sdk/artifact" && name != "enkv.sh/sdk/artifact/credentialroute" && owner != "sdk/artifact" {
			return errors.New("artifact author tools reached another component")
		}
		if withinModule(name, outputSDKPath) && (!output || name != outputSDKPath && owner != "sdk/output" && owner != "sdk/examples/local-value-output") {
			return errors.New("output child serving reached a private component")
		}
		if strings.HasPrefix(name, "enkv.sh/sdk/examples/") && !withinModule(name, source.Module) && !(withinModule(name, testServicePath) && (owner == "sdk/examples/local-token-generator" || owner == "sdk/examples/local-value-output")) && !(owner == "live" && name == consumer) {
			return errors.New("public example reached another component")
		}
		if owner == "protocols/manifest-generator" && withinModule(name, manifestSDKPath) && name != manifestSDKPath {
			return errors.New("manifest protocol imports author serving or conformance")
		}
		if withinModule(name, manifestSDKPath) && name != manifestSDKPath && !manifestAuthor && !(fixtureWriter && name == manifestSDKPath+"/jsonwriter") {
			return errors.New("manifest conformance reached a private component")
		}
		if withinModule(name, openTofuJSONPath) && (!renderer || name != openTofuJSONPath && owner != "plugins/manifest-generators/opentofu-tfvars-json") || withinModule(name, genericJSONPath) && (!renderer || name != genericJSONPath && owner != "plugins/manifest-generators/generic-json") {
			return errors.New("manifest renderer reached an unreviewed owner")
		}
	}
	return nil
}

func authorModuleDependencies(owner string) (string, map[string]string, map[string]string) {
	switch owner {
	case "protocols/generator":
		return "enkv.sh/sdk/protocols/generator", nil, nil
	case "protocols/output":
		return "enkv.sh/sdk/protocols/output", nil, nil
	case "sdk/generator":
		return generatorSDKPath, map[string]string{"enkv.sh/sdk/artifact": "../artifact", cloudflareProtocolPath: "../protocols/generator"}, nil
	case "plugins/local-random-secret":
		return "enkv.sh/plugins/generators/local-random-secret", map[string]string{"enkv.sh/sdk/artifact": "../../../sdk/artifact", generatorSDKPath: "../../../sdk/generator", cloudflareProtocolPath: "../../../sdk/protocols/generator"}, nil
	case "sdk/examples/local-token-generator":
		return generatorExamplePath, map[string]string{"enkv.sh/sdk/artifact": "../../artifact", generatorSDKPath: "../../generator", cloudflareProtocolPath: "../../protocols/generator", testServicePath: "../testservice"}, nil
	case "sdk/examples/testservice":
		return testServicePath, nil, nil
	case "sdk/artifact":
		return "enkv.sh/sdk/artifact", nil, nil
	case "sdk/output":
		return outputSDKPath, map[string]string{"enkv.sh/sdk/artifact": "../artifact", "enkv.sh/sdk/protocols/output": "../protocols/output"}, nil
	case "sdk/manifest-generator":
		return manifestSDKPath, map[string]string{"enkv.sh/sdk/artifact": "../artifact", "enkv.sh/sdk/protocols/manifest-generator": "../protocols/manifest-generator"}, nil
	case "protocols/manifest-generator":
		return "enkv.sh/sdk/protocols/manifest-generator", map[string]string{"enkv.sh/sdk/artifact": "../../artifact", manifestSDKPath: "../../manifest-generator"}, nil
	case "plugins/manifest-generators/generic-json":
		return genericJSONPath, map[string]string{"enkv.sh/sdk/artifact": "../../../sdk/artifact", manifestSDKPath: "../../../sdk/manifest-generator", "enkv.sh/sdk/protocols/manifest-generator": "../../../sdk/protocols/manifest-generator"}, nil
	case "plugins/manifest-generators/opentofu-tfvars-json":
		return openTofuJSONPath, map[string]string{"enkv.sh/sdk/artifact": "../../../sdk/artifact", manifestSDKPath: "../../../sdk/manifest-generator", "enkv.sh/sdk/protocols/manifest-generator": "../../../sdk/protocols/manifest-generator"}, nil
	case "sdk/examples/local-value-output":
		return outputExamplePath, map[string]string{"enkv.sh/sdk/artifact": "../../artifact", outputSDKPath: "../../output", "enkv.sh/sdk/protocols/output": "../../protocols/output", testServicePath: "../testservice"}, nil
	case "sdk/examples/ini-reference-manifest":
		return manifestExamplePath, map[string]string{"enkv.sh/sdk/artifact": "../../artifact", manifestSDKPath: "../../manifest-generator", "enkv.sh/sdk/protocols/manifest-generator": "../../protocols/manifest-generator"}, nil
	}
	return "", nil, nil
}

func checkAuthorModule(owner string, modules []resolvedModule, packages []compiledPackage) error {
	main, local, remote := authorModuleDependencies(owner)
	if main == "" {
		return errors.New("unknown public author module")
	}
	if len(modules) != 1+len(local)+len(remote) {
		return errors.New("public author module graph differs")
	}
	seen := make(map[string]bool, len(modules))
	for _, module := range modules {
		if seen[module.Path] {
			return errors.New("public author module duplicated")
		}
		seen[module.Path] = true
		if module.Path == main {
			if module.Version != "" || module.Replace != nil {
				return errors.New("public author main identity differs")
			}
		} else if replacement, ok := local[module.Path]; ok {
			if module.Version != "v0.1.0" || module.Replace == nil || module.Replace.Path != replacement || module.Replace.Version != "" || module.Replace.Replace != nil {
				return errors.New("public author local dependency differs")
			}
		} else if version := remote[module.Path]; version == "" || module.Version != version || module.Replace != nil {
			return errors.New("public author dependency differs")
		}
	}
	if !seen[main] {
		return errors.New("public author main missing")
	}
	for path := range local {
		if !seen[path] {
			return errors.New("public author local dependency missing")
		}
	}
	for _, pkg := range packages {
		if pkg.Standard || withinModule(pkg.ImportPath, main) {
			continue
		}
		allowed := false
		for path := range local {
			if withinModule(pkg.ImportPath, path) {
				allowed = true
				break
			}
		}
		if !allowed {
			for path := range remote {
				if withinModule(pkg.ImportPath, path) {
					allowed = true
					break
				}
			}
		}
		if !allowed {
			return errors.New("public author imports an unreviewed package")
		}
	}
	return nil
}

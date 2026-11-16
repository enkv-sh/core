package main

import "errors"

func checkGeneratorServingBoundary(owner string, modules []resolvedModule, packages []compiledPackage) error {
	public := owner == "plugins/local-random-secret" || owner == "sdk/generator" || owner == "sdk/examples/local-token-generator" || owner == cloudflareModule
	for _, module := range modules {
		if module.Path == generatorSDKPath && !(owner == "sdk/generator" && module.Version == "") && module.Version != "v0.1.0" {
			return errors.New("generator SDK module version differs")
		}
	}
	if !public {
		for _, pkg := range packages {
			if withinModule(pkg.ImportPath, generatorSDKPath) || withinModule(pkg.ImportPath, generatorExamplePath) {
				return errors.New("generator child serving reached a private component")
			}
		}
	}
	return nil
}

package main

import "errors"

func checkConfiguration(packages []compiledPackage) error {
	for _, p := range packages {
		if p.Standard || p.ImportPath == modulePrefix+"compositions/configuration" ||
			p.ImportPath == modulePrefix+"core/contract" || p.ImportPath == modulePrefix+"core/format" || p.ImportPath == manifestSDKPath ||
			p.ImportPath == "enkv.sh/sdk/artifact" || p.ImportPath == "enkv.sh/sdk/artifact/credentialroute" ||
			p.ImportPath == "enkv.sh/sdk/protocols/generator" || p.ImportPath == "enkv.sh/sdk/protocols/generator/retained" ||
			p.ImportPath == "enkv.sh/sdk/protocols/output" ||
			withinModule(p.ImportPath, modulePrefix+"telemetry") || neutral(p.ImportPath) {
			continue
		}
		return errors.New("configuration imports an operation or provider implementation")
	}
	return nil
}

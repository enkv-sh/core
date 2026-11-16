package main

import "errors"

func outputCredential(path string) bool {
	switch path {
	case "enkv.sh/plugins/outputs/aws-secrets-manager/credential", "enkv.sh/plugins/outputs/gcp-secret-manager/credential", "enkv.sh/plugins/outputs/github-actions/credential":
		return true
	}
	return false
}

func liveOutputCredential(provider, path string) bool {
	return (provider == "aws" || provider == "gcp") && path == modulePath("plugins/"+provider+"-output")+"/credential"
}

func checkOutputCredentialImports(p compiledPackage, standard map[string]bool) error {
	if !outputCredential(p.ImportPath) {
		return nil
	}
	for _, imported := range p.Imports {
		if !standard[imported] && imported != "enkv.sh/sdk/protocols/output" && imported != "enkv.sh/sdk/artifact/credentialroute" {
			return errors.New("output credential codec imports a non-wire dependency")
		}
	}
	return nil
}

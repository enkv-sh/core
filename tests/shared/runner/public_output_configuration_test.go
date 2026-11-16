package main

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

// full_only: false
func TestPublicOutputEnvironmentUsesOnlyRuntimeScopesAndStandardCredentials(t *testing.T) {
	root := maintainedCloudflareRoot(t)
	for _, provider := range []string{"aws", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			var original map[string]json.RawMessage
			if err := readSelectionFile(filepath.Join(root, "tests", "environments", "public-"+provider+".example.json"), &original); err != nil {
				t.Fatal(err)
			}
			for _, row := range []struct {
				name, outputs string
				admitted      bool
			}{
				{"exact", `{"repository":{"owner":"owner","repository":"repo"},"organization":{"owner":"org","visibility":"selected","repositories":[101,202]},"environment":{"owner":"owner","repository":"repo","environment":"prod"}}`, true},
				{"credential-file", `{"repository":{"owner":"owner","repository":"repo","credentials_file":"fixture-token"},"organization":{"owner":"org","visibility":"selected","repositories":[101,202]},"environment":{"owner":"owner","repository":"repo","environment":"prod"}}`, false},
				{"token-source", `{"repository":{"owner":"owner","repository":"repo","token_environment":"GH_TOKEN"},"organization":{"owner":"org","visibility":"selected","repositories":[101,202]},"environment":{"owner":"owner","repository":"repo","environment":"prod"}}`, false},
				{"missing-scope", `{"repository":{"owner":"owner","repository":"repo"},"organization":{"owner":"org","visibility":"selected","repositories":[101,202]}}`, false},
				{"empty-selection", `{"repository":{"owner":"owner","repository":"repo"},"organization":{"owner":"org","visibility":"selected","repositories":[]},"environment":{"owner":"owner","repository":"repo","environment":"prod"}}`, false},
			} {
				t.Run(row.name, func(t *testing.T) {
					original["public_outputs"] = json.RawMessage(row.outputs)
					path := filepath.Join(t.TempDir(), "environment.json")
					saveSelection(t, path, original)
					var environment environmentFile
					err := readSelectionFile(path, &environment)
					if err == nil {
						err = validatePublicConfigurationEnvironment(&environment)
					}
					if (err == nil) != row.admitted {
						t.Fatal("public runtime scope admission differs from the standard credential contract", err)
					}
				})
			}
		})
	}
}

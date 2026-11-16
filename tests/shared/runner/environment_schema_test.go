package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// full_only: false
func TestEnvironmentRefusesRemovedOperatorCleanupField(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		for _, kind := range []string{"state", "outputs", "public"} {
			for _, value := range []string{"object", "null"} {
				t.Run(provider+"/"+kind+"/"+value, func(t *testing.T) {
					path, input := outputEnvironmentInput(t, provider)
					switch kind {
					case "state":
						delete(input, "output_targets")
					case "public":
						body, err := os.ReadFile(filepath.Join(maintainedCloudflareRoot(t), "tests/environments/public-"+provider+".example.json"))
						if err != nil {
							t.Fatal(err)
						}
						input = nil
						if err := json.Unmarshal(body, &input); err != nil {
							t.Fatal(err)
						}
					}
					if _, err := loadOutputEnvironment(t, path, input); err != nil {
						t.Fatal("current environment control refused", err)
					}
					input["operator_cleanup"] = nil
					if value == "object" {
						input["operator_cleanup"] = map[string]any{"provider": provider, "region": "example-region", "bucket": "example-bucket", "credentials_file": "separate-cleanup"}
					}
					if _, err := loadOutputEnvironment(t, path, input); err == nil || !strings.Contains(err.Error(), "selection file") {
						t.Fatal("removed cleanup input did not refuse at the environment schema", err)
					}
				})
			}
		}
	}
}

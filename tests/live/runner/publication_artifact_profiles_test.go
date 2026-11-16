package core

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enkv.sh/compositions/outputhost"
	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestLivePublicationArtifactKeepsCurrentVersionAndBinding(t *testing.T) {
	profiles := []struct{ label, scope string }{
		{"ENKV/OUTPUT/TEST-PROFILE/v3", "test-output"},
		{"ENKV/OUTPUT/AWS-SECRETS-MANAGER/v3", "aws-secrets-manager"},
		{"ENKV/OUTPUT/GCP-SECRET-MANAGER/v3", "gcp-secret-manager"},
		{"ENKV/OUTPUT/GITHUB-REPOSITORY/v3", "github-repository"},
		{"ENKV/OUTPUT/GITHUB-ORGANIZATION/v3", "github-organization"},
		{"ENKV/OUTPUT/GITHUB-ENVIRONMENT/v3", "github-environment"},
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(filepath.Join(filepath.Dir(executable), "*.installation.json"))
	if err != nil || len(paths) == 0 {
		t.Fatal("current publication installation expectations missing", err)
	}
	seen := make(map[[32]byte]bool)
	for _, installationPath := range paths {
		path := strings.TrimSuffix(installationPath, ".installation.json")
		config, err := installedPublicationFixtureConfig(path)
		if err != nil {
			t.Fatal(err)
		}
		artifact := config.Artifact
		if seen[artifact.DescriptorID] {
			t.Fatal("current publication fixture repeats a descriptor")
		}
		seen[artifact.DescriptorID] = true
		index := -1
		for i, profile := range profiles {
			if filepath.Base(path) == "enkv-output-"+strings.ReplaceAll(profile.scope, "test-output", "contract-test") {
				index = i
				break
			}
		}
		if index == -1 {
			t.Fatal("current publication fixture contains an unknown command")
		}
		current := profiles[index]
		t.Run(current.scope, func(t *testing.T) {
			if artifact.DescriptorID.IsZero() || artifact.ConfigContractID == "" || artifact.CredentialRouteContractID == "" {
				t.Fatal("exact current publication artifact not installed", current.label)
			}
			root := t.TempDir()
			profile := records.OutputFixtureProfile{Scope: current.scope, ProfileID: current.label, Native: &records.OutputFixtureNative{
				ArtifactPath: path, ArtifactSHA256: hex.EncodeToString(artifact.SHA256[:]), ArtifactLength: artifact.Length,
				CredentialPath: filepath.Join(root, "unopened-credential"), CredentialRouteID: hex.EncodeToString(artifact.CredentialRouteID[:]), DescriptorID: hex.EncodeToString(artifact.DescriptorID[:]), ConfigContractID: artifact.ConfigContractID, CredentialRouteContractID: artifact.CredentialRouteContractID,
			}}
			// The native input's exact public coordinates remain independent of
			// the copied metadata and dependency fixture members.
			for _, suffix := range []string{".installation.json", ".dependency"} {
				body, err := os.ReadFile(path + suffix)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, filepath.Base(path))+suffix, body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			profile.Native.ArtifactPath = filepath.Join(root, filepath.Base(path))
			got, err := livePublicationArtifact(profile)
			if err != nil || got.Artifact != artifact || got.ArtifactPath != profile.Native.ArtifactPath || !bytes.Equal(got.Metadata, config.Metadata) || !bytes.Equal(got.Dependency, config.Dependency) {
				t.Fatal("current profile artifact rejected or installation fields changed", err)
			}
			if err := got.Validate(artifact.ConfigContractID); err != nil {
				t.Fatal("exact current publication semantics refused", err)
			}
			for _, field := range []string{"digest", "length", "route", "descriptor", "config-contract", "route-contract", "missing-native", "old-contract", "changed-dependency", "changed-metadata"} {
				t.Run(field, func(t *testing.T) {
					bad := profile
					native := *profile.Native
					bad.Native = &native
					switch field {
					case "digest":
						bad.Native.ArtifactSHA256 = strings.Repeat("0", 64)
					case "length":
						bad.Native.ArtifactLength++
					case "route":
						bad.Native.CredentialRouteID = strings.Repeat("0", 64)
					case "descriptor":
						bad.Native.DescriptorID = strings.Repeat("0", 64)
					case "config-contract":
						bad.Native.ConfigContractID = "other/config/v1"
					case "route-contract":
						bad.Native.CredentialRouteContractID = strings.Repeat("0", 64)
					case "changed-dependency":
						if err := os.WriteFile(bad.Native.ArtifactPath+".dependency", []byte("changed"), 0600); err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() {
							body, err := os.ReadFile(path + ".dependency")
							if err != nil {
								t.Error(err)
								return
							}
							if err := os.WriteFile(bad.Native.ArtifactPath+".dependency", body, 0600); err != nil {
								t.Error(err)
							}
						})
					case "changed-metadata":
						body, err := os.ReadFile(path + ".installation.json")
						if err != nil {
							t.Fatal(err)
						}
						var record map[string]json.RawMessage
						if err := json.Unmarshal(body, &record); err != nil {
							t.Fatal(err)
						}
						var row outputhost.Artifact
						if err := json.Unmarshal(record["artifact"], &row); err != nil {
							t.Fatal(err)
						}
						row.ExecutorID[0] ^= 1
						record["artifact"], err = json.Marshal(row)
						if err != nil {
							t.Fatal(err)
						}
						changed, err := json.Marshal(record)
						if err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(bad.Native.ArtifactPath+".installation.json", changed, 0600); err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() {
							if err := os.WriteFile(bad.Native.ArtifactPath+".installation.json", body, 0600); err != nil {
								t.Error(err)
							}
						})
					case "missing-native":
						bad.Native = nil
					case "old-contract":
						bad.Native.ConfigContractID = "superseded-profile/v3"
					}
					if _, err := livePublicationArtifact(bad); err == nil {
						t.Fatal("publication artifact admitted changed installation field", field)
					}
				})
			}
		})
	}
}

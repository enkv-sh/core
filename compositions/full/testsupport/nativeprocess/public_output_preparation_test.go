package nativeprocess

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	observer "enkv.sh/core/testsupport/nativeprocess"
	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
)

// full_only: false
func TestPublicNativeOutputPreparationUsesLinkedPluginWithoutSend(t *testing.T) {
	output := newNativePublicationServer(t)
	output.account = "123456789012"
	binaries := buildNativeOutputExecutables(t, output.server.URL)
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			s := newWorkflowServer(t, family, false)
			s.childLimit, s.requestLimit = 5, 5*workflowChildRequestLimit
			source := filepath.Join(t.TempDir(), "configuration.json")
			if err := os.WriteFile(source, workflowSetup(t, s, false), 0600); err != nil {
				t.Fatal(err)
			}
			workflowResult(t, workflowRun(t, s, binaries.cli, "init", observer.Policy{}, nil, "init", "--source", source, "--source-format", "json", "--json"), "success")
			before := workflowReadPair(t, source)
			head, _ := workflowHead(t, s)
			objects, effects := s.objectCount(), output.effectCount()
			plugin, kind := "aws-secrets-manager", "aws-shared-credentials"
			if family == "gcp" {
				plugin, kind = "gcp-secret-manager", "gcp-service-account-adc"
			}
			module := "plugins/aws-output"
			if family == "gcp" {
				module = "plugins/gcp-output"
			}
			descriptorPath := nativeGeneratedSourcePath(nativeRepository(t), module+"/cmd/enkv-output-"+plugin+"/plugin.json")
			descriptorBytes, err := os.ReadFile(descriptorPath)
			if err != nil {
				t.Fatal("current linked output descriptor unavailable")
			}
			descriptor, err := artifact.DecodeDescriptor(descriptorBytes)
			if err != nil || descriptor.Output == nil {
				t.Fatal("current linked output descriptor refused")
			}
			route, err := credentialroute.Decode(descriptor.Output.CredentialRoute)
			if err != nil {
				t.Fatal("current linked output route refused")
			}
			args := []string{"--source", source, "--source-format", "json", "--prepare-output-credential"}
			if family == "gcp" {
				args = append(args, "--output-project-number", "123456789012")
			}
			conditions := []string{"prepared", "wrong-source", "missing-source"}
			if family == "gcp" {
				conditions = append(conditions, "wrong-quota")
			}
			for _, condition := range conditions {
				t.Run(condition, func(t *testing.T) {
					environment := nativeOutputPreparationEnvironment(t, s)
					expected := kind
					if condition == "wrong-source" {
						expected = "aws-sso"
						if family == "gcp" {
							expected = "gcp-user-adc"
						}
					}
					if condition == "missing-source" || condition == "wrong-quota" {
						for _, setting := range environment {
							name, path, _ := strings.Cut(setting, "=")
							if name != "AWS_SHARED_CREDENTIALS_FILE" && name != "GOOGLE_APPLICATION_CREDENTIALS" {
								continue
							}
							if condition == "missing-source" {
								if err := os.Remove(path); err != nil {
									t.Fatal("controlled credential source removal failed")
								}
							} else {
								var source map[string]any
								nativeGeneratedReadJSON(t, path, &source)
								source["quota_project_id"] = "another-quota"
								nativeGeneratedWriteJSON(t, path, source)
							}
						}
					}
					child := workflowRunDeclaredEnvironment(t, s, binaries.helper, "authority", observer.Policy{ExpectedSourceKind: expected}, nil, environment, route.Names, args...)
					var result struct {
						OutputPreparation struct {
							Provider         string
							Prepared, Closed bool
						}
					}
					if len(child.diagnostic) != 0 || json.Unmarshal(child.out, &result) != nil || result.OutputPreparation.Provider != family {
						t.Fatal("output preparation lost its closed safe result")
					}
					witnesses, matched := 0, false
					for _, event := range child.capture.Events {
						if event.Kind == "source-kind" {
							if event.SourceKind != kind || event.Count != 1 {
								t.Fatal("output plugin source was inferred from the expected mode")
							}
							witnesses++
							matched = event.Matched
						}
					}
					success := result.OutputPreparation.Prepared && result.OutputPreparation.Closed
					if condition == "prepared" || condition == "wrong-source" {
						if child.code != 0 || !success || witnesses != 1 || matched != (condition == "prepared") {
							t.Fatal("linked plugin preparation lost its actual selected SDK source or closure")
						}
					} else if child.code != 2 || success || result.OutputPreparation.Closed || witnesses != 0 {
						t.Fatal("missing credentials or actual quota mismatch admitted preparation")
					}
					if output.effectCount() != effects || s.objectCount() != objects {
						t.Fatal("output preparation performed a mutation")
					}
				})
			}
			after, _ := workflowHead(t, s)
			if !reflect.DeepEqual(after, head) {
				t.Fatal("output preparation changed selected state")
			}
			workflowUnchanged(t, source, before)
		})
	}
}

func nativeOutputPreparationEnvironment(t *testing.T, s *workflowServer) []string {
	t.Helper()
	private := nativeGeneratedPrivateDirectory(t)
	if s.family == "gcp" {
		s.environment(t, private, "authority")
		path := filepath.Join(private, "local-adc.json")
		var source map[string]any
		nativeGeneratedReadJSON(t, path, &source)
		source["token_uri"] = "https://oauth2.googleapis.com/token"
		nativeGeneratedWriteJSON(t, path, source)
		return []string{"GOOGLE_APPLICATION_CREDENTIALS=" + path}
	}
	path := filepath.Join(private, "credentials")
	credentials := "[selected]\naws_access_key_id=" + workflowAccess("authority") + "\naws_secret_access_key=offline-local-not-a-cloud-secret\n"
	if err := os.WriteFile(path, []byte(credentials), 0600); err != nil {
		t.Fatal("controlled shared credential fixture unavailable")
	}
	return []string{"AWS_ACCESS_KEY_ID=", "AWS_SECRET_ACCESS_KEY=", "AWS_SESSION_TOKEN=", "AWS_PROFILE=selected", "AWS_CONFIG_FILE=" + filepath.Join(private, "absent-config"), "AWS_SHARED_CREDENTIALS_FILE=" + path, "AWS_EC2_METADATA_DISABLED=true", "HOME=" + private}
}

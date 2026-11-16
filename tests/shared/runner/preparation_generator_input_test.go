package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// full_only: false
func TestPreparedSuiteGeneratorNormalizationKeepsOriginalInput(t *testing.T) {
	for _, row := range []struct {
		name            string
		public, symlink bool
	}{{"private-canonical", false, false}, {"private-symlinks", false, true}, {"public-artifact-symlink", true, true}} {
		t.Run(row.name, func(t *testing.T) {
			ctx, root, bootstrap := localLivePreparationFixture(t, "aws")
			ctx = withRacePolicy(ctx, true)
			modules := []string{cloudflareModule, cloudflareProtocolModule, cloudflareSDKModule, "sdk/artifact"}
			for _, module := range modules {
				target, err := sourcePath(root, module)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.RemoveAll(target); err != nil {
					t.Fatal(err)
				}
			}
			copyPublicModuleKit(t, testRepositoryRoot(t), root, modules)
			input, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(input, "generator-entered")
			artifact := filepath.Join(input, "generator")
			mainPath, err := sourcePath(root, cloudflareModule+"/cmd/enkv-generator-cloudflare/main.go")
			if err != nil {
				t.Fatal(err)
			}
			main, err := os.ReadFile(mainPath)
			if err != nil || strings.Count(string(main), "func main() {") != 1 {
				t.Fatal("native generator entrypoint unavailable", err)
			}
			guard := `
 if marker := os.Getenv("ENKV_PREPARED_GENERATOR_ENTERED"); marker != "" {
  if err := os.WriteFile(marker, []byte("entered"), 0600); err != nil { os.Exit(74) }
  os.Exit(73)
 }
`
			if err := os.WriteFile(mainPath, []byte(strings.Replace(string(main), "func main() {", "func main() {"+guard, 1)), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("ENKV_PREPARED_GENERATOR_ENTERED", "")
			if _, err := runGoEnvironment(withRacePolicy(ctx, false), root, cloudflareModule, stockPluginBuildEnvironment(), cloudflareProductionBuildArgs(artifact, false)...); err != nil {
				t.Fatal("compile exact native generator input", err)
			}
			if err := os.Chmod(artifact, 0700); err != nil {
				t.Fatal(err)
			}
			if row.symlink {
				link := filepath.Join(input, "generator-link")
				if err := os.Symlink(artifact, link); err != nil {
					t.Fatal(err)
				}
				artifact = link
			}
			configuration, settings := configurationFixture(t, "aws")
			settings["credentials_file"] = filepath.Join(filepath.Dir(configuration), "identity.json")
			environment := environmentFor(settings)
			selected := "generated.retirement-acknowledgement-closes/one_current_one_retiring_manual_ack"
			if row.public {
				environment = environmentFile{}
				if err := readSelectionFile(filepath.Join(testRepositoryRoot(t), "tests/environments/public-aws.example.json"), &environment); err != nil {
					t.Fatal(err)
				}
				selected = "public-configuration.generated-manual-lifecycle/generated_manual_lifecycle"
			}
			environment.Generator = &generatorReference{Account: strings.Repeat("a", 32), PermissionGroup: strings.Repeat("b", 32), Artifact: artifact}
			suite, environmentPath, limitPath := filepath.Join(input, "suite.json"), filepath.Join(input, "environment.json"), filepath.Join(input, "limits.json")
			saveSelection(t, suite, suiteFixture("generator-input", []string{selected}))
			saveSelection(t, environmentPath, environment)
			saveSelection(t, limitPath, testLimits())
			request, err := resolveSavedRun([]string{suite}, environmentPath, "", limitPath, "disabled", "", "", "", 1, true)
			if err != nil {
				t.Fatal(err)
			}
			request.Resolved.Race = raceEnabled(ctx)
			request.execution = executionPolicy{Resolved: executionCapacity{Parallel: 1, MemoryLimitMiB: 8192}}
			prepared, err := prepareSuite(nil, ctx, root, bootstrap, request, io.Discard)
			if prepared != nil {
				defer func() {
					if err := prepared.close(ctx); err != nil {
						t.Error(err)
					}
				}()
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("ENKV_PREPARED_GENERATOR_ENTERED", marker)
			beforeEnvironment, err := json.Marshal(prepared.request.environment)
			if err != nil {
				t.Fatal(err)
			}
			beforeIdentity, err := suiteRequestIdentity(prepared.request)
			if err != nil {
				t.Fatal(err)
			}
			beforeState := preparationRecoverySnapshot(t, root)
			admissions := 0
			ctx = context.WithValue(ctx, rootAdmitterContextKey{}, rootAdmitter(func(ctx context.Context, admission rootAdmission) (context.Context, error) {
				admissions++
				if !admission.Live || admission.Execution.Resolved.Parallel != 1 {
					return ctx, errors.New("generator fixture lost live admission or assigned share")
				}
				return withExecutionCapacity(ctx, admission.Execution), nil
			}))
			admitted, err := admitPreparedExecution(ctx, prepared.admission())
			if err != nil {
				t.Fatal(err)
			}
			backup := filepath.Join(input, "limits-held.json")
			output := &ordinaryReviewEnvironmentWriter{before: "0000 ", change: func() {
				if err := os.Rename(limitPath, backup); err != nil {
					t.Fatal(err)
				}
			}}
			defer func() {
				if _, err := os.Stat(backup); err == nil {
					if err := os.Rename(backup, limitPath); err != nil {
						t.Error(err)
					}
				} else if !os.IsNotExist(err) {
					t.Error(err)
				}
			}()
			result, runErr := runPreparedSuite(admitted, root, bootstrap, prepared, output)
			if !output.done || admissions != 1 || runErr == nil || runErr.Error() != "limits unavailable" || !toolCommandsJoined(runErr) || !sourceCommandsJoined(runErr) {
				t.Fatal("normalization did not reach the exact later local limits refusal", runErr, output.done, admissions)
			}
			if result.Record != nil || result.Recovery != nil || !reflect.DeepEqual(beforeState, preparationRecoverySnapshot(t, root)) {
				t.Fatal("local limits refusal created durable live state")
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("local route fixture executed its body", err)
			}
			if err := os.Rename(backup, limitPath); err != nil {
				t.Fatal(err)
			}
			afterEnvironment, err := json.Marshal(prepared.request.environment)
			if err != nil {
				t.Fatal(err)
			}
			afterIdentity, err := suiteRequestIdentity(prepared.request)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(beforeEnvironment, afterEnvironment) || afterIdentity != beforeIdentity {
				t.Error("actual generator normalization mutated the frozen prepared environment")
			}
			if prepared.request.environment.Generator.Artifact != artifact {
				t.Error("normalization replaced the original artifact path spelling")
			}
			if prepared.request.environment.Generator.CredentialsFile != "" {
				t.Error("normalization added a credential file route")
			}
			if err := prepared.verify(admitted, root); err != nil {
				t.Error("restored same-inode limits did not preserve the original prepared request", err)
			}
		})
	}
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core/contract"
)

// full_only: false
func TestCommandSourcesDefaultAndInferBeforeExecution(t *testing.T) {
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	type sourceCheck func(string, configuration.Format)
	commands := []struct {
		name string
		run  func([]string, sourceCheck)
	}{
		{"inspect", func(args []string, check sourceCheck) {
			runInspectWithExecutors(t.Context(), args, io.Discard, io.Discard, func(_ context.Context, _ contract.ID, path string, format configuration.Format) compositionfull.ConfigurationInspectionResult {
				check(path, format)
				return compositionfull.ConfigurationInspectionResult{}
			}, nil, nil)
		}},
		{"receipt", func(args []string, check sourceCheck) {
			runReceiptWithExecutors(t.Context(), args, io.Discard, io.Discard, func(_ context.Context, _ contract.ID, path string, format configuration.Format) compositionfull.ConfigurationReceiptListResult {
				check(path, format)
				return compositionfull.ConfigurationReceiptListResult{}
			}, nil)
		}},
		{"manifest", func(args []string, check sourceCheck) {
			runManifestWithExecutor(t.Context(), append(args, "--plugin=private-renderer", "--out=manifest.json"), io.Discard, io.Discard, func(_ context.Context, _ contract.ID, path string, format configuration.Format, _ compositionfull.ManifestOptions, destination string) compositionfull.ManifestFileResult {
				check(path, format)
				if destination != filepath.Join(directory, "manifest.json") {
					t.Fatal("artifact did not use captured working directory", destination)
				}
				return compositionfull.ManifestFileResult{}
			})
		}},
		{"materialize", func(args []string, check sourceCheck) {
			runMaterializeWithExecutor(t.Context(), append(args, "--name=entry", "--out=application.env"), io.Discard, io.Discard, func(_ context.Context, _ contract.MaterializationRequest, path string, format configuration.Format, destination string, _ compositionfull.RecipientSelector) (compositionfull.ConfigurationMaterializationResult, error) {
				check(path, format)
				if destination != filepath.Join(directory, "application.env") {
					t.Fatal("artifact did not use captured working directory", destination)
				}
				return compositionfull.ConfigurationMaterializationResult{}, nil
			})
		}},
		{"gc", func(args []string, check sourceCheck) {
			runGCWithExecutors(t.Context(), append([]string{"plan", "--out=plan.bin"}, args...), io.Discard, io.Discard, func(_ context.Context, request compositionfull.GCPlanRequest, path string, format configuration.Format) compositionfull.GCPlanResult {
				check(path, format)
				if request.ArtifactPath != filepath.Join(directory, "plan.bin") {
					t.Fatal("artifact did not use captured working directory", request.ArtifactPath)
				}
				return compositionfull.GCPlanResult{}
			}, nil)
		}},
		{"init", func(args []string, check sourceCheck) {
			runInitWithInitializer(t.Context(), args, io.Discard, io.Discard, func(_ context.Context, path string, format configuration.Format) (compositionfull.InitializationResult, error) {
				check(path, format)
				return compositionfull.InitializationResult{}, nil
			})
		}},
		{"prepare", func(args []string, check sourceCheck) {
			runPrepareWithCoordinator(t.Context(), args, io.Discard, io.Discard, func(_ context.Context, request compositionfull.PrepareRequest) (*compositionfull.PrepareResult, error) {
				check(request.Source, request.Format)
				return compositionfull.NewPrepareRefusal()
			})
		}},
		{"set", func(args []string, check sourceCheck) {
			runSetWithSetter(t.Context(), append(args, "--name=entry"), io.NopCloser(strings.NewReader("value")), io.Discard, io.Discard, func(_ context.Context, path string, format configuration.Format, _ string, input io.ReadCloser, _ compositionfull.SetOptions) (*compositionfull.SetResult, error) {
				check(path, format)
				if err := input.Close(); err != nil {
					t.Fatal(err)
				}
				return compositionfull.NewSetRefusal(false)
			})
		}},
		{"local-edit", func(args []string, check sourceCheck) {
			runLocalEditWithExecutor(t.Context(), "domain-rename", append(args, "--name=renamed"), io.Discard, io.Discard, func(_ context.Context, command localEditCommand) (*compositionfull.LocalEditResult, error) {
				check(command.source, command.format)
				return compositionfull.NewLocalEditRefusal(command.action)
			})
		}},
		{"apply", func(args []string, check sourceCheck) {
			runApplyWithExecutor(t.Context(), args, io.Discard, io.Discard, func(_ context.Context, _ contract.ID, path string, format configuration.Format, _ contract.ID, _ compositionfull.ApplyOptions) compositionfull.ConfigurationApplyResult {
				check(path, format)
				return compositionfull.ConfigurationApplyResult{}
			})
		}},
		{"apply-publication", func(args []string, check sourceCheck) {
			runApplyWithExecutors(t.Context(), append(args, "--publish"), io.Discard, io.Discard, nil, func(_ context.Context, _, _ contract.ID, path string, format configuration.Format, _ contract.ID, _ compositionfull.ApplyPublicationOptions, _ compositionfull.ApplyOptions) compositionfull.ConfigurationApplyPublicationResult {
				check(path, format)
				return compositionfull.ConfigurationApplyPublicationResult{}
			})
		}},
		{"generated", func(args []string, check sourceCheck) {
			runGeneratedWithExecutors(t.Context(), append([]string{"list"}, args...), io.Discard, io.Discard, executeGeneratedMutation, func(_ context.Context, _ contract.ID, path string, format configuration.Format) compositionfull.ConfigurationGeneratedListResult {
				check(path, format)
				return compositionfull.ConfigurationGeneratedListResult{}
			})
		}},
		{"publish", func(args []string, check sourceCheck) {
			runPublishWithExecutor(t.Context(), append(args, "--name=entry"), io.Discard, io.Discard, func(_ context.Context, _ contract.ID, path string, format configuration.Format, _ compositionfull.PublicationOptions) compositionfull.ConfigurationPublicationResult {
				check(path, format)
				return compositionfull.ConfigurationPublicationResult{}
			})
		}},
		{"access", func(args []string, check sourceCheck) {
			runAccessMutationWithExecutor(t.Context(), contract.OperationEnvelopeRekey, append(args, "--name=entry", "--out=successor.yaml"), io.Discard, io.Discard, func(_ context.Context, _ uint16, _ contract.ID, command accessMutationCommand) compositionfull.MaintenanceCommandResult {
				check(command.source, command.format)
				if command.output != filepath.Join(directory, "successor.yaml") {
					t.Fatal("successor did not use captured working directory", command.output)
				}
				return compositionfull.MaintenanceCommandResult{}
			})
		}},
		{"keys", func(args []string, check sourceCheck) {
			args = append([]string{"replace", "--target=recipient", "--recipient=member", "--encryption=" + replacementCLIKey, "--out=successor.yaml"}, args...)
			runKeysWithExecutor(t.Context(), args, io.Discard, io.Discard, func(_ context.Context, _ contract.ID, path string, format configuration.Format, _ configuration.ReplacementRequest, output string, _ compositionfull.RecipientSelector) compositionfull.ReplacementCommandResult {
				check(path, format)
				if output != filepath.Join(directory, "successor.yaml") {
					t.Fatal("successor did not use captured working directory", output)
				}
				return compositionfull.ReplacementCommandResult{}
			})
		}},
		{"abandon", func(args []string, check sourceCheck) {
			runAbandonWithExecutor(t.Context(), append([]string{"list"}, args...), io.Discard, io.Discard, func(_ context.Context, _ contract.ID, path string, format configuration.Format, _ compositionfull.AbandonmentRequest) compositionfull.AbandonmentResult {
				check(path, format)
				return compositionfull.AbandonmentResult{}
			})
		}},
	}
	for _, command := range commands {
		for _, row := range []struct {
			name, path string
			args       []string
			format     configuration.Format
		}{
			{"default", "enkv.yaml", nil, configuration.YAML},
			{"inferred-json", "custom.JSON", []string{"--source=custom.JSON"}, configuration.JSON},
			{"inferred-yml", "custom.YmL", []string{"--source=custom.YmL"}, configuration.YAML},
			{"explicit-override", "custom.yaml", []string{"--source=custom.yaml", "--source-format=json"}, configuration.JSON},
		} {
			t.Run(command.name+"/"+row.name, func(t *testing.T) {
				calls := 0
				command.run(append(append([]string{}, row.args...), "--log-level=off"), func(path string, format configuration.Format) {
					calls++
					if path != filepath.Join(directory, row.path) || format != row.format {
						t.Fatal("selected source differs", path, format)
					}
				})
				if calls != 1 {
					t.Fatal("resolved source did not reach executor exactly once", calls)
				}
			})
		}
	}
}

// full_only: false
func TestSourceSelectionPrecedenceAndLimits(t *testing.T) {
	paths := commandPaths{directory: "/captured/app"}
	for _, row := range []struct {
		name, source, format string
		sourceSet, formatSet bool
		wantPath             string
		wantFormat           configuration.Format
		valid                bool
	}{
		{"default", "", "", false, false, "/captured/app/enkv.yaml", configuration.YAML, true},
		{"default-override", "", "json", false, true, "/captured/app/enkv.yaml", configuration.JSON, true},
		{"yaml", "custom.yaml", "", true, false, "/captured/app/custom.yaml", configuration.YAML, true},
		{"yml-uppercase", "custom.YML", "", true, false, "/captured/app/custom.YML", configuration.YAML, true},
		{"json-uppercase", "custom.JSON", "", true, false, "/captured/app/custom.JSON", configuration.JSON, true},
		{"absolute", "/other/config.json", "", true, false, "/other/config.json", configuration.JSON, true},
		{"clean-relative", "nested/../config.yaml", "", true, false, "/captured/app/config.yaml", configuration.YAML, true},
		{"explicit-over-suffix", "config.yaml", "json", true, true, "/captured/app/config.yaml", configuration.JSON, true},
		{"explicit-unknown-suffix", "config.conf", "yaml", true, true, "/captured/app/config.conf", configuration.YAML, true},
		{"no-suffix", "config", "", true, false, "", 0, false},
		{"unknown-suffix", "config.conf", "", true, false, "", 0, false},
		{"empty-source", "", "", true, false, "", 0, false},
		{"empty-format", "config.json", "", true, true, "", 0, false},
		{"invalid-format", "config.json", "automatic", true, true, "", 0, false},
		{"root", "/", "json", true, true, "", 0, false},
		{"nul", "config\x00.json", "", true, false, "", 0, false},
		{"invalid-utf8", "config" + string([]byte{255}) + ".json", "", true, false, "", 0, false},
		{"at-limit", "/" + strings.Repeat("x", 4090) + ".json", "", true, false, "/" + strings.Repeat("x", 4090) + ".json", configuration.JSON, true},
		{"over-limit", "/" + strings.Repeat("x", 4091) + ".json", "", true, false, "", 0, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			path, format, valid := paths.source(replacementFlag{row.source, row.sourceSet}, replacementFlag{row.format, row.formatSet})
			if valid != row.valid || path != row.wantPath || format != row.wantFormat {
				t.Fatal("source resolution differs", path, format, valid)
			}
		})
	}
	for _, row := range []struct {
		name         string
		path, format replacementFlag
		valid        bool
	}{
		{"absent", replacementFlag{}, replacementFlag{}, true},
		{"format-only", replacementFlag{}, replacementFlag{"json", true}, false},
		{"explicit-empty", replacementFlag{"", true}, replacementFlag{}, false},
		{"inferred", replacementFlag{"candidate.json", true}, replacementFlag{}, true},
	} {
		t.Run("candidate/"+row.name, func(t *testing.T) {
			path, format, valid := paths.candidate(row.path, row.format)
			if valid != row.valid || row.name == "absent" && (path != "" || format != 0) || row.name == "inferred" && (path != "/captured/app/candidate.json" || format != configuration.JSON) {
				t.Fatal("candidate resolution differs", path, format, valid)
			}
		})
	}
}

// full_only: false
func TestSourceSelectionKeepsCapturedDirectory(t *testing.T) {
	t.Chdir(t.TempDir())
	paths, ok := captureCommandPaths()
	if !ok {
		t.Fatal("working directory capture failed")
	}
	want := paths.directory
	t.Chdir(t.TempDir())
	path, format, ok := paths.source(replacementFlag{}, replacementFlag{})
	if !ok || path != filepath.Join(want, "enkv.yaml") || format != configuration.YAML || paths.absolute("successor.yaml") != filepath.Join(want, "successor.yaml") {
		t.Fatal("current working directory redirected captured paths", path)
	}
}

// full_only: false
func TestPlanResolvesDefaultAndIndependentCandidate(t *testing.T) {
	trusted, _, _, _ := setCommandPreparedSource(t)
	directory := t.TempDir()
	t.Chdir(directory)
	for name, body := range map[string]string{
		"enkv.yaml":      "schema: unsupported-plan-intent-fixture\n",
		"candidate.JSON": `{"schema":"unsupported-plan-intent-fixture"}`,
		"contrary.yaml":  `{"schema":"unsupported-plan-intent-fixture"}`,
	} {
		if err := os.WriteFile(name, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct {
		name, source string
		args         []string
	}{
		{"default", "trusted", nil},
		{"inferred-trusted", "trusted", []string{"--trusted=candidate.JSON"}},
		{"inferred-candidate", "candidate", []string{"--trusted=" + trusted, "--candidate=candidate.JSON"}},
		{"explicit-candidate-override", "candidate", []string{"--trusted=" + trusted, "--candidate=contrary.yaml", "--candidate-format=json"}},
	} {
		t.Run(row.name, func(t *testing.T) {
			code, body, diagnostic := planIntentRun(t, append(append([]string{}, row.args...), "--json", "--log-level=off"))
			var result struct {
				Payload struct {
					Diagnostics []struct {
						Reason string
						Source struct {
							ID string `json:"source_id"`
						} `json:"source_location"`
					}
				}
			}
			if err := json.Unmarshal(body, &result); err != nil || code != 2 || strings.Contains(diagnostic, "plan requires") || len(result.Payload.Diagnostics) != 1 || result.Payload.Diagnostics[0].Reason != "unsupported-schema" || result.Payload.Diagnostics[0].Source.ID != row.source {
				t.Fatal("plan selected another source or representation", code, diagnostic, string(body), err)
			}
		})
	}
}

// full_only: false
func TestDefaultSourceDoesNotSearchOrTryAnotherRepresentation(t *testing.T) {
	parent := t.TempDir()
	if err := os.WriteFile(filepath.Join(parent, "enkv.yaml"), []byte("schema: parent-file-sentinel\n"), 0600); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(parent, "app")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(directory)
	if err := os.WriteFile("enkv.json", []byte(`{"schema":"sibling-file-sentinel"}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, selectedExists := range []bool{false, true} {
		if selectedExists {
			if err := os.WriteFile("enkv.yaml", []byte("schema: [\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		code, body, diagnostic := planIntentRun(t, []string{"--json", "--log-level=off"})
		var result struct {
			Payload struct {
				Diagnostics []struct {
					Reason string
				}
			}
		}
		if err := json.Unmarshal(body, &result); err != nil || code != 2 || strings.Contains(diagnostic, "plan requires") || len(result.Payload.Diagnostics) != 1 || result.Payload.Diagnostics[0].Reason == "unsupported-schema" || bytes.Contains(body, []byte("parent-file-sentinel")) || bytes.Contains(body, []byte("sibling-file-sentinel")) {
			t.Fatal("selected-file failure searched or reparsed another source", selectedExists, code, diagnostic, string(body), err)
		}
	}
}

// full_only: false
func TestDefaultSourceProcessEditsApplicationConfiguration(t *testing.T) {
	if command := os.Getenv("ENKV_DEFAULT_SOURCE_PROCESS"); command != "" {
		args := []string{command, "--json", "--log-level=off"}
		if command == "set" {
			args = append(args, "--name=plain-entry", "--confidential=false")
		}
		os.Exit(run(args, os.Stdout, os.Stderr))
	}
	original, _, _, _ := setCommandPreparedSource(t)
	pair, err := configuration.Capture(t.Context(), original, configuration.JSON)
	if err != nil {
		t.Fatal(err)
	}
	model, parseErr := configuration.Parse(t.Context(), pair)
	var editable bytes.Buffer
	if parseErr == nil {
		parseErr = configuration.EmitEditable(&editable, model, configuration.YAML)
	}
	closeErr := pair.Close()
	if parseErr != nil || closeErr != nil {
		t.Fatal("local YAML fixture failed", parseErr, closeErr)
	}
	path := filepath.Join(filepath.Dir(original), "enkv.yaml")
	if err := os.WriteFile(path, editable.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"set", "publish"} {
		t.Run(command, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, binary, "-test.run=^TestDefaultSourceProcessEditsApplicationConfiguration$")
			child.Dir = filepath.Dir(path)
			child.Env = append(os.Environ(), "ENKV_DEFAULT_SOURCE_PROCESS="+command)
			child.Stdin = strings.NewReader("local process value")
			var out, diagnostic bytes.Buffer
			child.Stdout, child.Stderr = &out, &diagnostic
			err := child.Run()
			if command == "set" {
				if err != nil || !json.Valid(out.Bytes()) || !bytes.Contains(out.Bytes(), []byte(`"outcome": "edited"`)) {
					t.Fatal("default-source process did not edit local configuration", err, out.String(), diagnostic.String())
				}
			} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 2 || !strings.Contains(diagnostic.String(), "explicit --name or --delete-coordinate") {
				t.Fatal("default source changed required publication selector", err, diagnostic.String())
			}
		})
	}
	pair, err = configuration.Capture(t.Context(), path, configuration.YAML)
	if err != nil {
		t.Fatal(err)
	}
	model, parseErr = configuration.Parse(t.Context(), pair)
	closeErr = pair.Close()
	if parseErr != nil || closeErr != nil || len(model.Entries) != 1 || model.Entries[0].Name != "plain-entry" || string(model.Entries[0].Plain) != "local process value" {
		t.Fatal("process changed another source or value", parseErr, closeErr)
	}
}

package compositionfull

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/compositions/outputhost"
	"enkv.sh/core/contract"
	"enkv.sh/sdk/artifact"
	artifactbuild "enkv.sh/sdk/artifact/build"
	"enkv.sh/telemetry"
)

// full_only: false
func TestConfigurationValidationOwnsRetainedOutputLifetime(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	for _, key := range []string{"GOFLAGS", "GOEXPERIMENT", "GCCGO", "CC", "CXX", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS", "CGO_LDFLAGS", "GOTOOLDIR", "GOCACHEPROG", "GOFIPS140", "GODEBUG"} {
		t.Setenv(key, "")
	}
	for key, value := range map[string]string{"GOPROXY": "off", "GOSUMDB": "off", "GONOPROXY": "none"} {
		t.Setenv(key, value)
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	docs := filepath.Join(filepath.Dir(root), "enkv-extensions")
	fixture := filepath.Join(root, "tests", "fixtures", "output-contract-test", "cmd", "enkv-output-contract-test")
	author := t.TempDir()
	module := "module example.test/normalization-lifetime\n\ngo 1.27.0\n\nrequire (\n enkv.sh/sdk/artifact v0.1.0\n enkv.sh/sdk/output v0.1.0\n enkv.sh/sdk/protocols/output v0.1.0\n)\n"
	for name, body := range map[string]string{"go.mod": module, "LICENSE": "fixture license\n"} {
		if err := os.WriteFile(filepath.Join(author, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"main.go", "plugin.json"} {
		body, err := os.ReadFile(filepath.Join(fixture, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(author, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	modules := []struct{ name, path string }{
		{"enkv.sh/sdk/artifact", filepath.Join(docs, "sdk", "artifact")},
		{"enkv.sh/sdk/output", filepath.Join(docs, "sdk", "output")},
		{"enkv.sh/sdk/protocols/output", filepath.Join(docs, "sdk", "protocols", "output")},
	}
	var work strings.Builder
	fmt.Fprintf(&work, "go 1.27.0\n\nuse (\n %q\n", filepath.ToSlash(author))
	for _, module := range modules {
		fmt.Fprintf(&work, " %q\n", filepath.ToSlash(module.path))
	}
	work.WriteString(")\n\nreplace (\n")
	for _, module := range modules {
		fmt.Fprintf(&work, " %s v0.1.0 => %q\n", module.name, filepath.ToSlash(module.path))
	}
	work.WriteString(")\n")
	workspace := filepath.Join(t.TempDir(), "go.work")
	if err := os.WriteFile(workspace, []byte(work.String()), 0600); err != nil {
		t.Fatal(err)
	}
	output, home := t.TempDir(), t.TempDir()
	t.Cleanup(func() {
		for _, directory := range []string{output, home} {
			if err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if entry.IsDir() {
					return os.Chmod(path, 0700)
				}
				return nil
			}); err != nil {
				t.Error(err)
			}
		}
	})
	if _, err := artifactbuild.Run(ctx, artifactbuild.Config{Directory: author, Descriptor: "plugin.json", Command: ".", Output: output, Workspace: workspace}); err != nil {
		t.Fatal("build local output fixture", err)
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", "")
	savedOrigin, savedKeys, savedCLIKey, savedRedirects, savedRoots := installedPluginOrigin, installedPluginKeys, installedCLIVerificationKey, installedPluginRedirectHosts, installedPluginTLSRoots
	installedPluginOrigin = "https://127.0.0.1:1/releases/"
	installedPluginKeys = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	installedCLIVerificationKey = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
	installedPluginRedirectHosts, installedPluginTLSRoots = "", ""
	t.Cleanup(func() {
		installedPluginOrigin, installedPluginKeys, installedCLIVerificationKey, installedPluginRedirectHosts, installedPluginTLSRoots = savedOrigin, savedKeys, savedCLIKey, savedRedirects, savedRoots
	})
	for _, condition := range []string{"complete", "later-binding-refused", "final-cleanup-failed", "refusal-and-cleanup-failed", "invalid-and-cleanup-failed"} {
		t.Run(condition, func(t *testing.T) {
			temporary := t.TempDir()
			t.Setenv("TMPDIR", temporary)
			prefix := "first"
			switch condition {
			case "final-cleanup-failed":
				prefix = "deny-scope-cleanup"
			case "refusal-and-cleanup-failed":
				prefix = "refuse-and-deny-scope-cleanup"
			case "invalid-and-cleanup-failed":
				prefix = "collision-and-deny-scope-cleanup"
			}
			source := configurationReaderPair(t, "aws", configuration.JSON, func(editable, generated map[string]any) {
				destinations := map[string]any{"first": map[string]any{"plugin": "output-contract-test", "settings": map[string]any{"prefix": prefix}}}
				selected := []string{"first"}
				if condition == "complete" || condition == "later-binding-refused" {
					var second any = "second"
					if condition == "later-binding-refused" {
						second = 3
					}
					destinations["second"] = map[string]any{"plugin": "output-contract-test", "settings": map[string]any{"prefix": second}}
					selected = append(selected, "second")
				}
				entries := map[string]any{"secret": selected}
				if condition == "invalid-and-cleanup-failed" {
					entries["encoded"] = selected
				}
				delete(generated, "canonical_records")
				editable["outputs"] = map[string]any{"destinations": destinations, "routing": map[string]any{"entries": entries}}
			})
			application, err := filepath.EvalSymlinks(filepath.Dir(source.path))
			if err != nil {
				t.Fatal(err)
			}
			settings, err := artifact.EncodeSettings(artifact.Settings{Schema: "enkv/plugin-settings/v1", Applications: []artifact.Application{{Directory: application, Plugins: []artifact.LocalPlugin{{Name: "output-contract-test", Directory: output}}}}})
			if err != nil {
				t.Fatal(err)
			}
			configDirectory, err := os.UserConfigDir()
			if err != nil {
				t.Fatal(err)
			}
			settingsPath := filepath.Join(configDirectory, "enkv", "plugins.json")
			if err := os.MkdirAll(filepath.Dir(settingsPath), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(settingsPath, settings, 0600); err != nil {
				t.Fatal(err)
			}
			model, err := configuration.Parse(ctx, source.pair)
			if err != nil {
				t.Fatal(err)
			}
			recorder := telemetry.NewRecorder()
			callCtx := telemetry.WithCapability(ctx, telemetry.NewCapability(nil, recorder))
			result, _, _, err := configurationNormalizationValidation(callCtx, source.pair, source.pair, model, true)
			if condition == "complete" {
				if err != nil || !result.Valid || !result.Complete || !result.DiagnosticsComplete {
					t.Fatal("complete validation lost its result", result, err)
				}
			} else {
				if err == nil {
					t.Fatal("failed validation reported complete success", result)
				}
				if (condition == "later-binding-refused" || condition == "refusal-and-cleanup-failed") && !errors.Is(err, outputhost.ErrPassiveRefused) {
					t.Fatal("later refusal lost its original cause", err)
				}
				if strings.Contains(condition, "cleanup-failed") && !errors.Is(err, outputhost.ErrProcess) {
					t.Fatal("retained executable cleanup lost its cause", err)
				}
				if condition == "invalid-and-cleanup-failed" {
					var invalid *configurationNormalizationError
					duplicate := false
					for _, diagnostic := range result.Diagnostics {
						duplicate = duplicate || diagnostic.Reason == contract.ReasonDuplicateKey
					}
					if !errors.As(err, &invalid) || result.Valid || !duplicate || !result.DiagnosticsComplete {
						t.Fatal("converted validation lost its original facts or cleanup cause", result, err)
					}
				}
			}
			joins := 0
			for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 128)) {
				if record.Event == telemetry.DiagnosticReturn && record.Operation == telemetry.OpOutputHostJoin {
					joins++
				}
				if record.Operation == telemetry.OpOutputHostCredentialGate || record.Operation == telemetry.OpOutputHostDispatch {
					t.Fatal("normalization acquired private output work")
				}
			}
			wantJoins := 2
			switch condition {
			case "complete":
				wantJoins = 4
			case "refusal-and-cleanup-failed":
				wantJoins = 1
			case "invalid-and-cleanup-failed":
				wantJoins = 3
			}
			if joins != wantJoins {
				t.Fatal("validation lost positive child joins", joins, wantJoins)
			}
			stages, globErr := filepath.Glob(filepath.Join(temporary, ".enkv-output-stage-*"))
			if globErr != nil {
				t.Fatal(globErr)
			}
			if strings.Contains(condition, "cleanup-failed") {
				if len(stages) != 1 {
					t.Fatal("cleanup failure did not retain its exact executable root", stages)
				}
				if err := os.Chmod(stages[0], 0700); err != nil {
					t.Fatal(err)
				}
			} else if len(stages) != 0 {
				t.Fatal("validation returned before disposing its executable owner", stages)
			}
			source.assertUnchanged(t)
		})
	}
}

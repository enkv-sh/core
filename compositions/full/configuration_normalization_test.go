package compositionfull

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/compositions/full/plugininstallation"
	"enkv.sh/compositions/generatorhost"
	"enkv.sh/core/contract"
	"enkv.sh/sdk/artifact"
	artifactbuild "enkv.sh/sdk/artifact/build"
	generator "enkv.sh/sdk/protocols/generator"
)

// full_only: false
func TestConfigurationNormalizationRequirementsExcludeUnselectedPreferences(t *testing.T) {
	model := &configuration.Model{Entries: []configuration.Entry{{Name: "token", Generated: &configuration.Generator{Plugin: "private-generator", Settings: []byte(`{}`)}}}, Outputs: []configuration.OutputBinding{{DestinationID: "destination", Plugin: "private-output", Settings: []byte(`{}`)}}, Plugins: []configuration.PluginRequirement{{Name: "private-generator", Version: "2.0.0"}, {Name: "unrelated-renderer", Version: "1.0.0"}}}
	rows, err := configurationNormalizationRequirements(model)
	want := []plugininstallation.Requirement{{Name: "private-generator", Version: "2.0.0"}, {Name: "private-output"}}
	if err != nil || !reflect.DeepEqual(rows, want) {
		t.Fatal("source preferences changed actual passive dependencies", rows, err)
	}
	model.Entries[0].Generated.Plugin = ""
	model.Entries[0].Generated.Settings = nil
	model.Outputs[0].Plugin = ""
	model.Outputs[0].Settings = nil
	rows, err = configurationNormalizationRequirements(model)
	if err != nil || len(rows) != 0 {
		t.Fatal("canonical recovery acquired a renderer or effect dependency", rows, err)
	}
}

// full_only: false
func TestConfigurationNormalizationKeepsSourceLocationsAndRawSettings(t *testing.T) {
	// Independent canonical None intent with its complete71-byte framing.
	canonical := []byte(`{"size":17}`)
	intent := append([]byte{0, 1}, bytes.Repeat([]byte{69}, 32)...)
	intent = append(intent, 1)
	intent = append(intent, make([]byte, 32)...)
	intent = binary.BigEndian.AppendUint32(intent, uint32(len(canonical)))
	intent = append(intent, canonical...)
	location := &contract.SourceLocation{SourceID: "source", Line: 7, Column: 9}
	generator := &configuration.Generator{Plugin: "private-generator", Settings: []byte("{ \"size\": 17.0 }"), Intent: intent}
	generated := &contract.PublicGeneratedSettings{ConfigContractID: contract.PublicField[contract.ID]{State: contract.PublicUnavailable, SourceLocation: location}, ContentIntent: contract.PublicField[[]byte]{State: contract.PublicUnavailable, SourceLocation: location}}
	destination := contract.OutputDestination{ConfigContractID: "private-config/v1", ServiceContractID: "private-service/v1", CanonicalSettings: []byte(`{}`)}
	model := &configuration.Model{Entries: []configuration.Entry{{Name: "token", Generated: generator}}, Outputs: []configuration.OutputBinding{{DestinationID: "destination", Plugin: "private-output", Settings: []byte("{ }"), Binding: contract.NormalOutputBinding{DestinationID: "destination", Destination: destination}}}, Public: contract.PublicConfiguration{Entries: readerPresent([]contract.PublicEntry{{Name: "token", Generated: generated}}), OutputBindings: readerPresent([]contract.PublicOutputBinding{{DestinationID: "destination", Destination: contract.PublicField[contract.OutputDestination]{State: contract.PublicUnavailable, SourceLocation: location}}})}}
	if err := configurationProjectNormalized(model); err != nil {
		t.Fatal(err)
	}
	if generated.ConfigContractID.SourceLocation != location || generated.ContentIntent.SourceLocation != location || model.Public.OutputBindings.Value[0].Destination.SourceLocation != location {
		t.Fatal("passive normalization discarded captured source locations")
	}
	if generated.ContentIntent.State != contract.PublicPresent || !bytes.Equal(generated.ContentIntent.Value, intent) || generated.LifecycleMode.Value != contract.GeneratorLifecycleNone || model.Public.OutputBindings.Value[0].Destination.Value.ConfigContractID != "private-config/v1" {
		t.Fatal("derived canonical fields were not retained")
	}
	if string(generator.Settings) != "{ \"size\": 17.0 }" || string(model.Outputs[0].Settings) != "{ }" {
		t.Fatal("normalization rewrote source settings")
	}
}

// full_only: false
func TestConfigurationNormalizedLifecycleRequiresExplicitRetirement(t *testing.T) {
	for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
		for _, tc := range []struct {
			name, retirement string
			managed, valid   bool
		}{
			{"managed-missing", "", true, false},
			{"managed-manual", "manual", true, true},
			{"managed-auto", "auto", true, true},
			{"none-manual", "manual", false, false},
			{"none-auto", "auto", false, false},
			{"none-omitted", "", false, true},
		} {
			t.Run(configurationSourceFormat(format)+"/"+tc.name, func(t *testing.T) {
				source := configurationApplyPair(t, "aws", format, func(editable, _ map[string]any) {
					settings := map[string]any{"kind": "generated", "plugin": "independent-generator", "settings": map[string]any{}, "epoch": 0}
					if tc.retirement != "" {
						settings["retirement"] = tc.retirement
					}
					editable["entries"].(map[string]any)["generated"] = map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": settings}
				})
				model, err := configuration.Parse(t.Context(), source.pair)
				if err != nil {
					t.Fatal("settings input did not defer lifecycle validation", err)
				}
				var generated *configuration.Generator
				var public *contract.PublicGeneratedSettings
				for i := range model.Entries {
					if model.Entries[i].Name == "generated" {
						generated = model.Entries[i].Generated
					}
				}
				for i := range model.Public.Entries.Value {
					if model.Public.Entries.Value[i].Name == "generated" {
						public = model.Public.Entries.Value[i].Generated
					}
				}
				if generated == nil || public == nil {
					t.Fatal("parsed generated source missing")
				}
				settings := bytes.Clone(generated.Settings)
				location := &contract.SourceLocation{SourceID: "independent-source", Line: 9, Column: 7}
				public.ContentIntent.SourceLocation = location
				intent := append([]byte{0, 1}, bytes.Repeat([]byte{69}, 32)...)
				lifecycle := byte(1)
				resource := make([]byte, 32)
				if tc.managed {
					lifecycle = 2
					resource = bytes.Repeat([]byte{70}, 32)
				}
				intent = append(intent, lifecycle)
				intent = append(intent, resource...)
				intent = append(intent, 0, 0, 0, 2, '{', '}')
				generated.Intent = intent
				err = configurationProjectNormalized(model)
				if (err == nil) != tc.valid {
					t.Fatal("normalized intent bypassed explicit lifecycle retirement rule", err)
				}
				if !bytes.Equal(generated.Settings, settings) || generated.Retirement != tc.retirement {
					t.Fatal("lifecycle validation changed source settings or retirement")
				}
				if tc.valid {
					if public.ContentIntent.SourceLocation != location || !bytes.Equal(public.ContentIntent.Value, intent) {
						t.Fatal("normalized projection lost exact intent or source location")
					}
					if tc.managed {
						want := contract.GeneratedRetirementManual
						if tc.retirement == "auto" {
							want = contract.GeneratedRetirementAuto
						}
						if public.Retirement.State != contract.PublicPresent || public.Retirement.Value != want {
							t.Fatal("explicit retirement changed after normalization")
						}
					} else if public.Retirement.State != 0 || public.Completion.State != 0 {
						t.Fatal("unmanaged intent acquired retirement fields")
					}
				}
				if err := source.pair.CheckUnchanged(t.Context()); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// full_only: false
func TestConfigurationNormalizationPassesExactCommonSettingsToLenientPlugin(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	for _, key := range []string{"GOFLAGS", "GOEXPERIMENT", "GCCGO", "CC", "CXX", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS", "CGO_LDFLAGS", "GOTOOLDIR", "GOCACHEPROG", "GOFIPS140", "GODEBUG"} {
		t.Setenv(key, "")
	}
	for key, value := range map[string]string{"GOPROXY": "off", "GOSUMDB": "off", "GONOPROXY": "none"} {
		t.Setenv(key, value)
	}
	directory, err := filepath.Abs(filepath.Join("..", "generatorhost"))
	if err != nil {
		t.Fatal(err)
	}
	output := t.TempDir()
	t.Cleanup(func() {
		if err := filepath.WalkDir(output, func(path string, entry os.DirEntry, err error) error {
			if err != nil || !entry.IsDir() {
				return err
			}
			return os.Chmod(path, 0700)
		}); err != nil {
			t.Error(err)
		}
	})
	workspace := filepath.Join(directory, "..", "..", "..", "enkv-extensions", "go.work")
	marker, err := artifactbuild.Run(ctx, artifactbuild.Config{Directory: directory, Descriptor: "testdata/hermetic/plugin.json", Command: "./testdata/hermetic", Output: output, Workspace: workspace})
	if err != nil {
		t.Fatal("lenient plugin fixture build", err)
	}
	build := filepath.Join(output, filepath.FromSlash(marker.Directory))
	body, err := os.ReadFile(filepath.Join(build, "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := artifact.DecodeMetadata(body)
	if err != nil {
		t.Fatal(err)
	}
	dependency, err := os.ReadFile(filepath.Join(build, "dependencies.bin"))
	if err != nil {
		t.Fatal(err)
	}
	installed, err := generatorhost.NewInstallation(metadata, dependency)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.ReadFile(filepath.Join(build, "plugin"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "generator")
	if err := os.WriteFile(path, executable, 0700); err != nil {
		t.Fatal(err)
	}
	validator, err := generatorhost.NewPublicValidator(t.Context(), path, installed)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"value":"True","list":["TRUE","False","FALSE",true,false],"quoted":"true"}`
	for _, tc := range []struct {
		name, settings string
		format         configuration.Format
	}{
		{"yaml", `{value: True, list: [TRUE, False, FALSE, true, false], quoted: "true"}`, configuration.YAML},
		{"json", want, configuration.JSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := configurationApplyPair(t, "aws", tc.format, func(editable, _ map[string]any) {
				editable["entries"].(map[string]any)["opaque"] = map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": map[string]any{"kind": "generated", "plugin": "independent-host-generator", "epoch": 0, "retirement": "manual", "settings": "opaque-settings-placeholder"}}
			})
			needle := []byte(`"settings":"opaque-settings-placeholder"`)
			if bytes.Count(source.editableBytes, needle) != 1 {
				t.Fatal("source fixture has no unique settings field")
			}
			if err := source.pair.Close(); err != nil {
				t.Fatal(err)
			}
			body := bytes.Replace(source.editableBytes, needle, []byte(`"settings":`+tc.settings), 1)
			if err := os.Chmod(source.path, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(source.path, body, 0600); err != nil {
				t.Fatal(err)
			}
			pair, err := configuration.Capture(ctx, source.path, tc.format)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := pair.Close(); err != nil {
					t.Error(err)
				}
			}()
			model, err := configuration.Parse(ctx, pair)
			if err != nil {
				t.Fatal(err)
			}
			var selected *configuration.Generator
			for _, entry := range model.Entries {
				if entry.Name == "opaque" {
					selected = entry.Generated
				}
			}
			if selected == nil || selected.Plugin != "independent-host-generator" {
				t.Fatal("source lost its selected opaque generator")
			}
			before := bytes.Clone(selected.Settings)
			if err := configurationNormalizeGenerator(ctx, validator, generator.ID(installed.Artifact().ConfigContractID), selected); err != nil {
				t.Fatal("lenient plugin rejected common JSON", err)
			}
			intent, err := contract.InspectGeneratorIntent(selected.Intent)
			if err != nil || !bytes.Equal(intent.Settings, []byte(want)) || !bytes.Equal(selected.Settings, []byte(want)) || !bytes.Equal(selected.Settings, before) {
				t.Fatal("passive normalization changed common scalar types or source bytes", string(selected.Settings), err)
			}
			if err := pair.CheckUnchanged(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

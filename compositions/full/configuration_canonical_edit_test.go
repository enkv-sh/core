package compositionfull

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/compositions/full/plugininstallation"
	"enkv.sh/compositions/outputhost"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/sdk/artifact"
	artifactbuild "enkv.sh/sdk/artifact/build"
)

// full_only: false
func TestRecoveredSettingsEditsUseInstalledCanonicalValidationAndTargets(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	for _, name := range []string{"GOFLAGS", "GOEXPERIMENT", "GCCGO", "CC", "CXX", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS", "CGO_LDFLAGS", "GOTOOLDIR", "GOCACHEPROG", "GOFIPS140", "GODEBUG", "ENKV_EXAMPLE_TOKEN"} {
		t.Setenv(name, "")
	}
	t.Setenv("GOPROXY", "off")
	t.Setenv("GOSUMDB", "off")
	t.Setenv("GONOPROXY", "none")
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(root, "compositions", "full", "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(root)
		if parent == root {
			t.Fatal("implementation root unavailable")
		}
		root = parent
	}
	docs := filepath.Join(filepath.Dir(root), "enkv-extensions")
	var builds []artifact.LocalPlugin
	for _, example := range []struct{ directory, name string }{{"local-token-generator", "private-local-token"}, {"local-value-output", "private-local-values"}} {
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
		if _, err := artifactbuild.Run(ctx, artifactbuild.Config{Directory: filepath.Join(docs, "sdk", "examples", example.directory), Descriptor: "plugin.json", Command: ".", Output: output, Workspace: filepath.Join(docs, "go.work")}); err != nil {
			t.Fatal("real example build", err)
		}
		builds = append(builds, artifact.LocalPlugin{Name: example.name, Directory: output})
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	config, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(config, "enkv"), 0700); err != nil {
		t.Fatal(err)
	}
	configureLocalPluginTrust(t)
	assembly, err := configurationPluginAssembly(installedPluginOrigin, installedPluginKeys, installedCLIVerificationKey, installedPluginRedirectHosts, installedPluginTLSRoots)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1); w.WriteHeader(http.StatusForbidden) }))
	defer server.Close()
	configID, err := hex.DecodeString("0280ab3c4fbe2f8279f592344001095c9509d7ebd749f01be042e138b1033d2f")
	if err != nil {
		t.Fatal(err)
	}
	resource := sha256.Sum256([]byte("example/local-token-resource/v1"))
	beforeSettings := []byte(fmt.Sprintf(`{"endpoint":%q,"namespace":"example","subject":"token"}`, server.URL))
	beforeIntent := append([]byte{0, 1}, configID...)
	beforeIntent = append(beforeIntent, 2)
	beforeIntent = append(beforeIntent, resource[:]...)
	beforeIntent = binary.BigEndian.AppendUint32(beforeIntent, uint32(len(beforeSettings)))
	beforeIntent = append(beforeIntent, beforeSettings...)
	capabilities := contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityDeleteOwned
	oldDestination := contract.OutputDestination{ConfigContractID: "local-values-config/v1", ServiceContractID: "local-values-service/v1", CanonicalSettings: []byte(fmt.Sprintf(`{"endpoint":%q,"namespace":"dev"}`, server.URL)), Capabilities: capabilities}
	oldTarget := contract.OutputTarget{ServiceContractID: "local-values-service/v1", TargetContractID: "local-values-target/v1", CanonicalTarget: server.URL + "/values/dev/QVBJX1RPS0VO", ConsumerLocator: server.URL + "/values/dev/QVBJX1RPS0VO", TargetData: []byte(fmt.Sprintf(`{"endpoint":%q,"namespace":"dev","key":"QVBJX1RPS0VO"}`, server.URL)), PayloadEncoding: contract.OutputEncodingRaw, Capabilities: capabilities, CreateValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, WriteValueBounds: contract.OutputPayloadBounds{Maximum: 65536}}
	binding, err := contract.EncodeNormalOutputBinding(contract.NormalOutputBinding{DestinationID: "vault", Destination: oldDestination, Targets: []contract.NormalOutputTarget{{Name: "API_TOKEN", Target: oldTarget}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
		t.Run(configurationSourceFormat(format), func(t *testing.T) {
			t.Run("unrouted-output", func(t *testing.T) {
				checkUnroutedCanonicalSettings(t, ctx, format, config, builds, server.URL, oldDestination)
				if requests.Load() != 0 {
					t.Fatal("unrouted settings validation contacted the output service")
				}
			})
			source := configurationApplyPair(t, "aws", format, func(editable, generated map[string]any) {
				editable["entries"] = map[string]any{"API_TOKEN": map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": map[string]any{"kind": "generated", "plugin": "private-local-token", "epoch": uint64(7), "retirement": "manual", "canonical": map[string]any{"settings": json.RawMessage(beforeSettings)}}}}
				generated["secrets"] = map[string]any{}
				configurationCanonicalBacking(generated, "generators", "API_TOKEN", beforeIntent)
				configurationCanonicalBacking(generated, "outputs", "vault", binding)
				editable["outputs"] = map[string]any{"destinations": map[string]any{"vault": map[string]any{"plugin": "private-local-values", "canonical": map[string]any{"settings": json.RawMessage(oldDestination.CanonicalSettings)}}}, "routing": map[string]any{"default": []string{"vault"}}}
			})
			initial, err := configuration.Parse(ctx, source.pair)
			if err != nil {
				t.Fatal(err)
			}
			var editable bytes.Buffer
			if err := configuration.EmitEditable(&editable, initial, format); err != nil {
				t.Fatal(err)
			}
			if err := source.pair.Close(); err != nil {
				t.Fatal(err)
			}
			configurationSetWritable(t, source)
			if err := os.Chmod(source.path, 0600); err != nil {
				t.Fatal(err)
			}
			scope, err := filepath.EvalSymlinks(filepath.Dir(source.path))
			if err != nil {
				t.Fatal(err)
			}
			settings, err := artifact.EncodeSettings(artifact.Settings{Schema: "enkv/plugin-settings/v1", Applications: []artifact.Application{{Directory: scope, Plugins: builds}}})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(config, "enkv", "plugins.json"), settings, 0600); err != nil {
				t.Fatal(err)
			}
			beforeTokens := [3]string{`"subject": "token"`, `"namespace": "dev"`, `"epoch": 7`}
			afterTokens := [3]string{`"subject": "worker"`, `"namespace": "prod"`, `"epoch": 8`}
			emptyTokens := [2]string{`"subject": ""`, `"namespace": ""`}
			if format == configuration.YAML {
				beforeTokens = [3]string{"subject: token", "namespace: dev", "epoch: 7"}
				afterTokens = [3]string{"subject: worker", "namespace: prod", "epoch: 8"}
				emptyTokens = [2]string{`subject: ""`, `namespace: ""`}
			}
			edited := editable.String()
			for i, before := range beforeTokens {
				edited = strings.ReplaceAll(edited, before, afterTokens[i])
			}
			if edited == editable.String() {
				t.Fatal("operator edit did not change source")
			}
			for _, condition := range []string{"accepted", "unchanged", "different-offered-target", "generator-default-forbidden", "output-default-forbidden"} {
				t.Run(condition, func(t *testing.T) {
					candidate := edited
					unchanged := condition == "unchanged" || condition == "different-offered-target"
					if unchanged {
						candidate = editable.String()
					}
					if condition == "generator-default-forbidden" {
						candidate = strings.ReplaceAll(candidate, afterTokens[0], emptyTokens[0])
					}
					if condition == "output-default-forbidden" {
						candidate = strings.ReplaceAll(candidate, afterTokens[1], emptyTokens[1])
					}
					if err := os.WriteFile(source.path, []byte(candidate), 0600); err != nil {
						t.Fatal(err)
					}
					wantOffered := oldTarget
					if condition == "different-offered-target" {
						wantOffered.CanonicalTarget = server.URL + "/values/other/QVBJX1RPS0VO"
						body, err := contract.EncodeNormalOutputBinding(contract.NormalOutputBinding{DestinationID: "vault", Destination: oldDestination, Targets: []contract.NormalOutputTarget{{Name: "API_TOKEN", Target: wantOffered}}})
						if err != nil {
							t.Fatal(err)
						}
						old := []byte(base64.StdEncoding.EncodeToString(binding))
						if bytes.Count(source.generatedBytes, old) != 1 {
							t.Fatal("fixture canonical backing")
						}
						changed := bytes.Replace(source.generatedBytes, old, []byte(base64.StdEncoding.EncodeToString(body)), 1)
						if err := os.Chmod(source.generated, 0600); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(source.generated, changed, 0600); err != nil {
							t.Fatal(err)
						}
						defer func() {
							if err := os.WriteFile(source.generated, source.generatedBytes, 0600); err != nil {
								t.Error(err)
							}
						}()
					}
					beforeFiles := configurationApplySourceImage(t, filepath.Dir(source.path))
					pair, err := configuration.Capture(ctx, source.path, format)
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
					if unchanged {
						rows := model.Outputs[0].Binding.Targets
						if len(rows) != 1 || !rows[0].Target.Equal(wantOffered) {
							t.Fatal("missing exact canonical target for verification")
						}
					} else if model.Outputs[0].Binding.Targets != nil {
						t.Fatal("edited destination retained stale proposed targets")
					}
					coordinator, err := plugininstallation.New(assembly)
					if err != nil {
						t.Fatal(err)
					}
					session, installations, err := coordinator.Resolve(ctx, plugininstallation.Request{Directory: scope, Requirements: []plugininstallation.Requirement{{Name: "private-local-token"}, {Name: "private-local-values"}}, Mode: plugininstallation.Ordinary, CheckSource: pair.CheckUnchanged})
					if err != nil {
						t.Fatal(err)
					}
					captured := &configurationInstalledPlugins{session: session, coordinator: coordinator}
					if unchanged {
						byName := make(map[string]plugininstallation.Installation)
						for _, row := range installations {
							byName[row.Name] = row
						}
						facts, err := configurationCanonicalDependencyChecks(ctx, pair, model, captured, byName)
						result, checked := facts[prepareCanonicalDependency{role: "output", name: "private-local-values", semantic: oldDestination.ConfigContractID}]
						if err != nil || !checked || result.unavailable || result.refused != (condition == "different-offered-target") {
							t.Fatal("canonical target readiness", result, checked, err)
						}
					}
					_, _, err = configurationNormalizePluginsWithOutputValidator(ctx, pair, pair.CheckUnchanged, model, true, captured, outputhost.NewPublicValidator)
					if condition == "different-offered-target" {
						if !errors.Is(err, contract.ErrRecord) {
							t.Fatal("offered physical target passed installed interpretation", err)
						}
					} else if condition == "unchanged" {
						if err != nil || !model.Outputs[0].Binding.Targets[0].Target.Equal(oldTarget) {
							t.Fatal("exact independently interpreted source refused", err)
						}
					} else if condition != "accepted" {
						if err == nil {
							t.Fatal("canonical edit acquired author-input defaults")
						}
					} else {
						if err != nil {
							t.Fatal("real installed canonical edit refused", err)
						}
						wantSettings := []byte(fmt.Sprintf(`{"endpoint":%q,"namespace":"example","subject":"worker"}`, server.URL))
						intent, err := contract.InspectGeneratorIntent(model.Entries[0].Generated.Intent)
						if err != nil || !bytes.Equal(intent.Settings, wantSettings) || model.Entries[0].Generated.Epoch != 8 || model.Entries[0].Generated.Settings != nil {
							t.Fatal("generator edit changed unrelated fields or applied defaults", err)
						}
						want := oldTarget
						want.CanonicalTarget = server.URL + "/values/prod/QVBJX1RPS0VO"
						want.ConsumerLocator = want.CanonicalTarget
						want.TargetData = []byte(fmt.Sprintf(`{"endpoint":%q,"namespace":"prod","key":"QVBJX1RPS0VO"}`, server.URL))
						if len(model.Outputs[0].Binding.Targets) != 1 || model.Outputs[0].Binding.Targets[0].Name != "API_TOKEN" || !reflect.DeepEqual(model.Outputs[0].Binding.Targets[0].Target, want) {
							t.Fatal("real target interpretation did not produce the complete edited target")
						}
					}
					configurationApplyAssertUnchanged(t, filepath.Dir(source.path), beforeFiles)
					if requests.Load() != 0 {
						t.Fatal("passive canonical validation sent a service request")
					}
				})
			}
		})
	}
}

func checkUnroutedCanonicalSettings(t *testing.T, ctx context.Context, format configuration.Format, config string, plugins []artifact.LocalPlugin, endpoint string, stored contract.OutputDestination) {
	t.Helper()
	backing, err := contract.EncodeNormalOutputBinding(contract.NormalOutputBinding{DestinationID: "archive", Destination: stored})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, namespace          string
		selected, sibling, opens bool
	}{
		{"edit-missing-with-sibling", "warm", false, true, false},
		{"edit-missing-alone", "warm", false, false, false},
		{"edit-accepted", "warm", true, true, true},
		{"edit-refused", "", true, true, false},
		{"unchanged-unselected", "dev", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var selection any
			if tc.selected {
				selection = "private-local-values"
			}
			settings := []byte(fmt.Sprintf(`{"endpoint":%q,"namespace":%q}`, endpoint, tc.namespace))
			source := configurationApplyPair(t, "aws", format, func(editable, generated map[string]any) {
				editable["entries"] = map[string]any{"message": map[string]any{"confidentiality": "plain", "recipients": []string{}, "source": map[string]any{"kind": "supplied", "value": "local"}}}
				generated["secrets"] = map[string]any{}
				destinations := map[string]any{"archive": map[string]any{"plugin": selection, "canonical": map[string]any{"settings": json.RawMessage(settings)}}}
				routing := map[string]any{}
				if tc.sibling {
					destinations["active"] = map[string]any{"plugin": "private-local-values", "settings": map[string]any{"endpoint": endpoint, "namespace": "active"}}
					routing["default"] = []string{"active"}
				}
				editable["outputs"] = map[string]any{"destinations": destinations, "routing": routing}
				configurationCanonicalBacking(generated, "outputs", "archive", backing)
			})
			scope, err := filepath.EvalSymlinks(filepath.Dir(source.path))
			if err != nil {
				t.Fatal(err)
			}
			local, err := artifact.EncodeSettings(artifact.Settings{Schema: "enkv/plugin-settings/v1", Applications: []artifact.Application{{Directory: scope, Plugins: plugins}}})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(config, "enkv", "plugins.json"), local, 0600); err != nil {
				t.Fatal(err)
			}
			before := configurationApplySourceImage(t, scope)
			opens := 0
			result := applyConfiguration(ctx, contract.ID{1}, source.pair, func(_ context.Context, m *configuration.Model, _ core.ApplyInstallation, _ *configurationInstalledPlugins) (*core.InstalledApply, error) {
				opens++
				for _, output := range m.Outputs {
					if output.DestinationID == "archive" {
						want := stored
						want.CanonicalSettings = settings
						if len(output.Binding.Targets) != 0 || !reflect.DeepEqual(output.Binding.Destination, want) {
							t.Fatal("archive acquired a route or changed canonical fields")
						}
						return nil, ErrCell
					}
				}
				t.Fatal("archive missing from proposal")
				return nil, ErrCell
			})
			configurationApplyAssertUnchanged(t, scope, before)
			if tc.opens {
				if opens != 1 {
					t.Fatalf("valid proposal did not reach construction: %+v", result.PreAdmission)
				}
				configurationApplyAssertUnavailable(t, result)
				return
			}
			if opens != 0 || !result.RequestIdentity.IsZero() || result.Result.CommitMayHaveOccurred || result.PreAdmission == nil {
				t.Fatal("unverified destination reached construction or admission")
			}
			if tc.selected {
				if result.Result.Outcome != core.AdmissionRefused || result.PreAdmission.Stage != "declaration" {
					t.Fatal("canonical refusal lost its cause", result.PreAdmission)
				}
			} else if result.Result.Outcome != core.EvidenceUnavailable || result.PreAdmission.Code != string(contract.ReasonEvidenceUnavailable) {
				t.Fatal("missing selection lost its dependency result", result.PreAdmission)
			}
		})
	}
}

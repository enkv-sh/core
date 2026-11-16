package compositionfull

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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
	assembly, err := configurationPluginAssembly("https://127.0.0.1:1/releases/", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "", "")
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
			for _, condition := range []string{"accepted", "generator-default-forbidden", "output-default-forbidden"} {
				t.Run(condition, func(t *testing.T) {
					candidate := edited
					if condition == "generator-default-forbidden" {
						candidate = strings.ReplaceAll(candidate, afterTokens[0], emptyTokens[0])
					}
					if condition == "output-default-forbidden" {
						candidate = strings.ReplaceAll(candidate, afterTokens[1], emptyTokens[1])
					}
					if err := os.WriteFile(source.path, []byte(candidate), 0600); err != nil {
						t.Fatal(err)
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
					if model.Outputs[0].Binding.Targets != nil {
						t.Fatal("edited destination retained stale proposed targets")
					}
					coordinator, err := plugininstallation.New(assembly)
					if err != nil {
						t.Fatal(err)
					}
					session, _, err := coordinator.Resolve(ctx, plugininstallation.Request{Directory: scope, Requirements: []plugininstallation.Requirement{{Name: "private-local-token"}, {Name: "private-local-values"}}, Mode: plugininstallation.Ordinary, CheckSource: pair.CheckUnchanged})
					if err != nil {
						t.Fatal(err)
					}
					captured := &configurationInstalledPlugins{session: session, coordinator: coordinator}
					_, _, err = configurationNormalizePluginsWithOutputValidator(ctx, pair, pair.CheckUnchanged, model, captured, outputhost.NewPublicValidator)
					if condition != "accepted" {
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

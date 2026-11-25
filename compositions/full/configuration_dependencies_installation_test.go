package compositionfull

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/compositions/full/plugininstallation"
	"enkv.sh/compositions/generatorhost"
	"enkv.sh/compositions/outputhost"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/sdk/artifact"
	artifactbuild "enkv.sh/sdk/artifact/build"
	generator "enkv.sh/sdk/protocols/generator"
	outputprotocol "enkv.sh/sdk/protocols/output"
)

// full_only: false
func TestPrepareDependenciesKeepsVerifiedSemanticArtifactOnPartialFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	for _, key := range []string{"GOFLAGS", "GOEXPERIMENT", "GCCGO", "CC", "CXX", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS", "CGO_LDFLAGS", "GOTOOLDIR", "GOCACHEPROG", "GOFIPS140", "GODEBUG"} {
		t.Setenv(key, "")
	}
	for key, value := range map[string]string{"GOPROXY": "off", "GOSUMDB": "off", "GONOPROXY": "none"} {
		t.Setenv(key, value)
	}
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if info, err := os.Stat(filepath.Join(root, "compositions", "full", "go.mod")); err == nil && info.Mode().IsRegular() {
			break
		}
		parent := filepath.Dir(root)
		if parent == root {
			t.Fatal("implementation root unavailable")
		}
		root = parent
	}
	docs := filepath.Join(filepath.Dir(root), "enkv-extensions")
	sdk := filepath.Join(docs, "sdk", "manifest-generator")
	wire := filepath.Join(docs, "sdk", "protocols", "manifest-generator")
	directory, output, localOutput, home := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	cfDirectory, cfOutput := t.TempDir(), t.TempDir()
	valueDirectory, valueOutput := filepath.Join(docs, "sdk", "examples", "local-value-output"), t.TempDir()
	t.Cleanup(func() {
		for _, path := range []string{output, localOutput, cfOutput, valueOutput, home} {
			if err := filepath.WalkDir(path, func(path string, entry os.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if entry.IsDir() {
					return os.Chmod(path, 0700)
				}
				return nil
			}); err != nil {
				t.Error("fixture directory cleanup", err)
			}
		}
	})
	invoked := filepath.Join(t.TempDir(), "unexpected-execution")
	module := "module example.test/prepare-assessment\n\ngo 1.27.0\n\nrequire (\n enkv.sh/sdk/manifest-generator v0.1.1\n enkv.sh/sdk/protocols/manifest-generator v0.1.1\n)\n"
	main := fmt.Sprintf("package main\nimport \"os\"\nfunc main(){if err:=os.WriteFile(%q,[]byte(\"invoked\"),0600);err!=nil{panic(err)};panic(\"preparation executed the plugin\")}\n", invoked)
	for name, body := range map[string]string{"go.mod": module, "main.go": main, "LICENSE": "fixture license\n"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cfModule := "module example.test/prepare-cloudflare\n\ngo 1.27.0\n\nrequire (\n enkv.sh/plugins/generators/cloudflare-account-token v0.1.1\n enkv.sh/sdk/generator v0.1.1\n enkv.sh/sdk/protocols/generator v0.1.1\n)\n"
	cfMain := fmt.Sprintf(`package main
import (
 "bytes"
 "context"
 _ "embed"
 "encoding/hex"
 "os"
 "enkv.sh/sdk/generator"
 protocol "enkv.sh/sdk/protocols/generator"
)
//go:embed plugin.json
var descriptor []byte
func main() {
 body,err:=hex.DecodeString("7ede2a15bbf86395c097322b651f2752f9adf1bdfa346f09683e20e670ff10c1");if err!=nil{os.Exit(20)}
 var current,legacy,resource protocol.ID;copy(current[:],body);copy(legacy[:],bytes.Repeat([]byte{0x45},32));copy(resource[:],bytes.Repeat([]byte{0x46},32))
 binding,err:=generator.Bind(descriptor,current);if err!=nil{os.Exit(21)}
 effect:=func(){if err:=os.WriteFile(%q,[]byte("effect"),0600);err!=nil{os.Exit(22)}}
 implementation:=generator.Implementation{Binding:binding,
  Normalize:func(_ context.Context,r protocol.NormalizeRequest)(protocol.Intent,error){return protocol.Intent{Schema:1,ConfigContractID:current,LifecycleMode:protocol.LifecycleManaged,ResourceContractID:resource,Settings:bytes.Clone(r.Settings)},nil},
  ValidateCanonical:func(_ context.Context,i protocol.Intent)error{if bytes.Equal(i.Settings,[]byte("{\"size\":19}")){os.Exit(41)};if i.LifecycleMode!=protocol.LifecycleManaged||i.ResourceContractID!=resource||i.ConfigContractID!=current&&i.ConfigContractID!=legacy{return protocol.ErrProtocol};if i.ConfigContractID==legacy&&!bytes.Equal(i.Settings,[]byte("{\"size\":17}")){return protocol.ErrProtocol};return nil},
  CheckRetirementCompatibility:func(context.Context,protocol.RetirementCompatibilityRequest)(bool,error){return true,nil},
  Create:func(context.Context,generator.Invocation)(protocol.SafeFacts,[]byte,error){effect();return protocol.SafeFacts{},nil,protocol.ErrProtocol},
  Retire:func(context.Context,generator.Invocation)(protocol.SafeFacts,error){effect();return protocol.SafeFacts{},protocol.ErrProtocol},
 }
 os.Exit(generator.Main(implementation))
}
`, invoked)
	for name, body := range map[string]string{"go.mod": cfModule, "main.go": cfMain, "LICENSE": "fixture license\n"} {
		if err := os.WriteFile(filepath.Join(cfDirectory, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, fixture := range []struct{ directory, descriptor string }{{directory, filepath.Join(docs, "plugins", "manifest-generators", "generic-json", "cmd", "enkv-manifest-generic-json", "plugin.json")}, {cfDirectory, filepath.Join(docs, "plugins", "generators", "cloudflare-account-token", "cmd", "enkv-generator-cloudflare", "plugin.json")}} {
		body, err := os.ReadFile(fixture.descriptor)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(fixture.directory, "plugin.json"), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	workspace := filepath.Join(t.TempDir(), "go.work")
	localDirectory := filepath.Join(docs, "plugins", "generators", "local-random-secret")
	modules := []struct{ name, version, directory string }{
		{"enkv.sh/sdk/artifact", "v0.1.1", filepath.Join(docs, "sdk", "artifact")},
		{"enkv.sh/plugins/generators/cloudflare-account-token", "v0.1.1", filepath.Join(docs, "plugins", "generators", "cloudflare-account-token")},
		{"enkv.sh/sdk/manifest-generator", "v0.1.1", sdk}, {"enkv.sh/sdk/protocols/manifest-generator", "v0.1.1", wire},
		{"enkv.sh/sdk/generator", "v0.1.1", filepath.Join(docs, "sdk", "generator")},
		{"enkv.sh/sdk/protocols/generator", "v0.1.1", filepath.Join(docs, "sdk", "protocols", "generator")},
		{"enkv.sh/sdk/output", "v0.1.1", filepath.Join(docs, "sdk", "output")},
		{"enkv.sh/sdk/protocols/output", "v0.1.0", filepath.Join(docs, "sdk", "protocols", "output")},
		{"enkv.sh/sdk/examples/local-value-output", "v0.1.1", valueDirectory},
		{"enkv.sh/sdk/examples/testservice", "v0.1.0", filepath.Join(docs, "sdk", "examples", "testservice")},
		{"enkv.sh/plugins/generators/local-random-secret", "v0.1.1", filepath.Join(docs, "plugins", "generators", "local-random-secret")},
	}
	var work strings.Builder
	work.WriteString("go 1.27.0\n\nuse (\n")
	for _, path := range []string{directory, cfDirectory} {
		fmt.Fprintf(&work, " %q\n", filepath.ToSlash(path))
	}
	for _, module := range modules {
		fmt.Fprintf(&work, " %q\n", filepath.ToSlash(module.directory))
	}
	work.WriteString(")\n\nreplace (\n")
	for _, module := range modules {
		fmt.Fprintf(&work, " %s %s => %q\n", module.name, module.version, filepath.ToSlash(module.directory))
	}
	work.WriteString(")\n")
	if err := os.WriteFile(workspace, []byte(work.String()), 0600); err != nil {
		t.Fatal(err)
	}
	marker, err := artifactbuild.Run(ctx, artifactbuild.Config{Directory: directory, Descriptor: "plugin.json", Command: ".", Output: output, Workspace: workspace})
	if err != nil {
		t.Fatal("prepare assessment fixture build failed", err)
	}
	build := filepath.Join(output, filepath.FromSlash(marker.Directory))
	executable, err := os.ReadFile(filepath.Join(build, "plugin"))
	if err != nil {
		t.Fatal(err)
	}
	executableSHA := sha256.Sum256(executable)
	metadata, err := os.ReadFile(filepath.Join(build, "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	metadataID := artifact.Digest(sha256.Sum256(metadata))
	if metadataID == artifact.Digest(executableSHA) {
		t.Fatal("fixture does not distinguish executable digest from metadata identity")
	}
	localMarker, err := artifactbuild.Run(ctx, artifactbuild.Config{Directory: localDirectory, Descriptor: "cmd/enkv-generator-local-random-secret/plugin.json", Command: "./cmd/enkv-generator-local-random-secret", Output: localOutput, Workspace: workspace})
	if err != nil {
		t.Fatal("prepare local author fixture build failed", err)
	}
	localBuild := filepath.Join(localOutput, filepath.FromSlash(localMarker.Directory))
	localExecutable, err := os.ReadFile(filepath.Join(localBuild, "plugin"))
	if err != nil {
		t.Fatal(err)
	}
	localSHA := sha256.Sum256(localExecutable)
	localMetadata, err := os.ReadFile(filepath.Join(localBuild, "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	localMetadataID := artifact.Digest(sha256.Sum256(localMetadata))
	if localMetadataID == artifact.Digest(localSHA) {
		t.Fatal("local fixture does not distinguish executable from metadata identity")
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	savedOrigin, savedKeys, savedCLIKey, savedRedirects, savedRoots := installedPluginOrigin, installedPluginKeys, installedCLIVerificationKey, installedPluginRedirectHosts, installedPluginTLSRoots
	installedPluginOrigin = "https://127.0.0.1:1/releases/"
	installedCLIVerificationKey = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
	installedPluginKeys = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	installedPluginRedirectHosts, installedPluginTLSRoots = "", ""
	t.Cleanup(func() {
		installedPluginOrigin, installedPluginKeys, installedCLIVerificationKey, installedPluginRedirectHosts, installedPluginTLSRoots = savedOrigin, savedKeys, savedCLIKey, savedRedirects, savedRoots
	})
	source := configurationApplyPair(t, "aws", configuration.JSON, func(editable, generated map[string]any) {
		editable["plugins"] = map[string]any{"cloudflare-account-token": map[string]any{"version": "3.0.0"}, "generic-json": map[string]any{"version": "9.0.0"}}
		editable["entries"].(map[string]any)["local"] = map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": map[string]any{"kind": "generated", "plugin": "local-random-secret", "epoch": 0, "settings": map[string]any{}}}
	})
	scope, err := filepath.EvalSymlinks(filepath.Dir(source.path))
	if err != nil {
		t.Fatal(err)
	}
	config, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(config, "enkv"), 0700); err != nil {
		t.Fatal(err)
	}
	settings, err := artifact.EncodeSettings(artifact.Settings{Schema: "enkv/plugin-settings/v1", Applications: []artifact.Application{{Directory: scope, Plugins: []artifact.LocalPlugin{{Name: "cloudflare-account-token", Directory: t.TempDir()}, {Name: "generic-json", Directory: output}, {Name: "local-random-secret", Directory: localOutput}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(config, "enkv", "plugins.json"), settings, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := PrepareConfiguration(ctx, PrepareRequest{Source: source.path, Format: configuration.JSON})
	if !errors.Is(err, plugininstallation.ErrMissing) || result == nil || PrepareExitCode(result, nil) != 2 {
		t.Logf("partial preparation: result=%t exit=%d prepare_error=%t missing=%t invalid=%t source_changed=%t", result != nil, PrepareExitCode(result, nil), errors.Is(err, ErrPrepare), errors.Is(err, plugininstallation.ErrMissing), errors.Is(err, plugininstallation.ErrInvalid), errors.Is(err, plugininstallation.ErrSourceChanged))
		if result != nil {
			facts := result.facts
			t.Logf("partial preparation facts: branch=%s outcome=%s assessment=%s administrative_ready=%t declared_ready=%t diagnostics=%d requirements=%d installations=%d", facts.Branch, facts.Outcome, facts.Dependencies.Assessment, facts.Dependencies.MinimumAdministrativeReady, facts.Dependencies.AllDeclaredReady, len(facts.Diagnostics), len(facts.Dependencies.Requirements), len(facts.Dependencies.Installations))
			validate := false
			for _, diagnostic := range facts.Diagnostics[:min(8, len(facts.Diagnostics))] {
				t.Logf("partial preparation diagnostic: subject=%s reason=%s", diagnostic.Subject, diagnostic.Reason)
				validate = validate || diagnostic.Reason == "source-invalid"
			}
			for i, requirement := range facts.Dependencies.Requirements[:min(8, len(facts.Dependencies.Requirements))] {
				t.Logf("partial preparation requirement: index=%d role=%s status=%s reason=%s", i, requirement.Role, requirement.Status, requirement.Reason)
			}
			for i, installation := range facts.Dependencies.Installations[:min(8, len(facts.Dependencies.Installations))] {
				t.Logf("partial preparation installation: index=%d status=%s reason=%s", i, installation.Status, installation.Reason)
			}
			if validate {
				model, parseErr := configuration.Parse(ctx, source.pair)
				t.Logf("partial preparation source: parsed=%t", parseErr == nil)
				if parseErr == nil {
					validation := validateInstalledConfiguration(ctx, model.Public)
					t.Logf("partial preparation validation: valid=%t complete=%t diagnostics_complete=%t diagnostics=%d", validation.Valid, validation.Complete, validation.DiagnosticsComplete, len(validation.Diagnostics))
					for _, diagnostic := range validation.Diagnostics[:min(16, len(validation.Diagnostics))] {
						t.Logf("partial preparation validation diagnostic: kind=%s path=%v reason=%s", diagnostic.Subject.Kind, diagnostic.Path[:min(8, len(diagnostic.Path))], diagnostic.Reason)
					}
				}
			}
		}
		t.Fatal("partial installation failure lost its dependency error", err)
	}
	assessment := result.facts.Dependencies
	localExecutableSHA := hex.EncodeToString(localSHA[:])
	want := []PrepareDependencyRequirement{{Role: "generator", Subjects: []uint16{3}, Plugin: dependencyPluginName("local-random-secret"), Contract: "663075a79a657cf8e281991deb3cbfac760eff6445ead7af60005dd27d9e0caa", ProtocolVersion: 5, Artifact: &localExecutableSHA, Status: "verified", Reason: "none"}}
	if assessment.Assessment != "complete" || !assessment.MinimumAdministrativeReady || assessment.AllDeclaredReady || !reflect.DeepEqual(assessment.Requirements, want) || len(assessment.Installations) != 3 {
		t.Fatal("partial installation failure erased completed semantic verification", assessment)
	}
	failed, verified, local := assessment.Installations[0], assessment.Installations[1], assessment.Installations[2]
	if failed.Name != "cloudflare-account-token" || failed.Source != "local" || failed.Status != "missing" || failed.Reason != "not-installed" || failed.Version != "" || failed.Artifact != nil || failed.Previous != nil || failed.Changed {
		t.Fatal("missing local sibling claimed a selection", failed)
	}
	if verified.Name != "generic-json" || verified.Source != "local" || verified.Version != "0.1.1" || verified.Status != "verified" || verified.Reason != "none" || verified.Artifact == nil || *verified.Artifact != metadataID || verified.Previous != nil || verified.Changed {
		t.Fatal("verified installation lost its separate metadata identity or local override", verified)
	}
	if local.Name != "local-random-secret" || local.Source != "local" || local.Version != "0.1.1" || local.Status != "verified" || local.Reason != "none" || local.Artifact == nil || *local.Artifact != localMetadataID || local.Previous != nil || local.Changed {
		t.Fatal("verified local installation lost its exact identity", local)
	}
	if _, err := os.Stat(invoked); !os.IsNotExist(err) {
		t.Fatal("preparation executed the fixture plugin", err)
	}
	if result.facts.Outcome != "incomplete" || !reflect.DeepEqual(result.facts.Diagnostics, []prepareDiagnostic{{Reason: "dependency-missing", Subject: "dependencies"}}) {
		t.Fatal("partial installation failure changed operation facts", result.facts.Outcome, result.facts.Diagnostics)
	}
	if body, err := RenderPrepareJSON(result); err != nil || strings.Contains(string(body), "unexpected-execution") {
		t.Fatal("partial prepare result did not render closed facts", err)
	}
	source.assertUnchanged(t)

	cfMarker, err := artifactbuild.Run(ctx, artifactbuild.Config{Directory: cfDirectory, Descriptor: "plugin.json", Command: ".", Output: cfOutput, Workspace: workspace})
	if err != nil {
		t.Fatal("prepare Cloudflare author fixture build failed", err)
	}
	cfBuild := filepath.Join(cfOutput, filepath.FromSlash(cfMarker.Directory))
	cfExecutable, err := os.ReadFile(filepath.Join(cfBuild, "plugin"))
	if err != nil {
		t.Fatal(err)
	}
	cfSHA := sha256.Sum256(cfExecutable)
	cfExecutableSHA := hex.EncodeToString(cfSHA[:])
	cfMetadata, err := os.ReadFile(filepath.Join(cfBuild, "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfMetadataID := artifact.Digest(sha256.Sum256(cfMetadata))
	if cfMetadataID == artifact.Digest(cfSHA) {
		t.Fatal("Cloudflare fixture does not distinguish executable from metadata identity")
	}
	if _, err := artifactbuild.Run(ctx, artifactbuild.Config{Directory: valueDirectory, Descriptor: "plugin.json", Command: ".", Output: valueOutput, Workspace: workspace}); err != nil {
		t.Fatal("prepare output semantic fixture build failed", err)
	}
	localCanonical, err := hex.DecodeString("0001" + "663075a79a657cf8e281991deb3cbfac760eff6445ead7af60005dd27d9e0caa" + "01" + strings.Repeat("00", 32) + "000000027b7d")
	if err != nil {
		t.Fatal("independent local canonical intent fixture", err)
	}
	for _, retained := range []bool{false, true} {
		name := "selected-plugins"
		if retained {
			name = "recovered-without-selection"
		}
		t.Run(name, func(t *testing.T) {
			source := configurationApplyPair(t, "aws", configuration.JSON, func(editable, generated map[string]any) {
				editable["plugins"] = map[string]any{"generic-json": map[string]any{}}
				entries := editable["entries"].(map[string]any)
				entries["local"] = map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": map[string]any{"kind": "generated", "plugin": "local-random-secret", "epoch": 0, "settings": map[string]any{}}}
				// The two local declarations become the same requirement only
				// after the ordinary settings resolve their metadata contract.
				entries["local-canonical"] = map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": map[string]any{"kind": "generated", "plugin": "local-random-secret", "epoch": 0, "canonical": map[string]any{"settings": json.RawMessage(`{}`)}}}
				configurationCanonicalBacking(generated, "generators", "local-canonical", localCanonical)
				entries["current"] = map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": dependencyGeneratorSource(t, "0123456789abcdef0123456789abcdef")}
				if retained {
					old := dependencyCanonicalGeneratorSource(generated, "retained", true)
					entries["retained"] = map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": old}
				}
			})
			scope, err := filepath.EvalSymlinks(filepath.Dir(source.path))
			if err != nil {
				t.Fatal(err)
			}
			settings, err := artifact.EncodeSettings(artifact.Settings{Schema: "enkv/plugin-settings/v1", Applications: []artifact.Application{{Directory: scope, Plugins: []artifact.LocalPlugin{{Name: "cloudflare-account-token", Directory: cfOutput}, {Name: "generic-json", Directory: output}, {Name: "local-random-secret", Directory: localOutput}}}}})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(config, "enkv", "plugins.json"), settings, 0600); err != nil {
				t.Fatal(err)
			}
			result, err := PrepareConfiguration(ctx, PrepareRequest{Source: source.path, Format: configuration.JSON})
			if err != nil || result == nil {
				t.Fatal("verified installations failed preparation", err)
			}
			assessment := result.facts.Dependencies
			want := []PrepareDependencyRequirement{
				{Role: "generator", Subjects: []uint16{2}, Plugin: dependencyPluginName("cloudflare-account-token"), Contract: "7ede2a15bbf86395c097322b651f2752f9adf1bdfa346f09683e20e670ff10c1", ProtocolVersion: 5, Artifact: &cfExecutableSHA, Status: "verified", Reason: "none"},
				{Role: "generator", Subjects: []uint16{4, 5}, Plugin: dependencyPluginName("local-random-secret"), Contract: "663075a79a657cf8e281991deb3cbfac760eff6445ead7af60005dd27d9e0caa", ProtocolVersion: 5, Artifact: &localExecutableSHA, Status: "verified", Reason: "none"},
			}
			if retained {
				want = append(want, PrepareDependencyRequirement{Role: "generator", Subjects: []uint16{6}, Contract: strings.Repeat("45", 32), ProtocolVersion: 5, Status: "missing", Reason: "selection-required"})
			}

			slices.SortFunc(want, func(a, b PrepareDependencyRequirement) int { return strings.Compare(a.Contract, b.Contract) })
			if assessment.Assessment != "complete" || !assessment.MinimumAdministrativeReady || assessment.AllDeclaredReady != !retained || !reflect.DeepEqual(assessment.Requirements, want) {
				t.Fatalf("installation verification did not preserve exact semantic compatibility: got=%+v want=%+v", assessment, want)
			}
			if len(assessment.Installations) != 3 {
				t.Fatal("semantic assessment changed the complete installation set", assessment.Installations)
			}
			for i, want := range []struct {
				name, version string
				identity      artifact.Digest
			}{{"cloudflare-account-token", "0.1.1", cfMetadataID}, {"generic-json", "0.1.1", metadataID}, {"local-random-secret", "0.1.1", localMetadataID}} {
				got := assessment.Installations[i]
				if got.Name != want.name || got.Version != want.version || got.Source != "local" || got.Status != "verified" || got.Reason != "none" || got.Artifact == nil || *got.Artifact != want.identity || got.Previous != nil || got.Changed {
					t.Fatal("semantic mismatch changed independently verified installation facts", got)
				}
			}
			if retained {
				if PrepareExitCode(result, nil) != 2 || result.facts.Outcome != "incomplete" || !reflect.DeepEqual(result.facts.Diagnostics, []prepareDiagnostic{{Reason: "dependency-missing", Subject: "dependencies"}}) {
					t.Fatal("recovered requirement without local selection claimed completion", result.facts)
				}
			} else if PrepareExitCode(result, nil) != 0 || result.facts.Outcome != "complete" || len(result.facts.Diagnostics) != 0 {
				t.Fatal("current compatible requirements did not complete preparation", result.facts)
			}
			if _, err := os.Stat(invoked); !os.IsNotExist(err) {
				t.Fatal("semantic readiness executed a producer", err)
			}
			source.assertUnchanged(t)
		})
	}
	for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
		for _, operation := range []string{"rekey", "retire"} {
			t.Run(configurationSourceFormat(format)+"/maintenance-"+operation, func(t *testing.T) {
				source := configurationMaintenancePair(t, "aws", format, func(editable, generated map[string]any) {
					editable["entries"].(map[string]any)["unrelated-generated"] = map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": map[string]any{"kind": "generated", "plugin": "cloudflare-account-token", "epoch": 0, "retirement": "manual", "settings": map[string]any{"size": 17}}}
					editable["outputs"] = map[string]any{"destinations": map[string]any{"unrelated-output": map[string]any{"plugin": "private-local-values", "settings": map[string]any{"endpoint": "http://127.0.0.1:1", "namespace": "scope"}}}, "routing": map[string]any{"default": []string{"unrelated-output"}}}
				})
				scope, err := filepath.EvalSymlinks(filepath.Dir(source.path))
				if err != nil {
					t.Fatal(err)
				}
				settings, err := artifact.EncodeSettings(artifact.Settings{Schema: "enkv/plugin-settings/v1", Applications: []artifact.Application{{Directory: scope, Plugins: []artifact.LocalPlugin{{Name: "cloudflare-account-token", Directory: cfOutput}, {Name: "private-local-values", Directory: valueOutput}}}}})
				if err != nil || os.WriteFile(filepath.Join(config, "enkv", "plugins.json"), settings, 0600) != nil {
					t.Fatal("install maintenance semantic fixture settings", err)
				}
				calls := 0
				check := func(model *configuration.Model, installed core.AccessMutationInstallation) {
					calls++
					var generated *configuration.Generator
					for _, entry := range model.Entries {
						if entry.Name == "unrelated-generated" {
							generated = entry.Generated
						}
					}
					if generated == nil || len(generated.Intent) == 0 || !bytes.Equal(generated.Settings, []byte(`{"size":17}`)) || installed.Maintenance == nil || len(model.Outputs) != 1 || model.Outputs[0].Binding.Destination.ConfigContractID != "local-values-config/v1" || !bytes.Equal(model.Outputs[0].Binding.Destination.CanonicalSettings, []byte(`{"endpoint":"http://127.0.0.1:1","namespace":"scope"}`)) || len(model.Outputs[0].Binding.Targets) != len(model.Entries) {
						t.Fatal("maintenance reached construction without complete passive meaning")
					}
					intent, err := contract.InspectGeneratorIntent(generated.Intent)
					if err != nil || !bytes.Equal(intent.Settings, []byte(`{"size":17}`)) || intent.LifecycleMode != contract.GeneratorLifecycleManaged {
						t.Fatal("maintenance changed canonical generator meaning", err)
					}
				}
				var result core.PublicApplyResult
				if operation == "rekey" {
					result = rekeyConfigurationEnvelopeForTest(t, ctx, contract.ID{77}, source.pair, "secret", func(_ context.Context, model *configuration.Model, installed core.EnvelopeRekeyInstallation) (configurationRekeyEngine, error) {
						check(model, installed.AccessMutationInstallation)
						return nil, ErrCell
					})
				} else {
					model, err := configuration.Parse(ctx, source.pair)
					if err != nil || len(model.Recipients) == 0 {
						t.Fatal("recipient maintenance fixture missing", err)
					}
					result = retireConfigurationRecipientForTest(t, ctx, contract.ID{77}, source.pair, model.Recipients[0].Reference, func(_ context.Context, model *configuration.Model, installed core.RecipientRetirementInstallation) (configurationRetirementEngine, error) {
						check(model, installed.AccessMutationInstallation)
						return nil, ErrCell
					})
				}
				if calls != 1 {
					t.Fatal("valid plugin settings blocked maintenance before construction", calls, result.PreAdmission, result.Result, result.Diagnostics)
				}
				configurationApplyAssertUnavailable(t, result)
				if _, err := os.Stat(invoked); !os.IsNotExist(err) {
					t.Fatal("maintenance normalization entered a generator effect", err)
				}
				source.assertUnchanged(t)
			})
		}
	}
	type semanticCase struct {
		kind, failedSibling string
		missingFirst        bool
	}
	var semanticCases []semanticCase
	for _, kind := range []string{"older-generator-accepted", "generator-refused", "generator-accepted-first", "generator-refused-first", "generator-unavailable", "generator-refused-then-unavailable", "generator-unavailable-then-refused", "output-accepted", "output-refused", "output-accepted-first", "output-refused-first"} {
		semanticCases = append(semanticCases, semanticCase{kind: kind})
	}
	for _, kind := range []string{"older-generator-accepted", "generator-refused", "output-accepted", "output-refused"} {
		for _, failedSibling := range []string{"missing", "bad"} {
			for _, missingFirst := range []bool{false, true} {
				semanticCases = append(semanticCases, semanticCase{kind: kind, failedSibling: failedSibling, missingFirst: missingFirst})
			}
		}
	}
	for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
		for _, test := range semanticCases {
			kind, name := test.kind, test.kind
			sibling := ""
			if test.failedSibling != "" {
				sibling = "zzzz-" + test.failedSibling
				if test.missingFirst {
					sibling = "aaaa-" + test.failedSibling
				}
				name += "/" + sibling
			}
			t.Run(configurationSourceFormat(format)+"/"+name, func(t *testing.T) {
				accepted := kind == "older-generator-accepted" || kind == "output-accepted"
				isOutput := strings.HasPrefix(kind, "output-")
				bodies := [][]byte{dependencyCanonicalIntent(true)}
				if strings.Contains(kind, "refused") {
					bodies[0] = bytes.Replace(bodies[0], []byte(`{"size":17}`), []byte(`{"size":18}`), 1)
				}
				if strings.HasSuffix(kind, "first") {
					other := dependencyCanonicalIntent(true)
					if strings.Contains(kind, "accepted-first") {
						other = bytes.Replace(other, []byte(`{"size":17}`), []byte(`{"size":18}`), 1)
					}
					bodies = append(bodies, other)
				}
				unavailable := strings.Contains(kind, "unavailable")
				if unavailable {
					unavailableBody := bytes.Replace(dependencyCanonicalIntent(true), []byte(`{"size":17}`), []byte(`{"size":19}`), 1)
					refusedBody := bytes.Replace(dependencyCanonicalIntent(true), []byte(`{"size":17}`), []byte(`{"size":18}`), 1)
					switch kind {
					case "generator-refused-then-unavailable":
						bodies = [][]byte{refusedBody, unavailableBody}
					case "generator-unavailable-then-refused":
						bodies = [][]byte{unavailableBody, refusedBody}
					default:
						bodies = [][]byte{unavailableBody}
					}
				}
				var destinations []outputprotocol.Destination
				source := configurationApplyPair(t, "aws", format, func(editable, generated map[string]any) {
					if sibling != "" {
						editable["entries"].(map[string]any)["failed-sibling"] = map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": map[string]any{"kind": "generated", "plugin": sibling, "epoch": 0, "settings": map[string]any{}}}
					}
					for index, intent := range bodies {
						name := fmt.Sprintf("canonical-%d", index)
						if !isOutput {
							editable["entries"].(map[string]any)[name] = map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": map[string]any{"kind": "generated", "plugin": "cloudflare-account-token", "epoch": 0, "retirement": "manual", "canonical": map[string]any{"settings": json.RawMessage(intent[71:])}}}
							configurationCanonicalBacking(generated, "generators", name, intent)
							continue
						}
						namespace := "scope"
						if bytes.Contains(intent, []byte(`{"size":18}`)) {
							namespace = "invalid namespace"
						}
						settings := []byte(fmt.Sprintf(`{"endpoint":"http://127.0.0.1:1","namespace":%q}`, namespace))
						capabilities := contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityDeleteOwned
						destination := contract.OutputDestination{ConfigContractID: "local-values-config/v1", ServiceContractID: "local-values-service/v1", CanonicalSettings: settings, Capabilities: capabilities}
						body, err := contract.EncodeNormalOutputBinding(contract.NormalOutputBinding{DestinationID: name, Destination: destination})
						if err != nil {
							t.Fatal(err)
						}
						editable["outputs"].(map[string]any)["destinations"].(map[string]any)[name] = map[string]any{"plugin": "private-local-values", "canonical": map[string]any{"settings": json.RawMessage(settings)}}
						configurationCanonicalBacking(generated, "outputs", name, body)
						destinations = append(destinations, outputprotocol.Destination{ConfigContractID: destination.ConfigContractID, ServiceContractID: destination.ServiceContractID, CanonicalSettings: settings, Capabilities: outputprotocol.ActionCapabilities(capabilities)})
					}
				})
				scope, err := filepath.EvalSymlinks(filepath.Dir(source.path))
				if err != nil {
					t.Fatal(err)
				}
				localPlugins := []artifact.LocalPlugin{{Name: "cloudflare-account-token", Directory: cfOutput}, {Name: "private-local-values", Directory: valueOutput}}
				if sibling != "" {
					failedOutput := t.TempDir()
					if test.failedSibling == "bad" {
						if err := os.WriteFile(filepath.Join(failedOutput, "build.json"), []byte("{}"), 0600); err != nil {
							t.Fatal(err)
						}
					}
					localPlugins = append(localPlugins, artifact.LocalPlugin{Name: sibling, Directory: failedOutput})
					slices.SortFunc(localPlugins, func(a, b artifact.LocalPlugin) int { return strings.Compare(a.Name, b.Name) })
				}
				settings, err := artifact.EncodeSettings(artifact.Settings{Schema: "enkv/plugin-settings/v1", Applications: []artifact.Application{{Directory: scope, Plugins: localPlugins}}})
				if err != nil || os.WriteFile(filepath.Join(config, "enkv", "plugins.json"), settings, 0600) != nil {
					t.Fatal("install exact semantic fixture settings", err)
				}
				model, err := configuration.Parse(ctx, source.pair)
				if err != nil {
					t.Fatal("canonical fixture did not pass common admission", err)
				}
				plugin := "cloudflare-account-token"
				if isOutput {
					plugin = "private-local-values"
				}
				captured, _, err := configurationCapturePlugins(ctx, source.pair, []plugininstallation.Requirement{{Name: plugin}}, plugininstallation.Ordinary)
				if err != nil {
					t.Fatal(err)
				}
				selected, ok := captured.lookup(plugin)
				if !ok {
					t.Fatal("exact semantic fixture not captured")
				}
				metadata, err := selected.Metadata()
				if err != nil {
					t.Fatal(err)
				}
				deadline, err := configurationPassiveDeadline(ctx)
				if err != nil {
					t.Fatal(err)
				}
				for index, body := range bodies {
					want := !bytes.Contains(body, []byte(`{"size":18}`))
					if isOutput {
						installed, err := outputhost.NewInstallation(metadata, selected.DependencyBytes())
						if err != nil {
							t.Fatal(err)
						}
						validator, err := outputhost.NewPublicValidator(ctx, selected.Executable(), installed)
						if err != nil {
							t.Fatal(err)
						}
						_, err = validator.ValidateCanonical(ctx, outputprotocol.CanonicalRequest{Schema: 1, DeadlineUnixMillis: deadline, Destination: destinations[index]})
						if (err == nil) != want {
							t.Fatal("output fixture did not establish exact canonical acceptance", err)
						}
					} else {
						installed, err := generatorhost.NewInstallation(metadata, selected.DependencyBytes())
						if err != nil {
							t.Fatal(err)
						}
						validator, err := generatorhost.NewPublicValidator(ctx, selected.Executable(), installed)
						if err != nil {
							t.Fatal(err)
						}
						request := generator.CanonicalRequest{Schema: 1, Purpose: generator.CanonicalHistorical, DeadlineUnixMillis: deadline, Intent: body}
						request.InputDigest, err = generator.CanonicalInputDigest(request)
						if err != nil {
							t.Fatal(err)
						}
						_, err = validator.ValidateCanonical(ctx, request)
						if bytes.Contains(body, []byte(`{"size":19}`)) {
							if !errors.Is(err, generatorhost.ErrProcess) || errors.Is(err, generatorhost.ErrPassiveRefused) {
								t.Fatal("generator fixture did not establish passive process failure", err)
							}
						} else if (err == nil) != want {
							t.Fatal("generator fixture did not establish exact older canonical acceptance", err)
						}
					}
				}
				assessment, err := prepareDependencies(ctx, source.pair, model, false)
				wantCount := 1
				if sibling != "" {
					wantCount++
				}
				if (err == nil) != (sibling == "" && !unavailable) || assessment.Assessment != "complete" || !assessment.MinimumAdministrativeReady || assessment.AllDeclaredReady != (accepted && sibling == "") || len(assessment.Requirements) != wantCount || len(assessment.Installations) != wantCount {
					t.Fatal("semantic readiness ignored exact canonical acceptance", assessment, err)
				}
				rowIndex := slices.IndexFunc(assessment.Requirements, func(row PrepareDependencyRequirement) bool { return prepareDependencyPlugin(row) == plugin })
				installationIndex := slices.IndexFunc(assessment.Installations, func(row plugininstallation.Installation) bool { return row.Name == plugin })
				if rowIndex < 0 || installationIndex < 0 {
					t.Fatal("semantic assessment omitted the captured plugin", assessment)
				}
				row := assessment.Requirements[rowIndex]
				firstSubject := 0
				if !isOutput {
					firstSubject = 2 // The empty and a/\n雪 source declarations precede canonical-*.
				}
				wantSubjects := make([]uint16, len(bodies))
				for i := range wantSubjects {
					wantSubjects[i] = uint16(firstSubject + i)
				}
				if !reflect.DeepEqual(row.Subjects, wantSubjects) {
					t.Fatal("common binary requirement lost its complete source associations", row.Subjects, wantSubjects)
				}
				wantStatus, wantReason := "incompatible", "identity-mismatch"
				if accepted {
					wantStatus, wantReason = "verified", "none"
				} else if kind == "generator-unavailable" {
					wantStatus, wantReason = "unavailable", "unavailable"
				}
				if row.Status != wantStatus || row.Reason != wantReason || row.Artifact == nil || assessment.Installations[installationIndex].Status != "verified" {
					t.Fatal("semantic refusal changed byte verification or disappeared in deduplication", row)
				}
				if unavailable && (!errors.Is(err, generatorhost.ErrProcess) || errors.Is(err, generatorhost.ErrPassiveRefused)) {
					t.Fatal("semantic requirement fold lost a separate process failure", row, err)
				}
				if sibling != "" {
					wantCause, wantStatus, wantReason := plugininstallation.ErrMissing, "missing", "not-installed"
					if test.failedSibling == "bad" {
						wantCause, wantStatus, wantReason = plugininstallation.ErrInvalid, "tampered", "record-invalid"
					}
					failedIndex := slices.IndexFunc(assessment.Installations, func(row plugininstallation.Installation) bool { return row.Name == sibling })
					if !errors.Is(err, wantCause) || failedIndex < 0 || assessment.Installations[failedIndex].Status != wantStatus || assessment.Installations[failedIndex].Reason != wantReason {
						t.Fatal("partial semantic assessment erased its failed sibling or aggregate cause", assessment, err)
					}
				}
				if _, err := os.Stat(invoked); !os.IsNotExist(err) {
					t.Fatal("passive readiness entered an effect callback", err)
				}
				source.assertUnchanged(t)
			})
		}
	}
}

// full_only: false
func TestPrepareDependenciesReportsSharedSettingsFailure(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	savedOrigin, savedKeys, savedCLIKey := installedPluginOrigin, installedPluginKeys, installedCLIVerificationKey
	installedPluginOrigin = "https://127.0.0.1:1/releases/"
	installedPluginKeys = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	installedCLIVerificationKey = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
	t.Cleanup(func() {
		installedPluginOrigin, installedPluginKeys, installedCLIVerificationKey = savedOrigin, savedKeys, savedCLIKey
	})
	config, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	settingsPath := filepath.Join(config, "enkv", "plugins.json")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0700); err != nil {
		t.Fatal(err)
	}
	source := configurationApplyPair(t, "aws", configuration.JSON, func(editable, generated map[string]any) {
		editable["entries"] = map[string]any{"generated": map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": map[string]any{"kind": "generated", "plugin": "private-token", "epoch": 0, "settings": map[string]any{}}}}
	})
	if err := os.WriteFile(settingsPath, []byte(`{"schema":"enkv/plugin-settings/v1","applications":[],"unexpected":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	result, err := PrepareConfiguration(ctx, PrepareRequest{Source: source.path, Format: configuration.JSON})
	if err == nil || result == nil {
		t.Fatal("invalid settings admitted", err)
	}
	facts := result.facts.Dependencies
	want := []PrepareDependencyRequirement{{Role: "generator", Subjects: []uint16{0}, Plugin: dependencyPluginName("private-token"), ProtocolVersion: 5, Status: "not-attempted", Reason: "settings-invalid"}}
	if facts.Assessment != "incomplete" || !facts.MinimumAdministrativeReady || facts.AllDeclaredReady || len(facts.Installations) != 0 || !reflect.DeepEqual(facts.Requirements, want) {
		t.Fatal("settings failure invented selection or erased independent readiness", result.facts, err)
	}
	record := prepareResultWire(t, result)
	failure, ok := record["dependencies"].(map[string]any)["settings_failure"].(map[string]any)
	if !ok || failure["stage"] != "settings" || failure["object"] != "plugins.json" || failure["path"] != settingsPath || failure["reason"] != "unknown-field" || failure["action"] != "correct-settings" {
		t.Fatal("shared settings facts lost", record)
	}
	if PrepareExitCode(result, nil) != 2 {
		t.Fatal("invalid content exit lost", PrepareExitCode(result, nil))
	}
	source.assertUnchanged(t)
}

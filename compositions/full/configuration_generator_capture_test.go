package compositionfull

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/compositions/full/plugininstallation"
	"enkv.sh/compositions/generatorhost"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/sdk/artifact"
	artifactbuild "enkv.sh/sdk/artifact/build"
	protocol "enkv.sh/sdk/protocols/generator"
)

// full_only: false
func TestCurrentGeneratorCaptureUsesDeclaredPublicLocalBuild(t *testing.T) {
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
	author := filepath.Join(docs, "plugins", "generators", "local-random-secret")
	output, home := t.TempDir(), t.TempDir()
	t.Cleanup(func() {
		for _, path := range []string{output, home} {
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
	modules := []struct{ name, directory string }{
		{"enkv.sh/sdk/artifact", filepath.Join(docs, "sdk", "artifact")},
		{"enkv.sh/sdk/generator", filepath.Join(docs, "sdk", "generator")},
		{"enkv.sh/sdk/protocols/generator", filepath.Join(docs, "sdk", "protocols", "generator")},
	}
	var work strings.Builder
	fmt.Fprintf(&work, "go 1.27.0\n\nuse (\n %q\n", filepath.ToSlash(author))
	for _, module := range modules {
		fmt.Fprintf(&work, " %q\n", filepath.ToSlash(module.directory))
	}
	work.WriteString(")\n\nreplace (\n")
	for _, module := range modules {
		fmt.Fprintf(&work, " %s v0.1.0 => %q\n", module.name, filepath.ToSlash(module.directory))
	}
	work.WriteString(")\n")
	workspace := filepath.Join(t.TempDir(), "go.work")
	if err := os.WriteFile(workspace, []byte(work.String()), 0600); err != nil {
		t.Fatal(err)
	}
	marker, err := artifactbuild.Run(ctx, artifactbuild.Config{Directory: author, Descriptor: "cmd/enkv-generator-local-random-secret/plugin.json", Command: "./cmd/enkv-generator-local-random-secret", Output: output, Workspace: workspace})
	if err != nil {
		t.Fatal("public local author fixture build failed", err)
	}
	build := filepath.Join(output, filepath.FromSlash(marker.Directory))
	metadata, err := os.ReadFile(filepath.Join(build, "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.ReadFile(filepath.Join(build, "plugin"))
	if err != nil {
		t.Fatal(err)
	}
	metadataSHA, executableSHA := sha256.Sum256(metadata), sha256.Sum256(executable)

	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("CLOUDFLARE_API_TOKEN", "invalid-must-not-be-read")
	savedOrigin, savedKeys, savedCLIKey, savedRedirects, savedRoots := installedPluginOrigin, installedPluginKeys, installedCLIVerificationKey, installedPluginRedirectHosts, installedPluginTLSRoots
	installedPluginOrigin = "https://127.0.0.1:1/releases/"
	installedCLIVerificationKey = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
	installedPluginKeys = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	installedPluginRedirectHosts, installedPluginTLSRoots = "", ""
	t.Cleanup(func() {
		installedPluginOrigin, installedPluginKeys, installedCLIVerificationKey, installedPluginRedirectHosts, installedPluginTLSRoots = savedOrigin, savedKeys, savedCLIKey, savedRedirects, savedRoots
	})
	edit := func(editable, _ map[string]any) {
		editable["plugins"] = map[string]any{"cloudflare-account-token": map[string]any{"version": "7.0.0"}, "local-random-secret": map[string]any{"version": "2.0.0"}}
		editable["entries"].(map[string]any)["local"] = map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": map[string]any{"kind": "generated", "plugin": "local-random-secret", "epoch": 0, "settings": map[string]any{}}}
	}
	source := configurationApplyPair(t, "aws", configuration.JSON, edit)
	model, err := configuration.Parse(ctx, source.pair)
	if err != nil {
		t.Fatal(err)
	}
	config, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	// No declared generation leaves both current selections dormant. The zero
	// control refuses before provider construction and credential resolution.
	empty := *model
	empty.Entries = nil
	if engine, err := configurationCurrentApplyOpener(source.pair, ApplyOptions{})(ctx, &empty, core.ApplyInstallation{}, nil); engine != nil || !errors.Is(err, ErrCell) {
		t.Fatal("empty desired source did not reach the control refusal", err)
	}
	if _, err := os.Stat(config); !os.IsNotExist(err) {
		t.Fatal("empty desired source captured a generator", err)
	}
	scope, err := filepath.EvalSymlinks(filepath.Dir(source.path))
	if err != nil {
		t.Fatal(err)
	}
	settings, err := artifact.EncodeSettings(artifact.Settings{Schema: "enkv/plugin-settings/v1", Applications: []artifact.Application{{Directory: scope, Plugins: []artifact.LocalPlugin{{Name: "local-random-secret", Directory: output}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(config, "enkv"), 0700); err != nil {
		t.Fatal(err)
	}
	settingsPath := filepath.Join(config, "enkv", "plugins.json")
	if err := os.WriteFile(settingsPath, settings, 0600); err != nil {
		t.Fatal(err)
	}
	// Only the declared local build must be captured before the same deliberate
	// control refusal. An unrelated CF release preference supplies no dependency.
	plugins, _, err := configurationNormalizePlugins(ctx, source.pair, source.pair, model)
	if err != nil {
		t.Fatal("local desired source did not capture its plugin", err)
	}
	if engine, err := configurationCurrentApplyOpener(source.pair, ApplyOptions{})(ctx, model, core.ApplyInstallation{}, plugins); engine != nil || !errors.Is(err, ErrCell) {
		t.Fatal("local desired source did not reach control refusal", err)
	}

	stored := filepath.Join(config, "enkv", "installation", "builds", hex.EncodeToString(metadataSHA[:]))
	actualMetadata, err := os.ReadFile(filepath.Join(stored, "metadata.json"))
	if err != nil || !bytes.Equal(actualMetadata, metadata) {
		t.Fatal("apply opener did not retain the exact public local build", err)
	}
	plugins, err = configurationAttachGeneratedPlugins(ctx, source.pair, model, plugins, nil)
	if err != nil {
		t.Fatal(err)
	}
	releaseConfigurationSource(model)
	if err := os.WriteFile(settingsPath, []byte("invalid settings"), 0600); err != nil {
		t.Fatal(err)
	}
	request := localGeneratorCaptureRequest(t)
	row, installation, path, err := configurationGeneratedInstalled(ctx, plugins, request)
	if err != nil || installation == nil || path != filepath.Join(stored, "plugin") || row.ConfigContractID != request.ConfigContractID || row.ArtifactSHA256 != contract.ID(executableSHA) || row.ArtifactLength != uint64(len(executable)) || row.DescriptorID.IsZero() || row.ExecutorID.IsZero() || row.CredentialRouteID.IsZero() {
		t.Fatal("local lookup did not bind the exact captured public build", row, path, err)
	}
	again, sameInstallation, samePath, err := configurationGeneratedInstalled(ctx, plugins, request)
	if err != nil || !reflect.DeepEqual(again, row) || sameInstallation == nil || samePath != path {
		t.Fatal("local current lookup repeated settings capture", err)
	}
	intent, err := protocol.EncodeIntent(protocol.Intent{Schema: protocol.Schema, ConfigContractID: protocol.ID(request.ConfigContractID), LifecycleMode: protocol.LifecycleNone, Settings: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	ready := configurationGeneratedCreateReadiness(plugins)
	if err := ready(ctx, request.EntryName, row, intent); err != nil {
		t.Fatal("fresh readiness lost the exact captured build after source release", err)
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	expired, stopExpired := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer stopExpired()
	for _, unavailable := range []struct {
		ctx   context.Context
		cause error
	}{{cancelled, context.Canceled}, {expired, context.DeadlineExceeded}} {
		if err := ready(unavailable.ctx, request.EntryName, row, intent); !errors.Is(err, unavailable.cause) || errors.Is(err, contract.ErrRecord) {
			t.Fatal("fresh readiness changed operational unavailability into semantic refusal", err)
		}
	}
	for _, field := range []string{"descriptor", "executor", "route", "artifact", "protocol", "module"} {
		changed := row
		switch field {
		case "descriptor":
			changed.DescriptorID[0] ^= 1
		case "executor":
			changed.ExecutorID[0] ^= 1
		case "route":
			changed.CredentialRouteID[0] ^= 1
		case "artifact":
			changed.ArtifactContractID[0] ^= 1
		case "protocol":
			changed.ProtocolID[0] ^= 1
		case "module":
			changed.Module += "/changed"
		}
		if err := ready(ctx, request.EntryName, changed, intent); !errors.Is(err, ErrCell) {
			t.Fatal("fresh readiness accepted a different selected build", field, err)
		}
	}
	changedIntent := bytes.Clone(intent)
	copy(changedIntent[len(changedIntent)-2:], []byte(`[]`))
	if err := ready(ctx, request.EntryName, row, changedIntent); !errors.Is(err, generatorhost.ErrPassiveRefused) || !errors.Is(err, contract.ErrRecord) {
		t.Fatal("fresh semantic refusal lacks the Core admission-refusal category", err)
	}
	cfRequest := request
	cfRequest.EntryName = "remote"
	if _, installation, path, err := configurationGeneratedInstalled(ctx, plugins, cfRequest); !errors.Is(err, ErrCell) || installation != nil || path != "" {
		t.Fatal("dormant unrelated preference acquired a generator", err)
	}

	mixed := configurationApplyPair(t, "aws", configuration.JSON, func(editable, generated map[string]any) {
		edit(editable, generated)
		editable["entries"].(map[string]any)["z-remote"] = map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": dependencyGeneratorSource(t, "0123456789abcdef0123456789abcdef")}
	})
	mixedModel, err := configuration.Parse(ctx, mixed.pair)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseConfigurationSource(mixedModel)
	var generatedNames []string
	for _, entry := range mixedModel.Entries {
		if entry.Generated != nil {
			generatedNames = append(generatedNames, entry.Name)
		}
	}
	if len(generatedNames) != 2 || generatedNames[0] != "local" || generatedNames[1] != "z-remote" {
		t.Fatal("mixed capture fixture does not put the local declaration first", generatedNames)
	}
	mixedScope, err := filepath.EvalSymlinks(filepath.Dir(mixed.path))
	if err != nil {
		t.Fatal(err)
	}
	mixedSettings, err := artifact.EncodeSettings(artifact.Settings{Schema: "enkv/plugin-settings/v1", Applications: []artifact.Application{{Directory: mixedScope, Plugins: []artifact.LocalPlugin{{Name: "local-random-secret", Directory: output}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, mixedSettings, 0600); err != nil {
		t.Fatal(err)
	}
	if captured, _, err := configurationNormalizePlugins(ctx, mixed.pair, mixed.pair, mixedModel); captured != nil || !errors.Is(err, plugininstallation.ErrMissing) {
		t.Fatal("mixed desired source ignored its later missing CF declaration", err)
	}
	source.assertUnchanged(t)
	mixed.assertUnchanged(t)
}

func localGeneratorCaptureRequest(t testing.TB) core.GeneratedImplementationRequest {
	t.Helper()
	request := core.GeneratedImplementationRequest{EntryName: "local", LifecycleMode: contract.GeneratorLifecycleNone}
	body, err := hex.DecodeString("663075a79a657cf8e281991deb3cbfac760eff6445ead7af60005dd27d9e0caa")
	if err != nil || len(body) != len(request.ConfigContractID) {
		t.Fatal("invalid independent local config ID", err)
	}
	copy(request.ConfigContractID[:], body)
	return request
}

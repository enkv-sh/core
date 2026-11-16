package core

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/sdk/artifact"
)

// Keep provider discovery selectors anchored to the original SDK context. Only
// the local application installation/settings owner uses the test-owned HOME.
func publicPluginEnvironment(t testing.TB, inv records.Invocation, input liveRunInput, role string, environment, args []string) ([]string, func()) {
	t.Helper()
	if len(input.PublicConfiguration.Artifact.Plugins) == 0 {
		return environment, func() {}
	}
	if len(input.Scenarios) != 1 {
		t.Fatal("public plugin case unavailable")
	}
	row, ok := catalog.PublicConfiguration(input.Scenarios[0])
	generated := row.Generated && slices.ContainsFunc(input.PublicConfiguration.Artifact.Plugins, func(build records.StockPluginBuild) bool {
		return build.Metadata.Role == "generator" && build.Metadata.Name == "cloudflare-account-token"
	})
	if !ok || !row.Output && !generated {
		return environment, func() {}
	}
	home, err := stockCreateSDKHome(filepath.Join(inv.StateDir, "public-plugin-homes"), role, input.PublicConfiguration.Actors[role])
	if err != nil {
		t.Fatal("public test-owned plugin home unavailable")
	}
	lock, err := os.OpenFile(filepath.Join(home, "plugins.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		t.Fatal("public plugin settings lock unavailable")
	}
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX) != nil {
		lock.Close()
		t.Fatal("public plugin settings lock failed")
	}
	unlock := func() {
		if lock.Close() != nil {
			t.Error("public plugin settings lock close failed")
		}
	}
	defer func() {
		if err != nil {
			unlock()
		}
	}()
	path := filepath.Join(stockConfigDirectory(home), "enkv", "plugins.json")
	settings := artifact.Settings{Schema: "enkv/plugin-settings/v1", Applications: []artifact.Application{}}
	if body, readErr := os.ReadFile(path); readErr == nil {
		settings, err = artifact.DecodeSettings(body)
	} else if !errors.Is(readErr, os.ErrNotExist) {
		err = readErr
	}
	if err != nil {
		t.Fatal("public existing plugin settings refused")
	}
	plugins := make([]artifact.LocalPlugin, len(input.PublicConfiguration.Artifact.Plugins))
	for i, build := range input.PublicConfiguration.Artifact.Plugins {
		plugins[i] = artifact.LocalPlugin{Name: build.Metadata.Name, Directory: build.Directory}
	}
	previous := settings.Applications
	settings.Applications = []artifact.Application{}
	for i := 0; i+1 < len(args); i++ {
		if args[i] != "--source" && args[i] != "--trusted" && args[i] != "--candidate" {
			continue
		}
		var directory string
		directory, err = filepath.EvalSymlinks(filepath.Dir(args[i+1]))
		if err != nil || !filepath.IsAbs(args[i+1]) {
			err = errInventory
			t.Fatal("public plugin application scope unavailable")
		}
		at := slices.IndexFunc(previous, func(a artifact.Application) bool { return a.Directory == directory })
		if at >= 0 {
			if !reflect.DeepEqual(previous[at].Plugins, plugins) {
				err = errInventory
				t.Fatal("public plugin application selection changed")
			}
		}
		if !slices.ContainsFunc(settings.Applications, func(a artifact.Application) bool { return a.Directory == directory }) {
			settings.Applications = append(settings.Applications, artifact.Application{Directory: directory, Plugins: plugins})
		}
	}
	slices.SortFunc(settings.Applications, func(a, b artifact.Application) int { return strings.Compare(a.Directory, b.Directory) })
	var body []byte
	body, err = artifact.EncodeSettings(settings)
	if err != nil {
		t.Fatal("public plugin application settings refused")
	}
	err = os.MkdirAll(filepath.Dir(path), 0700)
	if err == nil {
		err = os.WriteFile(path, body, 0600)
	}
	if err != nil {
		t.Fatal("public test-owned plugin settings unavailable")
	}
	return stockReplaceEnvironment(stockReplaceEnvironment(environment, "HOME", home), "XDG_CONFIG_HOME", filepath.Join(home, ".config")), unlock
}

// full_only: false
func TestPublicPluginHomePreservesSelectedSDKInputs(t *testing.T) {
	for _, cell := range []struct{ provider, mode string }{{"aws", "aws-sso"}, {"aws", "aws-assume-role"}, {"aws", "aws-shared-credentials"}, {"gcp", "gcp-user-adc"}, {"gcp", "gcp-impersonated-adc"}, {"gcp", "gcp-service-account-adc"}} {
		t.Run(cell.mode, func(t *testing.T) {
			original := t.TempDir()
			paths := []string{".config/gcloud"}
			if cell.provider == "aws" {
				paths = []string{".aws/config", ".aws/credentials"}
				if cell.mode == "aws-sso" {
					paths = append(paths, ".aws/sso")
				}
			}
			for _, name := range paths {
				path := filepath.Join(original, filepath.FromSlash(name))
				if strings.HasSuffix(name, "sso") || strings.HasSuffix(name, "gcloud") {
					if err := os.MkdirAll(path, 0700); err != nil {
						t.Fatal(err)
					}
					continue
				}
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("selected public fixture reference"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			actor := liveSettings{Provider: cell.provider, SDKHome: original, SDKMode: cell.mode, SDKProfile: "selected"}
			if cell.provider == "gcp" {
				actor.SDKProfile = ""
			}
			if cell.mode == "gcp-service-account-adc" {
				actor.SDKCredentialsFile = filepath.Join(original, "selected-adc.json")
				actor.SDKQuotaProject = "selected-quota"
				if err := os.RemoveAll(filepath.Join(original, ".config")); err != nil {
					t.Fatal(err)
				}
			}
			before := actor
			state := t.TempDir()
			application := t.TempDir()
			source := filepath.Join(application, "source.json")
			if err := os.WriteFile(source, []byte("literal pair fixture"), 0400); err != nil {
				t.Fatal(err)
			}
			environment, err := publicContext(actor).Environment(cell.provider, []string{"KEEP=literal", "HOME=must-not-be-used"}, filepath.Join(state, "absent-credentials"))
			if err != nil {
				t.Fatal(err)
			}
			input := liveRunInput{Scenarios: []string{"public-configuration.output-standalone/output_standalone"}, PublicConfiguration: &publicConfigurationInput{Actors: map[string]liveSettings{"apply": actor}, Artifact: publicProcessArtifact{PublicProcessArtifact: records.PublicProcessArtifact{Plugins: []records.StockPluginBuild{{Directory: t.TempDir(), Metadata: artifact.Metadata{Name: "aws-secrets-manager"}}}}}}}
			selected, release := publicPluginEnvironment(t, records.Invocation{StateDir: state}, input, "apply", environment, []string{"--source", source})
			release()
			home := filepath.Join(state, "public-plugin-homes", "apply")
			if actor != before || home == original {
				t.Fatal("plugin home changed selected SDK context")
			}
			for _, item := range environment {
				if strings.HasPrefix(item, "HOME=") || strings.HasPrefix(item, "XDG_CONFIG_HOME=") {
					continue
				}
				if !slices.Contains(selected, item) {
					t.Fatal("plugin application storage replaced an original SDK selector")
				}
			}
			if !slices.Contains(selected, "HOME="+home) || !slices.Contains(selected, "XDG_CONFIG_HOME="+filepath.Join(home, ".config")) {
				t.Fatal("plugin application storage lost its owned home")
			}
			var settings artifact.Settings
			body, err := os.ReadFile(filepath.Join(stockConfigDirectory(home), "enkv", "plugins.json"))
			if err != nil {
				t.Fatal(err)
			}
			settings, err = artifact.DecodeSettings(body)
			canonical, canonicalErr := filepath.EvalSymlinks(application)
			if err != nil || canonicalErr != nil || len(settings.Applications) != 1 || settings.Applications[0].Directory != canonical || len(settings.Applications[0].Plugins) != 1 {
				t.Fatal("plugin settings lost exact application scope")
			}
			for _, name := range paths {
				if cell.mode == "gcp-service-account-adc" {
					continue
				}
				path := filepath.Join(home, filepath.FromSlash(name))
				if target, err := os.Readlink(path); err != nil || target != filepath.Join(original, filepath.FromSlash(name)) {
					t.Fatal("plugin home lost exact selected SDK reference")
				}
			}
			if err := os.WriteFile(filepath.Join(home, "unexpected"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(original, "unexpected")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("plugin home wrote original SDK context")
			}
			if body, err := os.ReadFile(source); err != nil || string(body) != "literal pair fixture" {
				t.Fatal("plugin settings changed source bytes")
			}
		})
	}
}

// full_only: false
func TestPublicPluginHomeRefusesReplacedSDKReference(t *testing.T) {
	original, root := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(original, ".aws", "sso"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(original, ".aws", "config"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	actor := liveSettings{Provider: "aws", SDKMode: "aws-sso", SDKHome: original}
	home, err := stockCreateSDKHome(root, "apply", actor)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, ".aws", "config")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := stockCreateSDKHome(root, "apply", actor); err == nil {
		t.Fatal("plugin home accepted a replaced SDK reference")
	}
}

// full_only: false
func TestPublicPluginEnvironmentLeavesIndependentCasesUnchanged(t *testing.T) {
	for _, scenario := range []string{"public-configuration.credential-discovery/credential_discovery", "public-configuration.capacity-gc/bounded_manual_gc", "public-configuration.portable-validation/portable_validation"} {
		if row, ok := catalog.PublicConfiguration(scenario); !ok || row.Output {
			t.Fatal("independent case control is not current")
		}
		state := t.TempDir()
		environment := []string{"HOME=/selected/original", "XDG_CONFIG_HOME=/selected/original/.config", "AWS_CONFIG_FILE=/selected/original/.aws/config"}
		input := liveRunInput{Scenarios: []string{scenario}, PublicConfiguration: &publicConfigurationInput{Artifact: publicProcessArtifact{PublicProcessArtifact: records.PublicProcessArtifact{Plugins: []records.StockPluginBuild{{Metadata: artifact.Metadata{Name: "aws-secrets-manager"}}}}}}}
		selected, release := publicPluginEnvironment(t, records.Invocation{StateDir: state}, input, "apply", environment, nil)
		release()
		if !reflect.DeepEqual(selected, environment) {
			t.Fatal("independent case changed its credential environment")
		}
		if _, err := os.Stat(filepath.Join(state, "public-plugin-homes")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("independent case acquired plugin storage")
		}
	}
}

// full_only: false
func TestPublicGeneratedPluginHomeUsesCapturedBinding(t *testing.T) {
	original, state, application := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(original, ".aws"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(original, ".aws", "config"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(application, "source.json")
	if err := os.WriteFile(source, []byte("literal generated fixture"), 0400); err != nil {
		t.Fatal(err)
	}
	actor := liveSettings{Provider: "aws", SDKMode: "aws-assume-role", SDKHome: original, SDKProfile: "selected"}
	environment, err := publicContext(actor).Environment("aws", nil, filepath.Join(state, "absent"))
	if err != nil {
		t.Fatal(err)
	}
	input := liveRunInput{Scenarios: []string{"public-configuration.generated-manual-lifecycle/generated_manual_lifecycle"}, PublicConfiguration: &publicConfigurationInput{Actors: map[string]liveSettings{"apply": actor}, Artifact: publicProcessArtifact{PublicProcessArtifact: records.PublicProcessArtifact{Plugins: []records.StockPluginBuild{{Directory: t.TempDir(), Metadata: artifact.Metadata{Name: "cloudflare-account-token", Role: "generator"}}}}}}}
	selected, release := publicPluginEnvironment(t, records.Invocation{StateDir: state}, input, "apply", environment, []string{"--source", source})
	release()
	home := filepath.Join(state, "public-plugin-homes", "apply")
	if !slices.Contains(selected, "HOME="+home) {
		t.Fatal("generated caller lost its captured plugin application home")
	}
	for _, item := range environment {
		if !strings.HasPrefix(item, "HOME=") && !strings.HasPrefix(item, "XDG_CONFIG_HOME=") && !slices.Contains(selected, item) {
			t.Fatal("generated fixture changed an original SDK selector")
		}
	}
}

// full_only: false
func TestPublicPluginHomeKeepsOnlyCurrentCommandScopes(t *testing.T) {
	original, state := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(original, ".aws"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(original, ".aws", "config"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	actor := liveSettings{Provider: "aws", SDKMode: "aws-assume-role", SDKHome: original, SDKProfile: "selected"}
	plugins := []records.StockPluginBuild{{Directory: t.TempDir(), Metadata: artifact.Metadata{Name: "generic-json"}}}
	input := liveRunInput{Scenarios: []string{"public-configuration.manifest/atomic_public_file"}, PublicConfiguration: &publicConfigurationInput{Actors: map[string]liveSettings{"reader": actor}, Artifact: publicProcessArtifact{PublicProcessArtifact: records.PublicProcessArtifact{Plugins: plugins}}}}
	inv := records.Invocation{StateDir: state}
	home := filepath.Join(state, "public-plugin-homes", "reader")
	settingsPath := filepath.Join(stockConfigDirectory(home), "enkv", "plugins.json")
	environment, err := publicContext(actor).Environment("aws", nil, filepath.Join(state, "absent"))
	if err != nil {
		t.Fatal(err)
	}
	ephemeral := filepath.Join(state, "ephemeral")
	if err := os.Mkdir(ephemeral, 0700); err != nil {
		t.Fatal(err)
	}
	_, release := publicPluginEnvironment(t, inv, input, "reader", environment, []string{"--source", filepath.Join(ephemeral, "source.yaml")})
	release()
	if err := os.Remove(ephemeral); err != nil {
		t.Fatal(err)
	}
	current, trusted := t.TempDir(), t.TempDir()
	_, release = publicPluginEnvironment(t, inv, input, "reader", environment, []string{"--source", filepath.Join(current, "source.json"), "--trusted", filepath.Join(trusted, "source.json"), "--candidate", filepath.Join(current, "candidate.json")})
	release()
	var settings artifact.Settings
	if records.ReadJSON(settingsPath, &settings) != nil || len(settings.Applications) != 2 {
		t.Fatal("current command retained an expired application scope or repeated a selected scope")
	}
	want := []string{current, trusted}
	for i := range want {
		want[i], err = filepath.EvalSymlinks(want[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	slices.Sort(want)
	for i, application := range settings.Applications {
		if application.Directory != want[i] || !reflect.DeepEqual(application.Plugins, []artifact.LocalPlugin{{Name: "generic-json", Directory: plugins[0].Directory}}) {
			t.Fatal("current command changed its exact application or plugin selection")
		}
	}
	_, release = publicPluginEnvironment(t, inv, input, "reader", environment, nil)
	release()
	if records.ReadJSON(settingsPath, &settings) != nil || len(settings.Applications) != 0 {
		t.Fatal("command without a source retained unrelated application scopes")
	}
	canonicalCurrent, err := filepath.EvalSymlinks(current)
	if err != nil {
		t.Fatal(err)
	}
	settings.Applications = []artifact.Application{{Directory: canonicalCurrent, Plugins: []artifact.LocalPlugin{{Name: "generic-json", Directory: t.TempDir()}}}}
	body, err := artifact.EncodeSettings(settings)
	if err != nil || os.WriteFile(settingsPath, body, 0600) != nil {
		t.Fatal("changed selected plugin fixture unavailable", err)
	}
	var refusal any
	func() {
		defer func() { refusal = recover() }()
		_, release := publicPluginEnvironment(recoveryCustodyRefusalTB{TB: t}, inv, input, "reader", environment, []string{"--source", filepath.Join(current, "source.json")})
		release()
	}()
	if message, ok := refusal.(recoveryCustodyRefusal); !ok || string(message) != "public plugin application selection changed" {
		t.Fatal("changed selected plugin was not refused at its original boundary", refusal)
	}
	after, err := os.ReadFile(settingsPath)
	if err != nil || !bytes.Equal(after, body) {
		t.Fatal("refused selected plugin changed saved settings")
	}
}

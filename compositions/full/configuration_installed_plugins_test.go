package compositionfull

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/compositions/full/plugininstallation"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	manifest "enkv.sh/sdk/manifest-generator"
)

// full_only: false
func TestFreshGeneratorResolutionCannotUseRetirementOnlySelection(t *testing.T) {
	for _, current := range []bool{false, true} {
		t.Run(map[bool]string{false: "canonical-unset", true: "current-selected"}[current], func(t *testing.T) {
			model := &configuration.Model{Entries: []configuration.Entry{{Name: "token", Generated: &configuration.Generator{}}}}
			if current {
				model.Entries[0].Generated.Plugin = "private-generator"
			}
			plugins, err := configurationAttachGeneratedPlugins(t.Context(), nil, model, nil, map[string]string{"token": "private-generator"})
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			captureErr := errors.New("controlled exact installation capture")
			plugins.currentGenerator = func(name string) (*configurationInstalledPlugins, error) {
				if name != "private-generator" {
					t.Fatal("resolver changed explicit local plugin")
				}
				calls++
				return nil, captureErr
			}
			request := core.GeneratedImplementationRequest{EntryName: "token", ConfigContractID: contract.ID{69}, ResourceContractID: contract.ID{70}, LifecycleMode: contract.GeneratorLifecycleManaged}
			_, installed, path, err := configurationGeneratedInstalled(t.Context(), plugins, request)
			wantCalls := 0
			if current {
				wantCalls = 1
			}
			if err == nil || installed != nil || path != "" || calls != wantCalls || current && !errors.Is(err, captureErr) {
				t.Fatal("fresh creation used retirement-only installation selection", calls, err)
			}
			if !current && (!errors.Is(err, ErrCell) || !errors.Is(err, contract.ErrRecord)) || current && errors.Is(err, contract.ErrRecord) {
				t.Fatal("known source refusal and unavailable capture lost their distinct causes", err)
			}
		})
	}
}

// full_only: false
func TestPluginDistributionAssemblyKeepsTrustAtBuildTime(t *testing.T) {
	const origin = "https://enkv.sh/releases/"
	const cliKey = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
	const key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	assembly, err := configurationPluginAssembly(origin, key, cliKey, "assets.example.invalid", "")
	if err != nil || len(assembly.PluginKeys) != 1 || hex.EncodeToString(assembly.PluginKeys[0]) != key || assembly.Origin != origin || len(assembly.RedirectHosts) != 1 || assembly.RedirectHosts[0] != "assets.example.invalid" || assembly.TLSRoots != nil || assembly.Check == nil {
		t.Fatal("fixed production assembly differs", err)
	}
	for _, row := range []struct{ name, origin, keys, redirects, roots string }{
		{"missing-key", origin, "", "", ""},
		{"short-key", origin, "01", "", ""},
		{"uppercase-key", origin, strings.ToUpper(key), "", ""},
		{"duplicate-key", origin, key + "," + key, "", ""},
		{"empty-key-member", origin, key + ",", "", ""},
		{"key-whitespace", origin, key + " ", "", ""},
		{"http", "http://enkv.sh/releases/", key, "", ""},
		{"origin-credentials", "https://name@enkv.sh/releases/", key, "", ""},
		{"origin-query", origin + "?", key, "", ""},
		{"duplicate-host", origin, key, "assets.example.invalid,assets.example.invalid", ""},
		{"same-host", origin, key, "enkv.sh", ""},
		{"empty-host", origin, key, "assets.example.invalid,", ""},
		{"host-path", origin, key, "assets.example.invalid/path", ""},
		{"wildcard-host", origin, key, "*.example.invalid", ""},
		{"host-port-range", origin, key, "127.0.0.1:65536", ""},
		{"host-zero-port", origin, key, "127.0.0.1:0", ""},
		{"host-empty-port", origin, key, "127.0.0.1:", ""},
		{"host-whitespace", origin, key, "assets.example.invalid ", ""},
		{"production-custom-tls", origin, key, "", "YQ=="},
	} {
		t.Run(row.name, func(t *testing.T) {
			if _, err := configurationPluginAssembly(row.origin, row.keys, cliKey, row.redirects, row.roots); err == nil {
				t.Fatal("malformed assembly accepted")
			}
		})
	}

	for _, value := range []string{"", "01", strings.ToUpper(cliKey), key} {
		if _, err := configurationPluginAssembly(origin, key, value, "", ""); err == nil {
			t.Fatal("missing, malformed or shared CLI verification key accepted")
		}
	}
	if _, err := configurationPluginAssembly(origin, key+","+cliKey, cliKey, "", ""); err == nil {
		t.Fatal("retained plugin key reused CLI verification root")
	}
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	roots := base64.StdEncoding.EncodeToString(certificate)
	assembly, err = configurationPluginAssembly(server.URL+"/releases/", key, cliKey, "127.0.0.1:43443", roots)
	if err != nil || assembly.TLSRoots == nil || len(assembly.PluginKeys) != 1 {
		t.Fatal("controlled development assembly refused", err)
	}
	for _, damage := range [][]byte{
		append([]byte("ignored-prefix\n"), certificate...),
		append(append([]byte(nil), certificate...), []byte("ignored-suffix")...),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: server.Certificate().Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid-certificate")}),
	} {
		if _, err := configurationPluginAssembly(server.URL+"/releases/", key, cliKey, "", base64.StdEncoding.EncodeToString(damage)); err == nil {
			t.Fatal("partial or invalid certificate image accepted")
		}
	}
	if _, err := configurationPluginAssembly(server.URL+"/releases/", key, cliKey, "", roots+"\n"); err == nil {
		t.Fatal("noncanonical embedded base64 accepted")
	}
}

// full_only: false
func TestManifestPreparationRefusesWithoutCapturedSource(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, plugin := range []string{"generic-json", "opentofu-tfvars-json", "private-renderer"} {
		request, prepare, err := configurationCaptureManifest(ctx, nil, configurationPluginRequirement(nil, plugin), ManifestOptions{Plugin: plugin})
		if !errors.Is(err, plugininstallation.ErrInvalid) || prepare != nil || !request.Renderer.ArtifactID.IsZero() {
			t.Fatal("uncaptured source produced a renderer", err)
		}
	}
	if _, prepare, err := configurationCaptureManifest(ctx, nil, configurationPluginRequirement(nil, "generic-json"), ManifestOptions{Plugin: "../unknown"}); err == nil || prepare != nil {
		t.Fatal("invalid plugin ID reached dependency capture", err)
	}
	cancel()
	if failure := configurationManifestPreparationFailure(ctx); failure != manifest.Cancelled {
		t.Fatal("cancelled preparation lost its closed result", failure)
	}
	expired, stop := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer stop()
	if failure := configurationManifestPreparationFailure(expired); failure != manifest.Expired {
		t.Fatal("expired preparation lost its closed result", failure)
	}

}

// full_only: false
func TestCurrentGeneratorCaptureKeepsItsBorrowedSourcePair(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("CLOUDFLARE_API_TOKEN", "invalid-must-not-be-captured")
	savedOrigin, savedKeys, savedCLIKey, savedRedirects, savedRoots := installedPluginOrigin, installedPluginKeys, installedCLIVerificationKey, installedPluginRedirectHosts, installedPluginTLSRoots
	installedPluginOrigin = "https://127.0.0.1:1/releases/"
	installedCLIVerificationKey = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
	installedPluginKeys = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	installedPluginRedirectHosts, installedPluginTLSRoots = "", ""
	t.Cleanup(func() {
		installedPluginOrigin, installedPluginKeys, installedCLIVerificationKey, installedPluginRedirectHosts, installedPluginTLSRoots = savedOrigin, savedKeys, savedCLIKey, savedRedirects, savedRoots
	})
	source := configurationReaderPair(t, "aws", configuration.JSON, func(editable, _ map[string]any) {
		editable["plugins"] = map[string]any{"cloudflare-account-token": map[string]any{"version": "1.0.0"}, "local-random-secret": map[string]any{"version": "2.0.0"}}
	})
	other := configurationReaderPair(t, "aws", configuration.JSON, nil)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	model, err := configuration.Parse(ctx, source.pair)
	if err != nil {
		t.Fatal(err)
	}
	requirement := configurationPluginRequirement(model, "cloudflare-account-token")
	local := configurationPluginRequirement(model, "local-random-secret")
	model.Entries = []configuration.Entry{{Name: "remote", Generated: &configuration.Generator{Plugin: "cloudflare-account-token"}}, {Name: "local", Generated: &configuration.Generator{Plugin: "local-random-secret"}}}
	plugins, err := configurationAttachGeneratedPlugins(ctx, source.pair, model, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	releaseConfigurationSource(model)
	if requirement.Name != "cloudflare-account-token" || requirement.Version != "1.0.0" || local.Name != "local-random-secret" || local.Version != "2.0.0" {
		t.Fatal("current selection lost the owned source preference", requirement)
	}
	directory, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatal("lazy owner created coordinator storage", err)
	}
	if err := os.Chmod(other.path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other.path, append(append([]byte(nil), other.editableBytes...), byte('\n')), 0600); err != nil {
		t.Fatal(err)
	}
	requests := []core.GeneratedImplementationRequest{localGeneratorCaptureRequest(t), localGeneratorCaptureRequest(t)}
	requests[0].EntryName = "remote"

	for _, request := range requests {
		if _, installed, path, err := configurationGeneratedInstalled(ctx, plugins, request); !errors.Is(err, plugininstallation.ErrMissing) || errors.Is(err, plugininstallation.ErrSourceChanged) || installed != nil || path != "" {
			t.Fatal("current capture used a different pair or acquired missing support", request.EntryName, err)
		}
	}
	// Source refusal must precede reading even malformed current settings.
	if err := os.WriteFile(filepath.Join(directory, "enkv", "plugins.json"), []byte("invalid settings"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(source.path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source.path, append(append([]byte(nil), source.editableBytes...), byte('\n')), 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := configurationAttachGeneratedPlugins(ctx, source.pair, &configuration.Model{Entries: []configuration.Entry{{Name: "remote", Generated: &configuration.Generator{Plugin: "cloudflare-account-token"}}, {Name: "local", Generated: &configuration.Generator{Plugin: "local-random-secret"}}}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range requests {
		if _, installed, path, err := configurationGeneratedInstalled(ctx, changed, request); !errors.Is(err, plugininstallation.ErrSourceChanged) || installed != nil || path != "" {
			t.Fatal("changed borrowed source reached settings or acquired support", request.EntryName, err)
		}
	}
	desired := &configuration.Model{Resolved: true, Entries: []configuration.Entry{{Name: "local", Generated: &configuration.Generator{Plugin: "local-random-secret", Settings: []byte(`{}`)}}}}
	if installed, _, err := configurationNormalizePlugins(ctx, source.pair, source.pair, desired); !errors.Is(err, configuration.ErrSourceChanged) || installed != nil {
		t.Fatal("desired generated selection lost source refusal before credentials", err)
	}
}

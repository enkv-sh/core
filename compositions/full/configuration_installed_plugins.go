package compositionfull

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"enkv.sh/compositions/configuration"
	"enkv.sh/compositions/full/plugininstallation"
	"enkv.sh/compositions/generatorhost"
	"enkv.sh/compositions/manifesthost"
	"enkv.sh/compositions/outputhost"
	"enkv.sh/core/contract"
	"enkv.sh/sdk/artifact"
	manifest "enkv.sh/sdk/manifest-generator"
)

// Distribution recipes set these at link time. Source builds have no implicit
// signing authority; ordinary configuration and environment cannot replace it.
var (
	installedPluginOrigin        = "https://enkv.sh/releases/"
	installedPluginKeys          string
	installedCLIVerificationKey  string
	installedPluginRedirectHosts string
	installedPluginTLSRoots      string
)

type configurationInstalledPlugins struct {
	session           *plugininstallation.Session
	coordinator       *plugininstallation.Coordinator
	generatorPlugins  map[string]string
	retirementPlugins map[string]string
	currentGenerator  func(string) (*configurationInstalledPlugins, error)
}

// configurationAttachGeneratedPlugins keeps local selection separate from the
// canonical intent and reuses builds already captured for normalization.
func configurationAttachGeneratedPlugins(ctx context.Context, pair *configuration.Pair, model *configuration.Model, captured *configurationInstalledPlugins, retirement map[string]string) (*configurationInstalledPlugins, error) {
	if len(retirement) > contract.GeneratedCurrentEntryLimit || model != nil && len(model.Entries) > contract.CryptoMaxValueEntries {
		return nil, ErrCell
	}
	current := make(map[string]string)
	selected := make(map[string]plugininstallation.Requirement)
	if model != nil {
		for _, entry := range model.Entries {
			if entry.Generated == nil {
				continue
			}
			name, plugin := strings.Clone(entry.Name), strings.Clone(entry.Generated.Plugin)
			if _, exists := current[name]; exists || len(current) >= contract.GeneratedCurrentEntryLimit || len(name) > contract.CryptoMaxName || !utf8.ValidString(name) || plugin != "" && !artifact.ValidPluginID(plugin) {
				return nil, ErrCell
			}
			current[name] = plugin
			if plugin == "" {
				continue
			}
			if _, exists := selected[plugin]; !exists && len(selected) >= configurationSelectionLimit {
				return nil, ErrCell
			}
			selected[plugin] = configurationPluginRequirement(model, plugin)
		}
	}
	old := make(map[string]string, len(retirement))
	for entry, plugin := range retirement {
		if len(entry) > contract.CryptoMaxName || !utf8.ValidString(entry) || !artifact.ValidPluginID(plugin) {
			return nil, ErrCell
		}
		if active, exists := current[entry]; exists && active != "" && active != plugin {
			return nil, ErrCell
		}
		name, plugin := strings.Clone(entry), strings.Clone(plugin)
		if _, exists := selected[plugin]; !exists && len(selected) >= configurationSelectionLimit {
			return nil, ErrCell
		}
		old[name] = plugin
		selected[plugin] = configurationPluginRequirement(model, plugin)
	}
	if captured == nil {
		captured = &configurationInstalledPlugins{}
	}
	captures := make(map[string]func() (*configurationInstalledPlugins, error), len(selected))
	for plugin, requirement := range selected {
		requirement.Name, requirement.Version = strings.Clone(requirement.Name), strings.Clone(requirement.Version)
		captures[plugin] = func() (*configurationInstalledPlugins, error) {
			if _, ok := captured.lookup(requirement.Name); ok {
				return captured, nil
			}
			plugins, _, err := configurationCapturePlugins(ctx, pair, []plugininstallation.Requirement{requirement}, plugininstallation.Ordinary)
			return plugins, err
		}
	}
	captured.generatorPlugins, captured.retirementPlugins = current, old
	captured.currentGenerator = configurationLazyCurrentGenerator(captures)
	return captured, nil
}

// Capture each fresh-work selection once. Accepted continuations bypass this
// map and resolve their exact retained support instead.
func configurationLazyCurrentGenerator(captures map[string]func() (*configurationInstalledPlugins, error)) func(string) (*configurationInstalledPlugins, error) {
	cached := make(map[string]func() (*configurationInstalledPlugins, error), len(captures))
	for name, capture := range captures {
		cached[strings.Clone(name)] = sync.OnceValues(capture)
	}
	return func(name string) (*configurationInstalledPlugins, error) {
		capture := cached[name]
		if capture == nil {
			return nil, ErrCell
		}
		return capture()
	}
}

func (p *configurationInstalledPlugins) generatorPlugin(entry string) (string, error) {
	if p == nil {
		return "", ErrCell
	}
	current, present := p.generatorPlugins[entry]
	old := p.retirementPlugins[entry]
	if present {
		if current == "" || old != "" && current != old {
			return "", errors.Join(ErrCell, contract.ErrRecord)
		}
		return current, nil
	}
	if old != "" {
		return old, nil
	}
	return "", errors.Join(ErrCell, contract.ErrRecord)
}

func (p *configurationInstalledPlugins) lookup(name string) (*plugininstallation.Installed, bool) {
	if p == nil || p.session == nil {
		return nil, false
	}
	return p.session.Lookup(name)
}

func configurationRetainedPlugins() (*configurationInstalledPlugins, error) {
	assembly, err := configurationPluginAssembly(installedPluginOrigin, installedPluginKeys, installedCLIVerificationKey, installedPluginRedirectHosts, installedPluginTLSRoots)
	if err != nil {
		return nil, err
	}
	coordinator, err := plugininstallation.New(assembly)
	if err != nil {
		return nil, err
	}
	return &configurationInstalledPlugins{coordinator: coordinator}, nil
}

func configurationCapturePlugins(ctx context.Context, pair *configuration.Pair, requirements []plugininstallation.Requirement, mode plugininstallation.Mode) (*configurationInstalledPlugins, []plugininstallation.Installation, error) {
	if pair == nil {
		return nil, nil, plugininstallation.ErrInvalid
	}
	return configurationCapturePluginsWithSourceCheck(ctx, pair, requirements, mode, pair.CheckUnchanged)
}

// The trusted pair selects installation scope; checkSource retains the source's
// actual lock owner when maintenance already holds the source and output locks.
func configurationCapturePluginsWithSourceCheck(ctx context.Context, pair *configuration.Pair, requirements []plugininstallation.Requirement, mode plugininstallation.Mode, checkSource func(context.Context) error) (*configurationInstalledPlugins, []plugininstallation.Installation, error) {
	if ctx == nil || pair == nil || pair.Editable == nil || checkSource == nil {
		return nil, nil, plugininstallation.ErrInvalid
	}
	if err := checkSource(ctx); err != nil {
		return nil, nil, errors.Join(plugininstallation.ErrSourceChanged, err)
	}
	directory, err := filepath.EvalSymlinks(filepath.Dir(pair.Editable.OriginalPath()))
	if err != nil {
		return nil, nil, err
	}
	plugins, err := configurationRetainedPlugins()
	if err != nil {
		return nil, nil, err
	}
	var rows []plugininstallation.Installation
	plugins.session, rows, err = plugins.coordinator.Resolve(ctx, plugininstallation.Request{
		Directory: directory, Requirements: requirements, Mode: mode, CheckSource: checkSource,
	})
	if err != nil && (mode == plugininstallation.Ordinary || plugins.session == nil) {
		return nil, rows, err
	}
	return plugins, rows, err
}

// Capture settings and rendering from the same measured build. The returned
// closure rejects any different selection rather than resolving current settings
// or another executable after Reader admission.
func configurationCaptureManifest(ctx context.Context, pair *configuration.Pair, requirement plugininstallation.Requirement, options ManifestOptions) (contract.ManifestRequest, func(context.Context, contract.ManifestRendererSelection) (manifest.Renderer, manifest.Failure), error) {
	if ctx == nil || requirement.Name != options.Plugin || !artifact.ValidPluginID(options.Plugin) {
		return contract.ManifestRequest{}, nil, contract.ErrRecord
	}
	plugins, _, err := configurationCapturePlugins(ctx, pair, []plugininstallation.Requirement{requirement}, plugininstallation.Ordinary)
	if err != nil {
		return contract.ManifestRequest{}, nil, err
	}
	installed, ok := plugins.lookup(requirement.Name)
	if !ok {
		return contract.ManifestRequest{}, nil, contract.ErrRecord
	}
	metadata, err := installed.Metadata()
	if err != nil {
		return contract.ManifestRequest{}, nil, err
	}
	facts, err := metadata.ManifestFacts()
	if err != nil {
		return contract.ManifestRequest{}, nil, err
	}
	protocolID, err := artifact.ParseDigest(facts.Descriptor.Wire.Identity)
	if err != nil {
		return contract.ManifestRequest{}, nil, err
	}
	native, err := manifesthost.NewNative(ctx, installed.Executable(), metadata, installed.DependencyBytes())
	if err != nil {
		return contract.ManifestRequest{}, nil, err
	}
	settings := native.ValidateSettings(ctx, manifest.SettingsRequest{
		FormatContractID: facts.Descriptor.Manifest.FormatContractID,
		ConfigContractID: facts.Descriptor.Manifest.ConfigContractID,
		Settings:         options.Settings,
	})
	defer clear(settings.Settings)
	if settings.Failure != "" {
		reason := contract.ReasonInvalidInput
		switch settings.Failure {
		case manifest.InvalidUTF8:
			reason = contract.ReasonInvalidUTF8
		case manifest.LimitExceeded:
			reason = contract.ReasonLimitExceeded
		case manifest.Cancelled:
			reason = contract.ReasonCancelled
		case manifest.Expired:
			reason = contract.ReasonExpired
		}
		return contract.ManifestRequest{}, nil, contract.ManifestRequestError{Reason: reason}
	}
	if err := pair.CheckUnchanged(ctx); err != nil {
		return contract.ManifestRequest{}, nil, err
	}
	selection := contract.ManifestRendererSelection{
		Name: metadata.Name, Version: metadata.Version, ProtocolID: contract.ID(protocolID),
		DescriptorID: contract.ID(facts.DescriptorID), ExecutorID: contract.ID(facts.ExecutorID),
		ArtifactContractID: contract.ID(facts.ArtifactContractID), DependencyManifestID: contract.ID(facts.DependencyManifestID),
		ArtifactID: contract.ID(installed.Identity()), ArtifactSHA256: contract.ID(facts.ArtifactSHA256), ArtifactLength: facts.ArtifactLength,
	}
	request, err := contract.OwnManifestRequest(contract.ManifestRequest{
		Renderer: selection, FormatContractID: facts.Descriptor.Manifest.FormatContractID,
		ConfigContractID: facts.Descriptor.Manifest.ConfigContractID, Settings: settings.Settings,
		TargetMode: options.TargetMode, EntryMode: options.EntryMode, TargetRecipientID: options.TargetRecipientID,
		EntryNames: options.EntryNames, ServiceFilter: options.ServiceFilter,
	})
	if err != nil {
		return contract.ManifestRequest{}, nil, err
	}
	prepare := func(ctx context.Context, selected contract.ManifestRendererSelection) (manifest.Renderer, manifest.Failure) {
		if ctx == nil || ctx.Err() != nil {
			return nil, configurationManifestPreparationFailure(ctx)
		}
		if selected != selection {
			return nil, manifest.InvalidInput
		}
		return native.Render, ""
	}
	return request, prepare, nil
}

func configurationManifestPreparationFailure(ctx context.Context) manifest.Failure {
	if ctx != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return manifest.Expired
		}
		if ctx.Err() != nil {
			return manifest.Cancelled
		}
	}
	return manifest.InvalidResult
}

func configurationPluginCheck(ctx context.Context, metadata artifact.Metadata, dependency []byte) error {
	if ctx == nil {
		return plugininstallation.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var err error
	switch metadata.Role {
	case "generator":
		err = generatorhost.ValidateInstallation(metadata, dependency)
		if errors.Is(err, generatorhost.ErrArtifactIncompatible) {
			return plugininstallation.ErrIncompatible
		}
	case "output":
		err = outputhost.ValidateInstallation(metadata, dependency)
		if errors.Is(err, outputhost.ErrArtifactIncompatible) {
			return plugininstallation.ErrIncompatible
		}
	case "manifest-generator":
		err = manifesthost.Check(ctx, metadata, dependency)
		if err == manifesthost.ErrUnsupported {
			return plugininstallation.ErrIncompatible
		}
	default:
		return plugininstallation.ErrInvalid
	}
	return err
}

func configurationPluginAssembly(origin, keys, cliKey, redirects, roots string) (plugininstallation.Assembly, error) {
	assembly := plugininstallation.Assembly{Origin: origin, Check: configurationPluginCheck}
	if len(origin) > 4096 || len(keys) > 4096 || len(cliKey) > 64 || len(redirects) > 4096 || len(roots) > 128*1024 {
		return assembly, plugininstallation.ErrInvalid
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "https" || !pluginDistributionHost(parsed.Host) || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawPath != "" || !strings.HasSuffix(parsed.Path, "/") {
		return assembly, plugininstallation.ErrInvalid
	}
	cli, err := hex.DecodeString(cliKey)
	if err != nil || len(cli) != ed25519.PublicKeySize || hex.EncodeToString(cli) != cliKey {
		return assembly, plugininstallation.ErrInvalid
	}
	seen := map[string]bool{}
	for _, text := range strings.Split(keys, ",") {
		key, err := hex.DecodeString(text)
		if err != nil || len(key) != ed25519.PublicKeySize || hex.EncodeToString(key) != text || seen[text] || text == cliKey {
			return assembly, plugininstallation.ErrInvalid
		}
		seen[text] = true
		assembly.PluginKeys = append(assembly.PluginKeys, ed25519.PublicKey(key))
	}
	seen = map[string]bool{parsed.Host: true}
	if redirects != "" {
		for _, host := range strings.Split(redirects, ",") {
			if !pluginDistributionHost(host) || seen[host] {
				return assembly, plugininstallation.ErrInvalid
			}
			seen[host] = true
			assembly.RedirectHosts = append(assembly.RedirectHosts, host)
		}
	}
	if roots != "" {
		ip := net.ParseIP(parsed.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return assembly, plugininstallation.ErrInvalid
		}
		body, err := base64.StdEncoding.Strict().DecodeString(roots)
		if err != nil || base64.StdEncoding.EncodeToString(body) != roots || len(body) == 0 {
			return assembly, plugininstallation.ErrInvalid
		}
		pool := x509.NewCertPool()
		for len(body) != 0 {
			if !strings.HasPrefix(string(body), "-----BEGIN CERTIFICATE-----\n") {
				return assembly, plugininstallation.ErrInvalid
			}
			block, rest := pem.Decode(body)
			if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				return assembly, plugininstallation.ErrInvalid
			}
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return assembly, plugininstallation.ErrInvalid
			}
			pool.AddCert(certificate)
			body = rest
		}
		assembly.TLSRoots = pool
	}
	return assembly, nil
}

func pluginDistributionHost(host string) bool {
	parsed, err := url.Parse("https://" + host)
	if err != nil || host == "" || parsed.Host != host || parsed.Hostname() == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.ContainsAny(host, "*%\\ \t\r\n") {
		return false
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 || strconv.FormatUint(value, 10) != port {
			return false
		}
	} else if strings.HasSuffix(host, ":") {
		return false
	}
	return true
}

package main

import (
	"context"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"strings"

	"enkv.sh/compositions/generatorhost"
	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
	"enkv.sh/sdk/artifact"
)

func scheduleNeedsPublicConfiguration(schedule catalog.Schedule) bool {
	for _, name := range schedule.Selected {
		if catalog.HasFixtureCapability(name, catalog.FixturePublicConfiguration) {
			return true
		}
	}
	return false
}

type publicConfigurationArtifact records.PublicProcessArtifact

func publicConfigurationBuildArgs(output, overlay string, race bool) []string {
	return compilerBuildFlags([]string{"build", "-mod=readonly", "-tags=netgo", "-trimpath", "-buildvcs=false", "-overlay=" + overlay, "-ldflags=" + publicConfigurationPluginTrust, "-o", output}, race)
}

// These public fixture keys admit explicit local builds. No release is acquired.
const publicConfigurationPluginTrust = "-X=enkv.sh/compositions/full.installedCLIVerificationKey=3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c -X=enkv.sh/compositions/full.installedPluginKeys=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a -X=enkv.sh/compositions/full.installedPluginOrigin=https://127.0.0.1:1/releases/"

const publicProcessSourceDirectory = "tests/live/publicprocess"
const publicProcessBuildDirectory = "compositions/full"

func buildPublicConfigurationArtifact(ctx context.Context, root, build string, outputs []*outputArtifactClosure, binding ...*cloudflareAssemblyBinding) (publicConfigurationArtifact, error) {
	if len(binding) > 1 {
		return publicConfigurationArtifact{}, errors.New("public generator binding refused")
	}
	if len(outputs) != 0 {
		if err := validateOutputArtifactClosures(outputs); err != nil {
			return publicConfigurationArtifact{}, err
		}
	}
	var generator *cloudflareAssemblyBinding
	var generatorMetadata *artifact.Metadata
	recipe := struct {
		Generated                            bool
		ArtifactSHA256, DependencyManifest   string
		ArtifactLength                       int64
		InstallationSHA256, DependencySHA256 string
	}{}
	if len(binding) == 1 && binding[0] != nil {
		captured := *binding[0]
		generator = &captured
		if len(generator.ArtifactSHA256) != 64 || generator.ArtifactLength <= 0 || len(generator.DependencyManifest) != 64 {
			return publicConfigurationArtifact{}, errors.New("public generator binding refused")
		}
		metadata, err := publicGeneratorMetadata(generator)
		if err != nil {
			return publicConfigurationArtifact{}, err
		}
		generatorMetadata = &metadata
		recipe.Generated, recipe.ArtifactSHA256, recipe.DependencyManifest, recipe.ArtifactLength = true, generator.ArtifactSHA256, generator.DependencyManifest, generator.ArtifactLength
		recipe.InstallationSHA256, recipe.DependencySHA256 = digestBytes(generator.Installation), digestBytes(generator.Dependency)
	}
	value, _, err := invocationArtifactValue(ctx, root, build, "public-configuration", recipe, func(directory string) (publicConfigurationArtifact, error) {
		if generator != nil && generator.artifactPath != "" {
			if err := linkInvocationFile(generator.artifactPath, filepath.Join(directory, "enkv-generator-cloudflare")); err != nil {
				return publicConfigurationArtifact{}, err
			}
		}
		return constructPublicConfigurationArtifact(ctx, root, directory, generator, generatorMetadata)
	})
	return value, err
}

func publicGeneratorMetadata(binding *cloudflareAssemblyBinding) (artifact.Metadata, error) {
	var envelope struct {
		Artifact contract.GeneratorImplementation
		Metadata json.RawMessage
	}
	refused := errors.New("public captured generator installation refused")
	if binding == nil || len(binding.Installation) == 0 || len(binding.Installation) > artifact.MaxMetadataBytes || len(binding.Dependency) == 0 || len(binding.Dependency) > artifact.MaxDependencyBytes || json.Unmarshal(binding.Installation, &envelope) != nil {
		return artifact.Metadata{}, refused
	}
	metadata, err := artifact.DecodeMetadata(envelope.Metadata)
	if err != nil || metadata.Name != "cloudflare-account-token" || metadata.Role != "generator" {
		return artifact.Metadata{}, refused
	}
	installed, err := generatorhost.NewInstallation(metadata, binding.Dependency)
	if err != nil {
		return artifact.Metadata{}, refused
	}
	row := installed.Artifact()
	if !reflect.DeepEqual(row, envelope.Artifact) || hex.EncodeToString(row.ArtifactSHA256[:]) != binding.ArtifactSHA256 || row.ArtifactLength != uint64(binding.ArtifactLength) || hex.EncodeToString(row.DependencyManifestID[:]) != binding.DependencyManifest {
		return artifact.Metadata{}, refused
	}
	return metadata, nil
}

func constructPublicConfigurationArtifact(ctx context.Context, root, build string, generator *cloudflareAssemblyBinding, generatorMetadata *artifact.Metadata) (publicConfigurationArtifact, error) {
	overlay, err := nativeprocess.BuildOverlay(root, filepath.Join(build, "public-configuration-overlay"))
	if err != nil {
		return publicConfigurationArtifact{}, err
	}
	result := publicConfigurationArtifact{Race: raceSetting(raceEnabled(ctx)), CLI: filepath.Join(build, "enkv-public"), Consumer: filepath.Join(build, "enkv-public-reconstruct"), Overlay: overlay}
	if generator != nil {
		result.Overlay, err = nativeprocess.AddGeneratedLedgerOverlay(root, overlay)
		if err != nil {
			return publicConfigurationArtifact{}, err
		}
		overlay = result.Overlay
		result.GeneratorArtifact, result.GeneratorSHA256, result.GeneratorLength, result.GeneratorManifest = filepath.Join(build, "enkv-generator-cloudflare"), generator.ArtifactSHA256, generator.ArtifactLength, generator.DependencyManifest
		digest, length, err := cloudflareArtifactIdentity(result.GeneratorArtifact)
		if err != nil || hex.EncodeToString(digest[:]) != result.GeneratorSHA256 || length != result.GeneratorLength {
			return publicConfigurationArtifact{}, errors.New("public generator artifact differs")
		}
		if generatorMetadata == nil {
			return publicConfigurationArtifact{}, errors.New("public captured generator metadata missing")
		}
		folder := filepath.Join(build, "public-plugins", generatorMetadata.Name)
		if _, err := artifact.PublishBuild(ctx, folder, *generatorMetadata, result.GeneratorArtifact, generator.Dependency); err != nil {
			return publicConfigurationArtifact{}, err
		}
		result.Plugins = []records.StockPluginBuild{{Directory: folder, Metadata: *generatorMetadata}}
	}
	cli := publicConfigurationBuildArgs(result.CLI, overlay.Path, *result.Race)
	cli = append(cli, "./cmd/enkv")
	if _, err = runGo(ctx, root, publicProcessBuildDirectory, cli...); err != nil {
		return publicConfigurationArtifact{}, err
	}
	if err := buildPublicProcessConsumer(ctx, root, result.Consumer, overlay, *result.Race); err != nil {
		return publicConfigurationArtifact{}, err
	}
	for _, path := range []string{result.CLI, result.Consumer} {
		observed, raceErr := binaryRace(path)
		if raceErr != nil || observed != *result.Race {
			return publicConfigurationArtifact{}, errors.Join(raceErr, errors.New("public executable race policy differs"))
		}
		if err = os.Chmod(path, 0700); err != nil {
			return publicConfigurationArtifact{}, err
		}
	}
	result.CLISHA256, err = assemblyFileSHA256(result.CLI)
	if err != nil {
		return publicConfigurationArtifact{}, err
	}
	result.ConsumerSHA256, err = assemblyFileSHA256(result.Consumer)
	if err != nil {
		return publicConfigurationArtifact{}, err
	}
	return result, nil
}
func (a publicConfigurationArtifact) valid() bool {
	if !records.PublicProcessArtifact(a).ValidatePlugins(context.Background(), filepath.Dir(a.CLI)) {
		return false
	}
	if a.GeneratorArtifact != "" {
		digest, length, err := cloudflareArtifactIdentity(a.GeneratorArtifact)
		if a.GeneratorArtifact != filepath.Join(filepath.Dir(a.CLI), "enkv-generator-cloudflare") || err != nil || hex.EncodeToString(digest[:]) != a.GeneratorSHA256 || length != a.GeneratorLength || len(a.GeneratorManifest) != 64 || !publicGeneratorBuildProfileValid(a.CLI, a.Race == nil || *a.Race) {
			return false
		}
	} else if a.GeneratorSHA256 != "" || a.GeneratorLength != 0 || a.GeneratorManifest != "" {
		return false
	}
	for _, item := range []struct{ path, sha string }{{a.CLI, a.CLISHA256}, {a.Consumer, a.ConsumerSHA256}} {
		if !filepath.IsAbs(item.path) || len(item.sha) != 64 {
			return false
		}
		info, err := os.Lstat(item.path)
		if err != nil || !info.Mode().IsRegular() {
			return false
		}
		current, err := assemblyFileSHA256(item.path)
		if err != nil || current != item.sha {
			return false
		}
	}
	for _, path := range []string{a.CLI, a.Consumer} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm()&0111 == 0 {
			return false
		}
	}
	return publicProcessOverlaySourcesValid(context.Background(), a.Overlay)
}

func publicProcessOverlaySourcesValid(ctx context.Context, overlay nativeprocess.Overlay) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	var mapping struct{ Replace map[string]string }
	var sources []nativeprocess.Source
	body, _, err := readPublicConfigurationFileContext(ctx, overlay.Path, records.MaximumJSONBytes, 0600)
	if err != nil || digestBytes(body) != overlay.SHA256 || json.Unmarshal(body, &mapping) != nil || len(mapping.Replace) == 0 || ctx.Err() != nil {
		return false
	}
	body, _, err = readPublicConfigurationFileContext(ctx, overlay.Manifest, records.MaximumJSONBytes, 0600)
	if err != nil || digestBytes(body) != overlay.ManifestSHA256 || json.Unmarshal(body, &sources) != nil || len(sources) != len(mapping.Replace) || ctx.Err() != nil {
		return false
	}
	seen := map[string]bool{}
	for _, source := range sources {
		if ctx.Err() != nil || !filepath.IsAbs(source.Target) || !filepath.IsAbs(source.Replacement) || seen[source.Target] || mapping.Replace[source.Target] != source.Replacement {
			return false
		}
		seen[source.Target] = true
		info, err := os.Lstat(source.Target)
		original := digestBytes(nil)
		if err == nil {
			body, _, readErr := readPublicConfigurationFileContext(ctx, source.Target, records.MaximumJSONBytes, info.Mode().Perm())
			if readErr != nil {
				return false
			}
			original = digestBytes(body)
		} else if !errors.Is(err, os.ErrNotExist) {
			return false
		}
		if original != source.OriginalSHA256 {
			return false
		}
		info, err = os.Lstat(source.Replacement)
		if err != nil {
			return false
		}
		body, _, err := readPublicConfigurationFileContext(ctx, source.Replacement, records.MaximumJSONBytes, info.Mode().Perm())
		if err != nil || digestBytes(body) != source.ReplacementSHA256 {
			return false
		}
	}
	return ctx.Err() == nil
}

type publicConfigurationClosure struct {
	GeneratorSHA256   string                          `json:"generator_sha256,omitempty"`
	GeneratorLength   int64                           `json:"generator_length,omitempty"`
	GeneratorManifest string                          `json:"generator_manifest,omitempty"`
	CLISHA256         string                          `json:"cli_sha256"`
	ConsumerSHA256    string                          `json:"consumer_sha256"`
	OverlaySHA256     string                          `json:"overlay_sha256"`
	SourceSHA256      string                          `json:"source_sha256"`
	Plugins           []records.StockPluginBuild      `json:"plugins,omitempty"`
	ManifestRenderer  *records.PublicManifestRenderer `json:"manifest_renderer,omitempty"`
}

func (a publicConfigurationArtifact) closure() *publicConfigurationClosure {
	plugins := append([]records.StockPluginBuild(nil), a.Plugins...)
	for i := range plugins {
		plugins[i].Directory = filepath.Join("public-plugins", plugins[i].Metadata.Name)
	}
	return &publicConfigurationClosure{CLISHA256: a.CLISHA256, ConsumerSHA256: a.ConsumerSHA256, OverlaySHA256: a.Overlay.SHA256, SourceSHA256: a.Overlay.ManifestSHA256, GeneratorSHA256: a.GeneratorSHA256, GeneratorLength: a.GeneratorLength, GeneratorManifest: a.GeneratorManifest, Plugins: plugins, ManifestRenderer: a.ManifestRenderer}
}
func publicConfigurationArtifactFromClosure(build string, c *publicConfigurationClosure, race bool) publicConfigurationArtifact {
	if c == nil {
		return publicConfigurationArtifact{}
	}
	generatorPath := ""
	if c.GeneratorSHA256 != "" {
		generatorPath = filepath.Join(build, "enkv-generator-cloudflare")
	}
	plugins := append([]records.StockPluginBuild(nil), c.Plugins...)
	for i := range plugins {
		plugins[i].Directory = filepath.Join(build, plugins[i].Directory)
	}
	return publicConfigurationArtifact{Race: raceSetting(race), GeneratorArtifact: generatorPath, GeneratorSHA256: c.GeneratorSHA256, GeneratorLength: c.GeneratorLength, GeneratorManifest: c.GeneratorManifest, CLI: filepath.Join(build, "enkv-public"), Consumer: filepath.Join(build, "enkv-public-reconstruct"), CLISHA256: c.CLISHA256, ConsumerSHA256: c.ConsumerSHA256, Overlay: nativeprocess.Overlay{Path: filepath.Join(build, "public-configuration-overlay", "overlay.json"), Manifest: filepath.Join(build, "public-configuration-overlay", "sources.json"), SHA256: c.OverlaySHA256, ManifestSHA256: c.SourceSHA256}, Plugins: plugins, ManifestRenderer: c.ManifestRenderer}
}

func publicGeneratorBuildProfileValid(path string, race bool) bool {
	info, err := buildinfo.ReadFile(path)
	return err == nil && publicGeneratorBuildSettingsValid(info, race)
}
func publicGeneratorBuildSettingsValid(info *debug.BuildInfo, race bool) bool {
	if info == nil || info.GoVersion != cloudflareGoVersion || info.Path != modulePrefix+"compositions/full/cmd/enkv" || info.Main.Path != modulePrefix+"compositions/full" {
		return false
	}
	settings := map[string]string{}
	for _, setting := range info.Settings {
		if _, duplicate := settings[setting.Key]; duplicate {
			return false
		}
		settings[setting.Key] = setting.Value
	}
	// Trimpath omits linker flags. The successful build and measured closure
	// bind the generator; build metadata establishes only this build profile.
	_, recordedLinkerFlags := settings["-ldflags"]
	return !recordedLinkerFlags && settings["-tags"] == "netgo" && (settings["-race"] == "true") == race && (settings["-race"] == "" || settings["-race"] == "true") && settings["-trimpath"] == "true"
}

func buildPublicProcessConsumer(ctx context.Context, root, output string, overlay nativeprocess.Overlay, race bool) error {
	helperDirectory := filepath.Join(root, filepath.FromSlash(publicProcessSourceDirectory))
	helper := publicConfigurationBuildArgs(output, overlay.Path, race)
	sourceFiles, err := filepath.Glob(filepath.Join(helperDirectory, "*.go"))
	if err != nil {
		return err
	}
	for _, path := range sourceFiles {
		if !strings.HasSuffix(path, "_test.go") {
			helper = append(helper, path)
		}
	}
	helper = append(helper, filepath.Join(helperDirectory, "nativeprocess_observer.go"))
	if _, err := runGo(ctx, root, publicProcessBuildDirectory, helper...); err != nil {
		return err
	}
	return nil
}

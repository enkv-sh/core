package records

import (
	"context"
	"path/filepath"
	"reflect"

	"enkv.sh/core/testsupport/nativeprocess"
	"enkv.sh/sdk/artifact"
)

// PublicProcessArtifact is the passive coordinator-to-worker artifact wire.
// The coordinator owns construction and verification of these fields.
type PublicProcessArtifact struct {
	Race              *bool                   `json:"race,omitempty"`
	GeneratorArtifact string                  `json:"generator_artifact,omitempty"`
	GeneratorSHA256   string                  `json:"generator_sha256,omitempty"`
	GeneratorLength   int64                   `json:"generator_length,omitempty"`
	GeneratorManifest string                  `json:"generator_manifest,omitempty"`
	CLI               string                  `json:"cli"`
	CLISHA256         string                  `json:"cli_sha256"`
	Consumer          string                  `json:"consumer"`
	ConsumerSHA256    string                  `json:"consumer_sha256"`
	Overlay           nativeprocess.Overlay   `json:"overlay"`
	Plugins           []StockPluginBuild      `json:"plugins,omitempty"`
	ManifestRenderer  *PublicManifestRenderer `json:"manifest_renderer,omitempty"`
}

// ValidatePlugins checks the exact local builds retained by the fixture owner.
// It executes no plugin and grants no production admission.
func (a PublicProcessArtifact) ValidatePlugins(ctx context.Context, build string) bool {
	if len(a.Plugins) > 7 {
		return false
	}
	var renderer *PublicManifestRenderer
	previous := ""
	for _, plugin := range a.Plugins {
		name := plugin.Metadata.Name
		if !artifact.ValidPluginID(name) || name <= previous || plugin.Directory != filepath.Join(build, "public-plugins", name) || plugin.Metadata.Role != "output" && plugin.Metadata.Role != "manifest-generator" && plugin.Metadata.Role != "generator" {
			return false
		}
		previous = name
		actual, err := artifact.VerifyBuild(ctx, plugin.Directory)
		if err != nil || !reflect.DeepEqual(actual, plugin.Metadata) {
			return false
		}
		if actual.Role == "manifest-generator" {
			if actual.Name != "generic-json" {
				return false
			}
			measured, err := PublicManifestRendererFromMetadata(actual)
			if err != nil {
				return false
			}
			renderer = &measured
		}
		if actual.Role == "generator" {
			facts, err := actual.GeneratorFacts()
			if err != nil || actual.Name != "cloudflare-account-token" || a.GeneratorArtifact == "" || facts.ArtifactSHA256.String() != a.GeneratorSHA256 || facts.ArtifactLength != uint64(a.GeneratorLength) || facts.DependencyManifestID.String() != a.GeneratorManifest {
				return false
			}
		}
	}
	return reflect.DeepEqual(renderer, a.ManifestRenderer)
}

type PublicManifestRenderer struct {
	Name             string `json:"name"`
	Version          string `json:"version"`
	Protocol         string `json:"protocol_id"`
	Descriptor       string `json:"descriptor_id"`
	Executor         string `json:"executor_id"`
	ArtifactContract string `json:"artifact_contract_id"`
	Dependency       string `json:"dependency_manifest_id"`
	Artifact         string `json:"artifact_id"`
	SHA256           string `json:"artifact_sha256"`
	Length           uint64 `json:"artifact_length"`
}

func PublicManifestRendererFromMetadata(metadata artifact.Metadata) (PublicManifestRenderer, error) {
	facts, err := metadata.ManifestFacts()
	if err != nil {
		return PublicManifestRenderer{}, err
	}
	identity, err := metadata.Identity()
	if err != nil {
		return PublicManifestRenderer{}, err
	}
	return PublicManifestRenderer{metadata.Name, metadata.Version, facts.Descriptor.Wire.Identity, facts.DescriptorID.String(), facts.ExecutorID.String(), facts.ArtifactContractID.String(), facts.DependencyManifestID.String(), identity.String(), facts.ArtifactSHA256.String(), facts.ArtifactLength}, nil
}

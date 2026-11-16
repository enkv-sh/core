package custody

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"enkv.sh/compositions/generatorhost"
	"enkv.sh/core/contract"
	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
	protocol "enkv.sh/sdk/protocols/generator"
	"reflect"
)

// This is a passive configuration fixture, not an executable qualification.
func normalGeneratedProcessConfig(t *testing.T) (GeneratedProcessConfig, contract.GeneratedProducerPreparation) {
	t.Helper()
	route, err := credentialroute.Encode(credentialroute.Route{Schema: 1, ContractID: [32]byte{2}, Mode: credentialroute.ModeEnvironment, Names: []string{"PRIVATE_GENERATOR_TOKEN"}})
	if err != nil {
		t.Fatal(err)
	}
	descriptor := artifact.Descriptor{Schema: 1, Name: "private-custody-generator", Role: "generator", Version: "0.0.0", Wire: artifact.Contract{Kind: "wire", Identity: artifact.Digest(protocol.ProtocolID()).String(), Version: 3}, Generator: &artifact.GeneratorDeclaration{ConfigContractID: artifact.Digest{3}, CredentialRoute: route}}
	main := "example.test/generator"
	options := []artifact.BuildOption{{Name: "-buildmode", Value: "exe"}, {Name: "-compiler", Value: "gc"}, {Name: "-trimpath", Value: "true"}, {Name: "CGO_ENABLED", Value: "0"}, {Name: "GOARCH", Value: runtime.GOARCH}}
	if runtime.GOARCH == "arm64" {
		options = append(options, artifact.BuildOption{Name: "GOARM64", Value: "v8.0"})
	} else {
		options = append(options, artifact.BuildOption{Name: "GOAMD64", Value: "v1"})
	}
	options = append(options, artifact.BuildOption{Name: "GOOS", Value: runtime.GOOS})
	slices.SortFunc(options, func(a, b artifact.BuildOption) int { return strings.Compare(a.Name, b.Name) })
	facts := artifact.BuildFacts{Role: "generator", MainModule: main, Command: main + "/cmd/plugin", Platform: runtime.GOOS + "/" + runtime.GOARCH, Toolchain: "go1.27.3", BuildOptions: options,
		Contracts: []artifact.Contract{descriptor.Wire},
		Sources:   []artifact.Source{{Module: main, Digest: artifact.Digest{1}}}, Resolved: []artifact.Dependency{{Path: main}}, Compiled: []artifact.Dependency{{Path: main, Version: "(devel)"}}}
	dependency, err := artifact.EncodeDependency(facts)
	if err != nil {
		t.Fatal(err)
	}
	id, err := artifact.DependencyID("generator", dependency)
	if err != nil {
		t.Fatal(err)
	}
	digest := artifact.Hash([]byte("passive fixture executable"))
	family, err := artifact.BindGeneratorFacts(artifact.GeneratorFacts{Schema: 2, Descriptor: descriptor, ExecutionFacts: artifact.ExecutionFacts{Module: main, Command: facts.Command, GoVersion: facts.Toolchain, NativeTuple: facts.Platform}}, digest, 26, id)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(family)
	if err != nil {
		t.Fatal(err)
	}
	metadata := artifact.Metadata{Schema: "enkv/plugin-artifact/v2", Purpose: "plugin-executable", Name: descriptor.Name, Role: facts.Role, Version: "0.0.0", MainModule: main, Command: facts.Command, Platform: facts.Platform, Toolchain: facts.Toolchain, BuildOptions: facts.BuildOptions, Contracts: facts.Contracts, Sources: facts.Sources, Resolved: facts.Resolved, Compiled: facts.Compiled, Executable: artifact.DigestLength{SHA256: digest, Length: 26}, Family: &artifact.Family{Schema: 2, Facts: body, Dependency: artifact.DigestLength{SHA256: artifact.Hash(dependency), Length: uint64(len(dependency))}}}
	encoded, err := artifact.EncodeMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := generatorhost.NewInstallation(metadata, dependency)
	if err != nil {
		t.Fatal(err)
	}
	row := installed.Artifact()
	return GeneratedProcessConfig{ArtifactPath: filepath.Join(t.TempDir(), "unopened-plugin"), Artifact: row, Metadata: encoded, Dependency: dependency}, contract.GeneratedProducerPreparation{Schema: contract.GeneratedProducerPreparationSchema, DescriptorID: row.DescriptorID, ExecutorID: row.ExecutorID, CredentialRouteID: row.CredentialRouteID}
}

// full_only: false
func TestGeneratedProcessConfigRequiresExactInstalledArtifact(t *testing.T) {
	config, preparation := normalGeneratedProcessConfig(t)
	// A malformed environment and absent executable cannot affect passive admission.
	t.Setenv("PRIVATE_GENERATOR_TOKEN", "invalid")
	host, err := generatedProcessHostConfig(config, preparation)
	if err != nil || host.Installation == nil || !reflect.DeepEqual(host.Artifact, config.Artifact) || host.Artifact.CredentialRouteID != preparation.CredentialRouteID {
		t.Fatal("normal captured installation configuration refused", err)
	}
	config.Metadata[0] ^= 1
	config.Dependency[0] ^= 1
	row := host.Installation.Artifact()
	if !reflect.DeepEqual(row, host.Artifact) {
		t.Fatal("caller mutation changed admitted installation", err)
	}
	config, preparation = normalGeneratedProcessConfig(t)
	for name, change := range map[string]func(*GeneratedProcessConfig, *contract.GeneratedProducerPreparation){
		"missing_metadata": func(c *GeneratedProcessConfig, _ *contract.GeneratedProducerPreparation) { c.Metadata = nil },
		"damaged_metadata": func(c *GeneratedProcessConfig, _ *contract.GeneratedProducerPreparation) { c.Metadata[0] ^= 1 },
		"oversized_metadata": func(c *GeneratedProcessConfig, _ *contract.GeneratedProducerPreparation) {
			c.Metadata = make([]byte, artifact.MaxMetadataBytes+1)
		},
		"missing_dependency": func(c *GeneratedProcessConfig, _ *contract.GeneratedProducerPreparation) { c.Dependency = nil },
		"damaged_dependency": func(c *GeneratedProcessConfig, _ *contract.GeneratedProducerPreparation) {
			c.Dependency[len(c.Dependency)-1] ^= 1
		},
		"oversized_dependency": func(c *GeneratedProcessConfig, _ *contract.GeneratedProducerPreparation) {
			c.Dependency = make([]byte, artifact.MaxDependencyBytes+1)
		},
		"exact_row": func(c *GeneratedProcessConfig, _ *contract.GeneratedProducerPreparation) {
			c.Artifact.ExecutorID[0] ^= 1
		},
		"descriptor": func(c *GeneratedProcessConfig, _ *contract.GeneratedProducerPreparation) {
			c.Artifact.DescriptorID[0] ^= 1
		},
		"prepared_descriptor": func(_ *GeneratedProcessConfig, p *contract.GeneratedProducerPreparation) { p.DescriptorID[0] ^= 1 },
		"prepared_executor":   func(_ *GeneratedProcessConfig, p *contract.GeneratedProducerPreparation) { p.ExecutorID[0] ^= 1 },
		"route":               func(_ *GeneratedProcessConfig, p *contract.GeneratedProducerPreparation) { p.CredentialRouteID[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			c, p := config, preparation
			c.Metadata, c.Dependency = slices.Clone(config.Metadata), slices.Clone(config.Dependency)
			change(&c, &p)
			if _, err := generatedProcessHostConfig(c, p); err == nil {
				t.Fatal("untrusted production configuration admitted")
			}
			if _, err := os.Stat(c.ArtifactPath); !os.IsNotExist(err) {
				t.Fatal("passive validation touched absent child", err)
			}
		})
	}
}

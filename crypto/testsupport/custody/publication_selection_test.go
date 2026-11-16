package custody

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"enkv.sh/compositions/outputhost"
	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
	protocol "enkv.sh/sdk/protocols/output"
)

func passivePublicationInstallation(t *testing.T, name, environment string, seed byte) *outputhost.Installation {
	t.Helper()
	route, err := credentialroute.Encode(credentialroute.Route{Schema: 1, ContractID: [32]byte{seed}, Mode: credentialroute.ModeEnvironment, Names: []string{environment}})
	if err != nil {
		t.Fatal(err)
	}
	descriptor := artifact.Descriptor{Schema: 1, Name: name, Role: "output", Version: "1.0.0", Wire: artifact.Contract{Kind: "wire", Identity: artifact.Digest(protocol.ProtocolID()).String(), Version: uint32(protocol.Version)}, Output: &artifact.OutputDeclaration{ConfigContractID: "independent-output/config/v1", CredentialRoute: route}}
	main := "example.test/independent-output"
	options := []artifact.BuildOption{{Name: "-buildmode", Value: "exe"}, {Name: "-compiler", Value: "gc"}, {Name: "-trimpath", Value: "true"}, {Name: "CGO_ENABLED", Value: "0"}, {Name: "GOARCH", Value: runtime.GOARCH}, {Name: "GOOS", Value: runtime.GOOS}}
	switch runtime.GOARCH {
	case "arm64":
		options = append(options, artifact.BuildOption{Name: "GOARM64", Value: "v8.0"})
	case "amd64":
		options = append(options, artifact.BuildOption{Name: "GOAMD64", Value: "v1"})
	}
	slices.SortFunc(options, func(a, b artifact.BuildOption) int { return strings.Compare(a.Name, b.Name) })
	facts := artifact.BuildFacts{Role: "output", MainModule: main, Command: main + "/cmd/plugin", Platform: runtime.GOOS + "/" + runtime.GOARCH, Toolchain: "go1.27.3", BuildOptions: options, Contracts: []artifact.Contract{descriptor.Wire}, Sources: []artifact.Source{{Module: main, Digest: artifact.Digest{seed}}}, Resolved: []artifact.Dependency{{Path: main}}, Compiled: []artifact.Dependency{{Path: main, Version: "(devel)"}}}
	dependency, err := artifact.EncodeDependency(facts)
	if err != nil {
		t.Fatal(err)
	}
	id, err := artifact.DependencyID("output", dependency)
	if err != nil {
		t.Fatal(err)
	}
	executable := artifact.DigestLength{SHA256: artifact.Digest{seed}, Length: 123}
	family, err := artifact.BindOutputFacts(artifact.OutputFacts{Schema: artifact.FamilySchema, Descriptor: descriptor, ExecutionFacts: artifact.ExecutionFacts{Module: main, Command: facts.Command, GoVersion: facts.Toolchain, NativeTuple: facts.Platform}}, executable.SHA256, executable.Length, id)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(family)
	if err != nil {
		t.Fatal(err)
	}
	metadata := artifact.Metadata{Schema: "enkv/plugin-artifact/v2", Purpose: "plugin-executable", Name: name, Role: facts.Role, Version: descriptor.Version, MainModule: main, Command: facts.Command, Platform: facts.Platform, Toolchain: facts.Toolchain, BuildOptions: options, Contracts: facts.Contracts, Sources: facts.Sources, Resolved: facts.Resolved, Compiled: facts.Compiled, Executable: executable, Family: &artifact.Family{Schema: artifact.FamilySchema, Facts: body, Dependency: artifact.DigestLength{SHA256: artifact.Hash(dependency), Length: uint64(len(dependency))}}}
	installed, err := outputhost.NewInstallation(metadata, dependency)
	if err != nil {
		t.Fatal(err)
	}
	return installed
}

// full_only: false
func TestPublicationSelectionKeepsDestinationBuildAndRouteIndependent(t *testing.T) {
	first := passivePublicationInstallation(t, "first-output", "FIRST_PRIVATE_OUTPUT_TOKEN", 1)
	second := passivePublicationInstallation(t, "second-output", "SECOND_PRIVATE_OUTPUT_TOKEN", 2)
	configContractID := first.Artifact().ConfigContractID
	if second.Artifact().ConfigContractID != configContractID || first.Artifact().DescriptorID == second.Artifact().DescriptorID || first.Artifact().ExecutorID == second.Artifact().ExecutorID || first.Artifact().CredentialRouteID == second.Artifact().CredentialRouteID {
		t.Fatal("fixture does not distinguish same-contract installations")
	}
	path := filepath.Join(t.TempDir(), "unopened-output")
	fixture := &Fixture{publicationOutputs: map[string]publicationOutput{
		"first":  {config: outputhost.Config{ArtifactPath: path, Installation: first}, configContractID: configContractID},
		"second": {config: outputhost.Config{ArtifactPath: path, Installation: second}, configContractID: configContractID},
	}}
	for destination, installed := range map[string]*outputhost.Installation{"first": first, "second": second} {
		got, err := fixture.PublicationArtifact(t.Context(), destination, configContractID)
		if err != nil || got != installed.Artifact() {
			t.Fatal("destination did not select its exact installation", destination, err)
		}
		got.DescriptorID[0] ^= 1
		got.ExecutorID[0] ^= 1
		got.CredentialRouteID[0] ^= 1
		again, err := fixture.PublicationArtifact(t.Context(), destination, configContractID)
		if err != nil || again != installed.Artifact() {
			t.Fatal("caller changed selected installation", destination, err)
		}
	}
	if _, err := fixture.PublicationArtifact(t.Context(), "missing", configContractID); err == nil {
		t.Fatal("missing destination selected another installation")
	}
	if _, err := fixture.PublicationArtifact(t.Context(), "first", "another-output/config/v1"); err == nil {
		t.Fatal("selected destination accepted a different config contract")
	}
}

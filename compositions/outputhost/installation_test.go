package outputhost

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
	protocol "enkv.sh/sdk/protocols/output"
)

func fixtureOutputDescriptor(name string) artifact.Descriptor {
	route, err := credentialroute.Encode(credentialroute.Route{Schema: 1, ContractID: sha256.Sum256([]byte("private-output/environment/v1")), Mode: credentialroute.ModeEnvironment, Names: []string{"ENKV_OUTPUT_TEST_CREDENTIAL"}})
	if err != nil {
		panic(err)
	}
	return artifact.Descriptor{Schema: 1, Name: name, Role: "output", Version: "1.2.3", Wire: artifact.Contract{Kind: "wire", Identity: artifact.Digest(protocol.ProtocolID()).String(), Version: uint32(protocol.Version)}, Output: &artifact.OutputDeclaration{ConfigContractID: "private-settings/v1", CredentialRoute: route}}
}
func fixturePublicBuildFacts(main, command string) artifact.BuildFacts {
	platform := strings.Split(testNativeTuple(), "/")
	options := []artifact.BuildOption{{Name: "-buildmode", Value: "exe"}, {Name: "-compiler", Value: "gc"}, {Name: "-trimpath", Value: "true"}, {Name: "CGO_ENABLED", Value: "0"}, {Name: "GOARCH", Value: platform[1]}, {Name: "GOOS", Value: platform[0]}}
	switch platform[1] {
	case "amd64":
		options = append(options, artifact.BuildOption{Name: "GOAMD64", Value: "v1"})
	case "arm64":
		options = append(options, artifact.BuildOption{Name: "GOARM64", Value: "v8.0"})
	}
	slices.SortFunc(options, func(a, b artifact.BuildOption) int { return strings.Compare(a.Name, b.Name) })
	return artifact.BuildFacts{Role: "output", MainModule: main, Command: command, Platform: testNativeTuple(), Toolchain: "go1.27.3", BuildOptions: options, Contracts: []artifact.Contract{fixtureOutputDescriptor("private-output").Wire}, Sources: []artifact.Source{{Module: main, Digest: artifact.Digest{1}}}, Resolved: []artifact.Dependency{{Path: main}}, Compiled: []artifact.Dependency{{Path: main, Version: "(devel)"}}}
}
func bindOutputMetadata(t *testing.T, metadata artifact.Metadata, descriptor artifact.Descriptor) (artifact.Metadata, []byte) {
	t.Helper()
	metadata.Name, metadata.Role, metadata.Version = descriptor.Name, descriptor.Role, descriptor.Version
	metadata.Contracts = []artifact.Contract{descriptor.Wire}
	dependency, err := artifact.EncodeDependency(metadata.BuildFacts())
	if err != nil {
		t.Fatal(err)
	}
	id, err := artifact.DependencyID("output", dependency)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := artifact.BindOutputFacts(artifact.OutputFacts{Schema: artifact.FamilySchema, Descriptor: descriptor, ExecutionFacts: artifact.ExecutionFacts{Module: metadata.MainModule, Command: metadata.Command, GoVersion: metadata.Toolchain, NativeTuple: metadata.Platform}}, metadata.Executable.SHA256, metadata.Executable.Length, id)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	metadata.Family = &artifact.Family{Schema: artifact.FamilySchema, Facts: body, Dependency: artifact.DigestLength{SHA256: artifact.Hash(dependency), Length: uint64(len(dependency))}}
	return metadata, dependency
}
func metadataFromBuildFacts(t *testing.T, facts artifact.BuildFacts, descriptor artifact.Descriptor, digest artifact.Digest, length uint64) (artifact.Metadata, []byte) {
	t.Helper()
	return bindOutputMetadata(t, artifact.Metadata{Schema: "enkv/plugin-artifact/v2", Purpose: "plugin-executable", MainModule: facts.MainModule, Command: facts.Command, Platform: facts.Platform, Toolchain: facts.Toolchain, BuildOptions: facts.BuildOptions, Executable: artifact.DigestLength{SHA256: digest, Length: length}, Sources: facts.Sources, Resolved: facts.Resolved, Compiled: facts.Compiled}, descriptor)
}
func fixtureOutputInstallation(t *testing.T, index int, command string) (artifact.Metadata, []byte, Artifact) {
	t.Helper()
	descriptor := fixtureOutputDescriptor(fmt.Sprintf("private-output-%d", index))
	facts := fixturePublicBuildFacts("example.invalid/independent/output", command)
	metadata, dependency := metadataFromBuildFacts(t, facts, descriptor, sha256.Sum256([]byte("independent executable")), 123)
	installation, err := NewInstallation(metadata, dependency)
	if err != nil {
		t.Fatal(err)
	}
	return metadata, dependency, installation.Artifact()
}

// full_only: false
func TestInstallationRequiresExactSupportedFamilyAndDependency(t *testing.T) {
	for _, command := range []string{"example.invalid/independent/output", "example.invalid/independent/output/tools/publish"} {
		metadata, dependency, want := fixtureOutputInstallation(t, 0, command)
		installation, err := NewInstallation(metadata, dependency)
		if err != nil || installation.Artifact() != want {
			t.Fatal("independent installation changed", err)
		}
		for _, damage := range []string{"raw-digest", "raw-length", "dependency-bytes", "outer-module", "outer-command", "outer-name", "family-extra", "contract-extra", "contract-version", "contract-missing", "compiled-set", "source", "role", "descriptor-config", "descriptor-route"} {
			t.Run(damage, func(t *testing.T) {
				m, body, _ := fixtureOutputInstallation(t, 0, command)
				switch damage {
				case "raw-digest":
					m.Family.Dependency.SHA256[0] ^= 1
				case "raw-length":
					m.Family.Dependency.Length++
				case "dependency-bytes":
					body = append(body, 0)
				case "outer-module":
					m.MainModule += "/other"
				case "outer-command":
					m.Command += "/other"
				case "outer-name":
					m.Name = "another-local-output"
				case "family-extra":
					m.Family.Facts = append(slices.Clone(m.Family.Facts[:len(m.Family.Facts)-1]), []byte(`,"extra":0}`)...)
				case "contract-extra":
					m.Contracts = append(m.Contracts, m.Contracts[0])
				case "contract-version":
					m.Contracts[0].Version++
				case "contract-missing":
					m.Contracts = nil
				case "compiled-set":
					m.Compiled[0].Version = "v1.0.0"
				case "source":
					m.Sources[0].Digest[0] ^= 1
				case "role":
					m.Role = "generator"
				case "descriptor-config", "descriptor-route":
					facts, err := m.OutputFacts()
					if err != nil {
						t.Fatal(err)
					}
					if damage == "descriptor-config" {
						facts.Descriptor.Output.ConfigContractID = "other-settings/v1"
					} else {
						facts.Descriptor.Output.CredentialRoute[len(facts.Descriptor.Output.CredentialRoute)-1] ^= 1
					}
					m.Family.Facts, err = json.Marshal(facts)
					if err != nil {
						t.Fatal(err)
					}
				}
				if ValidateInstallation(m, body) == nil {
					t.Fatal("different installation admitted", damage)
				}
			})
		}
	}
}

// full_only: false
func TestInstallationCopiesInputsAndRejectsRetainedNewWork(t *testing.T) {

	t.Run("versioned-main-and-nested-local-owner", func(t *testing.T) {
		metadata, _, _ := fixtureOutputInstallation(t, 0, "example.invalid/independent/output")
		metadata.Resolved[0].Version, metadata.Resolved[0].Sum = "v1.2.3", "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		metadata.Compiled[0] = metadata.Resolved[0]
		helper := "example.invalid/independent/public-helper"
		digest := artifact.Digest{9}
		metadata.Sources = append(metadata.Sources, artifact.Source{Module: helper, Digest: digest})
		metadata.Resolved = append(metadata.Resolved, artifact.Dependency{Path: helper, Version: "v0.4.0", Replacement: &artifact.Replacement{Path: "../public-helper", SourceDigest: digest}})
		metadata.Compiled = append(metadata.Compiled, artifact.Dependency{Path: helper, Version: "v0.4.0", Replacement: &artifact.Replacement{Path: "../public-helper", Version: "(devel)", SourceDigest: digest}})
		metadata, body := bindOutputMetadata(t, metadata, fixtureOutputDescriptor("private-output-0"))
		installed, err := NewInstallation(metadata, body)
		if err != nil {
			t.Fatal("versioned and local closure refused", err)
		}
		metadata.Resolved[1].Replacement.Path = "../changed"
		metadata.Compiled[1].Replacement.SourceDigest[0] ^= 1
		if installed.manifest.Facts.Resolved[1].Replacement.Path != "../public-helper" || installed.manifest.Facts.Compiled[1].Replacement.SourceDigest != digest {
			t.Fatal("nested replacement borrows caller state")
		}
	})
	m, body, want := fixtureOutputInstallation(t, 0, "example.invalid/independent/output")
	installation, err := NewInstallation(m, body)
	if err != nil {
		t.Fatal(err)
	}
	clear(body)
	clear(m.Family.Facts)
	m.Sources[0].Digest[0] ^= 1
	if installation.Artifact() != want || !installation.valid() {
		t.Fatal("installation retained mutable inputs")
	}
	route, err := installation.CredentialRoute()
	if err != nil {
		t.Fatal(err)
	}
	route.Names[0] = "OTHER"
	again, err := installation.CredentialRoute()
	if err != nil || again.Names[0] != "ENKV_OUTPUT_TEST_CREDENTIAL" {
		t.Fatal("route is not owned", err)
	}
	for _, schema := range []uint16{1, 2} {
		if _, err := DecodeDependencyManifest([]byte{0, byte(schema)}); err == nil {
			t.Fatal("removed dependency schema accepted")
		}
	}
}

// full_only: false
func TestInstallationAcceptsMeasuredToolchainsAndArbitraryNames(t *testing.T) {
	for _, version := range []string{"go1.27.0", "go1.27.3", "go1.27.4"} {
		m, _, _ := fixtureOutputInstallation(t, 0, "example.invalid/independent/output")
		m.Toolchain = version
		descriptor := fixtureOutputDescriptor("unpublished-local-output")
		descriptor.Output.ConfigContractID = "private-contract/with-different-meaning/v9"
		m, body := bindOutputMetadata(t, m, descriptor)
		installation, err := NewInstallation(m, body)
		if err != nil || installation.Artifact().GoVersion != version || installation.Artifact().ConfigContractID != descriptor.Output.ConfigContractID {
			t.Fatal("measured independent build refused", version, err)
		}
		if !reflect.DeepEqual(m.BuildFacts().Contracts, []artifact.Contract{descriptor.Wire}) {
			t.Fatal("implicit semantic catalog added")
		}
	}
}

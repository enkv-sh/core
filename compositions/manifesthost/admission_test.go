package manifesthost

import (
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"slices"
	"strings"
	"testing"
	"unsafe"

	"enkv.sh/sdk/artifact"
	protocol "enkv.sh/sdk/protocols/manifest-generator"
)

func fixtureOptions() []artifact.BuildOption {
	options := []artifact.BuildOption{{Name: "-buildmode", Value: "exe"}, {Name: "-compiler", Value: "gc"}, {Name: "-trimpath", Value: "true"}, {Name: "CGO_ENABLED", Value: "0"}, {Name: "GOOS", Value: runtime.GOOS}, {Name: "GOARCH", Value: runtime.GOARCH}}
	if runtime.GOARCH == "arm64" {
		options = append(options, artifact.BuildOption{Name: "GOARM64", Value: "v8.0"})
	} else {
		options = append(options, artifact.BuildOption{Name: "GOAMD64", Value: "v1"})
	}
	slices.SortFunc(options, func(a, b artifact.BuildOption) int { return strings.Compare(a.Name, b.Name) })
	return options
}

const testFormat = "private-format/v1"
const testConfig = "private-settings/v1"

func fixtureDeclaration() artifact.Descriptor {
	return artifact.Descriptor{Schema: 1, Name: "private-local-renderer", Role: "manifest-generator", Version: "1.0.0", Wire: artifact.Contract{Kind: "wire", Identity: artifact.Digest(protocol.ProtocolID()).String(), Version: protocol.Version}, Manifest: &artifact.ManifestDeclaration{FormatContractID: testFormat, ConfigContractID: testConfig}}
}
func bindFixture(m artifact.Metadata, d artifact.Descriptor) (artifact.Metadata, []byte, error) {
	m.Name, m.Role, m.Version = d.Name, d.Role, d.Version
	m.Contracts = []artifact.Contract{d.Wire}
	dep, err := artifact.EncodeDependency(m.BuildFacts())
	if err != nil {
		return m, nil, err
	}
	id, err := artifact.DependencyID(m.Role, dep)
	if err != nil {
		return m, nil, err
	}
	facts, err := artifact.BindManifestFacts(artifact.ManifestFacts{Schema: artifact.FamilySchema, Descriptor: d, ExecutionFacts: artifact.ExecutionFacts{Module: m.MainModule, Command: m.Command, GoVersion: m.Toolchain, NativeTuple: m.Platform}}, m.Executable.SHA256, m.Executable.Length, id)
	if err != nil {
		return m, nil, err
	}
	body, err := json.Marshal(facts)
	if err != nil {
		return m, nil, err
	}
	m.Family = &artifact.Family{Schema: artifact.FamilySchema, Facts: body, Dependency: artifact.DigestLength{SHA256: artifact.Hash(dep), Length: uint64(len(dep))}}
	return m, dep, nil
}
func metadataFixture() artifact.Metadata {
	digest := artifact.Digest{1}
	path := "example.test/private-renderer"
	m := artifact.Metadata{Schema: "enkv/plugin-artifact/v2", Purpose: "plugin-executable", MainModule: path, Command: path, Platform: runtime.GOOS + "/" + runtime.GOARCH, Toolchain: "go1.27.3", BuildOptions: fixtureOptions(), Executable: artifact.DigestLength{SHA256: digest, Length: 1}, Sources: []artifact.Source{{Module: path, Digest: digest}}, Resolved: []artifact.Dependency{{Path: path}}, Compiled: []artifact.Dependency{{Path: path, Version: "(devel)"}}}
	m, _, err := bindFixture(m, fixtureDeclaration())
	if err != nil {
		panic(err)
	}
	return m
}
func fixtureDependency(m artifact.Metadata) []byte {
	dep, err := artifact.EncodeDependency(m.BuildFacts())
	if err != nil {
		panic(err)
	}
	return dep
}

// full_only: false
func TestManifestAdmissionDistinguishesUnsupportedProtocolFromInvalidFacts(t *testing.T) {
	for _, condition := range []string{"complete", "wire", "extra-contract", "family", "dependency", "missing-dependency", "platform", "nil-context", "cancelled"} {
		t.Run(condition, func(t *testing.T) {
			m := metadataFixture()
			dep := fixtureDependency(m)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch condition {
			case "wire":
				d := fixtureDeclaration()
				d.Wire.Identity = artifact.Hash([]byte("future wire")).String()
				var err error
				m, dep, err = bindFixture(m, d)
				if err != nil {
					t.Fatal(err)
				}
			case "extra-contract":
				m.Contracts = append(m.Contracts, artifact.Contract{Kind: "wire", Identity: artifact.Hash([]byte("extra")).String(), Version: 1})
			case "family":
				m.Family = &artifact.Family{}
			case "dependency":
				dep = []byte{1}
			case "missing-dependency":
				dep = nil
			case "platform":
				if runtime.GOOS == "darwin" {
					m.Platform = "linux/amd64"
				} else {
					m.Platform = "darwin/arm64"
				}
			case "nil-context":
				ctx = nil
			case "cancelled":
				cancel()
			}
			err := Check(ctx, m, dep)
			if condition == "complete" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("invalid admission accepted")
			}
			if errors.Is(err, ErrUnsupported) != (condition == "wire") {
				t.Fatal("semantic fallback classification differs", condition, err)
			}
		})
	}
}

// full_only: false
func TestManifestAdmissionAcceptsUnlistedNamesFormatsAndMeasuredToolchains(t *testing.T) {
	for _, version := range []string{"go1.27.0", "go1.27.3", "go1.27.4"} {
		m := metadataFixture()
		m.Toolchain = version
		d := fixtureDeclaration()
		d.Name = "unpublished-renderer"
		d.Manifest.FormatContractID = "unpublished-format/v9"
		m, dep, err := bindFixture(m, d)
		if err != nil {
			t.Fatal(err)
		}
		if err := Check(t.Context(), m, dep); err != nil {
			t.Fatal("valid independent declaration refused", version, err)
		}
	}
}

// full_only: false
func TestManifestNativeRetainsBoundedDeclarationStorage(t *testing.T) {
	if unsafe.Sizeof(Native{}) != 120 {
		t.Fatal("native declaration descriptor not charged", unsafe.Sizeof(Native{}))
	}
}

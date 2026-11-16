package generatorhost

import (
	"bytes"
	"debug/buildinfo"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"enkv.sh/sdk/artifact"
)

func rebindGeneratorMetadata(t *testing.T, m artifact.Metadata, dependency []byte, id artifact.Digest) artifact.Metadata {
	t.Helper()
	family, err := m.GeneratorFacts()
	if err != nil {
		t.Fatal(err)
	}
	family.Module = m.MainModule
	family.Command = m.Command
	family.GoVersion = m.Toolchain
	family.NativeTuple = m.Platform
	family, err = artifact.BindGeneratorFacts(family, m.Executable.SHA256, m.Executable.Length, id)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(family)
	if err != nil {
		t.Fatal(err)
	}
	m.Family = &artifact.Family{Schema: artifact.FamilySchema, Facts: raw, Dependency: artifact.DigestLength{SHA256: artifact.Hash(dependency), Length: uint64(len(dependency))}}
	return m
}

// full_only: false
func TestInstalledGeneratorAdmitsIndependentMainAndExactBuildFacts(t *testing.T) {
	path := buildSDKGenerator(t)
	metadata, _ := generatorMetadata(t, path)
	original := metadata.MainModule
	metadata.MainModule = "author.example/custom-generator"
	metadata.Command = metadata.MainModule + "/arbitrary-command"
	for i := range metadata.Sources {
		if metadata.Sources[i].Module == original {
			metadata.Sources[i].Module = metadata.MainModule
		}
	}
	for i := range metadata.Resolved {
		if metadata.Resolved[i].Path == original {
			metadata.Resolved[i].Path = metadata.MainModule
		}
	}
	for i := range metadata.Compiled {
		if metadata.Compiled[i].Path == original {
			metadata.Compiled[i].Path = metadata.MainModule
		}
	}
	slices.SortFunc(metadata.Sources, func(a, b artifact.Source) int { return strings.Compare(a.Module, b.Module) })
	slices.SortFunc(metadata.Resolved, func(a, b artifact.Dependency) int { return strings.Compare(a.Path, b.Path) })
	slices.SortFunc(metadata.Compiled, func(a, b artifact.Dependency) int { return strings.Compare(a.Path, b.Path) })
	dependency, err := artifact.EncodeDependency(metadata.BuildFacts())
	if err != nil {
		t.Fatal(err)
	}
	id, err := artifact.DependencyID("generator", dependency)
	if err != nil {
		t.Fatal(err)
	}
	metadata = rebindGeneratorMetadata(t, metadata, dependency, id)
	installed, err := NewInstallation(metadata, dependency)
	if err != nil {
		t.Fatal("independent author coordinates refused", err)
	}
	row := installed.Artifact()
	if row.Module != metadata.MainModule || row.Command != metadata.Command {
		t.Fatal("independent coordinates lost")
	}
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info.Path, info.Main.Path = metadata.Command, metadata.MainModule
	if err := installed.verifyBuildInfo(info); err != nil {
		t.Fatal("complete independent build facts refused", err)
	}
	for _, version := range []string{"go1.27.0", "go1.27.2", "devel go1.27"} {
		changed := *info
		changed.GoVersion = version
		if installed.verifyBuildInfo(&changed) == nil {
			t.Fatal("different actual toolchain admitted", version)
		}
	}
	metadata.Sources[0].Digest[0] ^= 1
	if installed.verifyBuildInfo(info) != nil {
		t.Fatal("caller mutation changed immutable build facts")
	}
	info.Deps = info.Deps[:len(info.Deps)-1]
	if installed.verifyBuildInfo(info) == nil {
		t.Fatal("missing actual compiled module admitted")
	}
}

// full_only: false
func TestInstalledGeneratorRequiresSupportedWireAndExactDependency(t *testing.T) {
	path := buildSDKGenerator(t)
	metadata, dependency := generatorMetadata(t, path)
	if _, err := NewInstallation(metadata, append(bytes.Clone(dependency), 0)); err == nil {
		t.Fatal("trailing dependency byte admitted")
	}
	family, err := metadata.GeneratorFacts()
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*artifact.GeneratorFacts){
		func(v *artifact.GeneratorFacts) { v.Descriptor.Wire.Version++ }, func(v *artifact.GeneratorFacts) { v.Descriptor.Wire.Identity = strings.Repeat("1", 64) },
	} {
		changed := metadata
		f := family
		mutate(&f)
		changed.Contracts = []artifact.Contract{f.Descriptor.Wire}
		body, err := artifact.EncodeDependency(changed.BuildFacts())
		if err != nil {
			t.Fatal(err)
		}
		id, err := artifact.DependencyID("generator", body)
		if err != nil {
			t.Fatal(err)
		}
		f, err = artifact.BindGeneratorFacts(f, changed.Executable.SHA256, changed.Executable.Length, id)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		changed.Family = &artifact.Family{Schema: artifact.FamilySchema, Facts: raw, Dependency: artifact.DigestLength{SHA256: artifact.Hash(body), Length: uint64(len(body))}}
		if _, err := artifact.EncodeMetadata(changed); err != nil {
			t.Fatal("coherent unknown protocol metadata malformed", err)
		}
		if _, err := NewInstallation(changed, body); err == nil {
			t.Fatal("unsupported wire admitted")
		}
	}
}

// full_only: false
func TestRetainedGeneratorRefusesObsoleteDependencyEncoding(t *testing.T) {
	path := buildSDKGenerator(t)
	metadata, dependency := generatorMetadata(t, path)
	old := bytes.Clone(dependency)
	old[1] = 2
	if _, err := NewRetainedInstallation(metadata, old); err == nil {
		t.Fatal("obsolete dependency encoding reinterpreted")
	}
}

// full_only: false
func TestRetainedGeneratorInstallationUsesOriginalBytesAndRecipe(t *testing.T) {
	path := buildSDKGenerator(t)
	metadata, dependency := generatorMetadata(t, path)
	installed, err := NewRetainedInstallation(metadata, dependency)
	if err != nil {
		t.Fatal(err)
	}
	before := installed.Artifact()
	route, err := installed.CredentialRoute()
	if err != nil {
		t.Fatal(err)
	}
	route.Names[0] = "CHANGED"
	dependency[0] ^= 1
	metadata.Sources[0].Digest[0] ^= 1
	if !implementationEqual(before, installed.Artifact()) {
		t.Fatal("caller changed retained exact support")
	}
	changed := before
	changed.CredentialRoute = bytes.Clone(before.CredentialRoute)
	changed.CredentialRoute[2] ^= 1
	if installed.validRuntime(changed) {
		t.Fatal("changed retained route admitted")
	}
	if _, err := NewRetainedInstallation(metadata, dependency); err == nil {
		t.Fatal("changed original dependency admitted")
	}
}

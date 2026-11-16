package generatorhost

import (
	"debug/buildinfo"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"reflect"
	"runtime/debug"
	"slices"
	"strings"
	"testing"

	"enkv.sh/sdk/artifact"
)

func generatorBuildInputs(t *testing.T, build *exec.Cmd) ([]artifact.SourceModule, []artifact.SourcePackage) {
	t.Helper()
	flags := []string{"-mod=readonly"}
	for _, arg := range build.Args[2:] {
		if strings.HasPrefix(arg, "-modfile=") || arg == "-race" {
			flags = append(flags, arg)
		}
	}
	main := "./testdata/hermetic"

	list := func(args []string) []byte {
		command := exec.CommandContext(t.Context(), "go", args...)
		command.Dir = build.Dir
		command.Env = slices.Clone(build.Env)
		body, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("capture generator build inputs: %v\n%s", err, body)
		}
		return body
	}
	moduleBytes := list(append(append([]string{"list", "-m", "-json"}, flags...), "all"))
	var modules []artifact.SourceModule
	decoder := json.NewDecoder(strings.NewReader(string(moduleBytes)))
	for {
		var module artifact.SourceModule
		err := decoder.Decode(&module)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		modules = append(modules, module)
	}
	packageBytes := list(append(append([]string{"list", "-deps", "-json"}, flags...), main))
	var packages []artifact.SourcePackage
	decoder = json.NewDecoder(strings.NewReader(string(packageBytes)))
	for {
		var pkg artifact.SourcePackage
		err := decoder.Decode(&pkg)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		packages = append(packages, pkg)
	}
	return modules, packages
}

func generatorBuildFacts(t *testing.T, info *debug.BuildInfo, modules []artifact.SourceModule, packages []artifact.SourcePackage) artifact.BuildFacts {
	t.Helper()
	sources, err := artifact.CaptureSourcesForModules(t.Context(), "generator", packages, modules)
	if err != nil {
		t.Fatal(err)
	}
	options, err := artifact.CaptureBuildOptions(info)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := artifact.CompiledDependencies(info, sources)
	if err != nil {
		t.Fatal(err)
	}
	digests := map[string]artifact.Digest{}
	for _, source := range sources {
		digests[source.Module] = source.Digest
	}
	resolved := make([]artifact.Dependency, 0, len(modules))
	for _, module := range modules {
		row := artifact.Dependency{Path: module.Path, Version: module.Version, Sum: module.Sum}
		if replacement := module.Replace; replacement != nil {
			if replacement.Replace != nil {
				t.Fatal("nested replacement in generator build")
			}
			row.Replacement = &artifact.Replacement{Path: replacement.Path, Version: replacement.Version, Sum: replacement.Sum}
			if replacement.Version == "" && replacement.Sum == "" {
				row.Replacement.SourceDigest = digests[module.Path]
				if row.Replacement.SourceDigest.IsZero() {
					t.Fatal("local replacement source missing", module.Path)
				}
			}
		}
		resolved = append(resolved, row)
	}
	slices.SortFunc(resolved, func(a, b artifact.Dependency) int { return strings.Compare(a.Path, b.Path) })
	descriptor := testDescriptor(t)
	contracts := []artifact.Contract{descriptor.Wire}
	settings := map[string]string{}
	for _, option := range options {
		settings[option.Name] = option.Value
	}
	facts := artifact.BuildFacts{Role: "generator", MainModule: info.Main.Path, Command: info.Path, Platform: settings["GOOS"] + "/" + settings["GOARCH"], Toolchain: info.GoVersion, BuildOptions: options, Contracts: contracts, Sources: sources, Resolved: resolved, Compiled: compiled}
	if err := artifact.VerifyBuildInfo(info, facts); err != nil {
		t.Fatal(err)
	}
	return facts
}

func recordGeneratorBuildFacts(t *testing.T, path string, build *exec.Cmd, beforeModules []artifact.SourceModule, beforePackages []artifact.SourcePackage, beforeSources []artifact.Source) {
	t.Helper()
	modules, packages := generatorBuildInputs(t, build)
	if !reflect.DeepEqual(beforeModules, modules) || !reflect.DeepEqual(beforePackages, packages) {
		t.Fatal("Generator selected build inputs changed during build")
	}
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	facts := generatorBuildFacts(t, info, modules, packages)
	if !reflect.DeepEqual(beforeSources, facts.Sources) {
		t.Fatal("Generator selected source bytes changed during build")
	}
	body, err := artifact.EncodeDependency(facts)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".dependencies.bin", body, 0600); err != nil {
		t.Fatal(err)
	}
}

func testDescriptor(t *testing.T) artifact.Descriptor {
	t.Helper()
	body, err := os.ReadFile("testdata/hermetic/plugin.json")
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := artifact.DecodeDescriptor(body)
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
}
func generatorInstallation(t *testing.T, path string) *Installation {
	t.Helper()
	metadata, dependency := generatorMetadata(t, path)
	installed, err := NewInstallation(metadata, dependency)
	if err != nil {
		t.Fatal(err)
	}
	return installed
}
func generatorMetadata(t *testing.T, path string) (artifact.Metadata, []byte) {
	t.Helper()
	dependency, err := os.ReadFile(path + ".dependencies.bin")
	if err != nil {
		t.Fatal(err)
	}
	facts, err := artifact.DecodeDependency(dependency)
	if err != nil {
		t.Fatal(err)
	}
	id, err := artifact.DependencyID("generator", dependency)
	if err != nil {
		t.Fatal(err)
	}
	digest, length := artifactIdentity(t, path)
	descriptor := testDescriptor(t)
	var family artifact.GeneratorFacts
	family.Schema = artifact.FamilySchema
	family.Descriptor = descriptor
	family.Module = facts.MainModule
	family.Command = facts.Command
	family.GoVersion = facts.Toolchain
	family.NativeTuple = facts.Platform
	family, err = artifact.BindGeneratorFacts(family, artifact.Digest(digest), length, id)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(family)
	if err != nil {
		t.Fatal(err)
	}
	return artifact.Metadata{Schema: "enkv/plugin-artifact/v2", Purpose: "plugin-executable", Name: descriptor.Name, Role: descriptor.Role, Version: descriptor.Version, MainModule: facts.MainModule, Command: facts.Command, Platform: facts.Platform, Toolchain: facts.Toolchain, BuildOptions: facts.BuildOptions, Contracts: facts.Contracts, Sources: facts.Sources, Resolved: facts.Resolved, Compiled: facts.Compiled, Executable: artifact.DigestLength{SHA256: artifact.Digest(digest), Length: length}, Family: &artifact.Family{Schema: artifact.FamilySchema, Facts: raw, Dependency: artifact.DigestLength{SHA256: artifact.Hash(dependency), Length: uint64(len(dependency))}}}, dependency
}

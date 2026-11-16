package crypto

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"enkv.sh/sdk/artifact"
)

func prepareNativeModule(t testing.TB, root string, command *exec.Cmd, output string) string {
	t.Helper()
	root, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	directory := command.Dir
	if directory == "" {
		directory, err = os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		t.Fatal(err)
	}
	input, overlay := "", ""
	args := append([]string(nil), command.Args[:2]...)
	for _, arg := range command.Args[2:] {
		if value, ok := strings.CutPrefix(arg, "-modfile="); ok {
			input = value
			continue
		}
		if value, ok := strings.CutPrefix(arg, "-overlay="); ok {
			overlay = value
		}
		args = append(args, arg)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	prepare := exec.CommandContext(ctx, "go", "run", "-mod=readonly", filepath.Join(root, "tests/scripts/bootstrap.go"), "modfile", root, directory, input, overlay, output)
	prepare.Dir = root
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key != "GOWORK" && key != "GOTOOLCHAIN" {
			prepare.Env = append(prepare.Env, entry)
		}
	}
	prepare.Env = append(prepare.Env, "GOWORK=off", "GOTOOLCHAIN=local")
	if body, err := prepare.CombinedOutput(); err != nil {
		t.Fatalf("prepare native module inputs: %v\n%s", err, body)
	}
	command.Args = append(args[:2], append([]string{"-modfile=" + output}, args[2:]...)...)
	return output
}

func cloudflareBuildInputs(t *testing.T, build *exec.Cmd) ([]artifact.SourceModule, []artifact.SourcePackage, []artifact.Source) {
	t.Helper()
	flags := []string{"-mod=readonly"}
	for _, arg := range build.Args[2:] {
		if strings.HasPrefix(arg, "-modfile=") || strings.HasPrefix(arg, "-tags=") || strings.HasPrefix(arg, "-overlay=") || arg == "-race" {
			flags = append(flags, arg)
		}
	}
	list := func(args []string) []byte {
		command := exec.CommandContext(t.Context(), "go", args...)
		command.Dir, command.Env = build.Dir, slices.Clone(build.Env)
		body, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("capture Cloudflare build inputs: %v\n%s", err, body)
		}
		return body
	}
	moduleBytes := list(append(append([]string{"list", "-m", "-json"}, flags...), "all"))
	var modules []artifact.SourceModule
	decoder := json.NewDecoder(bytes.NewReader(moduleBytes))
	for {
		var module artifact.SourceModule
		if err := decoder.Decode(&module); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		modules = append(modules, module)
	}
	packageBytes := list(append(append([]string{"list", "-deps", "-json"}, flags...), "./cmd/enkv-generator-cloudflare-test"))
	var packages []artifact.SourcePackage
	decoder = json.NewDecoder(bytes.NewReader(packageBytes))
	for {
		var pkg artifact.SourcePackage
		if err := decoder.Decode(&pkg); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		packages = append(packages, pkg)
	}
	sources, err := artifact.CaptureSourcesForModules(t.Context(), "generator", packages, modules)
	if err != nil {
		t.Fatal(err)
	}
	return modules, packages, sources
}

func cloudflareBuildMetadata(t *testing.T, path string, build *exec.Cmd, descriptor artifact.Descriptor, beforeModules []artifact.SourceModule, beforePackages []artifact.SourcePackage, beforeSources []artifact.Source) (artifact.Metadata, []byte) {
	t.Helper()
	modules, packages, sources := cloudflareBuildInputs(t, build)
	if !reflect.DeepEqual(beforeModules, modules) || !reflect.DeepEqual(beforePackages, packages) || !reflect.DeepEqual(beforeSources, sources) {
		t.Fatal("Cloudflare selected build inputs changed during build")
	}
	info, err := buildinfo.ReadFile(path)
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
				t.Fatal("nested replacement in Cloudflare build")
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
	settings := map[string]string{}
	for _, option := range options {
		settings[option.Name] = option.Value
	}
	facts := artifact.BuildFacts{Role: "generator", MainModule: info.Main.Path, Command: info.Path, Platform: settings["GOOS"] + "/" + settings["GOARCH"], Toolchain: info.GoVersion, BuildOptions: options, Contracts: []artifact.Contract{descriptor.Wire}, Sources: sources, Resolved: resolved, Compiled: compiled}
	if err := artifact.VerifyBuildInfo(info, facts); err != nil {
		t.Fatal(err)
	}
	dependency, err := artifact.EncodeDependency(facts)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := artifact.DependencyID("generator", dependency)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := artifact.ExecutableIdentity(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	family, err := artifact.BindGeneratorFacts(artifact.GeneratorFacts{Schema: artifact.FamilySchema, Descriptor: descriptor, ExecutionFacts: artifact.ExecutionFacts{Module: facts.MainModule, Command: facts.Command, GoVersion: facts.Toolchain, NativeTuple: facts.Platform}}, executable.SHA256, executable.Length, identity)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(family)
	if err != nil {
		t.Fatal(err)
	}
	return artifact.Metadata{Schema: "enkv/plugin-artifact/v2", Purpose: "plugin-executable", Name: descriptor.Name, Role: descriptor.Role, Version: descriptor.Version, MainModule: facts.MainModule, Command: facts.Command, Platform: facts.Platform, Toolchain: facts.Toolchain, BuildOptions: facts.BuildOptions, Contracts: facts.Contracts, Sources: facts.Sources, Resolved: facts.Resolved, Compiled: facts.Compiled, Executable: executable, Family: &artifact.Family{Schema: artifact.FamilySchema, Facts: raw, Dependency: artifact.DigestLength{SHA256: artifact.Hash(dependency), Length: uint64(len(dependency))}}}, dependency
}

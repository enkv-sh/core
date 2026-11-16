package outputhost

import (
	"bytes"
	"debug/buildinfo"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"enkv.sh/sdk/artifact"
)

func testOutputBuildEnvironment(race bool) []string {
	platform := strings.Split(testNativeTuple(), "/")
	fixed := map[string]string{
		"GOENV": "off", "GO111MODULE": "on", "GOWORK": "off", "GOTOOLCHAIN": "local", "GOFLAGS": "", "GOEXPERIMENT": "",
		"CGO_ENABLED": "0", "GOOS": platform[0], "GOARCH": platform[1], "GOAMD64": "v1", "GOARM64": "v8.0",
		"GCCGO": "", "CC": "", "CXX": "", "CGO_CFLAGS": "", "CGO_CPPFLAGS": "", "CGO_CXXFLAGS": "", "CGO_FFLAGS": "", "CGO_LDFLAGS": "",
		"GOTOOLDIR": "", "GOCACHEPROG": "", "GOFIPS140": "", "GODEBUG": "",
	}
	if race {
		fixed["CGO_ENABLED"] = "1"
	}
	var environment []string
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if _, replaced := fixed[name]; !replaced {
			environment = append(environment, entry)
		}
	}
	for name, value := range fixed {
		environment = append(environment, name+"="+value)
	}
	slices.Sort(environment)
	return environment
}

func testBuildDependencyManifest(t *testing.T, path, directory string, race bool, descriptor artifact.Descriptor) []byte {
	t.Helper()
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) []byte {
		t.Helper()
		args = append(args[:1], append([]string{"-modfile=" + path + ".mod"}, args[1:]...)...)
		cmd := exec.CommandContext(t.Context(), "go", args...)
		cmd.Dir = directory
		cmd.Env = testOutputBuildEnvironment(race)
		for _, setting := range info.Settings {
			if setting.Key == "CGO_ENABLED" {
				cmd.Env = slices.DeleteFunc(cmd.Env, func(entry string) bool { return strings.HasPrefix(entry, "CGO_ENABLED=") })
				cmd.Env = append(cmd.Env, "CGO_ENABLED="+setting.Value)
			}
		}
		body, err := cmd.Output()
		if err != nil {
			if failure, ok := err.(*exec.ExitError); ok {
				t.Fatalf("list output build inputs %v: %v: %s", args, err, failure.Stderr)
			}
			t.Fatal("list output build inputs", err)
		}
		return body
	}
	var modules []artifact.SourceModule
	decoder := json.NewDecoder(bytes.NewReader(run("list", "-mod=readonly", "-m", "-json", "all")))
	for {
		var row artifact.SourceModule
		err := decoder.Decode(&row)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		modules = append(modules, row)
	}
	args := []string{"list", "-mod=readonly", "-trimpath", "-buildvcs=false", "-deps", "-json"}
	if race {
		args = append(args, "-race")
	}
	args = append(args, "./cmd/"+filepath.Base(info.Path))
	var packages []artifact.SourcePackage
	decoder = json.NewDecoder(bytes.NewReader(run(args...)))
	for {
		var row artifact.SourcePackage
		err := decoder.Decode(&row)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		packages = append(packages, row)
	}
	sources, err := artifact.CaptureSourcesForModules(t.Context(), "output", packages, modules)
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
	sourceMap := map[string]artifact.Digest{}
	for _, s := range sources {
		sourceMap[s.Module] = s.Digest
	}
	resolved := make([]artifact.Dependency, 0, len(modules))
	for _, r := range modules {
		row := artifact.Dependency{Path: r.Path, Version: r.Version, Sum: r.Sum}
		if r.Replace != nil {
			row.Replacement = &artifact.Replacement{Path: r.Replace.Path, Version: r.Replace.Version, Sum: r.Replace.Sum}
			if r.Replace.Version == "" && r.Replace.Sum == "" {
				row.Replacement.SourceDigest = sourceMap[r.Path]
			}
		}
		resolved = append(resolved, row)
	}
	slices.SortFunc(resolved, func(a, b artifact.Dependency) int { return strings.Compare(a.Path, b.Path) })
	facts := artifact.BuildFacts{Role: "output", MainModule: info.Main.Path, Command: info.Path, Platform: testNativeTuple(), Toolchain: info.GoVersion, BuildOptions: options, Contracts: []artifact.Contract{descriptor.Wire}, Sources: sources, Resolved: resolved, Compiled: compiled}
	body, err := EncodeDependencyManifest(DependencyManifest{Facts: &facts})
	if err != nil {
		t.Fatal("output build manifest refused", err)
	}
	if err := artifact.VerifyBuildInfo(info, facts); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".dependencies", body, 0600); err != nil {
		t.Fatal(err)
	}
	return body
}

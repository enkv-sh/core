package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"enkv.sh/sdk/artifact"
)

// full_only: false
func TestPublicPluginBuildCommandCapturesDetachedAuthorFamilies(t *testing.T) {
	ctx, cancel := context.WithTimeout(cacheOnlyGoContext(t.Context()), 6*time.Minute)
	defer cancel()
	maintained := maintainedCloudflareRoot(t)
	tool := publicPluginBuildTool(t, ctx, maintained)
	cases := []struct {
		name, role, example string
		selectors           []string
		remote              map[string]string
	}{
		{"private-local-token", "generator", "sdk/examples/local-token-generator", []string{"protocols/generator", "sdk/generator", "sdk/examples/testservice", "sdk/examples/local-token-generator"}, nil},
		{"private-local-values", "output", "sdk/examples/local-value-output", []string{"protocols/output", "sdk/output", "sdk/examples/testservice", "sdk/examples/local-value-output"}, nil},
		{"workshop-ini", "manifest-generator", "sdk/examples/ini-reference-manifest", []string{"protocols/manifest-generator", "sdk/manifest-generator", "sdk/examples/ini-reference-manifest"}, nil},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			root := sourceFixtureRoot(t)
			selectors := append([]string{"sdk/artifact"}, test.selectors...)
			copyPublicModuleKit(t, maintained, root, selectors)
			directories := make([]string, 0, len(selectors)+1)
			expectedResolved := map[string]string{}
			expectedCompiled := map[string]string{}
			for _, selector := range selectors {
				owner, err := sourcePath(root, selector)
				if err != nil {
					t.Fatal(err)
				}
				directories = append(directories, owner)
				row, ok := registeredModule(selector)
				if !ok {
					t.Fatal("public source owner missing", selector)
				}
				expectedResolved[row.Module] = ""
				if selector != "sdk/examples/testservice" {
					expectedCompiled[row.Module] = "(devel)"
				}
			}
			for path, version := range test.remote {
				expectedResolved[path] = version
				expectedCompiled[path] = version
			}
			example, err := sourcePath(root, test.example)
			if err != nil {
				t.Fatal(err)
			}
			main, ok := registeredModule(test.example)
			if !ok {
				t.Fatal("author module missing")
			}
			const helperModule = "example.test/author-helper"
			helper := filepath.Join(t.TempDir(), "helper")
			if err := os.Mkdir(helper, 0700); err != nil {
				t.Fatal(err)
			}
			for name, body := range map[string]string{"go.mod": "module " + helperModule + "\n\ngo 1.27.0\n", "LICENSE": "public build fixture\n"} {
				if err := os.WriteFile(filepath.Join(helper, name), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			helperSource := func(value string) []byte {
				return []byte("package helper\nimport \"os\"\nvar Value = " + fmt.Sprintf("%q", value) + "\nfunc init(){if len(os.Args)==0 {panic(Value)}}\n")
			}
			if err := os.WriteFile(filepath.Join(helper, "helper.go"), helperSource("first selected helper"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(example, "author_helper.go"), []byte("package main\nimport _ \""+helperModule+"\"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			directories = append(directories, helper)
			expectedResolved[helperModule] = ""
			expectedCompiled[helperModule] = "(devel)"
			workspace := publicPluginBuildWorkspace(t, ctx, directories)
			destination := publicPluginBuildOutput(t)
			descriptor := filepath.Join(example, "plugin.json")
			args := []string{"-directory", example, "-command", ".", "-workspace", workspace, "-output", destination}
			runPublicPluginBuildCommand(t, ctx, tool, root, args...)
			metadata, err := artifact.VerifyBuild(ctx, destination)
			if err != nil {
				t.Fatal(err)
			}
			checkPublicPluginBuildResolvedFacts(t, ctx, example, workspace, metadata)
			firstMarker, firstExecutable := publicPluginBuildSelection(t, destination)
			checkPublicPluginBuildFacts(t, metadata, descriptor, test.name, test.role, main.Module, main.Module, expectedResolved, expectedCompiled, firstExecutable)
			beforeDependency := metadata.Family
			if err := os.WriteFile(filepath.Join(helper, "helper.go"), helperSource("second selected helper"), 0600); err != nil {
				t.Fatal(err)
			}
			descriptorBody, err := os.ReadFile(descriptor)
			if err != nil {
				t.Fatal(err)
			}
			var alternate artifact.Descriptor
			if err := json.Unmarshal(descriptorBody, &alternate); err != nil {
				t.Fatal(err)
			}
			alternate.Version = "2.0.0"
			alternateBody, err := json.Marshal(alternate)
			if err != nil {
				t.Fatal(err)
			}
			alternatePath := filepath.Join(t.TempDir(), "alternate-descriptor.json")
			if err := os.WriteFile(alternatePath, alternateBody, 0600); err != nil {
				t.Fatal(err)
			}
			args = append(args, "-descriptor", alternatePath)
			runPublicPluginBuildCommand(t, ctx, tool, root, args...)
			changed, err := artifact.VerifyBuild(ctx, destination)
			if err != nil {
				t.Fatal(err)
			}
			checkPublicPluginBuildResolvedFacts(t, ctx, example, workspace, changed)
			secondMarker, secondExecutable := publicPluginBuildSelection(t, destination)
			checkPublicPluginBuildFacts(t, changed, alternatePath, test.name, test.role, main.Module, main.Module, expectedResolved, expectedCompiled, secondExecutable)
			if firstMarker.Artifact == secondMarker.Artifact {
				t.Fatal("selected helper change retained the artifact identity")
			}
			if metadata.Executable == changed.Executable {
				t.Fatal("changed linked helper retained executable bytes")
			}
			if artifact.VerifyExecutable(ctx, secondExecutable, metadata) == nil {
				t.Fatal("stale metadata admitted rebuilt executable")
			}
			if err := artifact.VerifyExecutable(ctx, firstExecutable, metadata); err != nil {
				t.Fatal("rebuild changed the previous immutable executable", err)
			}
			previousSources := map[string]artifact.Digest{}
			for _, source := range metadata.Sources {
				previousSources[source.Module] = source.Digest
			}
			changedSources := 0
			for _, source := range changed.Sources {
				if previousSources[source.Module] != source.Digest {
					changedSources++
					if source.Module != helperModule {
						t.Fatal("unmodified source owner changed", source.Module)
					}
				}
			}
			if changedSources != 1 {
				t.Fatal("helper change did not change exactly its source owner", changedSources)
			}
			if changed.Family.Dependency == beforeDependency.Dependency {
				t.Fatal("selected helper change retained family dependency bytes")
			}
		})
	}
}

func runPublicPluginBuildCommand(t *testing.T, ctx context.Context, tool, directory string, args ...string) {
	t.Helper()
	runPublicPluginBuildCommandEnvironment(t, ctx, tool, directory, nil, args...)
}
func runPublicPluginBuildCommandEnvironment(t *testing.T, ctx context.Context, tool, directory string, overrides map[string]string, args ...string) {
	t.Helper()
	env := environment(goEnvironment(), publicPluginBuildEnvironment("off"))
	env = environment(env, overrides)
	var stdout, stderr limitedOutput
	process := runProcessOutput(ctx, tool, directory, args, env, 2*time.Minute, &stdout, &stderr)
	if !process.Started || !process.Joined || process.Status != "passed" || stdout.overflow || stderr.overflow {
		t.Fatalf("public build command: result=%+v stdout=%s stderr=%s", process, stdout.String(), stderr.String())
	}
	marker, err := artifact.DecodeBuildMarker(bytes.TrimSuffix(stdout.Bytes(), []byte("\n")))
	if err != nil || marker.Artifact.IsZero() {
		t.Fatal("public command did not return its complete canonical marker", err)
	}
}

func publicPluginBuildEnvironment(workspace string) map[string]string {
	return map[string]string{"GOWORK": workspace, "GOENV": "off", "GOFLAGS": "", "GOEXPERIMENT": "", "GO111MODULE": "on", "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off", "GONOPROXY": "none", "CGO_ENABLED": "0", "GOOS": runtime.GOOS, "GOARCH": runtime.GOARCH, "GOAMD64": "v1", "GOARM64": "v8.0", "GCCGO": "", "CC": "", "CXX": "", "CGO_CFLAGS": "", "CGO_CPPFLAGS": "", "CGO_CXXFLAGS": "", "CGO_FFLAGS": "", "CGO_LDFLAGS": "", "GOTOOLDIR": "", "GOCACHEPROG": "", "GOFIPS140": "", "GODEBUG": ""}
}

func checkPublicPluginBuildResolvedFacts(t *testing.T, ctx context.Context, directory, workspace string, metadata artifact.Metadata) {
	t.Helper()
	body := runModuleModeCommand(t, ctx, directory, publicPluginBuildEnvironment(workspace), "list", "-mod=readonly", "-m", "-json", "all")
	modules, err := decodeObjects[resolvedModule](body)
	if err != nil {
		t.Fatal(err)
	}
	actual := make([]artifact.Dependency, 0, len(modules))
	for _, module := range modules {
		if module.Replace != nil {
			t.Fatal("actual workspace graph has a replaced selected owner", module.Path)
		}
		if (module.Version == "") != module.Main {
			t.Fatal("actual workspace owner flag differs from its local version representation", module.Path)
		}
		actual = append(actual, artifact.Dependency{Path: module.Path, Version: module.Version, Sum: module.Sum})
	}
	sort.Slice(actual, func(i, j int) bool { return actual[i].Path < actual[j].Path })
	if !reflect.DeepEqual(metadata.Resolved, actual) {
		t.Fatalf("resolved facts differ from actual Go metadata: got=%+v want=%+v", metadata.Resolved, actual)
	}
}

func publicPluginBuildSelection(t *testing.T, directory string) (artifact.BuildMarker, string) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(directory, "build.json"))
	if err != nil {
		t.Fatal(err)
	}
	marker, err := artifact.DecodeBuildMarker(body)
	if err != nil {
		t.Fatal(err)
	}
	return marker, filepath.Join(directory, filepath.FromSlash(marker.Directory), "plugin")
}
func publicPluginBuildOutput(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Cleanup(func() {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return os.Chmod(path, 0700)
			}
			return nil
		})
		if err != nil {
			t.Error(err)
		}
	})
	return root
}
func checkPublicPluginBuildFacts(t *testing.T, metadata artifact.Metadata, descriptorPath, name, role, main, command string, resolved, compiled map[string]string, executable string) {
	t.Helper()
	descriptorBody, err := os.ReadFile(descriptorPath)
	if err != nil {
		t.Fatal(err)
	}
	var expectedDescriptor artifact.Descriptor
	if err := json.Unmarshal(descriptorBody, &expectedDescriptor); err != nil {
		t.Fatal(err)
	}
	if metadata.Name != name || metadata.Role != role || metadata.Version != expectedDescriptor.Version || metadata.MainModule != main || metadata.Command != command || metadata.Platform != runtime.GOOS+"/"+runtime.GOARCH || metadata.Toolchain != "go1.27.3" {
		t.Fatal("public author metadata identity differs")
	}
	sourceOwners := make(map[string]bool, len(compiled))
	for path := range compiled {
		sourceOwners[path] = true
	}
	for path, version := range resolved {
		if version == "" {
			sourceOwners[path] = true
		}
	}
	if len(metadata.Resolved) != len(resolved) || len(metadata.Compiled) != len(compiled) || len(metadata.Sources) != len(sourceOwners) {
		t.Fatalf("module/source sets differ: resolved=%+v compiled=%+v sources=%+v", metadata.Resolved, metadata.Compiled, metadata.Sources)
	}
	for _, row := range metadata.Resolved {
		version, ok := resolved[row.Path]
		if !ok || row.Version != version || row.Replacement != nil || version == "" && row.Sum != "" {
			t.Fatal("resolved public module row differs", row)
		}
	}
	for _, row := range metadata.Compiled {
		version, ok := compiled[row.Path]
		if !ok || row.Version != version || row.Replacement != nil || version == "(devel)" && row.Sum != "" || version != "(devel)" && row.Sum == "" {
			t.Fatal("compiled public module row differs", row)
		}
	}
	for _, source := range metadata.Sources {
		if !sourceOwners[source.Module] || source.Digest.IsZero() {
			t.Fatal("bound public source owner differs", source)
		}
	}
	info, err := buildinfo.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	if info.GoVersion != "go1.27.3" {
		t.Fatal("actual public executable uses a noncurrent compiler", info.GoVersion)
	}
	actual := map[string]string{info.Main.Path: info.Main.Version}
	actualSums := map[string]string{info.Main.Path: info.Main.Sum}
	if info.Main.Replace != nil {
		t.Fatal("actual workspace main replacement was fabricated")
	}
	for _, module := range info.Deps {
		if _, exists := actual[module.Path]; exists {
			t.Fatal("actual compiled owner repeated")
		}
		if module.Replace != nil {
			t.Fatal("actual workspace compiled replacement was fabricated")
		}
		actual[module.Path] = module.Version
		actualSums[module.Path] = module.Sum
	}
	if !reflect.DeepEqual(actual, compiled) {
		t.Fatal("actual compiled set contains a missing or extra public/private module", actual, compiled)
	}
	for _, row := range metadata.Compiled {
		if row.Sum != actualSums[row.Path] {
			t.Fatal("compiled checksum differs from actual executable build information", row)
		}
	}
	descriptor, err := metadata.Descriptor()
	if err != nil || !reflect.DeepEqual(descriptor, expectedDescriptor) || descriptor.Name != name || descriptor.Role != role || !reflect.DeepEqual(metadata.Contracts, []artifact.Contract{expectedDescriptor.Wire}) {
		t.Fatal("public tool changed the supplied author declaration", err)
	}
	facts, err := metadata.ExecutionFacts()
	if err != nil || metadata.Family == nil || metadata.Family.Schema != 2 || facts.Module != main || facts.Command != command || facts.GoVersion != metadata.Toolchain || facts.NativeTuple != metadata.Platform || facts.ArtifactSHA256 != metadata.Executable.SHA256 || facts.ArtifactLength != metadata.Executable.Length {
		t.Fatal("measured family execution facts differ", err)
	}
	// Independent framing uses the JSON declaration and the documented domain,
	// u32 byte lengths, exact executable digest, u64 length and measured strings.
	blob := func(body, value []byte) []byte {
		return append(binary.BigEndian.AppendUint32(body, uint32(len(value))), value...)
	}
	canonical, err := json.Marshal(expectedDescriptor)
	if err != nil {
		t.Fatal(err)
	}
	descriptorID := artifact.Digest(sha256.Sum256(blob([]byte("ENKV/PLUGIN-DESCRIPTOR/v1\x00"), canonical)))
	dependencyBody, err := os.ReadFile(filepath.Join(filepath.Dir(executable), "dependencies.bin"))
	if err != nil {
		t.Fatal(err)
	}
	dependencyID := artifact.Digest(sha256.Sum256(blob([]byte("ENKV/"+strings.ToUpper(role)+"/v3/dependency-manifest\x00"), dependencyBody)))
	executorBody := blob([]byte("ENKV/PLUGIN-EXECUTOR/v1\x00"), []byte(role))
	executorBody = append(executorBody, metadata.Executable.SHA256[:]...)
	executorBody = binary.BigEndian.AppendUint64(executorBody, metadata.Executable.Length)
	executorBody = append(executorBody, dependencyID[:]...)
	for _, value := range []string{main, command, metadata.Toolchain, metadata.Platform} {
		executorBody = blob(executorBody, []byte(value))
	}
	executorID := artifact.Digest(sha256.Sum256(executorBody))
	contractBody := append([]byte("ENKV/PLUGIN-ARTIFACT/v1\x00"), executorID[:]...)
	contractID := artifact.Digest(sha256.Sum256(append(contractBody, descriptorID[:]...)))
	if facts.DescriptorID != descriptorID || facts.DependencyManifestID != dependencyID || facts.ExecutorID != executorID || facts.ArtifactContractID != contractID {
		t.Fatal("family identities differ from independent framing")
	}
}

func publicPluginBuildTool(t *testing.T, ctx context.Context, maintained string) string {
	t.Helper()
	root := sourceFixtureRoot(t)
	copyPublicModuleKit(t, maintained, root, []string{"sdk/artifact"})
	tool := filepath.Join(t.TempDir(), "enkv-plugin-build")
	if _, err := runGo(ctx, root, "sdk/artifact", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", tool, "./cmd/enkv-plugin-build"); err != nil {
		t.Fatal(err)
	}
	return tool
}

func publicPluginBuildWorkspace(t *testing.T, ctx context.Context, directories []string) string {
	t.Helper()
	type requirement struct{ Path, Version string }
	type moduleFile struct {
		Module  struct{ Path string }
		Require []requirement
	}
	owners := make(map[string]string, len(directories))
	var requirements []requirement
	var work strings.Builder
	work.WriteString("go 1.27.0\n\nuse (\n")
	for _, directory := range directories {
		body := runModuleModeCommand(t, ctx, directory, map[string]string{"GOWORK": "off", "GOENV": "off", "GOFLAGS": "", "GOPROXY": "off", "GOSUMDB": "off", "GONOPROXY": "none"}, "mod", "edit", "-json", filepath.Join(directory, "go.mod"))
		var parsed moduleFile
		if err := json.Unmarshal(body, &parsed); err != nil {
			t.Fatal(err)
		}
		if parsed.Module.Path == "" || owners[parsed.Module.Path] != "" {
			t.Fatal("workspace module identity is missing or repeated", parsed.Module.Path)
		}
		owners[parsed.Module.Path] = directory
		requirements = append(requirements, parsed.Require...)
		fmt.Fprintf(&work, "\t%q\n", filepath.ToSlash(directory))
	}
	work.WriteString(")\n")
	seen := make(map[requirement]bool)
	var replacements []requirement
	for _, row := range requirements {
		if owners[row.Path] != "" && !seen[row] {
			seen[row] = true
			replacements = append(replacements, row)
		}
	}
	sort.Slice(replacements, func(i, j int) bool {
		if replacements[i].Path != replacements[j].Path {
			return replacements[i].Path < replacements[j].Path
		}
		return replacements[i].Version < replacements[j].Version
	})
	if len(replacements) != 0 {
		work.WriteString("\nreplace (\n")
		for _, row := range replacements {
			fmt.Fprintf(&work, "\t%s %s => %q\n", row.Path, row.Version, filepath.ToSlash(owners[row.Path]))
		}
		work.WriteString(")\n")
	}
	workspace := filepath.Join(t.TempDir(), "go.work")
	if err := os.WriteFile(workspace, []byte(work.String()), 0600); err != nil {
		t.Fatal(err)
	}
	return workspace
}

// full_only: false
func TestPublicPluginBuildCommandCapturesFirstPartyExecutables(t *testing.T) {
	ctx, cancel := context.WithTimeout(cacheOnlyGoContext(t.Context()), 10*time.Minute)
	defer cancel()
	maintained := maintainedCloudflareRoot(t)
	tool := publicPluginBuildTool(t, ctx, maintained)
	cases := []struct {
		name, role, selector, command string
		selectors                     []string
		remote                        map[string]string
	}{
		{"local-random-secret", "generator", "plugins/local-random-secret", "enkv-generator-local-random-secret", []string{"protocols/generator", "sdk/generator", "plugins/local-random-secret"}, nil},
		{"cloudflare-account-token", "generator", "plugins/cloudflare", "enkv-generator-cloudflare", []string{"protocols/generator", "sdk/generator", "plugins/cloudflare"}, nil},
		{"generic-json", "manifest-generator", "plugins/manifest-generators/generic-json", "enkv-manifest-generic-json", []string{"protocols/manifest-generator", "sdk/manifest-generator", "plugins/manifest-generators/generic-json"}, nil},
		{"opentofu-tfvars-json", "manifest-generator", "plugins/manifest-generators/opentofu-tfvars-json", "enkv-manifest-opentofu-tfvars-json", []string{"protocols/manifest-generator", "sdk/manifest-generator", "plugins/manifest-generators/opentofu-tfvars-json"}, nil},
		{"aws-secrets-manager", "output", "plugins/aws-output", "enkv-output-aws-secrets-manager", []string{"protocols/output", "sdk/output", "plugins/aws-output"}, awsOutputPins},
		{"gcp-secret-manager", "output", "plugins/gcp-output", "enkv-output-gcp-secret-manager", []string{"protocols/output", "sdk/output", "plugins/gcp-output"}, gcpOutputPins},
		{"github-actions-repository", "output", "plugins/github-output", "enkv-output-github-repository", []string{"protocols/output", "sdk/output", "plugins/github-output"}, githubOutputPins},
		{"github-actions-organization", "output", "plugins/github-output", "enkv-output-github-organization", []string{"protocols/output", "sdk/output", "plugins/github-output"}, githubOutputPins},
		{"github-actions-environment", "output", "plugins/github-output", "enkv-output-github-environment", []string{"protocols/output", "sdk/output", "plugins/github-output"}, githubOutputPins},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			root := sourceFixtureRoot(t)
			selectors := append([]string{"sdk/artifact"}, test.selectors...)
			copyPublicModuleKit(t, maintained, root, selectors)
			resolved := map[string]string{}
			requiredCompiled := map[string]bool{}
			var directories []string
			for _, selector := range selectors {
				owner, err := sourcePath(root, selector)
				if err != nil {
					t.Fatal(err)
				}
				directories = append(directories, owner)
				row, ok := registeredModule(selector)
				if !ok {
					t.Fatal("public source owner missing", selector)
				}
				resolved[row.Module] = ""
				if selector != "sdk/examples/testservice" {
					requiredCompiled[row.Module] = true
				}
			}
			for path, version := range test.remote {
				resolved[path] = version
			}
			workspace := publicPluginBuildWorkspace(t, ctx, directories)
			owner, err := sourcePath(root, test.selector)
			if err != nil {
				t.Fatal(err)
			}
			main, ok := registeredModule(test.selector)
			if !ok {
				t.Fatal("first-party source owner missing")
			}
			destination := publicPluginBuildOutput(t)
			relativeCommand := "./cmd/" + test.command
			descriptor := filepath.Join(owner, "cmd", test.command, "plugin.json")
			runPublicPluginBuildCommand(t, ctx, tool, root, "-directory", owner, "-descriptor", descriptor, "-command", relativeCommand, "-workspace", workspace, "-output", destination)
			metadata, err := artifact.VerifyBuild(ctx, destination)
			if err != nil {
				t.Fatal(err)
			}
			checkPublicPluginBuildResolvedFacts(t, ctx, owner, workspace, metadata)
			_, executable := publicPluginBuildSelection(t, destination)
			info, err := buildinfo.ReadFile(executable)
			if err != nil {
				t.Fatal(err)
			}
			compiled := map[string]string{info.Main.Path: info.Main.Version}
			for _, module := range info.Deps {
				if _, exists := compiled[module.Path]; exists {
					t.Fatal("actual compiled owner repeated", module.Path)
				}
				version, known := resolved[module.Path]
				if !known {
					t.Fatal("first-party executable contains an unbound or private module", module.Path)
				}
				if version == "" {
					version = "(devel)"
				}
				if module.Version != version || module.Replace != nil {
					t.Fatal("actual first-party dependency differs from workspace or pinned owner", module.Path)
				}
				compiled[module.Path] = module.Version
			}
			for path := range requiredCompiled {
				if compiled[path] != "(devel)" {
					t.Fatal("first-party command omitted a required public compiled owner", path)
				}
			}
			checkPublicPluginBuildFacts(t, metadata, descriptor, test.name, test.role, main.Module, main.Module+"/cmd/"+test.command, resolved, compiled, executable)
		})
	}
}

// full_only: false
func TestPublicPluginBuildCommandCapturesColdVersionedClosure(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	tool := publicPluginBuildTool(t, cacheOnlyGoContext(ctx), maintainedCloudflareRoot(t))
	const mainModule = "example.test/versioned-generator"
	const helperModule = "example.test/plugin-helper"
	proxy, helper, main := t.TempDir(), t.TempDir(), t.TempDir()
	for name, body := range map[string]string{"LICENSE": "L", "go.mod": "module " + helperModule + "\n\ngo 1.27.0\n"} {
		if err := os.WriteFile(filepath.Join(helper, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, version := range []string{"v1.0.0", "v1.1.0"} {
		body := "package helper\nfunc Message()string{return " + fmt.Sprintf("%q", version) + "}\n"
		if err := os.WriteFile(filepath.Join(helper, "helper.go"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		modbody, err := os.ReadFile(filepath.Join(helper, "go.mod"))
		if err != nil {
			t.Fatal(err)
		}
		writePublicModuleArchive(t, proxy, helper, helperModule, version, modbody)
	}
	for name, body := range map[string]string{"LICENSE": "L", "main.go": "package main\nimport \"" + helperModule + "\"\nfunc main(){println(helper.Message())}\n"} {
		if err := os.WriteFile(filepath.Join(main, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// The route literal is schema 1, contract {2}, environment mode, no names
	// and an empty public body. Its bytes are independent of the route encoder.
	route := make([]byte, 40)
	route[1], route[2], route[34] = 1, 2, 1
	descriptorValue := artifact.Descriptor{Schema: 1, Name: "private-versioned-generator", Role: "generator", Version: "1.2.3", Wire: artifact.Contract{Kind: "wire", Identity: strings.Repeat("01", 32), Version: 9}, Generator: &artifact.GeneratorDeclaration{ConfigContractID: artifact.Digest{3}, CredentialRoute: route}}
	descriptorBody, err := json.Marshal(descriptorValue)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := filepath.Join(main, "plugin.json")
	if err := os.WriteFile(descriptor, descriptorBody, 0600); err != nil {
		t.Fatal(err)
	}
	proxyURL := (&url.URL{Scheme: "file", Path: filepath.ToSlash(proxy)}).String()
	preparedCache := t.TempDir()
	preparedEnvironment := map[string]string{"GOWORK": "off", "GOPROXY": proxyURL, "GOSUMDB": "off", "GONOPROXY": "none", "GONOSUMDB": "none", "GOPRIVATE": "", "GOMODCACHE": preparedCache, "GOFLAGS": buildGoFlags + " -modcacherw"}
	destination := publicPluginBuildOutput(t)
	var previous versionedPluginBuild
	for index, version := range []string{"v1.0.0", "v1.1.0"} {
		mod := []byte("module " + mainModule + "\n\ngo 1.27.0\n\nrequire " + helperModule + " " + version + "\n")
		if err := os.WriteFile(filepath.Join(main, "go.mod"), mod, 0600); err != nil {
			t.Fatal(err)
		}
		runModuleModeCommand(t, ctx, main, preparedEnvironment, "mod", "download", "all")
		listed := runModuleModeCommand(t, ctx, main, preparedEnvironment, "list", "-mod=readonly", "-m", "-json", "all")
		owners, err := decodeObjects[resolvedModule](listed)
		if err != nil {
			t.Fatal(err)
		}
		if len(owners) != 2 {
			t.Fatal("prepared versioned graph differs", owners)
		}
		expected := map[string]artifact.Dependency{}
		for _, owner := range owners {
			if owner.Replace != nil {
				t.Fatal("versioned fixture contains a filesystem replacement")
			}
			if owner.Main {
				if owner.Path != mainModule || owner.Version != "" || owner.Sum != "" {
					t.Fatal("prepared main facts differ", owner)
				}
			} else if owner.Path != helperModule || owner.Version != version || owner.Sum == "" {
				t.Fatal("prepared pinned helper differs", owner)
			}
			expected[owner.Path] = artifact.Dependency{Path: owner.Path, Version: owner.Version, Sum: owner.Sum}
		}
		cache := publicPluginBuildOutput(t)
		entries, err := os.ReadDir(cache)
		if err != nil || len(entries) != 0 {
			t.Fatal("actual command module cache is not empty", err)
		}
		actualEnvironment := map[string]string{"GOWORK": "off", "GOPROXY": proxyURL, "GOSUMDB": "off", "GONOPROXY": "none", "GONOSUMDB": "none", "GOPRIVATE": "", "GOMODCACHE": cache}
		runPublicPluginBuildCommandEnvironment(t, ctx, tool, main, actualEnvironment, "-directory", main, "-descriptor", descriptor, "-command", ".", "-versioned", "-output", destination)
		metadata, err := artifact.VerifyBuild(ctx, destination)
		if err != nil {
			t.Fatal(err)
		}
		marker, executable := publicPluginBuildSelection(t, destination)
		checkPublicPluginBuildFacts(t, metadata, descriptor, "private-versioned-generator", "generator", mainModule, mainModule, map[string]string{mainModule: "", helperModule: version}, map[string]string{mainModule: "(devel)", helperModule: version}, executable)
		if len(metadata.Resolved) != len(expected) {
			t.Fatal("versioned resolved set differs")
		}
		for _, row := range metadata.Resolved {
			want, ok := expected[row.Path]
			if !ok || !reflect.DeepEqual(row, want) {
				t.Fatal("versioned actual resolved facts differ from independent go list", row, want)
			}
		}
		info, err := buildinfo.ReadFile(executable)
		if err != nil {
			t.Fatal(err)
		}
		if len(info.Deps) != 1 || info.Deps[0].Path != helperModule || info.Deps[0].Version != version || info.Deps[0].Sum != expected[helperModule].Sum || info.Deps[0].Replace != nil {
			t.Fatal("versioned executable differs from exact independent version/sum", info.Deps)
		}
		dependency, err := os.ReadFile(filepath.Join(destination, filepath.FromSlash(marker.Directory), "dependencies.bin"))
		if err != nil {
			t.Fatal(err)
		}
		if len(dependency) < 6 || binary.BigEndian.Uint16(dependency[:2]) != 3 {
			t.Fatal("versioned command did not produce schema-3 dependency bytes")
		}
		facts, err := artifact.DecodeDependency(dependency)
		if err != nil || !reflect.DeepEqual(facts, metadata.BuildFacts()) {
			t.Fatal("versioned dependency facts differ", err)
		}
		// Independent family framing: domain+NUL followed by u32 length and body.
		preimage := binary.BigEndian.AppendUint32([]byte("ENKV/GENERATOR/v3/dependency-manifest\x00"), uint32(len(dependency)))
		preimage = append(preimage, dependency...)
		dependencyID := artifact.Digest(sha256.Sum256(preimage))
		family, err := metadata.GeneratorFacts()
		if err != nil || family.DependencyManifestID != dependencyID {
			t.Fatal("versioned dependency identity differs from independent framing", err)
		}
		if index > 0 {
			if marker.Artifact == previous.marker.Artifact || dependencyID == previous.dependencyID {
				t.Fatal("versioned helper update retained an artifact or dependency identity")
			}
			if artifact.VerifyExecutable(ctx, executable, previous.metadata) == nil {
				t.Fatal("stale metadata admitted changed versioned executable")
			}
			if err := artifact.VerifyExecutable(ctx, previous.executable, previous.metadata); err != nil {
				t.Fatal("versioned update changed previous immutable bytes", err)
			}
		}
		previous = versionedPluginBuild{metadata: metadata, marker: marker, executable: executable, dependencyID: dependencyID}
	}
}

type versionedPluginBuild struct {
	metadata     artifact.Metadata
	marker       artifact.BuildMarker
	executable   string
	dependencyID artifact.Digest
}

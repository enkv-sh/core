package main

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"enkv.sh/compositions/outputhost"
	artifactpkg "enkv.sh/sdk/artifact"
	protocol "enkv.sh/sdk/protocols/output"
)

// full_only: false
func TestOutputClosureRequiresBoundBinaryAndSource(t *testing.T) {
	closure := testOutputClosure(t, "ENKV/OUTPUT/TEST-PROFILE/v3", false)
	if err := validateOutputArtifactClosures([]*outputArtifactClosure{closure}); err != nil {
		t.Fatal(err)
	}
	flag, err := outputFixtureLinkerFlag([]*outputArtifactClosure{closure})
	prefix := "-X '" + componentPackage + ".publicationFixtureExpectations="
	if err != nil || !strings.HasPrefix(flag, prefix) || !strings.HasSuffix(flag, "'") {
		t.Fatal("exact installed expectations missing", err)
	}
	var expected map[string][2]string
	if err := json.Unmarshal([]byte(strings.TrimSuffix(strings.TrimPrefix(flag, prefix), "'")), &expected); err != nil {
		t.Fatal(err)
	}
	body, err := outputInstallationBytes(closure)
	if err != nil {
		t.Fatal(err)
	}
	if len(expected) != 1 || expected[outputTestCommand] != [2]string{digestBytes(body), digestBytes(closure.DependencyManifest)} {
		t.Fatal("installation member bytes differ")
	}
	reordered := *closure
	reordered.ResolvedModules = slices.Clone(closure.ResolvedModules)
	slices.Reverse(reordered.ResolvedModules)
	retained := slices.Clone(reordered.ResolvedModules)
	if err := validateOutputArtifactClosures([]*outputArtifactClosure{&reordered}); err != nil {
		t.Fatal("equivalent graph order refused", err)
	}
	if !slices.Equal(retained, reordered.ResolvedModules) {
		t.Fatal("validation changed retained graph")
	}
	for name, change := range map[string]func(*outputArtifactClosure){
		"missing metadata":          func(v *outputArtifactClosure) { v.Metadata = nil },
		"missing protocol source":   func(v *outputArtifactClosure) { v.ProtocolSource = nil },
		"missing SDK source":        func(v *outputArtifactClosure) { v.SDKSource = nil },
		"missing plugin source":     func(v *outputArtifactClosure) { v.PluginSource = nil },
		"missing dependency":        func(v *outputArtifactClosure) { v.DependencyManifest = nil },
		"duplicate resolved module": func(v *outputArtifactClosure) { v.ResolvedModules = append(v.ResolvedModules, v.ResolvedModules[0]) },
		"missing resolved module":   func(v *outputArtifactClosure) { v.ResolvedModules = v.ResolvedModules[1:] },
		"changed resolved version":  func(v *outputArtifactClosure) { v.ResolvedModules[0].Version = "v9.0.0" },
		"extra resolved module": func(v *outputArtifactClosure) {
			v.ResolvedModules = append(v.ResolvedModules, moduleIdentity{Path: "example.invalid/extra", Version: "v1.0.0"})
		},
		"executor":          func(v *outputArtifactClosure) { v.Artifact.ExecutorID[0] ^= 1 },
		"artifact contract": func(v *outputArtifactClosure) { v.Artifact.ArtifactContractID[0] ^= 1 },
		"dependency ID":     func(v *outputArtifactClosure) { v.Artifact.DependencyManifestID[0] ^= 1 },
		"descriptor":        func(v *outputArtifactClosure) { v.Artifact.DescriptorID[0] ^= 1 },
		"config contract":   func(v *outputArtifactClosure) { v.Artifact.ConfigContractID = "another/config/v1" },
		"route contract":    func(v *outputArtifactClosure) { v.Artifact.CredentialRouteContractID = "" },
		"protocol":          func(v *outputArtifactClosure) { v.Artifact.ProtocolID[0] ^= 1 },
		"route":             func(v *outputArtifactClosure) { v.Artifact.CredentialRouteID = protocol.ID{} },
		"unsupported tuple": func(v *outputArtifactClosure) { v.Artifact.NativeTuple = "unsupported/tuple" },
		"compiler":          func(v *outputArtifactClosure) { v.Artifact.GoVersion = "go1.27.0" },
		"old family schema": func(v *outputArtifactClosure) { v.Artifact.Schema = 1 },
		"zero digest":       func(v *outputArtifactClosure) { v.Artifact.SHA256 = protocol.ID{} },
		"zero length":       func(v *outputArtifactClosure) { v.Artifact.Length = 0 },
		"oversize length":   func(v *outputArtifactClosure) { v.Artifact.Length = 1 << 63 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := *closure
			changed.ResolvedModules = slices.Clone(closure.ResolvedModules)
			change(&changed)
			if validateOutputArtifactClosures([]*outputArtifactClosure{&changed}) == nil {
				t.Fatal("damaged complete installation admitted")
			}
		})
	}
	root := sourceFixtureRoot(t)
	path := filepath.Join(filepath.Dir(root), "enkv-extensions", "sdk", "protocols", "output", "go.mod")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	original := []byte("retained source input")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	files := []artifactSourceFile{{Path: "go.mod", SHA256: digestBytes(original)}}
	if _, err := retainedOutputSourceDigest(root, "protocols/output", "enkv.sh/sdk/protocols/output", files); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("substituted source"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := retainedOutputSourceDigest(root, "protocols/output", "enkv.sh/sdk/protocols/output", files); err == nil {
		t.Fatal("source substitution admitted")
	}
}

// full_only: false
func TestOutputSourceDigestHasDistinctDomainAndExactInputs(t *testing.T) {
	root := sourceFixtureRoot(t)
	module := "protocols/output"
	directory := filepath.Join(filepath.Dir(root), "enkv-extensions", "sdk", "protocols", "output")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"LICENSE": "license", "go.mod": "module " + modulePath(module) + "\n\ngo 1.27.0\n", "wire.go": "package output\n"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	packages := []compiledPackage{{ImportPath: modulePath(module), Dir: directory, GoFiles: []string{"wire.go"}}}
	files, output, err := compiledSourceDigest(root, module, modulePath(module), outputSourceDomain, []string{"LICENSE", "go.mod"}, packages)
	if err != nil || len(files) != 3 || files[0].Path != "LICENSE" || files[1].Path != "go.mod" || files[2].Path != "wire.go" {
		t.Fatal("output source input set", files, err)
	}
	_, generator, err := compiledSourceDigest(root, module, modulePath(module), "ENKV/GENERATOR/v1/source-set\x00", []string{"LICENSE", "go.mod"}, packages)
	if err != nil || output == generator {
		t.Fatal("artifact source domains are not distinct", err)
	}
	if err := os.Remove(filepath.Join(directory, "LICENSE")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := compiledSourceDigest(root, module, modulePath(module), outputSourceDomain, []string{"LICENSE", "go.mod"}, packages); err == nil {
		t.Fatal("required output license was omitted")
	}
	if err := os.WriteFile(filepath.Join(directory, "LICENSE"), []byte("license"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "wire.go"), []byte("package output\nconst Changed = true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, changed, err := compiledSourceDigest(root, module, modulePath(module), outputSourceDomain, []string{"LICENSE", "go.mod"}, packages)
	if err != nil || output == changed {
		t.Fatal("output source bytes were not bound", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "go.sum"), []byte("optional input"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := compiledSourceDigest(root, module, modulePath(module), outputSourceDomain, []string{"LICENSE", "go.mod"}, nil); err == nil {
		t.Fatal("optional checksum file admitted an empty compiled source set")
	}
	packages[0].EmbedFiles = []string{"input.bin"}
	if _, _, err := compiledSourceDigest(root, module, modulePath(module), outputSourceDomain, []string{"LICENSE", "go.mod"}, packages); err == nil {
		t.Fatal("output admitted untracked embedded input")
	}
}

// full_only: false
func TestOutputAssemblyRejectsDifferentArtifactRaceMode(t *testing.T) {
	for _, race := range []bool{false, true} {
		for _, label := range []string{"ENKV/OUTPUT/TEST-PROFILE/v3", "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v3"} {
			command, _ := outputCommand(label)
			wantRace := race && command.module == outputTestModule
			closure := testOutputClosure(t, label, !wantRace)
			value := assembly{Closure: assemblyClosure{Race: race, OutputArtifacts: []*outputArtifactClosure{closure}}}
			if err := checkAssemblyRace(t.Context(), value); err == nil || !strings.Contains(err.Error(), "race mode differs") {
				t.Fatal("assembly race mismatch admitted", race, label, err)
			}
		}
	}
}

// full_only: false
func TestProductionOutputBindingsHaveExactProfilesAndFrozenSelection(t *testing.T) {
	first, err := productionOutputBinding("ENKV/OUTPUT/GITHUB-ENVIRONMENT/v3")
	if err != nil {
		t.Fatal(err)
	}
	second, err := productionOutputBinding("ENKV/OUTPUT/AWS-SECRETS-MANAGER/v3")
	if err != nil {
		t.Fatal(err)
	}
	input := []outputProfileBinding{first, second}
	selected, err := validateOutputBindings(input)
	if err != nil || len(selected) != 2 || selected[0] != second || selected[1] != first {
		t.Fatal("fixed qualification order", selected, err)
	}
	input[0].CredentialRouteID[0] ^= 1
	if selected[1] != first {
		t.Fatal("selection borrows mutable input")
	}
	for name, change := range map[string]func(*outputProfileBinding){
		"unknown":        func(v *outputProfileBinding) { v.StoredProfileID = "unknown" },
		"test":           func(v *outputProfileBinding) { v.StoredProfileID = "ENKV/OUTPUT/TEST-PROFILE/v3" },
		"route":          func(v *outputProfileBinding) { v.CredentialRouteID = protocol.ID{} },
		"descriptor":     func(v *outputProfileBinding) { v.DescriptorID = protocol.ID{} },
		"config":         func(v *outputProfileBinding) { v.ConfigContractID = "" },
		"route contract": func(v *outputProfileBinding) { v.CredentialRouteContractID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := first
			change(&changed)
			if _, err := validateOutputBindings([]outputProfileBinding{changed}); err == nil {
				t.Fatal("invalid qualification binding admitted")
			}
		})
	}
	for _, v := range [][]outputProfileBinding{{}, {first, first}} {
		if _, err := validateOutputBindings(v); err == nil {
			t.Fatal("empty or duplicate selection admitted")
		}
	}
}

// full_only: false
func TestProductionOutputClosureHasFiveSeparateExactCommandRows(t *testing.T) {
	var rows []*outputArtifactClosure
	for _, command := range outputProductionCommands {
		closure := testOutputClosure(t, command.label, false)
		binding, err := outputBinding(closure.Artifact)
		if err != nil {
			t.Fatal(err)
		}
		expected, err := productionOutputBinding(command.label)
		if err != nil || binding != expected {
			t.Fatal("named qualification command differs", binding, expected, err)
		}
		rows = append(rows, closure)
	}
	if err := validateOutputArtifactClosures(rows); err != nil {
		t.Fatal(err)
	}
	if err := validateOutputArtifactClosures(rows[:1]); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]*outputArtifactClosure{nil, {}, {nil}, {rows[0], rows[0]}, append(slices.Clone(rows), rows[0])} {
		if validateOutputArtifactClosures(bad) == nil {
			t.Fatal("invalid installation set admitted")
		}
	}
	changed := *rows[1]
	changed.Race = true
	if validateOutputArtifactClosures([]*outputArtifactClosure{rows[0], &changed}) == nil {
		t.Fatal("mixed race modes admitted")
	}
	testRow := testOutputClosure(t, "ENKV/OUTPUT/TEST-PROFILE/v3", false)
	if _, err := retainedOutputBindings([]*outputArtifactClosure{testRow}); err != nil {
		t.Fatal("separate controlled child refused", err)
	}
	if _, err := retainedOutputBindings([]*outputArtifactClosure{testRow, rows[0]}); err == nil {
		t.Fatal("controlled and official qualification selection mixed")
	}
	t.Run("private descriptor uses complete metadata", func(t *testing.T) {
		private := *rows[0]
		descriptor, err := private.Metadata.Descriptor()
		if err != nil {
			t.Fatal(err)
		}
		descriptor.Name = "private-output"
		descriptor.Output.ConfigContractID = "private-output/config/v7"
		private.Artifact.ModulePath = "private.invalid/output"
		private.Artifact.CommandPath = "private.invalid/output/cmd/publish"
		bindOutputTestMetadata(t, &private, descriptor)
		if err := validateOutputArtifactClosures([]*outputArtifactClosure{&private}); err != nil {
			t.Fatal("generic complete metadata admission used a named qualification case", err)
		}
	})
	wrong := *rows[2]
	wrong.Artifact.CommandPath = rows[3].Artifact.CommandPath
	if validateOutputArtifactClosures([]*outputArtifactClosure{&wrong}) == nil {
		t.Fatal("command substitution admitted")
	}
}

// full_only: false
func TestAssemblyBindingsCopySelectedInputs(t *testing.T) {
	binding, err := productionOutputBinding("ENKV/OUTPUT/GITHUB-REPOSITORY/v3")
	if err != nil {
		t.Fatal(err)
	}
	input := assemblyBindings{Cloudflare: &cloudflareAssemblyBinding{ArtifactSHA256: "before"}, Output: []outputProfileBinding{binding}}
	copied, err := copyAssemblyBindings(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Cloudflare.ArtifactSHA256 = "after"
	input.Output[0].CredentialRouteID[0] ^= 1
	if copied.Cloudflare.ArtifactSHA256 != "before" || copied.Output[0] != binding {
		t.Fatal("assembly borrows input")
	}
	empty, err := copyAssemblyBindings(assemblyBindings{})
	if err != nil || empty.Output != nil || empty.Cloudflare != nil {
		t.Fatal("default assembly changed", err)
	}
	if _, err := copyAssemblyBindings(assemblyBindings{Output: []outputProfileBinding{}}); err == nil {
		t.Fatal("explicit empty selection admitted")
	}
}

func testOutputClosure(t *testing.T, label string, race bool) *outputArtifactClosure {
	t.Helper()
	command, ok := outputCommand(label)
	if !ok {
		t.Fatal("unknown qualification case")
	}
	descriptor, _, err := readOutputDescriptor(t.Context(), maintainedCloudflareRoot(t), command)
	if err != nil {
		t.Fatal(err)
	}
	row := outputhost.Artifact{ModulePath: modulePath(command.module), CommandPath: modulePath(command.module) + "/cmd/" + command.command, GoVersion: "go1.27.3", NativeTuple: runtime.GOOS + "/" + runtime.GOARCH, SHA256: protocol.ID{4}, Length: 10}
	closure := &outputArtifactClosure{Race: race, Artifact: row, ProtocolSource: []artifactSourceFile{{Path: "go.mod", SHA256: strings.Repeat("a", 64)}}, SDKSource: []artifactSourceFile{{Path: "go.mod", SHA256: strings.Repeat("b", 64)}}, PluginSource: []artifactSourceFile{{Path: "go.mod", SHA256: strings.Repeat("c", 64)}}}
	bindOutputTestMetadata(t, closure, descriptor)
	return closure
}

func bindOutputTestMetadata(t *testing.T, closure *outputArtifactClosure, descriptor artifactpkg.Descriptor) {
	t.Helper()
	a := closure.Artifact
	options := []artifactpkg.BuildOption{}
	if closure.Race {
		options = append(options, artifactpkg.BuildOption{Name: "-race", Value: "true"})
	}
	source := artifactpkg.Digest(sha256.Sum256([]byte("structural source fixture")))
	facts := artifactpkg.BuildFacts{Role: "output", MainModule: a.ModulePath, Command: a.CommandPath, Platform: a.NativeTuple, Toolchain: a.GoVersion, BuildOptions: options, Contracts: []artifactpkg.Contract{descriptor.Wire}, Sources: []artifactpkg.Source{{Module: a.ModulePath, Digest: source}}, Resolved: []artifactpkg.Dependency{{Path: a.ModulePath}}, Compiled: []artifactpkg.Dependency{{Path: a.ModulePath, Version: "(devel)"}}}
	facts.Resolved = append(facts.Resolved, artifactpkg.Dependency{Path: "example.invalid/public-dependency", Version: "v1.0.0"})
	slices.SortFunc(facts.Resolved, func(a, b artifactpkg.Dependency) int { return strings.Compare(a.Path, b.Path) })
	body, err := artifactpkg.EncodeDependency(facts)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := outputArtifactMetadata(descriptor, artifactpkg.Digest(a.SHA256), a.Length, facts, body)
	if err != nil {
		t.Fatal(err)
	}
	installation, err := outputhost.NewInstallation(metadata, body)
	if err != nil {
		t.Fatal(err)
	}
	closure.Artifact, closure.Metadata, closure.DependencyManifest = installation.Artifact(), &metadata, body
	closure.ResolvedModules = []moduleIdentity{{Path: a.ModulePath, Version: "local"}, {Path: "example.invalid/public-dependency", Version: "v1.0.0"}}
}

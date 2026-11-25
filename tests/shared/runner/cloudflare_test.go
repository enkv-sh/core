package main

import (
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/generatorhost"
	"enkv.sh/core/contract"
	"enkv.sh/sdk/artifact"
)

// full_only: false
func TestCloudflareDescriptorMatchesPublicContract(t *testing.T) {
	root := maintainedCloudflareRoot(t)
	production, _, err := readCloudflareDescriptor(t.Context(), root, false)
	if err != nil {
		t.Fatal(err)
	}
	tagged, _, err := readCloudflareDescriptor(t.Context(), root, true)
	if err != nil || !reflect.DeepEqual(production, tagged) {
		t.Fatal("tagged transport changed the declared semantic contract", err)
	}
	if production.Schema != 1 || production.Name != "cloudflare-account-token" || production.Version != "0.1.1" || production.Role != "generator" || production.Generator == nil || production.Generator.ConfigContractID.String() != "7ede2a15bbf86395c097322b651f2752f9adf1bdfa346f09683e20e670ff10c1" || !slices.Equal([]artifact.Contract{production.Wire}, cloudflareCurrentContractVector()) {
		t.Fatal("official descriptor differs", production)
	}
	canonical, err := artifact.EncodeDescriptor(production)
	if err != nil {
		t.Fatal(err)
	}
	preimage := binary.BigEndian.AppendUint32([]byte("ENKV/PLUGIN-DESCRIPTOR/v1\x00"), uint32(len(canonical)))
	expected := sha256.Sum256(append(preimage, canonical...))
	id, err := production.Identity()
	if err != nil || id != artifact.Digest(expected) {
		t.Fatal("descriptor identity differs from independent framing", err)
	}
}

// full_only: false
func TestCloudflareBuildCommandsAreFixedAndSeparate(t *testing.T) {
	production := []string{"go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", "<artifact>", "./cmd/enkv-generator-cloudflare"}
	testArtifact := []string{"go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-tags=enkv_cloudflare_testartifact",
		"-ldflags=-X=enkv.sh/plugins/generators/cloudflare-account-token/internal/cloudflare.unqualifiedTestArtifactOrigin=https://127.0.0.1.invalid/client/v4",
		"-o", "<artifact>", "./cmd/enkv-generator-cloudflare-test"}
	if !reflect.DeepEqual(cloudflareRecordedBuildCommand(false, false), production) || !reflect.DeepEqual(cloudflareRecordedBuildCommand(true, false), testArtifact) {
		t.Fatal("Cloudflare build command changed")
	}
	production = slices.Insert(production, 5, "-race")
	testArtifact = slices.Insert(testArtifact, 7, "-race")
	if !reflect.DeepEqual(cloudflareRecordedBuildCommand(false, true), production) || !reflect.DeepEqual(cloudflareRecordedBuildCommand(true, true), testArtifact) {
		t.Fatal("race-enabled Cloudflare build command changed")
	}
	t.Setenv("CGO_ENABLED", "1")
	t.Setenv("GOFLAGS", "-race -tags=untrusted")
	env := stockPluginBuildEnvironment()
	for _, want := range []string{"CGO_ENABLED=0", "GOFLAGS=" + buildGoFlags, "GOENV=off", "GOTOOLCHAIN=local", "GOWORK=off"} {
		if !slices.Contains(env, want) {
			t.Fatal("production plugin environment changed", want)
		}
	}
	if outputBuildEnvironment(outputProfileCommand{module: outputTestModule}) != nil {
		t.Fatal("private artifact lost its separate build environment")
	}
}

// full_only: false
func TestCloudflareBoundaryAdmitsOnlyGeneratorPublicModulesAndStandardLibrary(t *testing.T) {
	modules := []resolvedModule{
		{Path: cloudflareModulePath},
		{Path: generatorSDKPath, Version: "v0.1.1", Replace: &resolvedModule{Path: "../../../sdk/generator"}},
		{Path: cloudflareProtocolPath, Version: "v0.1.1", Replace: &resolvedModule{Path: "../../../sdk/protocols/generator"}},
		{Path: "enkv.sh/sdk/artifact", Version: "v0.1.1", Replace: &resolvedModule{Path: "../../../sdk/artifact"}},
	}
	packages := []compiledPackage{
		{ImportPath: cloudflareModulePath + "/internal/cloudflare"},
		{ImportPath: cloudflareProtocolPath},
		{ImportPath: generatorSDKPath},
		{ImportPath: "net/http", Standard: true},
	}
	if err := checkBoundary(cloudflareModule, modules, packages); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct {
		modules  []resolvedModule
		packages []compiledPackage
	}{
		{append(slices.Clone(modules), resolvedModule{Path: modulePrefix + "core"}), packages},
		{append(slices.Clone(modules), resolvedModule{Path: modulePrefix + "crypto"}), packages},
		{append(slices.Clone(modules), resolvedModule{Path: "github.com/cloudflare/cloudflare-go"}), packages},
		{modules, append(slices.Clone(packages), compiledPackage{ImportPath: modulePrefix + "compositions/generatorhost"})},
		{modules, append(slices.Clone(packages), compiledPackage{ImportPath: "github.com/cloudflare/cloudflare-go"})},
		{modules[:1], packages},
		{modules[:2], packages},
		{modules[:3], packages},
		{append(slices.Clone(modules[:1]), modules[2:]...), packages},
	} {
		if checkBoundary(cloudflareModule, mutation.modules, mutation.packages) == nil {
			t.Fatal("Cloudflare open boundary admitted a proprietary or external dependency")
		}
	}
}

// full_only: false
func TestCloudflareModuleDefinitionIsExact(t *testing.T) {
	validMod := "module " + cloudflareModulePath + "\n\ngo 1.27.0\n\nrequire (\nenkv.sh/sdk/artifact v0.1.1\n" + cloudflareProtocolPath + " v0.1.1\n" + generatorSDKPath + " v0.1.1\n)\n"

	for _, test := range []struct {
		name, mod, pluginLicense string
		valid                    bool
	}{
		{name: "exact", mod: validMod, pluginLicense: "Apache License\n                           Version 2.0\n", valid: true},
		{name: "different language minimum", mod: strings.Replace(validMod, "go 1.27.0", "go 1.27.1", 1), pluginLicense: "Apache License\n                           Version 2.0\n"},
		{name: "compiler patch is not the language minimum", mod: strings.Replace(validMod, "go 1.27.0", "go 1.27.3", 1), pluginLicense: "Apache License\n                           Version 2.0\n"},
		{name: "unexpected dependency", mod: strings.Replace(validMod, "require (", "require (\nexample.invalid/sdk v1.0.0", 1), pluginLicense: "Apache License\n                           Version 2.0\n"},
		{name: "missing helper", mod: strings.Replace(validMod, generatorSDKPath+" v0.1.1\n", "", 1), pluginLicense: "Apache License\n                           Version 2.0\n"},
		{name: "permanent helper replacement", mod: validMod + "\nreplace " + generatorSDKPath + " => ../../../sdk/generator\n", pluginLicense: "Apache License\n                           Version 2.0\n"},
		{name: "different license", mod: validMod, pluginLicense: "not Apache-2.0\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := sourceFixtureRoot(t)
			license := "Apache License\n                           Version 2.0\n"
			for path, body := range map[string]string{
				cloudflareModule + "/go.mod":          test.mod,
				cloudflareModule + "/LICENSE":         test.pluginLicense,
				cloudflareProtocolModule + "/LICENSE": license,
				cloudflareSDKModule + "/LICENSE":      license,
				"sdk/artifact/LICENSE":                license,
			} {
				full, err := sourcePath(root, path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil || os.WriteFile(full, []byte(body), 0600) != nil {
					t.Fatal("module fixture unavailable")
				}
			}
			err := checkCloudflareModuleDefinition(context.Background(), root)
			if (err == nil) != test.valid {
				t.Fatalf("module validity differs: %v", err)
			}
		})
	}
}

// full_only: false
func TestCloudflareSourceDigestBindsExactGoInputsAndRejectsOthers(t *testing.T) {
	root := sourceFixtureRoot(t)
	moduleRoot, err := sourcePath(root, cloudflareProtocolModule)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"LICENSE": "license", "go.mod": "module " + cloudflareProtocolPath + "\n\ngo 1.27.0\n", "wire.go": "package generator\n"} {
		path := filepath.Join(moduleRoot, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil || os.WriteFile(path, []byte(body), 0600) != nil {
			t.Fatal("source fixture unavailable")
		}
	}
	packages := []compiledPackage{{ImportPath: cloudflareProtocolPath, Dir: moduleRoot, GoFiles: []string{"wire.go"}}}
	files, first, err := compiledSourceDigest(root, cloudflareProtocolModule, cloudflareProtocolPath, "ENKV/GENERATOR/v1/source-set\x00", []string{"LICENSE", "go.mod"}, packages)
	if err != nil || len(files) != 3 || files[0].Path != "LICENSE" || files[1].Path != "go.mod" || files[2].Path != "wire.go" {
		t.Fatal("exact source input set differs", files, err)
	}
	if got := hex.EncodeToString(first[:]); got != "e43123df38c0e3511c4a693e3fa5f7798439faf6c0b01ba0528f6b01c3186708" {
		t.Fatal("generator source digest changed", got)
	}
	if err := os.WriteFile(filepath.Join(moduleRoot, "wire.go"), []byte("package generator\n\nconst changed = true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, second, err := compiledSourceDigest(root, cloudflareProtocolModule, cloudflareProtocolPath, "ENKV/GENERATOR/v1/source-set\x00", []string{"LICENSE", "go.mod"}, packages)
	if err != nil || first == second {
		t.Fatal("source bytes did not bind the digest")
	}
	packages[0].EmbedFiles = []string{"embedded.bin"}
	if _, _, err := compiledSourceDigest(root, cloudflareProtocolModule, cloudflareProtocolPath, "ENKV/GENERATOR/v1/source-set\x00", []string{"LICENSE", "go.mod"}, packages); err == nil {
		t.Fatal("missing embedded build input was not refused")
	}
	if err := os.WriteFile(filepath.Join(moduleRoot, "embedded.bin"), []byte("declared descriptor"), 0600); err != nil {
		t.Fatal(err)
	}
	files, embedded, err := compiledSourceDigest(root, cloudflareProtocolModule, cloudflareProtocolPath, "ENKV/GENERATOR/v1/source-set\x00", []string{"LICENSE", "go.mod"}, packages)
	if err != nil || embedded == second || !slices.ContainsFunc(files, func(file artifactSourceFile) bool { return file.Path == "embedded.bin" }) {
		t.Fatal("embedded build bytes did not bind source identity", err)
	}
	if err := os.WriteFile(filepath.Join(moduleRoot, "embedded.bin"), []byte("changed descriptor"), 0600); err != nil {
		t.Fatal(err)
	}
	_, changedEmbedded, err := compiledSourceDigest(root, cloudflareProtocolModule, cloudflareProtocolPath, "ENKV/GENERATOR/v1/source-set\x00", []string{"LICENSE", "go.mod"}, packages)
	if err != nil || changedEmbedded == embedded {
		t.Fatal("changed embedded bytes did not change source identity", err)
	}
	packages[0].GoFiles = nil
	if _, _, err := compiledSourceDigest(root, cloudflareProtocolModule, cloudflareProtocolPath, "ENKV/GENERATOR/v1/source-set\x00", []string{"LICENSE", "go.mod"}, packages); err == nil {
		t.Fatal("embedded data without selected Go source admitted")
	}
	packages[0].GoFiles = []string{"wire.go"}
	packages[0].EmbedFiles = []string{"../outside.bin"}
	if _, _, err := compiledSourceDigest(root, cloudflareProtocolModule, cloudflareProtocolPath, "ENKV/GENERATOR/v1/source-set\x00", []string{"LICENSE", "go.mod"}, packages); err == nil {
		t.Fatal("escaped embedded input admitted")
	}
	for _, owner := range []struct {
		name, selector, domain string
		required               []string
	}{
		{"public", cloudflareProtocolModule, "ENKV/GENERATOR/v1/source-set\x00", []string{"LICENSE", "go.mod"}},
		{"controlled", "plugins/output-contract-test", outputSourceDomain, []string{"go.mod"}},
	} {
		t.Run("present_metadata_inventory/"+owner.name, func(t *testing.T) {
			root := sourceFixtureRoot(t)
			directory, err := sourcePath(root, owner.selector)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(directory, 0700); err != nil {
				t.Fatal(err)
			}
			module := modulePath(owner.selector)
			inputs := map[string]string{"LICENSE": "license\n", "LICENSE.txt": "text license\n", "LICENSE.md": "markdown license\n", "NOTICE": "notice\n", "NOTICE.txt": "text notice\n", "THIRD_PARTY_NOTICES.md": "third party notices\n", "go.mod": "module " + module + "\n\ngo 1.27.0\n", "go.sum": "checksums\n", "wire.go": "package fixture\n"}
			for name, body := range inputs {
				if err := os.WriteFile(filepath.Join(directory, name), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			packages := []compiledPackage{{ImportPath: module, Dir: directory, GoFiles: []string{"wire.go"}}}
			checkFiles := func(t *testing.T, files []artifactSourceFile) {
				t.Helper()
				var expected []artifactSourceFile
				for _, name := range []string{"LICENSE", "LICENSE.md", "LICENSE.txt", "NOTICE", "NOTICE.txt", "THIRD_PARTY_NOTICES.md", "go.mod", "go.sum", "wire.go"} {
					sum := sha256.Sum256([]byte(inputs[name]))
					expected = append(expected, artifactSourceFile{Path: name, SHA256: hex.EncodeToString(sum[:])})
				}
				if !reflect.DeepEqual(files, expected) {
					t.Errorf("source evidence file set or hashes differ: got=%+v want=%+v", files, expected)
				}
			}
			files, first, err := compiledSourceDigest(root, owner.selector, module, owner.domain, owner.required, packages)
			if err != nil {
				t.Fatal(err)
			}
			checkFiles(t, files)
			for _, name := range []string{"LICENSE", "LICENSE.txt", "LICENSE.md", "NOTICE", "NOTICE.txt", "THIRD_PARTY_NOTICES.md", "go.mod", "go.sum"} {
				t.Run(name, func(t *testing.T) {
					original := inputs[name]
					inputs[name] += "changed\n"
					if err := os.WriteFile(filepath.Join(directory, name), []byte(inputs[name]), 0600); err != nil {
						t.Fatal(err)
					}
					files, changed, err := compiledSourceDigest(root, owner.selector, module, owner.domain, owner.required, packages)
					if err != nil {
						t.Fatal(err)
					}
					checkFiles(t, files)
					if changed == first {
						t.Error("present metadata bytes did not change source identity", name)
					}
					inputs[name] = original
					if err := os.WriteFile(filepath.Join(directory, name), []byte(original), 0600); err != nil {
						t.Fatal(err)
					}
				})
			}
		})
	}
}

// full_only: false
func TestCloudflareArtifactAssemblyOnMaintainedSource(t *testing.T) {
	root := maintainedCloudflareRoot(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	race, err := binaryRace(executable)
	if err != nil {
		t.Fatal("executing test binary race policy unavailable", err)
	}
	ctx, cancel := context.WithTimeout(withRacePolicy(t.Context(), race), 2*time.Minute)
	defer cancel()
	directory := t.TempDir()
	evidence, err := buildCloudflareArtifacts(ctx, root, directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("production-determinism", func(t *testing.T) {
		repeat := filepath.Join(directory, "production-repeat")
		if _, err := runGoEnvironment(withRacePolicy(ctx, false), root, cloudflareModule, stockPluginBuildEnvironment(), cloudflareProductionBuildArgs(repeat, false)...); err != nil {
			t.Fatal(err)
		}
		digest, length, err := cloudflareArtifactIdentity(repeat)
		if err != nil || hex.EncodeToString(digest[:]) != evidence.ProductionSHA256 || length != evidence.ProductionLength {
			t.Fatal("production construction is not deterministic", err)
		}
	})
	if !reflect.DeepEqual(evidence.ProductionBuildCommand, cloudflareRecordedBuildCommand(false, false)) ||
		!reflect.DeepEqual(evidence.TestBuildCommand, cloudflareRecordedBuildCommand(true, race)) {
		t.Fatal("recorded Cloudflare build commands differ from accepted race mode", evidence)
	}
	for _, name := range []string{"enkv-generator-cloudflare", "enkv-generator-cloudflare-test"} {
		wantRace := race && name == "enkv-generator-cloudflare-test"
		observed, err := binaryRace(filepath.Join(directory, name))
		if err != nil || observed != wantRace {
			t.Errorf("fresh Cloudflare artifact %s race policy differs from its construction: got %t want %t: %v", name, observed, wantRace, err)
		}
	}
	if evidence.GoVersion != "go1.27.3" || !slices.Contains(cloudflareSupportedTuples, evidence.NativeTuple) ||
		len(evidence.ProtocolSourceSHA256) != 64 || len(evidence.SDKSourceSHA256) != 64 || len(evidence.TestProtocolSourceSHA256) != 64 || len(evidence.TestSDKSourceSHA256) != 64 || len(evidence.PluginSourceSHA256) != 64 || len(evidence.DependencyManifestSHA256) != 64 ||
		len(evidence.TestPluginSourceSHA256) != 64 || len(evidence.TestDependencyManifestSHA256) != 64 ||
		evidence.ProductionLength == 0 || evidence.TestLength == 0 || evidence.ProductionSHA256 == evidence.TestSHA256 {
		t.Fatal("Cloudflare artifact evidence is incomplete", evidence)
	}
	metadata, err := artifact.DecodeMetadata(evidence.ProductionMetadata)
	if err != nil {
		t.Fatal("production metadata unavailable", err)
	}
	if !slices.Equal(metadata.Contracts, cloudflareCurrentContractVector()) || metadata.Family == nil || metadata.Family.Schema != artifact.FamilySchema {
		t.Fatal("fresh package contract set or outer family schema differs")
	}
	family, err := metadata.GeneratorFacts()
	descriptor, _, descriptorErr := readCloudflareDescriptor(ctx, root, false)
	if err != nil || descriptorErr != nil || family.Schema != artifact.FamilySchema || !reflect.DeepEqual(family.Descriptor, descriptor) || family.Module != cloudflareModulePath || family.Command != cloudflareProductionMain || family.ArtifactSHA256.String() != evidence.ProductionSHA256 || family.ArtifactLength != uint64(evidence.ProductionLength) || family.DependencyManifestID.String() != evidence.DependencyManifestSHA256 {
		t.Fatal("fresh measured generator family differs", err, descriptorErr)
	}
	testMetadata, err := artifact.DecodeMetadata(evidence.TestMetadata)
	if err != nil {
		t.Fatal("tagged metadata unavailable", err)
	}
	testFamily, err := testMetadata.GeneratorFacts()
	if err != nil || !reflect.DeepEqual(testFamily.Descriptor, descriptor) || testFamily.Command != cloudflareTestArtifactMain || testFamily.ArtifactSHA256.String() != evidence.TestSHA256 || testFamily.ArtifactLength != uint64(evidence.TestLength) || testFamily.DependencyManifestID.String() != evidence.TestDependencyManifestSHA256 || testFamily.ExecutorID == family.ExecutorID || testFamily.ArtifactContractID == family.ArtifactContractID {
		t.Fatal("tagged build lost exact independent execution binding", err)
	}
	installed, err := generatorhost.NewInstallation(metadata, evidence.DependencyManifest)
	if err != nil {
		t.Fatal("normal installed admission refused", err)
	}
	var account contract.ID
	copy(account[:], strings.Repeat("a", 32))
	row := installed.Artifact()
	if row.Validate() != nil || row.ConfigContractID != contract.ID(descriptor.Generator.ConfigContractID) || !slices.Equal(row.CredentialRoute, descriptor.Generator.CredentialRoute) {
		t.Fatal("normal installed route binding differs", err)
	}
	if err := generatorhost.VerifyInstalledArtifact(ctx, filepath.Join(directory, "enkv-generator-cloudflare"), installed); err != nil {
		t.Fatal("actual production bytes or build info differ", err)
	}
	testInstalled, err := generatorhost.NewInstallation(testMetadata, evidence.TestDependencyManifest)
	if err != nil {
		t.Fatal("normal tagged installation refused", err)
	}
	if err := generatorhost.VerifyInstalledArtifact(ctx, filepath.Join(directory, "enkv-generator-cloudflare-test"), testInstalled); err != nil {
		t.Fatal("actual tagged bytes or build info differ", err)
	}
	if race, err := binaryRace(filepath.Join(directory, "enkv-generator-cloudflare")); err != nil || race {
		t.Fatal("production generator inherited assembly race", race, err)
	}
	binding, err := cloudflareBinding(evidence, string(account[:]))
	if err != nil {
		t.Fatal(err)
	}
	flag, err := cloudflareFixtureLinkerFlag(directory, binding)
	if err != nil || !strings.Contains(flag, digestBytes(binding.Installation)) || !strings.Contains(flag, digestBytes(binding.Dependency)) {
		t.Fatal("fixture did not bind metadata and dependency bytes", err)
	}
	var envelope struct {
		Artifact contract.GeneratorImplementation `json:"artifact"`
	}
	if json.Unmarshal(binding.Installation, &envelope) != nil || !reflect.DeepEqual(envelope.Artifact, row) {
		t.Fatal("fixture changed the complete measured row")
	}
	t.Logf("go=%s tuple=%s protocol_source_sha256=%s sdk_source_sha256=%s plugin_source_sha256=%s dependency_manifest_sha256=%s test_plugin_source_sha256=%s test_dependency_manifest_sha256=%s production_sha256=%s production_length=%d test_sha256=%s test_length=%d",
		evidence.GoVersion, evidence.NativeTuple, evidence.ProtocolSourceSHA256, evidence.SDKSourceSHA256, evidence.PluginSourceSHA256, evidence.DependencyManifestSHA256,
		evidence.TestPluginSourceSHA256, evidence.TestDependencyManifestSHA256,
		evidence.ProductionSHA256, evidence.ProductionLength, evidence.TestSHA256, evidence.TestLength)
	for _, build := range []struct {
		body                          []byte
		id, command, tags, executable string
		sources                       map[string]string
	}{
		{evidence.DependencyManifest, evidence.DependencyManifestSHA256, cloudflareProductionMain, "", filepath.Join(directory, "enkv-generator-cloudflare"), map[string]string{cloudflareModulePath: evidence.PluginSourceSHA256, generatorSDKPath: evidence.SDKSourceSHA256, cloudflareProtocolPath: evidence.ProtocolSourceSHA256}},
		{evidence.TestDependencyManifest, evidence.TestDependencyManifestSHA256, cloudflareTestArtifactMain, cloudflareTestArtifactTag, filepath.Join(directory, "enkv-generator-cloudflare-test"), map[string]string{cloudflareModulePath: evidence.TestPluginSourceSHA256, generatorSDKPath: evidence.TestSDKSourceSHA256, cloudflareProtocolPath: evidence.TestProtocolSourceSHA256}},
	} {
		if len(build.body) < 6 || binary.BigEndian.Uint16(build.body) != 3 {
			t.Fatal("current build did not use schema3")
		}
		facts, err := artifact.DecodeDependency(build.body)
		if err != nil {
			t.Fatal(err)
		}
		if facts.Role != "generator" || facts.MainModule != cloudflareModulePath || facts.Command != build.command || facts.Platform != evidence.NativeTuple || facts.Toolchain != "go1.27.3" || len(facts.Sources) != 4 || len(facts.Resolved) != 4 || len(facts.Compiled) != 4 {
			t.Fatal("current whole build facts differ", facts)
		}
		resolvedPaths := make([]string, 0, len(facts.Resolved))
		for _, row := range facts.Resolved {
			resolvedPaths = append(resolvedPaths, row.Path)
		}
		compiledPaths := make([]string, 0, len(facts.Compiled))
		for _, row := range facts.Compiled {
			compiledPaths = append(compiledPaths, row.Path)
		}
		if !slices.Equal(resolvedPaths, []string{cloudflareModulePath, "enkv.sh/sdk/artifact", generatorSDKPath, cloudflareProtocolPath}) || !slices.Equal(compiledPaths, []string{cloudflareModulePath, "enkv.sh/sdk/artifact", generatorSDKPath, cloudflareProtocolPath}) {
			t.Fatal("resolved or compiled whole owner set differs", resolvedPaths, compiledPaths)
		}
		build.sources["enkv.sh/sdk/artifact"] = "public-artifact-inputs"
		for _, source := range facts.Sources {
			if source.Module == "enkv.sh/sdk/artifact" {
				if source.Digest.IsZero() {
					t.Fatal("compiled artifact module inputs missing")
				}
				delete(build.sources, source.Module)
				continue
			}
			if build.sources[source.Module] != source.Digest.String() {
				t.Fatal("source binding differs", source)
			}
			delete(build.sources, source.Module)
		}
		if len(build.sources) != 0 {
			t.Fatal("source owner missing", build.sources)
		}
		options := map[string]string{}
		for _, option := range facts.BuildOptions {
			options[option.Name] = option.Value
		}
		if options["-trimpath"] != "true" || options["-tags"] != build.tags {
			t.Fatal("exact build settings differ", options)
		}
		info, err := buildinfo.ReadFile(build.executable)
		if err != nil {
			t.Fatal(err)
		}
		expectedOptions := make([]artifact.BuildOption, 0, len(info.Settings))
		for _, setting := range info.Settings {
			expectedOptions = append(expectedOptions, artifact.BuildOption{Name: setting.Key, Value: setting.Value})
		}
		slices.SortFunc(expectedOptions, func(a, b artifact.BuildOption) int { return strings.Compare(a.Name, b.Name) })
		if !reflect.DeepEqual(facts.BuildOptions, expectedOptions) {
			t.Fatal("build options differ from actual executable settings", facts.BuildOptions, expectedOptions)
		}
		// Derive the expected family identity with the documented SHA-256
		// framing, without calling the public identity function.
		preimage := binary.BigEndian.AppendUint32([]byte("ENKV/GENERATOR/v3/dependency-manifest\x00"), uint32(len(build.body)))
		expected := sha256.Sum256(append(preimage, build.body...))
		if hex.EncodeToString(expected[:]) != build.id {
			t.Fatal("dependency identity differs", build.id)
		}
	}
	for _, source := range evidence.PluginSourceFiles {
		if strings.Contains(source.Path, "testartifact") || strings.Contains(source.Path, "enkv-generator-cloudflare-test") || strings.HasSuffix(source.Path, "_test.go") {
			t.Fatal("test-only source entered the production digest", source.Path)
		}
	}
	for _, source := range append(slices.Clone(evidence.ProtocolSourceFiles), evidence.SDKSourceFiles...) {
		if strings.HasSuffix(source.Path, "_test.go") {
			t.Fatal("protocol test source entered the production digest", source.Path)
		}
	}
	if !slices.ContainsFunc(evidence.PluginSourceFiles, func(source artifactSourceFile) bool {
		return source.Path == "cmd/enkv-generator-cloudflare/plugin.json"
	}) ||
		!slices.ContainsFunc(evidence.TestPluginSourceFiles, func(source artifactSourceFile) bool {
			return source.Path == "cmd/enkv-generator-cloudflare-test/plugin.json"
		}) {
		t.Fatal("selected embedded descriptor is missing from exact source inventory")
	}
	if !slices.ContainsFunc(evidence.TestPluginSourceFiles, func(source artifactSourceFile) bool { return source.Path == "internal/cloudflare/testartifact.go" }) ||
		!slices.ContainsFunc(evidence.TestPluginSourceFiles, func(source artifactSourceFile) bool {
			return source.Path == "cmd/enkv-generator-cloudflare-test/main.go"
		}) {
		t.Fatal("tagged test source set is incomplete")
	}
}

// full_only: false
func TestCloudflareMaintainedModuleClosesOpenBoundary(t *testing.T) {
	root := maintainedCloudflareRoot(t)
	ctx, cancel := context.WithTimeout(testRaceContext(t, t.Context()), 2*time.Minute)
	defer cancel()
	checked, err := checkModule(ctx, root, cloudflareModule)
	if err != nil {
		t.Fatal(err)
	}
	closure := checked.closure
	if closure.Suite != "unit" || closure.Provider != cloudflareModule || len(closure.ResolvedModules) != 4 || closure.Race != raceEnabled(ctx) || !validRaceSettings(closure.Race, closure.RaceOptions, closure.RaceExitSleepMillis) {
		t.Fatal("Cloudflare module closure differs", closure)
	}
	for _, module := range closure.ResolvedModules {
		if module.Path != cloudflareModulePath && module.Path != cloudflareProtocolPath && module.Path != generatorSDKPath && module.Path != "enkv.sh/sdk/artifact" {
			t.Fatal("proprietary or external module reached Cloudflare", module)
		}
	}
	for _, imported := range closure.CompiledImports {
		if strings.HasPrefix(imported, modulePrefix) && !withinModule(imported, cloudflareModulePath) && !withinModule(imported, cloudflareProtocolPath) && !withinModule(imported, generatorSDKPath) && !withinModule(imported, "enkv.sh/sdk/artifact") {
			t.Fatal("proprietary import reached Cloudflare", imported)
		}
	}
}

func maintainedCloudflareRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "core", "go.mod")); err == nil {
			return directory
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatal("maintained Cloudflare module was not found")
		}
		directory = parent
	}
}

// full_only: false
func TestGeneratorSourceKitBuildsWithoutImplementationSources(t *testing.T) {
	maintained := maintainedCloudflareRoot(t)
	kit := t.TempDir()
	root := filepath.Join(kit, "implementation")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	copyPublicModuleKit(t, maintained, root, []string{cloudflareProtocolModule, cloudflareSDKModule, "sdk/artifact", cloudflareModule})
	ctx, cancel := context.WithTimeout(cacheOnlyGoContext(testRaceContext(t, t.Context())), 2*time.Minute)
	defer cancel()
	ctx = withRacePolicy(ctx, false)
	env := stockPluginBuildEnvironment()
	if err := checkCloudflareModuleDefinition(ctx, root); err != nil {
		t.Fatal(err)
	}
	modules, packages, err := listClosureEnvironment(runGoEnvironment, ctx, root, cloudflareModule, env, []string{"-mod=readonly"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkBoundary(cloudflareModule, modules, packages); err != nil {
		t.Fatal(err)
	}
	for _, selector := range []string{cloudflareProtocolModule, cloudflareSDKModule, "sdk/artifact", cloudflareModule} {
		if err := checkModuleSource(root, modules, selector); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(kit, "enkv-generator-cloudflare")
	if _, err := runGoEnvironment(ctx, root, cloudflareModule, env, cloudflareProductionBuildArgs(binary, false)...); err != nil {
		t.Fatal(err)
	}
	if err := checkCloudflareBuildInfo(binary, cloudflareProductionMain, runtime.GOOS+"/"+runtime.GOARCH, false, raceEnabled(ctx)); err != nil {
		t.Fatal(err)
	}
	sdk, err := sourcePath(root, cloudflareSDKModule)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(sdk, sdk+"-missing"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := listClosureEnvironment(runGoEnvironment, ctx, root, cloudflareModule, env, []string{"-mod=readonly"}, false); err == nil {
		t.Fatal("kit resolved a missing required source outside its copy")
	}
}

// full_only: false
func TestCloudflareSDKSourceDigestBindsHelperAndMetadata(t *testing.T) {
	root := sourceFixtureRoot(t)
	moduleRoot, err := sourcePath(root, cloudflareSDKModule)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(moduleRoot, 0700); err != nil {
		t.Fatal(err)
	}
	original := map[string]string{"LICENSE": "license", "go.mod": "module enkv.sh/sdk/generator\n\ngo 1.27.0\n", "process.go": "package generator\n"}
	for name, body := range original {
		if err := os.WriteFile(filepath.Join(moduleRoot, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	packages := []compiledPackage{{ImportPath: generatorSDKPath, Dir: moduleRoot, GoFiles: []string{"process.go"}}}
	digest := func(packages []compiledPackage) ([32]byte, error) {
		_, sum, err := compiledSourceDigest(root, cloudflareSDKModule, generatorSDKPath, "ENKV/GENERATOR/v1/source-set\x00", []string{"LICENSE", "go.mod"}, packages)
		return sum, err
	}
	first, err := digest(packages)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(first[:]); got != "aeeddb5cd856d55adfbb83e2babdbcd0f4af73448da1954ae495eee1815b86bf" {
		t.Fatal("helper source digest differs", got)
	}
	manifestID := func(source [32]byte) artifact.Digest {
		facts := artifact.BuildFacts{Role: "generator", MainModule: generatorSDKPath, Command: generatorSDKPath + "/cmd/fixture", Platform: "darwin/arm64", Toolchain: "go1.27.3",
			BuildOptions: []artifact.BuildOption{}, Contracts: cloudflareCurrentContractVector(), Sources: []artifact.Source{{Module: generatorSDKPath, Digest: artifact.Digest(source)}},
			Resolved: []artifact.Dependency{{Path: generatorSDKPath}}, Compiled: []artifact.Dependency{{Path: generatorSDKPath, Version: "(devel)"}}}
		body, err := artifact.EncodeDependency(facts)
		if err != nil {
			t.Fatal(err)
		}
		id, err := artifact.DependencyID("generator", body)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	firstManifest := manifestID(first)
	for _, name := range []string{"LICENSE", "go.mod", "process.go", "go.sum"} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(moduleRoot, name), []byte(original[name]+"changed\n"), 0600); err != nil {
				t.Fatal(err)
			}
			changed, err := digest(packages)
			if err != nil || first == changed || manifestID(changed) == firstManifest {
				t.Fatal("helper input did not change source and manifest identities", err)
			}
			if name == "go.sum" {
				if err := os.Remove(filepath.Join(moduleRoot, name)); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(filepath.Join(moduleRoot, name), []byte(original[name]), 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
	if _, err := digest(nil); err == nil {
		t.Fatal("omitted compiled helper accepted")
	}
	if err := os.WriteFile(filepath.Join(moduleRoot, "tagged.go"), []byte("package generator\nconst tagged = true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	unchanged, err := digest(packages)
	if err != nil || unchanged != first {
		t.Fatal("unselected helper file changed source identity", err)
	}
	packages[0].GoFiles = append(packages[0].GoFiles, "tagged.go")
	tagged, err := digest(packages)
	if err != nil || tagged == first {
		t.Fatal("selected tagged helper input omitted", err)
	}
}

// full_only: false
func TestCloudflareBuildInfoRequiresExactPublicClosure(t *testing.T) {
	newInfo := func() *debug.BuildInfo {
		return &debug.BuildInfo{GoVersion: "go1.27.3", Path: cloudflareProductionMain,
			Main: debug.Module{Path: cloudflareModulePath, Version: "(devel)"},
			Deps: []*debug.Module{
				{Path: "enkv.sh/sdk/artifact", Version: "v0.1.1", Replace: &debug.Module{Path: "../../../sdk/artifact", Version: "(devel)"}},
				{Path: cloudflareProtocolPath, Version: "v0.1.1", Replace: &debug.Module{Path: "../../../sdk/protocols/generator", Version: "(devel)"}},
				{Path: generatorSDKPath, Version: "v0.1.1", Replace: &debug.Module{Path: "../../../sdk/generator", Version: "(devel)"}},
			}, Settings: []debug.BuildSetting{{Key: "-buildmode", Value: "exe"}, {Key: "-compiler", Value: "gc"}, {Key: "CGO_ENABLED", Value: "0"}, {Key: "GOARM64", Value: "v8.0"}, {Key: "GOOS", Value: "darwin"}, {Key: "GOARCH", Value: "arm64"}, {Key: "-trimpath", Value: "true"}}}
	}
	if err := checkCloudflareMetadata(newInfo(), cloudflareProductionMain, "darwin/arm64", false, false); err != nil {
		t.Fatal(err)
	}
	for _, tagged := range []bool{false, true} {
		for _, race := range []bool{false, true} {
			info := newInfo()
			main := cloudflareProductionMain
			if tagged {
				main = cloudflareTestArtifactMain
				info.Path = main
				info.Settings = append(info.Settings, debug.BuildSetting{Key: "-tags", Value: cloudflareTestArtifactTag})
			}
			if race {
				info.Settings = append(info.Settings, debug.BuildSetting{Key: "-race", Value: "true"})
			}
			if !tagged && race {
				if checkCloudflareMetadata(info, main, "darwin/arm64", tagged, race) == nil {
					t.Fatal("production race construction admitted")
				}
				continue
			}
			if err := checkCloudflareMetadata(info, main, "darwin/arm64", tagged, race); err != nil {
				t.Fatal("matching Cloudflare race mode refused", tagged, race, err)
			}
			if checkCloudflareMetadata(info, main, "darwin/arm64", tagged, !race) == nil {
				t.Fatal("mismatched Cloudflare race mode accepted", tagged, race)
			}
		}
	}
	for _, test := range []struct {
		name   string
		change func(*debug.BuildInfo)
	}{
		{"previous compiler", func(info *debug.BuildInfo) { info.GoVersion = "go1.27.0" }},
		{"other compiler patch", func(info *debug.BuildInfo) { info.GoVersion = "go1.27.2" }},
		{"development compiler", func(info *debug.BuildInfo) { info.GoVersion = "devel go1.27.3" }},
		{"custom compiler", func(info *debug.BuildInfo) { info.GoVersion = "go1.27.3-custom" }},
		{"missing helper", func(info *debug.BuildInfo) { info.Deps = info.Deps[:2] }},
		{"missing artifact codec", func(info *debug.BuildInfo) { info.Deps = info.Deps[1:] }},
		{"stale artifact replacement", func(info *debug.BuildInfo) { info.Deps[0].Replace.Path = "../../artifact" }},
		{"unknown dependency", func(info *debug.BuildInfo) { info.Deps[1].Path = "example.invalid/sdk" }},
		{"duplicate dependency", func(info *debug.BuildInfo) { info.Deps[1] = info.Deps[0] }},
		{"stale helper replacement", func(info *debug.BuildInfo) { info.Deps[2].Replace.Path = "../../generator" }},
		{"helper version", func(info *debug.BuildInfo) { info.Deps[2].Version = "v0.0.1" }},
		{"stale protocol replacement", func(info *debug.BuildInfo) { info.Deps[1].Replace.Path = "../../protocols/generator" }},
		{"production tag", func(info *debug.BuildInfo) {
			info.Settings = append(info.Settings, debug.BuildSetting{Key: "-tags", Value: cloudflareTestArtifactTag})
		}},
		{"duplicate setting", func(info *debug.BuildInfo) { info.Settings = append(info.Settings, info.Settings[0]) }},
		{"race", func(info *debug.BuildInfo) {
			info.Settings = append(info.Settings, debug.BuildSetting{Key: "-race", Value: "true"})
		}},
		{"invalid race setting", func(info *debug.BuildInfo) {
			info.Settings = append(info.Settings, debug.BuildSetting{Key: "-race", Value: "unknown"})
		}},
		{"linker", func(info *debug.BuildInfo) {
			info.Settings = append(info.Settings, debug.BuildSetting{Key: "-ldflags", Value: "-X=x.y=z"})
		}},
		{"cgo", func(info *debug.BuildInfo) { info.Settings[2].Value = "1" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			info := newInfo()
			test.change(info)
			if checkCloudflareMetadata(info, cloudflareProductionMain, "darwin/arm64", false, false) == nil {
				t.Fatal("inexact build metadata accepted")
			}
		})
	}
	tagged := newInfo()
	tagged.Path = cloudflareTestArtifactMain
	tagged.Settings = append(tagged.Settings, debug.BuildSetting{Key: "-tags", Value: cloudflareTestArtifactTag})
	if err := checkCloudflareMetadata(tagged, cloudflareTestArtifactMain, "darwin/arm64", true, false); err != nil {
		t.Fatal(err)
	}
	if checkCloudflareMetadata(tagged, cloudflareProductionMain, "darwin/arm64", false, false) == nil {
		t.Fatal("tagged artifact accepted as production")
	}
}

// The public wire declaration is an ordinary independent literal. Provider
// settings and credentials belong to each executable's embedded descriptor.
func cloudflareCurrentContractVector() []artifact.Contract {
	return []artifact.Contract{{Kind: "wire", Identity: "cc827c32a204204ec680e29c0b79df771ea2ad5d2c1df10170d8b450e7628b0f", Version: 5}}
}

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"enkv.sh/compositions/generatorhost"
	"enkv.sh/core/contract"
	"enkv.sh/sdk/artifact"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
)

const (
	cloudflareModule           = "plugins/cloudflare"
	cloudflareModulePath       = "enkv.sh/plugins/generators/cloudflare-account-token"
	cloudflareProtocolModule   = "protocols/generator"
	cloudflareProtocolPath     = "enkv.sh/sdk/protocols/generator"
	cloudflareSDKModule        = "sdk/generator"
	cloudflareGoVersion        = "go1.27.3"
	cloudflareTestArtifactTag  = "enkv_cloudflare_testartifact"
	cloudflareTestArtifactURL  = "https://127.0.0.1.invalid/client/v4"
	cloudflareProductionMain   = cloudflareModulePath + "/cmd/enkv-generator-cloudflare"
	cloudflareTestArtifactMain = cloudflareModulePath + "/cmd/enkv-generator-cloudflare-test"
)

var cloudflareSupportedTuples = []string{"darwin/arm64", "linux/amd64"}

type artifactSourceFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type cloudflareArtifactEvidence struct {
	GoVersion                    string               `json:"go_version"`
	NativeTuple                  string               `json:"native_tuple"`
	ProtocolSourceSHA256         string               `json:"protocol_source_sha256"`
	ProtocolSourceFiles          []artifactSourceFile `json:"protocol_source_files"`
	SDKSourceSHA256              string               `json:"sdk_source_sha256"`
	SDKSourceFiles               []artifactSourceFile `json:"sdk_source_files"`
	PluginSourceSHA256           string               `json:"plugin_source_sha256"`
	PluginSourceFiles            []artifactSourceFile `json:"plugin_source_files"`
	DependencyManifest           []byte               `json:"dependency_manifest"`
	DependencyManifestSHA256     string               `json:"dependency_manifest_sha256"`
	TestProtocolSourceSHA256     string               `json:"test_protocol_source_sha256"`
	TestProtocolSourceFiles      []artifactSourceFile `json:"test_protocol_source_files"`
	TestSDKSourceSHA256          string               `json:"test_sdk_source_sha256"`
	TestSDKSourceFiles           []artifactSourceFile `json:"test_sdk_source_files"`
	TestPluginSourceSHA256       string               `json:"test_plugin_source_sha256"`
	TestPluginSourceFiles        []artifactSourceFile `json:"test_plugin_source_files"`
	TestDependencyManifest       []byte               `json:"test_dependency_manifest"`
	TestDependencyManifestSHA256 string               `json:"test_dependency_manifest_sha256"`
	TestMetadata                 []byte               `json:"test_metadata"`
	ProductionBuildCommand       []string             `json:"production_build_command"`
	ProductionMetadata           []byte               `json:"production_metadata"`
	ProductionSHA256             string               `json:"production_sha256"`
	ProductionLength             int64                `json:"production_length"`
	TestBuildCommand             []string             `json:"test_build_command"`
	TestSHA256                   string               `json:"test_sha256"`
	TestLength                   int64                `json:"test_length"`
}

type cloudflareAssemblyBinding struct {
	artifactPath       string
	ArtifactSHA256     string
	ArtifactLength     int64
	DependencyManifest string
	Installation       []byte
	Dependency         []byte
}

func prepareCloudflareAssemblyBinding(ctx context.Context, root, directory string, generator generatorReference) (*cloudflareAssemblyBinding, error) {
	if !cloudflareAccount.MatchString(generator.Account) {
		return nil, errors.New("Cloudflare account refused")
	}
	value, _, err := invocationArtifactValue(ctx, root, directory, "cloudflare-binding", generator.Artifact, func(build string) (*cloudflareAssemblyBinding, error) {
		return constructCloudflareAssemblyBinding(ctx, root, build, generator)
	})
	return value, err
}

func constructCloudflareAssemblyBinding(ctx context.Context, root, directory string, generator generatorReference) (*cloudflareAssemblyBinding, error) {
	evidence, err := buildCloudflareArtifacts(ctx, root, directory)
	if err != nil {
		return nil, err
	}
	digest, length, err := cloudflareArtifactIdentity(generator.Artifact)
	if err != nil || hex.EncodeToString(digest[:]) != evidence.ProductionSHA256 || length != evidence.ProductionLength {
		return nil, errors.New("installed Cloudflare artifact differs from the exact native source build")
	}
	if err := checkCloudflareBuildInfo(generator.Artifact, cloudflareProductionMain, evidence.NativeTuple, false, false); err != nil {
		return nil, err
	}
	binding, err := cloudflareBinding(evidence, generator.Account)
	if binding != nil {
		binding.artifactPath = filepath.Join(directory, "enkv-generator-cloudflare")
	}
	return binding, err
}

type cloudflareModFile struct {
	Module        struct{ Path string }
	Go, Toolchain string
	Require       []struct {
		Path, Version string
		Indirect      bool
	}
	Replace []struct {
		Old, New struct{ Path, Version string }
	}
}

func checkCloudflareModuleDefinition(ctx context.Context, root string) error {
	body, err := runGo(ctx, root, cloudflareModule, "mod", "edit", "-json")
	if err != nil {
		return err
	}
	var mod cloudflareModFile
	if json.Unmarshal(body, &mod) != nil || mod.Module.Path != cloudflareModulePath || mod.Go != "1.27.0" || mod.Toolchain != "" || len(mod.Require) != 3 || len(mod.Replace) != 0 {
		return errors.New("Cloudflare module definition differs")
	}
	dependencies := map[string]string{cloudflareProtocolPath: "../../../sdk/protocols/generator", generatorSDKPath: "../../../sdk/generator", "enkv.sh/sdk/artifact": "../../../sdk/artifact"}
	requirements := make(map[string]bool, len(mod.Require))
	for _, requirement := range mod.Require {
		if _, ok := dependencies[requirement.Path]; !ok || requirements[requirement.Path] || requirement.Version != "v0.1.0" || requirement.Indirect {
			return errors.New("Cloudflare module requirements differ")
		}
		requirements[requirement.Path] = true
	}
	pluginLicense, err := registeredSourceBytes(root, cloudflareModule+"/LICENSE")
	if err != nil {
		return errors.New("Cloudflare Apache-2.0 license unavailable")
	}
	for _, module := range []string{cloudflareProtocolModule, cloudflareSDKModule, "sdk/artifact"} {
		license, err := registeredSourceBytes(root, module+"/LICENSE")
		if err != nil || !bytes.Equal(pluginLicense, license) || !bytes.Contains(pluginLicense, []byte("Apache License\n                           Version 2.0")) {
			return errors.New("Cloudflare Apache-2.0 license differs")
		}
	}
	return nil
}

func checkCloudflareConstructions(ctx context.Context, root string, production []compiledPackage) error {
	flags := compilerBuildFlags([]string{"-mod=readonly", "-tags=" + cloudflareTestArtifactTag}, raceEnabled(ctx))
	modules, tagged, err := listClosure(runGoEnvironment, ctx, root, cloudflareModule, flags, false)
	if err != nil {
		return err
	}
	if err := checkBoundary(cloudflareModule, modules, tagged); err != nil {
		return err
	}
	productionMain := packageByImport(production, cloudflareProductionMain)
	productionTestMain := packageByImport(production, cloudflareTestArtifactMain)
	productionInternal := packageByImport(production, cloudflareModulePath+"/internal/cloudflare")
	taggedTestMain := packageByImport(tagged, cloudflareTestArtifactMain)
	taggedInternal := packageByImport(tagged, cloudflareModulePath+"/internal/cloudflare")
	if productionMain == nil || productionTestMain != nil || productionInternal == nil || taggedTestMain == nil || taggedInternal == nil ||
		slices.Contains(productionInternal.GoFiles, "testartifact.go") || !slices.Contains(taggedInternal.GoFiles, "testartifact.go") ||
		len(productionMain.GoFiles) != 1 || productionMain.GoFiles[0] != "main.go" || len(taggedTestMain.GoFiles) != 1 || taggedTestMain.GoFiles[0] != "main.go" {
		return errors.New("Cloudflare production and test constructions differ")
	}
	if _, err := runGo(ctx, root, cloudflareModule, append(append([]string{"vet"}, flags...), "./...")...); err != nil {
		return err
	}
	if _, err := runGoEnvironment(withRacePolicy(ctx, false), root, cloudflareModule, stockPluginBuildEnvironment(), "vet", "-mod=readonly", "./cmd/enkv-generator-cloudflare"); err != nil {
		return err
	}
	return nil
}

func packageByImport(packages []compiledPackage, path string) *compiledPackage {
	for i := range packages {
		if packages[i].ImportPath == path {
			return &packages[i]
		}
	}
	return nil
}

func cloudflareProductionBuildArgs(output string, race bool) []string {
	flags := compilerBuildFlags([]string{"-mod=readonly", "-trimpath", "-buildvcs=false"}, race)
	return append(append([]string{"build"}, flags...), "-o", output, "./cmd/enkv-generator-cloudflare")
}

func cloudflareTestBuildArgs(output string, race bool) []string {
	flags := compilerBuildFlags([]string{"-mod=readonly", "-trimpath", "-buildvcs=false", "-tags=" + cloudflareTestArtifactTag,
		"-ldflags=-X=" + cloudflareModulePath + "/internal/cloudflare.unqualifiedTestArtifactOrigin=" + cloudflareTestArtifactURL}, race)
	return append(append([]string{"build"}, flags...), "-o", output, "./cmd/enkv-generator-cloudflare-test")
}

func cloudflareRecordedBuildCommand(test, race bool) []string {
	if test {
		return append([]string{"go"}, cloudflareTestBuildArgs("<artifact>", race)...)
	}
	return append([]string{"go"}, cloudflareProductionBuildArgs("<artifact>", race)...)
}

func buildCloudflareArtifacts(ctx context.Context, root, directory string) (cloudflareArtifactEvidence, error) {
	type retained struct {
		evidence  cloudflareArtifactEvidence
		directory string
	}
	value, _, err := invocationArtifactValue(ctx, root, directory, "cloudflare", "production-and-test", func(build string) (retained, error) {
		evidence, err := constructCloudflareArtifacts(ctx, root, build)
		return retained{evidence, build}, err
	})
	if err != nil {
		return cloudflareArtifactEvidence{}, err
	}
	for _, name := range []string{"enkv-generator-cloudflare", "enkv-generator-cloudflare-test"} {
		if err := linkInvocationFile(filepath.Join(value.directory, name), filepath.Join(directory, name)); err != nil {
			return cloudflareArtifactEvidence{}, err
		}
	}
	return value.evidence, nil
}

func constructCloudflareArtifacts(ctx context.Context, root, directory string) (cloudflareArtifactEvidence, error) {
	var evidence cloudflareArtifactEvidence
	productionCtx := withRacePolicy(ctx, false)
	env := stockPluginBuildEnvironment()
	versionBody, err := runGoEnvironment(productionCtx, root, cloudflareModule, env, "version")
	if err != nil {
		return evidence, err
	}
	fields := strings.Fields(string(versionBody))
	tuple := runtime.GOOS + "/" + runtime.GOARCH
	if len(fields) != 4 || fields[0] != "go" || fields[1] != "version" || fields[2] != cloudflareGoVersion || fields[3] != tuple || !slices.Contains(cloudflareSupportedTuples, tuple) {
		return evidence, errors.New("Cloudflare artifact requires exact Go 1.27.3 on a supported native tuple")
	}
	productionDescriptor, _, err := readCloudflareDescriptor(productionCtx, root, false)
	if err != nil {
		return evidence, err
	}
	testDescriptor, _, err := readCloudflareDescriptor(ctx, root, true)
	if err != nil {
		return evidence, err
	}
	race := raceEnabled(ctx)
	modules, packages, err := listClosureEnvironment(runGoEnvironment, productionCtx, root, cloudflareModule, env, []string{"-mod=readonly"}, false, "./cmd/enkv-generator-cloudflare")
	if err != nil {
		return evidence, err
	}
	protocolFiles, protocolDigest, err := compiledSourceDigest(root, cloudflareProtocolModule, cloudflareProtocolPath, "ENKV/GENERATOR/v1/source-set\x00", []string{"LICENSE", "go.mod"}, packages)
	if err != nil {
		return evidence, err
	}
	pluginFiles, pluginDigest, err := compiledSourceDigest(root, cloudflareModule, cloudflareModulePath, "ENKV/GENERATOR/v1/source-set\x00", []string{"LICENSE", "go.mod"}, packages)
	if err != nil {
		return evidence, err
	}
	sdkFiles, sdkDigest, err := compiledSourceDigest(root, cloudflareSDKModule, generatorSDKPath, "ENKV/GENERATOR/v1/source-set\x00", []string{"LICENSE", "go.mod"}, packages)
	if err != nil {
		return evidence, err
	}
	taggedModules, taggedPackages, err := listClosure(runGoEnvironment, ctx, root, cloudflareModule, compilerBuildFlags([]string{"-mod=readonly", "-tags=" + cloudflareTestArtifactTag}, race), false, "./cmd/enkv-generator-cloudflare-test")
	if err != nil {
		return evidence, err
	}
	testProtocolFiles, testProtocolDigest, err := compiledSourceDigest(root, cloudflareProtocolModule, cloudflareProtocolPath, "ENKV/GENERATOR/v1/source-set\x00", []string{"LICENSE", "go.mod"}, taggedPackages)
	if err != nil {
		return evidence, err
	}
	testSDKFiles, testSDKDigest, err := compiledSourceDigest(root, cloudflareSDKModule, generatorSDKPath, "ENKV/GENERATOR/v1/source-set\x00", []string{"LICENSE", "go.mod"}, taggedPackages)
	if err != nil {
		return evidence, err
	}
	testPluginFiles, testPluginDigest, err := compiledSourceDigest(root, cloudflareModule, cloudflareModulePath, "ENKV/GENERATOR/v1/source-set\x00", []string{"LICENSE", "go.mod"}, taggedPackages)
	if err != nil {
		return evidence, err
	}
	evidence = cloudflareArtifactEvidence{
		GoVersion: cloudflareGoVersion, NativeTuple: tuple,
		ProtocolSourceSHA256: hex.EncodeToString(protocolDigest[:]), ProtocolSourceFiles: protocolFiles,
		SDKSourceSHA256: hex.EncodeToString(sdkDigest[:]), SDKSourceFiles: sdkFiles,
		TestProtocolSourceSHA256: hex.EncodeToString(testProtocolDigest[:]), TestProtocolSourceFiles: testProtocolFiles,
		TestSDKSourceSHA256: hex.EncodeToString(testSDKDigest[:]), TestSDKSourceFiles: testSDKFiles,
		PluginSourceSHA256: hex.EncodeToString(pluginDigest[:]), PluginSourceFiles: pluginFiles,
		TestPluginSourceSHA256: hex.EncodeToString(testPluginDigest[:]), TestPluginSourceFiles: testPluginFiles,
		ProductionBuildCommand: cloudflareRecordedBuildCommand(false, false), TestBuildCommand: cloudflareRecordedBuildCommand(true, race),
	}
	production := filepath.Join(directory, "enkv-generator-cloudflare")
	testArtifact := filepath.Join(directory, "enkv-generator-cloudflare-test")
	if _, err := runGoEnvironment(productionCtx, root, cloudflareModule, env, cloudflareProductionBuildArgs(production, false)...); err != nil {
		return evidence, err
	}
	if err := os.Chmod(production, 0700); err != nil {
		return evidence, fmt.Errorf("set Cloudflare artifact permissions: %w", err)
	}
	if _, err := runGo(ctx, root, cloudflareModule, cloudflareTestBuildArgs(testArtifact, race)...); err != nil {
		return evidence, err
	}
	if err := os.Chmod(testArtifact, 0700); err != nil {
		return evidence, fmt.Errorf("set Cloudflare artifact permissions: %w", err)
	}
	productionDigest, productionLength, err := cloudflareArtifactIdentity(production)
	if err != nil {
		return evidence, err
	}
	testDigest, testLength, err := cloudflareArtifactIdentity(testArtifact)
	if err != nil {
		return evidence, err
	}
	productionBody, err := regularFileBytes(production)
	if err != nil {
		return evidence, errors.New("Cloudflare production artifact unavailable")
	}
	testBody, err := regularFileBytes(testArtifact)
	if err != nil {
		return evidence, errors.New("Cloudflare test artifact unavailable")
	}
	if productionDigest == testDigest || bytes.Contains(productionBody, []byte(cloudflareTestArtifactURL)) || !bytes.Contains(testBody, []byte(cloudflareTestArtifactURL)) {
		return evidence, errors.New("Cloudflare test artifact is not separated from production")
	}
	if err := checkCloudflareBuildInfo(production, cloudflareProductionMain, tuple, false, false); err != nil {
		return evidence, err
	}
	if err := checkCloudflareBuildInfo(testArtifact, cloudflareTestArtifactMain, tuple, true, race); err != nil {
		return evidence, err
	}
	evidence.DependencyManifest, err = captureCloudflareDependency(productionCtx, root, modules, packages, production, false, productionDescriptor)
	if err != nil {
		return evidence, err
	}
	manifestID, err := artifact.DependencyID("generator", evidence.DependencyManifest)
	if err != nil {
		return evidence, err
	}
	evidence.DependencyManifestSHA256 = manifestID.String()
	evidence.TestDependencyManifest, err = captureCloudflareDependency(ctx, root, taggedModules, taggedPackages, testArtifact, true, testDescriptor)
	if err != nil {
		return evidence, err
	}
	testManifestID, err := artifact.DependencyID("generator", evidence.TestDependencyManifest)
	if err != nil {
		return evidence, err
	}
	evidence.TestDependencyManifestSHA256 = testManifestID.String()
	evidence.ProductionSHA256, evidence.ProductionLength = hex.EncodeToString(productionDigest[:]), productionLength
	evidence.TestSHA256, evidence.TestLength = hex.EncodeToString(testDigest[:]), testLength
	evidence.ProductionMetadata, err = cloudflareMetadata(productionDescriptor, evidence.DependencyManifest, evidence.ProductionSHA256, evidence.ProductionLength)
	if err != nil {
		return evidence, err
	}
	evidence.TestMetadata, err = cloudflareMetadata(testDescriptor, evidence.TestDependencyManifest, evidence.TestSHA256, evidence.TestLength)
	if err != nil {
		return evidence, err
	}
	return evidence, nil
}

func compiledSourceDigest(root, module, modulePath, domain string, requiredFiles []string, packages []compiledPackage) ([]artifactSourceFile, [32]byte, error) {
	var zero [32]byte
	moduleRoot, err := sourcePath(root, module)
	if err != nil {
		return nil, zero, errors.New("native artifact source root unavailable")
	}
	paths := make(map[string]bool)
	compiledInput := false
	for _, name := range requiredFiles {
		paths[name] = true
	}
	for _, name := range artifact.SourceMetadataFiles() {
		if _, err := os.Lstat(filepath.Join(moduleRoot, name)); err == nil {
			paths[name] = true
		} else if !os.IsNotExist(err) {
			return nil, zero, errors.New("native artifact source input unavailable")
		}
	}
	for _, pkg := range packages {
		if !withinModule(pkg.ImportPath, modulePath) {
			continue
		}
		if len(pkg.CgoFiles)+len(pkg.CFiles)+len(pkg.CXXFiles)+len(pkg.MFiles)+len(pkg.HFiles)+len(pkg.FFiles)+len(pkg.SFiles)+
			len(pkg.SwigFiles)+len(pkg.SwigCXXFiles)+len(pkg.SysoFiles) != 0 {
			return nil, zero, errors.New("native artifact non-Go build input refused")
		}
		directory, err := filepath.EvalSymlinks(pkg.Dir)
		if err != nil {
			return nil, zero, errors.New("native artifact source package unavailable")
		}
		relativeDirectory, err := filepath.Rel(moduleRoot, directory)
		if err != nil || filepath.IsAbs(relativeDirectory) || relativeDirectory == ".." || strings.HasPrefix(relativeDirectory, ".."+string(filepath.Separator)) {
			return nil, zero, errors.New("native artifact source package escaped its module")
		}
		compiledInput = compiledInput || len(pkg.GoFiles) != 0
		for _, name := range append(slices.Clone(pkg.GoFiles), pkg.EmbedFiles...) {
			relative := filepath.Clean(filepath.Join(relativeDirectory, name))
			if filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				return nil, zero, errors.New("native artifact source input escaped its module")
			}
			paths[filepath.ToSlash(relative)] = true
		}
	}
	if !compiledInput {
		return nil, zero, errors.New("native artifact source input set is empty")
	}
	names := make([]string, 0, len(paths))
	for name := range paths {
		names = append(names, name)
	}
	slices.Sort(names)
	files := make([]artifactSourceFile, 0, len(names))
	for _, name := range names {
		body, err := regularFileBytes(filepath.Join(moduleRoot, filepath.FromSlash(name)))
		if err != nil {
			return nil, zero, errors.New("native artifact source input unavailable")
		}
		sum := sha256.Sum256(body)
		files = append(files, artifactSourceFile{Path: name, SHA256: hex.EncodeToString(sum[:])})
	}
	selected := make([]compiledPackage, 0, len(packages))
	for _, pkg := range packages {
		if withinModule(pkg.ImportPath, modulePath) {
			selected = append(selected, pkg)
		}
	}
	sourcePackages, err := artifactSourcePackages([]resolvedModule{{Path: modulePath, Dir: moduleRoot, Main: true}}, selected)
	if err != nil {
		return nil, zero, err
	}
	role := ""
	switch domain {
	case "ENKV/GENERATOR/v1/source-set\x00":
		role = "generator"
	case "ENKV/OUTPUT/v1/source-set\x00":
		role = "output"
	default:
		return nil, zero, errors.New("native artifact source domain refused")
	}
	sources, err := artifact.CaptureSources(context.Background(), role, sourcePackages)
	if err != nil || len(sources) != 1 {
		return nil, zero, errors.Join(errors.New("native artifact source capture refused"), err)
	}
	return files, [32]byte(sources[0].Digest), nil
}

func captureCloudflareDependency(ctx context.Context, root string, modules []resolvedModule, packages []compiledPackage, executable string, tagged bool, descriptor artifact.Descriptor) ([]byte, error) {
	main := packageByImport(packages, cloudflareProductionMain)
	if tagged {
		main = packageByImport(packages, cloudflareTestArtifactMain)
	}
	if main == nil || !slices.Equal(main.EmbedFiles, []string{"plugin.json"}) {
		return nil, errors.New("Cloudflare compiled descriptor differs")
	}
	info, err := buildinfo.ReadFile(executable)
	if err != nil {
		return nil, err
	}
	facts, err := captureArtifactBuildFacts(ctx, root, "generator", modules, packages, info, []artifact.Contract{descriptor.Wire})
	if err != nil {
		return nil, err
	}
	return artifact.EncodeDependency(facts)
}

func readCloudflareDescriptor(ctx context.Context, root string, tagged bool) (artifact.Descriptor, []byte, error) {
	command := "enkv-generator-cloudflare"
	if tagged {
		command = "enkv-generator-cloudflare-test"
	}
	path, err := sourcePath(root, cloudflareModule+"/cmd/"+command+"/plugin.json")
	if err != nil {
		return artifact.Descriptor{}, nil, err
	}
	return artifact.ReadDescriptor(ctx, path)
}

func cloudflareArtifactIdentity(path string) ([32]byte, int64, error) {
	var zero [32]byte
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 {
		return zero, 0, errors.New("Cloudflare artifact type or mode differs")
	}
	file, err := os.Open(path)
	if err != nil {
		return zero, 0, errors.New("Cloudflare artifact unavailable")
	}
	hash := sha256.New()
	length, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || length != info.Size() || length == 0 {
		return zero, 0, errors.New("Cloudflare artifact could not be measured")
	}
	copy(zero[:], hash.Sum(nil))
	return zero, length, nil
}

func checkCloudflareBuildInfo(path, mainPath, tuple string, tagged, race bool) error {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return errors.New("Cloudflare artifact build information unavailable")
	}
	return checkCloudflareMetadata(info, mainPath, tuple, tagged, race)
}

func checkCloudflareMetadata(info *debug.BuildInfo, mainPath, tuple string, tagged, race bool) error {
	if info == nil || info.GoVersion != cloudflareGoVersion || info.Path != mainPath || info.Main.Path != cloudflareModulePath || info.Main.Version != "(devel)" || info.Main.Sum != "" || info.Main.Replace != nil || !slices.Contains(cloudflareSupportedTuples, tuple) {
		return errors.New("Cloudflare artifact build identity differs")
	}
	dependencies := map[string]string{cloudflareProtocolPath: "../../../sdk/protocols/generator", generatorSDKPath: "../../../sdk/generator", "enkv.sh/sdk/artifact": "../../../sdk/artifact"}
	if len(info.Deps) != len(dependencies) {
		return errors.New("Cloudflare artifact dependency closure differs")
	}
	for _, dependency := range info.Deps {
		if dependency == nil {
			return errors.New("Cloudflare artifact dependency closure differs")
		}
		replacement, ok := dependencies[dependency.Path]
		if !ok || dependency.Version != "v0.1.0" || dependency.Sum != "" || dependency.Replace == nil || dependency.Replace.Path != replacement || dependency.Replace.Version != "(devel)" || dependency.Replace.Sum != "" || dependency.Replace.Replace != nil {
			return errors.New("Cloudflare artifact dependency closure differs")
		}
		delete(dependencies, dependency.Path)
	}
	if len(dependencies) != 0 {
		return errors.New("Cloudflare artifact dependency closure incomplete")
	}
	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		if _, exists := settings[setting.Key]; exists {
			return errors.New("Cloudflare artifact duplicate build setting")
		}
		settings[setting.Key] = setting.Value
	}
	goos, goarch, ok := strings.Cut(tuple, "/")
	wantTags := ""
	if tagged {
		wantTags = cloudflareTestArtifactTag
	}
	raceValue, observedRace := settings["-race"]
	if observedRace && raceValue != "true" || observedRace != race {
		return errors.New("Cloudflare artifact race setting differs")
	}
	if !ok || settings["GOOS"] != goos || settings["GOARCH"] != goarch || settings["-tags"] != wantTags || settings["-trimpath"] != "true" {
		return fmt.Errorf("Cloudflare artifact build settings differ: %v", settings)
	}
	if !tagged {
		if _, err := artifact.BuildOptions(info); err != nil {
			return err
		}
	}
	return nil
}

func regularFileBytes(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("regular file unavailable")
	}
	return os.ReadFile(path)
}

func registeredSourceBytes(root, name string) ([]byte, error) {
	physical, err := sourcePath(root, name)
	if err != nil {
		return nil, err
	}
	return regularFileBytes(physical)
}

func cloudflareAppendBlob(writer io.Writer, body []byte) {
	_ = binary.Write(writer, binary.BigEndian, uint32(len(body)))
	_, _ = writer.Write(body)
}

func cloudflareMetadata(descriptor artifact.Descriptor, dependency []byte, executableSHA256 string, executableLength int64) ([]byte, error) {
	facts, err := artifact.DecodeDependency(dependency)
	if err != nil {
		return nil, err
	}
	digest, err := artifact.ParseDigest(executableSHA256)
	if err != nil || executableLength <= 0 {
		return nil, errors.New("Cloudflare executable identity refused")
	}
	id, err := artifact.DependencyID("generator", dependency)
	if err != nil {
		return nil, err
	}
	family, err := artifact.BindGeneratorFacts(artifact.GeneratorFacts{Schema: artifact.FamilySchema, Descriptor: descriptor,
		ExecutionFacts: artifact.ExecutionFacts{Module: facts.MainModule, Command: facts.Command, GoVersion: facts.Toolchain, NativeTuple: facts.Platform}}, digest, uint64(executableLength), id)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(family)
	if err != nil {
		return nil, err
	}
	metadata := artifact.Metadata{Schema: "enkv/plugin-artifact/v2", Purpose: "plugin-executable", Name: descriptor.Name, Role: facts.Role, Version: descriptor.Version, MainModule: facts.MainModule, Command: facts.Command, Platform: facts.Platform, Toolchain: facts.Toolchain, BuildOptions: facts.BuildOptions, Contracts: facts.Contracts, Sources: facts.Sources, Resolved: facts.Resolved, Compiled: facts.Compiled, Executable: artifact.DigestLength{SHA256: digest, Length: uint64(executableLength)}, Family: &artifact.Family{Schema: artifact.FamilySchema, Facts: body, Dependency: artifact.DigestLength{SHA256: artifact.Hash(dependency), Length: uint64(len(dependency))}}}
	if _, err := generatorhost.NewInstallation(metadata, dependency); err != nil {
		return nil, err
	}
	return artifact.EncodeMetadata(metadata)
}

func cloudflareBinding(e cloudflareArtifactEvidence, account string) (*cloudflareAssemblyBinding, error) {
	if !cloudflareAccount.MatchString(account) || len(e.ProductionMetadata) == 0 || len(e.ProductionMetadata) > artifact.MaxMetadataBytes || len(e.DependencyManifest) == 0 || len(e.DependencyManifest) > artifact.MaxDependencyBytes {
		return nil, errors.New("Cloudflare installation facts refused")
	}
	metadata, err := artifact.DecodeMetadata(e.ProductionMetadata)
	if err != nil {
		return nil, err
	}
	installed, err := generatorhost.NewInstallation(metadata, e.DependencyManifest)
	if err != nil {
		return nil, err
	}
	row := installed.Artifact()
	if row.Validate() != nil || hex.EncodeToString(row.ArtifactSHA256[:]) != e.ProductionSHA256 || row.ArtifactLength != uint64(e.ProductionLength) || hex.EncodeToString(row.DependencyManifestID[:]) != e.DependencyManifestSHA256 {
		return nil, errors.New("Cloudflare runtime binding differs")
	}
	body, err := json.Marshal(struct {
		Artifact contract.GeneratorImplementation `json:"artifact"`
		Metadata json.RawMessage                  `json:"metadata"`
	}{row, e.ProductionMetadata})
	if err != nil || len(body) > artifact.MaxMetadataBytes {
		return nil, errors.New("Cloudflare installation envelope refused")
	}
	return &cloudflareAssemblyBinding{ArtifactSHA256: e.ProductionSHA256, ArtifactLength: e.ProductionLength, DependencyManifest: e.DependencyManifestSHA256, Installation: body, Dependency: slices.Clone(e.DependencyManifest)}, nil
}

func cloudflareFixtureLinkerFlag(directory string, binding *cloudflareAssemblyBinding) (string, error) {
	if binding == nil {
		return "", nil
	}
	if len(binding.Installation) == 0 || len(binding.Installation) > artifact.MaxMetadataBytes || len(binding.Dependency) == 0 || len(binding.Dependency) > artifact.MaxDependencyBytes {
		return "", errors.New("Cloudflare assembly binding refused")
	}
	if binding.artifactPath != "" {
		if err := linkInvocationFile(binding.artifactPath, filepath.Join(directory, "enkv-generator-cloudflare")); err != nil {
			return "", err
		}
	}
	for name, body := range map[string][]byte{"cloudflare.installation.json": binding.Installation, "cloudflare.dependency": binding.Dependency} {
		if err := os.WriteFile(filepath.Join(directory, name), body, 0600); err != nil {
			return "", err
		}
	}
	body, err := json.Marshal([2]string{digestBytes(binding.Installation), digestBytes(binding.Dependency)})
	if err != nil {
		return "", err
	}
	return "-X '" + componentPackage + ".generatorFixtureExpectations=" + string(body) + "'", nil
}

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"enkv.sh/compositions/outputhost"
	artifactpkg "enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
	protocol "enkv.sh/sdk/protocols/output"
)

const outputTestModule = "plugins/output-contract-test"
const outputTestCommand = "enkv-output-contract-test"
const outputSourceDomain = "ENKV/OUTPUT/v1/source-set\x00"

type outputArtifactClosure struct {
	directory          string
	Race               bool                  `json:"race"`
	Metadata           *artifactpkg.Metadata `json:"metadata,omitempty"`
	Artifact           outputhost.Artifact   `json:"artifact"`
	ProtocolSource     []artifactSourceFile  `json:"protocol_source"`
	SDKSource          []artifactSourceFile  `json:"sdk_source"`
	DependencyManifest []byte                `json:"dependency_manifest"`
	PluginSource       []artifactSourceFile  `json:"plugin_source"`
	ResolvedModules    []moduleIdentity      `json:"resolved_modules"`
	CompiledImports    []string              `json:"compiled_imports"`
}

type outputProfileBinding struct {
	StoredProfileID                             string
	DescriptorID, CredentialRouteID             protocol.ID
	ConfigContractID, CredentialRouteContractID string
}

type outputProfileCommand struct {
	label, module, command, provider string
}

var outputProductionCommands = [...]outputProfileCommand{
	{"ENKV/OUTPUT/AWS-SECRETS-MANAGER/v3", "plugins/aws-output", "enkv-output-aws-secrets-manager", "aws-secrets-manager"},
	{"ENKV/OUTPUT/GCP-SECRET-MANAGER/v3", "plugins/gcp-output", "enkv-output-gcp-secret-manager", "gcp-secret-manager"},
	{"ENKV/OUTPUT/GITHUB-REPOSITORY/v3", "plugins/github-output", "enkv-output-github-repository", "github-actions"},
	{"ENKV/OUTPUT/GITHUB-ORGANIZATION/v3", "plugins/github-output", "enkv-output-github-organization", "github-actions"},
	{"ENKV/OUTPUT/GITHUB-ENVIRONMENT/v3", "plugins/github-output", "enkv-output-github-environment", "github-actions"},
}

func outputCommand(label string) (outputProfileCommand, bool) {
	for _, command := range outputProductionCommands {
		if command.label == label {
			return command, true
		}
	}
	if label == "ENKV/OUTPUT/TEST-PROFILE/v3" {
		return outputProfileCommand{label, outputTestModule, outputTestCommand, "test-output"}, true
	}
	return outputProfileCommand{}, false
}

// Named commands select qualification cases only; installation admission is generic.
func outputBinding(row outputhost.Artifact) (outputProfileBinding, error) {
	for _, command := range append(outputProductionCommands[:], outputProfileCommand{"ENKV/OUTPUT/TEST-PROFILE/v3", outputTestModule, outputTestCommand, "test-output"}) {
		if row.ModulePath == modulePath(command.module) && row.CommandPath == modulePath(command.module)+"/cmd/"+command.command {
			return outputProfileBinding{StoredProfileID: command.label, DescriptorID: row.DescriptorID, CredentialRouteID: row.CredentialRouteID, ConfigContractID: row.ConfigContractID, CredentialRouteContractID: row.CredentialRouteContractID}, nil
		}
	}
	return outputProfileBinding{}, errors.New("output qualification command binding differs")
}

func validateOutputBindings(bindings []outputProfileBinding) ([]outputProfileBinding, error) {
	if len(bindings) == 0 || len(bindings) > len(outputProductionCommands) {
		return nil, errors.New("output production binding count refused")
	}
	seen := make(map[string]outputProfileBinding, len(bindings))
	for _, binding := range bindings {
		command, ok := outputCommand(binding.StoredProfileID)
		if !ok || command.module == outputTestModule || binding.DescriptorID.IsZero() || binding.CredentialRouteID.IsZero() || binding.ConfigContractID == "" || binding.CredentialRouteContractID == "" {
			return nil, errors.New("output production binding refused")
		}
		if _, duplicate := seen[binding.StoredProfileID]; duplicate {
			return nil, errors.New("output production profile repeated")
		}
		seen[binding.StoredProfileID] = binding
	}
	selected := make([]outputProfileBinding, 0, len(bindings))
	for _, command := range outputProductionCommands {
		if binding, ok := seen[command.label]; ok {
			selected = append(selected, binding)
		}
	}
	return selected, nil
}

func buildOutputArtifacts(ctx context.Context, root, directory string, race bool, bindings []outputProfileBinding) ([]*outputArtifactClosure, error) {
	return buildOutputArtifactsOwned(nil, ctx, root, directory, race, bindings)
}

func outputArtifactConstructionCommands(command outputProfileCommand) []checkCommandFacts {
	commands := make([]checkCommandFacts, 0, 6)
	for range 4 {
		commands = append(commands, preparationReservationFact(command.module, true))
	}
	return commands
}

func outputConstructionCommands(bindings []outputProfileBinding) ([]checkCommandFacts, error) {
	if bindings == nil {
		command, _ := outputCommand("ENKV/OUTPUT/TEST-PROFILE/v3")
		return outputArtifactConstructionCommands(command), nil
	}
	selected, err := validateOutputBindings(bindings)
	if err != nil {
		return nil, err
	}
	var commands []checkCommandFacts
	for _, binding := range selected {
		command, _ := outputCommand(binding.StoredProfileID)
		commands = append(commands, outputArtifactConstructionCommands(command)...)
	}
	return commands, nil
}

func buildOutputArtifactsOwned(diagnostics *checkDiagnostics, ctx context.Context, root, directory string, race bool, bindings []outputProfileBinding) ([]*outputArtifactClosure, error) {
	if diagnostics != nil && !diagnostics.hasPlan() {
		commands, err := outputConstructionCommands(bindings)
		if err != nil {
			return nil, err
		}
		if err := diagnostics.reserveCommands(commands); err != nil {
			return nil, err
		}
		defer diagnostics.cancelReservations()
	}
	if bindings == nil {
		closure, err := buildOutputTestArtifactOwned(diagnostics, ctx, root, directory, race)
		if err != nil {
			return nil, err
		}
		return []*outputArtifactClosure{closure}, nil
	}
	selected, err := validateOutputBindings(bindings)
	if err != nil {
		return nil, err
	}
	artifacts := make([]*outputArtifactClosure, 0, len(selected))
	for _, binding := range selected {
		command, _ := outputCommand(binding.StoredProfileID)
		artifact, err := buildOutputArtifactOwned(diagnostics, ctx, root, directory, race, command, binding)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, artifact)
	}
	return artifacts, nil
}

func buildOutputTestArtifactOwned(diagnostics *checkDiagnostics, ctx context.Context, root, directory string, race bool) (*outputArtifactClosure, error) {
	command, _ := outputCommand("ENKV/OUTPUT/TEST-PROFILE/v3")
	descriptor, _, err := readOutputDescriptor(ctx, root, command)
	if err != nil {
		return nil, err
	}
	binding, err := outputDescriptorBinding(command.label, descriptor)
	if err != nil {
		return nil, err
	}
	return buildOutputArtifactOwned(diagnostics, ctx, root, directory, race, command, binding)
}

func readOutputDescriptor(ctx context.Context, root string, command outputProfileCommand) (artifactpkg.Descriptor, []byte, error) {
	path, err := sourcePath(root, command.module+"/cmd/"+command.command+"/plugin.json")
	if err != nil {
		return artifactpkg.Descriptor{}, nil, err
	}
	return artifactpkg.ReadDescriptor(ctx, path)
}

func outputDescriptorBinding(label string, descriptor artifactpkg.Descriptor) (outputProfileBinding, error) {
	id, err := descriptor.Identity()
	if err != nil || descriptor.Role != "output" || descriptor.Output == nil {
		return outputProfileBinding{}, errors.Join(err, errors.New("output descriptor refused"))
	}
	route, err := credentialroute.Decode(descriptor.Output.CredentialRoute)
	if err != nil {
		return outputProfileBinding{}, err
	}
	routeID, err := credentialroute.Identity(route)
	if err != nil {
		return outputProfileBinding{}, err
	}
	return outputProfileBinding{StoredProfileID: label, DescriptorID: protocol.ID(id), CredentialRouteID: protocol.ID(routeID), ConfigContractID: descriptor.Output.ConfigContractID, CredentialRouteContractID: artifactpkg.Digest(route.ContractID).String()}, nil
}

func buildOutputArtifactOwned(diagnostics *checkDiagnostics, ctx context.Context, root, directory string, race bool, command outputProfileCommand, binding outputProfileBinding) (*outputArtifactClosure, error) {
	ctx = withRacePolicy(ctx, race && command.module == outputTestModule)
	recipe := struct {
		Module, Command string
		Binding         outputProfileBinding
	}{command.module, command.command, binding}
	value, _, err := invocationArtifactValue(ctx, root, directory, "output", recipe, func(build string) (*outputArtifactClosure, error) {
		value, err := constructOutputArtifactOwned(diagnostics, ctx, root, build, race, command, binding)
		if value != nil {
			value.directory = build
		}
		return value, err
	})
	if err != nil {
		return nil, err
	}
	for _, suffix := range []string{"", ".installation.json", ".dependency"} {
		if err := linkInvocationFile(filepath.Join(value.directory, command.command)+suffix, filepath.Join(directory, command.command)+suffix); err != nil {
			return nil, err
		}
	}
	return value, nil
}

func constructOutputArtifactOwned(diagnostics *checkDiagnostics, ctx context.Context, root, directory string, race bool, command outputProfileCommand, binding outputProfileBinding) (result *outputArtifactClosure, err error) {
	if diagnostics != nil && !diagnostics.hasPlan() {
		if err := diagnostics.reserveCommands(outputArtifactConstructionCommands(command)); err != nil {
			return nil, err
		}
		defer diagnostics.cancelReservations()
	}
	execute := runGoEnvironment
	if diagnostics != nil {
		execute = diagnostics.runGoEnvironment
	}
	descriptor, _, err := readOutputDescriptor(ctx, root, command)
	if err != nil {
		return nil, err
	}
	declared, err := outputDescriptorBinding(binding.StoredProfileID, descriptor)
	if err != nil || declared != binding {
		return nil, errors.Join(err, errors.New("output selected descriptor differs"))
	}
	race = race && command.module == outputTestModule
	ctx = withRacePolicy(ctx, race)
	env := outputBuildEnvironment(command)
	flags := []string{"-mod=readonly"}
	if race {
		flags = append(flags, "-race")
	}
	modules, packages, err := listClosureEnvironment(localDiscoveryCommand(execute), ctx, root, command.module, env, flags, false, "./cmd/"+command.command)
	if err != nil {
		return nil, err
	}
	protocolFiles, _, err := compiledSourceDigest(root, "protocols/output", "enkv.sh/sdk/protocols/output", outputSourceDomain, []string{"LICENSE", "go.mod"}, packages)
	if err != nil {
		return nil, err
	}
	sdkFiles, _, err := compiledSourceDigest(root, "sdk/output", "enkv.sh/sdk/output", outputSourceDomain, []string{"LICENSE", "go.mod"}, packages)
	if err != nil {
		return nil, err
	}
	pluginMetadata := []string{"LICENSE", "THIRD_PARTY_NOTICES.md", "go.mod"}
	if command.module == outputTestModule {
		pluginMetadata = []string{"go.mod"}
	}
	pluginFiles, _, err := compiledSourceDigest(root, command.module, modulePath(command.module), outputSourceDomain, pluginMetadata, packages)
	if err != nil {
		return nil, err
	}
	closure := makeClosure("output", command.provider, modules, packages)
	if _, err := execute(ctx, root, command.module, env, append(append([]string{"vet"}, flags...), "./...")...); err != nil {
		failure := containProcessFailure(ctx, err)
		if !containedCheckFailure(ctx, failure) {
			return nil, err
		}
		return nil, failure
	}
	path := filepath.Join(directory, command.command)
	buildArgs := []string{"build", "-mod=readonly", "-trimpath", "-buildvcs=false"}
	if race {
		buildArgs = append(buildArgs, "-race")
	}
	buildArgs = append(buildArgs, "-o", path, "./cmd/"+command.command)
	if _, err := execute(ctx, root, command.module, env, buildArgs...); err != nil {
		failure := containProcessFailure(ctx, err)
		if !containedCheckFailure(ctx, failure) {
			return nil, err
		}
		return nil, failure
	}
	if err := os.Chmod(path, 0700); err != nil {
		return nil, err
	}
	info, err := buildinfo.ReadFile(path)
	if err != nil || info.GoVersion != "go1.27.3" || info.Main.Path != modulePath(command.module) || info.Path != modulePath(command.module)+"/cmd/"+command.command {
		return nil, errors.New("output artifact build identity differs")
	}
	facts, err := captureArtifactBuildFacts(ctx, root, "output", modules, packages, info, []artifactpkg.Contract{descriptor.Wire})
	if err != nil {
		return nil, err
	}
	manifest, err := outputhost.EncodeDependencyManifest(outputhost.DependencyManifest{Facts: &facts})
	if err != nil {
		return nil, err
	}
	if err := outputhost.VerifyDependencyBuildInfo(info, manifest); err != nil {
		return nil, err
	}
	digest, length, err := cloudflareArtifactIdentity(path)
	if err != nil {
		return nil, err
	}
	metadata, err := outputArtifactMetadata(descriptor, artifactpkg.Digest(digest), uint64(length), facts, manifest)
	if err != nil {
		return nil, err
	}
	installation, err := outputhost.NewInstallation(metadata, manifest)
	if err != nil {
		return nil, err
	}
	evidence := &outputArtifactClosure{Race: race, Artifact: installation.Artifact(), Metadata: &metadata, ProtocolSource: protocolFiles, SDKSource: sdkFiles, DependencyManifest: manifest, PluginSource: pluginFiles, ResolvedModules: closure.ResolvedModules, CompiledImports: closure.CompiledImports}
	installationBytes, err := outputInstallationBytes(evidence)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path+".installation.json", installationBytes, 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path+".dependency", manifest, 0600); err != nil {
		return nil, err
	}
	return evidence, nil
}

func outputBuildEnvironment(command outputProfileCommand) []string {
	if command.module == outputTestModule {
		return nil
	}
	return stockPluginBuildEnvironment()
}

func stockPluginBuildEnvironment() []string {
	fixed := map[string]string{
		"GOENV": "off", "GO111MODULE": "on", "GOTOOLCHAIN": "local", "GOWORK": "off", "GOFLAGS": buildGoFlags,
		"CGO_ENABLED": "0", "GOOS": runtime.GOOS, "GOARCH": runtime.GOARCH, "GOAMD64": "v1", "GOARM64": "v8.0",
	}
	for _, key := range []string{"GOEXPERIMENT", "GCCGO", "CC", "CXX", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS", "CGO_LDFLAGS", "GOTOOLDIR", "GOCACHEPROG", "GOFIPS140", "GODEBUG"} {
		fixed[key] = ""
	}
	return environment(goEnvironment(), fixed)
}

func verifyOutputArtifact(ctx context.Context, root, directory string, closure *outputArtifactClosure) error {
	return verifyOutputArtifactOwned(nil, ctx, root, directory, closure)
}

func outputVerificationCommands(closure *outputArtifactClosure) ([]checkCommandFacts, error) {
	if err := validateOutputArtifactClosures([]*outputArtifactClosure{closure}); err != nil {
		return nil, err
	}
	binding, err := outputBinding(closure.Artifact)
	if err != nil {
		return nil, err
	}
	command, _ := outputCommand(binding.StoredProfileID)
	return []checkCommandFacts{preparationReservationFact(command.module, true), preparationReservationFact(command.module, true)}, nil
}

func verifyOutputArtifactOwned(diagnostics *checkDiagnostics, ctx context.Context, root, directory string, closure *outputArtifactClosure) error {
	if diagnostics != nil && !diagnostics.hasPlan() {
		commands, err := outputVerificationCommands(closure)
		if err != nil {
			return err
		}
		if err := diagnostics.reserveCommands(commands); err != nil {
			return err
		}
		defer diagnostics.cancelReservations()
	}
	execute := runGoEnvironment
	if diagnostics != nil {
		execute = diagnostics.runGoEnvironment
	}
	if err := validateOutputArtifactClosures([]*outputArtifactClosure{closure}); err != nil {
		return err
	}
	binding, err := outputBinding(closure.Artifact)
	if err != nil {
		return err
	}
	command, _ := outputCommand(binding.StoredProfileID)
	for _, source := range []struct {
		module, path string
		files        []artifactSourceFile
	}{
		{"protocols/output", "enkv.sh/sdk/protocols/output", closure.ProtocolSource},
		{"sdk/output", "enkv.sh/sdk/output", closure.SDKSource},
		{command.module, modulePath(command.module), closure.PluginSource},
	} {
		if _, err := retainedOutputSourceDigest(root, source.module, source.path, source.files); err != nil {
			return err
		}
	}
	descriptor, _, err := readOutputDescriptor(ctx, root, command)
	if err != nil {
		return err
	}
	declared, err := outputDescriptorBinding(binding.StoredProfileID, descriptor)
	if err != nil || declared != binding {
		return errors.Join(err, errors.New("output descriptor binding differs"))
	}
	ctx = withRacePolicy(ctx, closure.Race)
	flags := []string{"-mod=readonly"}
	if closure.Race {
		flags = append(flags, "-race")
	}
	modules, packages, err := listClosureEnvironment(execute, ctx, root, command.module, outputBuildEnvironment(command), flags, false, "./cmd/"+command.command)
	if err != nil {
		return err
	}
	info, err := buildinfo.ReadFile(filepath.Join(directory, command.command))
	if err != nil {
		return err
	}
	current, err := captureArtifactBuildFacts(ctx, root, "output", modules, packages, info, []artifactpkg.Contract{descriptor.Wire})
	if err != nil {
		return err
	}
	body, err := artifactpkg.EncodeDependency(current)
	if err != nil || !bytes.Equal(body, closure.DependencyManifest) {
		return errors.Join(err, errors.New("output artifact selected build facts changed"))
	}
	digest, length, err := cloudflareArtifactIdentity(filepath.Join(directory, command.command))
	if err != nil || protocol.ID(digest) != closure.Artifact.SHA256 || uint64(length) != closure.Artifact.Length {
		return errors.Join(err, errors.New("output artifact binary changed"))
	}
	return nil
}

func validateOutputArtifactClosures(closures []*outputArtifactClosure) error {
	if len(closures) == 0 || len(closures) > len(outputProductionCommands) {
		return errors.New("output installation binding count refused")
	}
	seen := make(map[protocol.ID]bool, len(closures))
	for _, closure := range closures {
		if closure == nil || closure.Metadata == nil || len(closure.ProtocolSource) == 0 || len(closure.SDKSource) == 0 || len(closure.PluginSource) == 0 || len(closure.DependencyManifest) == 0 {
			return errors.New("output installation complete metadata or source identity missing; incompatible continuation refused")
		}
		installation, err := outputhost.NewInstallation(*closure.Metadata, closure.DependencyManifest)
		if err != nil || installation.Artifact() != closure.Artifact {
			return errors.Join(err, errors.New("output installation metadata binding differs"))
		}
		facts := closure.Metadata.BuildFacts()
		race := slices.Contains(facts.BuildOptions, artifactpkg.BuildOption{Name: "-race", Value: "true"})
		if race != closure.Race {
			return errors.New("output installation dependency race mode differs")
		}
		expected := make([]moduleIdentity, 0, len(facts.Resolved))
		for _, row := range facts.Resolved {
			version := row.Version
			if version == "" {
				version = "local"
			}
			expected = append(expected, moduleIdentity{Path: row.Path, Version: version})
		}
		resolved := slices.Clone(closure.ResolvedModules)
		slices.SortFunc(resolved, func(a, b moduleIdentity) int { return strings.Compare(a.Path, b.Path) })
		slices.SortFunc(expected, func(a, b moduleIdentity) int { return strings.Compare(a.Path, b.Path) })
		if !slices.Equal(expected, resolved) {
			return errors.New("output manifest resolved graph differs")
		}
		if closure.Race != closures[0].Race {
			return errors.New("output installation race modes differ")
		}
		if seen[closure.Artifact.DescriptorID] {
			return errors.New("output installation descriptor repeated")
		}
		seen[closure.Artifact.DescriptorID] = true
	}
	return nil
}

func retainedOutputBindings(closures []*outputArtifactClosure) ([]outputProfileBinding, error) {
	if err := validateOutputArtifactClosures(closures); err != nil {
		return nil, err
	}
	selected := make([]outputProfileBinding, 0, len(closures))
	for _, closure := range closures {
		binding, err := outputBinding(closure.Artifact)
		if err != nil {
			return nil, err
		}
		if binding.StoredProfileID == "ENKV/OUTPUT/TEST-PROFILE/v3" {
			if len(closures) != 1 {
				return nil, errors.New("output test and production qualification installations mixed")
			}
			return nil, nil
		}
		selected = append(selected, binding)
	}
	return validateOutputBindings(selected)
}

func retainedOutputSourceDigest(root, module, modulePath string, files []artifactSourceFile) (protocol.ID, error) {
	hash := sha256.New()
	_, _ = hash.Write([]byte(outputSourceDomain))
	cloudflareAppendBlob(hash, []byte(modulePath))
	_, _ = hash.Write(binary.BigEndian.AppendUint32(nil, uint32(len(files))))
	previous := ""
	for _, file := range files {
		clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(file.Path)))
		if clean != file.Path || filepath.IsAbs(filepath.FromSlash(file.Path)) || clean == ".." || strings.HasPrefix(clean, "../") {
			return protocol.ID{}, errors.New("output source path refused")
		}
		if file.Path <= previous {
			return protocol.ID{}, errors.New("output source list is not canonical")
		}
		previous = file.Path
		path, err := sourcePath(root, module+"/"+file.Path)
		if err != nil {
			return protocol.ID{}, err
		}
		body, err := regularFileBytes(path)
		if err != nil {
			return protocol.ID{}, err
		}
		digest := sha256.Sum256(body)
		if hex.EncodeToString(digest[:]) != file.SHA256 {
			return protocol.ID{}, errors.New("output source changed")
		}
		cloudflareAppendBlob(hash, []byte(file.Path))
		cloudflareAppendBlob(hash, body)
	}
	var digest protocol.ID
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

func outputArtifactMetadata(descriptor artifactpkg.Descriptor, digest artifactpkg.Digest, length uint64, facts artifactpkg.BuildFacts, dependency []byte) (artifactpkg.Metadata, error) {
	dependencyID, err := artifactpkg.DependencyID("output", dependency)
	if err != nil {
		return artifactpkg.Metadata{}, err
	}
	family, err := artifactpkg.BindOutputFacts(artifactpkg.OutputFacts{Schema: artifactpkg.FamilySchema, Descriptor: descriptor, ExecutionFacts: artifactpkg.ExecutionFacts{Module: facts.MainModule, Command: facts.Command, GoVersion: facts.Toolchain, NativeTuple: facts.Platform}}, digest, length, dependencyID)
	if err != nil {
		return artifactpkg.Metadata{}, err
	}
	body, err := json.Marshal(family)
	if err != nil {
		return artifactpkg.Metadata{}, err
	}
	metadata := artifactpkg.Metadata{Schema: "enkv/plugin-artifact/v2", Purpose: "plugin-executable", Name: descriptor.Name, Role: facts.Role, Version: descriptor.Version, MainModule: facts.MainModule, Command: facts.Command, Platform: facts.Platform, Toolchain: facts.Toolchain, BuildOptions: facts.BuildOptions, Contracts: facts.Contracts, Sources: facts.Sources, Resolved: facts.Resolved, Compiled: facts.Compiled, Executable: artifactpkg.DigestLength{SHA256: digest, Length: length}, Family: &artifactpkg.Family{Schema: artifactpkg.FamilySchema, Facts: body, Dependency: artifactpkg.DigestLength{SHA256: artifactpkg.Hash(dependency), Length: uint64(len(dependency))}}}
	if _, err := outputhost.NewInstallation(metadata, dependency); err != nil {
		return artifactpkg.Metadata{}, err
	}
	return metadata, nil
}

func outputInstallationBytes(closure *outputArtifactClosure) ([]byte, error) {
	return json.Marshal(struct {
		Artifact outputhost.Artifact   `json:"artifact"`
		Metadata *artifactpkg.Metadata `json:"metadata,omitempty"`
	}{closure.Artifact, closure.Metadata})
}

func outputFixtureLinkerFlag(closures []*outputArtifactClosure) (string, error) {
	if err := validateOutputArtifactClosures(closures); err != nil {
		return "", err
	}
	expectations := make(map[string][2]string, len(closures))
	for _, closure := range closures {
		binding, err := outputBinding(closure.Artifact)
		if err != nil {
			return "", err
		}
		command, _ := outputCommand(binding.StoredProfileID)
		body, err := outputInstallationBytes(closure)
		if err != nil {
			return "", err
		}
		expectations[command.command] = [2]string{digestBytes(body), digestBytes(closure.DependencyManifest)}
	}
	body, err := json.Marshal(expectations)
	if err != nil {
		return "", err
	}
	return "-X '" + componentPackage + ".publicationFixtureExpectations=" + string(body) + "'", nil
}

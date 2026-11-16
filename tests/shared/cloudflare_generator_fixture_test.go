package core

import (
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/binary"
	"encoding/json"
	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
	protocol "enkv.sh/sdk/protocols/generator"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/generatorhost"
	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
	"golang.org/x/sys/unix"
)

const (
	hermeticCloudflareAccount    = "0123456789abcdef0123456789abcdef"
	hermeticCloudflarePermission = "11111111111111111111111111111111"
	hermeticCloudflareToken      = "22222222222222222222222222222222"
	hermeticCloudflareBearer     = "Management_bearer_0123456789_ABCDEFGHIJKLMN"
	hermeticCloudflareSecret     = "Generated_secret_0123456789_ABCDEFGHIJKLMN"
)

func generatorRemovalFixtureRoot(t testing.TB) string {
	t.Helper()
	root, err := os.MkdirTemp("", "enkv-generator-completion-")
	if err != nil {
		t.Fatal(err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		launches, err := filepath.Glob(filepath.Join(root, "enkv-generator-*", ".launch-*"))
		if err != nil {
			t.Error("generator completion fixture inventory unavailable")
			return
		}
		for _, launch := range launches {
			if !generatorRemovalChildAbsent(launch) {
				t.Errorf("generator completion fixture retained at %s: child settlement unavailable", root)
				return
			}
			if err := os.Chmod(launch, 0700); err != nil {
				t.Error("joined generator completion fixture permissions not restored")
				return
			}
		}
		if err := os.RemoveAll(root); err != nil {
			t.Error("joined generator completion fixture cleanup failed")
		}
	})
	t.Setenv("TMPDIR", root)
	return root
}

func generatorRemovalChildAbsent(launch string) bool {
	body, err := os.ReadFile(filepath.Join(launch, "completion.pid"))
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(string(body))
	return err == nil && pid > 0 && errors.Is(unix.Kill(pid, 0), unix.ESRCH)
}

func assertGeneratorRemovalFixture(t testing.TB, root string) {
	t.Helper()
	launches, err := filepath.Glob(filepath.Join(root, "enkv-generator-*", ".launch-*"))
	if err != nil || len(launches) != 1 {
		t.Fatalf("sole executable-removal premise unavailable: launch_count=%d inventory_error=%t", len(launches), err != nil)
	}
	info, err := os.Lstat(launches[0])
	absent := generatorRemovalChildAbsent(launches[0])
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0500 || !absent {
		t.Fatalf("sole executable-removal premise invalid: stat_error=%t child_absent=%t", err != nil, absent)
	}
}

func generatorCleanupDiagnostic(d contract.Diagnostic) bool {
	return d.Subject == (contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}) &&
		len(d.Path) == 1 && d.Path[0] == contract.FieldPresence && d.Outcome == contract.DiagnosticUnable &&
		d.Reason == contract.ReasonEvidenceUnavailable && d.SourceLocation == nil
}

func hermeticCloudflareIntent() ([]byte, []byte) {
	return cloudflareIntent(hermeticCloudflareAccount, hermeticCloudflarePermission, "generated")
}

func cloudflareIntent(accountID, permissionID, name string) ([]byte, []byte) {
	// The literal settings use the plugin's canonical JSON field order. The
	// generic envelope is constructed independently of the plugin normalizer.
	settings := []byte(fmt.Sprintf(`{"account":"%s","name":"%s","policies":[{"effect":"allow","permission_groups":["%s"],"resources":[{"kind":"account","id":"%s"}]}]}`, accountID, name, permissionID, accountID))
	intent := hermeticCloudflareCanonicalIntent(settings)
	request := []byte(fmt.Sprintf(`{"name":"%s","policies":[{"effect":"allow","permission_groups":[{"id":"%s"}],"resources":{"com.cloudflare.api.account.%s":"*"}}]}`,
		name, permissionID, accountID))
	return intent, request
}

func hermeticCloudflareHTTPRequestDigest(body []byte) contract.ID {
	return hermeticCloudflareActionDigest(1, "", body)
}

func hermeticCloudflareActionDigest(action uint8, target string, body []byte) contract.ID {
	return cloudflareActionDigest(hermeticCloudflareAccount, action, target, body)
}

func cloudflareActionDigest(account string, action uint8, target string, body []byte) contract.ID {
	path := "/accounts/" + account + "/tokens"
	contentType := "application/json"
	if action == 2 {
		path, contentType = path+"/"+target, ""
	}
	preimage := []byte{action}
	for _, value := range [][]byte{[]byte(path), []byte(contentType), body} {
		preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(value)))
		preimage = append(preimage, value...)
	}
	prefix := []byte("ENKV/GENERATOR/v1/http-request\x00")
	prefix = binary.BigEndian.AppendUint32(prefix, uint32(len(preimage)))
	return sha256.Sum256(append(prefix, preimage...))
}

func hermeticCloudflarePluginDirectory(t testing.TB) (string, string) {
	t.Helper()
	working, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	if filepath.Base(working) == "core" {
		working = filepath.Dir(working)
	}
	directory := filepath.Join(filepath.Dir(working), "enkv-extensions", "plugins/generators/cloudflare-account-token")
	if info, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil && info.Mode().IsRegular() {
		return working, directory
	}

	t.Fatal("Cloudflare plugin module unavailable")
	return "", ""
}

func buildHermeticCloudflareGenerator(t testing.TB, origin string) (string, contract.GeneratorImplementation) {
	t.Helper()
	return buildHermeticCloudflareGeneratorRevision(t, origin, false)
}

func buildHermeticCloudflareGeneratorWithRemovalFailure(t testing.TB, origin string) (string, contract.GeneratorImplementation) {
	t.Helper()
	return buildHermeticCloudflareGeneratorRevision(t, origin, true)
}

func buildHermeticCloudflareGeneratorRevision(t testing.TB, origin string, removalFailure bool) (string, contract.GeneratorImplementation) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "enkv-generator-cloudflare-test")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-tags=enkv_cloudflare_testartifact",
		"-ldflags=-X=enkv.sh/plugins/generators/cloudflare-account-token/internal/cloudflare.unqualifiedTestArtifactOrigin="+origin,
		"-o", path, "./cmd/enkv-generator-cloudflare-test")
	sourceRoot, pluginDirectory := hermeticCloudflarePluginDirectory(t)
	if removalFailure {
		copied := t.TempDir()
		if err := os.CopyFS(copied, os.DirFS(pluginDirectory)); err != nil {
			t.Fatal(err)
		}
		mainPath := filepath.Join(copied, "cmd/enkv-generator-cloudflare-test/main.go")
		body, err := os.ReadFile(mainPath)
		if err != nil {
			t.Fatal(err)
		}
		before := "os.Exit(generator.Main(implementation))"
		if strings.Count(string(body), before) != 1 {
			t.Fatal("controlled generator completion source changed")
		}
		body = []byte(strings.Replace(string(body), "import (", "import (\n\t\"context\"\n\t\"path/filepath\"\n\t\"strconv\"\n\tprotocol \"enkv.sh/sdk/protocols/generator\"", 1))
		after := `create := implementation.Create
	implementation.Create = func(ctx context.Context, invocation generator.Invocation) (protocol.SafeFacts, []byte, error) {
		facts, value, err := create(ctx, invocation)
		if err != nil || facts.Disposition != protocol.DispositionCompleteCreate { return facts, value, err }
		directory := filepath.Dir(os.Args[0])
		if err := os.WriteFile(filepath.Join(directory, "completion.pid"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			clear(value); return protocol.SafeFacts{}, nil, err
		}
		if err := os.Chmod(directory, 0500); err != nil {
			clear(value); return protocol.SafeFacts{}, nil, err
		}
		return facts, value, nil
	}
	` + before
		body = []byte(strings.Replace(string(body), before, after, 1))
		if err := os.WriteFile(mainPath, body, 0600); err != nil {
			t.Fatal(err)
		}
		pluginDirectory = copied
	}
	command.Dir = pluginDirectory
	command.Env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local", "GOFLAGS=-trimpath")
	if removalFailure {
		body, err := os.ReadFile(filepath.Join(pluginDirectory, "go.mod"))
		if err != nil {
			t.Fatal(err)
		}
		for _, relative := range []string{"sdk/artifact", "sdk/generator", "sdk/protocols/generator"} {
			physical, err := filepath.EvalSymlinks(filepath.Join(filepath.Dir(sourceRoot), "enkv-extensions", relative))
			if err != nil {
				t.Fatal(err)
			}
			body = append(body, []byte("\nreplace enkv.sh/"+relative+" => "+strconv.Quote(physical)+"\n")...)
		}
		modfile := path + ".mod"
		if err := os.WriteFile(modfile, body, 0600); err != nil {
			t.Fatal(err)
		}
		command.Args = append(command.Args[:2], append([]string{"-modfile=" + modfile}, command.Args[2:]...)...)
	} else {
		prepareNativeModule(t, sourceRoot, command, path+".mod")
	}
	before := captureHermeticGeneratorBuildInputs(t, command)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build tagged Cloudflare process: %v\n%s", err, output)
	}
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	info, err := buildinfo.ReadFile(path)
	if err != nil || info.GoVersion != "go1.27.3" {
		t.Fatal("current tagged Cloudflare compiler identity", err)
	}
	if err := os.Mkdir(filepath.Join(filepath.Dir(path), ".enkv-generator-staging"), 0700); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest, length := sha256.Sum256(body), uint64(len(body))
	clear(body)
	descriptorBytes, err := os.ReadFile(filepath.Join(pluginDirectory, "cmd/enkv-generator-cloudflare-test/plugin.json"))
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := artifact.DecodeDescriptor(descriptorBytes)
	if err != nil {
		t.Fatal(err)
	}
	metadata, dependency := hermeticGeneratorMetadata(t, command, path, descriptor, before)
	installed, err := generatorhost.NewInstallation(metadata, dependency)
	if err != nil {
		t.Fatal("admit tagged Cloudflare installation", err)
	}
	row := installed.Artifact()
	encoded, err := artifact.EncodeMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	for suffix, body := range map[string][]byte{".metadata.json": encoded, ".dependencies.bin": dependency} {
		if err := os.WriteFile(path+suffix, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("tagged Cloudflare custody artifact sha256=%x length=%d tuple=%s", digest, length, row.NativeTuple)
	return path, row
}

func nativeGeneratedFixtureProfile(t testing.TB, row contract.GeneratorImplementation) generatedFixtureProfile {
	t.Helper()
	profile := generatedFixtureProfile{LifecycleMode: contract.GeneratorLifecycleManaged, ResultReaderID: contract.GeneratorResultReaderID(), ConfigContractID: row.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(), ExecutorID: row.ExecutorID,
		CredentialRouteID: row.CredentialRouteID, DescriptorID: row.DescriptorID,
		CompletionClass: contract.GeneratedCompletionAcknowledged, RetirementMode: contract.GeneratedRetirementManual}
	var err error
	profile.CreateResultContractID, err = contract.GeneratedResultContractID(row, contract.GeneratorActionCreate,
		profile.CompletionClass, 65536, contract.GeneratorSafeFactsEnvelopeLength, contract.InputEncodingRaw)
	if err != nil {
		t.Fatal("native fixture create result contract", err)
	}
	profile.DeleteResultContractID, err = contract.GeneratedResultContractID(row, contract.GeneratorActionDelete,
		profile.CompletionClass, 0, contract.GeneratorSafeFactsEnvelopeLength, contract.InputEncodingRaw)
	if err != nil {
		t.Fatal("native fixture delete result contract", err)
	}
	return profile
}

func hermeticCloudflareConfig(t testing.TB, artifact, origin string, row contract.GeneratorImplementation,
	expected contract.GeneratorResultExpectation) custody.GeneratedProcessConfig {
	t.Helper()
	if row.ConfigContractID != expected.Template.ConfigContractID || hermeticCloudflareResourceContractID() != expected.Template.ResourceContractID || row.ExecutorID != expected.Template.ExecutorID || row.CredentialRouteID != expected.Template.CredentialRouteID || row.DescriptorID != expected.Template.DescriptorID {
		t.Fatal("tagged Cloudflare row differs from the selected attempt")
	}
	// Native Main installs this ordinary environment input after command admission.
	t.Setenv("CLOUDFLARE_API_TOKEN", hermeticCloudflareBearer)
	metadata, err := os.ReadFile(artifact + ".metadata.json")
	if err != nil {
		t.Fatal(err)
	}
	dependency, err := os.ReadFile(artifact + ".dependencies.bin")
	if err != nil {
		t.Fatal(err)
	}
	return custody.GeneratedProcessConfig{ArtifactPath: artifact, Artifact: row, Metadata: metadata, Dependency: dependency}
}

func hermeticCloudflareResourceContractID() contract.ID {
	return sha256.Sum256([]byte("ENKV/CLOUDFLARE-ACCOUNT-TOKEN/RESOURCE/v1\x00https://api.cloudflare.com/client/v4"))
}
func hermeticCloudflareCanonicalIntent(settings []byte) []byte {
	config := sha256.Sum256([]byte("ENKV/CLOUDFLARE-ACCOUNT-TOKEN/CONFIG/v1\x00https://api.cloudflare.com/client/v4"))
	resource := hermeticCloudflareResourceContractID()
	body := []byte{0, 1}
	body = append(body, config[:]...)
	body = append(body, byte(contract.GeneratorLifecycleManaged))
	body = append(body, resource[:]...)
	body = binary.BigEndian.AppendUint32(body, uint32(len(settings)))
	return append(body, settings...)
}

// This is the existing native build's complete public dependency capture. The
// test build uses measured tags and linker options, which are retained as data.
type hermeticGeneratorBuildInputs struct {
	modules  []artifact.SourceModule
	packages []artifact.SourcePackage
	sources  []artifact.Source
}

func captureHermeticGeneratorBuildInputs(t testing.TB, build *exec.Cmd) hermeticGeneratorBuildInputs {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	flags := []string{"-mod=readonly"}
	for _, arg := range build.Args[2:] {
		if strings.HasPrefix(arg, "-modfile=") || strings.HasPrefix(arg, "-tags=") || arg == "-race" {
			flags = append(flags, arg)
		}
	}
	list := func(args ...string) []byte {
		command := exec.CommandContext(ctx, "go", args...)
		command.Dir, command.Env = build.Dir, slices.Clone(build.Env)
		body, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("capture native generator closure: %v\n%s", err, body)
		}
		return body
	}
	var modules []artifact.SourceModule
	decoder := json.NewDecoder(strings.NewReader(string(list(append([]string{"list", "-m", "-json"}, append(flags, "all")...)...))))
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
	var packages []artifact.SourcePackage
	decoder = json.NewDecoder(strings.NewReader(string(list(append([]string{"list", "-deps", "-json"}, append(flags, build.Args[len(build.Args)-1])...)...))))
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
	sources, err := artifact.CaptureSourcesForModules(ctx, "generator", packages, modules)
	if err != nil {
		t.Fatal(err)
	}

	return hermeticGeneratorBuildInputs{modules: modules, packages: packages, sources: sources}
}
func hermeticGeneratorMetadata(t testing.TB, build *exec.Cmd, path string, descriptor artifact.Descriptor, before hermeticGeneratorBuildInputs) (artifact.Metadata, []byte) {
	t.Helper()
	after := captureHermeticGeneratorBuildInputs(t, build)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("native generator selected inputs changed during build")
	}
	modules, sources := after.modules, after.sources
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
	for _, row := range sources {
		digests[row.Module] = row.Digest
	}
	resolved := make([]artifact.Dependency, 0, len(modules))
	for _, module := range modules {
		row := artifact.Dependency{Path: module.Path, Version: module.Version, Sum: module.Sum}
		if r := module.Replace; r != nil {
			row.Replacement = &artifact.Replacement{Path: r.Path, Version: r.Version, Sum: r.Sum}
			if r.Version == "" && r.Sum == "" {
				row.Replacement.SourceDigest = digests[module.Path]
			}
		}
		resolved = append(resolved, row)
	}
	slices.SortFunc(resolved, func(a, b artifact.Dependency) int { return strings.Compare(a.Path, b.Path) })
	facts := artifact.BuildFacts{Role: "generator", MainModule: info.Main.Path, Command: info.Path, Platform: runtime.GOOS + "/" + runtime.GOARCH, Toolchain: info.GoVersion, BuildOptions: options, Contracts: []artifact.Contract{descriptor.Wire}, Sources: sources, Resolved: resolved, Compiled: compiled}
	if err := artifact.VerifyBuildInfo(info, facts); err != nil {
		t.Fatal(err)
	}
	dependency, err := artifact.EncodeDependency(facts)
	if err != nil {
		t.Fatal(err)
	}
	id, err := artifact.DependencyID("generator", dependency)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := artifact.ExecutableIdentity(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	family, err := artifact.BindGeneratorFacts(artifact.GeneratorFacts{Schema: artifact.FamilySchema, Descriptor: descriptor, ExecutionFacts: artifact.ExecutionFacts{Module: info.Main.Path, Command: info.Path, GoVersion: info.GoVersion, NativeTuple: facts.Platform}}, executable.SHA256, executable.Length, id)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(family)
	if err != nil {
		t.Fatal(err)
	}
	metadata := artifact.Metadata{Schema: "enkv/plugin-artifact/v2", Purpose: "plugin-executable", Name: descriptor.Name, Role: "generator", Version: descriptor.Version, MainModule: facts.MainModule, Command: facts.Command, Platform: facts.Platform, Toolchain: facts.Toolchain, BuildOptions: options, Contracts: facts.Contracts, Sources: sources, Resolved: resolved, Compiled: compiled, Executable: executable, Family: &artifact.Family{Schema: artifact.FamilySchema, Facts: raw, Dependency: artifact.DigestLength{SHA256: artifact.Hash(dependency), Length: uint64(len(dependency))}}}
	return metadata, dependency
}

func generatedFactsResourceDigest(facts contract.GeneratorSafeFacts) contract.ID {
	// Independent public preimage; provider diagnostics are deliberately excluded.
	if len(facts.Target) == 0 || len(facts.ResourceData) == 0 {
		return contract.ID{}
	}
	body := append([]byte("ENKV/GENERATOR/v1/resource-v1\x00"), 0, 0, 0, 0)
	payload := append([]byte(nil), facts.ResourceContractID[:]...)
	for _, value := range [][]byte{facts.Target, facts.ResourceData} {
		payload = binary.BigEndian.AppendUint32(payload, uint32(len(value)))
		payload = append(payload, value...)
	}
	binary.BigEndian.PutUint32(body[len(body)-4:], uint32(len(payload)))
	return sha256.Sum256(append(body, payload...))
}
func generatedTargetEvidence(t testing.TB, s *StateSession, target contract.GeneratorTarget) contract.GeneratorSafeFacts {
	t.Helper()
	work := mustSelectedGeneratedWork(t, s)
	facts, err := work.createTargetEvidence(t.Context(), target)
	if err != nil {
		t.Fatal("exact target birth evidence", err)
	}
	owned, err := facts.Own()
	if err != nil {
		t.Fatal("own exact target birth evidence", err)
	}
	return owned
}
func generatedUnknownFixtureFacts(expected contract.GeneratorResultExpectation, original contract.GeneratorSafeFacts) contract.GeneratorSafeFacts {
	x := expected.Template
	return contract.GeneratorSafeFacts{
		Schema: contract.GeneratorSafeFactsSchema, Action: x.Action, LifecycleMode: x.LifecycleMode,
		Disposition: contract.GeneratorDispositionUnknown, Reason: contract.GeneratorReasonTransport,
		ResourceContractID: x.ResourceContractID, RequestDigest: expected.RequestDigest, IntentDigest: x.IntentDigest,
		Target: slices.Clone(original.Target), ResourceData: slices.Clone(original.ResourceData),
	}
}

func hermeticCloudflareResourceDigest(token string) contract.ID {
	return generatedFactsResourceDigest(contract.GeneratorSafeFacts{ResourceContractID: hermeticCloudflareResourceContractID(), Target: []byte(hermeticCloudflareAccount), ResourceData: []byte(token)})
}
func generatedRetirementRequestDigest(target contract.GeneratorTarget) contract.ID {
	return sha256.Sum256(append([]byte("ENKV/TEST/RETIRE-RESOURCE/v1\x00"), target.ResourceDigest[:]...))
}
func installedGeneratorCreateReadiness(ctx context.Context, config custody.GeneratedProcessConfig, intent []byte) error {
	metadata, err := artifact.DecodeMetadata(config.Metadata)
	if err != nil {
		return err
	}
	installed, err := generatorhost.NewInstallation(metadata, config.Dependency)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(installed.Artifact(), config.Artifact) {
		return contract.ErrRecord
	}
	validator, err := generatorhost.NewPublicValidator(ctx, config.ArtifactPath, installed)
	if err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return contract.ErrRecord
	}
	request := protocol.CanonicalRequest{Schema: protocol.Schema, DeadlineUnixMillis: uint64(deadline.UnixMilli()), Purpose: protocol.CanonicalFreshCreate, Intent: intent}
	request.InputDigest, err = protocol.CanonicalInputDigest(request)
	if err != nil {
		return err
	}
	_, err = validator.ValidateCanonical(ctx, request)
	return err
}

func hermeticCloudflareRetirementExchange(ctx context.Context, path string, row contract.GeneratorImplementation, intent []byte, facts contract.GeneratorSafeFacts, completion uint8) ([]byte, []byte, error) {
	body, err := os.ReadFile(path + ".metadata.json")
	if err != nil {
		return nil, nil, err
	}
	metadata, err := artifact.DecodeMetadata(body)
	if err != nil {
		return nil, nil, err
	}
	dependency, err := os.ReadFile(path + ".dependencies.bin")
	if err != nil {
		return nil, nil, err
	}
	installed, err := generatorhost.NewInstallation(metadata, dependency)
	if err != nil {
		return nil, nil, err
	}
	if !reflect.DeepEqual(installed.Artifact(), row) {
		return nil, nil, contract.ErrRecord
	}
	validator, err := generatorhost.NewPublicValidator(ctx, path, installed)
	if err != nil {
		return nil, nil, err
	}
	original, err := contract.EncodeNativeGeneratorSafeFacts(facts)
	if err != nil {
		return nil, nil, err
	}
	request := protocol.RetirementCompatibilityRequest{Schema: protocol.Schema, DeadlineUnixMillis: uint64(time.Now().Add(30 * time.Second).UnixMilli()), CompletionClass: completion, Intent: intent, OriginalFacts: original}
	request.InputDigest, err = protocol.RetirementCompatibilityInputDigest(request)
	if err != nil {
		return nil, nil, err
	}
	response, err := validator.CheckRetirementCompatibility(ctx, request)
	if err != nil {
		return nil, nil, err
	}
	encoded, err := protocol.EncodeRetirementCompatibilityRequest(request)
	if err != nil {
		return nil, nil, err
	}
	result, err := protocol.EncodeValidationResponse(response)
	return encoded, result, err
}

func generatedEntryProviderToken(t testing.TB, s *StateSession, entry contract.ValueEntry) string {
	t.Helper()
	work := mustSelectedGeneratedWork(t, s)
	record, ok := work.records[generatedRecordKey{contract.GeneratedCreateEvidenceSupportKind, entry.Generated.CreateResultID}]
	if !ok {
		t.Fatal("current generated birth evidence missing")
	}
	evidence, err := contract.InspectGeneratedCreateEvidence(record.Body)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := contract.DecodeGeneratorSafeFacts(evidence.SafeFacts)
	if err != nil {
		t.Fatal(err)
	}
	return string(facts.ResourceData)
}
func generatedTargetProviderTokenID(t testing.TB, s *StateSession, target contract.GeneratorTarget) contract.ID {
	t.Helper()
	body := generatedTargetEvidence(t, s, target).ResourceData
	if len(body) != 32 {
		t.Fatal("Cloudflare fixture token width differs")
	}
	return contract.ID(body)
}

// The Core overlay supplies an ordinary passive compatibility response. Native
// installed tests use the actual selected child through PublicValidator instead.
func fixtureGeneratedSupportHandoffs(t testing.TB, s *StateSession, c *Comparison, registry []contract.GeneratorImplementation) map[string]contract.GeneratedSupportHandoff {
	t.Helper()
	if s.root.Generated.GeneratedCurrent == 0 || len(registry) == 0 {
		return nil
	}
	work := mustSelectedGeneratedWork(t, s)
	out := make(map[string]contract.GeneratedSupportHandoff)
	for _, named := range s.root.Names {
		entry := s.valueEntry(named.Slot)
		if entry.ValueSource != contract.Generated || entry.Generated.LifecycleMode != contract.GeneratorLifecycleManaged {
			continue
		}
		if slices.ContainsFunc(c.intent, func(row contract.CryptoIntentRow) bool {
			return row.Name == entry.Name && row.ValueSource == contract.Generated
		}) {
			continue
		}
		var row contract.GeneratorImplementation
		found := false
		for _, candidate := range registry {
			if candidate.ConfigContractID == entry.Generated.ConfigContractID {
				if found {
					t.Fatal("duplicate selected test generator")
				}
				row, found = candidate, true
			}
		}
		if !found {
			continue
		}
		evidence, ok := work.records[generatedRecordKey{contract.GeneratedCreateEvidenceSupportKind, entry.Generated.CreateResultID}]
		if !ok {
			t.Fatal("fixture generated birth evidence missing")
		}
		original, err := contract.InspectGeneratedCreateEvidence(evidence.Body)
		if err != nil {
			t.Fatal(err)
		}
		facts, err := contract.DecodeGeneratorSafeFacts(original.SafeFacts)
		if err != nil {
			t.Fatal(err)
		}
		native, err := contract.EncodeNativeGeneratorSafeFacts(facts)
		if err != nil {
			t.Fatal(err)
		}
		intent, err := work.readSelectedSlice(t.Context(), contract.GeneratorContentIntent, entry.Generated.IntentDigest, contract.GeneratorIntentMaxLength)
		if err != nil {
			t.Fatal(err)
		}
		request := protocol.RetirementCompatibilityRequest{Schema: protocol.Schema, DeadlineUnixMillis: uint64(time.Now().Add(time.Minute).UnixMilli()), CompletionClass: entry.Generated.CompletionClass, Intent: intent, OriginalFacts: native}
		request.InputDigest, err = protocol.RetirementCompatibilityInputDigest(request)
		if err != nil {
			t.Fatal(err)
		}
		requestBytes, err := protocol.EncodeRetirementCompatibilityRequest(request)
		if err != nil {
			t.Fatal(err)
		}
		responseBytes, err := protocol.EncodeValidationResponse(protocol.ValidationResponse{Schema: protocol.Schema, InputDigest: request.InputDigest, Accepted: true})
		if err != nil {
			t.Fatal(err)
		}
		route, err := credentialroute.Decode(row.CredentialRoute)
		if err != nil {
			t.Fatal(err)
		}
		out[entry.Name] = contract.GeneratedSupportHandoff{Implementation: row, CompatibilityRequest: requestBytes, CompatibilityResponse: responseBytes, Support: []contract.GeneratorSupportBinding{{Schema: contract.GeneratorSupportBindingSchema, Role: 7, ContractID: contract.ID(route.ContractID), ImplementationID: row.ExecutorID, PublicBindingDigest: row.CredentialRouteID, Binding: slices.Clone(row.CredentialRoute)}}}
	}
	return out
}

package nativeprocess

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"enkv.sh/core/contract"
	stateformat "enkv.sh/core/format"
	observer "enkv.sh/core/testsupport/nativeprocess"
	generatorartifact "enkv.sh/plugins/generators/cloudflare-account-token/artifact"
	"enkv.sh/sdk/artifact"
)

func nativeGoArguments(arguments ...string) []string {
	if nativeRaceEnabled {
		return append([]string{arguments[0], "-race"}, arguments[1:]...)
	}
	return arguments
}

func nativeRequireRaceMode(t *testing.T, path string) {
	t.Helper()
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		t.Fatal("native executable build information unavailable", err)
	}
	race := false
	for _, setting := range info.Settings {
		if setting.Key == "-race" {
			race = setting.Value == "true"
		}
	}
	if race != nativeRaceEnabled {
		t.Fatalf("native executable race mode differs from parent: child=%t parent=%t", race, nativeRaceEnabled)
	}
}

const (
	nativeGeneratedAccountA   = "0123456789abcdef0123456789abcdef"
	nativeGeneratedAccountB   = "fedcba9876543210fedcba9876543210"
	nativeGeneratedPermission = "11111111111111111111111111111111"
	nativeGeneratedBearerA    = "Management_bearer_0123456789_ABCDEFGHIJKLMN"
	nativeGeneratedBearerB    = "Management_bearer_9876543210_NMLKJIHGFEDCBA"
	nativeGeneratedSecret     = "Generated_secret_0123456789_ABCDEFGHIJKLMN"
)

type nativeGeneratedRequest struct{ Method, Account, Target string }
type nativeGeneratedServer struct {
	mu              sync.Mutex
	server          *httptest.Server
	requests        []nativeGeneratedRequest
	resources       map[string]string
	unknownDelete   string
	afterDelete     func()
	afterCreate     func(*http.Request)
	malformedCreate bool
	violations      []string
	serial          uint64
	requestBodies   map[string][]byte
	createTargets   map[string]string
	requestLimit    int
}

func newNativeGeneratedServer(t *testing.T) *nativeGeneratedServer {
	t.Helper()
	s := &nativeGeneratedServer{resources: map[string]string{}}
	s.server = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	t.Cleanup(func() {
		s.server.Close()
		s.mu.Lock()
		defer s.mu.Unlock()
		if len(s.violations) != 0 {
			t.Errorf("local generated fixture violations: %v", s.violations)
		}
	})
	return s
}

func (s *nativeGeneratedServer) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	refuse := func(reason string) {
		s.violations = append(s.violations, reason)
		http.Error(w, "local fixture refused", http.StatusForbidden)
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/client/v4/accounts/"), "/")
	if !strings.HasPrefix(r.URL.Path, "/client/v4/accounts/") || len(parts) < 2 || len(parts) > 3 || parts[1] != "tokens" ||
		r.Host != strings.TrimPrefix(s.server.URL, "https://") || r.URL.RawQuery != "" || r.ProtoMajor != 1 || !r.Close ||
		r.Header.Get("Accept-Encoding") != "identity" || len(s.requests) >= s.maximumRequests() {
		refuse("request-boundary")
		return
	}
	account := parts[0]
	bearer := map[string]string{nativeGeneratedAccountA: nativeGeneratedBearerA, nativeGeneratedAccountB: nativeGeneratedBearerB}[account]
	if bearer == "" || r.Header.Get("Authorization") != "Bearer "+bearer {
		refuse("exact-account-credential")
		return
	}
	bodyLimit := 8192
	if s.requestBodies != nil {
		bodyLimit = 1 << 20
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(bodyLimit)+1))
	closeErr := r.Body.Close()
	defer clear(body)
	if err != nil || closeErr != nil || len(body) > bodyLimit {
		refuse("request-body")
		return
	}
	var result any
	switch {
	case r.Method == http.MethodPost && len(parts) == 2:
		expected := nativeGeneratedRequestBody(account)
		createName := ""
		if s.requestBodies != nil {
			var named struct{ Name string }
			if json.Unmarshal(body, &named) != nil {
				refuse("create-name")
				return
			}
			expected = s.requestBodies[named.Name]
			createName = named.Name
		}
		if !bytes.Equal(body, expected) || r.Header.Get("Content-Type") != "application/json" {
			refuse("create-intent")
			return
		}
		s.serial++
		target := fmt.Sprintf("%032x", s.serial)
		s.resources[target] = account
		if s.requestBodies != nil {
			if s.createTargets == nil {
				s.createTargets = map[string]string{}
			}
			if s.createTargets[createName] != "" {
				refuse("duplicate-create-name")
				return
			}
			s.createTargets[createName] = target
		}
		s.requests = append(s.requests, nativeGeneratedRequest{r.Method, account, target})
		if s.afterCreate != nil {
			after := s.afterCreate
			s.afterCreate = nil
			after(r)
		}
		if s.malformedCreate {
			s.malformedCreate = false
			_, _ = io.WriteString(w, `{"success":true,"result":`)
			return
		}
		result = map[string]any{"id": target, "value": nativeGeneratedSecret + "_" + target, "status": "active", "name": "generated", "policies": []any{map[string]any{"effect": "allow", "permission_groups": []any{map[string]string{"id": nativeGeneratedPermission}}, "resources": map[string]string{"com.cloudflare.api.account." + account: "*"}}}}
		if s.requestBodies != nil {
			var echoed map[string]any
			if json.Unmarshal(expected, &echoed) != nil {
				refuse("expected-create")
				return
			}
			echoed["id"], echoed["value"], echoed["status"] = target, nativeGeneratedSecret+"_"+target, "active"
			result = echoed
		}
	case r.Method == http.MethodDelete && len(parts) == 3:
		target := parts[2]
		if len(body) != 0 || s.resources[target] != account {
			refuse("exact-owned-delete")
			return
		}
		s.requests = append(s.requests, nativeGeneratedRequest{r.Method, account, target})
		if s.unknownDelete == target {
			s.unknownDelete = ""
			w.Header().Set("Content-Type", "application/json")
			_, err = io.WriteString(w, `{"success":true,"result":`)
			if err != nil {
				s.violations = append(s.violations, "unknown-response-write")
			}
			return
		}
		if s.afterDelete != nil {
			s.afterDelete()
			s.afterDelete = nil
		}
		delete(s.resources, target)
		result = map[string]string{"id": target}
	default:
		refuse("method-or-target")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": result}); err != nil {
		s.violations = append(s.violations, "response-write")
	}
}

func (s *nativeGeneratedServer) maximumRequests() int {
	if s.requestLimit == 0 {
		return 64
	}
	return s.requestLimit
}

func nativeGeneratedRequestBody(account string) []byte {
	return []byte(fmt.Sprintf(`{"name":"generated","policies":[{"effect":"allow","permission_groups":[{"id":"%s"}],"resources":{"com.cloudflare.api.account.%s":"*"}}]}`, nativeGeneratedPermission, account))
}
func (s *nativeGeneratedServer) snapshot() ([]nativeGeneratedRequest, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.requests), len(s.resources)
}

type nativeGeneratedExecutables struct{ cli, library, plugin, cliDigest, pluginDigest, home, localBuild string }

func buildNativeGeneratedExecutables(t *testing.T, origin string, ledgerObserver ...bool) nativeGeneratedExecutables {
	t.Helper()
	root, private := nativeRepository(t), nativeGeneratedPrivateDirectory(t)
	plugin := filepath.Join(private, "enkv-generator-cloudflare")
	originFlag := "-X=enkv.sh/plugins/generators/cloudflare-account-token/internal/cloudflare.unqualifiedTestArtifactOrigin=" + origin
	pluginBuild := nativeGoArguments("build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-tags=enkv_cloudflare_testartifact", "-ldflags="+originFlag, "-o", plugin, "./cmd/enkv-generator-cloudflare-test")
	nativeGeneratedGo(t, root, "plugins/cloudflare", pluginBuild...)
	nativeRequireRaceMode(t, plugin)
	t.Logf("unqualified Cloudflare plugin build argv=%q", append([]string{"go"}, pluginBuild...))
	facts := nativeGeneratedBuildFacts(t, root, plugin, plugin+".mod")
	dependency, dependencyID, err := generatorartifact.DependencyManifest(facts)
	if err != nil {
		t.Fatal(err)
	}
	manifest := hex.EncodeToString(dependencyID[:])
	pluginBody, err := os.ReadFile(plugin)
	if err != nil {
		t.Fatal(err)
	}
	pluginDigest := workflowDigest(pluginBody)
	pluginLength := len(pluginBody)
	clear(pluginBody)
	overlay, err := observer.BuildOverlay(root, filepath.Join(private, "overlay"))
	if err != nil {
		t.Fatal(err)
	}
	var mapping struct{ Replace map[string]string }
	var sources []observer.Source
	nativeGeneratedReadJSON(t, overlay.Path, &mapping)
	nativeGeneratedReadJSON(t, overlay.Manifest, &sources)
	add := func(relative string, original, replacement []byte) {
		t.Helper()
		target := nativeGeneratedSourcePath(root, relative)
		if _, exists := mapping.Replace[target]; exists {
			t.Fatal("generated overlay overlaps existing source", relative)
		}
		path := filepath.Join(private, "overlay", strings.ReplaceAll(relative, "/", "_"))
		if os.WriteFile(path, replacement, 0600) != nil {
			t.Fatal("generated overlay source unavailable")
		}
		mapping.Replace[target] = path
		sources = append(sources, observer.Source{Target: target, OriginalSHA256: workflowDigest(original), Replacement: path, ReplacementSHA256: workflowDigest(replacement)})
	}
	// Tagged/race transport fixtures retain their exact measured compiler inputs.
	// The ordinary author workflow and the early extension case use stock builds.
	packagePath := nativeGeneratedSourcePath(root, "compositions/full/plugininstallation/package.go")
	packageSource, err := os.ReadFile(packagePath)
	const policyAnchor = "artifact.BuildOptions(&debug.BuildInfo{Settings: settings})"
	if err != nil || bytes.Count(packageSource, []byte(policyAnchor)) != 1 {
		t.Fatal("controlled build policy anchor differs", err)
	}
	add("compositions/full/plugininstallation/package.go", packageSource, bytes.Replace(packageSource, []byte(policyAnchor), []byte("artifact.CaptureBuildOptions(&debug.BuildInfo{Settings: settings})"), 1))
	slices.SortFunc(sources, func(a, b observer.Source) int { return strings.Compare(a.Target, b.Target) })
	nativeGeneratedWriteJSON(t, overlay.Path, mapping)
	nativeGeneratedWriteJSON(t, overlay.Manifest, sources)
	if len(ledgerObserver) == 1 && ledgerObserver[0] {
		overlay, err = observer.AddGeneratedLedgerOverlay(root, overlay)
		if err != nil {
			t.Fatal("generated custody observer source closure failed", err)
		}
	}
	localBuild := filepath.Join(private, "local-generator")
	metadata := nativeGeneratedArtifactMetadata(t, plugin, facts, dependency, artifact.Digest(dependencyID))
	if metadata.Executable.SHA256.String() != pluginDigest || metadata.Executable.Length != uint64(pluginLength) {
		t.Fatal("controlled plugin changed during metadata capture")
	}
	if _, err := artifact.PublishBuild(t.Context(), localBuild, metadata, plugin, dependency); err != nil {
		t.Fatal("publish controlled local generator build", err)
	}
	distributionOrigin := strings.TrimSuffix(origin, "/client/v4") + "/releases/"
	link := "-X=enkv.sh/compositions/full.installedCLIVerificationKey=3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c -X=enkv.sh/compositions/full.installedPluginKeys=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a -X=enkv.sh/compositions/full.installedPluginOrigin=" + distributionOrigin
	result := nativeGeneratedExecutables{cli: filepath.Join(private, "enkv"), library: filepath.Join(private, "library"), plugin: plugin, pluginDigest: pluginDigest, home: nativeGeneratedPrivateDirectory(t), localBuild: localBuild}
	build := func(path string, files ...string) {
		args := nativeGoArguments("build", "-mod=readonly", "-tags=netgo", "-trimpath", "-buildvcs=false", "-overlay="+overlay.Path, "-ldflags="+link, "-o", path)
		nativeGeneratedGo(t, root, "compositions/full", append(args, files...)...)
		nativeRequireRaceMode(t, path)
	}
	build(result.cli, "./cmd/enkv")
	helperDir := filepath.Join(private, "library-source")
	if os.Mkdir(helperDir, 0700) != nil {
		t.Fatal("library source directory unavailable")
	}
	helper := filepath.Join(helperDir, "main.go")
	if os.WriteFile(helper, []byte(nativeGeneratedLibrarySource), 0600) != nil {
		t.Fatal("library source unavailable")
	}
	observerBody, err := os.ReadFile(mapping.Replace[filepath.Join(root, "tests", "live", "publicprocess", "nativeprocess_observer.go")])
	if err != nil {
		t.Fatal(err)
	}
	helperObserver := filepath.Join(helperDir, "nativeprocess_observer.go")
	if os.WriteFile(helperObserver, observerBody, 0600) != nil {
		t.Fatal("library observer unavailable")
	}
	build(result.library, helper, helperObserver)
	cliBody, err := os.ReadFile(result.cli)
	if err != nil {
		t.Fatal(err)
	}
	result.cliDigest = workflowDigest(cliBody)
	clear(cliBody)
	t.Logf("unqualified Cloudflare fixture origin=%s plugin_sha256=%s length=%d manifest=%s cli_sha256=%s overlay=%s sources=%s tuple=%s/%s", origin, pluginDigest, pluginLength, manifest, result.cliDigest, overlay.Path, overlay.Manifest, runtime.GOOS, runtime.GOARCH)
	return result
}

func nativeGeneratedGo(t *testing.T, root, module string, args ...string) []byte {
	t.Helper()
	output := ""
	for i, arg := range args {
		if arg == "-o" && i+1 < len(args) {
			output = args[i+1]
		}
	}
	if !filepath.IsAbs(output) {
		t.Fatal("native executable fixture requires an absolute -o path")
	}
	body := nativeGeneratedGoCaptured(t, root, module, "", args...)
	if err := os.Chmod(output, 0700); err != nil {
		t.Fatal("private native executable fixture permissions", err)
	}
	return body
}

func nativeGeneratedGoCaptured(t *testing.T, root, module, modfile string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", args...)
	command.Dir = nativeGeneratedSourcePath(root, module)
	overrides := map[string]string{"GOWORK": "off", "GOTOOLCHAIN": "local", "GOFLAGS": "-trimpath -p=1", "GORACE": "log_path=stderr exitcode=66 halt_on_error=0 atexit_sleep_ms=1000"}
	if nativeRaceEnabled {
		overrides["CGO_ENABLED"] = "1"
	}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, replaced := overrides[key]; !replaced {
			command.Env = append(command.Env, entry)
		}
	}
	for key, value := range overrides {
		command.Env = append(command.Env, key+"="+value)
	}
	if modfile == "" {
		modfile = filepath.Join(t.TempDir(), "module.mod")
		for i, arg := range args {
			if arg == "-o" && i+1 < len(args) {
				modfile = args[i+1] + ".mod"
			}
		}
		prepareNativeModule(t, root, command, modfile)
	} else {
		capturedArgs := append([]string(nil), command.Args[:2]...)
		for _, arg := range command.Args[2:] {
			if !strings.HasPrefix(arg, "-modfile=") {
				capturedArgs = append(capturedArgs, arg)
			}
		}
		command.Args = append(capturedArgs[:2], append([]string{"-modfile=" + modfile}, capturedArgs[2:]...)...)
	}
	body, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("generated native fixture build failed: %v\n%s", err, body)
	}
	return body
}

// The plugin uses unchanged source; only the parent profile uses the recorded overlay.
func nativeGeneratedDependencyManifest(t *testing.T, root, executable, modfile string) string {
	t.Helper()
	_, identity, err := generatorartifact.DependencyManifest(nativeGeneratedBuildFacts(t, root, executable, modfile))
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(identity[:])
}

func nativeGeneratedBuildFacts(t *testing.T, root, executable, modfile string) artifact.BuildFacts {
	t.Helper()
	info, err := buildinfo.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	packageArgs := []string{"list", "-mod=readonly", "-deps", "-json", "-tags=enkv_cloudflare_testartifact"}
	for _, setting := range info.Settings {
		if setting.Key == "-race" && setting.Value == "true" {
			packageArgs = append(packageArgs, "-race")
		}
	}
	packageArgs = append(packageArgs, "./cmd/enkv-generator-cloudflare-test")
	body := nativeGeneratedGoCaptured(t, root, "plugins/cloudflare", modfile, packageArgs...)
	decoder := json.NewDecoder(bytes.NewReader(body))
	var packages []artifact.SourcePackage
	for {
		var p artifact.SourcePackage
		if err := decoder.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		packages = append(packages, p)
	}
	body = nativeGeneratedGoCaptured(t, root, "plugins/cloudflare", modfile, "list", "-mod=readonly", "-m", "-json", "all")
	decoder = json.NewDecoder(bytes.NewReader(body))
	var modules []artifact.SourceModule
	for {
		var module artifact.SourceModule
		if err := decoder.Decode(&module); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		modules = append(modules, module)
	}
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
				t.Fatal("generated fixture has a nested replacement")
			}
			row.Replacement = &artifact.Replacement{Path: replacement.Path, Version: replacement.Version, Sum: replacement.Sum}
			if replacement.Version == "" && replacement.Sum == "" {
				row.Replacement.SourceDigest = digests[module.Path]
			}
		}
		resolved = append(resolved, row)
	}
	slices.SortFunc(resolved, func(a, b artifact.Dependency) int { return strings.Compare(a.Path, b.Path) })
	descriptor, _, err := artifact.ReadDescriptor(t.Context(), nativeGeneratedSourcePath(root, "plugins/cloudflare/cmd/enkv-generator-cloudflare-test/plugin.json"))
	if err != nil {
		t.Fatal(err)
	}
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

// full_only: false
func TestNativeGeneratedDependencyManifestBindsCurrentBuildFacts(t *testing.T) {
	root := nativeRepository(t)
	plugin := filepath.Join(t.TempDir(), "enkv-generator-cloudflare")
	nativeGeneratedGo(t, root, "plugins/cloudflare", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-tags=enkv_cloudflare_testartifact", "-ldflags=-X=enkv.sh/plugins/generators/cloudflare-account-token/internal/cloudflare.unqualifiedTestArtifactOrigin=https://127.0.0.1:1/client/v4", "-o", plugin, "./cmd/enkv-generator-cloudflare-test")
	info, err := buildinfo.ReadFile(plugin)
	if err != nil {
		t.Fatal(err)
	}
	const main = "enkv.sh/plugins/generators/cloudflare-account-token"
	if info.Main.Path != main || info.Path != main+"/cmd/enkv-generator-cloudflare-test" || len(info.Deps) != 3 {
		t.Fatal("controlled generator executable closure differs", info)
	}
	var packages []artifact.SourcePackage
	listed := nativeGeneratedGoCaptured(t, root, "plugins/cloudflare", plugin+".mod", "list", "-mod=readonly", "-deps", "-json", "-tags=enkv_cloudflare_testartifact", "./cmd/enkv-generator-cloudflare-test")
	decoder := json.NewDecoder(bytes.NewReader(listed))
	for {
		var row artifact.SourcePackage
		if err := decoder.Decode(&row); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		packages = append(packages, row)
	}
	var modules []artifact.SourceModule
	listed = nativeGeneratedGoCaptured(t, root, "plugins/cloudflare", plugin+".mod", "list", "-mod=readonly", "-m", "-json", "all")
	decoder = json.NewDecoder(bytes.NewReader(listed))
	for {
		var row artifact.SourceModule
		if err := decoder.Decode(&row); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		modules = append(modules, row)
	}
	var resolvedOwners []string
	for _, row := range modules {
		resolvedOwners = append(resolvedOwners, row.Path)
	}
	slices.Sort(resolvedOwners)
	if !reflect.DeepEqual(resolvedOwners, []string{main, "enkv.sh/sdk/artifact", "enkv.sh/sdk/generator", "enkv.sh/sdk/protocols/generator"}) {
		t.Fatal("controlled generator resolved owners differ", resolvedOwners)
	}
	sources, err := artifact.CaptureSourcesForModules(t.Context(), "generator", packages, modules)
	if err != nil {
		t.Fatal(err)
	}
	var sourceOwners []string
	digests := map[string]artifact.Digest{}
	for _, source := range sources {
		sourceOwners = append(sourceOwners, source.Module)
		digests[source.Module] = source.Digest
	}
	if !reflect.DeepEqual(sourceOwners, resolvedOwners) {
		t.Fatal("selected and metadata-only source owners differ", sourceOwners)
	}
	options, err := artifact.CaptureBuildOptions(info)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := artifact.CompiledDependencies(info, sources)
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled) != 4 || !slices.ContainsFunc(compiled, func(row artifact.Dependency) bool { return row.Path == "enkv.sh/sdk/artifact" }) {
		t.Fatal("compiled descriptor owner is absent from exact compiled facts", compiled)
	}
	resolved := make([]artifact.Dependency, 0, len(modules))
	for _, module := range modules {
		row := artifact.Dependency{Path: module.Path, Version: module.Version, Sum: module.Sum}
		if replacement := module.Replace; replacement != nil {
			row.Replacement = &artifact.Replacement{Path: replacement.Path, Version: replacement.Version, Sum: replacement.Sum, SourceDigest: digests[module.Path]}
		}
		resolved = append(resolved, row)
	}
	slices.SortFunc(resolved, func(a, b artifact.Dependency) int { return strings.Compare(a.Path, b.Path) })
	// The wire literal is declared by the public generator protocol, independent
	// of the descriptor reader used by the fixture build helper.
	contracts := []artifact.Contract{{Kind: "wire", Identity: "cc827c32a204204ec680e29c0b79df771ea2ad5d2c1df10170d8b450e7628b0f", Version: 5}}
	facts := artifact.BuildFacts{Role: "generator", MainModule: info.Main.Path, Command: info.Path, Platform: runtime.GOOS + "/" + runtime.GOARCH, Toolchain: info.GoVersion, BuildOptions: options, Contracts: contracts, Sources: sources, Resolved: resolved, Compiled: compiled}
	if err := artifact.VerifyBuildInfo(info, facts); err != nil {
		t.Fatal("current facts do not bind the actual compiled executable", err)
	}
	body, err := artifact.EncodeDependency(facts)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := artifact.DependencyID("generator", body)
	if err != nil {
		t.Fatal(err)
	}
	if actual := nativeGeneratedDependencyManifest(t, root, plugin, plugin+".mod"); actual != identity.String() {
		t.Errorf("native generated dependency identity does not bind current schema3 facts: got=%s want=%s", actual, identity)
	}
	metadata := nativeGeneratedArtifactMetadata(t, plugin, facts, body, identity)
	family, err := metadata.GeneratorFacts()
	if err != nil || family.Schema != artifact.FamilySchema || family.Descriptor.Generator == nil || family.Descriptor.Generator.ConfigContractID.String() != "7ede2a15bbf86395c097322b651f2752f9adf1bdfa346f09683e20e670ff10c1" || family.Descriptor.Wire != contracts[0] || family.DependencyManifestID != identity || family.DescriptorID.IsZero() {
		t.Fatal("current native metadata lost its exact declaration and measured build", err)
	}
	changed := facts
	changed.Compiled = slices.Clone(facts.Compiled[:len(facts.Compiled)-1])
	if artifact.VerifyBuildInfo(info, changed) == nil {
		t.Fatal("current facts accepted an omitted actual compiled owner")
	}
}

func nativeGeneratedReadJSON(t *testing.T, path string, value any) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(body, value) != nil {
		t.Fatal("generated fixture JSON unavailable")
	}
}
func nativeGeneratedWriteJSON(t *testing.T, path string, value any) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil || os.WriteFile(path, body, 0600) != nil {
		t.Fatal("generated fixture JSON write failed")
	}
}

type nativeGeneratedFact struct {
	Facts struct {
		DutyID            string `json:"duty_id"`
		ResourceID        string `json:"resource_incarnation_id"`
		HazardID          string `json:"hazard_id"`
		Exposure          string `json:"exposure"`
		AttemptID         string `json:"attempt_id"`
		OriginalAttemptID string `json:"original_attempt_id"`
		ExecutorID        string `json:"executor_id"`
		State             string `json:"state"`
		Action            string `json:"action"`
		Status            string `json:"status"`
		Kind              string `json:"kind"`
		Completion        string `json:"completion_class"`
		Stage             uint64 `json:"stage"`
		Reason            uint64 `json:"reason"`
		Step              uint64 `json:"step"`
	}
	Target struct {
		ResourceDigest      string `json:"resource_digest"`
		ResourceID          string `json:"resource_incarnation_id"`
		OriginalOperationID string `json:"original_operation_id"`
		OriginalAttemptID   string `json:"original_attempt_id"`
		Account             string `json:"-"`
		TokenID             string `json:"-"`
	}
}
type nativeGeneratedOutput struct {
	Schema                   string
	State                    string `json:"state_result"`
	Operation                string `json:"operation_id"`
	Receipt                  string `json:"receipt_hex"`
	EffectSummary            string `json:"effect_summary"`
	Canonical                string `json:"canonical_outcome"`
	Effects, Duties, Hazards []nativeGeneratedFact
	Current                  []struct {
		ResourceDigest string `json:"resource_digest"`
		Account        string `json:"-"`
		TokenID        string `json:"-"`
		Generation     string `json:"generation_id"`
		ResourceID     string `json:"resource_incarnation_id"`
		Epoch          uint64
	} `json:"current_generations"`
	Next []struct {
		Command string
		Duty    string `json:"duty_id"`
		Attempt string `json:"attempt_id"`
	} `json:"next_actions"`
}

func nativeGeneratedOutcome(t *testing.T, child workflowChild, state string, code int) nativeGeneratedOutput {
	t.Helper()
	var out nativeGeneratedOutput
	if json.Unmarshal(child.out, &out) != nil || out.Schema != "ProductResult/v1" || out.State != state || child.code != code {
		var totalStarts, maxSequence, sent, unsent uint64
		for _, event := range child.capture.Events {
			if event.Kind != "http-start" {
				continue
			}
			totalStarts++
			maxSequence = max(maxSequence, event.Sequence)
			if event.Sent {
				sent++
			} else {
				unsent++
			}
		}
		t.Logf("generated request bounds: starts=%d max_sequence=%d sent=%d unsent=%d", totalStarts, maxSequence, sent, unsent)
		var facts struct {
			Identity    json.RawMessage `json:"request_identity"`
			Diagnostics []struct {
				Reason string `json:"reason"`
			} `json:"diagnostics"`
			Commit bool `json:"commit_may_have_occurred"`
		}
		var identity struct{ Schema, Stage, Code string }
		decoded := json.Unmarshal(child.out, &facts) == nil
		preAdmission := decoded && json.Unmarshal(facts.Identity, &identity) == nil && identity.Schema == "PreAdmissionRequestIdentity/v1"
		stage := "other"
		switch identity.Stage {
		case "dispatch", "input", "target", "deadline", "source", "prepared-source", "public-configuration", "public-basis", "prepared-keys", "candidate-bounds", "prepared-recipient", "candidate", "candidate-target", "delivery", "local-cleanup", "input-close", "cancelled", "unavailable", "refused", "profile-blocked", "positive-defect", "context", "output", "capture", "parse", "declaration", "construction", "resolution", "observation", "installation", "initialize", "apply", "compare", "rekey", "retire":
			stage = identity.Stage
		}
		safeReason := func(reason string) string {
			switch reason {
			case "required-public-fact-unavailable", "invalid-input", "missing-required-field", "duplicate-key", "duplicate-member", "unresolved-reference", "invalid-utf8", "limit-exceeded", "invalid-field-combination", "unsupported-schema", "unsupported-profile", "trust-basis-invalid", "domain-basis-invalid", "store-basis-invalid", "expired", "head-invalid", "proof-invalid", "selected-object-invalid", "selected-relation-invalid", "evidence-unavailable", "selected-object-unavailable", "read-contention", "cancelled", "diagnostics-incomplete", "unsupported-apply-change":
				return reason
			}
			return "other"
		}
		reasons := make([]string, 0, min(len(facts.Diagnostics), 4))
		for _, diagnostic := range facts.Diagnostics[:min(len(facts.Diagnostics), 4)] {
			reasons = append(reasons, safeReason(diagnostic.Reason))
		}
		t.Logf("generated failure facts: decoded=%t pre_admission=%t stage=%s code=%s diagnostics=%d reasons=%v commit_possible=%t diagnostic_bytes=%d", decoded, preAdmission, stage, safeReason(identity.Code), len(facts.Diagnostics), reasons, facts.Commit, len(child.diagnostic))

		safeState := workflowSafeState(out.State)
		switch out.State {
		case "possible-live-residue-accepted", "retirement-pending", "effect-pending", "effect-partial", "effect-unknown", "effect-terminal-failure":
			safeState = out.State
		}
		for i, effect := range out.Effects[:min(len(out.Effects), 4)] {
			f := effect.Facts
			t.Logf("generated effect[%d]: stage=%d reason=%d delete=%t succeeded=%t unknown=%t acknowledged=%t", i, f.Stage, f.Reason, f.Action == "delete", f.State == "succeeded", f.State == "unknown", f.Completion == "deletion-acknowledged")
		}
		for i, duty := range out.Duties[:min(len(out.Duties), 4)] {
			f := duty.Facts
			t.Logf("generated duty[%d]: step=%d retirement=%t not_started=%t prepared=%t transmitted=%t succeeded=%t unknown=%t acknowledged=%t", i, f.Step, f.Kind == "retirement", f.Status == "not-started", f.Status == "prepared", f.Status == "transmitted", f.Status == "succeeded", f.Status == "unknown", f.Completion == "deletion-acknowledged")
		}
		t.Fatalf("generated result expected=%s/%d actual=%s/%d schema=%t canonical_selected=%t effect_complete=%t effect_pending=%t effect_unknown=%t receipt_present=%t effects=%d duties=%d hazards=%d %s", state, code, safeState, child.code, out.Schema == "ProductResult/v1", out.Canonical == "selected", out.EffectSummary == "effect-complete", out.EffectSummary == "effect-pending", out.EffectSummary == "effect-unknown", out.Receipt != "", len(out.Effects), len(out.Duties), len(out.Hazards), child.summary)
	}
	// Provider-specific bytes stay in this private fixture projection. The
	// public command returns only the generic resource digest used for the join.
	project := func(digest string) (string, string) {
		facts, ok := child.generatedResources[digest]
		if !ok {
			if digest != "" {
				t.Fatal("selected generated resource has no retained private fixture facts")
			}
			return "", ""
		}
		if len(facts.Target) != 32 || len(facts.ResourceData) != 32 {
			t.Fatal("Cloudflare fixture resource data differs from its declared format")
		}
		return hex.EncodeToString(facts.Target), hex.EncodeToString(facts.ResourceData)
	}
	for i := range out.Current {
		out.Current[i].Account, out.Current[i].TokenID = project(out.Current[i].ResourceDigest)
	}
	for _, rows := range [][]nativeGeneratedFact{out.Effects, out.Duties, out.Hazards} {
		for i := range rows {
			rows[i].Target.Account, rows[i].Target.TokenID = project(rows[i].Target.ResourceDigest)
		}
	}
	for _, secret := range []string{nativeGeneratedBearerA, nativeGeneratedBearerB, nativeGeneratedSecret} {
		if bytes.Contains(child.out, []byte(secret)) || bytes.Contains(child.diagnostic, []byte(secret)) {
			t.Fatal("generated secret reached ordinary process output")
		}
	}
	return out
}

func nativeGeneratedInitialize(t *testing.T, s *workflowServer, cli string, recovery bool) string {
	t.Helper()
	s.childLimit = 32
	s.objectLimit = 512
	path := filepath.Join(t.TempDir(), "configuration.json")
	if os.WriteFile(path, workflowSetup(t, s, recovery), 0600) != nil {
		t.Fatal("generated setup unavailable")
	}
	workflowResult(t, workflowRun(t, s, cli, "init", observer.Policy{MaxStoreWrites: 16, MaxStoreWriteBytes: 8 << 20}, nil, "init", "--source", path, "--source-format", "json", "--json"), "success")
	return path
}

func nativeGeneratedDeclaration(t *testing.T, path, account, policy string, epoch uint64, present bool) workflowPair {
	t.Helper()
	var source map[string]any
	nativeGeneratedReadJSON(t, path, &source)
	entries := map[string]any{}
	if present {
		entries["generated"] = map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": map[string]any{"kind": "generated", "plugin": "cloudflare-account-token", "epoch": epoch, "retirement": policy, "settings": map[string]any{"account": account, "name": "generated", "policies": []any{map[string]any{"effect": "allow", "permission_groups": []string{nativeGeneratedPermission}, "resources": []any{map[string]string{"kind": "account", "id": account}}}}}}}
	}
	source["entries"] = entries
	nativeGeneratedWriteJSON(t, path, source)
	return workflowReadPair(t, path)
}

func nativeGeneratedRun(t *testing.T, s *workflowServer, binaries nativeGeneratedExecutables, path, bearer, action string, library bool, selectors ...string) workflowChild {
	t.Helper()
	t.Setenv("CLOUDFLARE_API_TOKEN", bearer)
	policy := observer.Policy{MaxStoreWrites: 256, MaxStoreWriteBytes: 32 << 20}
	phase := "apply"
	var args []string
	binary := binaries.cli
	if library {
		binary = binaries.library
		args = append([]string{action, path}, selectors...)
	} else {
		args = strings.Fields(action)
		args = append(args, "--source", path, "--source-format", "json", "--json")
		args = append(args, selectors...)
	}
	if action == "generated list" {
		policy.NoKMS, policy.StoreReadOnly, phase = true, true, "reader"
		policy.MaxStoreWrites, policy.MaxStoreWriteBytes = 0, 0
	}
	pair := workflowReadPair(t, path)
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{{path, 0400}, {filepath.Join(filepath.Dir(path), pair.reference), 0400}, {filepath.Join(filepath.Dir(path), ".enkv"), 0500}, {filepath.Dir(path), 0500}} {
		info, err := os.Stat(item.path)
		if err != nil || os.Chmod(item.path, item.mode) != nil {
			t.Fatal("generated read-only source setup failed")
		}
		defer func(path string, mode os.FileMode) {
			if os.Chmod(path, mode) != nil {
				t.Error("generated source mode restore failed")
			}
		}(item.path, info.Mode().Perm())
	}
	resources := nativeGeneratedSelectedResources(t, s)
	child := workflowRunEnvironment(t, s, binary, phase, policy, nil, nativeGeneratedEnvironment(t, binaries, path), args...)
	maps.Copy(resources, nativeGeneratedSelectedResources(t, s))
	child.generatedResources = resources
	workflowUnchanged(t, path, pair)
	if action == "generated list" {
		workflowGETOnly(t, child)
	}
	return child
}

func nativeGeneratedSelectedResources(t *testing.T, s *workflowServer) map[string]contract.GeneratorSafeFacts {
	t.Helper()
	head, _ := workflowHead(t, s)
	root := workflowRoot(t, s, head)
	resources := make(map[string]contract.GeneratorSafeFacts)
	for _, ref := range root.RequiredSupport {
		key, err := stateformat.Key(s.prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		page, err := stateformat.InspectRequiredSupportPage(s.object(t, key).body)
		if err != nil {
			t.Fatal(err)
		}
		for _, record := range page.Records {
			var facts contract.GeneratorSafeFacts
			switch record.Kind {
			case contract.GeneratedResultSupportKind:
				result, err := contract.InspectGeneratedResultRecord(record.Body)
				if err != nil {
					t.Fatal(err)
				}
				facts = result.SafeFacts.GeneratorSafeFacts
			case contract.GeneratedCreateEvidenceSupportKind:
				evidence, err := contract.InspectGeneratedCreateEvidence(record.Body)
				if err != nil {
					t.Fatal(err)
				}
				facts, err = contract.DecodeGeneratorSafeFacts(evidence.SafeFacts)
				if err != nil {
					t.Fatal(err)
				}
			default:
				continue
			}
			if facts.LifecycleMode != contract.GeneratorLifecycleManaged || len(facts.Target) == 0 || len(facts.ResourceData) == 0 {
				continue
			}
			digest, err := contract.GeneratorResourceDigest(facts)
			if err != nil {
				t.Fatal(err)
			}
			resources[hex.EncodeToString(digest[:])] = facts
		}
	}
	return resources
}

func nativeGeneratedProviderID(t *testing.T, encoded string) string {
	t.Helper()
	body, err := hex.DecodeString(encoded)
	if err != nil || len(body) != 32 {
		t.Fatal("generated provider identity unavailable")
	}
	return string(body)
}

// full_only: false
func TestPublicNativeGeneratedLostCreateMarker(t *testing.T) {
	cloudflare := newNativeGeneratedServer(t)
	binaries := buildNativeGeneratedExecutables(t, cloudflare.server.URL+"/client/v4")
	var attempts, agents []string
	for _, loseReply := range []bool{false, true} {
		store := newWorkflowServer(t, "aws", false)
		source := nativeGeneratedInitialize(t, store, binaries.cli, false)
		nativeGeneratedDeclaration(t, source, nativeGeneratedAccountA, "manual", 0, true)
		cloudflare.mu.Lock()
		cloudflare.afterCreate = func(r *http.Request) {
			agents = append(agents, r.UserAgent())
			if loseReply {
				panic(http.ErrAbortHandler) // The fake provider already committed the token.
			}
		}
		cloudflare.mu.Unlock()
		result := nativeGeneratedRun(t, store, binaries, source, nativeGeneratedBearerA, "apply", false)
		if !loseReply {
			created := nativeGeneratedOutcome(t, result, "success", 0)
			if len(created.Effects) != 1 {
				t.Fatal("expected one acknowledged CREATE")
			}
			attempts = append(attempts, created.Effects[0].Facts.AttemptID)
			continue
		}
		unknown := nativeGeneratedOutcome(t, result, "effect-unknown", 3)
		reader := nativeGeneratedRun(t, store, binaries, source, "", "generated list", false)
		list := nativeGeneratedOutcome(t, reader, "success", 0)
		if len(unknown.Hazards) != 1 || len(list.Hazards) != 1 || len(list.Current) != 0 ||
			list.Hazards[0].Facts.OriginalAttemptID != unknown.Hazards[0].Facts.OriginalAttemptID ||
			list.Hazards[0].Facts.Exposure != "possible-live" || list.Hazards[0].Target.ResourceDigest != "" {
			t.Fatal("the fresh reader lost the unresolved CREATE or selected an unknown value")
		}
		head, _ := workflowHead(t, store)
		if !workflowRoot(t, store, head).Generated.ActiveOwner.IsZero() {
			t.Fatal("the lost CREATE kept the domain occupied")
		}
		attempts = append(attempts, list.Hazards[0].Facts.OriginalAttemptID)
	}
	requests, live := cloudflare.snapshot()
	cloudflare.mu.Lock()
	defer cloudflare.mu.Unlock()
	if len(requests) != 2 || live != 2 || len(agents) != 2 || attempts[0] == attempts[1] {
		t.Fatal("expected two distinct attempts and exactly two same-name CREATEs")
	}
	for i, attempt := range attempts {
		raw, err := hex.DecodeString(attempt)
		if err != nil || len(raw) != 32 {
			t.Fatal("public CREATE Attempt ID has invalid encoding")
		}
		marker := sha256.Sum256(append([]byte("ENKV/Cloudflare/audit-marker/v1\x00"), raw...))
		if requests[i].Method != http.MethodPost || agents[i] != fmt.Sprintf("enkv-generator-cloudflare/0.1.0 audit/%x", marker) {
			t.Fatalf("request %d did not carry the marker reconstructed from its public Attempt ID", i+1)
		}
	}
}

// full_only: false
func TestPublicNativeGeneratedManualLifecycleBothRuntimeAccounts(t *testing.T) {
	cloudflare := newNativeGeneratedServer(t)
	binaries := buildNativeGeneratedExecutables(t, cloudflare.server.URL+"/client/v4")
	for _, family := range []string{"aws", "gcp"} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/recovery-%t", family, recovery), func(t *testing.T) {
				binaries := binaries
				binaries.home = nativeGeneratedPrivateDirectory(t)
				for i, account := range []string{nativeGeneratedAccountA, nativeGeneratedAccountB} {
					bearer := []string{nativeGeneratedBearerA, nativeGeneratedBearerB}[i]
					library := i == 1
					s := newWorkflowServer(t, family, recovery)
					path := nativeGeneratedInitialize(t, s, binaries.cli, recovery)
					nativeGeneratedDeclaration(t, path, account, "manual", 0, true)
					t.Setenv("CLOUDFLARE_API_TOKEN", "")
					pair := workflowReadPair(t, path)
					beforePlan, _ := cloudflare.snapshot()
					planned := workflowRunEnvironment(t, s, binaries.cli, "reader", observer.Policy{NoKMS: true, StoreReadOnly: true}, nil, nativeGeneratedEnvironment(t, binaries, path), "plan", "--trusted", path, "--trusted-format", "json", "--json")
					nativeGeneratedOutcome(t, planned, "success", 1)
					workflowGETOnly(t, planned)
					workflowUnchanged(t, path, pair)
					afterPlan, _ := cloudflare.snapshot()
					if !slices.Equal(beforePlan, afterPlan) {
						t.Fatal("public generated planning entered Cloudflare")
					}
					nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, bearer, "apply", false), "success", 0)
					first := nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, "", "generated list", library), "success", 0)
					if len(first.Current) != 1 || first.Current[0].Epoch != 0 || nativeGeneratedProviderID(t, first.Current[0].Account) != account {
						t.Fatal("initial generated current differs")
					}
					before, _ := cloudflare.snapshot()
					nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, "", "apply", library), "no-op", 0)
					after, _ := cloudflare.snapshot()
					if !slices.Equal(before, after) {
						t.Fatal("unchanged apply entered Cloudflare")
					}
					nativeGeneratedDeclaration(t, path, account, "manual", 1, true)
					nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, bearer, "apply", library), "retirement-pending", 3)
					rotated := nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, "", "generated list", library), "success", 0)
					if len(rotated.Current) != 1 || rotated.Current[0].Epoch != 1 || rotated.Current[0].Generation == first.Current[0].Generation || len(rotated.Duties) != 1 || rotated.Duties[0].Target.TokenID != first.Current[0].TokenID {
						t.Fatal("manual rotation lost old exact target or current generation")
					}
					other := nativeGeneratedAccountB
					if account == other {
						other = nativeGeneratedAccountA
					}
					nativeGeneratedDeclaration(t, path, other, "manual", 2, true)
					nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, bearer, "generated retire", library, "--duty", rotated.Duties[0].Facts.DutyID), "success", 0)
					requests, _ := cloudflare.snapshot()
					last := requests[len(requests)-1]
					if last != (nativeGeneratedRequest{http.MethodDelete, account, nativeGeneratedProviderID(t, first.Current[0].TokenID)}) {
						t.Fatal("local proposal changed retained retirement target")
					}
					observed := nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, "", "generated list", library), "success", 0)
					if len(observed.Duties) != 0 || len(observed.Current) != 1 || observed.Current[0].Generation != rotated.Current[0].Generation {
						t.Fatal("retirement changed current generation")
					}
					nativeGeneratedDeclaration(t, path, account, "manual", 1, false)
					nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, "", "apply", library, "--retire-generator", "generated=cloudflare-account-token"), "retirement-pending", 3)
					removed := nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, "", "generated list", library), "success", 0)
					if len(removed.Current) != 0 || len(removed.Duties) != 1 {
						t.Fatal("removal did not retain exact manual duty")
					}
					nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, bearer, "generated retire", library, "--duty", removed.Duties[0].Facts.DutyID), "success", 0)
					_, resources := cloudflare.snapshot()
					if resources != 0 {
						t.Fatal("local generated lifecycle left fixture resources")
					}
				}
			})
		}
	}
}

// full_only: false
func TestPublicNativeGeneratedRetainedBuildSurvivesCurrentSelectionAndRestart(t *testing.T) {
	cloudflare := newNativeGeneratedServer(t)
	origin := cloudflare.server.URL + "/client/v4"
	binaries := buildNativeGeneratedExecutables(t, origin, true)
	s := newWorkflowServer(t, "aws", false)
	source := nativeGeneratedInitialize(t, s, binaries.cli, false)
	nativeGeneratedDeclaration(t, source, nativeGeneratedAccountA, "manual", 0, true)
	ledgerPath := filepath.Join(nativeGeneratedPrivateDirectory(t), "generator-cleanup.json")
	runID := strings.Repeat("b", 32)
	nativeGeneratedWriteJSON(t, ledgerPath, map[string]any{"schema_version": 1, "run_id": runID, "provider": "cloudflare", "account": nativeGeneratedAccountA, "pending_creates": []string{}, "resources": []any{}})
	policy := observer.Policy{GeneratorLedgerPath: ledgerPath, GeneratorRunID: runID, GeneratorAccount: nativeGeneratedAccountA, GeneratorCreates: 3, GeneratorRetires: 1}
	// Every call starts and positively joins a new process. Only the private
	// installation/settings and authenticated provider objects survive it.
	run := func(action, bearer string, selectors ...string) workflowChild {
		t.Helper()
		cli, err := os.ReadFile(binaries.cli)
		if err != nil || workflowDigest(cli) != binaries.cliDigest {
			t.Fatal("retained continuation changed the frozen CLI")
		}
		clear(cli)
		t.Setenv("CLOUDFLARE_API_TOKEN", bearer)
		p, phase := policy, "apply"
		if action == "generated list" {
			p.NoKMS, phase = true, "reader"
		}
		args := append(strings.Fields(action), "--source", source, "--source-format", "json", "--json")
		pair := workflowReadPair(t, source)
		resources := nativeGeneratedSelectedResources(t, s)
		child := workflowRunEnvironment(t, s, binaries.cli, phase, p, nil, nativeGeneratedEnvironment(t, binaries, source), append(args, selectors...)...)
		maps.Copy(resources, nativeGeneratedSelectedResources(t, s))
		child.generatedResources = resources
		workflowUnchanged(t, source, pair)
		if p.NoKMS {
			workflowGETOnly(t, child)
		}
		return child
	}
	a, err := artifact.VerifyBuild(t.Context(), binaries.localBuild)
	if err != nil {
		t.Fatal("original A build unavailable", err)
	}
	aFamily, err := a.GeneratorFacts()
	if err != nil {
		t.Fatal(err)
	}
	var markerA artifact.BuildMarker
	nativeGeneratedReadJSON(t, filepath.Join(binaries.localBuild, "build.json"), &markerA)
	nativeGeneratedOutcome(t, run("apply", nativeGeneratedBearerA), "success", 0)
	first := nativeGeneratedOutcome(t, run("generated list", ""), "success", 0)
	if len(first.Current) != 1 || first.Current[0].Epoch != 0 || len(first.Duties) != 0 {
		t.Fatal("A did not create the initial selected generation")
	}

	// Accept A's retirement work before changing the current local build.
	nativeGeneratedDeclaration(t, source, nativeGeneratedAccountA, "manual", 1, true)
	rotationA := nativeGeneratedOutcome(t, run("apply", nativeGeneratedBearerA), "retirement-pending", 3)
	if !slices.ContainsFunc(rotationA.Effects, func(effect nativeGeneratedFact) bool {
		return effect.Facts.Action == "create" && effect.Facts.ExecutorID == aFamily.ExecutorID.String()
	}) {
		t.Fatal("rotation before replacement did not use A")
	}
	rotated := nativeGeneratedOutcome(t, run("generated list", ""), "success", 0)
	currentA := len(rotated.Current) == 1 && rotated.Current[0].Epoch == 1 &&
		rotated.Current[0].Generation != first.Current[0].Generation && rotated.Current[0].ResourceID != first.Current[0].ResourceID &&
		rotated.Current[0].TokenID != first.Current[0].TokenID
	dutyA := len(rotated.Duties) == 1 && rotated.Duties[0].Facts.ExecutorID == aFamily.ExecutorID.String() &&
		rotated.Duties[0].Target.TokenID == first.Current[0].TokenID && rotated.Duties[0].Target.Account == first.Current[0].Account
	if !currentA || !dutyA {
		t.Fatalf("accepted A rotation differs: current_count=%d current_matches=%t duty_count=%d duty_matches=%t", len(rotated.Current), currentA, len(rotated.Duties), dutyA)
	}

	// Build a second real executable, rather than relabeling A's metadata. The
	// linker build ID changes bytes while preserving the supported semantics.
	root := nativeRepository(t)
	pluginB := filepath.Join(nativeGeneratedPrivateDirectory(t), "generator-B")
	originFlag := "-X=enkv.sh/plugins/generators/cloudflare-account-token/internal/cloudflare.unqualifiedTestArtifactOrigin=" + origin
	nativeGeneratedGo(t, root, "plugins/cloudflare", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-tags=enkv_cloudflare_testartifact", "-ldflags="+originFlag+" -buildid=enkv-retained-selection-B", "-o", pluginB, "./cmd/enkv-generator-cloudflare-test")
	factsB := nativeGeneratedBuildFacts(t, root, pluginB, pluginB+".mod")
	dependencyB, dependencyIDB, err := generatorartifact.DependencyManifest(factsB)
	if err != nil {
		t.Fatal(err)
	}
	b := nativeGeneratedArtifactMetadata(t, pluginB, factsB, dependencyB, artifact.Digest(dependencyIDB))
	bFamily, err := b.GeneratorFacts()
	if err != nil || b.Executable.SHA256 == a.Executable.SHA256 || bFamily.ExecutorID == aFamily.ExecutorID {
		t.Fatal("A and B must have distinct actual executable and Executor identities", err)
	}
	markerB, err := artifact.PublishBuild(t.Context(), binaries.localBuild, b, pluginB, dependencyB)
	if err != nil || markerB.Artifact == markerA.Artifact {
		t.Fatal("select distinct local B build", err)
	}
	t.Logf("retained restart fixture cli_sha256=%s A_artifact=%s A_sha256=%s A_executor=%s B_artifact=%s B_sha256=%s B_executor=%s", binaries.cliDigest, markerA.Artifact, a.Executable.SHA256, aFamily.ExecutorID, markerB.Artifact, b.Executable.SHA256, bFamily.ExecutorID)
	beforeCapture, _ := cloudflare.snapshot()
	nativeGeneratedOutcome(t, run("apply", ""), "no-op", 0)
	afterCapture, _ := cloudflare.snapshot()
	captured := nativeGeneratedOutcome(t, run("generated list", ""), "success", 0)
	if !slices.Equal(beforeCapture, afterCapture) || !reflect.DeepEqual(captured.Current, rotated.Current) || !reflect.DeepEqual(captured.Duties, rotated.Duties) {
		t.Fatal("capturing B changed accepted A work or sent a provider request")
	}
	duty := rotated.Duties[0].Facts.DutyID
	config := filepath.Join(binaries.home, ".config")
	if runtime.GOOS == "darwin" {
		config = filepath.Join(binaries.home, "Library", "Application Support")
	}
	store := filepath.Join(config, "enkv", "installation")
	capturedB, err := os.ReadFile(filepath.Join(store, "builds", markerB.Artifact.String(), "plugin"))
	if err != nil || workflowDigest(capturedB) != b.Executable.SHA256.String() {
		clear(capturedB)
		t.Fatal("unchanged apply did not capture exact B bytes", err)
	}
	clear(capturedB)
	locatorPath := filepath.Join(store, "retained", "generator", aFamily.ExecutorID.String()+".json")
	locator, err := os.ReadFile(locatorPath)
	if err != nil {
		t.Fatal("captured A retained locator unavailable", err)
	}
	installedA := filepath.Join(store, "builds", markerA.Artifact.String(), "plugin")
	aBytes, err := os.ReadFile(installedA)
	if err != nil || workflowDigest(aBytes) != a.Executable.SHA256.String() {
		t.Fatal("captured A executable is not original A", err)
	}
	defer clear(aBytes)
	pluginMode, err := os.Stat(installedA)
	if err != nil {
		t.Fatal(err)
	}
	directoryMode, err := os.Stat(filepath.Dir(installedA))
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"missing-original", "changed-original"} {
		// These changes affect only this fixture's private captured member.
		// Restoration is explicit test setup, never a product recovery action.
		func() {
			if os.Chmod(filepath.Dir(installedA), 0700) != nil || os.Remove(installedA) != nil {
				t.Fatal("original support fault setup failed")
			}
			defer func() {
				if err := os.Remove(installedA); err != nil && !os.IsNotExist(err) {
					t.Error("remove changed fixture member", err)
				}
				if os.WriteFile(installedA, aBytes, pluginMode.Mode().Perm()) != nil || os.Chmod(filepath.Dir(installedA), directoryMode.Mode().Perm()) != nil {
					t.Error("restore exact original fixture bytes")
				}
			}()
			if fault == "changed-original" {
				changed := bytes.Clone(aBytes)
				changed[len(changed)-1] ^= 1
				err := os.WriteFile(installedA, changed, pluginMode.Mode().Perm())
				clear(changed)
				if err != nil {
					t.Fatal("changed original setup failed", err)
				}
			}
			_, headBefore := workflowHead(t, s)
			before, resourcesBefore := cloudflare.snapshot()
			child := run("generated retire", nativeGeneratedBearerA, "--duty", duty)
			nativeGeneratedOutcome(t, child, "unavailable", 3)
			_, headAfter := workflowHead(t, s)
			after, resourcesAfter := cloudflare.snapshot()
			for _, event := range child.capture.Events {
				if strings.HasPrefix(event.Kind, "generator-") {
					t.Fatal("unavailable original reached producer custody", fault)
				}
			}
			currentLocator, err := os.ReadFile(locatorPath)
			if err != nil || !bytes.Equal(currentLocator, locator) || !reflect.DeepEqual(headBefore, headAfter) || !slices.Equal(before, after) || resourcesBefore != resourcesAfter {
				t.Fatal("unavailable original rebound support, changed HEAD or deleted a resource", fault, err)
			}
			observed := nativeGeneratedOutcome(t, run("generated list", ""), "success", 0)
			if !reflect.DeepEqual(observed.Current, rotated.Current) || !reflect.DeepEqual(observed.Duties, rotated.Duties) {
				t.Fatal("unavailable original changed authenticated current generation or Duty", fault)
			}
		}()
	}
	before, _ := cloudflare.snapshot()
	retiredChild := run("generated retire", nativeGeneratedBearerA, "--duty", duty)
	retired := nativeGeneratedOutcome(t, retiredChild, "success", 0)
	after, resources := cloudflare.snapshot()
	if len(after) != len(before)+1 || resources != 1 || after[len(before)] != (nativeGeneratedRequest{http.MethodDelete, nativeGeneratedAccountA, nativeGeneratedProviderID(t, first.Current[0].TokenID)}) ||
		!slices.ContainsFunc(retired.Effects, func(effect nativeGeneratedFact) bool {
			return effect.Facts.Action == "delete" && effect.Facts.ExecutorID == aFamily.ExecutorID.String()
		}) {
		t.Fatal("restarted retirement did not launch exact A for A's original target")
	}
	var custody []observer.Event
	for _, event := range retiredChild.capture.Events {
		if strings.HasPrefix(event.Kind, "generator-") {
			custody = append(custody, event)
		}
	}
	if len(custody) != 2 || custody[0].Kind != "generator-entry" || custody[1].Kind != "generator-return" || !custody[1].GeneratorQualified ||
		custody[0].GeneratorAttempt != custody[1].GeneratorAttempt || custody[1].GeneratorTarget != after[len(before)].Target {
		t.Fatal("original retirement lacks a positively returned exact producer call")
	}
	observation := custody[1].GeneratorReturn
	if observation == nil || observation.Code != uint16(contract.CryptoSuccess) || !observation.ExpectedResultValid || observation.Qualification != "qualified" ||
		observation.CommonFacts == nil || observation.CommonFacts.Disposition != contract.GeneratorDispositionRetirementAcknowledged || observation.CommonFacts.Reason != contract.GeneratorReasonNone {
		t.Fatal("original retirement return classification differs")
	}
	observed := nativeGeneratedOutcome(t, run("generated list", ""), "success", 0)
	selected, err := artifact.VerifyBuild(t.Context(), binaries.localBuild)
	if err != nil || selected.Executable != b.Executable || len(observed.Duties) != 0 || !reflect.DeepEqual(observed.Current, rotated.Current) {
		t.Fatal("retiring A changed B selection or the current A generation", err)
	}

	// A fresh retirement obligation uses the current build for the exact old
	// target; that is separate from continuing the already accepted A Duty.
	nativeGeneratedDeclaration(t, source, nativeGeneratedAccountA, "manual", 2, true)
	rotationB := nativeGeneratedOutcome(t, run("apply", nativeGeneratedBearerA), "retirement-pending", 3)
	if !slices.ContainsFunc(rotationB.Effects, func(effect nativeGeneratedFact) bool {
		return effect.Facts.Action == "create" && effect.Facts.ExecutorID == bFamily.ExecutorID.String()
	}) {
		t.Fatal("fresh process did not use newly selected B for fresh creation")
	}
	currentB := nativeGeneratedOutcome(t, run("generated list", ""), "success", 0)
	currentMatches := len(currentB.Current) == 1 && currentB.Current[0].Epoch == 2 &&
		currentB.Current[0].Generation != rotated.Current[0].Generation && currentB.Current[0].ResourceID != rotated.Current[0].ResourceID &&
		currentB.Current[0].TokenID != rotated.Current[0].TokenID
	dutyMatches := len(currentB.Duties) == 1 && currentB.Duties[0].Facts.ExecutorID == bFamily.ExecutorID.String() &&
		currentB.Duties[0].Target.TokenID == rotated.Current[0].TokenID && currentB.Duties[0].Target.Account == rotated.Current[0].Account
	if !currentMatches || !dutyMatches {
		t.Fatalf("fresh B rotation differs: current_count=%d current_matches=%t duty_count=%d duty_matches=%t", len(currentB.Current), currentMatches, len(currentB.Duties), dutyMatches)
	}
	beforeBRetire, _ := cloudflare.snapshot()
	retiredA1 := nativeGeneratedOutcome(t, run("generated retire", nativeGeneratedBearerA, "--duty", currentB.Duties[0].Facts.DutyID), "success", 0)
	afterBRetire, remaining := cloudflare.snapshot()
	if len(afterBRetire) != len(beforeBRetire)+1 || remaining != 1 ||
		afterBRetire[len(beforeBRetire)] != (nativeGeneratedRequest{http.MethodDelete, nativeGeneratedAccountA, nativeGeneratedProviderID(t, rotated.Current[0].TokenID)}) ||
		!slices.ContainsFunc(retiredA1.Effects, func(effect nativeGeneratedFact) bool {
			return effect.Facts.Action == "delete" && effect.Facts.ExecutorID == bFamily.ExecutorID.String()
		}) {
		t.Fatal("new B retirement did not delete its exact A1 target once")
	}
	settledB := nativeGeneratedOutcome(t, run("generated list", ""), "success", 0)
	if len(settledB.Duties) != 0 || !reflect.DeepEqual(settledB.Current, currentB.Current) {
		t.Fatal("new B retirement changed B's current generation")
	}
	// Clean up B through its own authenticated Duty and unchanged current build.
	nativeGeneratedDeclaration(t, source, nativeGeneratedAccountA, "manual", 2, false)
	nativeGeneratedOutcome(t, run("apply", "", "--retire-generator", "generated=cloudflare-account-token"), "retirement-pending", 3)
	removed := nativeGeneratedOutcome(t, run("generated list", ""), "success", 0)
	if len(removed.Current) != 0 || len(removed.Duties) != 1 || removed.Duties[0].Facts.ExecutorID != bFamily.ExecutorID.String() {
		t.Fatal("B cleanup lost its exact original build")
	}
	nativeGeneratedOutcome(t, run("generated retire", nativeGeneratedBearerA, "--duty", removed.Duties[0].Facts.DutyID), "success", 0)
	if requests, resources := cloudflare.snapshot(); resources != 0 || len(requests) != 6 {
		t.Fatalf("retained build fixture terminal differs: requests=%d resources=%d", len(requests), resources)
	}
}

// full_only: false
func TestPublicNativeGeneratedUnknownRetirementRiskAndCleanup(t *testing.T) {
	cloudflare := newNativeGeneratedServer(t)
	binaries := buildNativeGeneratedExecutables(t, cloudflare.server.URL+"/client/v4")
	for _, family := range []string{"aws", "gcp"} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/recovery-%t", family, recovery), func(t *testing.T) {
				binaries := binaries
				binaries.home = nativeGeneratedPrivateDirectory(t)
				s := newWorkflowServer(t, family, recovery)
				path := nativeGeneratedInitialize(t, s, binaries.cli, recovery)
				for epoch := uint64(0); epoch < 2; epoch++ {
					nativeGeneratedDeclaration(t, path, nativeGeneratedAccountA, "manual", epoch, true)
					state, code := "success", 0
					if epoch != 0 {
						state, code = "retirement-pending", 3
					}
					nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, nativeGeneratedBearerA, "apply", false), state, code)
				}
				view := nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, "", "generated list", false), "success", 0)
				if len(view.Duties) != 1 {
					t.Fatal("unknown retirement duty unavailable")
				}
				duty := view.Duties[0]
				cloudflare.mu.Lock()
				cloudflare.unknownDelete = nativeGeneratedProviderID(t, duty.Target.TokenID)
				cloudflare.mu.Unlock()
				nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, nativeGeneratedBearerA, "generated retire", false, "--duty", duty.Facts.DutyID), "effect-unknown", 3)
				parked := nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, "", "generated list", false), "success", 0)
				attempt := ""
				for _, next := range parked.Next {
					if next.Command == "generated accept-retirement-risk" && next.Duty == duty.Facts.DutyID {
						attempt = next.Attempt
					}
				}
				if attempt == "" {
					t.Fatal("parked ambiguity did not expose its exact risk action")
				}
				before, _ := cloudflare.snapshot()
				accepted := nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, "", "generated accept-retirement-risk", recovery, "--duty", duty.Facts.DutyID, "--attempt", attempt), "possible-live-residue-accepted", 0)
				if accepted.EffectSummary != "not-applicable" || accepted.Receipt == "" {
					t.Fatal("risk acceptance lost no-effect or receipt fact")
				}
				after, _ := cloudflare.snapshot()
				if !slices.Equal(before, after) {
					t.Fatal("risk acceptance sent a provider request")
				}
				residue := nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, "", "generated list", true), "success", 0)
				if len(residue.Hazards) != 1 || residue.Hazards[0].Target.TokenID != duty.Target.TokenID {
					t.Fatal("risk acceptance lost exact possible-live resource")
				}
				nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, nativeGeneratedBearerA, "generated cleanup", false), "success", 0)
				cleaned := nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, "", "generated list", false), "success", 0)
				if len(cleaned.Hazards) != 0 || len(cleaned.Current) != 1 || cleaned.Current[0].Generation != view.Current[0].Generation {
					t.Fatal("cleanup changed current generation or retained residue")
				}
				nativeGeneratedDeclaration(t, path, nativeGeneratedAccountA, "manual", 1, false)
				nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, "", "apply", false, "--retire-generator", "generated=cloudflare-account-token"), "retirement-pending", 3)
				removed := nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, "", "generated list", false), "success", 0)
				if len(removed.Duties) != 1 {
					t.Fatal("current fixture resource not retained after removal")
				}
				nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, nativeGeneratedBearerA, "generated retire", false, "--duty", removed.Duties[0].Facts.DutyID), "success", 0)
				_, resources := cloudflare.snapshot()
				if resources != 0 {
					t.Fatal("risk/cleanup sequence left local fixture resources")
				}
			})
		}
	}
}

// full_only: false
func TestPublicNativeGeneratedAutomaticRetirement(t *testing.T) {
	cloudflare := newNativeGeneratedServer(t)
	binaries := buildNativeGeneratedExecutables(t, cloudflare.server.URL+"/client/v4")
	for _, family := range []string{"aws", "gcp"} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/recovery-%t", family, recovery), func(t *testing.T) {
				binaries := binaries
				binaries.home = nativeGeneratedPrivateDirectory(t)
				s := newWorkflowServer(t, family, recovery)
				s.childRequestLimit = 1024
				path := nativeGeneratedInitialize(t, s, binaries.cli, recovery)
				for epoch := uint64(0); epoch < 2; epoch++ {
					nativeGeneratedDeclaration(t, path, nativeGeneratedAccountA, "auto", epoch, true)
					nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, nativeGeneratedBearerA, "apply", false), "success", 0)
				}
				view := nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, "", "generated list", false), "success", 0)
				if len(view.Current) != 1 || view.Current[0].Epoch != 1 || len(view.Duties) != 0 {
					t.Fatal("automatic retirement did not complete after successor selection")
				}
				nativeGeneratedDeclaration(t, path, nativeGeneratedAccountA, "auto", 1, false)
				nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, "", "apply", false, "--retire-generator", "generated=cloudflare-account-token"), "retirement-pending", 3)
				removed := nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, "", "generated list", false), "success", 0)
				if len(removed.Current) != 0 || len(removed.Duties) != 1 {
					t.Fatal("removal did not retain its exact retirement duty")
				}
				nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, nativeGeneratedBearerA, "generated retire", false, "--duty", removed.Duties[0].Facts.DutyID), "success", 0)
				_, resources := cloudflare.snapshot()
				if resources != 0 {
					t.Fatal("automatic removal left local fixture resources")
				}
			})
		}
	}
	t.Run("selected-then-delete-cas-contention", func(t *testing.T) {
		binaries := binaries
		binaries.home = nativeGeneratedPrivateDirectory(t)
		s := newWorkflowServer(t, "aws", false)
		s.childRequestLimit = 1024
		path := nativeGeneratedInitialize(t, s, binaries.cli, false)
		nativeGeneratedDeclaration(t, path, nativeGeneratedAccountA, "auto", 0, true)
		nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, nativeGeneratedBearerA, "apply", false), "success", 0)
		first := nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, "", "generated list", false), "success", 0)
		if len(first.Current) != 1 || first.Current[0].ResourceID == "" {
			t.Fatal("initial selected generation unavailable")
		}
		s.mu.Lock()
		oldHead := bytes.Clone(s.objects[s.prefix+"/HEAD"].body)
		s.mu.Unlock()
		var selectedHead []byte
		cloudflare.mu.Lock()
		cloudflare.afterDelete = func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			selectedHead = bytes.Clone(s.objects[s.prefix+"/HEAD"].body)
			s.rejectNextHeadUpdate = true
		}
		cloudflare.mu.Unlock()
		before, _ := cloudflare.snapshot()
		nativeGeneratedDeclaration(t, path, nativeGeneratedAccountA, "auto", 1, true)
		result := nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, nativeGeneratedBearerA, "apply", false), "contention", 3)
		if result.Canonical != "selected" || result.Receipt != "" {
			t.Fatal("later delete CAS contention lost earlier selection or invented a receipt")
		}
		foundDelete, foundWork := false, false
		retirementDutyID := ""
		for _, effect := range result.Effects {
			if effect.Facts.Action == "delete" && effect.Target.TokenID == first.Current[0].TokenID && effect.Facts.AttemptID != "" {
				foundDelete = true
			}
		}
		for _, duty := range result.Duties {
			if duty.Facts.Kind == "retirement" && duty.Facts.ResourceID == first.Current[0].ResourceID && duty.Target.TokenID == first.Current[0].TokenID && duty.Facts.DutyID != "" {
				if foundWork {
					t.Fatal("contended rendering returned duplicate exact retirement duties")
				}
				foundWork = true
				retirementDutyID = duty.Facts.DutyID
			}
		}
		if !foundDelete || !foundWork {
			t.Fatal("contended rendering lost exact entered delete result or retained duty")
		}
		after, _ := cloudflare.snapshot()
		deletes := 0
		for _, request := range after[len(before):] {
			if request.Method == http.MethodDelete {
				deletes++
				if request.Account != nativeGeneratedAccountA || request.Target != nativeGeneratedProviderID(t, first.Current[0].TokenID) {
					t.Fatal("contended automatic retirement rebound target")
				}
			}
		}
		if deletes != 1 {
			t.Fatal("CAS contention repeated provider deletion", deletes)
		}
		view := nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, path, "", "generated list", false), "success", 0)
		currentMatches := len(view.Current) == 1 && view.Current[0].Epoch == 1 && view.Current[0].ResourceID != "" && view.Current[0].ResourceID != first.Current[0].ResourceID && view.Current[0].TokenID != first.Current[0].TokenID
		createMatches, retirementMatches := 0, 0
		for _, duty := range view.Duties {
			switch duty.Facts.Kind {
			case "create":
				if currentMatches && duty.Facts.ResourceID == view.Current[0].ResourceID && duty.Facts.DutyID != "" && duty.Facts.DutyID != retirementDutyID {
					createMatches++
				}
			case "retirement":
				if duty.Facts.DutyID == retirementDutyID && duty.Facts.ResourceID == first.Current[0].ResourceID && duty.Target.TokenID == first.Current[0].TokenID {
					retirementMatches++
				}
			}
		}
		if !currentMatches || len(view.Duties) != 2 || createMatches != 1 || retirementMatches != 1 || len(view.Hazards) != 0 {
			var epoch uint64
			if len(view.Current) != 0 {
				epoch = view.Current[0].Epoch
			}
			t.Fatalf("delete CAS contention changed B selection or exact complete Duty set: current=%d epoch_present=%t epoch=%d duties=%d exact_create=%d exact_retirement=%d hazards=%d", len(view.Current), len(view.Current) != 0, epoch, len(view.Duties), createMatches, retirementMatches, len(view.Hazards))
		}
		s.mu.Lock()
		finalHead := bytes.Clone(s.objects[s.prefix+"/HEAD"].body)
		armed := s.rejectNextHeadUpdate
		s.mu.Unlock()
		if armed || len(selectedHead) == 0 || bytes.Equal(oldHead, selectedHead) || !bytes.Equal(selectedHead, finalHead) {
			t.Fatal("one-shot fault was not after successor selection and before the retained HEAD")
		}
	})

}

const nativeGeneratedLibrarySource = `package main
import (
 "context"
 "crypto/rand"
 "encoding/hex"
 "os"
 "strings"
 "time"
 "enkv.sh/compositions/configuration"
 full "enkv.sh/compositions/full"
 "enkv.sh/core"
 "enkv.sh/core/contract"
)
func main() { code:=runLibrary(); nativeProcessFinish(code); os.Exit(code) }
func runLibrary() int {
 if len(os.Args)<3 { return 2 }
 ctx,cancel:=context.WithTimeout(context.Background(),2*time.Minute); defer cancel()
 pair,err:=configuration.Capture(ctx,os.Args[2],configuration.JSON); if err!=nil { return 2 }; defer pair.Close()
 var nonce contract.ID; if _,err=rand.Read(nonce[:]); err!=nil { return 2 }
 selected:=map[string]contract.ID{}
 options:=full.ApplyOptions{RetirementPlugins:map[string]string{}}
 for i:=3;i<len(os.Args);i+=2 {
  if i+1>=len(os.Args) { return 2 }
  if os.Args[i]=="--retire-generator" { name,plugin,ok:=strings.Cut(os.Args[i+1],"="); if !ok { return 2 }; options.RetirementPlugins[name]=plugin; continue }
  raw,err:=hex.DecodeString(os.Args[i+1]); if err!=nil || len(raw)!=32 { return 2 }; var id contract.ID; copy(id[:],raw); selected[os.Args[i]]=id
 }
 if os.Args[1]=="generated list" { r:=full.ListConfigurationGenerated(ctx,nonce,pair); body,err:=r.RenderJSON(); if err!=nil { return 2 }; if _,err=os.Stdout.Write(body); err!=nil { return 2 }; if r.Result.Outcome!=core.ObservedCurrent { return 2 }; return 0 }
 var r full.ConfigurationApplyResult
 kind:=uint16(contract.OperationApplyDeclaration)
 switch os.Args[1] {
 case "apply": r=full.ApplyConfiguration(ctx,nonce,pair,options)
 case "generated retire": kind=contract.OperationRetireGeneratedGeneration; r=full.RetireConfigurationGenerated(ctx,nonce,pair,core.GeneratedRetirementRequest{DutyID:selected["--duty"]})
 case "generated accept-retirement-risk": kind=contract.OperationAcceptGeneratedRetirementResidue; r=full.AcceptConfigurationGeneratedRetirementRisk(ctx,nonce,pair,core.GeneratedRetirementRiskRequest{DutyID:selected["--duty"],AttemptID:selected["--attempt"]})
 case "generated cleanup": kind=contract.OperationCleanOwnedFailureResidue; r=full.CleanupConfigurationGenerated(ctx,nonce,pair)
 default: return 2
 }
 var body []byte
 if kind==contract.OperationApplyDeclaration { body,err=r.RenderJSON() } else { body,err=r.RenderGeneratedJSON(kind) }
 if err!=nil { return 2 }; if _,err=os.Stdout.Write(body); err!=nil { return 2 }
 if r.Result.Outcome!=core.ObservedCurrent && r.Result.Outcome!=core.Unchanged { return 2 }
 if r.Generated!=nil { switch r.Generated.StateResult { case "retirement-pending","effect-pending","effect-partial","effect-unknown":return 3 } }
 return 0
}

`

// full_only: false
func TestPublicNativeGeneratedCustodyLedgerKeepsActualResultsAndLostOutput(t *testing.T) {
	cloudflare := newNativeGeneratedServer(t)
	binaries := buildNativeGeneratedExecutables(t, cloudflare.server.URL+"/client/v4", true)
	for _, condition := range []string{"qualified-output-discarded", "pre-entry-persistence-refused", "allowance-exhausted", "unqualified-provider-reply", "post-result-persistence-refused"} {
		t.Run(condition, func(t *testing.T) {
			binaries := binaries
			binaries.home = nativeGeneratedPrivateDirectory(t)
			s := newWorkflowServer(t, "aws", false)
			source := nativeGeneratedInitialize(t, s, binaries.cli, false)
			nativeGeneratedDeclaration(t, source, nativeGeneratedAccountA, "manual", 0, true)
			directory, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil || os.Chmod(directory, 0700) != nil {
				t.Fatal("private ledger directory unavailable", err)
			}
			ledgerPath := filepath.Join(directory, "generator-cleanup.json")
			runID := strings.Repeat("a", 32)
			// The real maintained ledger implementation is compiled into the overlay.
			// This empty fixture image grants no Product authority or ownership fact.
			nativeGeneratedWriteJSON(t, ledgerPath, map[string]any{"schema_version": 1, "run_id": runID, "provider": "cloudflare", "account": nativeGeneratedAccountA, "pending_creates": []string{}, "resources": []any{}})
			policy := observer.Policy{GeneratorLedgerPath: ledgerPath, GeneratorRunID: runID, GeneratorAccount: nativeGeneratedAccountA, GeneratorCreates: 3}
			if condition == "pre-entry-persistence-refused" {
				if os.Remove(ledgerPath) != nil {
					t.Fatal("persistence fault setup failed")
				}
			}
			if condition == "allowance-exhausted" {
				policy.GeneratorCreates = 0
			}
			cloudflare.mu.Lock()
			if condition == "unqualified-provider-reply" {
				cloudflare.malformedCreate = true
			}
			if condition == "post-result-persistence-refused" {
				cloudflare.afterCreate = func(*http.Request) {
					if err := os.Rename(ledgerPath, ledgerPath+".retained"); err != nil {
						t.Error("post-result persistence fault setup failed", err)
					}
				}
			}
			cloudflare.mu.Unlock()
			before, _ := cloudflare.snapshot()
			t.Setenv("CLOUDFLARE_API_TOKEN", nativeGeneratedBearerA)
			pair := workflowReadPair(t, source)
			child := workflowRunEnvironment(t, s, binaries.cli, "apply", policy, nil, nativeGeneratedEnvironment(t, binaries, source), "apply", "--source", source, "--source-format", "json", "--json")
			child.generatedResources = nativeGeneratedSelectedResources(t, s)
			workflowUnchanged(t, source, pair)
			after, _ := cloudflare.snapshot()
			var events []observer.Event
			for _, event := range child.capture.Events {
				switch event.Kind {
				case "generator-entry", "generator-return", "generator-refused":
					if event.GeneratorAccount != nativeGeneratedAccountA || event.GeneratorAction != contract.GeneratorActionCreate || event.GeneratorAttempt == "" {
						t.Fatal("custody observation changed exact account, action or Attempt identity")
					}
					events = append(events, event)
				}
			}
			if condition == "pre-entry-persistence-refused" || condition == "allowance-exhausted" {
				nativeGeneratedOutcome(t, child, "effect-unknown", 3)
				if len(after) != len(before) || len(events) != 2 || events[0].Kind != "generator-refused" || events[1].Kind != "generator-refused" || events[0].GeneratorAttempt == events[1].GeneratorAttempt {
					t.Fatalf("ledger admission did not refuse the two distinct graph Attempts before provider entry: events=%d requests=%d", len(events), len(after)-len(before))
				}
				if condition == "pre-entry-persistence-refused" {
					if _, err := os.Lstat(ledgerPath); !os.IsNotExist(err) {
						t.Fatal("refused ledger admission recreated the missing ledger")
					}
					return
				}
			} else {
				wantEntries := 1
				if condition == "unqualified-provider-reply" {
					wantEntries = 2
				}
				if len(after) != len(before)+wantEntries || len(events) != 2*wantEntries {
					t.Fatalf("custody did not retain the exact complete provider-entry transcript: events=%d requests=%d expected_entries=%d", len(events), len(after)-len(before), wantEntries)
				}
				attempts := map[string]bool{}
				for i := 0; i < wantEntries; i++ {
					entry, result := events[2*i], events[2*i+1]
					request := after[len(before)+i]
					if entry.Kind != "generator-entry" || result.Kind != "generator-return" || entry.GeneratorAttempt != result.GeneratorAttempt || attempts[entry.GeneratorAttempt] || request.Method != http.MethodPost || request.Account != nativeGeneratedAccountA {
						t.Fatalf("custody did not join one entry and return for each distinct exact Create Attempt: pair=%d", i)
					}
					attempts[entry.GeneratorAttempt] = true
					var observed struct {
						Return *struct {
							Code        uint16 `json:"code"`
							CommonFacts *struct {
								Disposition uint8 `json:"disposition"`
								Reason      uint8 `json:"reason"`
							} `json:"common_facts"`
							ExpectedResultValid bool   `json:"expected_result_valid"`
							Qualification       string `json:"qualification"`
						} `json:"generator_return"`
					}
					encoded, encodeErr := json.Marshal(result)
					if encodeErr != nil || json.Unmarshal(encoded, &observed) != nil || observed.Return == nil || observed.Return.CommonFacts == nil || observed.Return.Code != uint16(contract.CryptoSuccess) {
						t.Fatal("producer return classification unavailable")
					}
					wantDisposition, wantReason, wantExpected, wantQualification := uint8(contract.GeneratorDispositionCompleteCreate), uint8(contract.GeneratorReasonNone), true, "qualified"
					if condition == "unqualified-provider-reply" && i == 0 {
						wantDisposition, wantReason, wantExpected, wantQualification = contract.GeneratorDispositionUnknown, contract.GeneratorReasonMalformed, false, "facts-refused"
					} else if condition == "post-result-persistence-refused" {
						wantQualification = "ledger-unavailable"
					}
					if observed.Return.CommonFacts.Disposition != wantDisposition || observed.Return.CommonFacts.Reason != wantReason || observed.Return.ExpectedResultValid != wantExpected || observed.Return.Qualification != wantQualification {
						t.Fatal("producer return classification changed the actual result", observed.Return)
					}
					if condition == "unqualified-provider-reply" && i == 0 {
						if result.GeneratorQualified || result.GeneratorTarget != "" {
							t.Fatal("unqualified original reply claimed an owned target")
						}
					} else if result.GeneratorTarget != request.Target || result.GeneratorQualified != (condition != "post-result-persistence-refused") {
						t.Fatalf("custody return changed the exact provider target or harness qualification: pair=%d", i)
					}
				}
				switch condition {
				case "post-result-persistence-refused":
					// A harness ledger failure must not replace the actual Crypto result.
					nativeGeneratedOutcome(t, child, "success", 0)
					if _, err := os.Lstat(ledgerPath); !os.IsNotExist(err) {
						t.Fatal("post-result refusal recreated the displaced ledger")
					}
					ledgerPath += ".retained"
				case "unqualified-provider-reply":
					out := nativeGeneratedOutcome(t, child, "success", 0)
					if out.Canonical != "selected" || out.EffectSummary != "effect-complete" || out.Receipt == "" || len(out.Effects) != 2 || len(out.Duties) != 0 || len(out.Hazards) != 1 || out.Hazards[0].Facts.OriginalAttemptID != events[0].GeneratorAttempt {
						t.Fatal("successful successor erased the original unknown effect or its exact retained Hazard")
					}
					seenEffects := map[string]bool{}
					for _, effect := range out.Effects {
						if seenEffects[effect.Facts.AttemptID] {
							t.Fatal("successful successor returned a duplicate effect Attempt")
						}
						seenEffects[effect.Facts.AttemptID] = true
						switch effect.Facts.AttemptID {
						case events[0].GeneratorAttempt:
							if effect.Facts.State != "closed-with-residue" {
								t.Fatal("original unqualified effect became successful evidence")
							}
						case events[2].GeneratorAttempt:
							if effect.Facts.State != "succeeded" || effect.Target.TokenID != hex.EncodeToString([]byte(events[3].GeneratorTarget)) {
								t.Fatal("successful successor effect lost its exact owned target")
							}
						default:
							t.Fatal("successful successor returned an unrelated effect Attempt")
						}
					}
				default:
					if child.code != 0 {
						t.Fatal("qualified custody result failed before output discard")
					}
					// Deliberately consume no CLI JSON as ownership evidence.
					clear(child.out)
				}
			}
			var ledger struct {
				Account   string
				Pending   []string `json:"pending_creates"`
				Resources []struct {
					ID, Disposition string
					Attempt         string `json:"create_attempt"`
				}
			}
			nativeGeneratedReadJSON(t, ledgerPath, &ledger)
			if ledger.Account != nativeGeneratedAccountA {
				t.Fatal("observed ledger rebound account")
			}
			switch condition {
			case "allowance-exhausted":
				if len(ledger.Pending) != 0 || len(ledger.Resources) != 0 {
					t.Fatal("refused allowance created ledger ownership or entered intent")
				}
			case "post-result-persistence-refused":
				if len(ledger.Pending) != 1 || ledger.Pending[0] != events[0].GeneratorAttempt || len(ledger.Resources) != 0 {
					t.Fatal("missing terminal ledger evidence erased the exact conservative entered intent")
				}
			case "unqualified-provider-reply":
				if len(ledger.Pending) != 1 || ledger.Pending[0] != events[0].GeneratorAttempt || len(ledger.Resources) != 1 || ledger.Resources[0].Attempt != events[2].GeneratorAttempt || ledger.Resources[0].ID != events[3].GeneratorTarget || ledger.Resources[0].Disposition != "owned" {
					t.Fatal("ledger did not preserve the exact unknown original and independently owned successor")
				}
			default:
				if len(ledger.Pending) != 0 || len(ledger.Resources) != 1 || ledger.Resources[0].Attempt != events[0].GeneratorAttempt || ledger.Resources[0].ID != events[1].GeneratorTarget || ledger.Resources[0].Disposition != "owned" {
					t.Fatal("lost ordinary output erased exact custody-owned resource")
				}
			}
		})
	}
}

func nativeGeneratedSourcePath(root, logical string) string {
	for _, source := range nativeModuleSources {
		if logical == source.Selector || strings.HasPrefix(logical, source.Selector+"/") {
			owner := root
			if source.Sibling != "" {
				owner = filepath.Join(filepath.Dir(root), source.Sibling)
			}
			return filepath.Join(owner, source.Directory, strings.TrimPrefix(strings.TrimPrefix(logical, source.Selector), "/"))
		}
	}
	return filepath.Join(root, filepath.FromSlash(logical))
}

func nativeGeneratedModulePath(t *testing.T, selector string) string {
	t.Helper()
	for _, source := range nativeModuleSources {
		if source.Selector == selector {
			return source.Module
		}
	}
	t.Fatal("native module selector is not registered", selector)
	return ""
}

func nativeGeneratedArtifactMetadata(t *testing.T, path string, facts artifact.BuildFacts, dependency []byte, identity artifact.Digest) artifact.Metadata {
	t.Helper()
	descriptor, _, err := artifact.ReadDescriptor(t.Context(), nativeGeneratedSourcePath(nativeRepository(t), "plugins/cloudflare/cmd/enkv-generator-cloudflare-test/plugin.json"))
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
	return artifact.Metadata{Schema: "enkv/plugin-artifact/v2", Purpose: "plugin-executable", Name: descriptor.Name, Role: descriptor.Role, Version: descriptor.Version, MainModule: facts.MainModule, Command: facts.Command, Platform: facts.Platform, Toolchain: facts.Toolchain, BuildOptions: facts.BuildOptions, Contracts: facts.Contracts, Sources: facts.Sources, Resolved: facts.Resolved, Compiled: facts.Compiled, Executable: executable, Family: &artifact.Family{Schema: artifact.FamilySchema, Facts: raw, Dependency: artifact.DigestLength{SHA256: artifact.Hash(dependency), Length: uint64(len(dependency))}}}
}

func nativeGeneratedEnvironment(t *testing.T, binaries nativeGeneratedExecutables, path string) []string {
	t.Helper()
	scope, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	build, err := filepath.EvalSymlinks(binaries.localBuild)
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(binaries.home, ".config")
	if runtime.GOOS == "darwin" {
		config = filepath.Join(binaries.home, "Library", "Application Support")
	}
	if err := os.MkdirAll(filepath.Join(config, "enkv"), 0700); err != nil {
		t.Fatal(err)
	}
	xdg := filepath.Join(binaries.home, ".config")
	if err := os.MkdirAll(xdg, 0700); err != nil {
		t.Fatal(err)
	}
	settingsPath := filepath.Join(config, "enkv", "plugins.json")
	settings := artifact.Settings{Schema: "enkv/plugin-settings/v1", Applications: []artifact.Application{}}
	body, err := os.ReadFile(settingsPath)
	if err == nil {
		settings, err = artifact.DecodeSettings(body)
	}
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	found := false
	for _, application := range settings.Applications {
		if application.Directory == scope {
			found = true
			if len(application.Plugins) != 1 || application.Plugins[0].Name != "cloudflare-account-token" || application.Plugins[0].Directory != build {
				t.Fatal("native fixture application selection changed")
			}
		}
	}
	if !found {
		settings.Applications = append(settings.Applications, artifact.Application{Directory: scope, Plugins: []artifact.LocalPlugin{{Name: "cloudflare-account-token", Directory: build}}})
	}
	slices.SortFunc(settings.Applications, func(a, b artifact.Application) int { return strings.Compare(a.Directory, b.Directory) })
	body, err = artifact.EncodeSettings(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, body, 0600); err != nil {
		t.Fatal(err)
	}
	return []string{"HOME=" + binaries.home, "XDG_CONFIG_HOME=" + xdg}
}

func nativeGeneratedPrivateDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal("private installed-build directory permissions", err)
	}
	t.Cleanup(func() {
		if err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return os.Chmod(path, 0700)
			}
			return nil
		}); err != nil {
			t.Error("private installed-build cleanup", err)
		}
	})
	return directory
}
